/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Grégoire <bock@step.polymtl.ca>
  @author Copyright (C) 2008 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <ifaddrs.h>

#if defined(__NetBSD__)
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <util.h>
#endif

#ifdef __linux__
#include <netinet/in.h>
#include <net/if.h>
#endif

#include <string.h>
#include <pthread.h>
#include <netdb.h>

#include "common.h"
#include "client_list.h"
#include "safe.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "fw_iptables.h"


/* Defined in main.c */
extern time_t started_time;

/* Defined in clientlist.c */
extern pthread_mutex_t client_list_mutex;
extern pthread_mutex_t config_mutex;

/* Defined in auth.c */
extern unsigned int authenticated_since_start;

/* Defined in main.c */
extern int created_httpd_threads;
extern int current_httpd_threads;


static int _execute_ret(char* msg, int msg_len, const char *cmd)
{
	struct sigaction sa, oldsa;
	FILE *fp;
	int rc;

	debug(LOG_DEBUG, "执行命令:【%s】", cmd);

	/* Temporarily get rid of SIGCHLD handler (see main.c), until child exits. */
	debug(LOG_DEBUG,"设置默认 SIGCHLD 处理程序 SIG_DF");
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	if (sigaction(SIGCHLD, &sa, &oldsa) == -1) {
		debug(LOG_ERR, "sigaction() 无法设置默认 SIGCHLD 处理程序: %s", strerror(errno));
	}

	fp = popen(cmd, "r");
	if (fp == NULL) {
		debug(LOG_ERR, "popen():【%s】", strerror(errno));
		rc = -1;
		goto abort;
	}

	if (msg && msg_len > 0) {
		rc = fread(msg, msg_len - 1, 1, fp);
	}

	rc = pclose(fp);

	if (WIFSIGNALED(rc) != 0) {
		debug(LOG_WARNING, "命令进程因信号【%d】退出", WTERMSIG(rc));
	}

	rc = WEXITSTATUS(rc);

abort:

	/* Restore signal handler */
	if (sigaction(SIGCHLD, &oldsa, NULL) == -1) {
		debug(LOG_ERR, "sigaction() 恢复SIGCHLD处理程序失败！错误 %s", strerror(errno));
	}

	return rc;
}

int execute(const char fmt[], ...)
{
	char cmd[QUERYMAXLEN];
	va_list vlist;
	int rc;

	va_start(vlist, fmt);
	rc = vsnprintf(cmd, sizeof(cmd), fmt, vlist);
	va_end(vlist);

	if (rc < 0 || rc >= sizeof(cmd)) {
		debug(LOG_ERR, "格式字符串太小或编码错误");
		return -1;
	}

	return _execute_ret(NULL, 0, cmd);
}

int execute_ret(char* msg, int msg_len, const char fmt[], ...)
{
	char cmd[512];
	va_list vlist;
	int rc;

	va_start(vlist, fmt);
	rc = vsnprintf(cmd, sizeof(cmd), fmt, vlist);
	va_end(vlist);

	if (rc < 0 || rc >= sizeof(cmd)) {
		debug(LOG_ERR, "格式字符串太小或编码错误");
		return -1;
	}

	return _execute_ret(msg, msg_len, cmd);
}

char *
get_iface_ip(const char ifname[], int ip6)
{
	char addrbuf[INET6_ADDRSTRLEN];
	const struct ifaddrs *cur;
	struct ifaddrs *addrs;

	if (getifaddrs(&addrs) < 0) {
		debug(LOG_ERR, "getifaddrs():【%s】", strerror(errno));
		return NULL;
	}

	/* Set default address */
	sprintf(addrbuf, ip6 ? "::" : "0.0.0.0");

	/* Iterate all interfaces */
	cur = addrs;
	while (cur != NULL) {
		if ((cur->ifa_addr != NULL) && (strcmp( cur->ifa_name, ifname) == 0)) {

			if (ip6 && cur->ifa_addr->sa_family == AF_INET6) {
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)cur->ifa_addr)->sin6_addr, addrbuf, sizeof(addrbuf));
				break;
			}

			if (!ip6 && cur->ifa_addr->sa_family == AF_INET) {
				inet_ntop(AF_INET, &((struct sockaddr_in *)cur->ifa_addr)->sin_addr, addrbuf, sizeof(addrbuf));
				break;
			}
		}

		cur = cur->ifa_next;
	}

	freeifaddrs(addrs);

	return safe_strdup(addrbuf);
}

char *
get_iface_mac(const char ifname[])
{
#if defined(__linux__)
	int r, s;
	s_config *config;
	struct ifreq ifr;
	char *hwaddr, mac[18];

	config = config_get_config();
	strcpy(ifr.ifr_name, ifname);

	s = socket(config->ip6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		debug(LOG_ERR, "get_iface_mac socket:【%s】", strerror(errno));
		return NULL;
	}

	r = ioctl(s, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR):【%s】", strerror(errno));
		close(s);
		return NULL;
	}

	hwaddr = ifr.ifr_hwaddr.sa_data;
	close(s);
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
		hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF
	);

	return safe_strdup(mac);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	const char *hwaddr;
	char mac[18], *str = NULL;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs():【%s】", strerror(errno));
		return NULL;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_LINK)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "未分配链路层地址:【%s】");
		goto out;
	}
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	hwaddr = LLADDR(sdl);
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
			 hwaddr[0] & 0xFF, hwaddr[1] & 0xFF,
			 hwaddr[2] & 0xFF, hwaddr[3] & 0xFF,
			 hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

	str = safe_strdup(mac);
out:
	freeifaddrs(ifap);
	return str;
#else
	return NULL;
#endif
}

/** Get name of external interface (the one with default route to the net).
 *  Caller must free.
 */
char *
get_ext_iface(void)
{
#ifdef __linux__
	FILE *input;
	char device[16] = {0};
	char gw[16] = {0};
	int i = 1;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct timespec timeout;

	debug(LOG_DEBUG, "get_ext_iface(): 从路由表中自动检测外部接口");
	for (i = 1; i <= NUM_EXT_INTERFACE_DETECT_RETRY; i += 1) {
		input = fopen("/proc/net/route", "r");
		while (!feof(input)) {
			int rc = fscanf(input, "%s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw);
			if (rc == 2 && strcmp(gw, "00000000") == 0) {
				fclose(input);
				debug(LOG_INFO, "get_ext_iface(): 尝试【%d】后检测到默认网络接口为【%s】", i, device);
				return strdup(device);
			}
		}
		fclose(input);
		debug(LOG_ERR, "get_ext_iface(): 尝试【%d】次后仍无法检测到外部网络接口（可能接口尚未启动）。重试次数上限:【%d】", i, NUM_EXT_INTERFACE_DETECT_RETRY);

		/* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
		timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}

	debug(LOG_ERR, "get_ext_iface(): 尝试【%d】次后仍无法检测外部接口，正在中止", i);
	exit(1);
#endif
	return NULL;
}

char *
format_duration(time_t from, time_t to, char *buf)
{
	int days, hours, minutes, seconds;
	long long int secs;
	const char *neg = "";

	if (from <= to) {
		secs = to - from;
	} else {
		secs = from - to;
		// Prepend minus sign
		neg = "-";
	}

	days = secs / (24 * 60 * 60);
	secs -= days * (24 * 60 * 60);
	hours = secs / (60 * 60);
	secs -= hours * (60 * 60);
	minutes = secs / 60;
	secs -= minutes * 60;
	seconds = secs;

	if (days > 0) {
		snprintf(buf, 64, "%s%dd %dh %dm %ds", neg, days, hours, minutes, seconds);
	} else if (hours > 0) {
		snprintf(buf, 64, "%s%dh %dm %ds", neg, hours, minutes, seconds);
	} else if (minutes > 0) {
		snprintf(buf, 64, "%s%dm %ds", neg, minutes, seconds);
	} else {
		snprintf(buf, 64, "%s%ds", neg, seconds);
	}

	return buf;
}

char *
format_time(time_t time, char *buf)
{
	strftime(buf, 64, "%a %b %d %H:%M:%S %Y", localtime(&time));
	return buf;
}

char *
get_uptime_string(char *buf)
{
	return format_duration(started_time, time(NULL), buf);
}

int is_addr(const char* addr) {
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;

	return (inet_pton(AF_INET, addr, &sa.sin_addr) == 1) ||
		(inet_pton(AF_INET6, addr, &sa6.sin6_addr) == 1);
}

void
ndsctl_status(FILE *fp)
{
	char timebuf[64];
	char durationbuf[64];
	s_config *config;
	t_client *client;
	int indx;
	unsigned long int now, uptimesecs, durationsecs = 0;
	unsigned long long int download_bytes, upload_bytes;
	t_MAC *trust_mac;
	t_MAC *allow_mac;
	t_MAC *block_mac;

	config = config_get_config();

	fprintf(fp, "==================\nNoDogSplash 状态\n==================\n");

	now = time(NULL);
	uptimesecs = now - started_time;

	fprintf(fp, "版本: " VERSION "\n");

	format_duration(started_time, now, durationbuf);
	fprintf(fp, "运行时间: %s\n", durationbuf);

	fprintf(fp, "网关名称: %s\n", config->gw_name);
	fprintf(fp, "管理接口: %s\n", config->gw_interface);
	fprintf(fp, "管理 IP 范围: %s\n", config->gw_iprange);
	fprintf(fp, "服务器监听地址: http://%s\n", config->gw_http_name);
	if (strncmp(config->gw_http_name_port, config->gw_http_name, strlen(config->gw_http_name_port)))
		fprintf(fp, "服务器监听地址: http://%s\n", config->gw_http_name_port);
	if (config->gw_domain)
		fprintf(fp, "服务器域名地址: http://%s\n", config->gw_domain);

	if (config->binauth) {
		fprintf(fp, "Binauth 脚本: %s\n", config->binauth);
	} else {
		fprintf(fp, "Binauth: 已禁用\n");
	}

	if (config->preauth) {
		fprintf(fp, "预认证脚本: %s\n", config->preauth);
	} else {
		fprintf(fp, "预认证: 已禁用\n");
	}

	fprintf(fp, "客户端检查间隔: %ds\n", config->checkinterval);
	format_duration(0, config->preauth_idle_timeout * 60, durationbuf);
	fprintf(fp, "预认证空闲超时: %sm\n", durationbuf);
	format_duration(0, config->auth_idle_timeout * 60, durationbuf);
	fprintf(fp, "认证空闲超时: %s\n", durationbuf);
	format_duration(0, config->session_timeout * 60, durationbuf);
	fprintf(fp, "会话超时: %s\n", durationbuf);

	fprintf(fp, "会话超时后阻止访问: %s\n", config->session_timeout_block ? "是" : "否");

	if (config->session_limit_block) {
		fprintf(fp, "下载限制超出后阻止: %d MB\n", config->session_limit_block);
	}

	if (config->redirectURL) {
		fprintf(fp, "重定向 URL: %s\n", config->redirectURL);
	}

	fprintf(fp, "流量控制: %s\n", config->traffic_control ? "启用" : "禁用");

	if (config->traffic_control) {
		if (config->download_limit > 0) {
			fprintf(fp, "下载速率限制: %d kbit/s\n", config->download_limit);
		} else {
			fprintf(fp, "下载速率限制: 无\n");
		}
		if (config->upload_limit > 0) {
			fprintf(fp, "上传速率限制: %d kbit/s\n", config->upload_limit);
		} else {
			fprintf(fp, "上传速率限制: 无\n");
		}
	}

	download_bytes = iptables_fw_total_download();
	fprintf(fp, "总下载: %llu kByte", download_bytes / 1000);
	fprintf(fp, "; 平均速率: %.2f kbit/s\n", ((double) download_bytes) / 125 / uptimesecs);

	upload_bytes = iptables_fw_total_upload();
	fprintf(fp, "总上传: %llu kByte", upload_bytes / 1000);
	fprintf(fp, "; 平均速率: %.2f kbit/s\n", ((double) upload_bytes) / 125 / uptimesecs);
	fprintf(fp, "==================\n");
	fprintf(fp, "自启动以来认证的客户端数量: %u\n", authenticated_since_start);

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	fprintf(fp, "当前客户端数量: %d\n", get_client_list_length());

	client = client_get_first_client();
	if (client) {
		fprintf(fp, "\n");
	}

	indx = 0;
	while (client != NULL) {
		fprintf(fp, "客户端 %d\n", indx);

		fprintf(fp, "  IP: %s MAC: %s\n", client->ip, client->mac);

		format_time(client->counters.last_updated, timebuf);
		format_duration(client->counters.last_updated, now, durationbuf);
		fprintf(fp, "  最近活跃: %s (%s 前)\n", timebuf, durationbuf);

		if (client->session_start) {
			format_time(client->session_start, timebuf);
			format_duration(client->session_start, now, durationbuf);
			fprintf(fp, "  会话开始: %s (%s 前)\n", timebuf, durationbuf);
		} else {
			fprintf(fp, "  会话开始: -\n");
		}

		if (client->session_end) {
			format_time(client->session_end, timebuf);
			format_duration(now, client->session_end, durationbuf);
			fprintf(fp, "  会话结束:   %s (还剩 %s)\n", timebuf, durationbuf);
		} else {
			fprintf(fp, "  会话结束:   -\n");
		}

		fprintf(fp, "  Token: %s\n", client->token ? client->token : "无");

		fprintf(fp, "  状态: %s\n", fw_connection_state_as_string(client->fw_connection_state));

		download_bytes = client->counters.incoming;
		upload_bytes = client->counters.outgoing;
		durationsecs = now - client->session_start;

		// prevent divison by 0
		if (durationsecs < 1) {
			durationsecs = 1;
		}

		fprintf(fp, "  下载: %llu kByte; 平均: %.2f kbit/s\n  上传:   %llu kByte; 平均: %.2f kbit/s\n\n",
				download_bytes / 1000, ((double)download_bytes) / 125 / durationsecs,
				upload_bytes / 1000, ((double)upload_bytes) / 125 / durationsecs);

		indx++;
		client = client->next;
	}

	UNLOCK_CLIENT_LIST();

	fprintf(fp, "==================\n");

	fprintf(fp, "被阻止的 MAC 地址:");

	if (config->macmechanism == MAC_ALLOW) {
		fprintf(fp, " 不适用\n");
	} else  if (config->blockedmaclist != NULL) {
		fprintf(fp, "\n");
		for (block_mac = config->blockedmaclist; block_mac != NULL; block_mac = block_mac->next) {
			fprintf(fp, "  %s\n", block_mac->mac);
		}
	} else {
		fprintf(fp, " 无\n");
	}

	fprintf(fp, "允许的 MAC 地址:");

	if (config->macmechanism == MAC_BLOCK) {
		fprintf(fp, " 不适用\n");
	} else  if (config->allowedmaclist != NULL) {
		fprintf(fp, "\n");
		for (allow_mac = config->allowedmaclist; allow_mac != NULL; allow_mac = allow_mac->next) {
			fprintf(fp, "  %s\n", allow_mac->mac);
		}
	} else {
		fprintf(fp, " 无\n");
	}

	fprintf(fp, "受信任的 MAC 地址:");

	if (config->trustedmaclist != NULL) {
		fprintf(fp, "\n");
		for (trust_mac = config->trustedmaclist; trust_mac != NULL; trust_mac = trust_mac->next) {
			fprintf(fp, "  %s\n", trust_mac->mac);
		}
	} else {
		fprintf(fp, " 无\n");
	}

	fprintf(fp, "==================\n");
}

void
ndsctl_clients(FILE *fp)
{
	t_client *client;
	int indx;
	unsigned long int now, durationsecs = 0;
	unsigned long long int download_bytes, upload_bytes;

	now = time(NULL);

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	fprintf(fp, "%d\n", get_client_list_length());

	client = client_get_first_client();
	if (client) {
		fprintf(fp, "\n");
	}

	indx = 0;
	while (client != NULL) {
		fprintf(fp, "客户端ID=%d\n", indx);
		fprintf(fp, "IP地址=%s\nMAC地址=%s\n", client->ip, client->mac);
		fprintf(fp, "加入时间=%lld\n", (long long) client->session_start);
		fprintf(fp, "最后活跃时间=%lld\n", (long long) client->counters.last_updated);
		if (client->session_start) {
			fprintf(fp, "会话持续时间=%lld\n", (long long) (now - client->session_start));
		} else {
			fprintf(fp, "会话持续时间=%lld\n", 0ll);
		}
		fprintf(fp, "token=%s\n", client->token ? client->token : "none");
		fprintf(fp, "状态=%s\n", fw_connection_state_as_string(client->fw_connection_state));

		durationsecs = now - client->session_start;
		download_bytes = client->counters.incoming;
		upload_bytes = client->counters.outgoing;

		fprintf(fp, "已下载=%llu\n", download_bytes/1000);
		fprintf(fp, "平均下载速率=%.2f\n", ((double)download_bytes) / 125 / durationsecs);
		fprintf(fp, "已上传=%llu\n", upload_bytes/1000);
		fprintf(fp, "平均上传速率=%.2f\n\n", ((double)upload_bytes) / 125 / durationsecs);

		indx++;
		client = client->next;
	}

	UNLOCK_CLIENT_LIST();
}

static void
ndsctl_json_client(FILE *fp, const t_client *client, time_t now)
{
	unsigned long int durationsecs;
	unsigned long long int download_bytes, upload_bytes;

	fprintf(fp, "\"客户端ID\":%d,\n", client->id);
	fprintf(fp, "\"IP地址\":\"%s\",\n", client->ip);
	fprintf(fp, "\"MAC地址\":\"%s\",\n", client->mac);
	fprintf(fp, "\"加入时间\":%lld,\n", (long long) client->session_start);
	fprintf(fp, "\"最后活跃时间\":%lld,\n", (long long) client->counters.last_updated);
	if (client->session_start) {
		fprintf(fp, "\"会话持续时间\":%lld,\n", (long long) (now - client->session_start));
	} else {
		fprintf(fp, "\"会话持续时间\":%lld,\n", 0ll);
	}
	fprintf(fp, "\"token\":\"%s\",\n", client->token ? client->token : "none");
	fprintf(fp, "\"状态\":\"%s\",\n", fw_connection_state_as_string(client->fw_connection_state));

	durationsecs = now - client->session_start;
	download_bytes = client->counters.incoming;
	upload_bytes = client->counters.outgoing;

	fprintf(fp, "\"已下载\":%llu,\n", download_bytes / 1000);
	fprintf(fp, "\"平均下载速率\":%.2f,\n", ((double)download_bytes) / 125 / durationsecs);
	fprintf(fp, "\"已上传\":%llu,\n", upload_bytes / 1000);
	fprintf(fp, "\"平均上传速率\":%.2f\n", ((double)upload_bytes)/ 125 / durationsecs);
}

static void
ndsctl_json_one(FILE *fp, const char *arg)
{
	t_client *client;
	time_t now;

	now = time(NULL);

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	client = client_list_find_by_any(arg, arg, arg);

	if (client) {
		fprintf(fp, "{\n");
		ndsctl_json_client(fp, client, now);
		fprintf(fp, "}\n");
	} else {
		fprintf(fp, "{}\n");
	}

	UNLOCK_CLIENT_LIST();
}

static void
ndsctl_json_all(FILE *fp)
{
	t_client *client;
	time_t now;

	now = time(NULL);

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	fprintf(fp, "{\n\"客户端数量\": %d,\n", get_client_list_length());

	client = client_get_first_client();

	fprintf(fp, "\"客户端信息\":{\n");

	while (client != NULL) {
		fprintf(fp, "\"%s\":{\n", client->mac);
		ndsctl_json_client(fp, client, now);

		client = client->next;
		if (client) {
			fprintf(fp, "},\n");
		} else {
			fprintf(fp, "}\n");
		}
	}

	fprintf(fp, "}\n}\n");

	UNLOCK_CLIENT_LIST();
}

void
ndsctl_json(FILE *fp, const char *arg)
{
	if (arg && strlen(arg)) {
		ndsctl_json_one(fp, arg);
	} else {
		ndsctl_json_all(fp);
	}
}

unsigned short
rand16(void)
{
	static int been_seeded = 0;

	if (!been_seeded) {
		unsigned int seed = 0;
		struct timeval now;

		/* not a very good seed but what the heck, it needs to be quickly acquired */
		gettimeofday(&now, NULL);
		seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

		srand(seed);
		been_seeded = 1;
	}

	/* Some rand() implementations have less randomness in low bits
	 * than in high bits, so we only pay attention to the high ones.
	 * But most implementations don't touch the high bit, so we
	 * ignore that one.
	 **/
	return( (unsigned short) (rand() >> 15) );
}
