/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
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

/** @internal
  @file main.c
  @brief Main loop
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
  @author Copyright (C) 2008 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include <arpa/inet.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include "http_microhttpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "main.h"
#include "commandline.h"
#include "auth.h"
#include "client_list.h"
#include "ndsctl_thread.h"
#include "fw_iptables.h"
#include "state_file.h"
#include "util.h"

#include <microhttpd.h>

// Check for libmicrohttp version >= 0.9.51
#if MHD_VERSION < 0x00095100
#error libmicrohttp version >= 0.9.51 required
#endif

/** XXX Ugly hack
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_client_check = 0;

/* The internal web server */
struct MHD_Daemon * webserver = NULL;

/* Time when nodogsplash started  */
time_t started_time = 0;

bool write_state_file = false;

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * parent process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
	int	status;
	pid_t rc;

	debug(LOG_DEBUG, "SIGCHLD 处理程序：尝试回收子进程");

	rc = waitpid(-1, &status, WNOHANG | WUNTRACED);

	if (rc == -1) {
		if (errno == ECHILD) {
			debug(LOG_DEBUG, "SIGCHLD 处理程序：waitpid()：当前没有子进程。");
		} else {
			debug(LOG_ERR, "SIGCHLD 处理程序：回收子进程出错 (waitpid() 返回 -1)：%s", strerror(errno));
		}
		return;
	}

	if (WIFEXITED(status)) {
		debug(LOG_DEBUG, "SIGCHLD 处理程序：子进程 PID【%d】正常退出，状态【%d】", (int)rc, WEXITSTATUS(status));
		return;
	}

	if (WIFSIGNALED(status)) {
		debug(LOG_DEBUG, "SIGCHLD 处理程序：子进程 PID【%d】因信号【%d】退出", (int)rc, WTERMSIG(status));
		return;
	}

	debug(LOG_DEBUG, "SIGCHLD 处理程序：子进程 PID【%d】状态改变，状态【%d】未退出，忽略", (int)rc, status);
	return;
}

/** Exits cleanly after cleaning up the firewall.
 *  Use this function anytime you need to exit after firewall initialization */
void
termination_handler(int s)
{
	static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;

	debug(LOG_NOTICE, "终止信号处理程序捕获到信号【%d】", s);

	/* Makes sure we only call iptables_fw_destroy() once. */
	if (pthread_mutex_trylock(&sigterm_mutex)) {
		debug(LOG_INFO, "已有线程开始全局终止处理，此次退出");
		pthread_exit(NULL);
	} else {
		debug(LOG_INFO, "正在清理并退出");
	}

#ifdef WITH_STATE_FILE
	if (write_state_file) {
		s_config *config = config_get_config();
		if (config->statefile && strlen(config->statefile)) {
			debug(LOG_INFO, "将当前状态写入文件【%s】", config->statefile);
			state_file_export(config->statefile);
		}
	}
#endif /* WITH_STATE_FILE */

	auth_client_deauth_all();

	debug(LOG_INFO, "刷新防火墙规则 ...");
	iptables_fw_destroy();

	/* XXX Hack
	 * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
	 * termination handler) from happening so we need to explicitly kill the threads
	 * that use that
	 */
	if (tid_client_check) {
		debug(LOG_INFO, "明确终止 fw_counter 线程");
		pthread_kill(tid_client_check, SIGKILL);
	}

	debug(LOG_NOTICE, "退出...");
	exit(s == 0 ? 1 : 0);
}


/** @internal
 * Registers all the signal handlers
 */
static void
init_signals(void)
{
	struct sigaction sa;

	debug(LOG_DEBUG, "将 SIGCHLD 处理程序设置为 sigchld_handler()");
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction():【%s】", strerror(errno));
		exit(1);
	}

	/* Trap SIGPIPE */
	/* This is done so that when libhttpd does a socket operation on
	 * a disconnected socket (i.e.: Broken Pipes) we catch the signal
	 * and do nothing. The alternative is to exit. SIGPIPE are harmless
	 * if not desirable.
	 */
	debug(LOG_DEBUG, "将 SIGPIPE 处理程序设置为 SIG_IGN");
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction():【%s】", strerror(errno));
		exit(1);
	}

	debug(LOG_DEBUG, "将 SIGTERM、SIGQUIT、SIGINT 处理程序设置为 termination_handler()");
	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Trap SIGTERM */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction():【%s】", strerror(errno));
		exit(1);
	}

	/* Trap SIGQUIT */
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction():【%s】", strerror(errno));
		exit(1);
	}

	/* Trap SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction():【%s】", strerror(errno));
		exit(1);
	}
}

/**@internal
 * Main execution loop
 */
static void
main_loop(void)
{
	int result = 0;
	pthread_t tid;
	s_config *config;

	config = config_get_config();

	/* Set the time when nodogsplash started */
	if (!started_time) {
		debug(LOG_INFO, "设置started_time");
		started_time = time(NULL);
	} else if (started_time < MINIMUM_STARTED_TIME) {
		debug(LOG_WARNING, "检测到可能的时钟偏差 - 重新设置started_time");
		started_time = time(NULL);
	}

	/* If we don't have the Gateway IP address, get it. Exit on failure. */
	if (!config->gw_ip) {
		debug(LOG_DEBUG, "正在查找 【%s】 的 IP 地址", config->gw_interface);
		config->gw_ip = get_iface_ip(config->gw_interface, config->ip6);
		if (!config->gw_ip) {
			debug(LOG_ERR, "无法获取 【%s】 的 IP 地址信息，退出 ...", config->gw_interface);
			exit(1);
		}
	}

	/* format gw_address accordingly depending on if gw_ip is v4 or v6 */
	const char *ipfmt = config->ip6 ? "[%s]:%d" : "%s:%d";
	safe_asprintf(&config->gw_address, ipfmt, config->gw_ip, config->gw_port);

	if (config->gw_domain == NULL) {
		if (config->gw_port == 80)
			if (config->ip6)
				safe_asprintf(&config->gw_http_name, "[%s]", config->gw_ip);
			else
				safe_asprintf(&config->gw_http_name, "%s", config->gw_ip);
		else
			safe_asprintf(&config->gw_http_name, ipfmt, config->gw_ip, config->gw_port);

		safe_asprintf(&config->gw_http_name_port, ipfmt, config->gw_ip, config->gw_port);
	} else {
		if (config->gw_port == 80)
			safe_asprintf(&config->gw_http_name, "%s", config->gw_domain);
		else
			safe_asprintf(&config->gw_http_name, "%s:%d", config->gw_domain, config->gw_port);

		safe_asprintf(&config->gw_http_name_port, "%s:%d", config->gw_domain, config->gw_port);
	}

	if ((config->gw_mac = get_iface_mac(config->gw_interface)) == NULL) {
		debug(LOG_ERR, "无法获取 【%s】 的 MAC 地址信息，退出 ...", config->gw_interface);
		exit(1);
	}
	debug(LOG_NOTICE, "检测到网关IP地址 【%s】 接口名称 【%s】 MAC地址 【%s】", config->gw_ip, config->gw_interface, config->gw_mac);

	/* Initializes the web server */
	if ((webserver = MHD_start_daemon(
						MHD_USE_EPOLL_INTERNALLY | MHD_USE_TCP_FASTOPEN,
						config->gw_port,
						NULL, NULL,
						libmicrohttpd_cb, NULL,
						MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
						MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
						MHD_OPTION_END)) == NULL) {
		debug(LOG_ERR, "无法创建 Web 认证服务器: 【%s】", strerror(errno));
		exit(1);
	}

	/* TODO: set listening socket */
	debug(LOG_NOTICE, "已创建 Web 认证服务器： 【%s】", config->gw_http_name);

	if (config->binauth) {
		debug(LOG_NOTICE, "Binauth 已启用！\n");
		debug(LOG_NOTICE, "Binauth 脚本路径： 【%s】\n", config->binauth);
	}

	/* Reset the firewall (cleans it, in case we are restarting after nodogsplash crash) */
	iptables_fw_destroy();

	/* Then initialize it */
	if (iptables_fw_init() != 0) {
		debug(LOG_ERR, "初始化防火墙规则时出错！正在清理");
		iptables_fw_destroy();
		debug(LOG_ERR, "由于初始化防火墙规则时出错而退出");
		exit(1);
	}

#ifdef WITH_STATE_FILE
	result = state_file_import(config->statefile);
	if (result < 0) {
		debug(LOG_ERR, "无法解析状态文件，将覆盖旧状态");
		debug(LOG_ERR, "重置客户端和防火墙状态");
		iptables_fw_destroy();
		if (iptables_fw_init() != 0) {
			debug(LOG_ERR, "初始化防火墙规则时出错！正在清理");
			iptables_fw_destroy();
			debug(LOG_ERR, "由于初始化防火墙规则时出错而退出");
			exit(1);
		}
		client_list_flush();
	} else if (result > 0) {
		debug(LOG_ERR, "无法打开状态文件进行读取，已忽略");
	}
#endif

	/* Start client statistics and timeout clean-up thread */
	result = pthread_create(&tid_client_check, NULL, thread_client_timeout_check, NULL);
	if (result != 0) {
		debug(LOG_ERR, "严重错误：无法创建thread_client_timeout_check - 退出");
		termination_handler(0);
	}
	pthread_detach(tid_client_check);

	/* Start control thread */
	result = pthread_create(&tid, NULL, thread_ndsctl, (void *)(config->ndsctl_sock));
	if (result != 0) {
		debug(LOG_ERR, "严重错误：无法创建thread_ndsctl - 退出");
		termination_handler(1);
	}

	write_state_file = true;
	result = pthread_join(tid, NULL);
	if (result) {
		debug(LOG_INFO, "无法等待 nodogsplash 线程");
	}
	MHD_stop_daemon(webserver);
	termination_handler(result);
}

/** Main entry point for nodogsplash.
 * Reads the configuration file and then starts the main loop.
 */
int main(int argc, char **argv)
{
	s_config *config = config_get_config();
	config_init();

	parse_commandline(argc, argv);

	/* Initialize the config */
	debug(LOG_INFO, "读取并验证配置文件【%s】", config->configfile);
	config_read(config->configfile);
	config_validate();

	// Initializes the linked list of connected clients
	client_list_init();

	// Init the signals to catch chld/quit/etc
	debug(LOG_INFO, "初始化信号处理程序");
	init_signals();

	if (config->daemon) {

		debug(LOG_NOTICE, "以守护进程方式启动，正在分叉到后台运行");

		switch(safe_fork()) {
		case 0: // child
			setsid();
			main_loop();
			break;

		default: // parent
			exit(0);
			break;
		}
	} else {
		main_loop();
	}

	return 0; // never reached
}
