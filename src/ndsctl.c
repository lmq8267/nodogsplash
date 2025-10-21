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

/** @file ndsctl.c
    @brief Monitoring and control of nodogsplash, client part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    trivially modified for nodogsplash
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include "ndsctl.h"


struct argument {
	const char *cmd;
	const char *ifyes;
	const char *ifno;
};

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when ndsctl is run with -h or with an unknown option
 */
static void
usage(void)
{
	printf(
		"用法: ndsctl [选项] 命令 [参数]\n"
		"\n"
		"选项:\n"
		"  -s <路径>           套接字路径\n"
		"  -h                  打印此帮助信息\n"
		"\n"
		"命令:\n"
		"  status              查看 nodogsplash 状态\n"
		"  clients             显示机器可读的客户端列表\n"
		"  json [mac|ip|token] 以 JSON 格式显示客户端列表\n"
		"  stop                停止正在运行的 nodogsplash\n"
		"  auth mac|ip|token   认证指定 mac、ip 或 token 的用户\n"
		"  deauth mac|ip|token 取消认证指定 mac、ip 或 token 的用户\n"
		"  block mac           阻止指定 MAC 地址\n"
		"  unblock mac         解除阻止指定 MAC 地址\n"
		"  allow mac           允许指定 MAC 地址访问\n"
		"  unallow mac         取消允许指定 MAC 地址访问\n"
		"  trust mac           信任指定 MAC 地址\n"
		"  untrust mac         取消信任指定 MAC 地址\n"
		"  debuglevel n        设置日志详细级别为 n\n"
		"\n"
	);
}

static struct argument arguments[] = {
	{"clients", NULL, NULL},
	{"json", NULL, NULL},
	{"status", NULL, NULL},
	{"stop", NULL, NULL},
	{"debuglevel", "日志详细级别设置为 %s \n", "设置日志详细级别 %s 失败 \n"},
	{"deauth", "客户端 %s 已取消认证 \n", "未找到客户端 %s \n"},
	{"auth", "客户端 %s 已认证 \n", "认证客户端 %s 失败 \n"},
	{"block", "MAC %s 已阻止 \n", "阻止 MAC %s 失败 \n"},
	{"unblock", "MAC %s 已解除阻止 \n", "解除阻止 MAC %s 失败 \n"},
	{"allow", "MAC %s 已允许访问 \n", "允许 MAC %s 失败 \n"},
	{"unallow", "MAC %s 已取消允许访问 \n", "取消允许 MAC %s 失败 \n"},
	{"trust", "MAC %s 已被信任 \n", "信任 MAC %s 失败 \n"},
	{"untrust", "MAC %s 已取消信任 \n", "取消信任 MAC %s 失败 \n"},
	{NULL, NULL, NULL}
};

static const struct argument*
find_argument(const char *cmd) {
	int i;

	for (i = 0; arguments[i].cmd; i++) {
		if (strcmp(arguments[i].cmd, cmd) == 0) {
			return &arguments[i];
		}
	}

	return NULL;
}

static int
connect_to_server(const char sock_name[])
{
	int sock;
	struct sockaddr_un sa_un;

	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "ndsctl: nodogsplash 程序可能未启动 (错误代码: %s)\n", strerror(errno));
		return -1;
	}

	return sock;
}

static int
send_request(int sock, const char request[])
{
	ssize_t len, written;

	len = 0;
	while (len != strlen(request)) {
		written = write(sock, (request + len), strlen(request) - len);
		if (written == -1) {
			fprintf(stderr, "写入 nodogsplash 失败: %s\n", strerror(errno));
			exit(1);
		}
		len += written;
	}

	return((int)len);
}

/* Perform a ndsctl action, with server response Yes or No.
 * Action given by cmd, followed by config.param.
 * Responses printed to stdout, as formatted by ifyes or ifno.
 * config.param interpolated in format with %s directive if desired.
 */
static int
ndsctl_do(const char *socket, const struct argument *arg, const char *param)
{
	int sock;
	char buffer[4096];
	char request[128];
	int len, rlen;
	int ret;

	sock = connect_to_server(socket);
	if (sock < 0) {
		return 3;
	}

	if (param) {
		snprintf(request, sizeof(request), "%s %s\r\n\r\n", arg->cmd, param);
	} else {
		snprintf(request, sizeof(request), "%s\r\n\r\n", arg->cmd);
	}

	len = send_request(sock, request);

	if (arg->ifyes && arg->ifno) {
		len = 0;
		memset(buffer, 0, sizeof(buffer));
		while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
			(sizeof(buffer) - len))) > 0)) {
			len += rlen;
		}

		if (rlen < 0) {
			fprintf(stderr, "ndsctl: 读取套接字时出错: %s\n", strerror(errno));
			ret = 3;
		} else if (strcmp(buffer, "Yes") == 0) {
			printf(arg->ifyes, param);
			ret = 0;
		} else if (strcmp(buffer, "No") == 0) {
			printf(arg->ifno, param);
			ret = 1;
		} else {
			fprintf(stderr, "ndsctl: 错误：nodogsplash 发送了异常回复\n");
			ret = 2;
		}
	} else {
		while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
			buffer[len] = '\0';
			printf("%s", buffer);
		}
		ret = 0;
	}

	shutdown(sock, 2);
	close(sock);

	return ret;
}

int
main(int argc, char **argv)
{
	const struct argument* arg;
	const char *socket;
	int i = 1;

	socket = strdup(DEFAULT_SOCK);

	if (argc <= i) {
		usage();
		return 0;
	}

	if (strcmp(argv[1], "-h") == 0) {
		usage();
		return 1;
	}

	if (strcmp(argv[1], "-s") == 0) {
		if (argc >= 2) {
			socket = strdup(argv[2]);
			i = 3;
		} else {
			usage();
			return 1;
		}
	}

	// Too many arguments
	if (argc > (i+2)) {
		usage();
		return 1;
	}

	arg = find_argument(argv[i]);

	if (arg == NULL) {
		fprintf(stderr, "未知命令:【%s】\n", argv[i]);
		return 1;
	}

	// Send command, argv[i+1] may be NULL.
	return ndsctl_do(socket, arg, argv[i+1]);
}
