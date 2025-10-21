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

/** @file commandline.c
    @brief Command line argument handling
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "debug.h"
#include "safe.h"
#include "conf.h"


static void usage(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when nodogsplash is run with -h or with an unknown option
 */
static void
usage(void)
{
	printf("用法: nodogsplash [参数]\n"
		"\n"
		"  -c <路径>   使用配置文件\n"
		"  -f          在前台运行\n"
		"  -d <等级>   日志详细级别 (%d-%d)\n"
		"  -s          日志记录到系统日志\n"
		"  -w <路径>   Ndsctl 套接字路径\n"
		"  -h          打印此帮助信息\n"
		"  -v          打印版本号\n"
		"\n", DEBUGLEVEL_MIN, DEBUGLEVEL_MAX
	);
}

/** Uses getopt() to parse the command line and set configuration values
 */
void parse_commandline(int argc, char **argv)
{
	int c;

	s_config *config = config_get_config();

	while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vi:r:64"))) {

		switch(c) {

		case 'h':
			usage();
			exit(1);
			break;

		case 'c':
			if (optarg) {
				strncpy(config->configfile, optarg, sizeof(config->configfile)-1);
			}
			break;

		case 'w':
			if (optarg) {
				free(config->ndsctl_sock);
				config->ndsctl_sock = safe_strdup(optarg);
			}
			break;

		case 'f':
			config->daemon = 0;
			break;

		case 'd':
			if (set_debuglevel(optarg)) {
				printf("无法将日志详细级别设置为【%d】\n", atoi(optarg));
				exit(1);
			}
			break;

		case 's':
			config->log_syslog = 1;
			break;

		case 'v':
			printf("这是 Nodogsplash 版本 " VERSION "\n");
			exit(1);
			break;

		case 'r':
			if (optarg) {
				free(config->webroot);
				config->webroot = safe_strdup(optarg);
			}
			break;

		case '4':
			config->ip6 = 0;
			break;

		case '6':
			printf("尚不支持 IPv6 ！\n");
			exit(1);
			config->ip6 = 1;
			break;

		default:
			usage();
			exit(1);
			break;
		}
	}
}
