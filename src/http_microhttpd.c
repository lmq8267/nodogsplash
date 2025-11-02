/************************************************************************\
 * This program is free software; you can redistribute it and/or	*
 * modify it under the terms of the GNU General Public License as	*
 * published by the Free:Software Foundation; either version 2 of	*
 * the License, or (at your option) any later version.			*
 *									*
 * This program is distributed in the hope that it will be useful,	*
 * but WITHOUT ANY WARRANTY; without even the implied warranty of	*
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the		*
 * GNU General Public License for more details.				*
\************************************************************************/

/** @internal
 * @file http_microhttpd.c
 * @brief a httpd implementation using libmicrohttpd
 * @author Copyright (C) 2015 Alexander Couzens <lynxis@fe80.eu>
 * @author Copyright (C) 2023 Moritz Warning <moritzwarning@web.de>
 */

#define _GNU_SOURCE

#include <microhttpd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include "client_list.h"
#include "conf.h"
#include "common.h"
#include "debug.h"
#include "auth.h"
#include "http_microhttpd.h"
#include "http_microhttpd_utils.h"
#include "fw_iptables.h"
#include "mimetypes.h"
#include "path.h"
#include "safe.h"
#include "template.h"
#include "util.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* how much memory we reserve for extending template variables */
#define TMPLVAR_SIZE 4096

/* Max length of a query string QUERYMAXLEN in bytes defined in common.h */

/* Max dynamic html page size HTMLMAXSIZE in bytes defined in common.h */

int get_client_ip(char *ip, struct MHD_Connection *connection);  
int get_client_mac(char *mac, const char *ip);  
static int is_ipv4_address(const char *ip);
typedef void (*arp_entry_callback)(const char *ip, const char *mac, void *user_data);  
static int scan_arp_table_by_interface(const char *interface, arp_entry_callback callback, void *user_data);  
static void add_arp_device_to_client_list(const char *ip, const char *mac, void *user_data);  
void fw_refresh_client_list(void);
extern pthread_mutex_t config_mutex;
static t_client *add_client(const char mac[], const char ip[]);
static int authenticated(struct MHD_Connection *connection, const char *url, t_client *client);
static int preauthenticated(struct MHD_Connection *connection, const char *url, t_client *client);
static int authenticate_client(struct MHD_Connection *connection, const char *redirect_url, t_client *client);
static enum MHD_Result get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
static int serve_file(struct MHD_Connection *connection, t_client *client, const char *url);
static int show_splashpage(struct MHD_Connection *connection, t_client *client);
static int show_statuspage(struct MHD_Connection *connection, t_client *client);
static int encode_and_redirect_to_splashpage(struct MHD_Connection *connection, const char *originurl, const char *querystr);
static int redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *host, const char *url);
static enum MHD_Result send_error(struct MHD_Connection *connection, int error);
static int send_redirect_temp(struct MHD_Connection *connection, const char *url);
static int send_refresh(struct MHD_Connection *connection);
static int is_foreign_hosts(const char *host);
static int is_splashpage(const char *host, const char *url);
static const char *get_redirect_url(struct MHD_Connection *connection);
static const char *lookup_mimetype(const char *filename);

static int check_admin_auth(struct MHD_Connection *connection) {  
    s_config *config = config_get_config();  
    const char *token = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "admin_token");  
    char ip[INET6_ADDRSTRLEN+1];  
    char mac[18];  
      
    // 获取操作者的 IP 和 MAC  
    if (get_client_ip(ip, connection) != 0) {  
        strcpy(ip, "未知");  
    }  
      
    if (get_client_mac(mac, ip) != 0) {  
        strcpy(mac, "未知");  
    }  
      
    if (!token) {  
        // 记录令牌缺失的日志  
        debug(LOG_WARNING, "管理操作认证失败 - 操作者【%s - %s】令牌为空", ip, mac);  
        return 1;  // 令牌缺失  
    }  
      
    if (!config->admin_token || strcmp(token, config->admin_token) != 0) {  
        // 记录令牌错误的日志,包括使用的错误令牌  
        debug(LOG_WARNING, "管理操作认证失败 - 操作者【%s - %s】使用的令牌:【%s】",   
              ip, mac, token);  
        return 2;  // 令牌错误  
    }  
      
    // 记录认证成功的日志  
    debug(LOG_INFO, "管理操作认证成功 - 操作者【%s - %s】", ip, mac);  
    return 0;  // 验证成功  
}

static void log_admin_operation(struct MHD_Connection *connection, const char *operation, const char *target, int result) {  
    char ip[INET6_ADDRSTRLEN+1];  
    char mac[18];  
    const char *result_str = result == 0 ? "成功" : "失败";
    const char *op_cn; 
    
    // 根据 operation 的英文值映射成中文名称
    if (strcmp(operation, "auth") == 0) {
        op_cn = "认证";
    } else if (strcmp(operation, "deauth") == 0) {
        op_cn = "取消认证";
    } else if (strcmp(operation, "trust") == 0) {
        op_cn = "信任";
    } else if (strcmp(operation, "untrust") == 0) {
        op_cn = "取消信任";
    } else if (strcmp(operation, "block") == 0) {
        op_cn = "拉黑";
    } else if (strcmp(operation, "unblock") == 0) {
        op_cn = "取消拉黑";
    } else if (strcmp(operation, "allow") == 0) {
        op_cn = "允许";
    } else if (strcmp(operation, "unallow") == 0) {
        op_cn = "取消允许";
    } else {
        op_cn = operation;  // 如果没有匹配，保持原样
    } 
      
    // 获取操作者的 IP  
    if (get_client_ip(ip, connection) != 0) {  
        strcpy(ip, "未知");  
    }  
      
    // 获取操作者的 MAC  
    if (get_client_mac(mac, ip) != 0) {  
        strcpy(mac, "未知");  
    }  
      
    // 记录日志  
    debug(LOG_NOTICE, "管理操作 - 执行:【%s [%s]=>%s】操作者:【%s - %s】",   
          op_cn, target ? target : "无", result_str, ip, mac);  
}

/**  
 * 格式化字节数为人类可读格式 (T/G/M/K)  
 * 避免 buffer overflow  
 */  
static void format_bytes(unsigned long long bytes, char *buf, size_t buf_size)  
{  
	if (buf == NULL || buf_size < 32) {  
		return;  
	}  
	  
	double size = (double)bytes;  
	const char *units[] = {"B", "K", "M", "G", "T"};  
	int unit_index = 0;  
	  
	while (size >= 1024.0 && unit_index < 4) {  
		size /= 1024.0;  
		unit_index++;  
	}  
	  
	if (unit_index == 0) {  
		snprintf(buf, buf_size, "%llu %s", bytes, units[unit_index]);  
	} else {  
		snprintf(buf, buf_size, "%.2f %s", size, units[unit_index]);  
	}  
} 

/**  
 * @brief 检查是否为 IPv4 地址  
 * @param ip IP 地址字符串  
 * @return 1 是 IPv4, 0 不是  
 */  
static int  
is_ipv4_address(const char *ip)  
{  
	struct sockaddr_in sa;  
	return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;  
} 

/**  
 * @brief 从 ARP 表获取指定接口上的所有设备  
 * @param interface 网关接口名称(如 "br0")  
 * @param callback 回调函数,对每个找到的 IP-MAC 对调用  
 * @param user_data 传递给回调函数的用户数据  
 * @return 找到的设备数量  
 */  
typedef void (*arp_entry_callback)(const char *ip, const char *mac, void *user_data);  
  
static int  
scan_arp_table_by_interface(const char *interface, arp_entry_callback callback, void *user_data)  
{  
	char line[255] = {0};  
	char ip[INET6_ADDRSTRLEN] = {0};  
	char dev[32] = {0};  
	char mac[18] = {0};  
	FILE *stream;  
	int count = 0;  
	  
	if (!interface || !callback) {  
		return 0;  
	}  
	  
	stream = popen("ip neigh show", "r");  
	if (!stream) {  
		debug(LOG_ERR, "无法执行 ip neigh show 命令扫描设备添加到客户端列表！");  
		return 0;  
	}  
	  
	while (fgets(line, sizeof(line) - 1, stream) != NULL) {  
		// 解析格式: IP dev INTERFACE lladdr MAC STATE  
		// 跳过 FAILED 状态的条目(没有 MAC 地址)  
		if (strstr(line, "FAILED")) {  
			continue;  
		}  
		  
		// 解析 IP、接口名和 MAC 地址  
		if (sscanf(line, "%s dev %s %*s %17[A-Fa-f0-9:]", ip, dev, mac) == 3) {  
			// 检查是否是指定的接口  
			if (strcmp(dev, interface) != 0) {  
				continue;  
			}  
			  
			// 只处理 IPv4 地址,跳过所有 IPv6 地址  
			if (!is_ipv4_address(ip)) {  
				// debug(LOG_DEBUG, "跳过 IPv6 地址的设备: %s", ip);  
				continue;  
			}  
			  
			callback(ip, mac, user_data);  
			count++;  
		}  
	}  
	  
	pclose(stream);  
	// debug(LOG_DEBUG, "在接口【%s】上找到 %d 个 ARP 条目", interface, count);  
	return count;  
}  
  
/**  
 * @brief ARP 扫描回调函数 - 添加设备到客户端列表  
 */  
static void  
add_arp_device_to_client_list(const char *ip, const char *mac, void *user_data)  
{  
	t_client *existing;  
	  
	if (!ip || !mac) {  
		return;  
	}  
	  
	// 检查是否已在客户端列表中  
	LOCK_CLIENT_LIST();  
	existing = client_list_find(mac, ip);  
	  
	if (!existing) {  
		// 不在列表中,添加该客户端  
		t_client *new_client = client_list_add_client(mac, ip);  
		if (new_client) {  
			debug(LOG_INFO, "从 ARP 表添加设备IP【%s】MAC【%s】状态【%s】到客户端列表成功！ ",   
			      ip, mac, fw_connection_state_as_string(new_client->fw_connection_state));  
		} else {  
			debug(LOG_WARNING, "从 ARP 表添加设备IP【%s】MAC【%s】到客户端列表失败！", ip, mac);  
		}  
	}  
	  
	UNLOCK_CLIENT_LIST();  
}

static int admin_get_clients(struct MHD_Connection *connection) {  
    t_client *client;  
    struct MHD_Response *response;  
    char *json_str;  
    int ret;  
    int auth_result;
    time_t now = time(NULL); 
	s_config *config;
      
    //log_admin_operation(connection, "刷新客户端列表", NULL, 0);
    auth_result = check_admin_auth(connection);  
    if (auth_result != 0) {  
        const char *error_msg;  
        if (auth_result == 1) {  
            error_msg = "{\"success\":false,\"error\":\"管理员令牌为空\"}";  
        } else {  
            error_msg = "{\"success\":false,\"error\":\"管理员令牌错误\"}";  
        }  
        response = MHD_create_response_from_buffer(strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);  
        MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");  
        ret = MHD_queue_response(connection, 403, response);  
        MHD_destroy_response(response);  
        return ret;  
    }  
      
    // 更新流量计数和会话状态  
    iptables_fw_counters_update();  
    fw_refresh_client_list();  // 新增:检查到期时间并更新状态 

	 // 扫描 ARP 表并添加网关接口上的所有设备到客户端列表  
    config = config_get_config();  
    if (config && config->gw_interface) {  
        debug(LOG_DEBUG, "开始扫描网关接口【%s】上的 ARP 条目，检测是否已在客户端列表中...", config->gw_interface);  
        scan_arp_table_by_interface(config->gw_interface, add_arp_device_to_client_list, NULL);  
    }  
      
    LOCK_CLIENT_LIST(); 

	// 计算所需缓冲区大小  
	int client_count = get_client_list_length();  
	// 每个客户端约 500 字节,加上 4KB 的元数据和安全余量  
	size_t buffer_size = (client_count * 500) + 4096;  
	if (buffer_size < 16384) {  
    	buffer_size = 16384;  // 最小 16KB  
	}
      
    // 构建 JSON 响应  
    json_str = malloc(buffer_size);  
    if (!json_str) {  
        UNLOCK_CLIENT_LIST();  
        return send_error(connection, 500);  
    }  
      
    config = config_get_config();  
      
    // 在 JSON 开头添加配置信息  
    int offset = snprintf(json_str, buffer_size,   
        "{\"macmechanism\":\"%s\",\"客户端数量\":%d,\"客户端信息\":{",   
        config->macmechanism == MAC_ALLOW ? "allow" : "block",  
        get_client_list_length());  
      
    client = client_get_first_client();  
    int first = 1;  
      
    while (client != NULL) {  
        if (!first) {  
            offset += snprintf(json_str + offset, buffer_size - offset, ",");  
        }  
        first = 0;  
          
        // 计算剩余时间  
        long remaining = 0;  
        if (client->session_end > 0) {  
            remaining = client->session_end - now;  
            if (remaining < 0) remaining = 0;  
        }  
          
        // 判断各种状态  
        int is_authenticated = (client->fw_connection_state == FW_MARK_AUTHENTICATED);  
        int is_trusted = (client->fw_connection_state == FW_MARK_TRUSTED);  
        int is_blocked = (client->fw_connection_state == FW_MARK_BLOCKED);  
          
        // 检查是否在允许列表中  
        s_config *config = config_get_config();  
        int is_allowed = 0;  
        t_MAC *pa = config->allowedmaclist;  
        while (pa != NULL) {  
            if (strcmp(pa->mac, client->mac) == 0) {  
                is_allowed = 1;  
                break;  
            }  
            pa = pa->next;  
        }  
        // 格式化上传下载数据  
    	char download_str[64];  
    	char upload_str[64];  
    	format_bytes(client->counters.incoming, download_str, sizeof(download_str));  
    	format_bytes(client->counters.outgoing, upload_str, sizeof(upload_str));  
         
        
        offset += snprintf(json_str + offset, buffer_size - offset,  
            "\"%s\":{\"客户端ID\":%lu,\"主机名\":\"%s\",\"IP地址\":\"%s\",\"MAC地址\":\"%s\","  
            "\"加入时间\":%lld,\"最后活跃时间\":%lld,\"会话持续时间\":%lld,"  
            "\"token\":\"%s\",\"状态\":\"%s\",\"已下载\":\"%s\",\"已上传\":\"%s\","  
            "\"会话结束时间\":%lld,\"剩余时间\":%ld,"  
            "\"已认证\":%d,\"已信任\":%d,\"已拉黑\":%d,\"已允许\":%d}",  
            client->mac,  
            client->id,
            client->hostname ? client->hostname : "未知",  
            client->ip,  
            client->mac,  
            (long long)client->session_start,  
            (long long)client->counters.last_updated,  
            (long long)(client->session_start ? now - client->session_start : 0),  
            client->token ? client->token : "none",  
            fw_connection_state_as_string(client->fw_connection_state),  
            download_str,    
            upload_str,  
            (long long)client->session_end,  
            remaining,  
            is_authenticated,  
            is_trusted,  
            is_blocked,  
            is_allowed  
        );  
          
        client = client->next;  
    }  
      
    offset += snprintf(json_str + offset, buffer_size - offset, "}}");  
      
    UNLOCK_CLIENT_LIST();  
      
    response = MHD_create_response_from_buffer(strlen(json_str), json_str, MHD_RESPMEM_MUST_FREE);  
    MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");  
    ret = MHD_queue_response(connection, 200, response);  
    MHD_destroy_response(response);  
      
    return ret;  
}

static int admin_client_action(struct MHD_Connection *connection, const char *action) {  
    const char *identifier;  
    t_client *client;  
    int result = -1;  
    struct MHD_Response *response;  
    const char *resp_msg;  
    int ret;
    int auth_result;  
      
    auth_result = check_admin_auth(connection);  
    if (auth_result != 0) {  
        // 记录认证失败  
        log_admin_operation(connection, action, identifier, -1);  
          
        const char *error_msg;  
        if (auth_result == 1) {  
            error_msg = "{\"success\":false,\"error\":\"管理员令牌缺失\"}";  
        } else {  
            error_msg = "{\"success\":false,\"error\":\"管理员令牌错误\"}";  
        }  
        response = MHD_create_response_from_buffer(strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);  
        MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");  
        ret = MHD_queue_response(connection, 403, response);  
        MHD_destroy_response(response);  
        return ret;  
    }  
      
    identifier = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "client");  
    if (!identifier) {  
        return send_error(connection, 400);  
    }  
      
    LOCK_CLIENT_LIST();  
    client = client_list_find_by_any(identifier, identifier, identifier);  
      
    if (!client) {  
        UNLOCK_CLIENT_LIST();  
        resp_msg = "{\"success\":false,\"error\":\"未找到此设备\"}";  
        response = MHD_create_response_from_buffer(strlen(resp_msg), (void*)resp_msg, MHD_RESPMEM_PERSISTENT);  
        MHD_add_response_header(response, "Content-Type", "application/json");  
        ret = MHD_queue_response(connection, 404, response);  
        MHD_destroy_response(response);  
        return ret;  
    }  
      
    if (strcmp(action, "auth") == 0) {  
        result = auth_client_auth_nolock(client->id, "admin_auth");  
    } else if (strcmp(action, "deauth") == 0) {  
        unsigned long id = client->id;  
        UNLOCK_CLIENT_LIST();  
        result = auth_client_deauth(id, "admin_deauth");  
        LOCK_CLIENT_LIST();  
    } else if (strcmp(action, "trust") == 0) {  
        UNLOCK_CLIENT_LIST();  
        result = auth_client_trust(client->mac);  
        LOCK_CLIENT_LIST();  
    } else if (strcmp(action, "untrust") == 0) {  
        UNLOCK_CLIENT_LIST();  
        result = auth_client_untrust(client->mac);  
        LOCK_CLIENT_LIST();  
    } else if (strcmp(action, "block") == 0) {  
        UNLOCK_CLIENT_LIST();  
        result = auth_client_block(client->mac);  
        LOCK_CLIENT_LIST();  
    } else if (strcmp(action, "unblock") == 0) {  
        UNLOCK_CLIENT_LIST();  
        result = auth_client_unblock(client->mac);  
        LOCK_CLIENT_LIST();  
    } else if (strcmp(action, "allow") == 0) { 
    	UNLOCK_CLIENT_LIST();  
    	result = auth_client_allow(client->mac);  
    	LOCK_CLIENT_LIST();  
    } else if (strcmp(action, "unallow") == 0) { 
    	UNLOCK_CLIENT_LIST();  
    	result = auth_client_unallow(client->mac);  
    	LOCK_CLIENT_LIST();  
    }
      
    UNLOCK_CLIENT_LIST();
    
    // 记录操作日志  
    char target_info[128];  
    snprintf(target_info, sizeof(target_info), "%s - %s", client->ip, client->mac);  
    log_admin_operation(connection, action, target_info, result);  
      
    if (result == 0) {  
        resp_msg = "{\"success\":true}";  
    } else {  
        resp_msg = "{\"success\":false,\"error\":\"操作失败\"}";  
    }  
      
    response = MHD_create_response_from_buffer(strlen(resp_msg), (void*)resp_msg, MHD_RESPMEM_PERSISTENT);  
    MHD_add_response_header(response, "Content-Type", "application/json");  
    ret = MHD_queue_response(connection, result == 0 ? 200 : 500, response);  
    MHD_destroy_response(response);  
      
    return ret;  
}

static int admin_set_duration(struct MHD_Connection *connection) {  
    const char *identifier;  
    const char *duration_str;  
    t_client *client;  
    int duration;  
    struct MHD_Response *response;  
    const char *resp_msg;  
    int ret;  
    time_t now = time(NULL);  
    int auth_result;  
      
    auth_result = check_admin_auth(connection);  
    if (auth_result != 0) {  
          
        const char *error_msg;  
        if (auth_result == 1) {  
            error_msg = "{\"success\":false,\"error\":\"管理员令牌缺失\"}";  
        } else {  
            error_msg = "{\"success\":false,\"error\":\"管理员令牌错误\"}";  
        }  
        response = MHD_create_response_from_buffer(strlen(error_msg), (void*)error_msg, MHD_RESPMEM_PERSISTENT);  
        MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");  
        ret = MHD_queue_response(connection, 403, response);  
        MHD_destroy_response(response);  
        return ret;  
    } 
      
    identifier = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "client");  
    duration_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "duration");  
      
    if (!identifier || !duration_str) {  
        return send_error(connection, 400);  
    }  
      
    duration = atoi(duration_str);  
    if (duration < 0) {  
        return send_error(connection, 400);  
    }  
      
    LOCK_CLIENT_LIST();  
    client = client_list_find_by_any(identifier, identifier, identifier);  
      
    if (!client) {  
        UNLOCK_CLIENT_LIST();  
        resp_msg = "{\"success\":false,\"error\":\"未找到此设备\"}";  
        response = MHD_create_response_from_buffer(strlen(resp_msg), (void*)resp_msg, MHD_RESPMEM_PERSISTENT);  
        MHD_add_response_header(response, "Content-Type", "application/json");  
        ret = MHD_queue_response(connection, 404, response);  
        MHD_destroy_response(response);  
        return ret;  
    }  
    
    if (client->fw_connection_state != FW_MARK_AUTHENTICATED) {  
    	UNLOCK_CLIENT_LIST();  
    	resp_msg = "{\"success\":false,\"error\":\"只能对已认证客户端设置上网时长\"}";  
    	response = MHD_create_response_from_buffer(strlen(resp_msg), (void*)resp_msg, MHD_RESPMEM_PERSISTENT);  
    	MHD_add_response_header(response, "Content-Type", "application/json");  
    	ret = MHD_queue_response(connection, 400, response);  
    	MHD_destroy_response(response);  
    	return ret;  
    }
  
    if (duration > 0) {  
        client->session_end = now + duration;  
          
        // 如果设置的时长已经到期,立即踢下线  
        if (client->session_end <= now) {  
            s_config *config = config_get_config();  
            if (config->session_timeout_block > 0) {  
                auth_change_state(client, FW_MARK_BLOCKED, "timeout_deauth_block");  
            } else {  
                auth_change_state(client, FW_MARK_PREAUTHENTICATED, "timeout_deauth");  
            }  
        }  
    } else {  
        client->session_end = 0;  
    }  
      
    UNLOCK_CLIENT_LIST();
    
    // 记录操作日志  
    char target_info[256];  
    snprintf(target_info, sizeof(target_info), "%s - %s 时长:%d秒", client->mac, client->ip, duration);  
    log_admin_operation(connection, "设置上网时长", target_info, 0);  
      
    resp_msg = "{\"success\":true}";  
    response = MHD_create_response_from_buffer(strlen(resp_msg), (void*)resp_msg, MHD_RESPMEM_PERSISTENT);  
    MHD_add_response_header(response, "Content-Type", "application/json");  
    ret = MHD_queue_response(connection, 200, response);  
    MHD_destroy_response(response);  
      
    return ret;  
}

/* Get client settings from binauth */
static int do_binauth(struct MHD_Connection *connection, const char *binauth, t_client *client,
	int *seconds_ret, int *upload_ret, int *download_ret)
{
	char username_enc[64] = {0};
	char password_enc[64] = {0};
	const char *username;
	const char *password;
	char msg[255] = {0};
	int seconds;
	int upload;
	int download;
	int rc;

	username = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "username");
	password = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "password");

	if ((username && uh_urlencode(username_enc, sizeof(username_enc), username, strlen(username)) == -1)
		|| (password && uh_urlencode(password_enc, sizeof(password_enc), password, strlen(password)) == -1)) {
		debug(LOG_ERR, "无法对 binauth 的用户名和密码进行编码");
		return -1;
	}

	rc = execute_ret(msg, sizeof(msg) - 1, "%s auth_client %s '%s' '%s'",
		binauth, client->mac, username_enc, password_enc);

	if (rc != 0) {
		return -1;
	}

	rc = sscanf(msg, "%d %d %d", &seconds, &upload, &download);

	// store assigned parameters
	switch (rc) {
		case 3:
			*download_ret = MAX(download, 0);
		case 2:
			*upload_ret = MAX(upload, 0);
		case 1:
			*seconds_ret = MAX(seconds, 0);
		case 0:
			break;
		default:
			return -1;
	}

	return 0;
}

struct get_query_data {
	bool error;
	size_t capacity;
	size_t size;
	char *query;
};

static enum MHD_Result get_query_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	struct get_query_data *data = cls;
	const char separator = data->size ? '&' : '?';
	const char *format = value ? "%c%s=%s" : "%c%s";
	const int left = data->capacity - data->size;

	if (key != NULL && kind == MHD_GET_ARGUMENT_KIND) {
		// append '?foo=bar', '&foo=bar', '?foo', '&foo'
		int n = snprintf(&data->query[data->size], left, format, separator, key, value);
		if (n >= left) {
			data->query[data->size] = '\0';
			data->error = true;
			return MHD_NO;
		} else {
			data->size += n;
		}
	}

	// continue iteration
	return MHD_YES;
}

static int is_foreign_hosts(const char *host)
{
	s_config *config = config_get_config();

	/* we serve all request without a host entry as well we serve all request
	 * going to our gw_address/gw_http_name */
	if (host == NULL)
		return 0;

	if (!strcmp(host, config->gw_http_name))
		return 0;

	if (!strcmp(host, config->gw_http_name_port))
		return 0;

	return 1;
}

static int is_splashpage(const char *host, const char *url)
{
	char our_host[MAX_HOSTPORTLEN];
	s_config *config = config_get_config();
	snprintf(our_host, MAX_HOSTPORTLEN, "%s", config->gw_address);

	if (host == NULL) {
		/* no hostname given
		 * '/' -> splash
		 * '' -> splash [is this even possible with MHD?
		 */
		if (strlen(url) == 0 ||
				!strcmp("/", url)) {
			return 1;
		}
	} else {
		/* hostname give - check if it's our hostname */

		if (is_foreign_hosts(host)) {
			/* hostname isn't ours */
			return 0;
		}

		/* '/' -> splash
		 * '' -> splash
		 */
		if (strlen(url) == 0 ||
				!strcmp("/", url)) {
			return 1;
		}

		if (strlen(url) > 0 &&
				!strcmp(config->splashpage, url+1)) {
			return 1;
		}
	}
	/* doesnt hit one of our rules - this isn't the splashpage */
	return 0;
}


/* @brief Get client mac by ip address from neighbor cache */
int
get_client_mac(char mac[18], const char req_ip[])
{
	char line[255] = {0};
	char ip[64];
	FILE *stream;
	int len;

	len = strlen(req_ip);

	if ((len + 2) > sizeof(ip)) {
		return -1;
	}

	// Extend search string by one space
	memcpy(ip, req_ip, len);
	ip[len] = ' ';
	ip[len+1] = '\0';

	stream = popen("ip neigh show", "r");
	if (!stream) {
		return -1;
	}

	while (fgets(line, sizeof(line) - 1, stream) != NULL) {
		if (0 == strncmp(line, ip, len + 1)) {
			if (1 == sscanf(line, "%*s %*s %*s %*s %17[A-Fa-f0-9:] ", mac)) {
				pclose(stream);
				return 0;
			}
		}
	}

	pclose(stream);

	return -1;
}

/**
 * @brief get_client_ip
 * @param connection
 * @return ip address - must be freed by caller
 */
int
get_client_ip(char ip_addr[INET6_ADDRSTRLEN], struct MHD_Connection *connection)
{
	const union MHD_ConnectionInfo *connection_info;
	const struct sockaddr *client_addr;
	const struct sockaddr_in *addrin;
	const struct sockaddr_in6 *addrin6;

	if (!(connection_info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS))) {
		return -1;
	}

	/* cast required for legacy MHD API < 0.9.6*/
	client_addr = (const struct sockaddr *) connection_info->client_addr;
	addrin = (const struct sockaddr_in *) client_addr;
	addrin6 = (const struct sockaddr_in6 *) client_addr;

	switch (client_addr->sa_family) {
	case AF_INET:
		if (inet_ntop(AF_INET, &addrin->sin_addr, ip_addr, INET_ADDRSTRLEN)) {
			return 0;
		}
		break;

	case AF_INET6:
		if (inet_ntop(AF_INET6, &addrin6->sin6_addr, ip_addr, INET6_ADDRSTRLEN)) {
			return 0;
		}
		break;
	}

	return -1;
}

/**
 * @brief libmicrohttpd_cb called when the client does a request to this server
 * @param cls unused
 * @param connection - client connection
 * @param url - which url was called
 * @param method - POST / GET / ...
 * @param version http 1.0 or 1.1
 * @param upload_data - unused
 * @param upload_data_size - unused
 * @param ptr - unused
 * @return
 */
enum MHD_Result
libmicrohttpd_cb(void *cls,
				struct MHD_Connection *connection,
				const char *_url,
				const char *method,
				const char *version,
				const char *upload_data, size_t *upload_data_size, void **ptr)
{

	t_client *client;
	char ip[INET6_ADDRSTRLEN+1];
	char mac[18];
	char url[PATH_MAX] = { 0 };
	int rc = 0;

	/* path sanitaze */
	buffer_path_simplify(url, _url);

	debug(LOG_DEBUG, "访问请求：方法=【%s】URL=【%s】", method, url);

	/* only allow get */
	if (0 != strcmp(method, "GET")) {
		debug(LOG_DEBUG, "不支持的 HTTP 方法:【 %s】", method);
		return send_error(connection, 503);
	}

	/* switch between preauth, authenticated */
	/* - always - set caching headers
	 * a) possible implementation - redirect first and serve them using a tempo redirect
	 * b) serve direct
	 * should all requests redirected? even those to .css, .js, ... or respond with 404/503/...
	 */
	if (strncmp(url, "/admin/clients", 14) == 0) {  
    		return admin_get_clients(connection);  
	}  
  
	if (strncmp(url, "/admin/auth", 11) == 0) {  
    		return admin_client_action(connection, "auth");  
	}  
  
	if (strncmp(url, "/admin/deauth", 13) == 0) {  
    		return admin_client_action(connection, "deauth");  
	}  
  
	if (strncmp(url, "/admin/trust", 12) == 0) {  
    		return admin_client_action(connection, "trust");  
	}  
  
	if (strncmp(url, "/admin/untrust", 14) == 0) {  
    		return admin_client_action(connection, "untrust");  
	}  

	if (strncmp(url, "/admin/allow", 12) == 0) {  
    		return admin_client_action(connection, "allow");  
	}  
  
	if (strncmp(url, "/admin/unallow", 14) == 0) {  
    		return admin_client_action(connection, "unallow");  
	}
  
	if (strncmp(url, "/admin/block", 12) == 0) {  
    		return admin_client_action(connection, "block");  
	}

	if (strncmp(url, "/admin/unblock", 14) == 0) {  
    		return admin_client_action(connection, "unblock");  
	}  
  
	if (strncmp(url, "/admin/set_duration", 19) == 0) {  
    		return admin_set_duration(connection);  
	}  
  
	s_config *config = config_get_config();  
	char admin_url[PATH_MAX];  
	snprintf(admin_url, PATH_MAX, "/%s", config->adminpage);  
  
	if (strcmp(url, admin_url) == 0 || strcmp(url, "/admin") == 0) {  
    		return serve_file(connection, NULL, config->adminpage);  
	}
	
	rc = get_client_ip(ip, connection);
	if (rc != 0) {
		return send_error(connection, 503);
	}

	rc = get_client_mac(mac, ip);
	if (rc != 0) {
		return send_error(connection, 503);
	}

	client = client_list_find(mac, ip);
	if (!client) {
		client = add_client(mac, ip);
		if (!client) {
			return send_error(connection, 503);
		}
	}

	if (client && (client->fw_connection_state == FW_MARK_AUTHENTICATED ||
			client->fw_connection_state == FW_MARK_TRUSTED)) {
		/* client already authed - dangerous!!! This should never happen */
		return authenticated(connection, url, client);
	}

	return preauthenticated(connection, url, client);
}

/**
 * @brief check if url contains authdir
 * @param url
 * @param authdir
 * @return
 *
 * url must look ("/%s/", authdir) to match this
 */
static int check_authdir_match(const char *url, const char *authdir)
{
	if (strlen(url) != (2 + strlen(authdir)))
		return 0;

	if (strncmp(url + 1, authdir, strlen(authdir)))
		return 0;

	/* match */
	return 1;
}

/**
 * @brief try_to_authenticate
 * @param connection
 * @param client
 * @param host
 * @param url
 * @return
 */
static int try_to_authenticate(struct MHD_Connection *connection, t_client *client, const char *host, const char *url)
{
	s_config *config;
	const char *tok;

	/* a successful auth looks like
	 * http://192.168.42.1:2050/nodogsplash_auth/?redir=http%3A%2F%2Fberlin.freifunk.net%2F&tok=94c4cdd2
	 * when authaction -> http://192.168.42.1:2050/nodogsplash_auth/
	 */
	config = config_get_config();

	/* Check for authdir */
	if (check_authdir_match(url, config->authdir)) {
		tok = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "tok");
		debug(LOG_DEBUG, "客户端 token=【%s】传入 token=【%s】", client->token, tok );

		if (tok && !strcmp(client->token, tok)) {
			/* Token is valid */
			return 1;
		}
	}

	debug(LOG_WARNING, "Token 无效" );

/*	//TODO: do we need denydir?
	if (check_authdir_match(url, config->denydir)) {
		// matched to deauth
		return 0;
	}
*/

	return 0;
}

/**
 * @brief authenticate the client and redirect them
 * @param connection
 * @param ip_addr - needs to be freed
 * @param mac - needs to be freed
 * @param redirect_url - redirect the client to this url
 * @return
 */
static int authenticate_client(struct MHD_Connection *connection,
							const char *redirect_url,
							t_client *client)
{
	s_config *config = config_get_config();
	time_t now = time(NULL);
	int seconds = 60 * config->session_timeout;
	int upload = 0;
	int download = 0;
	int rc;
	char *query_str = NULL;
	int ret;

	if (config->binauth) {
		rc = do_binauth(connection, config->binauth, client, &seconds, &upload, &download);
		if (rc != 0) {
			safe_asprintf(&query_str, "?clientip=%s&gatewayname=%s&tok=%s", client->ip, config->gw_name, client->token);
			ret = encode_and_redirect_to_splashpage(connection, redirect_url, query_str);
			free(query_str);
			return ret;
		}
		rc = auth_client_auth(client->id, "client_auth");
	} else {
		rc = auth_client_auth(client->id, NULL);
	}

	if (rc != 0) {
		return send_error(connection, 503);
	}

	debug(LOG_NOTICE, "客户端【%s %s】已认证成功", client->mac, client->ip);

	/* set client values */
	client->download_limit = download;
	client->upload_limit = upload;
	client->session_start = now;

	if (seconds) {
		client->session_end = now + seconds;
	} else {
		client->session_end = 0;
	}

	if (redirect_url) {
		return send_redirect_temp(connection, redirect_url);
	} else {
		return send_error(connection, 200);
	}
}

/**
 * @brief authenticated - called for all request from authenticated clients.
 * @param connection
 * @param ip_addr
 * @param mac
 * @param url
 * @param client
 * @return
 *
 * It's unsual to received request from clients which are already authenticated.
 * Happens when the user:
 * - clicked in multiple windows on "accept" -> redirect to origin - no checking
 * - when the user reloaded a splashpage -> redirect to origin
 * - when a user calls deny url -> deauth it
 */
static int authenticated(struct MHD_Connection *connection,
						const char *url,
						t_client *client)
{
	s_config *config = config_get_config();
	const char *host = NULL;
	char redirect_to_us[128];

	MHD_get_connection_values(connection, MHD_HEADER_KIND, get_host_value_callback, &host);

	/* check if this is an late request meaning the user tries to get the internet, but ended up here,
	 * because the iptables rule came too late */
	if (is_foreign_hosts(host)) {
		/* might happen if the firewall rule isn't yet installed */
		return send_refresh(connection);
	}

	if (check_authdir_match(url, config->denydir)) {
		auth_client_deauth(client->id, "client_deauth");
		snprintf(redirect_to_us, sizeof(redirect_to_us), "http://%s/", config->gw_http_name);
		return send_redirect_temp(connection, redirect_to_us);
	}

	if (check_authdir_match(url, config->authdir)) {
		return show_statuspage(connection, client);
	}

	/* user doesn't want the splashpage or tried to auth itself */
	return serve_file(connection, client, url);
}

/**
 * @brief preauthenticated - called for all request of a client in this state.
 * @param connection
 * @param ip_addr
 * @param mac
 * @return
 */
static int preauthenticated(struct MHD_Connection *connection,
							const char *url,
							t_client *client)
{
	const char *host = NULL;
	const char *redirect_url;
	char *querystr = NULL;

	s_config *config = config_get_config();

	debug(LOG_DEBUG, "URL 地址:【%s】", url);

	MHD_get_connection_values(connection, MHD_HEADER_KIND, get_host_value_callback, &host);

	debug(LOG_DEBUG, "未认证用户 - 请求的主机是【%s】", host);
	debug(LOG_DEBUG, "未认证用户 - 请求的 URL 是【%s】", url);
	debug(LOG_DEBUG, "未认证用户 - 网关地址是【%s】", config->gw_address);
	debug(LOG_DEBUG, "未认证用户 - 网关端口是【%u】", config->gw_port);

	/* check if this is a redirect query with a foreign host as target */
	if (is_foreign_hosts(host)) {
		return redirect_to_splashpage(connection, client, host, url);
	}

	/* request is directed to us */
	/* check if client wants to be authenticated */
	if (check_authdir_match(url, config->authdir)) {
		/* Only the first request will redirected to config->redirectURL.
		 * When the client reloads a page when it's authenticated, it should be redirected
		 * to their origin url
		 */
		debug(LOG_DEBUG, "检测到认证目录 URL:【%s】", url);

		if (config->redirectURL) {
			redirect_url = config->redirectURL;
		} else {
			redirect_url = get_redirect_url(connection);
		}

		if (!try_to_authenticate(connection, client, host, url)) {
			/* user used an invalid token, redirect to splashpage but hold query "redir" intact */
			return encode_and_redirect_to_splashpage(connection, redirect_url, querystr);
		}

		return authenticate_client(connection, redirect_url, client);
	}

	if (is_splashpage(host, url)) {
		return show_splashpage(connection, client);
	}

	/* no special handling left - try to serve static content to the user */
	return serve_file(connection, client, url);
}

/**
 * @brief encode originurl and redirect the client to the splash page
 * @param connection
 * @param client
 * @param originurl
 * @return
 */
static int encode_and_redirect_to_splashpage(struct MHD_Connection *connection, const char *originurl, const char *querystr)
{
	char *splashpageurl = NULL;
	char encoded[QUERYMAXLEN] = {0};
	s_config *config;
	int ret;

	config = config_get_config();

	if (originurl) {
		if (uh_urlencode(encoded, sizeof(encoded), originurl, strlen(originurl)) == -1) {
			debug(LOG_WARNING, "无法编码 URL");
			/* not enough memory */
			return send_error(connection, 503);
		} else {
			debug(LOG_DEBUG, "原始 URL 地址：【%s】", originurl);
		}
	}

	safe_asprintf(&splashpageurl, "http://%s/%s?redir=%s",
			config->gw_http_name, config->splashpage, encoded);

	debug(LOG_DEBUG, "欢迎页 URL 地址:【%s】", splashpageurl);

	ret = send_redirect_temp(connection, splashpageurl);
	free(splashpageurl);
	return ret;
}

/**
 * @brief redirect_to_splashpage
 * @param connection
 * @param client
 * @param host
 * @param url
 * @return
 */
static int redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *host, const char *url)
{
	char *originurl = NULL;
	char query[QUERYMAXLEN] = { 0 };
	char *querystr = NULL;
	s_config *config = config_get_config();

	struct get_query_data data = {
		.error = false,
		.size = 0,
		.capacity = QUERYMAXLEN,
		.query = query,
	};

	// collect query
	if (MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, get_query_callback, &data) < 0 || data.error) {
		debug(LOG_DEBUG, "无法获取查询字符串 - 错误 503");
		/* not enough memory */
		return send_error(connection, 503);
	}

	debug(LOG_DEBUG, "查询字符串是【%s】", query);

	safe_asprintf(&querystr, "?clientip=%s&gatewayname=%s", client->ip, config->gw_name);
	safe_asprintf(&originurl, "http://%s%s%s", host, url, query);
	int ret = encode_and_redirect_to_splashpage(connection, originurl, querystr);
	free(originurl);
	free(querystr);
	return ret;
}


/**
 *	Add client making a request to client list.
 *	Return pointer to the client list entry for this client.
 *
 *	N.B.: This does not authenticate the client; it only makes
 *	their information available on the client list.
 */
static t_client *
add_client(const char *mac, const char *ip)
{
	t_client *client;

	LOCK_CLIENT_LIST();
	client = client_list_add_client(mac, ip);
	UNLOCK_CLIENT_LIST();

	return client;
}

int send_redirect_temp(struct MHD_Connection *connection, const char *url)
{
	struct MHD_Response *response;
	int ret;
	char *redirect = NULL;

	const char *redirect_body =
	"<!DOCTYPE html>"
	"<html lang='zh-CN'>"
	"<head>"
	"<meta charset='utf-8'>"
	"<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>"
	"<meta http-equiv='Pragma' content='no-cache'>"
	"<meta http-equiv='Expires' content='0'>"
	"<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
	"<title>页面跳转中...</title>"
	"<style>"
	"body, html {"
	"    margin: 0;"
	"    padding: 0;"
	"    width: 100%%;"
	"    height: 100%%;"
	"    font-family: 'Microsoft YaHei', 'SimHei', 'Arial', sans-serif;"
	"    background: linear-gradient(135deg, #1e3c72, #2a5298);"
	"    color: #fff;"
	"    display: flex;"
	"    justify-content: center;"
	"    align-items: center;"
	"}"
	".container {"
	"    background: rgba(255, 255, 255, 0.08);"
	"    backdrop-filter: blur(10px);"
	"    border-radius: 20px;"
	"    padding: 40px;"
	"    text-align: center;"
	"    max-width: 480px;"
	"    width: 90%%;"
	"    box-shadow: 0 5px 20px rgba(0,0,0,0.3);"
	"    animation: fadeIn 1.2s ease-in-out;"
	"}"
	"@keyframes fadeIn {"
	"    from { opacity: 0; transform: translateY(-20px); }"
	"    to { opacity: 1; transform: translateY(0); }"
	"}"
	"h1 {"
	"    font-size: 1.8rem;"
	"    color: #ffeb3b;"
	"    margin-bottom: 20px;"
	"}"
	".btn-continue {"
	"    display: inline-block;"
	"    text-decoration: none;"
	"    padding: 12px 30px;"
	"    border-radius: 10px;"
	"    background: linear-gradient(90deg, #4caf50, #81c784);"
	"    color: #fff;"
	"    font-weight: bold;"
	"    transition: transform 0.2s, box-shadow 0.2s;"
	"}"
	".btn-continue:hover {"
	"    transform: translateY(-3px);"
	"    box-shadow: 0 5px 15px rgba(0,0,0,0.3);"
	"}"
	".info {"
	"    margin-top: 15px;"
	"    font-size: 0.95rem;"
	"    color: #ddd;"
	"}"
	"</style>"
	"</head>"
	"<body>"
	"<div class='container'>"
	"    <h1>页面跳转中...</h1>"
	"    <p>系统正在为您重定向到目标页面：</p>"
	"    <div class='info'>%s</div>"
	"    <a href='%s' class='btn-continue'>点此立即前往</a>"
	"    <div class='info'>如果未自动跳转，请点击上方按钮。</div>"
	"</div>"
	"<script>"
	"setTimeout(function(){ window.location.href='%s'; }, 2000);"  // ✅ 2秒后自动跳转
	"</script>"
	"</body>"
	"</html>";

	safe_asprintf(&redirect, redirect_body, url, url, url);

	response = MHD_create_response_from_buffer(strlen(redirect), redirect, MHD_RESPMEM_MUST_FREE);
	if (!response) {
		return send_error(connection, 503);
	}

	// MHD_set_response_options(response, MHD_RF_HTTP_VERSION_1_0_ONLY, MHD_RO_END);
	MHD_add_response_header(response, "Location", url);
	MHD_add_response_header(response, "Connection", "close");
	ret = MHD_queue_response(connection, MHD_HTTP_TEMPORARY_REDIRECT, response);
	MHD_destroy_response(response);

	return ret;
}


/**
 * @brief get_url_from_query
 * @param connection
 * @param redirect_url as plaintext - not url encoded
 * @param redirect_url_len
 * @return NULL or redirect url
 */
static const char *get_redirect_url(struct MHD_Connection *connection)
{
	return MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "redir");
}

static int send_refresh(struct MHD_Connection *connection)
{
	struct MHD_Response *response = NULL;

	const char *refresh = "<html><meta http-equiv=\"refresh\" content=\"1\"><head/></html>";
	const char *mimetype = lookup_mimetype("foo.html");
	int ret;

	response = MHD_create_response_from_buffer(strlen(refresh), (char *)refresh, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, "Content-Type", mimetype);
	MHD_add_response_header (response, MHD_HTTP_HEADER_CONNECTION, "close");
	ret = MHD_queue_response(connection, 200, response);

	return ret;
}

static enum MHD_Result send_error(struct MHD_Connection *connection, int error)
{
	struct MHD_Response *response = NULL;
	// cannot automate since cannot translate automagically between error number and MHD's status codes
	// -- and cannot rely on MHD_HTTP_ values to provide an upper bound for an array
	const char *page_200 = "<html><header><title>已认证</title><body><h1>已认证</h1></body></html>";
	const char *page_400 = "<html><head><title>Error 400</title></head><body><h1>Error 400 - 错误请求！</h1></body></html>";
	const char *page_403 = "<html><head><title>Error 403</title></head><body><h1>Error 403 - 禁止访问！</h1></body></html>";
	const char *page_404 =
		"<!DOCTYPE html>"
		"<html lang='zh-CN'>"
		"<head>"
		"<meta charset='utf-8'>"
		"<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>"
		"<meta http-equiv='Pragma' content='no-cache'>"
		"<meta http-equiv='Expires' content='0'>"
		"<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
		"<title>错误 404 - 页面未找到</title>"
		"<style>"
		"body, html {"
		"    margin: 0;"
		"    padding: 0;"
		"    width: 100%%;"
		"    height: 100%%;"
		"    font-family: 'Microsoft YaHei', 'SimHei', 'Arial', sans-serif;"
		"    background: linear-gradient(135deg, #1e3c72, #2a5298);"
		"    color: #fff;"
		"    display: flex;"
		"    justify-content: center;"
		"    align-items: center;"
		"}"
		".container {"
		"    background: rgba(255, 255, 255, 0.08);"
		"    backdrop-filter: blur(10px);"
		"    border-radius: 20px;"
		"    padding: 40px;"
		"    text-align: center;"
		"    max-width: 500px;"
		"    width: 90%%;"
		"    box-shadow: 0 5px 20px rgba(0,0,0,0.3);"
		"    animation: fadeIn 1.2s ease-in-out;"
		"}"
		"@keyframes fadeIn {"
		"    from { opacity: 0; transform: translateY(-20px); }"
		"    to { opacity: 1; transform: translateY(0); }"
		"}"
		"h1 {"
		"    font-size: 2rem;"
		"    color: #ffeb3b;"
		"    margin-bottom: 20px;"
		"    text-shadow: 1px 1px 5px rgba(0,0,0,0.5);"
		"}"
		".desc {"
		"    font-size: 1rem;"
		"    color: #f8f9fa;"
		"    line-height: 1.8;"
		"    margin-bottom: 20px;"
		"}"
		".btn-back {"
		"    display: inline-block;"
		"    text-decoration: none;"
		"    padding: 10px 25px;"
		"    border-radius: 10px;"
		"    background: linear-gradient(90deg, #ff5722, #ff9800);"
		"    color: #fff;"
		"    font-weight: bold;"
		"    transition: transform 0.2s, box-shadow 0.2s;"
		"}"
		".btn-back:hover {"
		"    transform: translateY(-3px);"
		"    box-shadow: 0 5px 15px rgba(0,0,0,0.3);"
		"}"
		".copy-right {"
		"    margin-top: 25px;"
		"    font-size: 0.8rem;"
		"    color: #ccc;"
		"}"
		"</style>"
		"</head>"
		"<body>"
		"<div class='container'>"
		"    <h1>错误 404 - 页面未找到</h1>"
		"    <div class='desc'>请求的前端页面文件不存在，或 <strong>WebRoot</strong> 参数配置不正确。</div>"
		"    <div class='copy-right'>版权所有 &copy; Nodogsplash 贡献者 2004-2025</div>"
		"</div>"
		"</body>"
		"</html>";
	const char *page_500 = "<html><head><title>Error 500</title></head><body><h1>Error 500 - 内部服务器错误！</body></html>";
	const char *page_501 = "<html><head><title>Error 501</title></head><body><h1>Error 501 - 未实现！</h1></body></html>";
	const char *page_503 = "<html><head><title>Error 503</title></head><body><h1>Error 503 - 服务不可用！</h1></body></html>";

	const char *mimetype = lookup_mimetype("foo.html");

	int ret = MHD_NO;

	switch (error) {
	case 200:
		response = MHD_create_response_from_buffer(strlen(page_200), (char *)page_200, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, error, response);
		break;

	case 400:
		response = MHD_create_response_from_buffer(strlen(page_400), (char *)page_400, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
		break;

	case 403:
		response = MHD_create_response_from_buffer(strlen(page_403), (char *)page_403, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, response);
		break;

	case 404:
		response = MHD_create_response_from_buffer(strlen(page_404), (char *)page_404, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		break;

	case 500:
		response = MHD_create_response_from_buffer(strlen(page_500), (char *)page_500, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		break;

	case 501:
		response = MHD_create_response_from_buffer(strlen(page_501), (char *)page_501, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_IMPLEMENTED, response);
		break;
	case 503:
		response = MHD_create_response_from_buffer(strlen(page_503), (char *)page_503, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		break;
	}

	if (response)
		MHD_destroy_response(response);
	return ret;
}

/**
 * @brief get_host_value_callback safe Host into cls which is a char**
 * @param cls - a char ** pointer to our target buffer. This buffer will be alloc in this function.
 * @param kind - see doc of	MHD_KeyValueIterator's
 * @param key
 * @param value
 * @return MHD_YES or MHD_NO. MHD_NO means we found our item and this callback will not called again.
 */
static enum MHD_Result get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	const char **host = (const char **)cls;
	if (MHD_HEADER_KIND != kind) {
		*host = NULL;
		return MHD_NO;
	}

	if (!strcmp("Host", key)) {
		*host = value;
		return MHD_NO;
	}

	return MHD_YES;
}
  
/**  
 * 格式化会话到期时间   
 */  
static void format_sessionend(t_client *client, char *buf, size_t buf_size)  
{  
	if (buf == NULL || buf_size < 128) {  
		return;  
	}  
	  
	time_t now = time(NULL);  
	  
	// 检查是否为信任或允许状态  
	if (client->fw_connection_state == FW_MARK_TRUSTED) {  
		snprintf(buf, buf_size, "无限制");  
		return;  
	}  
	  
	// 检查是否被拉黑  
	if (client->fw_connection_state == FW_MARK_BLOCKED) {  
		snprintf(buf, buf_size, "已到期，请重新认证或联系管理员！");  
		return;  
	}  
	  
	// 如果 session_end 为 0 或未设置,表示无限制  
	if (client->session_end == 0) {  
		snprintf(buf, buf_size, "无限制");  
		return;  
	}  
	  
	// 格式化到期时间  
	struct tm *tm_info = localtime(&client->session_end);  
	char time_str[64];  
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);  
	  
	// 计算剩余时间  
	long long remaining = (long long)(client->session_end - now);  
	  
	if (remaining <= 0) {  
		snprintf(buf, buf_size, "已到期，请重新认证或联系管理员！");  
		return;  
	}  
	  
	// 转换为天时分秒  
	int days = remaining / (24 * 3600);  
	remaining %= (24 * 3600);  
	int hours = remaining / 3600;  
	remaining %= 3600;  
	int minutes = remaining / 60;  
	int seconds = remaining % 60;  
	  
	if (days > 0) {  
		snprintf(buf, buf_size, "%s (剩余 %d天%d时%d分%d秒)",   
			time_str, days, hours, minutes, seconds);  
	} else if (hours > 0) {  
		snprintf(buf, buf_size, "%s (剩余 %d时%d分%d秒)",   
			time_str, hours, minutes, seconds);  
	} else if (minutes > 0) {  
		snprintf(buf, buf_size, "%s (剩余 %d分%d秒)",   
			time_str, minutes, seconds);  
	} else {  
		snprintf(buf, buf_size, "%s (剩余 %d秒)",   
			time_str, seconds);  
	}  
}

/**
 * Replace variables in src and copy result to dst
 */
static void replace_variables(
	struct MHD_Connection *connection, t_client *client,
	char *dst, size_t dst_len, const char *src, size_t src_len)
{
	s_config *config = config_get_config();

	char nclients[12];
	char maxclients[12];
	char clientupload[64] = "0 B";  
	char clientdownload[64] = "0 B";  
	char sessionend[128] = "未知"; 
	char uptime[64];

	const char *redirect_url = NULL;
	char *denyaction = NULL;
	char *authaction = NULL;
	char *authtarget = NULL;

	if (client != NULL) {
		format_bytes(client->counters.outgoing, clientupload, sizeof(clientupload)); 
		format_bytes(client->counters.incoming, clientdownload, sizeof(clientdownload));  
		format_sessionend(client, sessionend, sizeof(sessionend));  
	}

	get_uptime_string(uptime);
	redirect_url = get_redirect_url(connection);

	sprintf(nclients, "%d", get_client_list_length());
	sprintf(maxclients, "%d", config->maxclients);
	safe_asprintf(&denyaction, "http://%s/%s/", config->gw_http_name, config->denydir);
	safe_asprintf(&authaction, "http://%s/%s/", config->gw_http_name, config->authdir);
	safe_asprintf(&authtarget, "http://%s/%s/?tok=%s&amp;redir=%s", config->gw_http_name, config->authdir, client->token, redirect_url);

	struct template vars[] = {
		{"authaction", authaction},
		{"denyaction", denyaction},
		{"authtarget", authtarget},
		{"clientip", client->ip},
		{"clientmac", client->mac},
		{"clientupload", clientupload},
		{"clientdownload", clientdownload},
		{"sessionend", sessionend},
		{"gatewaymac", config->gw_mac},
		{"gatewayname", config->gw_name},
		{"maxclients", maxclients},
		{"nclients", nclients},
		{"redir", redirect_url},
		{"tok", client->token},
		{"token", client->token},
		{"uptime", uptime},
		{"version", VERSION},
		{NULL, NULL}
	};

	tmpl_parse(vars, dst, dst_len, src, src_len);

	free(denyaction);
	free(authaction);
	free(authtarget);
}

static int show_templated_page(struct MHD_Connection *connection, t_client *client, const char *page)
{
	struct MHD_Response *response;
	s_config *config = config_get_config();
	int ret = -1;
	char filename[PATH_MAX];
	const char *mimetype;
	int size = 0, bytes = 0;
	int page_fd;
	char *page_result;
	char *page_tmpl;

	snprintf(filename, PATH_MAX, "%s/%s", config->webroot, page);

	page_fd = open(filename, O_RDONLY);
	if (page_fd < 0) {
		return send_error(connection, 404);
	}

	mimetype = lookup_mimetype(filename);

	/* input size */
	size = lseek(page_fd, 0, SEEK_END);
	lseek(page_fd, 0, SEEK_SET);

	/* we TMPLVAR_SIZE for template variables */
	page_tmpl = calloc(size, 1);
	if (page_tmpl == NULL) {
		close(page_fd);
		return send_error(connection, 503);
	}

	page_result = calloc(size + TMPLVAR_SIZE, 1);
	if (page_result == NULL) {
		close(page_fd);
		free(page_tmpl);
		return send_error(connection, 503);
	}

	while (bytes < size) {
		ret = read(page_fd, page_tmpl + bytes, size - bytes);
		if (ret < 0) {
			free(page_result);
			free(page_tmpl);
			close(page_fd);
			return send_error(connection, 503);
		}
		bytes += ret;
	}

	replace_variables(connection, client, page_result, size + TMPLVAR_SIZE, page_tmpl, size);

	response = MHD_create_response_from_buffer(strlen(page_result), (void *)page_result, MHD_RESPMEM_MUST_FREE);
	if (!response) {
		close(page_fd);
		return send_error(connection, 503);
	}

	MHD_add_response_header(response, "Content-Type", mimetype);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	free(page_tmpl);
	close(page_fd);

	return ret;
}

/**
 * @brief show_splashpage is called when the client clicked on Ok as well when the client doesn't know us yet.
 * @param connection
 * @param client
 * @return
 */
static int show_splashpage(struct MHD_Connection *connection, t_client *client)
{
	s_config *config = config_get_config();
	return show_templated_page(connection, client, config->splashpage);
}

/**
 * @brief show_statuspage is called when the client is already authenticated but still accesses the captive portal
 * @param connection
 * @param client
 * @return
 */
static int show_statuspage(struct MHD_Connection *connection, t_client *client)
{
	s_config *config = config_get_config();
	return show_templated_page(connection, client, config->statuspage);
}

/**
 * @brief return an extension like `csv` if file = '/bar/foobar.csv'.
 * @param filename
 * @return a pointer within file is returned. NULL can be returned as well as
 */
const char *get_extension(const char *filename)
{
	int pos = strlen(filename);
	while (pos > 0) {
		pos--;
		switch (filename[pos]) {
		case '/':
			return NULL;
		case '.':
			return (filename+pos+1);
		}
	}

	return NULL;
}

#define DEFAULT_MIME_TYPE "application/octet-stream"

const char *lookup_mimetype(const char *filename)
{
	int i;
	const char *extension;

	if (!filename) {
		return NULL;
	}

	extension = get_extension(filename);
	if (!extension)
		return DEFAULT_MIME_TYPE;

	for (i = 0; i< ARRAY_SIZE(uh_mime_types); i++) {
		if (strcmp(extension, uh_mime_types[i].extn) == 0) {
			return uh_mime_types[i].mime;
		}
	}

	debug(LOG_INFO, "无法找到扩展名【%s】对应的 MIME 类型", extension);

	return DEFAULT_MIME_TYPE;
}

/**
 * @brief serve_file try to serve a request via filesystem. Using webroot as root.
 * @param connection
 * @param client
 * @return
 */
static int serve_file(struct MHD_Connection *connection, t_client *client, const char *url)
{
	struct stat stat_buf;
	s_config *config = config_get_config();
	struct MHD_Response *response;
	char filename[PATH_MAX];
	int ret = MHD_NO;
	const char *mimetype = NULL;
	off_t size;

	snprintf(filename, PATH_MAX, "%s/%s", config->webroot, url);

	/* check if file exists and is not a directory */
	ret = stat(filename, &stat_buf);
	if (ret) {
		/* stat failed */
		return send_error(connection, 404);
	}

	if (!S_ISREG(stat_buf.st_mode)) {
#ifdef S_ISLNK
		/* ignore links */
		if (!S_ISLNK(stat_buf.st_mode))
#endif /* S_ISLNK */
		return send_error(connection, 404);
	}

	int fd = open(filename, O_RDONLY);
	if (fd < 0)
		return send_error(connection, 404);

	mimetype = lookup_mimetype(filename);

	/* serving file and creating response */
	size = lseek(fd, 0, SEEK_END);
	if (size < 0)
		return send_error(connection, 404);

	response = MHD_create_response_from_fd(size, fd);
	if (!response)
		return send_error(connection, 503);

	MHD_add_response_header(response, "Content-Type", mimetype);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	return ret;
}
