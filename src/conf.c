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

/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"

/** @internal
 * Holds the current configuration of the gateway */
static s_config config = {{0}};

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oSessionTimeout,
	oSessionTimeoutBlock,
	oSessionLimitBlock,
	oDaemon,
	oDebugLevel,
	oMaxClients,
	oGatewayName,
	oGatewayDomainName,
	oGatewayInterface,
	oGatewayIPRange,
	oGatewayIP,
	/* TODO: deprecate oGatewayAddress option */
	oGatewayAddress,
	oGatewayPort,
	oHTTPDMaxConn,
	oWebRoot,
	oSplashPage,
	oStatusPage,
	oAdminPage,
	oRedirectURL,
	oPreauthIdleTimeout,
	oAuthIdleTimeout,
	oCheckInterval,
	oSetMSS,
	oMSSValue,
	oTrafficControl,
	oDownloadLimit,
	oUploadLimit,
	oUploadIFB,
	oNdsctlSocket,
	oSyslogFacility,
	oFirewallRule,
	oFirewallRuleSet,
	oEmptyRuleSetPolicy,
	oMACmechanism,
	oTrustedMACList,
	oBlockedMACList,
	oAllowedMACList,
	oFWMarkAuthenticated,
	oFWMarkTrusted,
	oFWMarkBlocked,
	oBinAuth,
	oPreAuth,
	oStateFile,
	oAdminToken,
	oAutoAuthTimeout,
	oAddressReuse,
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
	int required;
} keywords[] = {
	{ "sessiontimeout", oSessionTimeout },
	{ "sessiontimeoutblock", oSessionTimeoutBlock },
	{ "sessionlimitblock", oSessionLimitBlock },
	{ "daemon", oDaemon },
	{ "debuglevel", oDebugLevel },
	{ "maxclients", oMaxClients },
	{ "gatewayname", oGatewayName },
	{ "gatewaydomainname", oGatewayDomainName },
	{ "gatewayinterface", oGatewayInterface },
	{ "gatewayiprange", oGatewayIPRange },
	{ "gatewayip", oGatewayIP },
	/* TODO: remove/deprecate gatewayaddress keyword */
	{ "gatewayaddress", oGatewayAddress },
	{ "gatewayport", oGatewayPort },
	{ "webroot", oWebRoot },
	{ "splashpage", oSplashPage },
	{ "statuspage", oStatusPage },
	{ "redirectURL", oRedirectURL },
	{ "preauthidletimeout", oPreauthIdleTimeout },
	{ "authidletimeout", oAuthIdleTimeout },
	{ "checkinterval", oCheckInterval },
	{ "setmss", oSetMSS },
	{ "mssvalue", oMSSValue },
	{ "trafficcontrol",	oTrafficControl },
	{ "downloadlimit", oDownloadLimit },
	{ "uploadlimit", oUploadLimit },
	{ "ifb", oUploadIFB },
	{ "syslogfacility", oSyslogFacility },
	{ "ndsctlsocket", oNdsctlSocket },
	{ "firewallruleset", oFirewallRuleSet },
	{ "firewallrule", oFirewallRule },
	{ "emptyrulesetpolicy", oEmptyRuleSetPolicy },
	{ "trustedmaclist", oTrustedMACList },
	{ "blockedmaclist", oBlockedMACList },
	{ "allowedmaclist", oAllowedMACList },
	{ "MACmechanism", oMACmechanism },
	{ "fw_mark_authenticated", oFWMarkAuthenticated },
	{ "fw_mark_trusted", oFWMarkTrusted },
	{ "fw_mark_blocked", oFWMarkBlocked },
	{ "binauth", oBinAuth },
	{ "preauth", oPreAuth },
	{ "statefile", oStateFile },
	{"AdminToken", oAdminToken},
	{"adminpage", oAdminPage},
	{ "autoauthtimeout", oAutoAuthTimeout },
	{ "addressreuse", oAddressReuse },
	{ NULL, oBadOption },
};

static void config_notnull(const void *parm, const char *parmname);
static int parse_boolean(const char *);
static void _parse_firewall_rule(t_firewall_ruleset *ruleset, char *leftover);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);

static OpCodes config_parse_opcode(const char *cp, const char *filename, int linenum);

/** @internal
Strip comments and leading and trailing whitespace from a string.
Return a pointer to the first nonspace char in the string.
*/
static char* _strip_whitespace(char* p1);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
	return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	t_firewall_ruleset *rs;

	debug(LOG_DEBUG, "设置默认配置参数");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile)-1);
	config.session_timeout = DEFAULT_SESSION_TIMEOUT;
	config.session_timeout_block = DEFAULT_SESSION_TIMEOUT_BLOCK;
	config.session_limit_block = DEFAULT_SESSION_LIMIT_BLOCK;
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.maxclients = DEFAULT_MAXCLIENTS;
	config.gw_name = safe_strdup(DEFAULT_GATEWAYNAME);
	config.gw_interface = NULL;
	config.gw_iprange = safe_strdup(DEFAULT_GATEWAY_IPRANGE);
	config.gw_address = NULL;
	config.gw_domain = NULL;
	config.gw_ip = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.webroot = safe_strdup(DEFAULT_WEBROOT);
	config.splashpage = safe_strdup(DEFAULT_SPLASHPAGE);
	config.statuspage = safe_strdup(DEFAULT_STATUSPAGE);
	config.adminpage = safe_strdup(DEFAULT_ADMINPAGE);
	config.authdir = safe_strdup(DEFAULT_AUTHDIR);
	config.denydir = safe_strdup(DEFAULT_DENYDIR);
	config.redirectURL = NULL;
	config.preauth_idle_timeout = DEFAULT_PREAUTH_IDLE_TIMEOUT,
	config.auth_idle_timeout = DEFAULT_AUTH_IDLE_TIMEOUT,
	config.checkinterval = DEFAULT_CHECKINTERVAL;
	config.daemon = -1;
	config.set_mss = DEFAULT_SET_MSS;
	config.mss_value = DEFAULT_MSS_VALUE;
	config.traffic_control = DEFAULT_TRAFFIC_CONTROL;
	config.upload_limit =  DEFAULT_UPLOAD_LIMIT;
	config.download_limit = DEFAULT_DOWNLOAD_LIMIT;
	config.upload_ifb =  DEFAULT_UPLOAD_IFB;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	config.log_syslog = DEFAULT_LOG_SYSLOG;
	config.ndsctl_sock = safe_strdup(DEFAULT_NDSCTL_SOCK);
	config.internal_sock = safe_strdup(DEFAULT_INTERNAL_SOCK);
	config.rulesets = NULL;
	config.trustedmaclist = NULL;
	config.blockedmaclist = NULL;
	config.allowedmaclist = NULL;
	config.macmechanism = DEFAULT_MACMECHANISM;
	config.fw_mark_authenticated = DEFAULT_FW_MARK_AUTHENTICATED;
	config.fw_mark_trusted = DEFAULT_FW_MARK_TRUSTED;
	config.fw_mark_blocked = DEFAULT_FW_MARK_BLOCKED;
	config.ip6 = DEFAULT_IP6;
	config.binauth = NULL;
	config.preauth = NULL;
	config.statefile = safe_strdup(DEFAULT_STATE_FILE);
	config.admin_token = safe_strdup(DEFAULT_ADMIN_TOKEN);
	config.auto_auth_timeout = DEFAULT_AUTO_AUTH_TIMEOUT;
	config.address_reuse = DEFAULT_ADDRESS_REUSE;

	/* Set up default FirewallRuleSets, and their empty ruleset policies */
	rs = add_ruleset("trusted-users");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_TRUSTED_USERS_POLICY);
	rs = add_ruleset("trusted-users-to-router");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_TRUSTED_USERS_TO_ROUTER_POLICY);
	rs = add_ruleset("users-to-router");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_USERS_TO_ROUTER_POLICY);
	rs = add_ruleset("authenticated-users");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_AUTHENTICATED_USERS_POLICY);
	rs = add_ruleset("preauthenticated-users");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_PREAUTHENTICATED_USERS_POLICY);
}

/**
 * If the command-line didn't specify a config, use the default.
 */
void
config_init_override(void)
{
	if (config.daemon == -1) {
		config.daemon = DEFAULT_DAEMON;
	}
}

/** @internal
Attempts to parse an opcode from the config file
*/
static OpCodes
config_parse_opcode(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++) {
		if (strcasecmp(cp, keywords[i].name) == 0) {
			return keywords[i].opcode;
		}
	}

	debug(LOG_ERR, "在 %s 中的第 %d 行出现了错误的配置选项：【 %s】", filename, linenum, cp);
	return oBadOption;
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** Add a firewall ruleset with the given name, and return it.
 *  Do not allow duplicates. */
t_firewall_ruleset *
add_ruleset(const char rulesetname[])
{
	t_firewall_ruleset *ruleset;

	ruleset = get_ruleset(rulesetname);

	if (ruleset != NULL) {
		debug(LOG_DEBUG, "add_ruleset(): 防火墙规则集【%s】已存在！", rulesetname);
		return ruleset;
	}

	debug(LOG_DEBUG, "add_ruleset(): 正在创建防火墙规则集【%s】", rulesetname);

	/* Create and place at head of config.rulesets */
	ruleset = safe_malloc(sizeof(t_firewall_ruleset));
	memset(ruleset, 0, sizeof(t_firewall_ruleset));
	ruleset->name = safe_strdup(rulesetname);
	ruleset->next = config.rulesets;
	config.rulesets = ruleset;

	return ruleset;
}

/** @internal
Parses an empty ruleset policy directive
*/
static void
parse_empty_ruleset_policy(char *ptr, const char *filename, int lineno)
{
	char *rulesetname, *policy;
	t_firewall_ruleset *ruleset;

	/* find first whitespace delimited word; this is ruleset name */
	while ((*ptr != '\0') && (isblank(*ptr))) ptr++;
	rulesetname = ptr;
	while ((*ptr != '\0') && (!isblank(*ptr))) ptr++;
	*ptr = '\0';

	/* get the ruleset struct with this name; error if it doesn't exist */
	debug(LOG_DEBUG, "正在解析 EmptyRuleSetPolicy 中的【%s】", rulesetname);
	ruleset = get_ruleset(rulesetname);
	if (ruleset == NULL) {
		debug(LOG_ERR, "在 %s 中的第 %d 行出现无法识别的 FirewallRuleSet 名称：【%s】", filename, lineno, rulesetname);
		debug(LOG_ERR, "退出...");
		exit(1);
	}

	/* find next whitespace delimited word; this is policy name */
	ptr++;
	while ((*ptr != '\0') && (isblank(*ptr))) ptr++;
	policy = ptr;
	while ((*ptr != '\0') && (!isblank(*ptr))) ptr++;
	*ptr = '\0';

	/* make sure policy is one of the possible ones:
	 "passthrough" means iptables RETURN
	 "allow" means iptables ACCEPT
	 "block" means iptables REJECT
	*/
	if (ruleset->emptyrulesetpolicy != NULL) free(ruleset->emptyrulesetpolicy);
	if (!strcasecmp(policy,"passthrough")) {
		ruleset->emptyrulesetpolicy =  safe_strdup("RETURN");
	} else if (!strcasecmp(policy,"allow")) {
		ruleset->emptyrulesetpolicy =  safe_strdup("ACCEPT");
	} else if (!strcasecmp(policy,"block")) {
		ruleset->emptyrulesetpolicy =  safe_strdup("REJECT");
	} else {
		debug(LOG_ERR, "在 %s 中的第 %d 行出现无法识别的 EmptyRuleSetPolicy 指令：【%s】", filename, lineno, policy);
		debug(LOG_ERR, "退出...");
		exit(1);
	}

	debug(LOG_DEBUG, "将【%s】的 EmptyRuleSetPolicy 设置为【%s】", rulesetname, policy);
}



/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(const char *rulesetname, FILE *fd, const char *filename, int *linenum)
{
	char line[MAX_BUF], *p1, *p2;
	t_firewall_ruleset *ruleset;
	int opcode;

	/* find whitespace delimited word in ruleset string; this is its name */
	p1 = strchr(rulesetname,' ');
	if (p1) *p1 = '\0';
	p1 = strchr(rulesetname,'\t');
	if (p1) *p1 = '\0';

	debug(LOG_DEBUG, "解析防火墙规则集【%s】", rulesetname);
	ruleset = get_ruleset(rulesetname);
	if (ruleset == NULL) {
		debug(LOG_ERR, "无法识别的防火墙规则集名称：【%s】", rulesetname);
		debug(LOG_ERR, "退出...");
		exit(1);
	}

	/* Parsing the rules in the set */
	while (fgets(line, MAX_BUF, fd)) {
		(*linenum)++;
		p1 = _strip_whitespace(line);

		/* if nothing left, get next line */
		if (p1[0] == '\0') continue;

		/* if closing brace, we are done */
		if (p1[0] == '}') break;

		/* next, we coopt the parsing of the regular config */

		/* keep going until word boundary is found. */
		p2 = p1;
		while ((*p2 != '\0') && (!isblank(*p2))) p2++;
		/* if this is end of line, it's a problem */
		if (p2[0] == '\0') {
			debug(LOG_ERR, "在 %s 中的第 %d 行出现防火墙规则不完整", filename, *linenum);
			debug(LOG_ERR, "退出...");
			exit(1);
		}
		/* terminate first word, point past it */
		*p2 = '\0';
		p2++;

		/* skip whitespace to point at arg */
		while (isblank(*p2)) p2++;

		/* Get opcode */
		opcode = config_parse_opcode(p1, filename, *linenum);

		debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);

		switch (opcode) {
		case oFirewallRule:
			_parse_firewall_rule(ruleset, p2);
			break;

		case oBadOption:
		default:
			debug(LOG_ERR, "在 %s 中的第 %d 行解析 FirewallRuleSet 时出现错误选项【%s】", filename, *linenum, p1);
			debug(LOG_ERR, "退出...");
			exit(1);
			break;
		}
	}
	debug(LOG_DEBUG, "FirewallRuleSet【%s】已解析", rulesetname);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static void
_parse_firewall_rule(t_firewall_ruleset *ruleset, char *leftover)
{
	int i;
	t_firewall_target target = TARGET_REJECT; /**< firewall target */
	int all_nums = 1; /**< If 0, word contained illegal chars */
	int finished = 0; /**< reached end of line */
	char *token = NULL; /**< First word */
	char *port = NULL; /**< port(s) to allow/block */
	char *protocol = NULL; /**< protocol to allow/block: tcp/udp/icmp/all */
	char *mask = NULL; /**< Netmask */
	char *ipset = NULL; /**< ipset */
	char *other_kw = NULL; /**< other key word */
	t_firewall_rule *tmp;
	t_firewall_rule *tmp2;

	/* debug(LOG_DEBUG, "leftover: %s", leftover); */

	/* lowercase everything */
	for (i = 0; *(leftover + i) != '\0'
			&& (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++);
	token = leftover;
	TO_NEXT_WORD(leftover, finished);

	/* Parse token */
	if (!strcasecmp(token, "block")) {
		target = TARGET_REJECT;
	} else if (!strcasecmp(token, "drop")) {
		target = TARGET_DROP;
	} else if (!strcasecmp(token, "allow")) {
		target = TARGET_ACCEPT;
	} else if (!strcasecmp(token, "log")) {
		target = TARGET_LOG;
	} else if (!strcasecmp(token, "ulog")) {
		target = TARGET_ULOG;
	} else {
		debug(LOG_ERR, "无效的规则类型【%s】，应该是 "
			  "\"block\",\"drop\",\"allow\",\"log\" 或 \"ulog\"", token);
		exit(1);
	}

	/* Parse the remainder */

	/* Get the optional protocol */
	if (strncmp(leftover, "tcp", 3) == 0
			|| strncmp(leftover, "udp", 3) == 0
			|| strncmp(leftover, "all", 3) == 0
			|| strncmp(leftover, "icmp", 4) == 0) {
		protocol = leftover;
		TO_NEXT_WORD(leftover, finished);
	}

	/* Get the optional port or port range */
	if (strncmp(leftover, "port", 4) == 0) {
		if (protocol == NULL ||
				!(strncmp(protocol, "tcp", 3) == 0 || strncmp(protocol, "udp", 3) == 0)) {
			debug(LOG_ERR, "不含 tcp 或 udp 协议的端口");
			exit(1);
		}
		TO_NEXT_WORD(leftover, finished);
		/* Get port now */
		port = leftover;
		TO_NEXT_WORD(leftover, finished);
		for (i = 0; *(port + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(port + i)) && ((unsigned char)*(port + i) != ':'))
				all_nums = 0; /*< No longer only digits or : */
		if (!all_nums) {
			debug(LOG_ERR, "无效端口：【 %s】", port);
			exit(1);
		}
	}

	if (strncmp(leftover, "ipset", 5) == 0) {
		TO_NEXT_WORD(leftover, finished);
		/* Get ipset now */
		ipset = leftover;
		TO_NEXT_WORD(leftover, finished);

		/* TODO check if ipset exists */
	}

	/* Now, look for optional IP address/mask */
	if (!finished) {
		/* should be exactly "to" */
		other_kw = leftover;
		TO_NEXT_WORD(leftover, finished);
		if (strcmp(other_kw, "to") || finished) {
			debug(LOG_ERR, "无效或意外的关键字【%s】，"
				  "应该是 \"to\"", other_kw);
			exit(1);
		}

		/* Get IP address/mask now */
		mask = leftover;
		TO_NEXT_WORD(leftover, finished);
		all_nums = 1;
		for (i = 0; *(mask + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(mask + i)) && (*(mask + i) != '.')
					&& (*(mask + i) != '/'))
				all_nums = 0; /*< No longer only digits or . or / */
		if (!all_nums) {
			debug(LOG_ERR, "无效掩码【%s】", mask);
			exit(1);
		}
	}

	/* Generate rule record */
	tmp = safe_malloc(sizeof(t_firewall_rule));
	memset((void *)tmp, 0, sizeof(t_firewall_rule));
	tmp->target = target;
	if (protocol != NULL)
		tmp->protocol = safe_strdup(protocol);
	if (port != NULL)
		tmp->port = safe_strdup(port);
	if (ipset != NULL)
		tmp->ipset = safe_strdup(ipset);
	if (mask == NULL)
		tmp->mask = safe_strdup("0.0.0.0/0");
	else
		tmp->mask = safe_strdup(mask);

	debug(LOG_DEBUG, "将 FirewallRule【%s】【%s】端口【%s】添加到 FirewallRuleset【%s】的【%s】", token, tmp->protocol, tmp->port, tmp->mask, ruleset->name);

	/* Add the rule record */
	if (ruleset->rules == NULL) {
		/* No rules... */
		ruleset->rules = tmp;
	} else {
		tmp2 = ruleset->rules;
		while (tmp2->next != NULL)
			tmp2 = tmp2->next;
		tmp2->next = tmp;
	}
}

int
is_empty_ruleset (const char *rulesetname)
{
	return get_ruleset_list(rulesetname) == NULL;
}

char *
get_empty_ruleset_policy(const char *rulesetname)
{
	t_firewall_ruleset *rs;

	rs = get_ruleset(rulesetname);
	return rs ? rs->emptyrulesetpolicy : NULL;
}


t_firewall_ruleset *
get_ruleset(const char ruleset[])
{
	t_firewall_ruleset *tmp;

	for (tmp = config.rulesets; tmp != NULL
			&& strcmp(tmp->name, ruleset) != 0; tmp = tmp->next);

	return (tmp);
}

t_firewall_rule *
get_ruleset_list(const char *ruleset)
{
	t_firewall_ruleset *tmp;

	tmp = get_ruleset(ruleset);
	return tmp ? tmp->rules : NULL;
}

/** @internal
Strip comments and leading and trailing whitespace from a string.
Return a pointer to the first nonspace char in the string.
*/
static char*
_strip_whitespace(char* p1)
{
	char *p2, *p3;

	p3 = p1;
	while ((p2 = strchr(p3,'#')) != 0) {  /* strip the comment */
		/* but allow # to be escaped by \ */
		if (p2 > p1 && (*(p2 - 1) == '\\')) {
			p3 = p2 + 1;
			continue;
		}
		*p2 = '\0';
		break;
	}

	/* strip leading whitespace */
	while(isspace(p1[0])) p1++;
	/* strip trailing whitespace */
	while(p1[0] != '\0' && isspace(p1[strlen(p1)-1]))
		p1[strlen(p1)-1] = '\0';

	return p1;
}

/**
@param filename Full path of the configuration file to be read
*/
void
config_read(const char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value;
	struct stat sb;

	debug(LOG_INFO, "正在读取配置文件 '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "致命错误：无法打开配置文件 '%s', "
			  "退出...", filename);
		exit(1);
	}

	while (fgets(line, MAX_BUF, fd)) {
		linenum++;
		s = _strip_whitespace(line);

		/* if nothing left, get next line */
		if (s[0] == '\0') continue;

		/* now we require the line must have form: <option><whitespace><arg>
		 * even if <arg> is just a left brace, for example
		 */

		/* find first word (i.e. option) end boundary */
		p1 = s;
		while ((*p1 != '\0') && (!isspace(*p1))) p1++;
		/* if this is end of line, it's a problem */
		if (p1[0] == '\0') {
			debug(LOG_ERR, "在 %s 中的第 %d 行需要【%s】参数", filename, linenum, s);
			debug(LOG_ERR, "退出...");
			exit(1);
		}

		/* terminate option, point past it */
		*p1 = '\0';
		p1++;

		/* skip any additional leading whitespace, make p1 point at start of arg */
		while (isblank(*p1)) p1++;

		debug(LOG_DEBUG, "解析选项：【%s】，参数：【%s】", s, p1);
		opcode = config_parse_opcode(s, filename, linenum);

		switch(opcode) {
		case oSessionTimeout:
			if (sscanf(p1, "%d", &config.session_timeout) < 1 || config.session_timeout < 0) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oSessionTimeoutBlock:
			if (sscanf(p1, "%u", &config.session_timeout_block) < 1) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(-1);
			}
			break;
		case oSessionLimitBlock:
			if (sscanf(p1, "%u", &config.session_limit_block) < 0) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(-1);
			}
			break;
		case oDaemon:
			if (config.daemon == -1 && ((value = parse_boolean(p1)) != -1)) {
				config.daemon = value;
			}
			break;
		case oDebugLevel:
			if (sscanf(p1, "%d", &config.debuglevel) < 1 || config.debuglevel < DEBUGLEVEL_MIN) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误。有效的级别范围是【%d】到【%d】",
					filename, linenum, s, p1, DEBUGLEVEL_MIN, DEBUGLEVEL_MAX);
				debug(LOG_ERR, "退出...");
				exit(1);
			} else if (config.debuglevel > DEBUGLEVEL_MAX) {
				config.debuglevel = DEBUGLEVEL_MAX;
				debug(LOG_WARNING, "日志详细级别无效。请设置为最高级别");
			}
			break;
		case oAdminToken:  
    			config.admin_token = safe_strdup(p1);  
    			break;
    		case oAdminPage:  
    			config.adminpage = safe_strdup(p1);  
    			break;
    		case oAutoAuthTimeout:  
    			if (sscanf(p1, "%d", &config.auto_auth_timeout) < 1 || config.auto_auth_timeout < 0) {  
        			debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);  
        				debug(LOG_ERR, "退出...");  
        			exit(1);  
    			}  
    			break;
    		case oAddressReuse:  
    			if ((value = parse_boolean(p1)) != -1) {  
        			config.address_reuse = value;  
    			}  
    			break;
		case oMaxClients:
			if (sscanf(p1, "%d", &config.maxclients) < 1 || config.maxclients < 1) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oGatewayName:
			config.gw_name = safe_strdup(p1);
			break;
		case oGatewayDomainName:
			config.gw_domain = safe_strdup(p1);
			break;
		case oGatewayInterface:
			config.gw_interface = safe_strdup(p1);
			break;
		case oGatewayIPRange:
			config.gw_iprange = safe_strdup(p1);
			break;
		/* TODO: deprecate oGatewayAddress option */
		case oGatewayAddress:
		case oGatewayIP:
			config.gw_ip = safe_strdup(p1);
			break;
		case oGatewayPort:
			if (sscanf(p1, "%u", &config.gw_port) < 1) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oBinAuth:
			config.binauth = safe_strdup(p1);
			if (!((stat(p1, &sb) == 0) && S_ISREG(sb.st_mode) && (sb.st_mode & S_IXUSR))) {
				debug(LOG_ERR, "binauth 脚本文件不存在或没有可执行权限：【%s】", p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oPreAuth:
			config.preauth = safe_strdup(p1);
			if (!((stat(p1, &sb) == 0) && S_ISREG(sb.st_mode) && (sb.st_mode & S_IXUSR))) {
				debug(LOG_ERR, "preauth program 脚本文件不存在或没有可执行权限：【%s】", p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oFirewallRuleSet:
			parse_firewall_ruleset(p1, fd, filename, &linenum);
			break;
		case oEmptyRuleSetPolicy:
			parse_empty_ruleset_policy(p1, filename, linenum);
			break;
		case oTrustedMACList:
			parse_trusted_mac_list(p1);
			break;
		case oBlockedMACList:
			parse_blocked_mac_list(p1);
			break;
		case oAllowedMACList:
			parse_allowed_mac_list(p1);
			break;
		case oMACmechanism:
			if (!strcasecmp("allow", p1)) {
				config.macmechanism = MAC_ALLOW;
			} else if (!strcasecmp("block", p1)) {
				config.macmechanism = MAC_BLOCK;
			} else {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oWebRoot:
			/* remove any trailing slashes from webroot path */
			while((p2 = strrchr(p1,'/')) == (p1 + strlen(p1) - 1)) *p2 = '\0';
			config.webroot = safe_strdup(p1);
			break;
		case oSplashPage:
			config.splashpage = safe_strdup(p1);
			break;
		case oStatusPage:
			config.statuspage = safe_strdup(p1);
			break;
		case oRedirectURL:
			config.redirectURL = safe_strdup(p1);
			break;
		case oAuthIdleTimeout:
			if (sscanf(p1, "%d", &config.auth_idle_timeout) < 1 || config.auth_idle_timeout < 0) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oPreauthIdleTimeout:
			if (sscanf(p1, "%d", &config.preauth_idle_timeout) < 1 || config.preauth_idle_timeout < 0) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oNdsctlSocket:
			free(config.ndsctl_sock);
			config.ndsctl_sock = safe_strdup(p1);
			break;
		case oSetMSS:
			if ((value = parse_boolean(p1)) != -1) {
				config.set_mss = value;
			} else {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oMSSValue:
			if (sscanf(p1, "%d", &config.mss_value) < 1) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oTrafficControl:
			if ((value = parse_boolean(p1)) != -1) {
				config.traffic_control = value;
			} else {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oDownloadLimit:
			if (sscanf(p1, "%d", &config.download_limit) < 1 || config.download_limit < 0) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oUploadLimit:
			if (sscanf(p1, "%d", &config.upload_limit) < 1 || config.upload_limit < 0) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oUploadIFB:
			if(sscanf(p1, "%d", &config.upload_ifb) < 1 || config.upload_ifb < 0) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oFWMarkAuthenticated:
			if (sscanf(p1, "%x", &config.fw_mark_authenticated) < 1 ||
					config.fw_mark_authenticated == 0 ||
					config.fw_mark_authenticated == config.fw_mark_blocked ||
					config.fw_mark_authenticated == config.fw_mark_trusted) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oFWMarkBlocked:
			if (sscanf(p1, "%x", &config.fw_mark_blocked) < 1 ||
					config.fw_mark_blocked == 0 ||
					config.fw_mark_blocked == config.fw_mark_authenticated ||
					config.fw_mark_blocked == config.fw_mark_trusted) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oFWMarkTrusted:
			if (sscanf(p1, "%x", &config.fw_mark_trusted) < 1 ||
					config.fw_mark_trusted == 0 ||
					config.fw_mark_trusted == config.fw_mark_authenticated ||
					config.fw_mark_trusted == config.fw_mark_blocked) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oCheckInterval:
			if (sscanf(p1, "%i", &config.checkinterval) < 1 || config.checkinterval < 1) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oSyslogFacility:
			if (sscanf(p1, "%d", &config.syslog_facility) < 1) {
				debug(LOG_ERR, "在 %s 中的第 %d 行选项 %s 的参数【%s】出现错误", filename, linenum, s, p1);
				debug(LOG_ERR, "退出...");
				exit(1);
			}
			break;
		case oBadOption:
			debug(LOG_ERR, "在 %s 中的第 %d 行选项【%s】出现错误。", filename, linenum, s);
			debug(LOG_ERR, "退出...");
			exit(1);
			break;
		case oStateFile:
			if (config.statefile)
				free(config.statefile);

			config.statefile = safe_strdup(p1);
#ifndef WITH_STATE_FILE
			debug(LOG_ERR, "nodogsplash 构建时没有状态文件，但给出了状态文件。");
#endif /* WITH_STATE_FILE */
			break;
		}
	}

	fclose(fd);

	debug(LOG_INFO, "读取配置文件【%s】完成 ", filename);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean(const char *line)
{
	if (strcasecmp(line, "no") == 0 ||
			strcasecmp(line, "false") == 0 ||
			strcmp(line, "0") == 0) {
		return 0;
	}
	if (strcasecmp(line, "yes") == 0 ||
			strcasecmp(line, "true") == 0 ||
			strcmp(line, "1") == 0) {
		return 1;
	}

	return -1;
}

/* Parse a string to see if it is valid decimal dotted quad IP V4 format */
int check_ip_format(const char *possibleip)
{
	unsigned char buf[sizeof(struct in6_addr)];
	return inet_pton(AF_INET, possibleip, buf) > 0;
}

/* Parse a string to see if it is valid MAC address format */
int check_mac_format(const char possiblemac[])
{
	return ether_aton(possiblemac) != NULL;
}

int add_to_trusted_mac_list(const char possiblemac[])
{
	char mac[18];
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_WARNING, "【%s】不是有效的MAC地址", possiblemac);
		debug(LOG_WARNING, "请从配置文件中的 trustedmac 列表中删除这个MAC地址【%s】", possiblemac);
		return 1;
	}

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.trustedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac, mac)) {
			debug(LOG_INFO, "MAC地址【%s】已在信任列表中", mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.trustedmaclist;
	config.trustedmaclist = p;
	debug(LOG_INFO, "将MAC地址【%s】添加到信任列表", mac);
	return 0;
}


/* Remove given MAC address from the config's trusted mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_trusted_mac_list(const char possiblemac[])
{
	char mac[18];
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "【%s】不是有效的MAC地址", possiblemac);
		return -1;
	}

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.trustedmaclist == NULL) {
		debug(LOG_INFO, "MAC地址【%s】不在空的信任列表中", mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.trustedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac, mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "从信任列表中删除了MAC地址【%s】", mac);
			free(del);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC地址【%s】不在可信列表中", mac);
	return -1;
}


/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.trustedmaclist.
 */
void parse_trusted_mac_list(const char ptr[])
{
	char *ptrcopy = NULL, *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "解析字符串【%s】以获取可信 MAC 地址", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac) > 0) {
			if (add_to_trusted_mac_list(possiblemac) < 0) {
				exit(1);
			}
		}
	}

	free(ptrcopyptr);
}

int is_blocked_mac(const char *mac)
{
	s_config *config;
	t_MAC *block_mac;

	config = config_get_config();

	if (MAC_ALLOW != config->macmechanism) {
		for (block_mac = config->blockedmaclist; block_mac != NULL; block_mac = block_mac->next) {
			if (!strcmp(block_mac->mac, mac)) {
				return 1;
			}
		}
	}

	return 0;
}

int is_allowed_mac(const char *mac)
{
	s_config *config;
	t_MAC *allow_mac;

	config = config_get_config();

	if (MAC_BLOCK != config->macmechanism) {
		for (allow_mac = config->allowedmaclist; allow_mac != NULL; allow_mac = allow_mac->next) {
			if (!strcmp(allow_mac->mac, mac)) {
				return 1;
			}
		}
	}

	return 0;
}

int is_trusted_mac(const char *mac)
{
	s_config *config;
	t_MAC *trust_mac;

	config = config_get_config();

	// Is a client even recognized here?
	for (trust_mac = config->trustedmaclist; trust_mac != NULL; trust_mac = trust_mac->next) {
		if (!strcmp(trust_mac->mac, mac)) {
			return 1;
		}
	}

	return 0;
}

/* Add given MAC address to the config's blocked mac list.
 * Return 0 on success, nonzero on failure
 */
int add_to_blocked_mac_list(const char possiblemac[])
{
	char mac[18];
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "【%s】不是有效的MAC地址，无法阻止", possiblemac);
		return -1;
	}

	/* abort if not using BLOCK mechanism */
	if (MAC_BLOCK != config.macmechanism) {
		debug(LOG_NOTICE, "尝试访问阻止的MAC列表，但控制机制 != block");
		return -1;
	}

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.blockedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac,mac)) {
			debug(LOG_INFO, "MAC地址【%s】已在阻止列表中", mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.blockedmaclist;
	config.blockedmaclist = p;
	debug(LOG_INFO, "将MAC地址【%s】添加到阻止列表", mac);
	return 0;
}


/* Remove given MAC address from the config's blocked mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_blocked_mac_list(const char possiblemac[])
{
	char mac[18];
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "【%s】不是有效的MAC地址", possiblemac);
		return -1;
	}

	/* abort if not using BLOCK mechanism */
	if (MAC_BLOCK != config.macmechanism) {
		debug(LOG_NOTICE, "尝试访问阻止的MAC列表，但控制机制 != block");
		return -1;
	}

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.blockedmaclist == NULL) {
		debug(LOG_INFO, "MAC地址【%s】不在空的阻止列表中", mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &config.blockedmaclist; *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac,mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "从阻止列表中删除了MAC地址【%s】", mac);
			free(del);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC地址【%s】不在阻止列表中", mac);
	return -1;
}


/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.blockedmaclist
 */
void parse_blocked_mac_list(const char ptr[])
{
	char *ptrcopy = NULL, *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "正在解析字符串【%s】以获取要阻止的MAC地址", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac) > 0) {
			if (add_to_blocked_mac_list(possiblemac) < 0) {
				exit(1);
			}
		}
	}

	free(ptrcopyptr);
}

/* Add given MAC address to the config's allowed mac list.
 * Return 0 on success, nonzero on failure
 */
int add_to_allowed_mac_list(const char possiblemac[])
{
	char mac[18];
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "【%s】不是允许的有效MAC地址", possiblemac);
		return -1;
	}

	/* abort if not using ALLOW mechanism */
	if (MAC_ALLOW != config.macmechanism) {
		debug(LOG_NOTICE, "尝试访问允许的 MAC 列表，但控制机制 != allow");
		return -1;
	}

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.allowedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac, mac)) {
			debug(LOG_INFO, "MAC地址【%s】已在允许列表中", mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.allowedmaclist;
	config.allowedmaclist = p;
	debug(LOG_INFO, "将MAC地址【%s】添加到允许列表", mac);
	return 0;
}


/* Remove given MAC address from the config's allowed mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_allowed_mac_list(const char possiblemac[])
{
	char mac[18];
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "【%s】不是允许的有效MAC地址", possiblemac);
		return -1;
	}

	/* abort if not using ALLOW mechanism */
	if (MAC_ALLOW != config.macmechanism) {
		debug(LOG_NOTICE, "尝试访问允许的MAC列表，但控制机制 != allow");
		return -1;
	}

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.allowedmaclist == NULL) {
		debug(LOG_INFO, "MAC地址【%s】不在空的允许列表中", mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.allowedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac, mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "从允许列表中删除了MAC地址【%s】", mac);
			free(del);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC地址【%s】不在允许列表中", mac);
	return -1;
}

/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.allowedmaclist
 */
void parse_allowed_mac_list(const char ptr[])
{
	char *ptrcopy = NULL;
	char *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "解析字符串【%s】以获取允许的MAC地址", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac) > 0) {
			if (add_to_allowed_mac_list(possiblemac) < 0) {
				exit(1);
			}
		}
	}

	free(ptrcopyptr);
}

/** Set the debug log level.  See syslog.h
 *  Return 0 on success.
 */
int set_debuglevel(const char opt[])
{
	char *end;

	if (opt == NULL || strlen(opt) == 0) {
		return 1;
	}

	// parse number
	int level = strtol(opt, &end, 10);
	if (end != (opt + strlen(opt))) {
		return 1;
	}

	if (level >= DEBUGLEVEL_MIN && level <= DEBUGLEVEL_MAX) {
		config.debuglevel = level;
		return 0;
	} else {
		return 1;
	}
}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.gw_interface, "GatewayInterface");

	if (missing_parms) {
		debug(LOG_ERR, "配置不完整，退出...");
		exit(1);
	}

	if (config.preauth_idle_timeout > 0 && config.checkinterval >= (60 * config.preauth_idle_timeout) / 2) {
		debug(LOG_ERR, "设置的检测间隔【%ds】必须小于预认证空闲超时时间的一半【%ds】",
        		config.checkinterval, 60 * config.preauth_idle_timeout);
		exit(1);
	}

	if (config.auth_idle_timeout > 0 && config.checkinterval >= (60 * config.auth_idle_timeout) / 2) {
		debug(LOG_ERR, "设置的检测间隔【%ds】必须小于认证空闲超时时间的一半【%ds】",
        		config.checkinterval, 60 * config.auth_idle_timeout);
		exit(1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char parmname[])
{
	if (parm == NULL) {
		debug(LOG_ERR, "【%s】未设置", parmname);
		missing_parms = 1;
	}
}
