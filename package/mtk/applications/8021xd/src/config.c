
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <linux/if.h>			/* for IFNAMSIZ and co... */
#include <linux/wireless.h>

#include "rtdot1x.h"
#include "ieee802_1x.h"
#include "os.h"
#include "md5.h"

#if RADIUS_DAS_SUPPORT
#define RADIUS_DAS_PORT 3799
#define RADIUS_DAS_TIME_WINDOW 300
#endif

extern char MainIfName[IFNAMSIZ];

unsigned char BtoH(
    unsigned char ch)
{
    if (ch >= '0' && ch <= '9') return (ch - '0');        // Handle numerals
    if (ch >= 'A' && ch <= 'F') return (ch - 'A' + 0xA);  // Handle capitol hex digits
    if (ch >= 'a' && ch <= 'f') return (ch - 'a' + 0xA);  // Handle small hex digits
    return(255);
}

//
//  PURPOSE:  Converts ascii string to network order hex
//
//  PARAMETERS:
//    src    - pointer to input ascii string
//    dest   - pointer to output hex
//    destlen - size of dest
//
//  COMMENTS:
//
//    2 ascii bytes make a hex byte so must put 1st ascii byte of pair
//    into upper nibble and 2nd ascii byte of pair into lower nibble.
//
void AtoH(
    char            *src,
    unsigned char	*dest,
    int		        destlen)
{
    char *srcptr;
    unsigned char *destTemp;

    srcptr = src;
    destTemp = (unsigned char *) dest;

    while(destlen--)
    {
        *destTemp = BtoH(*srcptr++) << 4;    // Put 1st ascii byte in upper nibble.
        *destTemp += BtoH(*srcptr++);      // Add 2nd ascii byte to above.
        destTemp++;
    }
}

/**
 * rstrtok - Split a string into tokens
 * @s: The string to be searched
 * @ct: The characters to search for
 * * WARNING: strtok is deprecated, use strsep instead. However strsep is not compatible with old architecture.
 */
char * __rstrtok;
char * rstrtok(char * s,const char * ct)
{
	char *sbegin, *send;

	sbegin  = s ? s : __rstrtok;
	if (!sbegin)
	{
		return NULL;
	}

	sbegin += strspn(sbegin,ct);
	if (*sbegin == '\0')
	{
		__rstrtok = NULL;
		return( NULL );
	}

	send = strpbrk( sbegin, ct);
	if (send && *send != '\0')
		*send++ = '\0';

	__rstrtok = send;

	return (sbegin);
}


static int
Config_read_radius_addr(struct hostapd_radius_server **server,
                int *num_server, unsigned int addr, int def_port,
                struct hostapd_radius_server **curr_serv)
{
    struct hostapd_radius_server *nserv;
    int ret = 0;

	if (addr == 0)
		return -1;

    nserv = realloc(*server, (*num_server + 1) * sizeof(*nserv));
    if (nserv == NULL)
        return -1;

    *server = nserv;
    nserv = &nserv[*num_server];
    (*num_server)++;
    (*curr_serv) = nserv;

    memset(nserv, 0, sizeof(*nserv));
    nserv->port = def_port;

	//if (addr == 0)
	//	ret = -1;
	//else
    	nserv->addr.s_addr = addr;

    return ret;
}

#if HOTSPOT_R3
char * config_get_line(char *s, int size, FILE *stream, int *line,
								char **_pos)
{
	char *pos, *end, *sstart;

	while (fgets(s, size, stream)) {
		(*line)++;
		s[size - 1] = '\0';
		pos = s;

		/* Skip white space from the beginning of line. */
		while (*pos == ' ' || *pos == '\t' || *pos == '\r')
			pos++;

		/* Skip comment lines and empty lines */
		if (*pos == '#' || *pos == '\n' || *pos == '\0')
			continue;

		/*
		 * Remove # comments unless they are within a double quoted
		 * string.
			   */

		sstart = os_strchr(pos, '"');
		if (sstart)
			sstart = os_strrchr(sstart + 1, '"');
		if (!sstart)
			sstart = pos;
		end = os_strchr(sstart, '#');
		if (end)
			*end-- = '\0';
		else
			end = pos + os_strlen(pos) - 1;

		/* Remove trailing white space. */
		while (end > pos &&
				(*end == '\n' || *end == ' ' || *end == '\t' ||
				*end == '\r'))
				*end-- = '\0';

		if (*pos == '\0')
			continue;

		if (_pos)
			*_pos = pos;
		return pos;
	}

	if (_pos)
		*_pos = NULL;
	return NULL;
}

BOOLEAN hs_read_from_config(char *prefix_name, struct rtapd_config *conf)
{
	FILE *file;
	char buf[256], *pos, *token;
	int line = 0;

	if (os_strcmp(prefix_name, "ra") == 0) {
		file = fopen(HS_CONFIG_FILE_RA, "r");
	} else if (os_strcmp(prefix_name, "rax") == 0) {
		file = fopen(HS_CONFIG_FILE_RAX, "r");
	} else {
		DBGPRINT(RT_DEBUG_ERROR, "hs_read_from_config failed!\n");
		return FALSE;
	}

	if (!file) {
		DBGPRINT(RT_DEBUG_ERROR, "File open fail\n");
		return FALSE;
	}

	while (config_get_line(buf, sizeof(buf), file, &line, &pos)) {
		token = strtok(pos, "=");

		if (token != NULL) {
			if (os_strcmp(token, "t_c_filename") == 0) {
				token = strtok(NULL, "");
				if (token != NULL) {
					conf->hs_TandC_filename =
						os_strdup(token);
					conf->hs_TandC_filename_len =
						os_strlen(token);
					DBGPRINT(RT_DEBUG_TRACE,
						"hs_TandC_filename = %s\n",
						conf->hs_TandC_filename);
				} else {
					conf->hs_TandC_filename = NULL;
					conf->hs_TandC_filename_len = 0;
					DBGPRINT(RT_DEBUG_WARN,
						"hs_TandC_filename_len = %d\n",
						conf->hs_TandC_filename_len);
				}
			} else if (os_strcmp(token, "t_c_server_url") == 0) {
				token = strtok(NULL, "");
				if (token != NULL) {
					conf->hs_TandC_server_url =
						os_strdup(token);
					conf->hs_TandC_server_url_len =
						os_strlen(token);
					DBGPRINT(RT_DEBUG_TRACE,
						"hs_TandC_server_url = %s\n",
						conf->hs_TandC_server_url);
				} else {
					conf->hs_TandC_server_url = NULL;
					conf->hs_TandC_server_url_len = 0;
					DBGPRINT(RT_DEBUG_WARN,
						"hs_TandC_server_url_len= %d\n",
						conf->hs_TandC_server_url_len);
				}
			} else if (os_strcmp(token, "t_c_timestamp") == 0) {
				token = strtok(NULL, "");
				if (token != NULL) {
					conf->hs_TandC_timestamp =
						os_strdup(token);
					DBGPRINT(RT_DEBUG_TRACE,
						"hs_TandC_timestamp = %s\n",
						conf->hs_TandC_timestamp);
				} else {
					conf->hs_TandC_timestamp = NULL;
					DBGPRINT(RT_DEBUG_WARN,
						"hs_TandC_timestamp = NULL\n");
				}
			}
		}
	}

	if (fclose(file) != 0)
		DBGPRINT(RT_DEBUG_WARN, "File close fail\n");

	return TRUE;
}
#endif

BOOLEAN Query_config_from_driver(int ioctl_sock, char *prefix_name, struct rtapd_config *conf, int *errors, int *flag)
{
	char 	*buf;
	int 	len;
    int		i, idx, m_num;
	int		radius_count = 0, radius_port_count = 0, radius_key_count = 0;
	int		num_eap_if = 0, num_preauth_if = 0;
	PDOT1X_CMM_CONF pDot1xCmmConf;
	char conf_name[IFNAMSIZ];

	*flag = 0;
	*errors = 0;

	len = sizeof(DOT1X_CMM_CONF);
	buf = (char *) malloc(len + 1);
	if (buf == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, "malloc() failed for Query_config_from_driver(len=%d)\n", len);
		return FALSE;
	}
	else
	{
		DBGPRINT(RT_DEBUG_TRACE, "alloc memory(%d) for Query_config_from_driver. \n", len);
		memset(buf, 0, len);
	}

	if((RT_ioctl(ioctl_sock, RT_PRIV_IOCTL, buf, len, MainIfName, 0, OID_802_DOT1X_CONFIGURATION)) != 0)
	{
		DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for Query_config_from_driver(len=%d, ifname=%s)\n", len, MainIfName);
		free(buf);
		return FALSE;
	}

	pDot1xCmmConf = (PDOT1X_CMM_CONF)buf;

	// BssidNum
	conf->SsidNum = pDot1xCmmConf->mbss_num;
	if(conf->SsidNum > MAX_MBSSID_NUM)
		conf->SsidNum = 1;
	DBGPRINT(RT_DEBUG_TRACE, "MBSS number: %d\n", conf->SsidNum);

#if MULTIPLE_RADIUS
	m_num = conf->SsidNum;
#else
	m_num = 1;
#endif

	// own_ip_addr
	conf->own_ip_addr.s_addr = pDot1xCmmConf->own_ip_addr;
	if (conf->own_ip_addr.s_addr != 0)
	{
		(*flag) |= 0x01;
		DBGPRINT(RT_DEBUG_TRACE, "own ip address: '%s'(%x)\n", inet_ntoa(conf->own_ip_addr), conf->own_ip_addr.s_addr);
	}
	else
	{
		(*errors)++;
		DBGPRINT(RT_DEBUG_ERROR, "Invalid own ip address \n");
	}

	// own_radius_port
	conf->own_radius_port = pDot1xCmmConf->own_radius_port;
	if (conf->own_radius_port != 0)
	{
		(*flag) |= 0x01;
		DBGPRINT(RT_DEBUG_TRACE, "own radius port: '%d'\n", conf->own_radius_port);
	}
	else
	{
		/* own radius port value not set in driver. Kernel will assign dynamically */
		DBGPRINT(RT_DEBUG_ERROR, "own radius port not set in driver. Default 0 value set.\n");
	}

	for (i = 0; i < m_num; i++)
	{
		if (i == 0)
			snprintf(conf_name, IFNAMSIZ, "%s", MainIfName);
		else
			snprintf(conf_name, IFNAMSIZ, "%s%d", prefix_name, i);

		for (idx = 0; idx < pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_num; idx++)
		{
#if MULTIPLE_RADIUS
			// RADIUS_Server ip address
			if (!Config_read_radius_addr(
        	    &conf->mbss_auth_servers[i],
	            &conf->mbss_num_auth_servers[i],
	            pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_ip,
	            1812,
            	&conf->mbss_auth_server[i]))
    		{
        	    radius_count++;
				DBGPRINT(RT_DEBUG_TRACE, "(no.%d) Radius ip address: '%s'(%x) for %s\n", conf->mbss_num_auth_servers[i],
										inet_ntoa(conf->mbss_auth_server[i]->addr),
										conf->mbss_auth_server[i]->addr.s_addr, conf_name);
   			}

			// RADIUS_Port and RADIUS_Key
			if (conf->mbss_auth_server[i] && conf->mbss_auth_server[i]->addr.s_addr != 0)
			{
				if (pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_port > 0)
				{
					radius_port_count++;
					conf->mbss_auth_server[i]->port = pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_port;
					DBGPRINT(RT_DEBUG_TRACE, "(no.%d) Radius port: '%d' for %s\n", conf->mbss_num_auth_servers[i], conf->mbss_auth_server[i]->port, conf_name);
				}
				else
					DBGPRINT(RT_DEBUG_ERROR, "(no.%d) Radius port is invalid for %s\n", conf->mbss_num_auth_servers[i], conf_name);

				if (pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key_len > 0)
				{
					radius_key_count++;
					conf->mbss_auth_server[i]->shared_secret = (u8 *)strdup((const char *)pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key);
	    	        conf->mbss_auth_server[i]->shared_secret_len = pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key_len;
					DBGPRINT(RT_DEBUG_TRACE,"(no.%d) Radius key: '%s', key_len: %lu for %s \n",
						conf->mbss_num_auth_servers[i], conf->mbss_auth_server[i]->shared_secret, conf->mbss_auth_server[i]->shared_secret_len, conf_name);
				}
				else
					DBGPRINT(RT_DEBUG_ERROR, "(no.%d) Radius key is invalid for %s\n", conf->mbss_num_auth_servers[i], conf_name);

			}
#else
			// RADIUS_Server ip address
			if (!Config_read_radius_addr(
	            &conf->auth_servers,
	            &conf->num_auth_servers,
	            pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_ip,
	            1812,
	            &conf->auth_server))
		    {
		            radius_count++;
			}
		    DBGPRINT(RT_DEBUG_TRACE, "(no.%d) Radius ip address: '%s'(%x)\n",
												conf->num_auth_servers,
												inet_ntoa(conf->auth_server->addr),
												conf->auth_server->addr.s_addr);

			// RADIUS_Port and RADIUS_Key
			if (conf->auth_server && conf->auth_server->addr.s_addr != 0)
			{
				if (pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_port > 0)
				{
					radius_port_count++;
		    		conf->auth_server->port = pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_port;
					DBGPRINT(RT_DEBUG_TRACE,"(no.%d) Radius port: '%d'\n", conf->num_auth_servers, conf->auth_server->port);
				}
				else
					DBGPRINT(RT_DEBUG_ERROR, "(no.%d) Radius port is invalid\n", conf->num_auth_servers);

				if (pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key_len > 0)
				{
					radius_key_count++;
					conf->auth_server->shared_secret =
						(u8 *)strdup((const char *)pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key);
					conf->auth_server->shared_secret_len =
						pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key_len;
					DBGPRINT(RT_DEBUG_TRACE,"(no.%d) Radius key: '%s', key_len: %d \n", conf->num_auth_servers,
						conf->auth_server->shared_secret, conf->auth_server->shared_secret_len);
				}
				else
					DBGPRINT(RT_DEBUG_ERROR, "(no.%d) Radius key is invalid\n", conf->num_auth_servers);

			}
#endif
#if HOTSPOT_R3
#if RADIUS_DAS_SUPPORT
				// radius_das_client ip address
			conf->radius_das.client_addr.s_addr = pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_ip;
			DBGPRINT(RT_DEBUG_TRACE, "(no.%d) Radius das client ip address: '%s'(%x)\n", i, inet_ntoa(conf->radius_das.client_addr), conf->radius_das.client_addr.s_addr);
				// radius_das_port and radius_das_key
			conf->radius_das.port = RADIUS_DAS_PORT;
			if (conf->radius_das.port > 0) {
				DBGPRINT(RT_DEBUG_TRACE,"(no.%d) Radius das port: '%d'\n", i, conf->radius_das.port);
			} else
				DBGPRINT(RT_DEBUG_ERROR, "(no.%d) Radius das port is 0\n", i);

			if (pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key_len > 0)
			{
				os_free(conf->radius_das.shared_secret);
				conf->radius_das.shared_secret = (u8 *)strdup((const char *)pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key);
				conf->radius_das.shared_secret_len = pDot1xCmmConf->Dot1xBssInfo[i].radius_srv_info[idx].radius_key_len;
				DBGPRINT(RT_DEBUG_TRACE,"(no.%d) Radius das key: '%s', key_len: %lu \n", i, conf->radius_das.shared_secret, conf->radius_das.shared_secret_len);
			}
			else
				DBGPRINT(RT_DEBUG_ERROR, "(no.%d) Radius das key is invalid\n", i);

				// radius_das_time_window
			conf->radius_das.time_window = RADIUS_DAS_TIME_WINDOW;
			DBGPRINT(RT_DEBUG_TRACE, "(no.%d) Radius das time_window: %d\n", i, conf->radius_das.time_window);
#endif /* RADIUS_DAS_SUPPORT */
#endif
		}
	}

	// Sanity check for radius ip address
	if (radius_count != 0)
		(*flag) |= 0x02;
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, "No any valid radius ip address \n");
		(*errors)++;
	}
	// Sanity check for radius port number
    if (radius_count == radius_port_count)
		(*flag) |= 0x04;
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, "No enough radius port \n");
		(*errors)++;
	}

	// Sanity check for radius key
	if (radius_count == radius_key_count)
		(*flag) |= 0x08;
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, "No enough radius key \n");
		(*errors)++;
	}

   	// radius_retry_primary_interval
   	conf->radius_retry_primary_interval = pDot1xCmmConf->retry_interval;
	if (conf->radius_retry_primary_interval > 0)
		DBGPRINT(RT_DEBUG_TRACE,"Radius retry primary interval %d seconds. \n", conf->radius_retry_primary_interval);

	// session_timeout_interval
	conf->session_timeout_interval = pDot1xCmmConf->session_timeout_interval;
    if (conf->session_timeout_interval == 0)
    {
        conf->session_timeout_set= 0;
    }
    else
    {
        conf->session_timeout_set= 1;

		if (conf->session_timeout_interval < 60)
			conf->session_timeout_interval = REAUTH_TIMER_DEFAULT_reAuthPeriod;

    	DBGPRINT(RT_DEBUG_TRACE,"Radius session timeout interval %d seconds. \n", conf->session_timeout_interval);
    }
    DBGPRINT(RT_DEBUG_TRACE,"session_timeout policy is %s \n", conf->session_timeout_set ? "enabled" : "disabled");

	/* QuietPeriod */
	conf->quiet_interval = pDot1xCmmConf->quiet_interval;
	if (conf->quiet_interval < AUTH_PAE_DEFAULT_quietPeriod)
		conf->quiet_interval = AUTH_PAE_DEFAULT_quietPeriod;
	DBGPRINT(RT_DEBUG_TRACE, "Quiet period %d seconds \n", conf->quiet_interval);


	for (i = 0; i < m_num; i++)
	{
		int	g_key_len = 0;

		if (i == 0)
			snprintf(conf_name, IFNAMSIZ, "%s", MainIfName);
		else
			snprintf(conf_name, IFNAMSIZ, "%s%d", prefix_name, i);

		// DefaultKeyID
		if (pDot1xCmmConf->Dot1xBssInfo[i].ieee8021xWEP)
		{
			// set group key index
			conf->DefaultKeyID[i] = pDot1xCmmConf->Dot1xBssInfo[i].key_index;

			// set unicast key index
			if (conf->DefaultKeyID[i] == 3)
				conf->individual_wep_key_idx[i] = 0;
			else
				conf->individual_wep_key_idx[i] = 3;

			DBGPRINT(RT_DEBUG_TRACE,"IEEE8021X WEP: group key index(%d) and unicast key index(%d) for %s\n",
																	conf->DefaultKeyID[i], conf->individual_wep_key_idx[i], conf_name);

			g_key_len = pDot1xCmmConf->Dot1xBssInfo[i].key_length;
			if (g_key_len == 5 || g_key_len == 13)
			{
				conf->individual_wep_key_len[i] = g_key_len;
				memset(conf->IEEE8021X_ikey[i], 0, WEP8021X_KEY_LEN);
	            memcpy(conf->IEEE8021X_ikey[i], pDot1xCmmConf->Dot1xBssInfo[i].key_material, g_key_len);

				DBGPRINT(RT_DEBUG_TRACE,"IEEE8021X WEP: use Key%dStr as shared Key and its key_len is %d for %s\n",
											conf->DefaultKeyID[i]+1, g_key_len, conf_name);
			}
		}

		/* NAS Identifier */
		if (pDot1xCmmConf->Dot1xBssInfo[i].nasId_len > 0)
		{
			memcpy(conf->nasId[i], pDot1xCmmConf->Dot1xBssInfo[i].nasId, pDot1xCmmConf->Dot1xBssInfo[i].nasId_len);
			conf->nasId_len[i] = pDot1xCmmConf->Dot1xBssInfo[i].nasId_len;
		}
		DBGPRINT(RT_DEBUG_TRACE, "NAS-Identifier: %s and len=%d for %s \n",
									conf->nasId[i], conf->nasId_len[i], conf_name);


		// EAPifname
		if (pDot1xCmmConf->EAPifname_len[i] > 0)
		{
			memset(conf->eap_if_name[num_eap_if], 0, IFNAMSIZ);
			memcpy(conf->eap_if_name[num_eap_if], pDot1xCmmConf->EAPifname[i], pDot1xCmmConf->EAPifname_len[i]);

			DBGPRINT(RT_DEBUG_TRACE, "(no.%d) EAPifname: %s \n", num_eap_if + 1, conf->eap_if_name[num_eap_if]);
			num_eap_if ++;
		}

		// PreAuthifname
		if (pDot1xCmmConf->PreAuthifname_len[i] > 0)
		{
			memset(conf->preauth_if_name[num_preauth_if], 0, IFNAMSIZ);
			memcpy(conf->preauth_if_name[num_preauth_if], pDot1xCmmConf->PreAuthifname[i], pDot1xCmmConf->PreAuthifname_len[i]);

			DBGPRINT(RT_DEBUG_TRACE,"(no.%d) PreAuthifname: %s \n", num_preauth_if + 1, conf->preauth_if_name[num_preauth_if]);
			num_preauth_if ++;
		}

#ifdef RADIUS_MAC_ACL_SUPPORT
		// Radius ACL Cache
		conf->RadiusAclEnable[i] = pDot1xCmmConf->RadiusAclEnable[i];
	        DBGPRINT(RT_DEBUG_TRACE,"(no.%d) ACL_Enable: %d \n", i, conf->RadiusAclEnable[i]);

		conf->AclCacheTimeout[i] = pDot1xCmmConf->AclCacheTimeout[i];
		DBGPRINT(RT_DEBUG_TRACE,"(no.%d) ACL_Cache_Timeout: %d \n", i, conf->AclCacheTimeout[i]);
#endif /* RADIUS_MAC_ACL_SUPPORT */
	}

	if (num_eap_if > 0)
		conf->num_eap_if = num_eap_if;
	if (num_preauth_if > 0)
		conf->num_preauth_if = num_preauth_if;

	free(buf);

	return TRUE;

}


struct rtapd_config * Config_read(int ioctl_sock, char *prefix_name)
{
	struct rtapd_config *conf;
	int errors = 0, i = 0;
	int flag = 0, res = 0;

    conf = malloc(sizeof(*conf));
    if (conf == NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "Failed to allocate memory for configuration data.\n");
        return NULL;
    }
    memset(conf, 0, sizeof(*conf));

    conf->SsidNum = 1;
    conf->session_timeout_set = 0xffff;

    /* Some related variable per BSS set to default */
    for (i = 0; i < MAX_MBSSID_NUM; i++)
    {
		/* initial default shared-key material and index */
		conf->DefaultKeyID[i] = 0;										// broadcast key index
		conf->individual_wep_key_idx[i] = 3;							// unicast key index
    	conf->individual_wep_key_len[i] = WEP8021X_KEY_LEN;				// key length
    	hostapd_get_rand(conf->IEEE8021X_ikey[i], WEP8021X_KEY_LEN);    // generate shared key randomly

		/* Initial NAS-ID */
		memcpy(conf->nasId[i], "RalinkAP", 8);
		conf->nasId[i][8] = '0' + i;
		conf->nasId_len[i] = 9;
  	}
#ifdef CONFIG_SUPPORT_OPENWRT
	// initial default EAP IF name and Pre-Auth IF name	as "br-lan"
	conf->num_eap_if = 1;
	conf->num_preauth_if = 1;
	res = snprintf(conf->eap_if_name[0], IFNAMSIZ, "br-lan");
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");
		goto fail;
	}

	res = snprintf(conf->preauth_if_name[0], IFNAMSIZ, "br-lan");
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");
		goto fail;
	}
#else
	// initial default EAP IF name and Pre-Auth IF name	as "br0"
	conf->num_eap_if = 1;
	conf->num_preauth_if = 1;
	res = snprintf(conf->eap_if_name[0], IFNAMSIZ, "br0");
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");
		goto fail;
	}

	res = snprintf(conf->preauth_if_name[0], IFNAMSIZ, "br0");
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");
		goto fail;
	}

#endif

#if HOTSPOT_R3
	if (!hs_read_from_config(prefix_name, conf))
		DBGPRINT(RT_DEBUG_TRACE, "Read from config failed");
#endif
	// Get parameters from deiver through IOCTL cmd
	if(!Query_config_from_driver(ioctl_sock, prefix_name, conf, &errors, &flag))
	{
#if HOTSPOT_R3
		if (conf->hs_TandC_filename)
			free(conf->hs_TandC_filename);
		if (conf->hs_TandC_server_url)
			free(conf->hs_TandC_server_url);
		if (conf->hs_TandC_timestamp)
			free(conf->hs_TandC_timestamp);
#endif
		Config_free(conf);
		return NULL;
	}

	struct iwreq iwr;
	char ssidBuf[HOSTAPD_MAX_SSID_LEN];
	for(i = 0; i < conf->SsidNum; i++)
	{
		memset(&iwr, 0, sizeof(iwr));
		memset(ssidBuf, 0, sizeof(ssidBuf));

		if (i == 0)
			res = snprintf(iwr.ifr_name, IFNAMSIZ, "%s", MainIfName);
		else
			res = snprintf(iwr.ifr_name, IFNAMSIZ, "%s%d", prefix_name, i);

		if (os_snprintf_error(IFNAMSIZ, res)) {
			DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");
			goto fail;
		}
		iwr.u.essid.pointer = ssidBuf;
		iwr.u.essid.length = HOSTAPD_MAX_SSID_LEN;

		if (ioctl(ioctl_sock, SIOCGIWESSID, &iwr) < 0)
		{
			perror("ioctl[SIOCGIWESSID]");
		}
		else
		{
			conf->SsidLen[i] = iwr.u.essid.length;
			memset(conf->Ssid[i], 0, HOSTAPD_MAX_SSID_LEN);
			memcpy(conf->Ssid[i], ssidBuf, conf->SsidLen[i]);
			DBGPRINT(RT_DEBUG_TRACE, "From Driver MBSSID%d: %s, %d\n", i, conf->Ssid[i], conf->SsidLen[i]);
		}

	}

#if MULTIPLE_RADIUS
	for (i = 0; i < MAX_MBSSID_NUM; i++)
	{
		struct hostapd_radius_server *servs, *cserv, *nserv;
		int c;

		if (i == 0)
			res = snprintf(iwr.ifr_name, IFNAMSIZ, "%s", MainIfName);
		else
			res = snprintf(iwr.ifr_name, IFNAMSIZ, "%s%d", prefix_name, i);

		if (os_snprintf_error(IFNAMSIZ, res)) {
			DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");
			goto fail;
		}

		conf->mbss_auth_server[i] = conf->mbss_auth_servers[i];

		if (!conf->mbss_auth_server[i])
			continue;

		cserv	= conf->mbss_auth_server[i];
		servs 	= conf->mbss_auth_servers[i];

		DBGPRINT(RT_DEBUG_TRACE, "%s, Current IP: %s \n", iwr.ifr_name, inet_ntoa(cserv->addr));
		for (c = 0; c < conf->mbss_num_auth_servers[i]; c++)
		{
			nserv = &servs[c];
			DBGPRINT(RT_DEBUG_TRACE, "	   Server IP List: %s \n", inet_ntoa(nserv->addr));
		}
	}
#else
	conf->auth_server = conf->auth_servers;
#endif

	if (errors)
	{
		DBGPRINT(RT_DEBUG_ERROR,"%d errors for radius setting\n", errors);
#if HOTSPOT_R3
		if (conf->hs_TandC_filename)
			free(conf->hs_TandC_filename);
		if (conf->hs_TandC_server_url)
			free(conf->hs_TandC_server_url);
		if (conf->hs_TandC_timestamp)
			free(conf->hs_TandC_timestamp);
#endif
		Config_free(conf);
		conf = NULL;
	}
	if ((flag&0x0f)!=0x0f)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Not enough necessary parameters are found, flag = %x\n", flag);
		if (conf) {
#if HOTSPOT_R3
			if (conf->hs_TandC_filename)
				free(conf->hs_TandC_filename);
			if (conf->hs_TandC_server_url)
				free(conf->hs_TandC_server_url);
			if (conf->hs_TandC_timestamp)
				free(conf->hs_TandC_timestamp);
#endif
			Config_free(conf);
			conf = NULL;
		}
	}

	return conf;

fail:
#if HOTSPOT_R3
	if (conf->hs_TandC_filename)
		free(conf->hs_TandC_filename);
	if (conf->hs_TandC_server_url)
		free(conf->hs_TandC_server_url);
	if (conf->hs_TandC_timestamp)
		free(conf->hs_TandC_timestamp);
#endif
	Config_free(conf);
	conf = NULL;
	return conf;
}

static void Config_free_radius(struct hostapd_radius_server *servers, int num_servers)
{
    int i;

    for (i = 0; i < num_servers; i++)
    {
        free(servers[i].shared_secret);
    }
    free(servers);
}

void Config_free(struct rtapd_config *conf)
{
#if MULTIPLE_RADIUS
	int	i;
#endif

    if (conf == NULL)
        return;

#if MULTIPLE_RADIUS
	for (i = 0; i < MAX_MBSSID_NUM; i++)
	{
		if (conf->mbss_auth_servers[i])
			Config_free_radius(conf->mbss_auth_servers[i], conf->mbss_num_auth_servers[i]);
	}
#else
    Config_free_radius(conf->auth_servers, conf->num_auth_servers);
#endif
    free(conf);
}

