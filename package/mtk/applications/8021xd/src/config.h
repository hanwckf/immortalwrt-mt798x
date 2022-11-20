#ifndef CONFIG_H
#define CONFIG_H

#if HOTSPOT_R3
#define TC_FILENAME_LEN 128
#define TC_SERVER_URL_LEN
#define HS_CONFIG_FILE_RA "/etc/wapp_ap_ra0.conf"
#define HS_CONFIG_FILE_RAX "/etc/wapp_ap_rax0.conf"
#endif

#include "utils/list.h"
#include "ip_addr.h"

typedef u8 macaddr[ETH_ALEN];

struct hostapd_radius_server {
	struct in_addr addr;
	int port;
	u8 *shared_secret;
	size_t shared_secret_len;
};

#define HOSTAPD_MAX_SSID_LEN 32

struct rtapd_config {
	char iface_name[IFNAMSIZ + 1];
	int SsidNum;
	char Ssid[MAX_MBSSID_NUM][HOSTAPD_MAX_SSID_LEN+1];
	int SsidLen[MAX_MBSSID_NUM];
#ifdef RADIUS_MAC_ACL_SUPPORT
	unsigned int AclCacheTimeout[MAX_MBSSID_NUM];  /* From Driver, Default 30s */
	unsigned char RadiusAclEnable[MAX_MBSSID_NUM];
#endif /* RADIUS_MAC_ACL_SUPPORT */
	int DefaultKeyID[MAX_MBSSID_NUM];
	int individual_wep_key_len[MAX_MBSSID_NUM];
	int	individual_wep_key_idx[MAX_MBSSID_NUM];
	u8 IEEE8021X_ikey[MAX_MBSSID_NUM][WEP8021X_KEY_LEN];
	
#define HOSTAPD_MODULE_IEEE80211 BIT(0)
#define HOSTAPD_MODULE_IEEE8021X BIT(1)
#define HOSTAPD_MODULE_RADIUS BIT(2)

	enum { HOSTAPD_DEBUG_NO = 0, HOSTAPD_DEBUG_MINIMAL = 1,
	       HOSTAPD_DEBUG_VERBOSE = 2,
	       HOSTAPD_DEBUG_MSGDUMPS = 3 } debug; /* debug verbosity level */
	int daemonize; /* fork into background */

	struct in_addr own_ip_addr;
	int own_radius_port;

	/* RADIUS Authentication and Accounting servers in priority order */
#if MULTIPLE_RADIUS
	struct hostapd_radius_server *mbss_auth_servers[MAX_MBSSID_NUM], *mbss_auth_server[MAX_MBSSID_NUM];
	int mbss_num_auth_servers[MAX_MBSSID_NUM];
#else
	struct hostapd_radius_server *auth_servers, *auth_server;
	int num_auth_servers;
#endif
	
	int	 num_eap_if;
	char eap_if_name[MAX_MBSSID_NUM][IFNAMSIZ];

	int	 num_preauth_if;
	char preauth_if_name[MAX_MBSSID_NUM][IFNAMSIZ];

	int radius_retry_primary_interval;

	int session_timeout_set;
	int session_timeout_interval;

	/* The initialization value used for the quietWhile timer. 
	   Its default value is 60 s; it can be set by management 
	   to any value in the range from 0 to 65535 s. 

	   NOTE 1 - The Authenticator may increase the value of quietPeriod 
	   per Port to ignore authorization failures for longer periods 
	   of time after a number of authorization failures have occurred.*/	
	int 	quiet_interval;

	u8		nasId[MAX_MBSSID_NUM][32];
	int		nasId_len[MAX_MBSSID_NUM];

#ifdef CONFIG_FILS
    struct dl_list fils_realms; /* list of struct fils_realm */
    struct hostapd_ip_addr dhcp_server;
    int dhcp_rapid_commit_proxy;
    unsigned int fils_hlp_wait_time;
    u16 dhcp_server_port;
    u16 dhcp_relay_port;
#endif /* CONFIG_FILS */

#if HOTSPOT_R3
#ifdef RADIUS_DAS_SUPPORT
    struct radius_das_data radius_das;
#endif /* RADIUS_DAS_SUPPORT */
	char *hs_TandC_filename;
	int hs_TandC_filename_len;
	char *hs_TandC_server_url;
	int hs_TandC_server_url_len;
	char *hs_TandC_timestamp;
#endif /* HOTSPOT_R3 */
};


struct rtapd_config * Config_read(int ioctl_sock, char *prefix_name);
void Config_free(struct rtapd_config *conf);


#endif /* CONFIG_H */
