#include "includes.h"

#include "common.h"
#include "utils/list.h"
#include "common/dhcp.h"
#include "rtdot1x.h"
#include "config.h"
/*
 conf->
    struct dl_list fils_realms;
    struct hostapd_ip_addr dhcp_server;
    int dhcp_rapid_commit_proxy;
    unsigned int fils_hlp_wait_time;
    u16 dhcp_server_port;
    u16 dhcp_relay_port;

 apd_data->
	 struct sec_info ap_sec_info[MAX_MBSSID_NUM];
	 u16 sync_status[MAX_MBSSID_NUM];
	 u16 capab_info[MAX_MBSSID_NUM];
 */

void fils_config_default(struct apd_data *hapd)
{
	struct rtapd_config *conf = NULL;

	if (!hapd->conf)
		return;

	conf = hapd->conf;
	
	dl_list_init(&conf->fils_realms);
	conf->fils_hlp_wait_time = 100;
	conf->dhcp_server_port = DHCP_SERVER_PORT;
	conf->dhcp_relay_port = DHCP_SERVER_PORT;

	hapd->dhcp_sock = -1;	
}
