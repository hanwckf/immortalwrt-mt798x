

#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if.h>			/* for IFNAMSIZ and co... */
#include <linux/wireless.h>

#include "rtdot1x.h"
#include "eloop.h"
#include "ieee802_1x.h"
#include "eapol_sm.h"
#include "ap.h"
#include "sta_info.h"
#include "radius_client.h"
#include "config.h"
#include "radius.h"
#include "os.h"
#ifdef RADIUS_MAC_ACL_SUPPORT
#include "ieee802_11_auth.h"
#endif /* RADIUS_MAC_ACL_SUPPORT */

//#define RT2860AP_SYSTEM_PATH   "/etc/Wireless/RT2860AP/RT2860AP.dat"
#include "drvcallbak/drv_hook.h"
extern const struct wpa_driver_ops wpa_driver_mediatek_ops;

struct hapd_interfaces {
	int count;
	rtapd **rtapd;
};

int	RTDebugLevel = RT_DEBUG_ERROR;
char	MainIfName[IFNAMSIZ];

/*
	========================================================================

	Routine Description:
		Compare two memory block

	Arguments:
		Adapter						Pointer to our adapter

	Return Value:
		0:			memory is equal
		1:			pSrc1 memory is larger
		2:			pSrc2 memory is larger

	Note:

	========================================================================
*/
u16	RTMPCompareMemory(void *pSrc1,void *pSrc2, u16 Length)
{
	char *pMem1;
	char *pMem2;
	u16	Index = 0;

	pMem1 = (char*) pSrc1;
	pMem2 = (char*) pSrc2;

	for (Index = 0; Index < Length; Index++)
	{
		if (pMem1[Index] > pMem2[Index])
			return (1);
		else if (pMem1[Index] < pMem2[Index])
			return (2);
	}

	// Equal
	return (0);
}

int RT_ioctl(
		int 			sid,
		int 			param,
		char  			*data,
		int 			data_len,
		char 			*prefix_name,
		unsigned char 	apidx,
		int 			flags)
{
	int ret = 1;
	struct iwreq wrq;
	int res = 0;

	if (apidx == 0)
		res = snprintf(wrq.ifr_name, IFNAMSIZ, "%s", MainIfName);
	else
		res = snprintf(wrq.ifr_name, IFNAMSIZ, "%s%d", prefix_name, apidx);
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");
		return ret;
	}

	wrq.u.data.flags = flags;
	wrq.u.data.length = data_len;
	wrq.u.data.pointer = (caddr_t) data;

	ret = ioctl(sid, param, &wrq);

	return ret;
}

void dot1x_set_IdleTimeoutAction(
		rtapd *rtapd,
		struct sta_info *sta,
		u32		idle_timeout)
{
	DOT1X_IDLE_TIMEOUT dot1x_idle_time;

	memset(&dot1x_idle_time, 0, sizeof(DOT1X_IDLE_TIMEOUT));

	memcpy(dot1x_idle_time.StaAddr, sta->addr, MAC_ADDR_LEN);

	dot1x_idle_time.idle_timeout =
		((idle_timeout < DEFAULT_IDLE_INTERVAL) ? DEFAULT_IDLE_INTERVAL : idle_timeout);

	if (RT_ioctl(rtapd->ioctl_sock,
				 RT_PRIV_IOCTL,
				 (char *)&dot1x_idle_time,
				 sizeof(DOT1X_IDLE_TIMEOUT),
				 rtapd->prefix_wlan_name, sta->ApIdx,
				 RT_OID_802_DOT1X_IDLE_TIMEOUT))
	{
    	DBGPRINT(RT_DEBUG_ERROR,"Failed to RT_OID_802_DOT1X_IDLE_TIMEOUT\n");
    	return;
	}

}

static void write_pidfile(char *funcName)
{
	char pid_file_path[256];
	char *path_name	= "/var/run/";
	FILE *fp;
	int res = 0;

	/* Write the pid file */
	memset(&pid_file_path[0], 0, sizeof(pid_file_path));
	res = snprintf(pid_file_path, sizeof(pid_file_path), "%s%s_%s.pid", path_name, funcName, MainIfName);
	if (os_snprintf_error(sizeof(pid_file_path), res))
		DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");

	if ((fp = fopen(pid_file_path, "w")) != NULL)
	{
		if (fprintf(fp, "%d", getpid()) < 0)
			DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected fprintf fail!\n", __LINE__);
		if (fclose(fp) != 0)
			DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected fclose fail!\n", __LINE__);
	}
}

static void Handle_reload_config(
	rtapd 	*rtapd)
{
	struct rtapd_config *newconf;
#if MULTIPLE_RADIUS
	int i;
#endif // MULTIPLE_RADIUS //

	DBGPRINT(RT_DEBUG_TRACE, "Reloading configuration\n");

	/* create new config */
	newconf = Config_read(rtapd->ioctl_sock, rtapd->prefix_wlan_name);
	if (newconf == NULL)
    {
		DBGPRINT(RT_DEBUG_ERROR, "Failed to read new configuration file - continuing with old.\n");
		return;
	}

	/* TODO: update dynamic data based on changed configuration
	 * items (e.g., open/close sockets, remove stations added to
	 * deny list, etc.) */
	Radius_client_flush(rtapd);
	Config_free(rtapd->conf);
	rtapd->conf = newconf;
    Apd_free_stas(rtapd);

	/* when reStartAP, no need to reallocate sock
    for (i = 0; i < rtapd->conf->SsidNum; i++)
    {
        if (rtapd->sock[i] >= 0)
            close(rtapd->sock[i]);

	    rtapd->sock[i] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	    if (rtapd->sock[i] < 0)
        {
		    perror("socket[PF_PACKET,SOCK_RAW]");
		    return;
	    }
    }*/

#if MULTIPLE_RADIUS
	for (i = 0; i < MAX_MBSSID_NUM; i++)
		rtapd->radius->mbss_auth_serv_sock[i] = -1;
#else
	rtapd->radius->auth_serv_sock = -1;
#endif

    if (Radius_client_init(rtapd))
    {
	    DBGPRINT(RT_DEBUG_ERROR,"RADIUS client initialization failed.\n");
	    return;
    }
#if MULTIPLE_RADIUS
	for (i = 0; i < rtapd->conf->SsidNum; i++)
		DBGPRINT(RT_DEBUG_TRACE, "auth_serv_sock[%d] = %d\n", i, rtapd->radius->mbss_auth_serv_sock[i]);
#else
    DBGPRINT(RT_DEBUG_TRACE,"rtapd->radius->auth_serv_sock = %d\n",rtapd->radius->auth_serv_sock);
#endif

	fils_config_default(rtapd);
}

static void Handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	rtapd *rtapd = eloop_ctx;
	int len;
	unsigned char buf[3000];
	u8 *sa, *da, *pos, *pos_vlan, apidx=0, isVlanTag=0;
	u16 ethertype,i;
	priv_rec *rec;
	int left;
	u8 	RalinkIe[9] = {221, 7, 0x00, 0x0c, 0x43, 0x00, 0x00, 0x00, 0x00};
	u8 icmd;
	u8 skip_cmd_len_check = 0;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0)
    {
		perror("recv");
        Handle_term(15,eloop_ctx,sock_ctx);
        return;
	}

	rec = (priv_rec*)buf;
    left = len -sizeof(*rec)+1;
	if (left <= 0)
	{
		DBGPRINT(RT_DEBUG_ERROR," too short recv\n");
		return;
	}

    sa = rec->saddr;
	da = rec->daddr;
	ethertype = rec->ethtype[0] << 8;
	ethertype |= rec->ethtype[1];

#ifdef ETH_P_VLAN
	if(ethertype == ETH_P_VLAN)
    {
    	pos_vlan = rec->xframe;

        if(left >= 4)
        {
			ethertype = *(pos_vlan+2) << 8;
			ethertype |= *(pos_vlan+3);
		}

		if((ethertype == ETH_P_PRE_AUTH) || (ethertype == ETH_P_PAE))
		{
			isVlanTag = 1;
			DBGPRINT(RT_DEBUG_TRACE,"Recv vlan tag for 802.1x. (%02x %02x)\n", *(pos_vlan), *(pos_vlan+1));
		}
    }
#endif

	if ((ethertype == ETH_P_PRE_AUTH) || (ethertype == ETH_P_PAE))
    {
        // search this packet is coming from which interface
		for (i = 0; i < rtapd->conf->SsidNum; i++)
		{
			if (memcmp(da, rtapd->own_addr[i], 6) == 0)
		    {
		        apidx = i;
		        break;
		    }
		}

		if(i >= rtapd->conf->SsidNum)
		{
	        DBGPRINT(RT_DEBUG_WARN, "Receive unexpected DA "MACSTR"\n",MAC2STR(da));
		    return;
		}
		// eth_sock and wlan_sock bind to br-lan. Only eth_sock[0]/wlan_sock[0] is valid.
		if (ethertype == ETH_P_PRE_AUTH)
		{
			if(rtapd->eth_sock[0] != sock)
				return;
		}
		else
		{
			if(rtapd->wlan_sock[0] != sock)
				return;
		}

		if (ethertype == ETH_P_PRE_AUTH)
		{
			if (apidx == 0)
			{
				DBGPRINT(RT_DEBUG_TRACE, "Receive WPA2 pre-auth packet for %s\n", rtapd->main_wlan_name);
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE, "Receive WPA2 pre-auth packet for %s%d\n", rtapd->prefix_wlan_name, apidx);
			}
		}
		else
		{
			if (apidx == 0)
			{
				DBGPRINT(RT_DEBUG_TRACE, "Receive EAP packet for %s\n", rtapd->main_wlan_name);
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE, "Receive EAP packet for %s%d\n", rtapd->prefix_wlan_name, apidx);
			}
		}
    }
	else
	{
		DBGPRINT(RT_DEBUG_ERROR, "Receive unexpected ethertype 0x%04X!!!\n", ethertype);
		return;
	}

    pos = rec->xframe;

    //strip 4 bytes for valn tag
    if(isVlanTag)
    {
    	pos += 4;
    	left -= 4;
	}

	icmd = *(pos + 5);

	if ((icmd == DOT1X_MLME_MGMT_EVENT) ||
	    (icmd == DOT1X_MLME_AEAD_DECR_EVENT) ||
	    (icmd == DOT1X_MLME_AEAD_ENCR_EVENT))
	   skip_cmd_len_check = 1;

	/* Check if this is a internal command or not */
	if ((left == sizeof(RalinkIe) || skip_cmd_len_check) &&
		RTMPCompareMemory(pos, RalinkIe, 5) == 0)
	{
		switch(icmd)
		{
			case DOT1X_DISCONNECT_ENTRY:
			{
				struct sta_info *s;

				s = rtapd->sta_hash[STA_HASH(sa)];
				while (s != NULL && memcmp(s->addr, sa, 6) != 0)
				s = s->hnext;

				DBGPRINT(RT_DEBUG_TRACE, "Receive discard-notification form wireless driver.\n");
				if (s)
				{
					DBGPRINT(RT_DEBUG_TRACE,"This station"MACSTR " is removed.\n", MAC2STR(sa));
					Ap_free_sta(rtapd, s);
				}
				else
				{
					DBGPRINT(RT_DEBUG_INFO, "This station"MACSTR "doesn't exist.\n", MAC2STR(sa));
				}
			}
			break;

			case DOT1X_RELOAD_CONFIG:
				Handle_reload_config(rtapd);
			break;
#ifdef RADIUS_MAC_ACL_SUPPORT
			case DOT1X_ACL_ENTRY:
				DBGPRINT(RT_DEBUG_TRACE, "STA "MACSTR "go to RADIUS-ACL Checking.\n", MAC2STR(sa));
				DBGPRINT(RT_DEBUG_TRACE, "--> From AP Index: %d\n", apidx);
				DBGPRINT(RT_DEBUG_TRACE, "--> Socket No.: %d\n", sock);
				u32 session_timeout, acct_interim_interval;
				int vlan_id = 0, res = 0;

				res = hostapd_allowed_address(rtapd, sa, &apidx, ethertype, sock, NULL, 0,
							&session_timeout, &acct_interim_interval, &vlan_id);

				if (res == HOSTAPD_ACL_ACCEPT_TIMEOUT)
                                        DBGPRINT(RT_DEBUG_TRACE, "--> SessionTimeout: %d\n", session_timeout);

			break;
#endif /* RADIUS_MAC_ACL_SUPPORT */
			case DOT1X_MLME_MGMT_EVENT:
				pos += sizeof(RalinkIe);
    			left -= sizeof(RalinkIe);
				DBGPRINT(RT_DEBUG_ERROR, "DOT1X_MLME_MGMT_EVENT command(%d)!!!\n", icmd);
				//hex_dump("mgmt event", pos , left);
				Handle_mlme_event(rtapd, sa, &apidx, ethertype, sock, pos, left);
			break;
			case DOT1X_MLME_AEAD_DECR_EVENT:
				pos += sizeof(RalinkIe);
    			left -= sizeof(RalinkIe);
				DBGPRINT(RT_DEBUG_ERROR, "DOT1X_MLME_AEAD_DECR_EVENT command(%d)!!!\n", icmd);
				Handle_aead_decr_event(rtapd, sa, &apidx, ethertype, sock, pos, left);
			break;
			case DOT1X_MLME_AEAD_ENCR_EVENT:
				pos += sizeof(RalinkIe);
    			left -= sizeof(RalinkIe);
				DBGPRINT(RT_DEBUG_ERROR, "DOT1X_MLME_AEAD_ENCR_EVENT command(%d)!!!\n", icmd);
				Handle_aead_encr_event(rtapd, sa, &apidx, ethertype, sock, pos, left);
			break;
			default:
				DBGPRINT(RT_DEBUG_ERROR, "Unknown internal command(%d)!!!\n", icmd);
			break;
		}
	}
	else
	{
		/* Process the general EAP packet */
#ifndef HOTSPOT_R2 || HOTSPOT_R3
	if(rtapd->wlan_sock[i] == sock)
#endif
    		ieee802_1x_receive(rtapd, sa, &apidx, pos, left, ethertype, sock);
	}
}

int Apd_init_sockets(rtapd *rtapd)
{
	struct ifreq ifr;
	struct sockaddr_ll addr;
	int res = 0, i;

	/* 1. init ethernet interface socket for pre-auth */
	for (i = 0; i < rtapd->conf->num_preauth_if; i++)
	{
		rtapd->eth_sock[i] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PRE_AUTH));
		if (rtapd->eth_sock[i] < 0) {
			perror("socket[PF_PACKET,SOCK_RAW](eth_sock)");
			return -1;
		}

		if (eloop_register_read_sock(rtapd->eth_sock[i], Handle_read, rtapd, NULL)) {
			DBGPRINT(RT_DEBUG_ERROR, "Could not register read socket(eth_sock)\n");
			return -1;
		}

		memset(&ifr, 0, sizeof(ifr));
		res = snprintf(ifr.ifr_name, IFNAMSIZ, "%s", rtapd->conf->preauth_if_name[i]);
		if (os_snprintf_error(IFNAMSIZ, res)) {
			DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
			return -1;
		}
		DBGPRINT(RT_DEBUG_TRACE, "Register pre-auth interface as (%s)\n", ifr.ifr_name);

		if (ioctl(rtapd->eth_sock[i], SIOCGIFINDEX, &ifr) != 0) {
			perror("ioctl(SIOCGIFHWADDR)(eth_sock)");
			return -1;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sll_family = AF_PACKET;
		addr.sll_ifindex = ifr.ifr_ifindex;
		if (bind(rtapd->eth_sock[i], (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			perror("bind");
			return -1;
		}
		DBGPRINT(RT_DEBUG_TRACE, "Pre-auth raw packet socket binding on %s(socknum=%d,ifindex=%d)\n",
					  ifr.ifr_name, rtapd->eth_sock[i], addr.sll_ifindex);
	}

	/* 2. init wireless interface socket for EAP negotiation */
	for (i = 0; i < rtapd->conf->num_eap_if; i++)
	{
		rtapd->wlan_sock[i] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));

		if (rtapd->wlan_sock[i] < 0) {
			perror("socket[PF_PACKET,SOCK_RAW]");
			return -1;
		}

		if (eloop_register_read_sock(rtapd->wlan_sock[i], Handle_read, rtapd, NULL)) {
			DBGPRINT(RT_DEBUG_ERROR, "Could not register read socket\n");
			return -1;
		}

		memset(&ifr, 0, sizeof(ifr));
		res = snprintf(ifr.ifr_name, IFNAMSIZ, "%s", rtapd->conf->eap_if_name[i]);
		if (os_snprintf_error(IFNAMSIZ, res)) {
			DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
			return -1;
		}
		DBGPRINT(RT_DEBUG_TRACE,"Register EAP interface as (%s)\n", ifr.ifr_name);

		if (ioctl(rtapd->wlan_sock[i], SIOCGIFINDEX, &ifr) != 0) {
			perror("ioctl(SIOCGIFHWADDR)");
			return -1;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sll_family = AF_PACKET;
		addr.sll_ifindex = ifr.ifr_ifindex;
		if (bind(rtapd->wlan_sock[i], (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			perror("bind");
			return -1;
		}
		DBGPRINT(RT_DEBUG_TRACE, "EAP raw packet socket binding on %s (socknum=%d,ifindex=%d)\n",
					  ifr.ifr_name, rtapd->wlan_sock[i], addr.sll_ifindex);
	}


	/* 3. Get wireless interface MAC address */
	for (i = 0; i < rtapd->conf->SsidNum; i++) {
		int s = 0;

		s = socket(AF_INET, SOCK_DGRAM, 0);

		if (s < 0) {
			perror("socket[AF_INET,SOCK_DGRAM]");
			return -1;
		}

		memset(&ifr, 0, sizeof(ifr));

		if (i == 0)
			res = snprintf(ifr.ifr_name, IFNAMSIZ, "%s", rtapd->main_wlan_name);
		else
			res = snprintf(ifr.ifr_name, IFNAMSIZ, "%s%d", rtapd->prefix_wlan_name, i);
		if (os_snprintf_error(IFNAMSIZ, res)) {
			DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
			close(s);
			return -1;
		}

		/* Get MAC address */
		if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0) {
			perror("ioctl(SIOCGIFHWADDR)");
			close(s);
			return -1;
		}

		DBGPRINT(RT_DEBUG_INFO, " Device %s has ifr.ifr_hwaddr.sa_family %d\n", ifr.ifr_name, ifr.ifr_hwaddr.sa_family);
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
			DBGPRINT(RT_DEBUG_ERROR, "IF-%s : Invalid HW-addr family 0x%04x\n", ifr.ifr_name, ifr.ifr_hwaddr.sa_family);
			close(s);
			return -1;
		}

		memcpy(rtapd->own_addr[i], ifr.ifr_hwaddr.sa_data, ETH_ALEN);
		DBGPRINT(RT_DEBUG_TRACE, "IF-%s MAC Address = " MACSTR "\n", ifr.ifr_name, MAC2STR(rtapd->own_addr[i]));

		close(s);
	}


	return 0;
}

static void Apd_cleanup(rtapd *rtapd)
{
	int i;
	struct sec_info *ap_sec_info = NULL;

	for (i = 0; i < MAX_MBSSID_NUM; i++)
	{
		if (rtapd->wlan_sock[i] >= 0)
			close(rtapd->wlan_sock[i]);
		if (rtapd->eth_sock[i] >= 0)
			close(rtapd->eth_sock[i]);

		ap_sec_info = &rtapd->ap_sec_info[i];
		if (ap_sec_info->wpa_ie)
			free(ap_sec_info->wpa_ie);
	}

	if (rtapd->ioctl_sock >= 0)
		close(rtapd->ioctl_sock);

	Radius_client_deinit(rtapd);
#ifdef RADIUS_DAS_SUPPORT
        radius_das_deinit(rtapd->conf);
#endif /* RADIUS_DAS_SUPPORT */
	pmksa_cache_local_free(rtapd->pmk_cache);

	Config_free(rtapd->conf);
	rtapd->conf = NULL;

	free(rtapd->main_wlan_name);
	free(rtapd->prefix_wlan_name);
}

static int Apd_setup_interface(rtapd *rtapd)
{
	struct ifreq ifr;
	int res = 0;
#if MULTIPLE_RADIUS
	int i;
#endif

	if (Apd_init_sockets(rtapd))
		return -1;

	if (Radius_client_init(rtapd))
	{
		DBGPRINT(RT_DEBUG_ERROR,"RADIUS client initialization failed.\n");
		return -1;
	}

	if (ieee802_1x_init(rtapd))
	{
		DBGPRINT(RT_DEBUG_ERROR,"IEEE 802.1X initialization failed.\n");
		return -1;
	}
#if MULTIPLE_RADIUS
	for (i = 0; i < rtapd->conf->SsidNum; i++)
		DBGPRINT(RT_DEBUG_TRACE, "auth_serv_sock[%d] = %d\n", i, rtapd->radius->mbss_auth_serv_sock[i]);
#else
	DBGPRINT(RT_DEBUG_TRACE, "rtapd->radius->auth_serv_sock = %d\n", rtapd->radius->auth_serv_sock);
#endif

#ifdef RADIUS_MAC_ACL_SUPPORT
	if (hostapd_acl_init(rtapd))
	{
		DBGPRINT(RT_DEBUG_ERROR, "ACL initialization failed.\n");
		return -1;
	}
#endif /* RADIUS_MAC_ACL_SUPPORT */

#if HOTSPOT_R3
#ifdef RADIUS_DAS_SUPPORT
	memset(&ifr, 0, sizeof(ifr));
	res = snprintf(ifr.ifr_name, IFNAMSIZ, "%s", rtapd->main_wlan_name);
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
		return -1;
	}

	if (!os_strcmp(ifr.ifr_name, "rax0"))
	{
		if (radius_das_init(rtapd))
		{
			DBGPRINT(RT_DEBUG_ERROR,"DAS initialization failed.\n");
			return -1;
		}
	}
#endif /* RADIUS_DAS_SUPPORT */
#endif /*HOTSPOT_R3*/
	return 0;
}

static void usage(void)
{
	DBGPRINT(RT_DEBUG_OFF, "USAGE :  	rtdot1xd [optional command]\n");
	DBGPRINT(RT_DEBUG_OFF, "[optional command] : \n");
	DBGPRINT(RT_DEBUG_OFF, "-i <main_interface_name> : indicate which main interface name is used\n");
	DBGPRINT(RT_DEBUG_OFF, "-p <prefix name> : indicate which prefix name is used\n");
	DBGPRINT(RT_DEBUG_OFF, "-d <debug_level> : set debug level\n");

	exit(1);
}

static int mtk_sec_akmp_to_profile(u32 wpa_key_mgmt)
{
	if (IS_AKM_FILS_SHA256(wpa_key_mgmt))
		return WPA_KEY_MGMT_FILS_SHA256;
	else if (IS_AKM_FILS_SHA384(wpa_key_mgmt))
		return WPA_KEY_MGMT_FILS_SHA384;
	else
		return WPA_KEY_MGMT_IEEE8021X;
}

static void mtk_sec_rsne_sync(rtapd *rtapd)
{
	RT_802_11_SEC_INFO_SYNC_EVENT sta_sec_event;
	struct sec_info *ap_sec_info = NULL;
	int i = 0, ret = 0;

	for (i = 0; i < rtapd->conf->SsidNum; i++)
	{
		ap_sec_info = &rtapd->ap_sec_info[i];
		memset(&sta_sec_event, 0, sizeof(RT_802_11_SEC_INFO_SYNC_EVENT));
		sta_sec_event.apidx = i;

		/* RSNE Sync from driver */
		ret = RT_ioctl(rtapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&sta_sec_event,
			sizeof(RT_802_11_SEC_INFO_SYNC_EVENT), rtapd->prefix_wlan_name, i,
			RT_OID_802_DOT1X_RSNE_SYNC);

	    if (ret < 0) {
	            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to get RSNE (MBSS %d)\n",
	                       __func__, i);
	    } else {
	    	if (sta_sec_event.rsne_len > 0) {
				ap_sec_info->wpa_ie_len = sta_sec_event.rsne_len;
				ap_sec_info->wpa_ie = malloc(ap_sec_info->wpa_ie_len);

				if (!ap_sec_info->wpa_ie) {
		            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to alloc memory for RSNE (MBSS %d)\n",
		                       __func__, i);
					continue;
				}

				memmove(ap_sec_info->wpa_ie, sta_sec_event.rsne, ap_sec_info->wpa_ie_len);
				hex_dump("RSNE", ap_sec_info->wpa_ie, ap_sec_info->wpa_ie_len);

				ap_sec_info->wpa_key_mgmt = mtk_sec_akmp_to_profile(sta_sec_event.wpa_key_mgmt);
				DBGPRINT(RT_DEBUG_TRACE, "%s: AP%d WPA key mgmt (0x%x)\n",
					__func__, i, ap_sec_info->wpa_key_mgmt);

				ap_sec_info->group_mgmt_cipher = WPA_CIPHER_AES_128_CMAC; //todo: driver only BIP_CMAC_128
				ap_sec_info->ieee80211w = MGMT_FRAME_PROTECTION_OPTIONAL;
				ap_sec_info->wpa = WPA_PROTO_RSN;
				if (ap_sec_info->wpa == WPA_PROTO_RSN)
					ap_sec_info->rsn_pairwise = WPA_CIPHER_CCMP;
				else
					ap_sec_info->wpa_pairwise = WPA_CIPHER_CCMP;
				ap_sec_info->wpa_group = WPA_CIPHER_CCMP;
				rtapd->capab_info[i] = sta_sec_event.CapabilityInfo;

				ap_sec_info->GN = sta_sec_event.GN;
				ap_sec_info->GTK_len = sta_sec_event.GTK_len;
				memcpy(ap_sec_info->GTK, sta_sec_event.GTK, ap_sec_info->GTK_len);
				hex_dump("GTK", ap_sec_info->GTK, ap_sec_info->GTK_len);

				ap_sec_info->IGN = sta_sec_event.IGN;
				ap_sec_info->IGTK_len = sta_sec_event.IGTK_len;
				memcpy(ap_sec_info->IGTK, sta_sec_event.IGTK, ap_sec_info->IGTK_len);
				hex_dump("IGTK", ap_sec_info->IGTK, ap_sec_info->IGTK_len);


				ap_sec_info->FilsCacheId = sta_sec_event.FilsCacheId;

				rtapd->conf->dhcp_server.af = AF_INET;
				rtapd->conf->dhcp_server.u.v4.s_addr = sta_sec_event.FilsDhcpServerIp;
	    	}
	    }
	}
}

static rtapd * Apd_init(const char *prefix_name)
{
	rtapd *rtapd;
	int		i;

	rtapd = malloc(sizeof(*rtapd));
	if (rtapd == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not allocate memory for rtapd data\n");
		goto fail;
	}
	memset(rtapd, 0, sizeof(*rtapd));

	rtapd->prefix_wlan_name = strdup(prefix_name);
	if (rtapd->prefix_wlan_name == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not allocate memory for prefix_wlan_name\n");
		goto fail;
	}

	rtapd->main_wlan_name = strdup(MainIfName);
	if (rtapd->main_wlan_name == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not allocate memory for main_wlan_name\n");
		goto fail;
	}
	// init ioctl socket
	rtapd->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (rtapd->ioctl_sock < 0)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not init ioctl socket \n");
		goto fail;
	}


	rtapd->conf = Config_read(rtapd->ioctl_sock, rtapd->prefix_wlan_name);
	if (rtapd->conf == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not allocate memory for rtapd->conf \n");
		goto fail;
	}

	for (i = 0; i < MAX_MBSSID_NUM; i++)
	{
		rtapd->wlan_sock[i] = -1;
		rtapd->eth_sock[i] = -1;
	}

	mtk_sec_rsne_sync(rtapd);
	rtapd->driver = &wpa_driver_mediatek_ops;

	fils_config_default(rtapd);

	return rtapd;

fail:
	if (rtapd) {
		if (rtapd->conf)
			Config_free(rtapd->conf);

		if (rtapd->prefix_wlan_name)
			free(rtapd->prefix_wlan_name);

		if (rtapd->main_wlan_name)
			free(rtapd->main_wlan_name);

		if (rtapd->ioctl_sock >= 0)
			close(rtapd->ioctl_sock);

		free(rtapd);
	}
	return NULL;

}

static void Handle_usr1(int sig, void *eloop_ctx, void *signal_ctx)
{
	struct hapd_interfaces *rtapds = (struct hapd_interfaces *) eloop_ctx;
	struct rtapd_config *newconf;
	int i;

	DBGPRINT(RT_DEBUG_TRACE,"Reloading configuration\n");
	for (i = 0; i < rtapds->count; i++)
	{
		rtapd *rtapd = rtapds->rtapd[i];
		newconf = Config_read(rtapd->ioctl_sock, rtapd->prefix_wlan_name);
		if (newconf == NULL)
		{
			DBGPRINT(RT_DEBUG_ERROR,"Failed to read new configuration file - continuing with old.\n");
			continue;
		}

		/* TODO: update dynamic data based on changed configuration
		 * items (e.g., open/close sockets, remove stations added to
		 * deny list, etc.) */
		Radius_client_flush(rtapd);
		Config_free(rtapd->conf);
		rtapd->conf = newconf;
		Apd_free_stas(rtapd);

/* when reStartAP, no need to reallocate sock
        for (i = 0; i < rtapd->conf->SsidNum; i++)
        {
            if (rtapd->sock[i] >= 0)
                close(rtapd->sock[i]);

    	    rtapd->sock[i] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    	    if (rtapd->sock[i] < 0)
            {
    		    perror("socket[PF_PACKET,SOCK_RAW]");
    		    return;
    	    }
        }*/

#if MULTIPLE_RADIUS
		for (i = 0; i < MAX_MBSSID_NUM; i++)
			rtapd->radius->mbss_auth_serv_sock[i] = -1;
#else
		rtapd->radius->auth_serv_sock = -1;
#endif

		if (Radius_client_init(rtapd))
		{
			DBGPRINT(RT_DEBUG_ERROR,"RADIUS client initialization failed.\n");
			return;
		}
#if MULTIPLE_RADIUS
		for (i = 0; i < rtapd->conf->SsidNum; i++)
			DBGPRINT(RT_DEBUG_TRACE, "auth_serv_sock[%d] = %d\n", i, rtapd->radius->mbss_auth_serv_sock[i]);
#else
        DBGPRINT(RT_DEBUG_TRACE,"rtapd->radius->auth_serv_sock = %d\n",rtapd->radius->auth_serv_sock);
#endif
	}
}

void Handle_term(int sig, void *eloop_ctx, void *signal_ctx)
{
	//FILE    *f;
	//char    buf[256], *pos;
	//int     line = 0, i;
    //int     filesize,cur = 0;
    //char    *ini_buffer;             /* storage area for .INI file */

	DBGPRINT(RT_DEBUG_ERROR,"Signal %d received - terminating\n", sig);

#if 0
	f = fopen(RT2860AP_SYSTEM_PATH, "r");
	if (f == NULL)
    {
		DBGPRINT(RT_DEBUG_ERROR,"Could not open configuration file '%s' for reading.\n", RT2860AP_SYSTEM_PATH);
		return;
	}

    if ((fseek(f, 0, SEEK_END))!=0)
        return;
    filesize=ftell(f);
	DBGPRINT(RT_DEBUG_ERROR,"filesize %d   - terminating\n", filesize);

    if ((ini_buffer=(char *)malloc(filesize + 1 ))==NULL)
        return;   //out of memory
    fseek(f,0,SEEK_SET);
    fread(ini_buffer, filesize, 1, f);
    fseek(f,0,SEEK_SET);
    ini_buffer[filesize]='\0';

	while ((fgets(buf, sizeof(buf), f)))
    {
		line++;
		if (buf[0] == '#')
			continue;
		pos = buf;
		while (*pos != '\0')
        {
			if (*pos == '\n')
            {
				*pos = '\0';
				break;
			}
			pos++;
		}
		if (buf[0] == '\0')
			continue;

		pos = strchr(buf, '=');
		if (pos == NULL)
        {
		    pos = strchr(buf, '[');
			continue;
		}
		*pos = '\0';
		pos++;

        if ((strcmp(buf, "pid") == 0) )
        {
            cur = 0;
            while(cur < (int)filesize)
            {
                if ((ini_buffer[cur]=='p') && (ini_buffer[cur+1]=='i') && (ini_buffer[cur+2]=='d'))
                {
                    cur += 4;
                    for( i=4; i>=0; i--)
                    {
                        if (ini_buffer[cur] !='\n' )
                        {
                            ini_buffer[cur] =0x30;
                        }
                        else
                        {
                            break;
                        }
                        cur++;
                    }
                    break;
                }
                cur++;
            }
		}
    }
    fseek(f,0,SEEK_SET);
    fprintf(f, "%s", ini_buffer);
    fclose(f);
#endif

	eloop_terminate();
}


int main(int argc, char *argv[])
{
	struct hapd_interfaces interfaces;
	pid_t child_pid;
	int ret = 1, res = 0, i, c;
	pid_t auth_pid;
	char prefix_name[IFNAMSIZ];
	char *infName = NULL;
	char *preName = NULL;

	memset(&MainIfName[0], 0, IFNAMSIZ);

	/* For old arch, it need to remove */
	if (strcmp(argv[0], "rtinicapd") == 0) {
		res = snprintf(prefix_name, IFNAMSIZ, "rai");
	} else if (strcmp(argv[0], "rtwifi3apd") == 0) {
		res = snprintf(prefix_name, IFNAMSIZ, "rae");
	} else {
		if (strcmp(argv[0], "rt2860apd_x") == 0)
			res = snprintf(prefix_name, IFNAMSIZ, "rax");
		else
			res = snprintf(prefix_name, IFNAMSIZ, "ra");
	}
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
		return ret;
	}

	res = snprintf(MainIfName, IFNAMSIZ, "%s%d", prefix_name, 0);
	if (os_snprintf_error(IFNAMSIZ, res)) {
		DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
		return ret;
	}

	for (;;)
	{
		c = getopt(argc, argv, "d:i:p:h");
		if (c < 0)
			break;

		switch (c)
		{
			case 'd':
				/* 	set Debug level -
						RT_DEBUG_OFF		0
						RT_DEBUG_ERROR		1
						RT_DEBUG_WARN		2
						RT_DEBUG_TRACE		3
						RT_DEBUG_INFO		4
				*/
				printf("Set debug level as %s\n", optarg);
				RTDebugLevel = (int)strtol(optarg, 0, 10);
				break;

			case 'i':

				infName = optarg;

				if (strlen(infName))
				{
					memset(MainIfName, 0, IFNAMSIZ);
					res = snprintf(MainIfName, IFNAMSIZ, "%s", infName);
					if (os_snprintf_error(IFNAMSIZ, res)) {
						DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
						return ret;
					}
				}

				break;

			case 'p':
				preName = optarg;

				if (strlen(preName))
				{
					memset(prefix_name, 0, IFNAMSIZ);
					res = snprintf(prefix_name, IFNAMSIZ, "%s", preName);
					if (os_snprintf_error(IFNAMSIZ, res)) {
						DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
						return ret;
					}
				}

				break;

			case 'h':
			default:
				usage();
				break;
		}
	}

	DBGPRINT(RT_DEBUG_OFF, "Ralink DOT1X daemon, version = '%s' \n", dot1x_version);
	DBGPRINT(RT_DEBUG_TRACE, "Main Interface name = '%s'\n", MainIfName);
	DBGPRINT(RT_DEBUG_TRACE, "prefix_name = '%s'\n", prefix_name);

	child_pid = fork();
	if (child_pid == 0)
	{
		auth_pid = getpid();
		DBGPRINT(RT_DEBUG_TRACE, "Porcess ID = %d\n",auth_pid);

		openlog("rtdot1xd",0,LOG_DAEMON);
		// set number of configuration file 1
		interfaces.count = 1;
		interfaces.rtapd = malloc(sizeof(rtapd *));
		if (interfaces.rtapd == NULL)
		{
			DBGPRINT(RT_DEBUG_ERROR,"malloc failed\n");
			exit(1);
		}

		write_pidfile(argv[0]);

		eloop_init(&interfaces);
		eloop_register_signal(SIGINT, Handle_term, NULL);
		eloop_register_signal(SIGTERM, Handle_term, NULL);
		eloop_register_signal(SIGUSR1, Handle_usr1, NULL);
		eloop_register_signal(SIGHUP, Handle_usr1, NULL);

		interfaces.rtapd[0] = Apd_init(prefix_name);
		if (!interfaces.rtapd[0])
			goto out;
		if (Apd_setup_interface(interfaces.rtapd[0]))
			goto out;

		// Notify driver about PID
		if (RT_ioctl(interfaces.rtapd[0]->ioctl_sock, RT_PRIV_IOCTL, (char *)&auth_pid, sizeof(int), MainIfName, 0, RT_SET_APD_PID | OID_GET_SET_TOGGLE)) {
			DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for Notify driver about PID\n");
		}

		eloop_run();

#ifdef RADIUS_MAC_ACL_SUPPORT
		/* Clear Inside Radius ACL Cache */
		hostapd_acl_deinit(interfaces.rtapd[0]);

		/* Clear Driver Side Radius ACL Cache */
		for(i = 0; i < interfaces.rtapd[0]->conf->SsidNum; i++)
		{
			RT_ioctl(interfaces.rtapd[0]->ioctl_sock, RT_PRIV_IOCTL, (char *)&auth_pid, sizeof(int),
					prefix_name, i, RT_OID_802_DOT1X_RADIUS_ACL_CLEAR_CACHE);
		}
#endif /* RADIUS_MAC_ACL_SUPPORT */

		Apd_free_stas(interfaces.rtapd[0]);
		ret = 0;

out:
		for (i = 0; i < interfaces.count; i++)
		{
			if (!interfaces.rtapd[i])
				continue;

			Apd_cleanup(interfaces.rtapd[i]);
			free(interfaces.rtapd[i]);
		}
		DBGPRINT(RT_DEBUG_ERROR,"8021xd_ended!!\n");

		free(interfaces.rtapd);
		eloop_destroy();
		closelog();
		return ret;
	}
	else
		return 0;
}

