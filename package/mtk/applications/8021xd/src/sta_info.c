

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if.h>			/* for IFNAMSIZ and co... */
#include <linux/wireless.h>

#include "rtdot1x.h"
#include "sta_info.h"
#include "eloop.h"
#include "ieee802_1x.h"
#include "radius.h"
#include "eapol_sm.h"

struct sta_info* Ap_get_sta_instance(rtapd *apd, u8 *sa)
{
	struct sta_info *s;

	s = apd->sta_hash[STA_HASH(sa)];
	while (s != NULL && memcmp(s->addr, sa, 6) != 0)
		s = s->hnext;

	return s;
}

struct sta_info* Ap_get_sta(rtapd *apd, u8 *sa, u8 *apidx, u16 ethertype, int sock)
{
	struct sta_info *s;

	s = apd->sta_hash[STA_HASH(sa)];
	while (s != NULL && memcmp(s->addr, sa, 6) != 0)
		s = s->hnext;

	if (s == NULL)
	{
		if (apd->num_sta >= MAX_STA_COUNT)
		{
			/* FIX: might try to remove some old STAs first? */
			DBGPRINT(RT_DEBUG_ERROR,"No more room for new STAs (%d/%d)\n", apd->num_sta, MAX_STA_COUNT);
			return NULL;
		}

		s = (struct sta_info *) malloc(sizeof(struct sta_info));
		if (s == NULL)
		{
			DBGPRINT(RT_DEBUG_ERROR,"Malloc failed\n");
			return NULL;
		}

		memset(s, 0, sizeof(struct sta_info));
		s->radius_identifier = -1;

		s->ethertype = ethertype;
		if (apd->conf->SsidNum > 1)
			s->ApIdx = *apidx;
		else
			s->ApIdx = 0;

		if (s->ApIdx == 0)
		{
			DBGPRINT(RT_DEBUG_TRACE,"Create a new STA(in %s%d)\n", apd->main_wlan_name, s->ApIdx);
		}
		else
		{
			DBGPRINT(RT_DEBUG_TRACE,"Create a new STA(in %s%d)\n", apd->prefix_wlan_name, s->ApIdx);
		}

		DOT1X_QUERY_STA_AID qStaAid;
        	memset(&qStaAid, 0, sizeof(DOT1X_QUERY_STA_AID));
        	memcpy(qStaAid.StaAddr, sa, MAC_ADDR_LEN);

        	if (RT_ioctl(apd->ioctl_sock, RT_PRIV_IOCTL, (char *)&qStaAid, sizeof(DOT1X_QUERY_STA_AID),
                	 			apd->prefix_wlan_name, s->ApIdx, OID_802_DOT1X_QUERY_STA_AID))
		{
			DBGPRINT(RT_DEBUG_ERROR,"IOCTL ERROR with OID_802_DOT1X_QUERY_STA_AID\n");
		}
		s->aid = qStaAid.aid;
		s->wcid = qStaAid.wcid;
		DBGPRINT(RT_DEBUG_TRACE,"STA:" MACSTR " AID: %d\n", MAC2STR(sa), s->aid);

		DOT1X_QUERY_STA_RSN sta_rsn;
        	memset(&sta_rsn, 0, sizeof(DOT1X_QUERY_STA_RSN));
        	memcpy(sta_rsn.sta_addr, sa, MAC_ADDR_LEN);

        	if (RT_ioctl(apd->ioctl_sock, RT_PRIV_IOCTL, (char *)&sta_rsn, sizeof(DOT1X_QUERY_STA_RSN),
                	 			apd->prefix_wlan_name, s->ApIdx, OID_802_DOT1X_QUERY_STA_RSN))
		{
			DBGPRINT(RT_DEBUG_ERROR,"IOCTL ERROR with OID_802_DOT1X_QUERY_STA_RSN\n");
		}
		s->akm = sta_rsn.akm;
		s->pairwise_cipher = sta_rsn.pairwise_cipher;
		s->group_cipher = sta_rsn.group_cipher;
		s->group_mgmt_cipher = sta_rsn.group_mgmt_cipher;
		DBGPRINT(RT_DEBUG_TRACE,"STA:" MACSTR " AKM: %x, Pairwise: %x, Group: %x, Group mgmt: %x\n",
			MAC2STR(sa), s->akm, s->pairwise_cipher, s->group_cipher, s->group_mgmt_cipher);

		s->SockNum = sock;
		memcpy(s->addr, sa, ETH_ALEN);
		s->next = apd->sta_list;
		s->priv = apd;
		apd->sta_list = s;
		apd->num_sta++;
		Ap_sta_hash_add(apd, s);
		ieee802_1x_new_station(apd, s);
#if HOTSPOT_R3
		hotspot_ioctl_query_sta_info(apd, s);
#endif /* HOTSPOT_R3 */
		return s;
	}
	else
	{
		if (s->ApIdx == 0)
		{
			DBGPRINT(RT_DEBUG_TRACE,"A STA has existed(in %s)\n", apd->prefix_wlan_name);
		}
		else
		{
			DBGPRINT(RT_DEBUG_TRACE,"A STA has existed(in %s%d)\n", apd->prefix_wlan_name, s->ApIdx);
		}
	}

	return s;
}

struct sta_info* Ap_get_sta_radius_identifier(rtapd *apd, u8 radius_identifier)
{
	struct sta_info *s;

	s = apd->sta_list;

	while (s)
	{
		if (s->radius_identifier >= 0 && s->radius_identifier == radius_identifier)
			return s;
		s = s->next;
	}

	return NULL;
}

static void Ap_sta_list_del(rtapd *apd, struct sta_info *sta)
{
	struct sta_info *tmp;

	if (apd->sta_list == sta)
	{
		apd->sta_list = sta->next;
		return;
	}

	tmp = apd->sta_list;
	while (tmp != NULL && tmp->next != sta)
		tmp = tmp->next;
	if (tmp == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not remove STA " MACSTR " from list.\n", MAC2STR(sta->addr));
	} else
		tmp->next = sta->next;
}

void Ap_sta_hash_add(rtapd *apd, struct sta_info *sta)
{
	sta->hnext = apd->sta_hash[STA_HASH(sta->addr)];
	apd->sta_hash[STA_HASH(sta->addr)] = sta;
}

static void Ap_sta_hash_del(rtapd *apd, struct sta_info *sta)
{
	struct sta_info *s;

	s = apd->sta_hash[STA_HASH(sta->addr)];
	if (s == NULL) return;
	if (memcmp(s->addr, sta->addr, 6) == 0)
	{
		apd->sta_hash[STA_HASH(sta->addr)] = s->hnext;
		return;
	}

	while (s->hnext != NULL && memcmp(s->hnext->addr, sta->addr, 6) != 0)
		s = s->hnext;
	if (s->hnext != NULL)
		s->hnext = s->hnext->hnext;
	else
		DBGPRINT(RT_DEBUG_ERROR,"AP: could not remove STA " MACSTR " from hash table\n", MAC2STR(sta->addr));
}

/*
	========================================================================
	Routine Description:
	   remove the specified input-argumented sta from linked list..
	Arguments:
		*sta	to-be-removed station.
	Return Value:
	========================================================================
*/
void Ap_free_sta(rtapd *apd, struct sta_info *sta)
{
	struct sta_sec_info *sta_sec_info = NULL;
	sta_sec_info = &sta->sta_sec_info;

	DBGPRINT(RT_DEBUG_TRACE," AP_free_sta" MACSTR " \n",
		MAC2STR(sta->addr))

	Ap_sta_hash_del(apd, sta);
	Ap_sta_list_del(apd, sta);

	//if (sta->aid > 0)
	//	apd->sta_aid[sta->aid - 1] = NULL;

	apd->num_sta--;

	ieee802_1x_free_station(sta);

	if (sta->last_assoc_req)
		free(sta->last_assoc_req);

	if (sta_sec_info->wpa_ie)
		free(sta_sec_info->wpa_ie);

	free(sta);
}

/*
	========================================================================
	Description:
		remove all stations.
	========================================================================
*/
void Apd_free_stas(rtapd *apd)
{
	struct sta_info *sta, *prev;

	sta = apd->sta_list;
	DBGPRINT(RT_DEBUG_TRACE,"Apd_free_stas\n");
	while (sta)
	{
		prev = sta;
		sta = sta->next;
		DBGPRINT(RT_DEBUG_ERROR,"Removing station " MACSTR "\n", MAC2STR(prev->addr));
		Ap_free_sta(apd, prev);
	}
}

void Ap_handle_session_timer(void *eloop_ctx, void *timeout_ctx)
{
	char *buf;
	rtapd *apd = eloop_ctx;
	size_t len;
	struct ieee8023_hdr *hdr3;
	struct sta_info *sta = timeout_ctx;

	DBGPRINT(RT_DEBUG_TRACE,"AP_HANDLE_SESSION_TIMER \n");
	len = sizeof(*hdr3) + 2;
	buf = (char *) malloc(len);
	if (buf == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"malloc() failed for ieee802_1x_send(len=%lu)\n", len);
		return;
	}

	memset(buf, 0, len);
	hdr3 = (struct ieee8023_hdr *) buf;
	memcpy(hdr3->dAddr, sta->addr, ETH_ALEN);
	memcpy(hdr3->sAddr, apd->own_addr[sta->ApIdx], ETH_ALEN);
	// send deauth
	DBGPRINT(RT_DEBUG_TRACE,"AP_HANDLE_SESSION_TIMER : Send Deauth \n");
	if (RT_ioctl(apd->ioctl_sock,
				 RT_PRIV_IOCTL, buf, len,
				 apd->prefix_wlan_name, sta->ApIdx,
				 RT_OID_802_DOT1X_RADIUS_DATA))
	{
		DBGPRINT(RT_DEBUG_ERROR," ioctl \n");
		return;
	}
	free(buf);

//	Ap_free_sta(apd, sta);
}

void Ap_sta_session_timeout(rtapd *apd, struct sta_info *sta, u32 session_timeout)
{
	DBGPRINT(RT_DEBUG_TRACE,"AP_STA_SESSION_TIMEOUT %d seconds \n",session_timeout);
	eloop_cancel_timeout(Ap_handle_session_timer, apd, sta);
	eloop_register_timeout(session_timeout, 0, Ap_handle_session_timer, apd, sta);
}

void Ap_sta_no_session_timeout(rtapd *apd, struct sta_info *sta)
{
	eloop_cancel_timeout(Ap_handle_session_timer, apd, sta);
}

void Ap_sta_skip_eap_sm(rtapd *apd, struct sta_info *sta)
{

 	if (sta && sta->eapol_sm) {
		DBGPRINT(RT_DEBUG_TRACE,
					   "" MACSTR " PMK from FILS - skip IEEE 802.1X/EAP\n",
					   MAC2STR(sta->addr));

		/* Setup EAPOL state machines to already authenticated state
		 * because of existing FILS information. */
		//sta->eapol_sm->keyRun = TRUE;
		sta->eapol_sm->keyAvailable = TRUE;
		sta->eapol_sm->auth_pae.state = AUTH_PAE_AUTHENTICATING;
		sta->eapol_sm->be_auth.state = BE_AUTH_SUCCESS;
		sta->eapol_sm->authSuccess = TRUE;
		sta->eapol_sm->authFail = FALSE;
		sta->eapol_sm->portValid = TRUE;
		//if (sta->eapol_sm->eap)
		 // 	  eap_sm_notify_cached(sta->eapol_sm->eap);
	} else {
		DBGPRINT(RT_DEBUG_TRACE,
					   "PMK from FILS - skip IEEE 802.1X/EAP\n");

	}
}

#if HOTSPOT_R3
void hotspot_ioctl_query_sta_info(rtapd *apd, struct sta_info *sta)
{
	STA_HS_CONSORTIUM_OI hs_consortium;

	if (sta) {
		memset(&hs_consortium, 0, sizeof(STA_HS_CONSORTIUM_OI));
		hs_consortium.sta_wcid = sta->wcid;
		DBGPRINT(RT_DEBUG_TRACE, "sta->wcid = %d\n", sta->wcid);
		if (RT_ioctl(apd->ioctl_sock,
					RT_PRIV_IOCTL, (char *)&hs_consortium, sizeof(STA_HS_CONSORTIUM_OI),
					apd->prefix_wlan_name, sta->ApIdx,
					OID_802_11_GET_STA_HSINFO))
		{
			DBGPRINT(RT_DEBUG_OFF,"IOCTL ERROR with OID_802_11_GET_STA_HSINFO\n");
		}
		DBGPRINT(RT_DEBUG_TRACE, "hs_consortium.sta_wcid = %d, len = %d \n", hs_consortium.sta_wcid, hs_consortium.oi_len);
		if (hs_consortium.sta_wcid) {
			sta->hs_roaming_oi.sta_wcid = hs_consortium.sta_wcid;
			sta->hs_roaming_oi.oi_len = hs_consortium.oi_len;
			memcpy(sta->hs_roaming_oi.selected_roaming_consortium_oi, hs_consortium.selected_roaming_consortium_oi,
												hs_consortium.oi_len);
		}
		DBGPRINT(RT_DEBUG_TRACE, "hs consortium oi:-> %2x, %2x, %2x, %2x, %2x\n", sta->hs_roaming_oi.selected_roaming_consortium_oi[0],
						sta->hs_roaming_oi.selected_roaming_consortium_oi[1], sta->hs_roaming_oi.selected_roaming_consortium_oi[2],
						sta->hs_roaming_oi.selected_roaming_consortium_oi[3], sta->hs_roaming_oi.selected_roaming_consortium_oi[4]);
	}
}
#endif /* HOTSPOT_R3 */
