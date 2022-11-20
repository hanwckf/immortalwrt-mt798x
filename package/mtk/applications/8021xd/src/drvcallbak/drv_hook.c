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

#include "drv_hook.h"
#include "ap.h"
#include "sta_info.h"
#include "ap/fils.h"
#include "ap/fils_hlp.h"

#include "wpabuf.h"
#include "eloop.h"
#include "common/ieee802_11_common.h"

#ifdef CONFIG_FILS
void hostapd_notify_assoc_fils_finish(struct apd_data *hapd,
                                      struct sta_info *sta)
{
	DBGPRINT(RT_DEBUG_ERROR, "Shouldn't here %s FILS: Finish association with "
			MACSTR "\n", __func__, MAC2STR(sta->addr));

}

static void hostapd_notify_auth_fils_finish(struct apd_data *hapd,
                                            struct sta_info *sta, u16 resp,
                                            struct wpabuf *data, int pub)
{
    if (resp == WLAN_STATUS_SUCCESS) {
            DBGPRINT(RT_DEBUG_TRACE, "authentication OK (FILS)\n");
            sta->flags |= WLAN_STA_AUTH;
            //wpa_auth_sm_event(sta->wpa_sm, WPA_AUTH);
            sta->auth_alg = WLAN_AUTH_FILS_SK;
            //mlme_authenticate_indication(hapd, sta);
    } else {
            DBGPRINT(RT_DEBUG_TRACE, "authentication failed (FILS)");
    }

    hostapd_sta_auth(hapd, sta->addr, 2, resp,
                     data ? wpabuf_head(data) : NULL,
                     data ? wpabuf_len(data) : 0);
    wpabuf_free(data);
}
#endif /* CONFIG_FILS */

static void hostapd_notif_auth(struct apd_data *hapd,
                               struct auth_info *rx_auth)
{
    struct sta_info *sta = NULL;
    u16 status = WLAN_STATUS_UNSPECIFIED_FAILURE; //test
    u8 resp_ies[2 + WLAN_AUTH_CHALLENGE_LEN];
    size_t resp_ies_len = 0;

    sta = Ap_get_sta(hapd, rx_auth->peer, &rx_auth->apidx,
		rx_auth->ethertype, rx_auth->SockNum);

    if (!sta) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Station not found for sta_auth processing\n",
                       __func__);
            goto fail;
    }

	Ap_sta_skip_eap_sm(hapd, sta);

	switch (rx_auth->auth_type) {
#ifdef CONFIG_FILS
	case WLAN_AUTH_FILS_SK:
    {
        sta->auth_alg = WLAN_AUTH_FILS_SK;
        handle_auth_fils(hapd, sta, rx_auth->ies, rx_auth->ies_len,
                         rx_auth->auth_type, rx_auth->auth_transaction,
                         rx_auth->status_code,
                         hostapd_notify_auth_fils_finish);
        return;
    }
		break;
#endif /* CONFIG_FILS */
	case WLAN_AUTH_OPEN:
		DBGPRINT(RT_DEBUG_ERROR, "Station " MACSTR
                       " using open to Auth (%d)\n",
                       MAC2STR(sta->addr), status);
		break;
	default:
		break;
	}

fail:
    hostapd_sta_auth(hapd, rx_auth->peer, rx_auth->auth_transaction + 1,
                     status, resp_ies, resp_ies_len);
}

static void hostapd_notif_assoc(struct apd_data *hapd,
                               struct assoc_info *rx_assoc)
{
    struct sta_info *sta = NULL;
	sta = Ap_get_sta_instance(hapd, rx_assoc->peer);
	if (!sta) {
			DBGPRINT(RT_DEBUG_ERROR, "%s: Station " MACSTR
					   " not found for sta_assoc processing\n",
					   __func__, MAC2STR(rx_assoc->peer));

			/*
			 * Avoid the 1xDaemon not respond the assocReq from Driver
			 * then insert the STA entry to respond the FAIL to Driver
			 */
			sta = Ap_get_sta(hapd, rx_assoc->peer, &rx_assoc->apidx,
				rx_assoc->ethertype, rx_assoc->SockNum);

			if (!sta) {
					DBGPRINT(RT_DEBUG_ERROR,
						"%s: not found for sta_assoc by Ap_get_sta()\n",
						__func__);
					return;
			}

			Ap_sta_skip_eap_sm(hapd, sta);
	}

	handle_assoc_fils(hapd, sta, rx_assoc->frame, rx_assoc->frame_len,
		rx_assoc->reassoc);

}

int hostapd_ap_set_key(struct apd_data *hapd, u8 apidx, int vlan_id,
                                   enum wpa_alg alg, const u8 *addr, int idx,
                                   u8 *key, size_t key_len)
{
        if (hapd->driver->set_key == NULL)
                return -1;

		return hapd->driver->set_key(hapd, apidx, alg, addr, idx,
                                     key, key_len);
}


u16 hostapd_ap_capab_info(struct apd_data *hapd, struct sta_info *sta)
{
	return hapd->capab_info[sta->ApIdx];
}

static void handle_assoc_cb(struct apd_data *hapd,
                            struct sta_info *sta, int reassoc, u16 status)
{
	if (status != WLAN_STATUS_SUCCESS)
			return;

#ifdef CONFIG_FILS
    if ((sta->auth_alg == WLAN_AUTH_FILS_SK ||
         sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
         sta->auth_alg == WLAN_AUTH_FILS_PK) &&
        fils_set_tk(sta) < 0) {
            DBGPRINT(RT_DEBUG_ERROR, "FILS: TK configuration failed\n");
            //ap_sta_disconnect(hapd, sta, WLAN_REASON_UNSPECIFIED);
            return;
    }
#endif /* CONFIG_FILS */

}

int hostapd_sta_assoc(struct apd_data *hapd, const u8 *own_addr, const u8 *addr,
                          int reassoc, u16 status, const u8 *ie, size_t len)
{
    struct sta_info *sta = NULL;

    if (!hapd->driver || !hapd->driver->sta_assoc)
            return 0;

	sta = Ap_get_sta_instance(hapd, addr);
    if (!sta) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Station " MACSTR
                       " not found for sta_assoc processing\n",
                       __func__, MAC2STR(addr));
            return 0;
    }

	handle_assoc_cb(hapd, sta, reassoc, status);

    return hapd->driver->sta_assoc(hapd, own_addr, addr, reassoc, status,
                                       ie, len);
}

int hostapd_sta_auth(struct apd_data *hapd, const u8 *addr,
                     u16 seq, u16 status, const u8 *ie, size_t len)
{
    struct wpa_driver_sta_auth_params params;
    struct sta_info *sta;

    if (hapd->driver == NULL || hapd->driver->sta_auth == NULL)
            return 0;

    memset(&params, 0, sizeof(params));

    sta = Ap_get_sta_instance(hapd, addr);
    if (!sta) {
        DBGPRINT(RT_DEBUG_ERROR, "%s: Station " MACSTR
                   " not found for sta_auth processing\n",
                   __func__, MAC2STR(addr));
        return 0;
    }

#ifdef CONFIG_FILS
    if (sta->auth_alg == WLAN_AUTH_FILS_SK ||
        sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
        sta->auth_alg == WLAN_AUTH_FILS_PK) {

		params.fils_auth = 1;
		memcpy(params.fils_anonce, sta->fils_anonce, FILS_NONCE_LEN);
		memcpy(params.fils_snonce, sta->fils_snonce, FILS_NONCE_LEN);
		memcpy(params.fils_kek, sta->PTK.kek, WPA_KEK_MAX_LEN);
		params.fils_kek_len = sta->PTK.kek_len;
    }
#endif /* CONFIG_FILS */

	params.own_addr = hapd->own_addr[sta->ApIdx];
	params.addr = addr;
	params.seq = seq;
	params.status = status;
	params.ie = ie;
	params.len = len;

	return hapd->driver->sta_auth(hapd, &params);

}

void wpa_supplicant_event(struct apd_data *hapd, enum wpa_event_type event,
                          union wpa_event_data *data)
{
	switch (event) {
		case EVENT_AUTH:
			hostapd_notif_auth(hapd, &data->auth);
			break;
		case EVENT_ASSOC:
			hostapd_notif_assoc(hapd, &data->assoc_info);
			break;

		default:
			DBGPRINT(RT_DEBUG_ERROR, "Unknown event %d", event);
			break;
	}
}

void Handle_mlme_event(struct apd_data *hapd, u8 *addr,
	u8 *apidx, u16 ethertype, int SockNum, u8 *ie, size_t ie_len)
{
	const struct ieee80211_mgmt *mgmt;
	union wpa_event_data event;
	u16 fc, stype;
	int ielen;
	const u8 *iebuf;

	DBGPRINT(RT_DEBUG_TRACE, "STA(" MACSTR ") Recv MlmePkt and len%lu\n",
		MAC2STR(addr), ie_len);

	mgmt = (const struct ieee80211_mgmt *) ie;

	fc = le_to_host16(mgmt->frame_control);

	if (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT) {
		DBGPRINT(RT_DEBUG_ERROR, "Unknown type of frame\n");
		return;
	}

	stype = WLAN_FC_GET_STYPE(fc);

	DBGPRINT(RT_DEBUG_TRACE, "%s: subtype 0x%x len %d\n", __func__, stype,
		   (int) ie_len);

	switch (stype) {
	case WLAN_FC_STYPE_ASSOC_REQ:
		if (ie_len < IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req))
			break;
		event.assoc_info.reassoc = 0;
		memcpy(event.assoc_info.peer, mgmt->sa, ETH_ALEN);
		event.assoc_info.frame = ie;
		event.assoc_info.frame_len = ie_len;

		event.assoc_info.SockNum = SockNum;
		event.assoc_info.apidx = apidx;
		event.assoc_info.ethertype = ethertype;
		wpa_supplicant_event(hapd, EVENT_ASSOC, &event);
		break;

	case WLAN_FC_STYPE_REASSOC_REQ:
		if (ie_len < IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req))
			break;
		event.assoc_info.reassoc = 1;
		memcpy(event.assoc_info.peer, mgmt->sa, ETH_ALEN);
		event.assoc_info.frame = ie;
		event.assoc_info.frame_len = ie_len;

		event.assoc_info.SockNum = SockNum;
		event.assoc_info.apidx = apidx;
		event.assoc_info.ethertype = ethertype;
		wpa_supplicant_event(hapd, EVENT_ASSOC, &event);
		break;

	case WLAN_FC_STYPE_AUTH:
		if (ie_len < IEEE80211_HDRLEN + sizeof(mgmt->u.auth))
			break;
		memset(&event, 0, sizeof(event));

		memcpy(event.auth.peer, mgmt->sa, ETH_ALEN);
		memcpy(event.auth.bssid, mgmt->bssid, ETH_ALEN);
		event.auth.auth_type = le_to_host16(mgmt->u.auth.auth_alg);
		event.auth.status_code =
			le_to_host16(mgmt->u.auth.status_code);
		event.auth.auth_transaction =
			le_to_host16(mgmt->u.auth.auth_transaction);
		event.auth.ies = mgmt->u.auth.variable;
		event.auth.ies_len = ie_len - IEEE80211_HDRLEN -
			sizeof(mgmt->u.auth);

		event.auth.SockNum = SockNum;
		event.auth.apidx = apidx;
		event.auth.ethertype = ethertype;

		wpa_supplicant_event(hapd, EVENT_AUTH, &event);
		break;
	default:
		DBGPRINT(RT_DEBUG_ERROR, "Unknown subtype of frame\n")
		break;
	}
}

void Handle_aead_decr_event(struct apd_data *hapd, u8 *addr,
	u8 *apidx, u16 ethertype, int SockNum, u8 *ie, size_t ie_len)
{
    int ret = WLAN_STATUS_UNSPECIFIED_FAILURE;
	RT_802_11_STA_MLME_EVENT sta_mlme_event;
	struct sec_info *ap_sec_info = NULL;
    struct sta_info *sta = NULL;
	struct wpa_ptk *ptk = NULL;
	u16 eapol_packet_len = 0, key_data_len = 0;

	sta = Ap_get_sta(hapd, addr, apidx, ethertype, SockNum);
    if (!sta) {
            DBGPRINT(RT_DEBUG_TRACE, "%s: Station " MACSTR
                       " not found for AEAD processing\n",
                       __func__, MAC2STR(addr));
            return 0;
    }

	Ap_sta_skip_eap_sm(hapd, sta);

	/* Fill the PTK from Driver */
	ptk = &sta->PTK;

	ap_sec_info = &hapd->ap_sec_info[sta->ApIdx];

	/* Todo -- start shall ioctl get the STA secInfo */
	sta->sta_sec_info.wpa_key_mgmt = ap_sec_info->wpa_key_mgmt;
	sta->sta_sec_info.pairwise = WPA_CIPHER_CCMP;
	/* Todo -- end */

	if (wpa_key_mgmt_sha384(sta->sta_sec_info.wpa_key_mgmt)) {
		ptk->kek_len = 64;
	} else if (wpa_key_mgmt_sha256(sta->sta_sec_info.wpa_key_mgmt)) {
		ptk->kek_len = 32;
	} else {
		DBGPRINT(RT_DEBUG_ERROR, "%s: Unknown akmp\n", __func__);
		return;
	}

	ptk->kck_len = 0;
	ptk->tk_len = wpa_cipher_key_len(sta->sta_sec_info.pairwise);

	//hex_dump("2x aead decr event with PMK", ie, ptk->kek_len + ptk->tk_len);

	memmove(ptk->kek, ie, ptk->kek_len);
	memmove(ptk->tk, &ie[ptk->kek_len], ptk->tk_len);

	/* AEAD Action */
	eapol_packet_len = ie_len - ptk->kek_len - ptk->tk_len;
	//hex_dump("before decrypt", &ie[ptk->kek_len + ptk->tk_len],
	//	eapol_packet_len);

	if (wpa_aead_decrypt(sta, ptk, &ie[ptk->kek_len + ptk->tk_len],
		eapol_packet_len, &key_data_len) == 0) {
		ret = WLAN_STATUS_SUCCESS;
	} else {
		DBGPRINT(RT_DEBUG_ERROR, "%s: wpa_aead_decrypt fail\n", __func__);
	}

	//hex_dump("after decrypt", &ie[ptk->kek_len + ptk->tk_len],
	//	eapol_packet_len);

	memset(&sta_mlme_event, 0, sizeof(sta_mlme_event));
	sta_mlme_event.status = ret;
	memcpy(sta_mlme_event.addr, sta->addr, MAC_ADDR_LEN);

	if (ret == WLAN_STATUS_SUCCESS) {
		sta_mlme_event.mgmt_subtype = WLAN_FC_STYPE_ACTION;
		sta_mlme_event.auth_algo = WLAN_AUTH_OPEN;
		sta_mlme_event.len = eapol_packet_len;
	    if (sta_mlme_event.len) {
	            if (sta_mlme_event.len < MAX_OPT_IE) {
	                    memcpy(sta_mlme_event.ie, &ie[ptk->kek_len + ptk->tk_len],
							sta_mlme_event.len);
	            } else {
	                    DBGPRINT(RT_DEBUG_TRACE, "%s: Not enough space to copy "
	                               "opt_ie STA (addr " MACSTR "ie_len %d)",
	                               __func__, MAC2STR(sta->addr),
	                               (int) eapol_packet_len);
	                    return -1;
	            }
	    }
	}

	ret = RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&sta_mlme_event,
		sizeof(RT_802_11_STA_MLME_EVENT), hapd->prefix_wlan_name, sta->ApIdx,
		RT_OID_802_DOT1X_MLME_EVENT);

	if (ret < 0) {
			DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to auth STA (addr " MACSTR
					   " \n",
					   __func__, MAC2STR(sta->addr));
	}

}

void Handle_aead_encr_event(struct apd_data *hapd, u8 *addr,
	u8 *apidx, u16 ethertype, int SockNum, u8 *ie, size_t ie_len)
{
    int ret = WLAN_STATUS_UNSPECIFIED_FAILURE;
	RT_802_11_STA_MLME_EVENT sta_mlme_event;
    struct sta_info *sta = NULL;
	struct wpa_ptk *ptk = NULL;
	u16 eapol_packet_len = 0, buf_len = 0;
	u16 encr_data_len = 0;
	u8 *buf = NULL;

	sta = Ap_get_sta_instance(hapd, addr);
    if (!sta) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Station " MACSTR
                       " not found for AEAD processing\n",
                       __func__, MAC2STR(addr));
            return;
    }

	/* AEAD Encr Action */
	buf_len = ie_len + 16;
	buf = malloc(buf_len);
	if (!buf)
			return;

	memcpy(buf, ie, ie_len);
	eapol_packet_len = ie_len;
	ptk = &sta->PTK;

	if (wpa_aead_encrypt(sta, ptk, buf, eapol_packet_len, &encr_data_len) == 0) {
		ret = WLAN_STATUS_SUCCESS;
	} else {
		DBGPRINT(RT_DEBUG_ERROR, "%s: wpa_aead_encryt fail\n", __func__);
	}

	//hex_dump("WPA: after the AEAD", buf, encr_data_len);

	memset(&sta_mlme_event, 0, sizeof(sta_mlme_event));
	sta_mlme_event.status = ret;
	memcpy(sta_mlme_event.addr, sta->addr, MAC_ADDR_LEN);

	if (ret == WLAN_STATUS_SUCCESS) {
		sta_mlme_event.mgmt_subtype = WLAN_FC_STYPE_ACTION;
		sta_mlme_event.auth_algo = WLAN_AUTH_SHARED_KEY;
		sta_mlme_event.len = encr_data_len ;
		if (sta_mlme_event.len) {
				if (sta_mlme_event.len < MAX_OPT_IE) {
						memcpy(sta_mlme_event.ie, buf,
							sta_mlme_event.len);
				} else {
						DBGPRINT(RT_DEBUG_TRACE, "%s: Not enough space to copy "
								   "opt_ie STA (addr " MACSTR "ie_len %d)",
								   __func__, MAC2STR(sta->addr),
								   (int) eapol_packet_len);
						goto out;
				}
		}
	}

	ret = RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&sta_mlme_event,
		sizeof(RT_802_11_STA_MLME_EVENT), hapd->prefix_wlan_name, sta->ApIdx,
		RT_OID_802_DOT1X_MLME_EVENT);

	if (ret < 0) {
			DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to auth STA (addr " MACSTR
					   " \n",
					   __func__, MAC2STR(sta->addr));
	}

out:
	free(buf);
}

