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
#include "rtdot1x.h"
#include "ap.h"
#include "sta_info.h"

static int
mediatek_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
                          int reassoc, u16 status, const u8 *ie, size_t len)
{
    int ret;
	RT_802_11_STA_MLME_EVENT sta_mlme_event;
	struct apd_data *hapd = priv;
	struct sta_info *sta = NULL;

    DBGPRINT(RT_DEBUG_OFF, "%s: addr=" MACSTR " status_code=%d\n",
               __func__, MAC2STR(addr), status);

    sta = Ap_get_sta_instance(hapd, addr);
    if (!sta) {
            DBGPRINT(RT_DEBUG_TRACE, "%s: Station " MACSTR
                       " not found for sta_assoc processing\n",
                       __func__, MAC2STR(addr));
            return -1;
    }

	memset(&sta_mlme_event, 0, sizeof(sta_mlme_event));
	if (reassoc)
		sta_mlme_event.mgmt_subtype = WLAN_FC_STYPE_REASSOC_REQ;
	else
		sta_mlme_event.mgmt_subtype = WLAN_FC_STYPE_ASSOC_REQ;

	sta_mlme_event.status = status;
    memcpy(sta_mlme_event.addr, addr, MAC_ADDR_LEN);
    sta_mlme_event.len= len;
    if (len) {
            if (len < MAX_OPT_IE) {
                    memcpy(sta_mlme_event.ie, ie, len);
            } else {
                    DBGPRINT(RT_DEBUG_TRACE, "%s: Not enough space to copy "
                               "opt_ie STA (addr " MACSTR " reason %d, "
                               "ie_len %d\n)",
                               __func__, MAC2STR(addr),
                               status, (int) len);
                    return -1;
            }
    }

	ret = RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&sta_mlme_event,
		sizeof(RT_802_11_STA_MLME_EVENT), hapd->prefix_wlan_name, sta->ApIdx,
		RT_OID_802_DOT1X_MLME_EVENT);

    if (ret < 0) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to auth STA (addr " MACSTR
                       " reason %d)\n",
                       __func__, MAC2STR(addr), status);
    }
    return ret;

}

static int
mediatek_sta_auth(void *priv, struct wpa_driver_sta_auth_params *params)
{
    int ret;
	RT_802_11_STA_MLME_EVENT sta_mlme_event;
	struct apd_data *hapd = priv;
	struct sta_info *sta = NULL;

    DBGPRINT(RT_DEBUG_OFF, "%s: addr=" MACSTR " status_code=%d\n",
               __func__, MAC2STR(params->addr), params->status);

    sta = Ap_get_sta_instance(hapd, params->addr);
    if (!sta) {
            DBGPRINT(RT_DEBUG_TRACE, "%s: Station " MACSTR
                       " not found for sta_auth processing\n",
                       __func__, MAC2STR(params->addr));
            return -1;
    }

	memset(&sta_mlme_event, 0, sizeof(sta_mlme_event));
	sta_mlme_event.mgmt_subtype = WLAN_FC_STYPE_AUTH;
	sta_mlme_event.auth_algo = WLAN_AUTH_OPEN;
#ifdef CONFIG_FILS
    /* Copy FILS AAD parameters if the driver supports FILS */
    if (params->fils_auth) {
            DBGPRINT(RT_DEBUG_TRACE, "%s: im_op IEEE80211_MLME_AUTH_FILS\n",
                       __func__);
			sta_mlme_event.auth_algo = WLAN_AUTH_FILS_SK;
            memcpy(sta_mlme_event.fils_anonce, params->fils_anonce,
                      FILS_NONCE_LEN);
            memcpy(sta_mlme_event.fils_snonce, params->fils_snonce,
                      FILS_NONCE_LEN);
            memcpy(sta_mlme_event.fils_kek, params->fils_kek,
                      WPA_KEK_MAX_LEN);
            sta_mlme_event.fils_kek_len = params->fils_kek_len;

			//hex_dump("FILS: ANonce", sta_mlme_event.fils_anonce,
			//	FILS_NONCE_LEN);
            //hex_dump("FILS: SNonce", sta_mlme_event.fils_snonce,
			//	FILS_NONCE_LEN);
            //hex_dump("FILS: KEK", sta_mlme_event.fils_kek,
			//	sta_mlme_event.fils_kek_len);
    }
#endif /* CONFIG_FILS */

    sta_mlme_event.status = params->status;
    sta_mlme_event.seq = params->seq;
    memcpy(sta_mlme_event.addr, params->addr, MAC_ADDR_LEN);
    sta_mlme_event.len= params->len;

    if (params->len) {
            if (params->len < MAX_OPT_IE) {
                    memcpy(sta_mlme_event.ie, params->ie, params->len);
            } else {
                    DBGPRINT(RT_DEBUG_TRACE, "%s: Not enough space to copy "
                               "opt_ie STA (addr " MACSTR " reason %d, "
                               "ie_len %d)",
                               __func__, MAC2STR(params->addr),
                               params->status, (int) params->len);
                    return -1;
            }
    }

	ret = RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&sta_mlme_event,
		sizeof(RT_802_11_STA_MLME_EVENT), hapd->prefix_wlan_name, sta->ApIdx,
		RT_OID_802_DOT1X_MLME_EVENT);

    if (ret < 0) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to auth STA (addr " MACSTR
                       " reason %d)\n",
                       __func__, MAC2STR(params->addr), params->status);
    }
    return ret;
}

static int
mediatek_get_seqnum(void *priv, u8 apidx, const u8 *addr, int idx,
                   u8 *seq)
{
	struct apd_data *hapd = priv;
	RT_802_11_KEY_EVENT wk;

	DBGPRINT(RT_DEBUG_TRACE, "%s: idx=%d\n",
			   __func__, idx);

	memset(&wk, 0, sizeof(wk));
	wk.action = FILS_KEY_GET_TSC;

	if (addr == NULL)
		memset(wk.keyInfo.addr, 0xff, MAC_ADDR_LEN);
	else
		memcpy(wk.keyInfo.addr, addr, MAC_ADDR_LEN);
	wk.keyInfo.KeyIndex = idx;

    if (RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&wk,
		sizeof(RT_802_11_KEY_EVENT), hapd->prefix_wlan_name, apidx,
		RT_OID_802_DOT1X_KEY_EVENT)) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to get encryption data "
                       "(addr " MACSTR " key_idx %d)\n",
                       __func__, MAC2STR(wk.keyInfo.addr), idx);
            return -1;
    }

#ifdef WORDS_BIGENDIAN
    {
            /*
             * wk.ik_keytsc is in host byte order (big endian), need to
             * swap it to match with the byte order used in WPA.
             */
            int i;
#ifndef WPA_KEY_RSC_LEN
#define WPA_KEY_RSC_LEN 8
#endif
            u8 tmp[WPA_KEY_RSC_LEN];
            memcpy(tmp, &wk.ik_keytsc, sizeof(wk.keytsc));
            for (i = 0; i < WPA_KEY_RSC_LEN; i++) {
                    seq[i] = tmp[WPA_KEY_RSC_LEN - i - 1];
            }
    }
#else /* WORDS_BIGENDIAN */
    memcpy(seq, &wk.keytsc, sizeof(wk.keytsc));
#endif /* WORDS_BIGENDIAN */
        return 0;

}

static int
mediatek_set_key(void *priv, u8 apidx, enum wpa_alg alg,
  				  const u8 *addr, int key_idx,
  				  const u8 *key, size_t key_len)
{
	struct apd_data *hapd = priv;
	RT_802_11_KEY_EVENT wk;

	DBGPRINT(RT_DEBUG_TRACE, "%s: idx=%d " MACSTR "\n",
			   __func__, key_idx, MAC2STR(addr));

	memset(&wk, 0, sizeof(wk));
	wk.action = FILS_KEY_INSTALL_PTK;

	if (addr == NULL)
		memset(wk.keyInfo.addr, 0xff, MAC_ADDR_LEN);
	else
		memcpy(wk.keyInfo.addr, addr, MAC_ADDR_LEN);
	wk.keyInfo.KeyIndex = key_idx;
	wk.keyInfo.KeyLength = key_len;

	if (key_len > sizeof(wk.keyInfo.KeyMaterial)) {
        DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to set key data and len%lu exceeded!\n",
                   __func__, key_len);
		return -1;
	}

	memcpy(wk.keyInfo.KeyMaterial, key, wk.keyInfo.KeyLength);

    if (RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&wk,
		sizeof(RT_802_11_KEY_EVENT), hapd->prefix_wlan_name, apidx,
		RT_OID_802_DOT1X_KEY_EVENT)) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to get encryption data "
                       "(addr " MACSTR " key_idx %d)\n",
                       __func__, MAC2STR(wk.keyInfo.addr), key_idx);
            return -1;
    }

	return 0;
}

const struct wpa_driver_ops wpa_driver_mediatek_ops = {
        .name                   = "mediatek",
        .sta_assoc              = mediatek_sta_assoc,
        .sta_auth               = mediatek_sta_auth,
        .get_seqnum             = mediatek_get_seqnum,
        .set_key                = mediatek_set_key,
};
