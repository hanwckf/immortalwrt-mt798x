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

#include "includes.h"
#include "fils.h"

#include "common.h"
#include "sta_info.h"
#include "rtdot1x.h"
#include "rtmp_type.h"
#include "eapol_sm.h"
#include "ieee802_1x.h"
#include "utils/wpabuf.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/crypto.h"
#include "common/ieee802_11_common.h"
#include "common/wpa_common.h"
#include "drvcallbak/drv_hook.h"
#include "wpa.h"
#include "os.h"
#include "fils_hlp.h"
#include "eloop.h"
#include "pmk_cache_ctrl.h"

int fils_set_tk(struct sta_info *sta)
{
        enum wpa_alg alg;
        int klen;

        if (!sta || !sta->PTK_valid) {
                 DBGPRINT(RT_DEBUG_ERROR, "FILS: No valid PTK available to set TK\n");
                return -1;
        }
        if (sta->tk_already_set) {
                DBGPRINT(RT_DEBUG_ERROR, "FILS: TK already set to the driver\n");
                return -1;
        }

        alg = wpa_cipher_to_alg(sta->sta_sec_info.pairwise);
        klen = wpa_cipher_key_len(sta->sta_sec_info.pairwise);

        DBGPRINT(RT_DEBUG_TRACE, "FILS: Configure TK to the driver\n");
		hex_dump("FILS TK", sta->PTK.tk, klen);

        if (hostapd_ap_set_key(sta->priv, sta->ApIdx, 0, alg, sta->addr, 0,
                             sta->PTK.tk, klen)) {
                DBGPRINT(RT_DEBUG_ERROR, "FILS: Failed to set TK to the driver");
                return -1;
        }
        sta->tk_already_set = TRUE;

        return 0;
}

int fils_pmkid_erp(int akmp, const u8 *reauth, size_t reauth_len,
                   u8 *pmkid)
{
        const u8 *addr[1];
        size_t len[1];
        u8 hash[SHA384_MAC_LEN] = {0};
        int res;

        /* PMKID = Truncate-128(Hash(EAP-Initiate/Reauth)) */
        addr[0] = reauth;
        len[0] = reauth_len;
        if (wpa_key_mgmt_sha384(akmp))
                res = sha384_vector(1, addr, len, hash);
        else if (wpa_key_mgmt_sha256(akmp))
                res = sha256_vector(1, addr, len, hash);
        else {
			DBGPRINT(RT_DEBUG_ERROR, "%s: not support for this akm",
				__func__);
            return -1;
        }

        if (res) {
			DBGPRINT(RT_DEBUG_ERROR, "%s: sha-function error", __func__);
        	return res;
        }

        memcpy(pmkid, hash, PMKID_LEN);
        hex_dump("FILS: PMKID", pmkid, PMKID_LEN);
        return 0;
}


int fils_rmsk_to_pmk(int akmp, const u8 *rmsk, size_t rmsk_len,
                     const u8 *snonce, const u8 *anonce, const u8 *dh_ss,
                     size_t dh_ss_len, u8 *pmk, size_t *pmk_len)
{
    u8 nonces[2 * FILS_NONCE_LEN];
    const u8 *addr[2];
    size_t len[2];
    size_t num_elem;
    int res;

    /* PMK = HMAC-Hash(SNonce || ANonce, rMSK [ || DHss ]) */
    //DBGPRINT(RT_DEBUG_TRACE, "FILS: rMSK to PMK derivation\n");

    if (wpa_key_mgmt_sha384(akmp))
        *pmk_len = SHA384_MAC_LEN;
    else if (wpa_key_mgmt_sha256(akmp))
        *pmk_len = SHA256_MAC_LEN;
    else
        return -1;

    //hex_dump("FILS: rMSK", rmsk, rmsk_len);
    //hex_dump("FILS: SNonce", snonce, FILS_NONCE_LEN);
    //hex_dump("FILS: ANonce", anonce, FILS_NONCE_LEN);
    //hex_dump("FILS: DHss", dh_ss, dh_ss_len);

    memcpy(nonces, snonce, FILS_NONCE_LEN);
    memcpy(&nonces[FILS_NONCE_LEN], anonce, FILS_NONCE_LEN);
    addr[0] = rmsk;
    len[0] = rmsk_len;
    num_elem = 1;
    if (dh_ss) {
            addr[1] = dh_ss;
            len[1] = dh_ss_len;
            num_elem++;
    }

    if (wpa_key_mgmt_sha384(akmp))
        res = hmac_sha384_vector(nonces, 2 * FILS_NONCE_LEN, num_elem,
                                 addr, len, pmk);
    else
        res = hmac_sha256_vector(nonces, 2 * FILS_NONCE_LEN, num_elem,
                                 addr, len, pmk);

    if (res == 0)
        ; //hex_dump("FILS: PMK", pmk, *pmk_len);
    else
       *pmk_len = 0;

    return res;
}

int fils_pmk_to_ptk(const u8 *pmk, size_t pmk_len, const u8 *spa, const u8 *aa,
                    const u8 *snonce, const u8 *anonce, const u8 *dhss,
                    size_t dhss_len, struct wpa_ptk *ptk,
                    u8 *ick, size_t *ick_len, int akmp, int cipher,
                    u8 *fils_ft, size_t *fils_ft_len)
{
	u8 *data, *pos;
	size_t data_len;
	u8 tmp[FILS_ICK_MAX_LEN + WPA_KEK_MAX_LEN + WPA_TK_MAX_LEN +
		   FILS_FT_MAX_LEN];
	size_t key_data_len;
	const char *label = "FILS PTK Derivation";
	int ret = -1;

/*
 * FILS-Key-Data = PRF-X(PMK, "FILS PTK Derivation",
 *						 SPA || AA || SNonce || ANonce [ || DHss ])
 * ICK = L(FILS-Key-Data, 0, ICK_bits)
 * KEK = L(FILS-Key-Data, ICK_bits, KEK_bits)
 * TK = L(FILS-Key-Data, ICK_bits + KEK_bits, TK_bits)
 * If doing FT initial mobility domain association:
 * FILS-FT = L(FILS-Key-Data, ICK_bits + KEK_bits + TK_bits,
 *			   FILS-FT_bits)
 */
	data_len = 2 * ETH_ALEN + 2 * FILS_NONCE_LEN + dhss_len;
	data = malloc(data_len);
	if (!data)
			goto err;
	pos = data;
	memcpy(pos, spa, ETH_ALEN);
	pos += ETH_ALEN;
	memcpy(pos, aa, ETH_ALEN);
	pos += ETH_ALEN;
	memcpy(pos, snonce, FILS_NONCE_LEN);
	pos += FILS_NONCE_LEN;
	memcpy(pos, anonce, FILS_NONCE_LEN);
	pos += FILS_NONCE_LEN;
	if (dhss)
			memcpy(pos, dhss, dhss_len);

	ptk->kck_len = 0;
	ptk->kek_len = wpa_kek_len(akmp, pmk_len);
	ptk->tk_len = wpa_cipher_key_len(cipher);
	if (wpa_key_mgmt_sha384(akmp))
		*ick_len = 48;
	else if (wpa_key_mgmt_sha256(akmp))
		*ick_len = 32;
	else
		goto err;
	key_data_len = *ick_len + ptk->kek_len + ptk->tk_len;

	if (fils_ft && fils_ft_len) {
		if (akmp == WPA_KEY_MGMT_FT_FILS_SHA256) {
				*fils_ft_len = 32;
		} else if (akmp == WPA_KEY_MGMT_FT_FILS_SHA384) {
				*fils_ft_len = 48;
		} else {
				*fils_ft_len = 0;
				fils_ft = NULL;
		}
		key_data_len += *fils_ft_len;
	}

	if (wpa_key_mgmt_sha384(akmp)) {
			DBGPRINT(RT_DEBUG_TRACE, "FILS: PTK derivation using PRF(SHA384)\n");
			if (sha384_prf(pmk, pmk_len, label, data, data_len,
						   tmp, key_data_len) < 0)
					goto err;
	} else {
			DBGPRINT(RT_DEBUG_TRACE, "FILS: PTK derivation using PRF(SHA256)\n");
			if (sha256_prf(pmk, pmk_len, label, data, data_len,
						   tmp, key_data_len) < 0)
					goto err;
	}

	//DBGPRINT(RT_DEBUG_TRACE, "FILS: PTK derivation - SPA=" MACSTR
	//		   " AA=" MACSTR, MAC2STR(spa), MAC2STR(aa));
	//hex_dump("FILS: SNonce", snonce, FILS_NONCE_LEN);
	//hex_dump("FILS: ANonce", anonce, FILS_NONCE_LEN);
	//if (dhss)
	//	hex_dump("FILS: DHss", dhss, dhss_len);
	//hex_dump("FILS: PMK", pmk, pmk_len);
	//hex_dump("FILS: FILS-Key-Data", tmp, key_data_len);

	memcpy(ick, tmp, *ick_len);
	//hex_dump("FILS: ICK", ick, *ick_len);

	memcpy(ptk->kek, tmp + *ick_len, ptk->kek_len);
	//hex_dump("FILS: KEK", ptk->kek, ptk->kek_len);

	memcpy(ptk->tk, tmp + *ick_len + ptk->kek_len, ptk->tk_len);
	//hex_dump("FILS: TK", ptk->tk, ptk->tk_len);

	if (fils_ft && fils_ft_len) {
		memcpy(fils_ft, tmp + *ick_len + ptk->kek_len + ptk->tk_len,
				  *fils_ft_len);
		hex_dump("FILS: FILS-FT", fils_ft, *fils_ft_len);
	}

    ptk->kek2_len = 0;
    ptk->kck2_len = 0;

    memset(tmp, 0, sizeof(tmp));
    ret = 0;
err:
    bin_clear_free(data, data_len);
    return ret;
}

int fils_key_auth_sk(const u8 *ick, size_t ick_len, const u8 *snonce,
                     const u8 *anonce, const u8 *sta_addr, const u8 *bssid,
                     const u8 *g_sta, size_t g_sta_len,
                     const u8 *g_ap, size_t g_ap_len,
                     int akmp, u8 *key_auth_sta, u8 *key_auth_ap,
                     size_t *key_auth_len)
{
    const u8 *addr[6];
    size_t len[6];
    size_t num_elem = 4;
    int res;

    DBGPRINT(RT_DEBUG_TRACE, "FILS: Key-Auth derivation: STA-MAC=" MACSTR
               " AP-BSSID=" MACSTR, MAC2STR(sta_addr), MAC2STR(bssid));
    //wpa_hexdump_key(MSG_DEBUG, "FILS: ICK", ick, ick_len);
    //wpa_hexdump(MSG_DEBUG, "FILS: SNonce", snonce, FILS_NONCE_LEN);
    //wpa_hexdump(MSG_DEBUG, "FILS: ANonce", anonce, FILS_NONCE_LEN);
    //wpa_hexdump(MSG_DEBUG, "FILS: gSTA", g_sta, g_sta_len);
    //wpa_hexdump(MSG_DEBUG, "FILS: gAP", g_ap, g_ap_len);

	/*
	 * For (Re)Association Request frame (STA->AP):
	 * Key-Auth = HMAC-Hash(ICK, SNonce || ANonce || STA-MAC || AP-BSSID
	 *						[ || gSTA || gAP ])
	 */
	addr[0] = snonce;
	len[0] = FILS_NONCE_LEN;
	addr[1] = anonce;
	len[1] = FILS_NONCE_LEN;
	addr[2] = sta_addr;
	len[2] = ETH_ALEN;
	addr[3] = bssid;
	len[3] = ETH_ALEN;
	if (g_sta && g_ap_len && g_ap && g_ap_len) {
			addr[4] = g_sta;
			len[4] = g_sta_len;
			addr[5] = g_ap;
			len[5] = g_ap_len;
			num_elem = 6;
	}

	if (wpa_key_mgmt_sha384(akmp)) {
			*key_auth_len = 48;
			res = hmac_sha384_vector(ick, ick_len, num_elem, addr, len,
									 key_auth_sta);
	} else if (wpa_key_mgmt_sha256(akmp)) {
			*key_auth_len = 32;
			res = hmac_sha256_vector(ick, ick_len, num_elem, addr, len,
									 key_auth_sta);
	} else {
			return -1;
	}
	if (res < 0)
			return res;

	/*
	 * For (Re)Association Response frame (AP->STA):
	 * Key-Auth = HMAC-Hash(ICK, ANonce || SNonce || AP-BSSID || STA-MAC
	 *						[ || gAP || gSTA ])
	 */
	addr[0] = anonce;
	addr[1] = snonce;
	addr[2] = bssid;
	addr[3] = sta_addr;
	if (g_sta && g_ap_len && g_ap && g_ap_len) {
			addr[4] = g_ap;
			len[4] = g_ap_len;
			addr[5] = g_sta;
			len[5] = g_sta_len;
	}

	if (wpa_key_mgmt_sha384(akmp))
			res = hmac_sha384_vector(ick, ick_len, num_elem, addr, len,
									 key_auth_ap);
	else if (wpa_key_mgmt_sha256(akmp))
			res = hmac_sha256_vector(ick, ick_len, num_elem, addr, len,
									 key_auth_ap);
	if (res < 0)
			return res;

#if 0
	wpa_hexdump(MSG_DEBUG, "FILS: Key-Auth (STA)",
				key_auth_sta, *key_auth_len);
	wpa_hexdump(MSG_DEBUG, "FILS: Key-Auth (AP)",
				key_auth_ap, *key_auth_len);
#endif
	return 0;
}

int fils_auth_pmk_to_ptk(struct apd_data *hapd, struct sta_info *sta,
						 int akmp, const u8 *pmk,
                         size_t pmk_len, const u8 *snonce, const u8 *anonce,
                         const u8 *dhss, size_t dhss_len,
                         struct wpabuf *g_sta, struct wpabuf *g_ap)
{
	u8 ick[FILS_ICK_MAX_LEN];
	size_t ick_len;
	int res;
	u8 fils_ft[FILS_FT_MAX_LEN];
	size_t fils_ft_len = 0;
	int wpa_key_mgmt = akmp;
	int pairwise = sta->sta_sec_info.pairwise;

	res = fils_pmk_to_ptk(pmk, pmk_len, sta->addr, hapd->own_addr[sta->ApIdx],
						  snonce, anonce, dhss, dhss_len,
						  &sta->PTK, ick, &ick_len,
						  wpa_key_mgmt, pairwise,
						  fils_ft, &fils_ft_len);
	if (res < 0)
			return res;

    sta->PTK_valid = TRUE;
    sta->tk_already_set = FALSE;

#ifdef CONFIG_IEEE80211R_AP
        if (fils_ft_len) {
                struct wpa_authenticator *wpa_auth = sm->wpa_auth;
                struct wpa_auth_config *conf = &wpa_auth->conf;
                u8 pmk_r0[PMK_LEN], pmk_r0_name[WPA_PMK_NAME_LEN];

                if (wpa_derive_pmk_r0(fils_ft, fils_ft_len,
                                      conf->ssid, conf->ssid_len,
                                      conf->mobility_domain,
                                      conf->r0_key_holder,
                                      conf->r0_key_holder_len,
                                      sm->addr, pmk_r0, pmk_r0_name) < 0)
                        return -1;

                wpa_hexdump_key(MSG_DEBUG, "FILS+FT: PMK-R0", pmk_r0, PMK_LEN);
                wpa_hexdump(MSG_DEBUG, "FILS+FT: PMKR0Name",
                            pmk_r0_name, WPA_PMK_NAME_LEN);
                wpa_ft_store_pmk_fils(sm, pmk_r0, pmk_r0_name);
                os_memset(fils_ft, 0, sizeof(fils_ft));
        }
#endif /* CONFIG_IEEE80211R_AP */

	res = fils_key_auth_sk(ick, ick_len, snonce, anonce,
						   sta->addr, hapd->own_addr[sta->ApIdx],
						   g_sta ? wpabuf_head(g_sta) : NULL,
						   g_sta ? wpabuf_len(g_sta) : 0,
						   g_ap ? wpabuf_head(g_ap) : NULL,
						   g_ap ? wpabuf_len(g_ap) : 0,
						   wpa_key_mgmt, sta->fils_key_auth_sta,
						   sta->fils_key_auth_ap,
						   &sta->fils_key_auth_len);
	memset(ick, 0, sizeof(ick));

	/* Store nonces for (Re)Association Request/Response frame processing */
	memcpy(sta->fils_snonce, snonce, FILS_NONCE_LEN);
	memcpy(sta->fils_anonce, anonce, FILS_NONCE_LEN);

	return res;
}

static u16 check_assoc_ies(struct apd_data *hapd, struct sta_info *sta,
                           const u8 *ies, size_t ies_len, int reassoc)
{
	return WLAN_STATUS_SUCCESS;
}

u16 send_assoc_resp(struct apd_data *hapd, struct sta_info *sta,
                           const u8 *addr, u16 status_code, int reassoc,
                           const u8 *ies, size_t ies_len)
{
	int send_len = 0;
	u8 *buf = NULL;
	size_t buflen;
	struct ieee80211_mgmt *reply = NULL;
	u8 *p = NULL;
	u16 res = WLAN_STATUS_SUCCESS;
	u8 *pos = NULL;
	int enc_block_len = 0;
	int ret;
	RT_802_11_STA_MLME_EVENT sta_mlme_event;

	DBGPRINT(RT_DEBUG_TRACE, "%s: %d\n",  __func__, __LINE__);

	if (!sta) {
		DBGPRINT(RT_DEBUG_TRACE, "%s: %d sta is null!!!\n", __func__, __LINE__);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
	buflen = sizeof(struct ieee80211_mgmt) + 1024;
#ifdef CONFIG_FILS
	if (sta && sta->fils_hlp_resp)
			buflen += wpabuf_len(sta->fils_hlp_resp);
#endif /* CONFIG_FILS */

	buf = os_zalloc(buflen);
	if (!buf) {
			status_code = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto done;
	}

	memset(&sta_mlme_event, 0, sizeof(sta_mlme_event));
	if (reassoc)
		sta_mlme_event.mgmt_subtype = WLAN_FC_STYPE_REASSOC_RESP;
	else
		sta_mlme_event.mgmt_subtype = WLAN_FC_STYPE_ASSOC_RESP;

    memcpy(sta_mlme_event.addr, sta->addr, MAC_ADDR_LEN);

	ret = RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&sta_mlme_event,
		sizeof(RT_802_11_STA_MLME_EVENT), hapd->prefix_wlan_name, sta->ApIdx,
		RT_OID_802_DOT1X_MLME_EVENT);

    if (ret < 0) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to auth STA (addr " MACSTR
                       " reason %d)\n",
                       __func__, MAC2STR(addr), sta_mlme_event.status);
			status_code = WLAN_STATUS_UNSPECIFIED_FAILURE;
			sta_mlme_event.len = 0;
    }

	memcpy(buf, sta_mlme_event.ie, sta_mlme_event.len);

	DBGPRINT(RT_DEBUG_TRACE, "%s: %d ==> len(%d)\n",
		__func__, __LINE__, sta_mlme_event.len);

	if (sta_mlme_event.len == 0) {
#if 0
		DBGPRINT(RT_DEBUG_TRACE, "%s: Fail to get AssocRsp from driver ==> making Rsp\n",
			__func__);

		reply->frame_control =
				IEEE80211_FC(WLAN_FC_TYPE_MGMT,
							 (reassoc ? WLAN_FC_STYPE_REASSOC_RESP :
							  WLAN_FC_STYPE_ASSOC_RESP));
		memcpy(reply->da, addr, ETH_ALEN);
		memcpy(reply->sa, hapd->own_addr[sta->ApIdx], ETH_ALEN);
		memcpy(reply->bssid, hapd->own_addr[sta->ApIdx], ETH_ALEN);

		reply->u.assoc_resp.capab_info =
				host_to_le16(hostapd_ap_capab_info(hapd, sta));
		reply->u.assoc_resp.status_code = host_to_le16(status_code);

		reply->u.assoc_resp.aid = host_to_le16((sta ? sta->aid : 0) |
											   BIT(14) | BIT(15));
		goto done;
#endif
		if (buf)
			free(buf);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	reply = (struct ieee80211_mgmt *) buf;
	p = buf + sta_mlme_event.len;

	send_len = IEEE80211_HDRLEN;
	send_len += sizeof(reply->u.assoc_resp);
	send_len += p - reply->u.assoc_resp.variable;
#ifdef CONFIG_FILS
	if (sta &&
		(sta->auth_alg == WLAN_AUTH_FILS_SK ||
		 sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
		 sta->auth_alg == WLAN_AUTH_FILS_PK)) {
			struct ieee802_11_elems elems;

			if (ieee802_11_parse_elems(ies, ies_len, &elems, 0) ==
				ParseFailed || !elems.fils_session) {
					status_code = WLAN_STATUS_UNSPECIFIED_FAILURE;
					goto done;
			}

			/* FILS Session */
			*p++ = WLAN_EID_EXTENSION; /* Element ID */
			*p++ = 1 + FILS_SESSION_LEN; /* Length */
			*p++ = WLAN_EID_EXT_FILS_SESSION; /* Element ID Extension */
			memcpy(p, elems.fils_session, FILS_SESSION_LEN);
			send_len += 2 + 1 + FILS_SESSION_LEN;

			pos = buf + send_len;
			enc_block_len = send_len;

			send_len = fils_encrypt_assoc(sta, buf, send_len,
										  buflen, sta->fils_hlp_resp);
			if (send_len < 0) {
					status_code = WLAN_STATUS_UNSPECIFIED_FAILURE;
					goto done;
			}

			//hex_dump("AEAD ENCR ASSOC_RSP", pos, enc_block_len);
	}
#endif /* CONFIG_FILS */

done:
	DBGPRINT(RT_DEBUG_TRACE,
		   "%s: %d\n",
		   __func__, __LINE__);
	if (reply)
		reply->u.assoc_resp.status_code = host_to_le16(status_code);

    if (hostapd_sta_assoc(hapd, hapd->own_addr[sta->ApIdx], sta->addr,
			reassoc, status_code, buf, send_len) < 0) {
            DBGPRINT(RT_DEBUG_ERROR, "Failed to send assoc resp: %s\n",
                       strerror(errno));
            res = WLAN_STATUS_UNSPECIFIED_FAILURE;
    }

	if (buf)
		free(buf);

	return res;
}

static struct wpabuf *
prepare_auth_resp_fils(struct apd_data *hapd,
                       struct sta_info *sta, u16 *resp,
                       struct _RT_802_PMKSA_CACHE_ENTRY *pmksa,
                       const u8 *erp_resp, size_t erp_resp_len,
                       const u8 *msk, size_t msk_len,
                       int *is_pub)
{
	u8 fils_nonce[FILS_NONCE_LEN];
	size_t ielen;
	struct wpabuf *data = NULL;
	const u8 *ie = NULL;
	u8 *ie_buf = NULL;
	const u8 *pmk = NULL;
	size_t pmk_len = 0;
	u8 pmk_buf[PMK_LEN_MAX];
	struct wpabuf *pub = NULL;
	int wpa_key_mgmt = sta->sta_sec_info.wpa_key_mgmt;

	if (*resp != WLAN_STATUS_SUCCESS)
			goto fail;

	ie = wpa_auth_get_wpa_ie(hapd, sta->ApIdx, &ielen);
	if (!ie) {
			*resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
	}

	if (pmksa) {
			/* Add PMKID of the selected PMKSA into RSNE */
			ie_buf = malloc(ielen + 2 + 2 + PMKID_LEN);
			if (!ie_buf) {
					*resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
					goto fail;
			}

			memcpy(ie_buf, ie, ielen);
			if (wpa_insert_pmkid(ie_buf, &ielen, pmksa->pmkid) < 0) {
					*resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
					goto fail;
			}
			ie = ie_buf;
	}

	if (random_get_bytes(fils_nonce, FILS_NONCE_LEN) < 0) {
			*resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
	}
	//hex_dump("RSN: Generated FILS Nonce", fils_nonce, FILS_NONCE_LEN);

    data = wpabuf_alloc(1000 + ielen);
    if (!data) {
			DBGPRINT(RT_DEBUG_ERROR, "%s: ===> %d\n", __func__, __LINE__);
            *resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
            goto fail;
    }

    /* RSNE */
    wpabuf_put_data(data, ie, ielen);
	//hex_dump("AP IE", ie, ielen);

	/* FILS Nonce */
	wpabuf_put_u8(data, WLAN_EID_EXTENSION); /* Element ID */
	wpabuf_put_u8(data, 1 + FILS_NONCE_LEN); /* Length */
	/* Element ID Extension */
	wpabuf_put_u8(data, WLAN_EID_EXT_FILS_NONCE);
	wpabuf_put_data(data, fils_nonce, FILS_NONCE_LEN);
	/* FILS Session */
	wpabuf_put_u8(data, WLAN_EID_EXTENSION); /* Element ID */
	wpabuf_put_u8(data, 1 + FILS_SESSION_LEN); /* Length */
	/* Element ID Extension */
	wpabuf_put_u8(data, WLAN_EID_EXT_FILS_SESSION);
	wpabuf_put_data(data, sta->fils_session, FILS_SESSION_LEN);
	/* FILS Wrapped Data */
	if (!pmksa && erp_resp) {
			wpabuf_put_u8(data, WLAN_EID_EXTENSION); /* Element ID */
			wpabuf_put_u8(data, 1 + erp_resp_len); /* Length */
			/* Element ID Extension */
			wpabuf_put_u8(data, WLAN_EID_EXT_FILS_WRAPPED_DATA);
			wpabuf_put_data(data, erp_resp, erp_resp_len);

			if (fils_rmsk_to_pmk(wpa_key_mgmt,
								 msk, msk_len, sta->fils_snonce, fils_nonce,
								 sta->fils_dh_ss ?
								 wpabuf_head(sta->fils_dh_ss) : NULL,
								 sta->fils_dh_ss ?
								 wpabuf_len(sta->fils_dh_ss) : 0,
								 pmk_buf, &pmk_len)) {
					DBGPRINT(RT_DEBUG_ERROR, "FILS: Failed to derive PMK");
					*resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
					wpabuf_free(data);
					data = NULL;
					goto fail;
			}
			pmk = pmk_buf;

            /* Don't use DHss in PTK derivation if PMKSA caching is not
             * used. */
            wpabuf_clear_free(sta->fils_dh_ss);
            sta->fils_dh_ss = NULL;

			if (sta->fils_erp_pmkid_set) {
				sta->fils_erp_pmkid_set = 0;

				if (pmksa_cache_add(hapd, sta, pmk, pmk_len, sta->fils_erp_pmkid) < 0) {
					DBGPRINT(RT_DEBUG_ERROR,
							   "FILS: Failed to add PMKSA cache entry based on ERP");
				}
			}
	} else if (pmksa) {
		pmk = pmksa->pmk;
		pmk_len = pmksa->pmk_len;
	}

	if (!pmk) {
			DBGPRINT(RT_DEBUG_ERROR, "FILS: No PMK available");
			*resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			wpabuf_free(data);
			data = NULL;
			goto fail;
	}

	if (fils_auth_pmk_to_ptk(hapd, sta, wpa_key_mgmt, pmk, pmk_len,
							 sta->fils_snonce, fils_nonce,
							 sta->fils_dh_ss ?
							 wpabuf_head(sta->fils_dh_ss) : NULL,
							 sta->fils_dh_ss ?
							 wpabuf_len(sta->fils_dh_ss) : 0,
							 sta->fils_g_sta, pub) < 0) {
			*resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			wpabuf_free(data);
			data = NULL;
			goto fail;
	}

fail:
	if (is_pub)
			*is_pub = pub != NULL;
	if (ie_buf)
		free(ie_buf);
	wpabuf_free(pub);
	wpabuf_clear_free(sta->fils_dh_ss);
	sta->fils_dh_ss = NULL;

	if (data)
		hex_dump("AUTH RES", wpabuf_head(data), wpabuf_len(data));

	return data;
}

void ieee802_11_finish_fils_auth(struct apd_data *hapd,
                                 struct sta_info *sta, int success)
{
	struct wpabuf *data;
	int pub = 0;
	u16 resp;
	u8 *msk = NULL;
	size_t msk_len = 0;

	sta->flags &= ~WLAN_STA_PENDING_FILS_ERP;

	if (!sta->fils_pending_cb)
			return;

	resp = success ? WLAN_STATUS_SUCCESS : WLAN_STATUS_UNSPECIFIED_FAILURE;

	DBGPRINT(RT_DEBUG_ERROR, "%s: ===> %d\n", __func__, __LINE__);

	if (resp == WLAN_STATUS_SUCCESS) {
		msk_len = sta->eapol_key_crypt_len + sta->eapol_key_sign_len;
		msk = malloc(msk_len);
		if (msk) {
			memcpy(msk, sta->eapol_key_crypt, sta->eapol_key_crypt_len);
			memcpy(msk + sta->eapol_key_crypt_len,
				sta->eapol_key_sign, sta->eapol_key_sign_len);
		} else {
			DBGPRINT(RT_DEBUG_ERROR,
					   "%s: malloc failure (msk_len:%lu)\n",
					   __func__, msk_len);
			return;
		}
	}

	data = prepare_auth_resp_fils(hapd, sta, &resp, NULL, sta->last_eap_radius,
								  sta->last_eap_radius_len,
								  msk, msk_len, &pub);
	if (!data) {
			DBGPRINT(RT_DEBUG_ERROR,
					   "%s: prepare_auth_resp_fils() returned failure",
					   __func__);
	}
	sta->fils_pending_cb(hapd, sta, resp, data, pub);

	if (msk)
		free(msk);

	DBGPRINT(RT_DEBUG_ERROR, "%s: ===> %d\n", __func__, __LINE__);
}

void handle_auth_fils(struct apd_data *hapd, struct sta_info *sta,
                      const u8 *pos, size_t len, u16 auth_alg,
                      u16 auth_transaction, u16 status_code,
                      void (*cb)(struct apd_data *hapd,
                                 struct sta_info *sta, u16 resp,
                                 struct wpabuf *data, int pub))
{
	u16 resp = WLAN_STATUS_SUCCESS;
	const u8 *end;
	struct ieee802_11_elems elems;
	int res;
	struct wpa_ie_data rsn;
	struct _RT_802_PMKSA_CACHE_ENTRY *pmksa = NULL;
	struct sec_info *ap_sec_info = NULL;

	memset((void *)&elems, 0, sizeof(struct ieee802_11_elems));
	if (auth_transaction != 1 || status_code != WLAN_STATUS_SUCCESS)
			return;

	ap_sec_info = &hapd->ap_sec_info[sta->ApIdx];
	end = pos + len;

	//hex_dump("FILS: Authentication frame fields",
	//			pos, end - pos);
	//hex_dump("FILS: Remaining IEs", pos, end - pos);

	if (ieee802_11_parse_elems(pos, end - pos, &elems, 1) == ParseFailed) {
			DBGPRINT(RT_DEBUG_TRACE, "FILS: Could not parse elements");
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
	}

	/* RSNE */
	//hex_dump("FILS: RSN element", elems.rsn_ie, elems.rsn_ie_len);
	if (!elems.rsn_ie ||
		wpa_parse_wpa_ie_rsn(elems.rsn_ie - 2, elems.rsn_ie_len + 2,
							 &rsn) < 0) {
			DBGPRINT(RT_DEBUG_TRACE, "FILS: No valid RSN element\n");
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
	}

	res = wpa_validate_wpa_ie(hapd, sta,
							  elems.rsn_ie - 2, elems.rsn_ie_len + 2,
							  elems.mdie, elems.mdie_len, NULL, 0);
	resp = wpa_res_to_status_code(res);
	if (resp != WLAN_STATUS_SUCCESS)
			goto fail;

	if (!elems.fils_nonce) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: No FILS Nonce field");
		resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
		goto fail;
	}

	//hex_dump("FILS: SNonce", elems.fils_nonce, FILS_NONCE_LEN);
	memcpy(sta->fils_snonce, elems.fils_nonce, FILS_NONCE_LEN);

	if (ap_sec_info->FilsCacheId) {
		DBGPRINT(RT_DEBUG_TRACE, "FILS: PMKASA CacheFunction Enabled (0x%4x)\n",
			ap_sec_info->FilsCacheId);

		/* PMKID List */
		if (rsn.pmkid && rsn.num_pmkid > 0) {
			u8 num;
			const u8 *pmkid;

			//hex_dump("FILS: PMKID List",
			//		rsn.pmkid, rsn.num_pmkid * PMKID_LEN);

			pmkid = rsn.pmkid;
			num = rsn.num_pmkid;
			while (num) {
			//	hex_dump("FILS: PMKID", pmkid, PMKID_LEN);
				pmksa = pmksa_cache_get(hapd, sta, pmkid);
				if (pmksa)
					break;

				pmkid += PMKID_LEN;
				num--;
			}
		}
	} else 	{
		DBGPRINT(RT_DEBUG_TRACE, "FILS: PMKASA CacheFunction not Enabled\n");
	}

	if (pmksa)
		DBGPRINT(RT_DEBUG_TRACE, "FILS: Found matching PMKSA cache entry\n");

	/* FILS Session */
	if (!elems.fils_session) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: No FILS Session element\n");
		resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
		goto fail;
	}

	//hex_dump("FILS: FILS Session", elems.fils_session,
	//		FILS_SESSION_LEN);
	memcpy(sta->fils_session, elems.fils_session, FILS_SESSION_LEN);

	/* FILS Wrapped Data */
	if (elems.fils_wrapped_data) {
		//hex_dump("FILS: Wrapped Data",
		//	    elems.fils_wrapped_data,
		//	    elems.fils_wrapped_data_len);
		if (!pmksa) {
			if (!sta->eapol_sm) {
				sta->eapol_sm = eapol_sm_alloc(hapd, sta);
			}
			DBGPRINT(RT_DEBUG_OFF,
				   "FILS: Forward EAP-Initiate/Re-auth to authentication server\n");
			ieee802_1x_encapsulate_radius(
				hapd, sta, elems.fils_wrapped_data,
				elems.fils_wrapped_data_len);
			sta->fils_pending_cb = cb;
			sta->flags |= WLAN_STA_PENDING_FILS_ERP;

			/* Calculate pending PMKID here so that we do not need
			 * to maintain a copy of the EAP-Initiate/Reauth
			 * message. */
			if (fils_pmkid_erp(sta->sta_sec_info.wpa_key_mgmt,
					   elems.fils_wrapped_data,
					   elems.fils_wrapped_data_len,
					   sta->fils_erp_pmkid) == 0)
				sta->fils_erp_pmkid_set = 1;
			return;
		}
	}

fail:
	if (cb) {
		struct wpabuf *data;
		int pub = 0;

		data = prepare_auth_resp_fils(hapd, sta, &resp, pmksa, NULL, 0,
					      NULL, 0, &pub);
		if (!data) {
			DBGPRINT(RT_DEBUG_TRACE,
				 "%s: prepare_auth_resp_fils() returned failure\n",
				 __func__);
		}

		cb(hapd, sta, resp, data, pub);
	}
}

void handle_assoc_fils(struct apd_data *hapd,
	 struct sta_info *sta, const struct ieee80211_mgmt *mgmt,
	 size_t len, int reassoc)
{
	u16 capab_info, listen_interval, seq_ctrl, fc;
	u16 resp = WLAN_STATUS_SUCCESS, reply_res;
	const u8 *pos = NULL;
	int left = 0;
	u8 *tmp = NULL;
#ifdef CONFIG_FILS
	int delay_assoc = 0;

	if (!sta) {
		DBGPRINT(RT_DEBUG_ERROR, "sta is null !!!\n");
		return;
	}

	if (sta->auth_alg != WLAN_AUTH_FILS_SK) {
		resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
		goto fail;
	}
#endif /* CONFIG_FILS */

	fc = le_to_host16(mgmt->frame_control);
	seq_ctrl = le_to_host16(mgmt->seq_ctrl);

	if (reassoc) {
		capab_info = le_to_host16(mgmt->u.reassoc_req.capab_info);
		listen_interval = le_to_host16(
			mgmt->u.reassoc_req.listen_interval);
		DBGPRINT(RT_DEBUG_TRACE, "reassociation request: STA=" MACSTR
			   " capab_info=0x%02x listen_interval=%d current_ap="
			   MACSTR " seq_ctrl=0x%x%s\n",
			   MAC2STR(mgmt->sa), capab_info, listen_interval,
			   MAC2STR(mgmt->u.reassoc_req.current_ap),
			   seq_ctrl, (fc & WLAN_FC_RETRY) ? " retry" : "");
		left = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.reassoc_req));
		pos = mgmt->u.reassoc_req.variable;
	} else {
		capab_info = le_to_host16(mgmt->u.assoc_req.capab_info);
		listen_interval = le_to_host16(
			mgmt->u.assoc_req.listen_interval);
		DBGPRINT(RT_DEBUG_TRACE, "association request: STA=" MACSTR
			   " capab_info=0x%02x listen_interval=%d "
			   "seq_ctrl=0x%x%s\n",
			   MAC2STR(mgmt->sa), capab_info, listen_interval,
			   seq_ctrl, (fc & WLAN_FC_RETRY) ? " retry" : "");
		left = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.assoc_req));
		pos = mgmt->u.assoc_req.variable;
	}

	sta = Ap_get_sta_instance(hapd, mgmt->sa);
	if (!sta) {
		DBGPRINT(RT_DEBUG_TRACE, "Station " MACSTR
				   " not found for sta_auth processing\n",
				   MAC2STR(mgmt->sa));
		return;
	}

#ifdef CONFIG_FILS
	if (sta->auth_alg == WLAN_AUTH_FILS_SK ||
	    sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
	    sta->auth_alg == WLAN_AUTH_FILS_PK) {
		int res;

		/* The end of the payload is encrypted. Need to decrypt it
		 * before parsing. */

		tmp = os_memdup(pos, left);
		if (!tmp) {
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
		}

		res = fils_decrypt_assoc(sta, mgmt,
					 len, tmp, left);
		if (res < 0) {
			resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
		}
		pos = tmp;
		left = res;
	}
#endif /* CONFIG_FILS */

	/* followed by SSID and Supported rates; and HT capabilities if 802.11n
	 * is used */
	resp = check_assoc_ies(hapd, sta, pos, left, reassoc);
	if (resp != WLAN_STATUS_SUCCESS)
		goto fail;

#ifdef CONFIG_FILS
	if (sta->auth_alg == WLAN_AUTH_FILS_SK ||
	    sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
	    sta->auth_alg == WLAN_AUTH_FILS_PK) {
		if (fils_process_hlp(hapd, sta, pos, left) > 0)
			delay_assoc = 1;
	}
#endif /* CONFIG_FILS */

fail:

#ifdef CONFIG_FILS
	if (sta) {
		eloop_cancel_timeout(fils_hlp_timeout, hapd, sta);
		if (sta->fils_pending_assoc_req)
			free(sta->fils_pending_assoc_req);

		sta->fils_pending_assoc_req = NULL;
		sta->fils_pending_assoc_req_len = 0;
		wpabuf_free(sta->fils_hlp_resp);
		sta->fils_hlp_resp = NULL;
	}

	if (sta && delay_assoc &&
		resp == WLAN_STATUS_SUCCESS) {

		sta->fils_pending_assoc_req = tmp;
		sta->fils_pending_assoc_req_len = left;
		sta->fils_pending_assoc_is_reassoc = reassoc;

		DBGPRINT(RT_DEBUG_TRACE,
			   "FILS: Waiting for HLP processing before sending (Re)Association Response frame to \n"
			   MACSTR "\n", MAC2STR(sta->addr));

		eloop_cancel_timeout(fils_hlp_timeout, hapd, sta);
		eloop_register_timeout(0, hapd->conf->fils_hlp_wait_time * 1024,
					   fils_hlp_timeout, hapd, sta);
		return;
	}
#endif /* CONFIG_FILS */

	reply_res = send_assoc_resp(hapd, sta, mgmt->sa, resp, reassoc, pos,
					left);
	if (reply_res != WLAN_STATUS_SUCCESS)
		DBGPRINT(RT_DEBUG_ERROR, "send_assoc_resp fail! fail reason: %d\n", reply_res)

	if (tmp)
		free(tmp);

	/*
	 * Remove the station in case tranmission of a success response fails
	 * (the STA was added associated to the driver) or if the station was
	 * previously added unassociated.
	 */
#if 0
	if (sta && ((reply_res != WLAN_STATUS_SUCCESS &&
			 resp == WLAN_STATUS_SUCCESS) || sta->added_unassoc)) {
		Ap_free_sta(hapd,sta);
		sta->added_unassoc = 0;
	}
#endif
}
