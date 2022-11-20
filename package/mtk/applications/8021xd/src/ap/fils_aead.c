#include "includes.h"
#include "fils.h"

#include "common.h"
#include "sta_info.h"
#include "rtdot1x.h"
#include "rtmp_type.h"
#include "eapol_sm.h"
#include "ieee802_1x.h"
#include "utils/wpabuf.h"
#include "crypto/aes.h"
#include "crypto/aes_siv.h"

#include "common/ieee802_11_common.h"
#include "common/wpa_common.h"
#include "drvcallbak/drv_hook.h"
#include "wpa.h"

static struct wpabuf * fils_prepare_plainbuf(struct sta_info *sta,
					     const struct wpabuf *hlp)
{
	struct wpabuf *plain;
	u8 *len, *tmp, *tmp2;
	u8 hdr[2];
	u8 *gtk;
	size_t gtk_len;
	struct apd_data *hapd = NULL;
	struct sec_info *ap_sec_info = NULL;

	plain = wpabuf_alloc(1000);
	if (!plain)
		return NULL;

	hapd = sta->priv;
	ap_sec_info = &hapd->ap_sec_info[sta->ApIdx];

	/* TODO: FILS Public Key */

	/* FILS Key Confirmation */
	wpabuf_put_u8(plain, WLAN_EID_EXTENSION); /* Element ID */
	wpabuf_put_u8(plain, 1 + sta->fils_key_auth_len); /* Length */
	/* Element ID Extension */
	wpabuf_put_u8(plain, WLAN_EID_EXT_FILS_KEY_CONFIRM);
	wpabuf_put_data(plain, sta->fils_key_auth_ap, sta->fils_key_auth_len);

	/* FILS HLP Container */
	if (hlp)
		wpabuf_put_buf(plain, hlp);

	/* TODO: FILS IP Address Assignment */

	/* Key Delivery */
	wpabuf_put_u8(plain, WLAN_EID_EXTENSION); /* Element ID */
	len = wpabuf_put(plain, 1);
	wpabuf_put_u8(plain, WLAN_EID_EXT_KEY_DELIVERY);
	hostapd_get_seqnum(sta, sta->addr, ap_sec_info->GN,
			    wpabuf_put(plain, WPA_KEY_RSC_LEN));

	/* GTK KDE */
	gtk = ap_sec_info->GTK;
	gtk_len = ap_sec_info->GTK_len;
	hdr[0] = ap_sec_info->GN & 0x03;
	hdr[1] = 0;
	tmp = wpabuf_put(plain, 0);
	tmp2 = wpa_add_kde(tmp, RSN_KEY_DATA_GROUPKEY, hdr, 2,
			   gtk, gtk_len);
	wpabuf_put(plain, tmp2 - tmp);

	/* IGTK KDE */
	tmp = wpabuf_put(plain, 0);
	tmp2 = ieee80211w_kde_add(sta, tmp);
	wpabuf_put(plain, tmp2 - tmp);
	*len = (u8 *) wpabuf_put(plain, 0) - len - 1;
	return plain;
}

int wpa_fils_validate_key_confirm(struct sta_info *sta, const u8 *ies,
				  size_t ies_len)
{
	struct ieee802_11_elems elems;

	memset((void *)&elems, 0, sizeof(struct ieee802_11_elems));
	if (ieee802_11_parse_elems(ies, ies_len, &elems, 1) == ParseFailed) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: Failed to parse decrypted elements\n");
		return -1;
	}

	if (!elems.fils_session) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: No FILS Session element\n");
		return -1;
	}

	if (!elems.fils_key_confirm) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: No FILS Key Confirm element\n");
		return -1;
	}

	if (elems.fils_key_confirm_len != sta->fils_key_auth_len) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: Unexpected Key-Auth length %d (expected %d)\n",
			   elems.fils_key_confirm_len,
			   (int) sta->fils_key_auth_len);
		return -1;
	}

	if (memcmp(elems.fils_key_confirm, sta->fils_key_auth_sta,
			  sta->fils_key_auth_len) != 0) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: Key-Auth mismatch\n");
		hex_dump("FILS: Received Key-Auth",
				elems.fils_key_confirm, elems.fils_key_confirm_len);
		hex_dump("FILS: Expected Key-Auth",
				sta->fils_key_auth_sta, sta->fils_key_auth_len);
		return -1;
	}

	hex_dump("FILS: Received Key-Auth",
			elems.fils_key_confirm, elems.fils_key_confirm_len);
	hex_dump("FILS: Expected Key-Auth",
			sta->fils_key_auth_sta, sta->fils_key_auth_len);

	return 0;

}

const u8 * wpa_fils_validate_fils_session(struct sta_info *sta,
					  const u8 *ies, size_t ies_len,
					  const u8 *fils_session)
{
	const u8 *ie, *end;
	const u8 *session = NULL;

	if (!wpa_key_mgmt_fils(sta->sta_sec_info.wpa_key_mgmt)) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: Not a FILS AKM - reject association");
		return NULL;
	}

	if (!fils_session) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: %s: Could not find FILS Session element in STA entry - reject",
			   __func__);
		return NULL;
	}

	/* Verify Session element */
	ie = ies;
	end = ((const u8 *) ie) + ies_len;
	while (ie + 1 < end) {
		if (ie + 2 + ie[1] > end)
			break;
		if (ie[0] == WLAN_EID_EXTENSION &&
		    ie[1] >= 1 + FILS_SESSION_LEN &&
		    ie[2] == WLAN_EID_EXT_FILS_SESSION) {
			session = ie;
			break;
		}
		ie += 2 + ie[1];
	}

	if (!session) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: %s: Could not find FILS Session element in Assoc Req - reject",
			   __func__);
		return NULL;
	}

	if (memcmp(fils_session, session + 3, FILS_SESSION_LEN) != 0) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: Session mismatch");
		hex_dump("FILS: Expected FILS Session",
			    fils_session, FILS_SESSION_LEN);
		hex_dump("FILS: Received FILS Session",
			    session + 3, FILS_SESSION_LEN);
		return NULL;
	}
	return session;
}

int fils_decrypt_assoc(struct sta_info *sta, const struct ieee80211_mgmt *mgmt, size_t frame_len,
		       u8 *pos, size_t left)
{
	u16 fc, stype;
	const u8 *end, *ie_start, *ie, *session, *crypt;
	const u8 *aad[5];
	size_t aad_len[5];
	const u8 *fils_session;

	if (!sta || !sta->PTK_valid) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: No KEK to decrypt Assocication Request frame");
		return -1;
	}

	if (!wpa_key_mgmt_fils(sta->sta_sec_info.wpa_key_mgmt)) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: Not a FILS AKM - reject association");
		return -1;
	}

	fils_session = sta->fils_session;

	end = ((const u8 *) mgmt) + frame_len;
	fc = le_to_host16(mgmt->frame_control);
	stype = WLAN_FC_GET_STYPE(fc);
	if (stype == WLAN_FC_STYPE_REASSOC_REQ)
		ie_start = mgmt->u.reassoc_req.variable;
	else
		ie_start = mgmt->u.assoc_req.variable;
	ie = ie_start;

	/*
	 * Find FILS Session element which is the last unencrypted element in
	 * the frame.
	 */
	session = wpa_fils_validate_fils_session(sta, ie, end - ie,
						 fils_session);
	if (!session) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: Session validation failed\n");
		return -1;
	}

	crypt = session + 2 + session[1];

	if (end - crypt < AES_BLOCK_SIZE) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: Too short frame to include AES-SIV data\n");
		return -1;
	}

	/* AES-SIV AAD vectors */

	/* The STA's MAC address */
	aad[0] = mgmt->sa;
	aad_len[0] = ETH_ALEN;
	/* The AP's BSSID */
	aad[1] = mgmt->da;
	aad_len[1] = ETH_ALEN;
	/* The STA's nonce */
	aad[2] = sta->fils_snonce;
	aad_len[2] = FILS_NONCE_LEN;
	/* The AP's nonce */
	aad[3] = sta->fils_anonce;
	aad_len[3] = FILS_NONCE_LEN;
	/*
	 * The (Re)Association Request frame from the Capability Information
	 * field to the FILS Session element (both inclusive).
	 */
	aad[4] = (const u8 *) &mgmt->u.assoc_req.capab_info;
	aad_len[4] = crypt - aad[4];

	if (aes_siv_decrypt(sta->PTK.kek, sta->PTK.kek_len, crypt, end - crypt,
				5, aad, aad_len, pos + (crypt - ie_start)) < 0) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: Invalid AES-SIV data in the frame\n");
		return -1;
	}

	//hex_dump("FILS: Decrypted Association Request elements",
	//		pos, left - AES_BLOCK_SIZE);


	if (wpa_fils_validate_key_confirm(sta, pos, left - AES_BLOCK_SIZE) < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: Key Confirm validation failed\n");
		return -1;
	}

	return left - AES_BLOCK_SIZE;
}

int fils_encrypt_assoc(struct sta_info *sta, u8 *buf,
		       size_t current_len, size_t max_len,
		       const struct wpabuf *hlp)
{
	u8 *end = buf + max_len;
	u8 *pos = buf + current_len;
	struct ieee80211_mgmt *mgmt;
	struct wpabuf *plain;
	const u8 *aad[5];
	size_t aad_len[5];

	if (!sta || !sta->PTK_valid)
		return -1;

	//hex_dump("FILS: Association Response frame before FILS processing",
	//	    buf, current_len);

	mgmt = (struct ieee80211_mgmt *) buf;

	/* AES-SIV AAD vectors */

	/* The AP's BSSID */
	aad[0] = mgmt->sa;
	aad_len[0] = ETH_ALEN;
	/* The STA's MAC address */
	aad[1] = mgmt->da;
	aad_len[1] = ETH_ALEN;
	/* The AP's nonce */
	aad[2] = sta->fils_anonce;
	aad_len[2] = FILS_NONCE_LEN;
	/* The STA's nonce */
	aad[3] = sta->fils_snonce;
	aad_len[3] = FILS_NONCE_LEN;
	/*
	 * The (Re)Association Response frame from the Capability Information
	 * field (the same offset in both Association and Reassociation
	 * Response frames) to the FILS Session element (both inclusive).
	 */
	aad[4] = (const u8 *) &mgmt->u.assoc_resp.capab_info;
	aad_len[4] = pos - aad[4];


	/* The following elements will be encrypted with AES-SIV */
	plain = fils_prepare_plainbuf(sta, hlp);
	if (!plain) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: Plain buffer prep failed");
		return -1;
	}

	if (pos + wpabuf_len(plain) + AES_BLOCK_SIZE > end) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: Not enough room for FILS elements");
		wpabuf_free(plain);
		return -1;
	}

	if (aes_siv_encrypt(sta->PTK.kek, sta->PTK.kek_len,
				wpabuf_head(plain), wpabuf_len(plain),
				5, aad, aad_len, pos) < 0) {
		wpabuf_free(plain);
		return -1;
	}

	//hex_dump("FILS: Encrypted Association Response elements",
	//		pos, AES_BLOCK_SIZE + wpabuf_len(plain));
	current_len += wpabuf_len(plain) + AES_BLOCK_SIZE;
	wpabuf_free(plain);

	sta->fils_completed = 1;

	return current_len;

}

int wpa_aead_decrypt(struct sta_info *sta, struct wpa_ptk *ptk,
                            u8 *buf, size_t buf_len, u16 *_key_data_len)
{
    struct ieee802_1x_hdr *hdr = NULL;
    struct wpa_eapol_key *key = NULL;
    u8 *pos;
    u16 key_data_len;
    u8 *tmp;
    const u8 *aad[1];
    size_t aad_len[1];

    hdr = (struct ieee802_1x_hdr *) buf;
	key = (struct wpa_eapol_key *) (hdr + 1);
    pos = (u8 *) (key + 1);
   	key_data_len = WPA_GET_BE16(pos);

    if (key_data_len < AES_BLOCK_SIZE ||
        key_data_len > buf_len - sizeof(*hdr) - sizeof(*key) - 2) {
            DBGPRINT(RT_DEBUG_ERROR, "STA: " MACSTR " No room for AES-SIV data in the frame\n",
				MAC2STR(sta->addr));
            return -1;
    }
    pos += 2; /* Pointing at the Encrypted Key Data field */

    tmp = malloc(key_data_len);
    if (!tmp)
            return -1;

	/* AES-SIV AAD from EAPOL protocol version field (inclusive) to
	 * to Key Data (exclusive). */
	aad[0] = buf;
	aad_len[0] = pos - buf;

	if (aes_siv_decrypt(ptk->kek, ptk->kek_len, pos, key_data_len,
						1, aad, aad_len, tmp) < 0) {
			 DBGPRINT(RT_DEBUG_ERROR,
			 	"STA: " MACSTR " Invalid AES-SIV data in the frame\n",
			 	MAC2STR(sta->addr));
			bin_clear_free(tmp, key_data_len);
			return -1;
	}

	/* AEAD decryption and validation completed successfully */
	key_data_len -= AES_BLOCK_SIZE;
	//hex_dump("WPA: Decrypted Key Data", tmp, key_data_len);

	/* Replace Key Data field with the decrypted version */
	memcpy(pos, tmp, key_data_len);
	pos -= 2; /* Key Data Length field */
	WPA_PUT_BE16(pos, key_data_len);
	bin_clear_free(tmp, key_data_len);
	if (_key_data_len)
			*_key_data_len = key_data_len;
	return 0;
}

int wpa_aead_encrypt(struct sta_info *sta, struct wpa_ptk *ptk,
                            u8 *msg, size_t msg_len, u16 *_key_data_len)
{
	/* AEAD cipher - Key MIC field not used */
	struct ieee802_1x_hdr *s_hdr, *hdr;
	struct wpa_eapol_key *s_key, *key;
	u8 *buf, *s_key_data, *key_data;
	size_t buf_len = msg_len + AES_BLOCK_SIZE;
	size_t key_data_len;
	u16 eapol_len;
	const u8 *aad[1];
	size_t aad_len[1];
	int ret = -1;

	if (!ptk || !ptk->kek_len)
			return ret;

	key_data_len = msg_len - sizeof(struct ieee802_1x_hdr) -
			sizeof(struct wpa_eapol_key) - 2;

	buf = malloc(buf_len);
	if (!buf)
			return ret;

	memcpy(buf, msg, msg_len);
	hdr = (struct ieee802_1x_hdr *) buf;
	key = (struct wpa_eapol_key *) (hdr + 1);
	key_data = ((u8 *) (key + 1)) + 2;

	/* Update EAPOL header to include AES-SIV overhead */
	eapol_len = be_to_host16(hdr->length);
	eapol_len += AES_BLOCK_SIZE;
	hdr->length = host_to_be16(eapol_len);

	/* Update Key Data Length field to include AES-SIV overhead */
	WPA_PUT_BE16((u8 *) (key + 1), AES_BLOCK_SIZE + key_data_len);

	//hex_dump("WPA: EAPOL MESSAGE", msg, msg_len);

	s_hdr = (struct ieee802_1x_hdr *) msg;
	s_key = (struct wpa_eapol_key *) (s_hdr + 1);
	s_key_data = ((u8 *) (s_key + 1)) + 2;

	/* Update EAPOL header to include AES-SIV overhead */
	eapol_len = be_to_host16(s_hdr->length);
	eapol_len += AES_BLOCK_SIZE;
	s_hdr->length = host_to_be16(eapol_len);

	/* Update Key Data Length field to include AES-SIV overhead */
	WPA_PUT_BE16((u8 *) (s_key + 1), AES_BLOCK_SIZE + key_data_len);

	//hex_dump("WPA: Plaintext Key Data", s_key_data, key_data_len);

	 /* AES-SIV AAD from EAPOL protocol version field (inclusive) to
	  * to Key Data (exclusive). */
	aad[0] = buf;
	aad_len[0] = key_data - buf;
	if (aes_siv_encrypt(ptk->kek, ptk->kek_len,
						s_key_data, key_data_len,
						1, aad, aad_len, key_data) < 0) {
			free(buf);
			return ret;
	}

	//hex_dump("WPA: Encrypted Key Data from SIV",
	//			key_data, AES_BLOCK_SIZE + key_data_len);

	memcpy(s_key_data, key_data, (AES_BLOCK_SIZE + key_data_len));
	*_key_data_len = buf_len;

	free(buf);
	return 0;
}

