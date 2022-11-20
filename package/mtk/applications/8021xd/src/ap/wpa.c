#include "includes.h"
#include "wpa.h"
#include "ap.h"
#include "os.h"

#include "common/wpa_common.h"
#include "drvcallbak/drv_hook.h"

int rsn_selector_to_bitfield(const u8 *s)
{
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_NONE)
                return WPA_CIPHER_NONE;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_TKIP)
                return WPA_CIPHER_TKIP;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_CCMP)
                return WPA_CIPHER_CCMP;
#ifdef CONFIG_IEEE80211W
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_AES_128_CMAC)
                return WPA_CIPHER_AES_128_CMAC;
#endif /* CONFIG_IEEE80211W */
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_GCMP)
                return WPA_CIPHER_GCMP;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_CCMP_256)
                return WPA_CIPHER_CCMP_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_GCMP_256)
                return WPA_CIPHER_GCMP_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_BIP_GMAC_128)
                return WPA_CIPHER_BIP_GMAC_128;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_BIP_GMAC_256)
                return WPA_CIPHER_BIP_GMAC_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_BIP_CMAC_256)
                return WPA_CIPHER_BIP_CMAC_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED)
                return WPA_CIPHER_GTK_NOT_USED;
        return 0;
}

int rsn_key_mgmt_to_bitfield(const u8 *s)
{
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_UNSPEC_802_1X)
            return WPA_KEY_MGMT_IEEE8021X;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X)
            return WPA_KEY_MGMT_PSK;
#ifdef CONFIG_IEEE80211R
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_802_1X)
            return WPA_KEY_MGMT_FT_IEEE8021X;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_PSK)
            return WPA_KEY_MGMT_FT_PSK;
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SHA256)
            return WPA_KEY_MGMT_IEEE8021X_SHA256;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_PSK_SHA256)
            return WPA_KEY_MGMT_PSK_SHA256;
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_SAE
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_SAE)
            return WPA_KEY_MGMT_SAE;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_SAE)
            return WPA_KEY_MGMT_FT_SAE;
#endif /* CONFIG_SAE */
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SUITE_B)
            return WPA_KEY_MGMT_IEEE8021X_SUITE_B;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192)
            return WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FILS_SHA256)
            return WPA_KEY_MGMT_FILS_SHA256;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FILS_SHA384)
            return WPA_KEY_MGMT_FILS_SHA384;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_FILS_SHA256)
            return WPA_KEY_MGMT_FT_FILS_SHA256;
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_FILS_SHA384)
            return WPA_KEY_MGMT_FT_FILS_SHA384;
#ifdef CONFIG_OWE
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_OWE)
            return WPA_KEY_MGMT_OWE;
#endif /* CONFIG_OWE */
#ifdef CONFIG_DPP
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_DPP)
            return WPA_KEY_MGMT_DPP;
#endif /* CONFIG_DPP */
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_OSEN)
            return WPA_KEY_MGMT_OSEN;
    return 0;
}

enum wpa_alg wpa_cipher_to_alg(int cipher)
{
        switch (cipher) {
        case WPA_CIPHER_CCMP_256:
                return WPA_ALG_CCMP_256;
        case WPA_CIPHER_GCMP_256:
                return WPA_ALG_GCMP_256;
        case WPA_CIPHER_CCMP:
                return WPA_ALG_CCMP;
        case WPA_CIPHER_GCMP:
                return WPA_ALG_GCMP;
        case WPA_CIPHER_TKIP:
                return WPA_ALG_TKIP;
        case WPA_CIPHER_AES_128_CMAC:
                return WPA_ALG_IGTK;
        case WPA_CIPHER_BIP_GMAC_128:
                return WPA_ALG_BIP_GMAC_128;
        case WPA_CIPHER_BIP_GMAC_256:
                return WPA_ALG_BIP_GMAC_256;
        case WPA_CIPHER_BIP_CMAC_256:
                return WPA_ALG_BIP_CMAC_256;
        }
        return WPA_ALG_NONE;
}

u32 sup_wpa_cipher_to_suite(int proto, int cipher)
{
	if (cipher & WPA_CIPHER_CCMP_256)
		return RSN_CIPHER_SUITE_CCMP_256;
	if (cipher & WPA_CIPHER_GCMP_256)
		return RSN_CIPHER_SUITE_GCMP_256;
	if (cipher & WPA_CIPHER_CCMP)
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_CCMP : WPA_CIPHER_SUITE_CCMP);
	if (cipher & WPA_CIPHER_GCMP)
		return RSN_CIPHER_SUITE_GCMP;
	if (cipher & WPA_CIPHER_TKIP)
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_TKIP : WPA_CIPHER_SUITE_TKIP);
	if (cipher & WPA_CIPHER_NONE)
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_NONE : WPA_CIPHER_SUITE_NONE);
	if (cipher & WPA_CIPHER_GTK_NOT_USED)
		return RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED;
	if (cipher & WPA_CIPHER_AES_128_CMAC)
		return RSN_CIPHER_SUITE_AES_128_CMAC;
	if (cipher & WPA_CIPHER_BIP_GMAC_128)
		return RSN_CIPHER_SUITE_BIP_GMAC_128;
	if (cipher & WPA_CIPHER_BIP_GMAC_256)
		return RSN_CIPHER_SUITE_BIP_GMAC_256;
	if (cipher & WPA_CIPHER_BIP_CMAC_256)
		return RSN_CIPHER_SUITE_BIP_CMAC_256;
	return 0;
}

int wpa_cipher_valid_pairwise(int cipher)
{
        return cipher == WPA_CIPHER_CCMP_256 ||
                cipher == WPA_CIPHER_GCMP_256 ||
                cipher == WPA_CIPHER_CCMP ||
                cipher == WPA_CIPHER_GCMP ||
                cipher == WPA_CIPHER_TKIP;
}

int wpa_cipher_valid_group(int cipher)
{
    return wpa_cipher_valid_pairwise(cipher) ||
            cipher == WPA_CIPHER_GTK_NOT_USED;
}

int wpa_pick_pairwise_cipher(int ciphers, int none_allowed)
{
	if (ciphers & WPA_CIPHER_CCMP_256)
		return WPA_CIPHER_CCMP_256;
	if (ciphers & WPA_CIPHER_GCMP_256)
		return WPA_CIPHER_GCMP_256;
	if (ciphers & WPA_CIPHER_CCMP)
		return WPA_CIPHER_CCMP;
	if (ciphers & WPA_CIPHER_GCMP)
		return WPA_CIPHER_GCMP;
	if (ciphers & WPA_CIPHER_TKIP)
		return WPA_CIPHER_TKIP;
	if (none_allowed && (ciphers & WPA_CIPHER_NONE))
		return WPA_CIPHER_NONE;
	return -1;
}

int wpa_validate_wpa_ie(struct apd_data *hapd, struct sta_info *sta,
			const u8 *wpa_ie, size_t wpa_ie_len,
			const u8 *mdie, size_t mdie_len,
			const u8 *owe_dh, size_t owe_dh_len)
{
	struct wpa_ie_data data;
	int ciphers, key_mgmt, version;
	int res = 0;
	u32 selector;
	size_t i;
	const u8 *pmkid = NULL;
	struct sec_info *ap_sec_info = NULL;
	struct sta_sec_info *sta_sec_info = NULL;

	os_memset(&data, 0, sizeof(data));

	if (hapd == NULL || sta == NULL)
		return WPA_NOT_ENABLED;

	if (wpa_ie == NULL || wpa_ie_len < 1)
		return WPA_INVALID_IE;

	ap_sec_info = &hapd->ap_sec_info[sta->ApIdx];
	sta_sec_info = &sta->sta_sec_info;

	if (wpa_ie[0] == WLAN_EID_RSN)
		version = WPA_PROTO_RSN;
	else
		version = WPA_PROTO_WPA;

	if (!(ap_sec_info->wpa & version)) {
		DBGPRINT(RT_DEBUG_TRACE, "Invalid WPA proto (%d) from " MACSTR,
			   version, MAC2STR(sta->addr));
		return WPA_INVALID_PROTO;
	}

	if (version == WPA_PROTO_RSN) {
		res = wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, &data);

		selector = RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
		if (0) {
		}
		else if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192)
			selector = RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192;
		else if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B)
			selector = RSN_AUTH_KEY_MGMT_802_1X_SUITE_B;
#ifdef CONFIG_FILS
#ifdef CONFIG_IEEE80211R_AP
		else if (data.key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA384)
			selector = RSN_AUTH_KEY_MGMT_FT_FILS_SHA384;
		else if (data.key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA256)
			selector = RSN_AUTH_KEY_MGMT_FT_FILS_SHA256;
#endif /* CONFIG_IEEE80211R_AP */
		else if (data.key_mgmt & WPA_KEY_MGMT_FILS_SHA384)
			selector = RSN_AUTH_KEY_MGMT_FILS_SHA384;
		else if (data.key_mgmt & WPA_KEY_MGMT_FILS_SHA256)
			selector = RSN_AUTH_KEY_MGMT_FILS_SHA256;
#endif /* CONFIG_FILS */
#ifdef CONFIG_IEEE80211R_AP
		else if (data.key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X)
			selector = RSN_AUTH_KEY_MGMT_FT_802_1X;
		else if (data.key_mgmt & WPA_KEY_MGMT_FT_PSK)
			selector = RSN_AUTH_KEY_MGMT_FT_PSK;
#endif /* CONFIG_IEEE80211R_AP */
#ifdef CONFIG_IEEE80211W
		else if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256)
			selector = RSN_AUTH_KEY_MGMT_802_1X_SHA256;
		else if (data.key_mgmt & WPA_KEY_MGMT_PSK_SHA256)
			selector = RSN_AUTH_KEY_MGMT_PSK_SHA256;
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_SAE
		else if (data.key_mgmt & WPA_KEY_MGMT_SAE)
			selector = RSN_AUTH_KEY_MGMT_SAE;
		else if (data.key_mgmt & WPA_KEY_MGMT_FT_SAE)
			selector = RSN_AUTH_KEY_MGMT_FT_SAE;
#endif /* CONFIG_SAE */
		else if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X)
			selector = RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
		else if (data.key_mgmt & WPA_KEY_MGMT_PSK)
			selector = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
#ifdef CONFIG_OWE
		else if (data.key_mgmt & WPA_KEY_MGMT_OWE)
			selector = RSN_AUTH_KEY_MGMT_OWE;
#endif /* CONFIG_OWE */
#ifdef CONFIG_DPP
		else if (data.key_mgmt & WPA_KEY_MGMT_DPP)
			selector = RSN_AUTH_KEY_MGMT_DPP;
#endif /* CONFIG_DPP */
		ap_sec_info->dot11RSNAAuthenticationSuiteSelected = selector;

		selector = sup_wpa_cipher_to_suite(WPA_PROTO_RSN,
					       data.pairwise_cipher);
		if (!selector)
			selector = RSN_CIPHER_SUITE_CCMP;
		ap_sec_info->dot11RSNAPairwiseCipherSelected = selector;

		selector = sup_wpa_cipher_to_suite(WPA_PROTO_RSN,
					       data.group_cipher);
		if (!selector)
			selector = RSN_CIPHER_SUITE_CCMP;
		ap_sec_info->dot11RSNAGroupCipherSelected = selector;
	} else {
#if 0
//YF_TODO for WPA1 case
		res = wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, &data);

		selector = WPA_AUTH_KEY_MGMT_UNSPEC_802_1X;
		if (data.key_mgmt & WPA_KEY_MGMT_IEEE8021X)
			selector = WPA_AUTH_KEY_MGMT_UNSPEC_802_1X;
		else if (data.key_mgmt & WPA_KEY_MGMT_PSK)
			selector = WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X;
		ap_sec_info->dot11RSNAAuthenticationSuiteSelected = selector;

		selector = sup_wpa_cipher_to_suite(WPA_PROTO_WPA,
						   data.pairwise_cipher);
		if (!selector)
			selector = RSN_CIPHER_SUITE_TKIP;
		ap_sec_info->dot11RSNAPairwiseCipherSelected = selector;

		selector = sup_wpa_cipher_to_suite(WPA_PROTO_WPA,
						   data.group_cipher);
		if (!selector)
			selector = WPA_CIPHER_SUITE_TKIP;
		ap_sec_info->dot11RSNAGroupCipherSelected = selector;
#endif
	}
	if (res) {
		DBGPRINT(RT_DEBUG_TRACE, "Failed to parse WPA/RSN IE from "
			   MACSTR " (res=%d)", MAC2STR(sta->addr), res);
		//wpa_hexdump(MSG_DEBUG, "WPA/RSN IE", wpa_ie, wpa_ie_len);
		return WPA_INVALID_IE;
	}

	if (data.group_cipher != ap_sec_info->wpa_group) {
		DBGPRINT(RT_DEBUG_TRACE, "Invalid WPA group cipher (0x%x) from "
			   MACSTR, data.group_cipher, MAC2STR(sta->addr));
		return WPA_INVALID_GROUP;
	}

	key_mgmt = data.key_mgmt & ap_sec_info->wpa_key_mgmt;
	if (!key_mgmt) {
		DBGPRINT(RT_DEBUG_TRACE, "Invalid WPA key mgmt (0x%x) from "
			   MACSTR "\n", data.key_mgmt, MAC2STR(sta->addr));
		return WPA_INVALID_AKMP;
	}

	if (0) {
	}
	else if (key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
	else if (key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X_SUITE_B;
#ifdef CONFIG_FILS
#ifdef CONFIG_IEEE80211R_AP
	else if (key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA384)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_FT_FILS_SHA384;
	else if (data.key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA256)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_FT_FILS_SHA256;
#endif /* CONFIG_IEEE80211R_AP */
	else if (key_mgmt & WPA_KEY_MGMT_FILS_SHA384)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_FILS_SHA384;
	else if (key_mgmt & WPA_KEY_MGMT_FILS_SHA256)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_FILS_SHA256;
#endif /* CONFIG_FILS */
#ifdef CONFIG_IEEE80211R_AP
	else if (key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_FT_IEEE8021X;
	else if (key_mgmt & WPA_KEY_MGMT_FT_PSK)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_FT_PSK;
#endif /* CONFIG_IEEE80211R_AP */
#ifdef CONFIG_IEEE80211W
	else if (key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X_SHA256;
	else if (key_mgmt & WPA_KEY_MGMT_PSK_SHA256)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_PSK_SHA256;
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_SAE
	else if (key_mgmt & WPA_KEY_MGMT_SAE)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_SAE;
	else if (key_mgmt & WPA_KEY_MGMT_FT_SAE)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_FT_SAE;
#endif /* CONFIG_SAE */
	else if (key_mgmt & WPA_KEY_MGMT_IEEE8021X)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_IEEE8021X;
#ifdef CONFIG_OWE
	else if (key_mgmt & WPA_KEY_MGMT_OWE)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_OWE;
#endif /* CONFIG_OWE */
#ifdef CONFIG_DPP
	else if (key_mgmt & WPA_KEY_MGMT_DPP)
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_DPP;
#endif /* CONFIG_DPP */
	else
		sta_sec_info->wpa_key_mgmt = WPA_KEY_MGMT_PSK;

	if (version == WPA_PROTO_RSN)
		ciphers = data.pairwise_cipher & ap_sec_info->rsn_pairwise;
	else
		ciphers = data.pairwise_cipher & ap_sec_info->wpa_pairwise;
	if (!ciphers) {
		DBGPRINT(RT_DEBUG_TRACE, "Invalid %s pairwise cipher (0x%x) "
			   "from " MACSTR,
			   version == WPA_PROTO_RSN ? "RSN" : "WPA",
			   data.pairwise_cipher, MAC2STR(sta->addr));
		return WPA_INVALID_PAIRWISE;
	}

	if (ap_sec_info->ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED) {
		if (!(data.capabilities & WPA_CAPABILITY_MFPC)) {
			DBGPRINT(RT_DEBUG_TRACE, "Management frame protection "
				   "required, but client did not enable it\n");
			return WPA_MGMT_FRAME_PROTECTION_VIOLATION;
		}

		if (data.mgmt_group_cipher != ap_sec_info->group_mgmt_cipher)
		{
			DBGPRINT(RT_DEBUG_TRACE, "Unsupported management group "
				   "cipher %d\n", data.mgmt_group_cipher);
			return WPA_INVALID_MGMT_GROUP_CIPHER;
		}
	}

#ifdef CONFIG_SAE
	if (wpa_auth->conf.ieee80211w == MGMT_FRAME_PROTECTION_OPTIONAL &&
	    wpa_key_mgmt_sae(sm->wpa_key_mgmt) &&
	    !(data.capabilities & WPA_CAPABILITY_MFPC)) {
		wpa_printf(MSG_DEBUG,
			   "Management frame protection required with SAE, but client did not enable it");
		return WPA_MGMT_FRAME_PROTECTION_VIOLATION;
	}
#endif /* CONFIG_SAE */

	if (ap_sec_info->ieee80211w == NO_MGMT_FRAME_PROTECTION ||
	    !(data.capabilities & WPA_CAPABILITY_MFPC))
		sta_sec_info->mgmt_frame_prot = 0;
	else
		sta_sec_info->mgmt_frame_prot = 1;

	if (sta_sec_info->mgmt_frame_prot && (ciphers & WPA_CIPHER_TKIP)) {
		    DBGPRINT(RT_DEBUG_TRACE,
			       "Management frame protection cannot use TKIP\n");
		    return WPA_MGMT_FRAME_PROTECTION_VIOLATION;
	}

#ifdef CONFIG_IEEE80211R_AP
	if (wpa_key_mgmt_ft(sm->wpa_key_mgmt)) {
		if (mdie == NULL || mdie_len < MOBILITY_DOMAIN_ID_LEN + 1) {
			wpa_printf(MSG_DEBUG, "RSN: Trying to use FT, but "
				   "MDIE not included");
			return WPA_INVALID_MDIE;
		}
		if (os_memcmp(mdie, wpa_auth->conf.mobility_domain,
			      MOBILITY_DOMAIN_ID_LEN) != 0) {
			wpa_hexdump(MSG_DEBUG, "RSN: Attempted to use unknown "
				    "MDIE", mdie, MOBILITY_DOMAIN_ID_LEN);
			return WPA_INVALID_MDIE;
		}
	} else if (mdie != NULL) {
		wpa_printf(MSG_DEBUG,
			   "RSN: Trying to use non-FT AKM suite, but MDIE included");
		return WPA_INVALID_AKMP;
	}
#endif /* CONFIG_IEEE80211R_AP */

#ifdef CONFIG_OWE
	if (sm->wpa_key_mgmt == WPA_KEY_MGMT_OWE && !owe_dh) {
		wpa_printf(MSG_DEBUG,
			   "OWE: No Diffie-Hellman Parameter element");
		return WPA_INVALID_AKMP;
	}
	if (sm->wpa_key_mgmt != WPA_KEY_MGMT_OWE && owe_dh) {
		wpa_printf(MSG_DEBUG,
			   "OWE: Unexpected Diffie-Hellman Parameter element with non-OWE AKM");
		return WPA_INVALID_AKMP;
	}
#endif /* CONFIG_OWE */

	sta_sec_info->pairwise = wpa_pick_pairwise_cipher(ciphers, 0);
	if (sta_sec_info->pairwise < 0)
		return WPA_INVALID_PAIRWISE;

	/* TODO: clear WPA/WPA2 state if STA changes from one to another */
	if (wpa_ie[0] == WLAN_EID_RSN)
		sta_sec_info->wpa = WPA_VERSION_WPA2;
	else
		sta_sec_info->wpa = WPA_VERSION_WPA;
#if 0
//YF_TODO
	sm->pmksa = NULL;
	for (i = 0; i < data.num_pmkid; i++) {
		wpa_hexdump(MSG_DEBUG, "RSN IE: STA PMKID",
				&data.pmkid[i * PMKID_LEN], PMKID_LEN);
		sm->pmksa = pmksa_cache_auth_get(wpa_auth->pmksa, sm->addr,
						 &data.pmkid[i * PMKID_LEN]);
		if (sm->pmksa) {
			pmkid = sm->pmksa->pmkid;
			break;
		}
	}
	for (i = 0; sm->pmksa == NULL && wpa_auth->conf.okc &&
			 i < data.num_pmkid; i++) {
		struct wpa_auth_okc_iter_data idata;
		idata.pmksa = NULL;
		idata.aa = wpa_auth->addr;
		idata.spa = sm->addr;
		idata.pmkid = &data.pmkid[i * PMKID_LEN];
		wpa_auth_for_each_auth(wpa_auth, wpa_auth_okc_iter, &idata);
		if (idata.pmksa) {
			wpa_auth_vlogger(wpa_auth, sm->addr, LOGGER_DEBUG,
					 "OKC match for PMKID");
			sm->pmksa = pmksa_cache_add_okc(wpa_auth->pmksa,
							idata.pmksa,
							wpa_auth->addr,
							idata.pmkid);
			pmkid = idata.pmkid;
			break;
		}
	}
	if (sm->pmksa && pmkid) {
		struct vlan_description *vlan;

		vlan = sm->pmksa->vlan_desc;
		wpa_auth_vlogger(wpa_auth, sm->addr, LOGGER_DEBUG,
				 "PMKID found from PMKSA cache eap_type=%d vlan=%d%s",
				 sm->pmksa->eap_type_authsrv,
				 vlan ? vlan->untagged : 0,
				 (vlan && vlan->tagged[0]) ? "+" : "");
		os_memcpy(wpa_auth->dot11RSNAPMKIDUsed, pmkid, PMKID_LEN);
	}
#endif

#ifdef CONFIG_SAE
	if (sm->wpa_key_mgmt == WPA_KEY_MGMT_SAE && data.num_pmkid &&
	    !sm->pmksa) {
		wpa_auth_vlogger(wpa_auth, sm->addr, LOGGER_DEBUG,
				 "No PMKSA cache entry found for SAE");
		return WPA_INVALID_PMKID;
	}
#endif /* CONFIG_SAE */

#ifdef CONFIG_DPP
	if (sm->wpa_key_mgmt == WPA_KEY_MGMT_DPP && !sm->pmksa) {
		wpa_auth_vlogger(wpa_auth, sm->addr, LOGGER_DEBUG,
				 "No PMKSA cache entry found for DPP");
		return WPA_INVALID_PMKID;
	}
#endif /* CONFIG_DPP */

	if (sta_sec_info->wpa_ie == NULL || sta_sec_info->wpa_ie_len < wpa_ie_len) {
		free(sta_sec_info->wpa_ie);
		sta_sec_info->wpa_ie = malloc(wpa_ie_len);
		if (sta_sec_info->wpa_ie == NULL)
			return WPA_ALLOC_FAIL;
	}
	memcpy(sta_sec_info->wpa_ie, wpa_ie, wpa_ie_len);
	sta_sec_info->wpa_ie_len = wpa_ie_len;

	return WPA_IE_OK;
}

int wpa_parse_wpa_ie_rsn(const u8 *rsn_ie, size_t rsn_ie_len,
                         struct wpa_ie_data *data)
{
    const u8 *pos;
    int left;
    int i, count;

    memset(data, 0, sizeof(*data));
    data->proto = WPA_PROTO_RSN;
    data->pairwise_cipher = WPA_CIPHER_CCMP;
    data->group_cipher = WPA_CIPHER_CCMP;
    data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
    data->capabilities = 0;
    data->pmkid = NULL;
    data->num_pmkid = 0;
#ifdef CONFIG_IEEE80211W
    data->mgmt_group_cipher = WPA_CIPHER_AES_128_CMAC;
#else /* CONFIG_IEEE80211W */
    data->mgmt_group_cipher = 0;
#endif /* CONFIG_IEEE80211W */

    if (rsn_ie_len == 0) {
            /* No RSN IE - fail silently */
            return -1;
    }

    if (rsn_ie_len < sizeof(struct rsn_ie_hdr)) {
            DBGPRINT(RT_DEBUG_TRACE, "%s: ie len too short %lu",
                       __func__, (unsigned long) rsn_ie_len);
            return -1;
    }

	if (rsn_ie_len >= 6 && rsn_ie[1] >= 4 &&
		rsn_ie[1] == rsn_ie_len - 2 &&
		WPA_GET_BE32(&rsn_ie[2]) == OSEN_IE_VENDOR_TYPE) {
			pos = rsn_ie + 6;
			left = rsn_ie_len - 6;

			data->proto = WPA_PROTO_OSEN;
	} else {
			const struct rsn_ie_hdr *hdr;

			hdr = (const struct rsn_ie_hdr *) rsn_ie;

			if (hdr->elem_id != WLAN_EID_RSN ||
				hdr->len != rsn_ie_len - 2 ||
				WPA_GET_LE16(hdr->version) != RSN_VERSION) {
					DBGPRINT(RT_DEBUG_TRACE, "%s: malformed ie or unknown version",
							   __func__);
					return -2;
			}

			pos = (const u8 *) (hdr + 1);
			left = rsn_ie_len - sizeof(*hdr);
	}

	if (left >= RSN_SELECTOR_LEN) {
			data->group_cipher = rsn_selector_to_bitfield(pos);
			if (!wpa_cipher_valid_group(data->group_cipher)) {
					DBGPRINT(RT_DEBUG_TRACE,
							   "%s: invalid group cipher 0x%x (%08x)",
							   __func__, data->group_cipher,
							   WPA_GET_BE32(pos));
					return -1;
			}
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
	} else if (left > 0) {
			DBGPRINT(RT_DEBUG_TRACE, "%s: ie length mismatch, %u too much",
					   __func__, left);
			return -3;
	}

    if (left >= 2) {
            data->pairwise_cipher = 0;
            count = WPA_GET_LE16(pos);
            pos += 2;
            left -= 2;
            if (count == 0 || count > left / RSN_SELECTOR_LEN) {
                   DBGPRINT(RT_DEBUG_TRACE, "%s: ie count botch (pairwise), "
                               "count %u left %u", __func__, count, left);
                    return -4;
            }
            for (i = 0; i < count; i++) {
                    data->pairwise_cipher |= rsn_selector_to_bitfield(pos);
                    pos += RSN_SELECTOR_LEN;
                    left -= RSN_SELECTOR_LEN;
            }
#ifdef CONFIG_IEEE80211W
            if (data->pairwise_cipher & WPA_CIPHER_AES_128_CMAC) {
                    DBGPRINT(RT_DEBUG_TRACE, "%s: AES-128-CMAC used as "
                               "pairwise cipher", __func__);
                    return -1;
            }
#endif /* CONFIG_IEEE80211W */
    } else if (left == 1) {
            DBGPRINT(RT_DEBUG_TRACE, "%s: ie too short (for key mgmt)",
                       __func__);
            return -5;
    }

	if (left >= 2) {
			data->key_mgmt = 0;
			count = WPA_GET_LE16(pos);
			pos += 2;
			left -= 2;
			if (count == 0 || count > left / RSN_SELECTOR_LEN) {
					DBGPRINT(RT_DEBUG_TRACE, "%s: ie count botch (key mgmt), "
							   "count %u left %u", __func__, count, left);
					return -6;
			}
			for (i = 0; i < count; i++) {
					data->key_mgmt |= rsn_key_mgmt_to_bitfield(pos);
					pos += RSN_SELECTOR_LEN;
					left -= RSN_SELECTOR_LEN;
			}
	} else if (left == 1) {
			DBGPRINT(RT_DEBUG_TRACE, "%s: ie too short (for capabilities)",
					   __func__);
			return -7;
	}

	if (left >= 2) {
			data->capabilities = WPA_GET_LE16(pos);
			pos += 2;
			left -= 2;
	}

    if (left >= 2) {
            u16 num_pmkid = WPA_GET_LE16(pos);
            pos += 2;
            left -= 2;
            if (num_pmkid > (unsigned int) left / PMKID_LEN) {
                    DBGPRINT(RT_DEBUG_TRACE,"%s: PMKID underflow "
                               "(num_pmkid=%u left=%d)",
                               __func__, num_pmkid, left);
                    data->num_pmkid = 0;
                    return -9;
            } else {
                    data->num_pmkid = num_pmkid;
                    data->pmkid = pos;
                    pos += data->num_pmkid * PMKID_LEN;
                    left -= data->num_pmkid * PMKID_LEN;
            }
    }

#ifdef CONFIG_IEEE80211W
    if (left >= 4) {
            data->mgmt_group_cipher = rsn_selector_to_bitfield(pos);
            if (!wpa_cipher_valid_mgmt_group(data->mgmt_group_cipher)) {
                    DBGPRINT(RT_DEBUG_TRACE,
                               "%s: Unsupported management group cipher 0x%x (%08x)",
                               __func__, data->mgmt_group_cipher,
                               WPA_GET_BE32(pos));
                    return -10;
            }
            pos += RSN_SELECTOR_LEN;
            left -= RSN_SELECTOR_LEN;
    }
#endif /* CONFIG_IEEE80211W */

    if (left > 0) {
            hex_dump("wpa_parse_wpa_ie_rsn: ignore trailing bytes",
                        pos, left);
    }

    return 0;
}

int wpa_cipher_key_len(int cipher)
{
        switch (cipher) {
        case WPA_CIPHER_CCMP_256:
        case WPA_CIPHER_GCMP_256:
        case WPA_CIPHER_BIP_GMAC_256:
        case WPA_CIPHER_BIP_CMAC_256:
                return 32;
        case WPA_CIPHER_CCMP:
        case WPA_CIPHER_GCMP:
        case WPA_CIPHER_AES_128_CMAC:
        case WPA_CIPHER_BIP_GMAC_128:
                return 16;
        case WPA_CIPHER_TKIP:
                return 32;
        }

        return 0;
}

unsigned int wpa_kek_len(int akmp, size_t pmk_len)
{
        switch (akmp) {
        case WPA_KEY_MGMT_FILS_SHA384:
        case WPA_KEY_MGMT_FT_FILS_SHA384:
                return 64;
        case WPA_KEY_MGMT_IEEE8021X_SUITE_B_192:
        case WPA_KEY_MGMT_FILS_SHA256:
        case WPA_KEY_MGMT_FT_FILS_SHA256:
                return 32;
        case WPA_KEY_MGMT_DPP:
                return pmk_len <= 32 ? 16 : 32;
        case WPA_KEY_MGMT_OWE:
                return pmk_len <= 32 ? 16 : 32;
        default:
                return 16;
        }
}

u16 wpa_res_to_status_code(int res)
{
	if (res == WPA_INVALID_GROUP)
		return WLAN_STATUS_GROUP_CIPHER_NOT_VALID;
	if (res == WPA_INVALID_PAIRWISE)
		return WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID;
	if (res == WPA_INVALID_AKMP)
		return WLAN_STATUS_AKMP_NOT_VALID;
	if (res == WPA_ALLOC_FAIL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
#ifdef CONFIG_IEEE80211W
	if (res == WPA_MGMT_FRAME_PROTECTION_VIOLATION)
		return WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION;
	if (res == WPA_INVALID_MGMT_GROUP_CIPHER)
		return WLAN_STATUS_CIPHER_REJECTED_PER_POLICY;
#endif /* CONFIG_IEEE80211W */
	if (res == WPA_INVALID_MDIE)
		return WLAN_STATUS_INVALID_MDIE;
	if (res == WPA_INVALID_PMKID)
		return WLAN_STATUS_INVALID_PMKID;
	if (res != WPA_IE_OK)
		return WLAN_STATUS_INVALID_IE;
	return WLAN_STATUS_SUCCESS;
}

u8 * wpa_add_kde(u8 *pos, u32 kde, const u8 *data, size_t data_len,
		 const u8 *data2, size_t data2_len)
{
	*pos++ = WLAN_EID_VENDOR_SPECIFIC;
	*pos++ = RSN_SELECTOR_LEN + data_len + data2_len;
	RSN_SELECTOR_PUT(pos, kde);
	pos += RSN_SELECTOR_LEN;
	memcpy(pos, data, data_len);
	pos += data_len;
	if (data2) {
		memcpy(pos, data2, data2_len);
		pos += data2_len;
	}
	return pos;
}

u8 * ieee80211w_kde_add(struct sta_info *sta, u8 *pos)
{
    struct wpa_igtk_kde igtk;
    u8 rsc[WPA_KEY_RSC_LEN];
	struct apd_data *rtapd = sta->priv;
	struct sec_info *ap_sec_info = NULL;
    size_t len = 0;

	ap_sec_info = &rtapd->ap_sec_info[sta->ApIdx];
	len = wpa_cipher_key_len(ap_sec_info->group_mgmt_cipher);

    if (!sta->sta_sec_info.mgmt_frame_prot)
            return pos;

    igtk.keyid[0] = ap_sec_info->IGN;
    igtk.keyid[1] = 0;

    if (hostapd_get_seqnum(sta, sta->addr, ap_sec_info->IGN, rsc) < 0)
    	memset(igtk.pn, 0, sizeof(igtk.pn));
    else
        memcpy(igtk.pn, rsc, sizeof(igtk.pn));

    memcpy(igtk.igtk, ap_sec_info->IGTK, len);
    pos = wpa_add_kde(pos, RSN_KEY_DATA_IGTK,
                      (const u8 *) &igtk, WPA_IGTK_KDE_PREFIX_LEN + len,
                      NULL, 0);
    return pos;
}

int wpa_insert_pmkid(u8 *ies, size_t *ies_len, const u8 *pmkid)
{
    u8 *start, *end, *rpos, *rend;
    int added = 0;

    start = ies;
    end = ies + *ies_len;

    while (start < end) {
            if (*start == WLAN_EID_RSN)
                    break;
            start += 2 + start[1];
    }
    if (start >= end) {
            DBGPRINT(RT_DEBUG_ERROR, "FT: Could not find RSN IE in "
                       "IEs data\n");
            return -1;
    }
    hex_dump("FT: RSN IE before modification",
                start, 2 + start[1]);

    /* Find start of PMKID-Count */
    rpos = start + 2;
    rend = rpos + start[1];

    /* Skip Version and Group Data Cipher Suite */
    rpos += 2 + 4;
    /* Skip Pairwise Cipher Suite Count and List */
    rpos += 2 + WPA_GET_LE16(rpos) * RSN_SELECTOR_LEN;
    /* Skip AKM Suite Count and List */
    rpos += 2 + WPA_GET_LE16(rpos) * RSN_SELECTOR_LEN;

    if (rpos == rend) {
            /* Add RSN Capabilities */
            memmove(rpos + 2, rpos, end - rpos);
            *rpos++ = 0;
            *rpos++ = 0;
            added += 2;
            start[1] += 2;
            rend = rpos;
    } else {
            /* Skip RSN Capabilities */
            rpos += 2;
            if (rpos > rend) {
                    DBGPRINT(RT_DEBUG_ERROR, "Could not parse RSN IE in "
                               "IEs data");
                    return -1;
            }
    }

	if (rpos == rend) {
			/* No PMKID-Count field included; add it */
			memmove(rpos + 2 + PMKID_LEN, rpos, end + added - rpos);
			WPA_PUT_LE16(rpos, 1);
			rpos += 2;
			memcpy(rpos, pmkid, PMKID_LEN);
			added += 2 + PMKID_LEN;
			start[1] += 2 + PMKID_LEN;
	} else {
			u16 num_pmkid;

			if (rend - rpos < 2)
					return -1;
			num_pmkid = WPA_GET_LE16(rpos);
			/* PMKID-Count was included; use it */
			if (num_pmkid != 0) {
					u8 *after;

					if (num_pmkid * PMKID_LEN > rend - rpos - 2)
							return -1;
					/*
					 * PMKID may have been included in RSN IE in
					 * (Re)Association Request frame, so remove the old
					 * PMKID(s) first before adding the new one.
					 */
					 DBGPRINT(RT_DEBUG_TRACE,
							   "Remove %u old PMKID(s) from RSN IE\n",
							   num_pmkid);
					after = rpos + 2 + num_pmkid * PMKID_LEN;
					memmove(rpos + 2, after, rend - after);
					start[1] -= num_pmkid * PMKID_LEN;
					added -= num_pmkid * PMKID_LEN;
			}
			WPA_PUT_LE16(rpos, 1);
			rpos += 2;
			memmove(rpos + PMKID_LEN, rpos, end + added - rpos);
			memcpy(rpos, pmkid, PMKID_LEN);
			added += PMKID_LEN;
			start[1] += PMKID_LEN;
	}

	hex_dump("RSN IE after modification "
				"(PMKID inserted)", start, 2 + start[1]);

	*ies_len += added;

	return 0;
}

const u8 * wpa_auth_get_wpa_ie(struct apd_data *hapd, u8 ApIdx, size_t *len)
{
	struct sec_info *ap_sec_info = NULL;
	ap_sec_info = &hapd->ap_sec_info[ApIdx];

    *len = ap_sec_info->wpa_ie_len;
    return ap_sec_info->wpa_ie;
}


