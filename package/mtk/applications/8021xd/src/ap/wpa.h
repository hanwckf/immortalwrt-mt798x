#ifndef WPA_H
#define WPA_H

#include "rtdot1x.h"

#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)
#define WPA_CIPHER_AES_128_CMAC BIT(5)
#define WPA_CIPHER_GCMP BIT(6)
#define WPA_CIPHER_SMS4 BIT(7)
#define WPA_CIPHER_GCMP_256 BIT(8)
#define WPA_CIPHER_CCMP_256 BIT(9)
#define WPA_CIPHER_BIP_GMAC_128 BIT(11)
#define WPA_CIPHER_BIP_GMAC_256 BIT(12)
#define WPA_CIPHER_BIP_CMAC_256 BIT(13)
#define WPA_CIPHER_GTK_NOT_USED BIT(14)

#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
#define WPA_KEY_MGMT_NONE BIT(2)
#define WPA_KEY_MGMT_IEEE8021X_NO_WPA BIT(3)
#define WPA_KEY_MGMT_WPA_NONE BIT(4)
#define WPA_KEY_MGMT_FT_IEEE8021X BIT(5)
#define WPA_KEY_MGMT_FT_PSK BIT(6)
#define WPA_KEY_MGMT_IEEE8021X_SHA256 BIT(7)
#define WPA_KEY_MGMT_PSK_SHA256 BIT(8)
#define WPA_KEY_MGMT_WPS BIT(9)
#define WPA_KEY_MGMT_SAE BIT(10)
#define WPA_KEY_MGMT_FT_SAE BIT(11)
#define WPA_KEY_MGMT_WAPI_PSK BIT(12)
#define WPA_KEY_MGMT_WAPI_CERT BIT(13)
#define WPA_KEY_MGMT_CCKM BIT(14)
#define WPA_KEY_MGMT_OSEN BIT(15)
#define WPA_KEY_MGMT_IEEE8021X_SUITE_B BIT(16)
#define WPA_KEY_MGMT_IEEE8021X_SUITE_B_192 BIT(17)
#define WPA_KEY_MGMT_FILS_SHA256 BIT(18)
#define WPA_KEY_MGMT_FILS_SHA384 BIT(19)
#define WPA_KEY_MGMT_FT_FILS_SHA256 BIT(20)
#define WPA_KEY_MGMT_FT_FILS_SHA384 BIT(21)
#define WPA_KEY_MGMT_OWE BIT(22)
#define WPA_KEY_MGMT_DPP BIT(23)

#define WPA_PROTO_WPA BIT(0)
#define WPA_PROTO_RSN BIT(1)
#define WPA_PROTO_WAPI BIT(2)
#define WPA_PROTO_OSEN BIT(3)

struct sta_info;
struct apd_data; 

enum wpa_alg {
        WPA_ALG_NONE,
        WPA_ALG_WEP,
        WPA_ALG_TKIP,
        WPA_ALG_CCMP,
        WPA_ALG_IGTK,
        WPA_ALG_PMK,
        WPA_ALG_GCMP,
        WPA_ALG_SMS4,
        WPA_ALG_KRK,
        WPA_ALG_GCMP_256,
        WPA_ALG_CCMP_256,
        WPA_ALG_BIP_GMAC_128,
        WPA_ALG_BIP_GMAC_256,
        WPA_ALG_BIP_CMAC_256
};

static inline int wpa_key_mgmt_fils(int akm)
{
        return !!(akm & (WPA_KEY_MGMT_FILS_SHA256 |
                         WPA_KEY_MGMT_FILS_SHA384 |
                         WPA_KEY_MGMT_FT_FILS_SHA256 |
                         WPA_KEY_MGMT_FT_FILS_SHA384));
}

static inline int wpa_key_mgmt_sha256(int akm)
{
        return !!(akm & (WPA_KEY_MGMT_PSK_SHA256 |
                         WPA_KEY_MGMT_IEEE8021X_SHA256 |
                         WPA_KEY_MGMT_SAE |
                         WPA_KEY_MGMT_FT_SAE |
                         WPA_KEY_MGMT_OSEN |
                         WPA_KEY_MGMT_IEEE8021X_SUITE_B |
                         WPA_KEY_MGMT_FILS_SHA256 |
                         WPA_KEY_MGMT_FT_FILS_SHA256));
}

static inline int wpa_key_mgmt_sha384(int akm)
{
        return !!(akm & (WPA_KEY_MGMT_IEEE8021X_SUITE_B_192 |
                         WPA_KEY_MGMT_FILS_SHA384 |
                         WPA_KEY_MGMT_FT_FILS_SHA384));
}

int rsn_selector_to_bitfield(const u8 *s);
int rsn_key_mgmt_to_bitfield(const u8 *s);

enum wpa_alg wpa_cipher_to_alg(int cipher);
u32 sup_wpa_cipher_to_suite(int proto, int cipher);
int wpa_cipher_valid_pairwise(int cipher);
int wpa_cipher_valid_group(int cipher);
int wpa_pick_pairwise_cipher(int ciphers, int none_allowed);
int wpa_cipher_key_len(int cipher);
unsigned int wpa_kek_len(int akmp, size_t pmk_len);
u16 wpa_res_to_status_code(int res);

int wpa_validate_wpa_ie(struct apd_data *hapd, struct sta_info *sta,
			const u8 *wpa_ie, size_t wpa_ie_len,
			const u8 *mdie, size_t mdie_len,
			const u8 *owe_dh, size_t owe_dh_len);
int wpa_parse_wpa_ie_rsn(const u8 *rsn_ie, size_t rsn_ie_len,
                         struct wpa_ie_data *data);

u8 * wpa_add_kde(u8 *pos, u32 kde, const u8 *data, size_t data_len,
		 const u8 *data2, size_t data2_len);
u8 * ieee80211w_kde_add(struct sta_info *sta, u8 *pos);

const u8 * wpa_auth_get_wpa_ie(struct apd_data *hapd, u8 ApIdx, size_t *len);

#endif
