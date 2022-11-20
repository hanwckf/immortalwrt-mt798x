#ifndef AP_H
#define AP_H

#include "common/wpa_common.h"

#define WLAN_FC_PVER		0x0003
#define WLAN_FC_TODS		0x0100
#define WLAN_FC_FROMDS		0x0200
#define WLAN_FC_MOREFRAG	0x0400
#define WLAN_FC_RETRY		0x0800
#define WLAN_FC_PWRMGT		0x1000
#define WLAN_FC_MOREDATA	0x2000
#define WLAN_FC_ISWEP		0x4000
#define WLAN_FC_ORDER		0x8000

#define WLAN_AUTH_OPEN			0
#define WLAN_AUTH_SHARED_KEY	1
#define WLAN_AUTH_FT			2
#define WLAN_AUTH_SAE			3
#define WLAN_AUTH_FILS_SK		4
#define WLAN_AUTH_FILS_SK_PFS	5
#define WLAN_AUTH_FILS_PK		6

#define FILS_NONCE_LEN 16
#define FILS_SESSION_LEN 8
#define FILS_CACHE_ID_LEN 2
#define FILS_MAX_KEY_AUTH_LEN 48

#define WLAN_FC_TYPE_MGMT		0
#define WLAN_FC_TYPE_CTRL		1
#define WLAN_FC_TYPE_DATA		2

/* management */
#define WLAN_FC_STYPE_ASSOC_REQ		0
#define WLAN_FC_STYPE_ASSOC_RESP	1
#define WLAN_FC_STYPE_REASSOC_REQ	2
#define WLAN_FC_STYPE_REASSOC_RESP	3
#define WLAN_FC_STYPE_PROBE_REQ		4
#define WLAN_FC_STYPE_PROBE_RESP	5
#define WLAN_FC_STYPE_BEACON		8
#define WLAN_FC_STYPE_ATIM		9
#define WLAN_FC_STYPE_DISASSOC		10
#define WLAN_FC_STYPE_AUTH		11
#define WLAN_FC_STYPE_DEAUTH		12
#define WLAN_FC_STYPE_ACTION		13

#define WLAN_AUTH_CHALLENGE_LEN 128

#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_UNSPECIFIED_FAILURE 1
#define WLAN_STATUS_INVALID_IE 40
#define WLAN_STATUS_GROUP_CIPHER_NOT_VALID 41
#define WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID 42
#define WLAN_STATUS_AKMP_NOT_VALID 43
#define WLAN_STATUS_INVALID_PMKID 53
#define WLAN_STATUS_INVALID_MDIE 54

#define WLAN_EID_RSN 48
#define WLAN_EID_VENDOR_SPECIFIC 221
#define WLAN_EID_FRAGMENT 242
#define WLAN_EID_EXTENSION 255

/* Element ID Extension (EID 255) values */
#define WLAN_EID_EXT_ASSOC_DELAY_INFO 1
#define WLAN_EID_EXT_FILS_REQ_PARAMS 2
#define WLAN_EID_EXT_FILS_KEY_CONFIRM 3
#define WLAN_EID_EXT_FILS_SESSION 4
#define WLAN_EID_EXT_FILS_HLP_CONTAINER 5
#define WLAN_EID_EXT_FILS_IP_ADDR_ASSIGN 6
#define WLAN_EID_EXT_KEY_DELIVERY 7
#define WLAN_EID_EXT_FILS_WRAPPED_DATA 8
#define WLAN_EID_EXT_FTM_SYNC_INFO 9
#define WLAN_EID_EXT_EXTENDED_REQUEST 10
#define WLAN_EID_EXT_ESTIMATED_SERVICE_PARAMS 11
#define WLAN_EID_EXT_FILS_PUBLIC_KEY 12
#define WLAN_EID_EXT_FILS_NONCE 13
#define WLAN_EID_EXT_FUTURE_CHANNEL_GUIDANCE 14
#define WLAN_EID_EXT_OWE_DH_PARAM 32
#define WLAN_EID_EXT_HE_CAPABILITIES 35
#define WLAN_EID_EXT_HE_OPERATION 36

#define OSEN_IE_VENDOR_TYPE 0x506f9a12

enum {
        WPA_IE_OK, WPA_INVALID_IE, WPA_INVALID_GROUP, WPA_INVALID_PAIRWISE,
        WPA_INVALID_AKMP, WPA_NOT_ENABLED, WPA_ALLOC_FAIL,
        WPA_MGMT_FRAME_PROTECTION_VIOLATION, WPA_INVALID_MGMT_GROUP_CIPHER,
        WPA_INVALID_MDIE, WPA_INVALID_PROTO, WPA_INVALID_PMKID
};

/* STA flags */
#define WLAN_STA_AUTH           BIT(0)
#define WLAN_STA_ASSOC          BIT(1)
#define WLAN_STA_PS             BIT(2)
#define WLAN_STA_TIM            BIT(3)
#define WLAN_STA_PERM           BIT(4)
#define WLAN_STA_PENDING_POLL   BIT(6) /* pending activity poll not ACKed */
#define WLAN_STA_PENDING_FILS_ERP BIT(22)

#define WLAN_RATE_1M            BIT(0)
#define WLAN_RATE_2M            BIT(1)
#define WLAN_RATE_5M5           BIT(2)
#define WLAN_RATE_11M           BIT(3)
#define WLAN_RATE_COUNT         4

/* Maximum size of Supported Rates info element. IEEE 802.11 has a limit of 8,
 * but some pre-standard IEEE 802.11g products use longer elements. */
#define WLAN_SUPP_RATES_MAX     32

#define IEEE80211_MAX_MMPDU_SIZE 2304

struct apd_data; 

struct sta_sec_info {
	enum {
		WPA_VERSION_NO_WPA = 0 /* WPA not used */,
		WPA_VERSION_WPA = 1 /* WPA / IEEE 802.11i/D3.0 */,
		WPA_VERSION_WPA2 = 2 /* WPA2 / IEEE 802.11i */
	} wpa;

	u32 wpa_key_mgmt;
	int pairwise;
	int wpa_group;
	int mgmt_frame_prot;
	
	u8 *wpa_ie;
	size_t wpa_ie_len;	
};

#if HOTSPOT_R3
	typedef struct _sta_hs_consortium_oi {
		u32 sta_wcid;
		u8 oi_len;
		u8 selected_roaming_consortium_oi[5];
	}__attribute__ ((packed)) STA_HS_CONSORTIUM_OI, *PSTA_HS_CONSORTIUM_OI;
#endif

struct sta_info {
	struct sta_info         *next; /* next entry in sta list */
	struct sta_info         *hnext; /* next entry in hash table list */
	u8                      addr[6];
	u8			wcid;
	u16                     aid; /* STA's unique AID (1 .. 2007) or 0 if not yet assigned */
	u32                     akm;
	u32                     pairwise_cipher;
	u32                     group_cipher;
	u32                     group_mgmt_cipher;
	u32                     flags;
	u16                     capability;
	u16                     listen_interval; /* or beacon_int for APs */
	u8                      supported_rates[WLAN_SUPP_RATES_MAX];
	u8                      tx_supp_rates;

	enum { STA_NULLFUNC = 0, STA_DISASSOC, STA_DEAUTH } timeout_next;

	/* IEEE 802.1X related data */
	struct                  eapol_state_machine *eapol_sm;
	int                     radius_identifier;
	/* TODO: check when the last messages can be released */
	struct radius_msg       *last_recv_radius;
	u8                      *last_eap_supp; /* last received EAP Response from Supplicant */
	size_t                  last_eap_supp_len;
	u8                      *last_eap_radius; /* last received EAP Response from Authentication Server */
	size_t                  last_eap_radius_len;
	u8                      *identity;
	size_t                  identity_len;

	/* Keys for encrypting and signing EAPOL-Key frames */
	u8                      *eapol_key_sign;
	size_t                  eapol_key_sign_len;
	u8                      *eapol_key_crypt;
	size_t                  eapol_key_crypt_len;

	/* IEEE 802.11f (IAPP) related data */
	struct ieee80211_mgmt   *last_assoc_req;

	// Multiple SSID interface
	u8						ApIdx;
	u16						ethertype;

	// From which raw socket
	int						SockNum;
	
#if HOTSPOT_R2	
	/* Hotspot-R2 related data */
	u8						hs_version;
	u8						hs_ie_exist;
	u16						ppsmo_id;
#endif	

#if HOTSPOT_R3
	/* Hotspot-R3 related data */
	STA_HS_CONSORTIUM_OI				hs_roaming_oi;
#endif /* HOTSPOT_R3 */

#ifdef CONFIG_FILS
	u16 auth_alg;

    u8 fils_snonce[FILS_NONCE_LEN];	
    u8 fils_anonce[FILS_NONCE_LEN];
    u8 fils_session[FILS_SESSION_LEN];
    u8 fils_erp_pmkid[PMKID_LEN];
    u8 *fils_pending_assoc_req;
    size_t fils_pending_assoc_req_len;
    unsigned int fils_pending_assoc_is_reassoc:1;
    unsigned int fils_dhcp_rapid_commit_proxy:1;
    unsigned int fils_erp_pmkid_set:1;
    struct wpabuf *fils_hlp_resp;
    struct wpabuf *hlp_dhcp_discover;
    void (*fils_pending_cb)(struct apd_data *hapd, struct sta_info *sta,
                            u16 resp, struct wpabuf *data, int pub);
    struct wpabuf *fils_dh_ss;
    struct wpabuf *fils_g_sta;

	u8 fils_key_auth_sta[FILS_MAX_KEY_AUTH_LEN];
	u8 fils_key_auth_ap[FILS_MAX_KEY_AUTH_LEN];
	size_t fils_key_auth_len;
	unsigned int fils_completed:1;

	struct wpa_ptk PTK;
	u8 PTK_valid:1;
	u8 tk_already_set:1;
#endif /* CONFIG_FILS */

	struct sta_sec_info sta_sec_info;
	void* priv;
};

#define MAX_STA_COUNT           1024

/* Maximum number of AIDs to use for STAs; must be 2007 or lower
 * (8802.11 limitation) */
#define MAX_AID_TABLE_SIZE      256

#define STA_HASH_SIZE           256
#define STA_HASH(sta)           (sta[5])

/* Default value for maximum station inactivity. After AP_MAX_INACTIVITY has
 * passed since last received frame from the station, a nullfunc data frame is
 * sent to the station. If this frame is not acknowledged and no other frames
 * have been received, the station will be disassociated after
 * AP_DISASSOC_DELAY. Similarily, a the station will be deauthenticated after
 * AP_DEAUTH_DELAY. AP_TIMEOUT_RESOLUTION is the resolution that is used with
 * max inactivity timer. All these times are in seconds. */
#define AP_MAX_INACTIVITY       (5* 60)
#define AP_DISASSOC_DELAY       (1)
#define AP_DEAUTH_DELAY         (1)

void hex_dump(char *str, const unsigned char *pSrcBufVA, unsigned int SrcBufLen);
#endif /* AP_H */
