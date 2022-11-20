#ifndef RADIUS_H
#define RADIUS_H

/* RFC 2865 - RADIUS */

struct radius_hdr {
	u8 code;
	u8 identifier;
	u16 length; /* including this header */
	u8 authenticator[16];
	/* followed by length-20 octets of attributes */
} __attribute__ ((packed));

enum { RADIUS_CODE_ACCESS_REQUEST = 1,
       RADIUS_CODE_ACCESS_ACCEPT = 2,
       RADIUS_CODE_ACCESS_REJECT = 3,
       RADIUS_CODE_ACCOUNTING_REQUEST = 4,
       RADIUS_CODE_ACCOUNTING_RESPONSE = 5,
       RADIUS_CODE_ACCESS_CHALLENGE = 11,
       RADIUS_CODE_STATUS_SERVER = 12,
       RADIUS_CODE_STATUS_CLIENT = 13,
#if HOTSPOT_R3
#ifdef RADIUS_DAS_SUPPORT
       RADIUS_CODE_DISCONNECT_REQUEST = 40,
       RADIUS_CODE_DISCONNECT_ACK = 41,
       RADIUS_CODE_DISCONNECT_NAK = 42,
       RADIUS_CODE_COA_REQUEST = 43,
       RADIUS_CODE_COA_ACK = 44,
       RADIUS_CODE_COA_NAK = 45,
#endif /* RADIUS_DAS_SUPPORT */
#endif /* HOTSPOT_R3 */
       RADIUS_CODE_RESERVED = 255
};

struct radius_attr_hdr {
	u8 type;
	u8 length; /* including this header */
	/* followed by length-2 octets of attribute value */
} __attribute__ ((packed));

#define RADIUS_MAX_ATTR_LEN (255 - sizeof(struct radius_attr_hdr))

enum { RADIUS_ATTR_USER_NAME = 1,
       RADIUS_ATTR_USER_PASSWORD = 2,
       RADIUS_ATTR_NAS_IP_ADDRESS = 4,
       RADIUS_ATTR_NAS_PORT = 5,
       RADIUS_ATTR_FRAMED_MTU = 12,
       RADIUS_ATTR_STATE = 24,
       RADIUS_ATTR_VENDOR_SPECIFIC = 26,
       RADIUS_ATTR_SESSION_TIMEOUT = 27,
       RADIUS_ATTR_IDLE_TIMEOUT = 28,
       RADIUS_ATTR_TERMINATION_ACTION = 29,
       RADIUS_ATTR_CALLED_STATION_ID = 30,
       RADIUS_ATTR_CALLING_STATION_ID = 31,
       RADIUS_ATTR_NAS_IDENTIFIER = 32,
       RADIUS_ATTR_ACCT_STATUS_TYPE = 40,
       RADIUS_ATTR_ACCT_DELAY_TIME = 41,
       RADIUS_ATTR_ACCT_INPUT_OCTETS = 42,
       RADIUS_ATTR_ACCT_OUTPUT_OCTETS = 43,
       RADIUS_ATTR_ACCT_SESSION_ID = 44,
       RADIUS_ATTR_ACCT_AUTHENTIC = 45,
       RADIUS_ATTR_ACCT_SESSION_TIME = 46,
       RADIUS_ATTR_ACCT_INPUT_PACKETS = 47,
       RADIUS_ATTR_ACCT_OUTPUT_PACKETS = 48,
       RADIUS_ATTR_ACCT_TERMINATE_CAUSE = 49,
       RADIUS_ATTR_ACCT_MULTI_SESSION_ID = 50,
       RADIUS_ATTR_ACCT_LINK_COUNT = 51,
       RADIUS_ATTR_EVENT_TIMESTAMP = 55,
       RADIUS_ATTR_NAS_PORT_TYPE = 61,
       RADIUS_ATTR_CONNECT_INFO = 77,
       RADIUS_ATTR_EAP_MESSAGE = 79,
       RADIUS_ATTR_MESSAGE_AUTHENTICATOR = 80,
//YF: updated from Hostapd 1.0
       RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID = 81,
       RADIUS_ATTR_ACCT_INTERIM_INTERVAL = 85,
       RADIUS_ATTR_CHARGEABLE_USER_IDENTITY = 89,
       RADIUS_ATTR_NAS_IPV6_ADDRESS = 95,
/* ellis: updated for WPA3 SUITEB*/
       RADIUS_ATTR_WLAN_PAIRWISE_CIPHER = 186,
       RADIUS_ATTR_WLAN_GROUP_CIPHER = 187,
       RADIUS_ATTR_WLAN_AKM_SUITE = 188,
       RADIUS_ATTR_WLAN_GROUP_MGMT_CIPHER = 189,
};


/* Termination-Action */
#define RADIUS_TERMINATION_ACTION_DEFAULT 0
#define RADIUS_TERMINATION_ACTION_RADIUS_REQUEST 1

/* NAS-Port-Type */
#define RADIUS_NAS_PORT_TYPE_IEEE_802_11 19


/* RFC 2548 - Microsoft Vendor-specific RADIUS Attributes */
#define RADIUS_VENDOR_ID_MICROSOFT 311

#define RADIUS_VENDOR_ID_WFA 40808
struct radius_attr_vendor_microsoft {
	u8 vendor_type;
	u8 vendor_length;
} __attribute__ ((packed));

enum { RADIUS_VENDOR_ATTR_MS_MPPE_SEND_KEY = 16,
       RADIUS_VENDOR_ATTR_MS_MPPE_RECV_KEY = 17
};

struct radius_ms_mppe_keys {
	u8 *send;
	size_t send_len;
	u8 *recv;
	size_t recv_len;
};


/* RADIUS message structure for new and parsed messages */
struct radius_msg {
	unsigned char *buf;
	size_t buf_size; /* total size allocated for buf */
	size_t buf_used; /* bytes used in buf */

	struct radius_hdr *hdr;

	struct radius_attr_hdr **attrs; /* array of pointers to attributes */
	size_t attr_size; /* total size of the attribute pointer array */
	size_t attr_used; /* total number of attributes in the array */
};


/* Default size to be allocated for new RADIUS messages */
#define RADIUS_DEFAULT_MSG_SIZE 1024

/* Default size to be allocated for attribute array */
#define RADIUS_DEFAULT_ATTR_COUNT 16


/* MAC address ASCII format for IEEE 802.1X use
 * (draft-congdon-radius-8021x-20.txt) */
#define RADIUS_802_1X_ADDR_FORMAT "%02X-%02X-%02X-%02X-%02X-%02X"
/* MAC address ASCII format for non-802.1X use */
#define RADIUS_ADDR_FORMAT "%02x%02x%02x%02x%02x%02x"

/* RSN attribute */
enum {
	SEC_CIPHER_NONE,
	SEC_CIPHER_WEP40,
	SEC_CIPHER_WEP104,
	SEC_CIPHER_WEP128,
	SEC_CIPHER_TKIP,
	SEC_CIPHER_CCMP128,
	SEC_CIPHER_CCMP256,
	SEC_CIPHER_GCMP128,
	SEC_CIPHER_GCMP256,
	SEC_CIPHER_BIP_CMAC128,
	SEC_CIPHER_BIP_CMAC256,
	SEC_CIPHER_BIP_GMAC128,
	SEC_CIPHER_BIP_GMAC256,
	SEC_CIPHER_WPI_SMS4, /* WPI SMS4 support */
	SEC_CIPHER_MAX /* Not a real mode, defined as upper bound */
};

#define IS_CIPHER_NONE(_Cipher)          (((_Cipher) & (1 << SEC_CIPHER_NONE)) > 0)
#define IS_CIPHER_WEP40(_Cipher)          (((_Cipher) & (1 << SEC_CIPHER_WEP40)) > 0)
#define IS_CIPHER_WEP104(_Cipher)        (((_Cipher) & (1 << SEC_CIPHER_WEP104)) > 0)
#define IS_CIPHER_WEP128(_Cipher)        (((_Cipher) & (1 << SEC_CIPHER_WEP128)) > 0)
#define IS_CIPHER_WEP(_Cipher)              (((_Cipher) & ((1 << SEC_CIPHER_WEP40) | (1 << SEC_CIPHER_WEP104) | (1 << SEC_CIPHER_WEP128))) > 0)
#define IS_CIPHER_TKIP(_Cipher)              (((_Cipher) & (1 << SEC_CIPHER_TKIP)) > 0)
#define IS_CIPHER_WEP_TKIP_ONLY(_Cipher)     ((IS_CIPHER_WEP(_Cipher) || IS_CIPHER_TKIP(_Cipher)) && (_Cipher < (1 << SEC_CIPHER_CCMP128)))
#define IS_CIPHER_CCMP128(_Cipher)      (((_Cipher) & (1 << SEC_CIPHER_CCMP128)) > 0)
#define IS_CIPHER_CCMP256(_Cipher)      (((_Cipher) & (1 << SEC_CIPHER_CCMP256)) > 0)
#define IS_CIPHER_GCMP128(_Cipher)     (((_Cipher) & (1 << SEC_CIPHER_GCMP128)) > 0)
#define IS_CIPHER_GCMP256(_Cipher)     (((_Cipher) & (1 << SEC_CIPHER_GCMP256)) > 0)
#define IS_CIPHER_BIP_CMAC128(_Cipher)     (((_Cipher) & (1 << SEC_CIPHER_BIP_CMAC128)) > 0)
#define IS_CIPHER_BIP_CMAC256(_Cipher)     (((_Cipher) & (1 << SEC_CIPHER_BIP_CMAC256)) > 0)
#define IS_CIPHER_BIP_GMAC128(_Cipher)     (((_Cipher) & (1 << SEC_CIPHER_BIP_GMAC128)) > 0)
#define IS_CIPHER_BIP_GMAC256(_Cipher)     (((_Cipher) & (1 << SEC_CIPHER_BIP_GMAC256)) > 0)


enum {
	SEC_AKM_OPEN,
	SEC_AKM_SHARED,
	SEC_AKM_AUTOSWITCH,
	SEC_AKM_WPA1, /* Enterprise security over 802.1x */
	SEC_AKM_WPA1PSK,
	SEC_AKM_WPANone, /* For Win IBSS, directly PTK, no handshark */
	SEC_AKM_WPA2, /* Enterprise security over 802.1x */
	SEC_AKM_WPA2PSK,
	SEC_AKM_FT_WPA2,
	SEC_AKM_FT_WPA2PSK,
	SEC_AKM_WPA2_SHA256,
	SEC_AKM_WPA2PSK_SHA256,
	SEC_AKM_TDLS,
	SEC_AKM_SAE_SHA256,
	SEC_AKM_FT_SAE_SHA256,
	SEC_AKM_SUITEB_SHA256,
	SEC_AKM_SUITEB_SHA384,
	SEC_AKM_FT_WPA2_SHA384,
	SEC_AKM_WAICERT, /* WAI certificate authentication */
	SEC_AKM_WAIPSK, /* WAI pre-shared key */
	SEC_AKM_OWE,
	SEC_AKM_FILS_SHA256,
	SEC_AKM_FILS_SHA384,	
	SEC_AKM_MAX /* Not a real mode, defined as upper bound */
};

#define IS_AKM_OPEN(_AKMMap)                           ((_AKMMap & (1 << SEC_AKM_OPEN)) > 0)
#define IS_AKM_SHARED(_AKMMap)                       ((_AKMMap & (1 << SEC_AKM_SHARED)) > 0)
#define IS_AKM_AUTOSWITCH(_AKMMap)              ((_AKMMap & (1 << SEC_AKM_AUTOSWITCH)) > 0)
#define IS_AKM_WPA1(_AKMMap)                           ((_AKMMap & (1 << SEC_AKM_WPA1)) > 0)
#define IS_AKM_WPA1PSK(_AKMMap)                    ((_AKMMap & (1 << SEC_AKM_WPA1PSK)) > 0)
#define IS_AKM_WPANONE(_AKMMap)                  ((_AKMMap & (1 << SEC_AKM_WPANone)) > 0)
#define IS_AKM_WPA2(_AKMMap)                          ((_AKMMap & (1 << SEC_AKM_WPA2)) > 0)
#define IS_AKM_WPA2PSK(_AKMMap)                    ((_AKMMap & (1 << SEC_AKM_WPA2PSK)) > 0)
#define IS_AKM_FT_WPA2(_AKMMap)                     ((_AKMMap & (1 << SEC_AKM_FT_WPA2)) > 0)
#define IS_AKM_FT_WPA2PSK(_AKMMap)              ((_AKMMap & (1 << SEC_AKM_FT_WPA2PSK)) > 0)
#define IS_AKM_WPA2_SHA256(_AKMMap)            ((_AKMMap & (1 << SEC_AKM_WPA2_SHA256)) > 0)
#define IS_AKM_WPA2PSK_SHA256(_AKMMap)      ((_AKMMap & (1 << SEC_AKM_WPA2PSK_SHA256)) > 0)
#define IS_AKM_TDLS(_AKMMap)                             ((_AKMMap & (1 << SEC_AKM_TDLS)) > 0)
#define IS_AKM_SAE_SHA256(_AKMMap)                ((_AKMMap & (1 << SEC_AKM_SAE_SHA256)) > 0)
#define IS_AKM_FT_SAE_SHA256(_AKMMap)          ((_AKMMap & (1 << SEC_AKM_FT_SAE_SHA256)) > 0)
#define IS_AKM_SUITEB_SHA256(_AKMMap)          ((_AKMMap & (1 << SEC_AKM_SUITEB_SHA256)) > 0)
#define IS_AKM_SUITEB_SHA384(_AKMMap)          ((_AKMMap & (1 << SEC_AKM_SUITEB_SHA384)) > 0)
#define IS_AKM_FT_WPA2_SHA384(_AKMMap)      ((_AKMMap & (1 << SEC_AKM_FT_WPA2_SHA384)) > 0)
#define IS_AKM_WAICERT(_AKMMap)                      ((_AKMMap & (1 << SEC_AKM_WAICERT)) > 0)
#define IS_AKM_WPIPSK(_AKMMap)                        ((_AKMMap & (1 << SEC_AKM_WAIPSK)) > 0)
#define IS_AKM_OWE(_AKMMap)      ((_AKMMap & (1 << SEC_AKM_OWE)) > 0)
#define IS_AKM_FILS_SHA256(_AKMMap)                ((_AKMMap & (1 << SEC_AKM_FILS_SHA256)) > 0)
#define IS_AKM_FILS_SHA384(_AKMMap)                ((_AKMMap & (1 << SEC_AKM_FILS_SHA384)) > 0)

#define WPA_PROTO_WPA BIT(0)
#define WPA_PROTO_RSN BIT(1)
#define WPA_PROTO_WAPI BIT(2)
#define WPA_PROTO_OSEN BIT(3)

#define WPA_SELECTOR_LEN 4
#define WPA_VERSION 1
#define RSN_SELECTOR_LEN 4
#define RSN_VERSION 1

#define RSN_SELECTOR(a, b, c, d) \
	((((u32) (a)) << 24) | (((u32) (b)) << 16) | (((u32) (c)) << 8) | \
	 (u32) (d))

#define WPA_AUTH_KEY_MGMT_NONE RSN_SELECTOR(0x00, 0x50, 0xf2, 0)
#define WPA_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x50, 0xf2, 1)
#define WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x50, 0xf2, 2)
#define WPA_AUTH_KEY_MGMT_CCKM RSN_SELECTOR(0x00, 0x40, 0x96, 0)
#define WPA_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x50, 0xf2, 0)
#define WPA_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x50, 0xf2, 2)
#define WPA_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x50, 0xf2, 4)


#define RSN_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_AUTH_KEY_MGMT_FT_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 3)
#define RSN_AUTH_KEY_MGMT_FT_PSK RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_AUTH_KEY_MGMT_802_1X_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 5)
#define RSN_AUTH_KEY_MGMT_PSK_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 6)
#define RSN_AUTH_KEY_MGMT_TPK_HANDSHAKE RSN_SELECTOR(0x00, 0x0f, 0xac, 7)
#define RSN_AUTH_KEY_MGMT_SAE RSN_SELECTOR(0x00, 0x0f, 0xac, 8)
#define RSN_AUTH_KEY_MGMT_FT_SAE RSN_SELECTOR(0x00, 0x0f, 0xac, 9)
#define RSN_AUTH_KEY_MGMT_802_1X_SUITE_B RSN_SELECTOR(0x00, 0x0f, 0xac, 11)
#define RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192 RSN_SELECTOR(0x00, 0x0f, 0xac, 12)
#define RSN_AUTH_KEY_MGMT_FT_802_1X_SUITE_B_192 \
RSN_SELECTOR(0x00, 0x0f, 0xac, 13)
#define RSN_AUTH_KEY_MGMT_FILS_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 14)
#define RSN_AUTH_KEY_MGMT_FILS_SHA384 RSN_SELECTOR(0x00, 0x0f, 0xac, 15)
#define RSN_AUTH_KEY_MGMT_FT_FILS_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 16)
#define RSN_AUTH_KEY_MGMT_FT_FILS_SHA384 RSN_SELECTOR(0x00, 0x0f, 0xac, 17)
#define RSN_AUTH_KEY_MGMT_OWE RSN_SELECTOR(0x00, 0x0f, 0xac, 18)
#define RSN_AUTH_KEY_MGMT_CCKM RSN_SELECTOR(0x00, 0x40, 0x96, 0x00)
#define RSN_AUTH_KEY_MGMT_OSEN RSN_SELECTOR(0x50, 0x6f, 0x9a, 0x01)
#define RSN_AUTH_KEY_MGMT_DPP RSN_SELECTOR(0x50, 0x6f, 0x9a, 0x02)

#define RSN_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x0f, 0xac, 0)
#define RSN_CIPHER_SUITE_WEP40 RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#if 0
#define RSN_CIPHER_SUITE_WRAP RSN_SELECTOR(0x00, 0x0f, 0xac, 3)
#endif
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_CIPHER_SUITE_WEP104 RSN_SELECTOR(0x00, 0x0f, 0xac, 5)
#define RSN_CIPHER_SUITE_AES_128_CMAC RSN_SELECTOR(0x00, 0x0f, 0xac, 6)
#define RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED RSN_SELECTOR(0x00, 0x0f, 0xac, 7)
#define RSN_CIPHER_SUITE_GCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 8)
#define RSN_CIPHER_SUITE_GCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 9)
#define RSN_CIPHER_SUITE_CCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 10)
#define RSN_CIPHER_SUITE_BIP_GMAC_128 RSN_SELECTOR(0x00, 0x0f, 0xac, 11)
#define RSN_CIPHER_SUITE_BIP_GMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 12)
#define RSN_CIPHER_SUITE_BIP_CMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 13)
#define RSN_CIPHER_SUITE_SMS4 RSN_SELECTOR(0x00, 0x14, 0x72, 1)
#define RSN_CIPHER_SUITE_CKIP RSN_SELECTOR(0x00, 0x40, 0x96, 0)
#define RSN_CIPHER_SUITE_CKIP_CMIC RSN_SELECTOR(0x00, 0x40, 0x96, 1)
#define RSN_CIPHER_SUITE_CMIC RSN_SELECTOR(0x00, 0x40, 0x96, 2)
/* KRK is defined for nl80211 use only */
#define RSN_CIPHER_SUITE_KRK RSN_SELECTOR(0x00, 0x40, 0x96, 255)

struct radius_msg *Radius_msg_new(u8 code, u8 identifier);
int Radius_msg_initialize(struct radius_msg *msg, size_t init_len);
void Radius_msg_set_hdr(struct radius_msg *msg, u8 code, u8 identifier);
void Radius_msg_free(struct radius_msg *msg);
void Radius_msg_finish(struct radius_msg *msg, u8 *secret, size_t secret_len);
struct radius_attr_hdr *Radius_msg_add_attr(struct radius_msg *msg, u8 type,
					    u8 *data, size_t data_len);
struct radius_msg *Radius_msg_parse(const u8 *data, size_t len);
int Radius_msg_add_eap(struct radius_msg *msg, u8 *data, size_t data_len);
u8 *Radius_msg_get_eap(struct radius_msg *msg, size_t *len);
int Radius_msg_verify(struct radius_msg *msg, u8 *secret, size_t secret_len,
		      struct radius_msg *sent_msg);
int Radius_msg_verify_acct(struct radius_msg *msg, u8 *secret,
			   size_t secret_len, struct radius_msg *sent_msg);
int Radius_msg_copy_attr(struct radius_msg *dst, struct radius_msg *src, u8 type);
void Radius_msg_make_authenticator(struct radius_msg *msg, u8 *data, size_t len);
struct radius_ms_mppe_keys *
Radius_msg_get_ms_keys(struct radius_msg *msg, struct radius_msg *sent_msg,
		       u8 *secret, size_t secret_len);
struct radius_attr_hdr *
Radius_msg_add_attr_user_password(struct radius_msg *msg,
				  u8 *data, size_t data_len, u8 *secret, size_t secret_len);
int Radius_msg_get_attr(struct radius_msg *msg, u8 type, u8 *buf, size_t len);

static inline int Radius_msg_add_attr_int32(struct radius_msg *msg, u8 type, u32 value)
{
	u32 val = htonl(value);
	return Radius_msg_add_attr(msg, type, (u8 *) &val, 4) != NULL;
}

static inline int Radius_msg_get_attr_int32(struct radius_msg *msg, u8 type, u32 *value)
{
	u32 val;
	int res;
	res = Radius_msg_get_attr(msg, type, (u8 *) &val, 4);
	if (res != 4)
		return -1;

	*value = ntohl(val);
	return 0;
}

enum { RADIUS_VENDOR_ATTR_WFA_REMEDIATION = 1,
       RADIUS_VENDOR_ATTR_WFA_HS2AP = 2,
       RADIUS_VENDOR_ATTR_WFA_HS2STA = 3,
       RADIUS_VENDOR_ATTR_WFA_DEAUTH = 4,
       RADIUS_VENDOR_ATTR_WFA_SESSION_INFO = 5,
#if HOTSPOT_R3
       RADIUS_VENDOR_ATTR_WFA_HS2_ROAMING_CONSORTIUM = 6,
       RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_FILENAME = 7,
       RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_TIMESTAMP = 8,
       RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_FILTERING = 9,
       RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_URL = 10
#endif
};

struct radius_attr_vendor_wfa {
	u8 vendor_subtype;
	u8 vendor_sublength;
} __attribute__ ((packed));

struct wnm_req_data {
	u32 ifindex;
	u8	peer_mac_addr[6];
	u32 type;
	u32	req_len;
	u8	req[256];
};

struct btm_req_data {
	u32 ifindex;
	u8 peer_mac_addr[6];
	u32 req_len;
	u8  req[260];
} __attribute__ ((packed));

struct radius_attr_vendor {
	u8 vendor_type;
	u8 vendor_length;
} STRUCT_PACKED;
#endif /* RADIUS_H */
