#ifndef RTDOT1XD_H
#define RTDOT1XD_H

#include "common.h"
#include "ap.h"


#define MAC_ADDR_LEN				6
#define MAX_MBSSID_NUM              16
#define WEP8021X_KEY_LEN            13

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#include "config.h"

/* It shall be the same with wireless driver */
#define dot1x_version	"3.0.1.0"

#define NIC_DBG_STRING	"[DOT1X] "

#define RT_DEBUG_OFF		0
#define RT_DEBUG_ERROR		1
#define RT_DEBUG_WARN		2
#define RT_DEBUG_TRACE		3
#define RT_DEBUG_INFO		4

// OID definition
#define OID_GET_SET_TOGGLE							0x8000
#define RT_QUERY_SIGNAL_CONTEXT						0x0402
#define	RT_SET_APD_PID								0x0405
#define RT_SET_DEL_MAC_ENTRY						0x0406


#define RT_PRIV_IOCTL								(SIOCIWFIRSTPRIV + 0x01)
#if 0
#define OID_802_11_RADIUS_QUERY_SETTING				0x0540
#define RTPRIV_IOCTL_ADD_PMKID_CACHE                (SIOCIWFIRSTPRIV + 0x0A)
#define RTPRIV_IOCTL_RADIUS_DATA                    (SIOCIWFIRSTPRIV + 0x0C)
#define RTPRIV_IOCTL_ADD_WPA_KEY                    (SIOCIWFIRSTPRIV + 0x0E)
#define RTPRIV_IOCTL_STATIC_WEP_COPY                (SIOCIWFIRSTPRIV + 0x10)
#else
#define OID_802_DOT1X_CONFIGURATION					0x0540
#define OID_802_DOT1X_PMKID_CACHE					0x0541
#define OID_802_DOT1X_RADIUS_DATA					0x0542
#define OID_802_DOT1X_WPA_KEY						0x0543
#define OID_802_DOT1X_STATIC_WEP_COPY				0x0544
#define OID_802_DOT1X_IDLE_TIMEOUT					0x0545

#ifdef RADIUS_MAC_ACL_SUPPORT
#define OID_802_DOT1X_RADIUS_ACL_NEW_CACHE                              0x0546
#define OID_802_DOT1X_RADIUS_ACL_DEL_CACHE                              0x0547
#define OID_802_DOT1X_RADIUS_ACL_CLEAR_CACHE                            0x0548
#endif /* RADIUS_MAC_ACL_SUPPORT */
#define OID_802_DOT1X_QUERY_STA_AID                                     0x0549
#define OID_802_DOT1X_QUERY_STA_DATA					0x0550
#define OID_802_DOT1X_QUERY_STA_RSN					0x0551
#ifdef CONFIG_FILS
#define OID_802_DOT1X_MLME_EVENT                	0x0552
#define OID_802_DOT1X_KEY_EVENT               		0x0553
#define OID_802_DOT1X_RSNE_SYNC               	   	0x0554
#define OID_802_DOT1X_PMK_CACHE_EVENT 				0x0555
#endif /* CONFIG_FILS */


#define OID_802_11_WNM_BTM_REQ                  	0x0928
#define OID_802_11_WNM_NOTIFY_REQ					0x0944
#define OID_802_11_GET_STA_HSINFO	             	0x0946

#define RT_OID_802_DOT1X_PMKID_CACHE		(OID_GET_SET_TOGGLE | OID_802_DOT1X_PMKID_CACHE)
#define RT_OID_802_DOT1X_RADIUS_DATA		(OID_GET_SET_TOGGLE | OID_802_DOT1X_RADIUS_DATA)
#define RT_OID_802_DOT1X_WPA_KEY			(OID_GET_SET_TOGGLE | OID_802_DOT1X_WPA_KEY)
#define RT_OID_802_DOT1X_STATIC_WEP_COPY	(OID_GET_SET_TOGGLE | OID_802_DOT1X_STATIC_WEP_COPY)
#define RT_OID_802_DOT1X_IDLE_TIMEOUT		(OID_GET_SET_TOGGLE | OID_802_DOT1X_IDLE_TIMEOUT)

#ifdef RADIUS_MAC_ACL_SUPPORT
#define RT_OID_802_DOT1X_RADIUS_ACL_NEW_CACHE   (OID_GET_SET_TOGGLE | OID_802_DOT1X_RADIUS_ACL_NEW_CACHE)
#define RT_OID_802_DOT1X_RADIUS_ACL_DEL_CACHE   (OID_GET_SET_TOGGLE | OID_802_DOT1X_RADIUS_ACL_DEL_CACHE)
#define RT_OID_802_DOT1X_RADIUS_ACL_CLEAR_CACHE (OID_GET_SET_TOGGLE | OID_802_DOT1X_RADIUS_ACL_CLEAR_CACHE)
#endif /* RADIUS_MAC_ACL_SUPPORT */
#ifdef CONFIG_FILS
#define RT_OID_802_DOT1X_MLME_EVENT      (OID_GET_SET_TOGGLE | OID_802_DOT1X_MLME_EVENT)
#define RT_OID_802_DOT1X_KEY_EVENT       (OID_GET_SET_TOGGLE | OID_802_DOT1X_KEY_EVENT)
#define RT_OID_802_DOT1X_RSNE_SYNC       (OID_GET_SET_TOGGLE | OID_802_DOT1X_RSNE_SYNC)
#define RT_OID_802_DOT1X_PMK_CACHE_EVENT (OID_GET_SET_TOGGLE | OID_802_DOT1X_PMK_CACHE_EVENT)
#endif /* CONFIG_FILS */

#define RT_OID_802_11_WNM_NOTIFY_REQ		(OID_GET_SET_TOGGLE | OID_802_11_WNM_NOTIFY_REQ)
#define RT_OID_802_11_WNM_BTM_REQ			(OID_GET_SET_TOGGLE | OID_802_11_WNM_BTM_REQ)
#define RT_OID_802_11_GET_STA_HSINFO		(OID_802_11_GET_STA_HSINFO)
#endif

#ifdef MASK_PARTIAL_MACADDR
#define MAC2STR(a) (a)[0], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:**:**:%02x:%02x:%02x"
#else
/* Debug print format string for the MAC Address */
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
/* Debug print argument for the MAC Address */
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif /* MASK_PARTIAL_MACADDR */

/* Radius use full mac */
#define RADIUS_MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

#ifndef ETH_P_PAE
#define ETH_P_PAE 0x888E /* Port Access Entity (IEEE 802.1X) */
#endif /* ETH_P_PAE */

#ifndef ETH_P_PRE_AUTH
#define ETH_P_PRE_AUTH 0x88C7 /* Port Access Entity (WPA2 pre-auth mode) */
#endif /* ETH_P_PRE_AUTH */

#ifndef ETH_P_VLAN
#define ETH_P_VLAN 0x8100 /* VLAN Protocol */
#endif /* ETH_P_VLAN */

#ifndef BIT
#define BIT(x) (1U << (x))
#endif
#define REAUTH_TIMER_DEFAULT_reAuthEnabled TRUE
#define REAUTH_TIMER_DEFAULT_reAuthPeriod 3600
#define AUTH_PAE_DEFAULT_quietPeriod 		60
#define DEFAULT_IDLE_INTERVAL 				60

#if DBG
extern int RTDebugLevel;
#define DBGPRINT(Level, ...)				\
{							\
	if (Level <= RTDebugLevel) {			\
		printf(NIC_DBG_STRING"[%s]", __func__);	\
		printf(__VA_ARGS__);			\
	}						\
}
#else
#define DBGPRINT(Level, ...)
#endif

struct wpa_driver_ops;

struct ieee8023_hdr {
	u8 dAddr[6];
	u8 sAddr[6];
	u16 eth_type;
} __attribute__ ((packed));

enum mfp_options {
    NO_MGMT_FRAME_PROTECTION = 0,
    MGMT_FRAME_PROTECTION_OPTIONAL = 1,
    MGMT_FRAME_PROTECTION_REQUIRED = 2,
};

enum FILS_KEY_ACTION {
	FILS_KEY_INSTALL_PTK = 0,
	FILS_KEY_GET_RSC,
	FILS_KEY_GET_TSC,
};

struct sec_info {
	int wpa;
	u32 wpa_key_mgmt;
	int wpa_group;
	int wpa_pairwise;
	int rsn_pairwise;
	enum mfp_options ieee80211w;
	int group_mgmt_cipher;

	u32 dot11RSNAAuthenticationSuiteSelected;
	u32 dot11RSNAPairwiseCipherSelected;
	u32 dot11RSNAGroupCipherSelected;

	u8 *wpa_ie;
	size_t wpa_ie_len;

	int GN;
	u8 GTK[WPA_GTK_MAX_LEN];
	int GTK_len;

	int IGN;
	u8 IGTK[WPA_GTK_MAX_LEN];
	int IGTK_len;

	u16 FilsCacheId;
};

#define DRIVER_SYNC_AP_CAP_INFO           BIT(0)
#define DRIVER_SYNC_AP_SEC_INFO           BIT(1)

typedef struct apd_data {
	struct rtapd_config *conf;
	char *prefix_wlan_name;		/* the prefix name of wireless interface */
	char *main_wlan_name;		/* the main name of wireless interface */

	int wlan_sock[MAX_MBSSID_NUM];		/* raw packet socket for wireless interface access */
	int eth_sock[MAX_MBSSID_NUM]; 		/* raw packet socket for ethernet interface access */
	int ioctl_sock; /* socket for ioctl() use */
	u8 own_addr[MAX_MBSSID_NUM][MAC_ADDR_LEN];		/* indicate the wireless MAC address */

	int num_sta; /* number of entries in sta_list */
	struct sta_info *sta_list; /* STA info list head */
	struct sta_info *sta_hash[STA_HASH_SIZE];

	/* pointers to STA info; based on allocated AID or NULL if AID free
	 * AID is in the range 1-2007, so sta_aid[0] corresponders to AID 1
	 * and so on
	 */
	struct sta_info *sta_aid[MAX_AID_TABLE_SIZE];

	struct radius_client_data *radius;

#ifdef RADIUS_MAC_ACL_SUPPORT
	/* Radius ACL & Query Cache */
	struct hostapd_cached_radius_acl *acl_cache;
	struct hostapd_acl_query_data *acl_queries;
#endif /* RADIUS_MAC_ACL_SUPPORT */

	struct sec_info ap_sec_info[MAX_MBSSID_NUM];
	const struct wpa_driver_ops *driver;
	void *drv_priv;

	struct _RT_802_PMKSA_CACHE_ENTRY *pmk_cache;

	u16 sync_status[MAX_MBSSID_NUM];
	u16 capab_info[MAX_MBSSID_NUM];
	int dhcp_sock; /* UDP socket used with the DHCP server */
	u8 dhcp_server_port_binded;
} rtapd;

typedef struct recv_from_ra {
    u8 daddr[6];
    u8 saddr[6];
    u8 ethtype[2];
    u8 xframe[1];
} __attribute__ ((packed)) priv_rec;

#ifdef RADIUS_MAC_ACL_SUPPORT
typedef struct _RT_802_11_ACL_ENTRY {
	unsigned char Addr[MAC_ADDR_LEN];
	unsigned short Rsv;
} RT_802_11_ACL_ENTRY, *PRT_802_11_ACL_ENTRY;
#endif /* RADIUS_MAC_ACL_SUPPORT */

typedef struct _DOT1X_QUERY_STA_AID {
        unsigned char StaAddr[6];
        unsigned int  aid;
	unsigned int wcid;
} __attribute__ ((packed)) DOT1X_QUERY_STA_AID;

typedef struct _DOT1X_QUERY_STA_RSN {
	u8 sta_addr[MAC_ADDR_LEN];
	u32 akm;
	u32 pairwise_cipher;
	u32 group_cipher;
	u32 group_mgmt_cipher;
} __attribute__ ((packed)) DOT1X_QUERY_STA_RSN;

enum PMK_CACHE_ACTION {
	PMK_CACHE_QUERY = 0,
	PMK_CACHE_ADD,
	PMK_CACHE_DEL,

	/* res */
	PMK_CACHE_STATUS_OK,
	PMK_CACHE_STATUS_FAIL,
};

typedef struct _RT_802_11_PMK_CACHE_SYNC_EVENT {
	u8 addr[MAC_ADDR_LEN];
	u8 pmkid[PMKID_LEN];
	u8 pmk[PMK_LEN_MAX];
	u8 pmk_len;
	u32 akmp; /* WPA_KEY_MGMT_* */
	u8 res;
} __attribute__ ((packed)) RT_802_11_PMK_CACHE_SYNC_EVENT ;

#define MAX_OPT_IE 1024
typedef struct _RT_802_11_STA_MLME_EVENT {
	u8 addr[MAC_ADDR_LEN];
	s16 seq;
	s16 status;
	u8 ie[MAX_OPT_IE];
	unsigned int len;
	u8 mgmt_subtype;
	s16 auth_algo;
	u8 fils_anonce[WPA_NONCE_LEN];
	u8 fils_snonce[WPA_NONCE_LEN];
	u8 fils_kek[WPA_KEK_MAX_LEN];
	unsigned int fils_kek_len;
} __attribute__ ((packed)) RT_802_11_STA_MLME_EVENT;

typedef struct _RT_802_11_SEC_INFO_SYNC_EVENT {
	u8 apidx;
	u8 wpa;
	u32 wpa_key_mgmt;
	u32 wpa_group;
	u32 wpa_pairwise;
	u32 rsn_pairwise;
	u8 rsne[MAX_OPT_IE];
	unsigned int rsne_len;
	u16 CapabilityInfo;
	u8 GN;
	u8 GTK[WPA_GTK_MAX_LEN];
	u8 GTK_len;
	u8 IGN;
	u8 IGTK[WPA_GTK_MAX_LEN];
	u8 IGTK_len;
	u16 FilsCacheId;
	u32 FilsDhcpServerIp;
} __attribute__ ((packed)) RT_802_11_SEC_INFO_SYNC_EVENT;

typedef struct _NDIS_FILS_802_11_KEY
{
    u8            addr[MAC_ADDR_LEN];
    u32           KeyIndex;
    u32           KeyLength;          // length of key in bytes
    u8            KeyMaterial[64];     // variable length depending on above field
} __attribute__ ((packed)) NDIS_FILS_802_11_KEY, *PNDIS_FILS_802_11_KEY;

typedef struct _RT_802_11_KEY_EVENT {
	u8 action;
	NDIS_FILS_802_11_KEY keyInfo;
	u32 keyrsc;
	u32 keytsc;
} __attribute__ ((packed)) RT_802_11_KEY_EVENT;

struct _RT_802_PMKSA_CACHE_ENTRY {
	u8 pmkid[PMKID_LEN];
	u8 pmk[PMK_LEN_MAX];
	u8 pmk_len;
	u8 addr[ETH_ALEN];

	int akmp; /* WPA_KEY_MGMT_* */
	u8 apIdx; /* Which MBSSID */
	struct _RT_802_PMKSA_CACHE_ENTRY *next;
}__attribute__ ((packed)) RT_802_PMKSA_CACHE_ENTRY;


void ieee802_1x_receive(rtapd *apd, u8 *sa, u8 *apidx, u8 *buf, size_t len, u16 ethertype, int	SockNum);
u16	RTMPCompareMemory(void *pSrc1,void *pSrc2, u16 Length);
void Handle_term(int sig, void *eloop_ctx, void *signal_ctx);
int RT_ioctl(int sid, int param, char  *data, int data_len, char *name, unsigned char apidx, int flags);

void dot1x_set_IdleTimeoutAction(
		rtapd *rtapd,
		struct sta_info *sta,
		u32		idle_timeout);

#endif // RTDOT1XD_H //
