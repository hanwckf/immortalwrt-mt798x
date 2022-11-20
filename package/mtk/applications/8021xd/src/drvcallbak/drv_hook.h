#ifndef DRV_HOOK_H
#define DRV_HOOK_H

#include "includes.h"
#include "rtdot1x.h"
#include "ap/wpa.h"

struct sta_info;
struct apd_data; 

struct wpa_driver_sta_auth_params {

	/**
	 * own_addr - Source address and BSSID for authentication frame
	 */
	const u8 *own_addr;

	/**
	 * addr - MAC address of the station to associate
	 */
	const u8 *addr;

	/**
	 * seq - authentication sequence number
	 */
	u16 seq;

	/**
	 * status - authentication response status code
	 */
	u16 status;

	/**
	 * ie - authentication frame ie buffer
	 */
	const u8 *ie;

	/**
	 * len - ie buffer length
	 */
	size_t len;

	/**
	 * fils_auth - Indicates whether FILS authentication is being performed
	 */
	int fils_auth;

	/**
	 * fils_anonce - ANonce (required for FILS)
	 */
	u8 fils_anonce[WPA_NONCE_LEN];

	/**
	 * fils_snonce - SNonce (required for FILS)
	*/
	u8 fils_snonce[WPA_NONCE_LEN];

	/**
	 * fils_kek - key for encryption (required for FILS)
	 */
	u8 fils_kek[WPA_KEK_MAX_LEN];

	/**
	 * fils_kek_len - Length of the fils_kek in octets (required for FILS)
	 */
	size_t fils_kek_len;
};

/**
 * struct wpa_driver_associate_params - Association parameters
 * Data for struct wpa_driver_ops::associate().
 */
struct wpa_driver_associate_params {
	/**
	 * bssid - BSSID of the selected AP
	 * This can be %NULL, if ap_scan=2 mode is used and the driver is
	 * responsible for selecting with which BSS to associate. */
	const u8 *bssid;

	/**
	 * bssid_hint - BSSID of a proposed AP
	 *
	 * This indicates which BSS has been found a suitable candidate for
	 * initial association for drivers that use driver/firmwate-based BSS
	 * selection. Unlike the @bssid parameter, @bssid_hint does not limit
	 * the driver from selecting other BSSes in the ESS.
	 */
	const u8 *bssid_hint;

	/**
	 * ssid - The selected SSID
	 */
	const u8 *ssid;

	/**
	 * ssid_len - Length of the SSID (1..32)
	 */
	size_t ssid_len;

	/**
	 * freq - channel parameters
	 */
	//struct hostapd_freq_params freq;

	/**
	 * freq_hint - Frequency of the channel the proposed AP is using
	 *
	 * This provides a channel on which a suitable BSS has been found as a
	 * hint for the driver. Unlike the @freq parameter, @freq_hint does not
	 * limit the driver from selecting other channels for
	 * driver/firmware-based BSS selection.
	 */
	int freq_hint;

	/**
	 * bg_scan_period - Background scan period in seconds, 0 to disable
	 * background scan, or -1 to indicate no change to default driver
	 * configuration
	 */
	int bg_scan_period;

	/**
	 * beacon_int - Beacon interval for IBSS or 0 to use driver default
	 */
	int beacon_int;

	/**
	 * wpa_ie - WPA information element for (Re)Association Request
	 * WPA information element to be included in (Re)Association
	 * Request (including information element id and length). Use
	 * of this WPA IE is optional. If the driver generates the WPA
	 * IE, it can use pairwise_suite, group_suite, group_mgmt_suite, and
	 * key_mgmt_suite to select proper algorithms. In this case,
	 * the driver has to notify wpa_supplicant about the used WPA
	 * IE by generating an event that the interface code will
	 * convert into EVENT_ASSOCINFO data (see below).
	 *
	 * When using WPA2/IEEE 802.11i, wpa_ie is used for RSN IE
	 * instead. The driver can determine which version is used by
	 * looking at the first byte of the IE (0xdd for WPA, 0x30 for
	 * WPA2/RSN).
	 *
	 * When using WPS, wpa_ie is used for WPS IE instead of WPA/RSN IE.
	 */
	const u8 *wpa_ie;

	/**
	 * wpa_ie_len - length of the wpa_ie
	 */
	size_t wpa_ie_len;

	/**
	 * wpa_proto - Bitfield of WPA_PROTO_* values to indicate WPA/WPA2
	 */
	unsigned int wpa_proto;

	/**
	 * pairwise_suite - Selected pairwise cipher suite (WPA_CIPHER_*)
	 *
	 * This is usually ignored if @wpa_ie is used.
	 */
	unsigned int pairwise_suite;

	/**
	 * group_suite - Selected group cipher suite (WPA_CIPHER_*)
	 *
	 * This is usually ignored if @wpa_ie is used.
	 */
	unsigned int group_suite;

	/**
	 * mgmt_group_suite - Selected group management cipher suite (WPA_CIPHER_*)
	 *
	 * This is usually ignored if @wpa_ie is used.
	 */
	unsigned int mgmt_group_suite;

	/**
	 * key_mgmt_suite - Selected key management suite (WPA_KEY_MGMT_*)
	 *
	 * This is usually ignored if @wpa_ie is used.
	 */
	unsigned int key_mgmt_suite;

	/**
	 * auth_alg - Allowed authentication algorithms
	 * Bit field of WPA_AUTH_ALG_*
	 */
	int auth_alg;

	/**
	 * mode - Operation mode (infra/ibss) IEEE80211_MODE_*
	 */
	int mode;

	/**
	 * wep_key - WEP keys for static WEP configuration
	 */
	const u8 *wep_key[4];

	/**
	 * wep_key_len - WEP key length for static WEP configuration
	 */
	size_t wep_key_len[4];

	/**
	 * wep_tx_keyidx - WEP TX key index for static WEP configuration
	 */
	int wep_tx_keyidx;

	/**
	 * mgmt_frame_protection - IEEE 802.11w management frame protection
	 */
	//enum mfp_options mgmt_frame_protection;

	/**
	 * passphrase - RSN passphrase for PSK
	 *
	 * This value is made available only for WPA/WPA2-Personal (PSK) and
	 * only for drivers that set WPA_DRIVER_FLAGS_4WAY_HANDSHAKE. This is
	 * the 8..63 character ASCII passphrase, if available. Please note that
	 * this can be %NULL if passphrase was not used to generate the PSK. In
	 * that case, the psk field must be used to fetch the PSK.
	 */
	const char *passphrase;

	/**
	 * psk - RSN PSK (alternative for passphrase for PSK)
	 *
	 * This value is made available only for WPA/WPA2-Personal (PSK) and
	 * only for drivers that set WPA_DRIVER_FLAGS_4WAY_HANDSHAKE. This is
	 * the 32-octet (256-bit) PSK, if available. The driver wrapper should
	 * be prepared to handle %NULL value as an error.
	 */
	const u8 *psk;

	/**
	 * drop_unencrypted - Enable/disable unencrypted frame filtering
	 *
	 * Configure the driver to drop all non-EAPOL frames (both receive and
	 * transmit paths). Unencrypted EAPOL frames (ethertype 0x888e) must
	 * still be allowed for key negotiation.
	 */
	int drop_unencrypted;

	/**
	 * prev_bssid - Previously used BSSID in this ESS
	 *
	 * When not %NULL, this is a request to use reassociation instead of
	 * association.
	 */
	const u8 *prev_bssid;

	/**
	 * wps - WPS mode
	 *
	 * If the driver needs to do special configuration for WPS association,
	 * this variable provides more information on what type of association
	 * is being requested. Most drivers should not need ot use this.
	 */
	//enum wps_mode wps;

	/**
	 * p2p - Whether this connection is a P2P group
	 */
	int p2p;

	/**
	 * uapsd - UAPSD parameters for the network
	 * -1 = do not change defaults
	 * AP mode: 1 = enabled, 0 = disabled
	 * STA mode: bits 0..3 UAPSD enabled for VO,VI,BK,BE
	 */
	int uapsd;

	/**
	 * fixed_bssid - Whether to force this BSSID in IBSS mode
	 * 1 = Fix this BSSID and prevent merges.
	 * 0 = Do not fix BSSID.
	 */
	int fixed_bssid;

	/**
	 * fixed_freq - Fix control channel in IBSS mode
	 * 0 = don't fix control channel (default)
	 * 1 = fix control channel; this prevents IBSS merging with another
	 *	channel
	 */
	int fixed_freq;

	/**
	 * disable_ht - Disable HT (IEEE 802.11n) for this connection
	 */
	int disable_ht;

	/**
	 * htcaps - HT Capabilities over-rides
	 *
	 * Only bits set in the mask will be used, and not all values are used
	 * by the kernel anyway. Currently, MCS, MPDU and MSDU fields are used.
	 *
	 * Pointer to struct ieee80211_ht_capabilities.
	 */
	const u8 *htcaps;

	/**
	 * htcaps_mask - HT Capabilities over-rides mask
	 *
	 * Pointer to struct ieee80211_ht_capabilities.
	 */
	const u8 *htcaps_mask;

#ifdef CONFIG_VHT_OVERRIDES
	/**
	 * disable_vht - Disable VHT for this connection
	 */
	int disable_vht;

	/**
	 * VHT capability overrides.
	 */
	const struct ieee80211_vht_capabilities *vhtcaps;
	const struct ieee80211_vht_capabilities *vhtcaps_mask;
#endif /* CONFIG_VHT_OVERRIDES */

	/**
	 * req_key_mgmt_offload - Request key management offload for connection
	 *
	 * Request key management offload for this connection if the device
	 * supports it.
	 */
	int req_key_mgmt_offload;

	/**
	 * Flag for indicating whether this association includes support for
	 * RRM (Radio Resource Measurements)
	 */
	int rrm_used;

	/**
	 * pbss - If set, connect to a PCP in a PBSS. Otherwise, connect to an
	 * AP as usual. Valid for DMG network only.
	 */
	int pbss;

	/**
	 * fils_kek - KEK for FILS association frame protection (AES-SIV)
	 */
	const u8 *fils_kek;

	/**
	 * fils_kek_len: Length of fils_kek in bytes
	 */
	size_t fils_kek_len;

	/**
	 * fils_nonces - Nonces for FILS association frame protection
	 * (AES-SIV AAD)
	 */
	const u8 *fils_nonces;

	/**
	 * fils_nonces_len: Length of fils_nonce in bytes
	 */
	size_t fils_nonces_len;

	/**
	 * fils_erp_username - Username part of keyName-NAI
	 */
	const u8 *fils_erp_username;

	/**
	 * fils_erp_username_len - Length of fils_erp_username in bytes
	 */
	size_t fils_erp_username_len;

	/**
	 * fils_erp_realm - Realm/domain name to use in FILS ERP
	 */
	const u8 *fils_erp_realm;

	/**
	 * fils_erp_realm_len - Length of fils_erp_realm in bytes
	 */
	size_t fils_erp_realm_len;

	/**
	 * fils_erp_next_seq_num - The next sequence number to use in FILS ERP
	 * messages
	 */
	u16 fils_erp_next_seq_num;

	/**
	 * fils_erp_rrk - Re-authentication root key (rRK) for the keyName-NAI
	 * specified by fils_erp_username@fils_erp_realm.
	 */
	const u8 *fils_erp_rrk;

	/**
	 * fils_erp_rrk_len - Length of fils_erp_rrk in bytes
	 */
	size_t fils_erp_rrk_len;
};

struct wpa_driver_ops {
	/** Name of the driver interface */
	const char *name;

	/**
	 * sta_auth - Station authentication indication
	 * @priv: private driver interface data
	 * @params: Station authentication parameters
	 *
	 * Returns: 0 on success, -1 on failure
	 */
	 int (*sta_auth)(void *priv,
			 struct wpa_driver_sta_auth_params *params);	

	/**
	 * sta_assoc - Station association indication
	 * @priv: Private driver interface data
	 * @own_addr: Source address and BSSID for association frame
	 * @addr: MAC address of the station to associate
	 * @reassoc: flag to indicate re-association
	 * @status: association response status code
	 * @ie: assoc response ie buffer
	 * @len: ie buffer length
	 * Returns: 0 on success, -1 on failure
	 *
	 * This function indicates the driver to send (Re)Association
	 * Response frame to the station.
	 */
	 int (*sta_assoc)(void *priv, const u8 *own_addr, const u8 *addr,
					  int reassoc, u16 status, const u8 *ie, size_t len);

	/**
	 * get_seqnum - Fetch the current TSC/packet number (AP only)
	 * @ifname: The interface name (main or virtual)
	 * @priv: Private driver interface data
	 * @addr: MAC address of the station or %NULL for group keys
	 * @idx: Key index
	 * @seq: Buffer for returning the latest used TSC/packet number
	 * Returns: 0 on success, -1 on failure
	 *
	 * This function is used to fetch the last used TSC/packet number for
	 * a TKIP, CCMP, GCMP, or BIP/IGTK key. It is mainly used with group
	 * keys, so there is no strict requirement on implementing support for
	 * unicast keys (i.e., addr != %NULL).
	 */
	 int (*get_seqnum)(void *priv, u8 apidx, const u8 *addr,
				  int idx, u8 *seq);

  	 int (*set_key)(void *priv, u8 apidx, enum wpa_alg alg,
  				  const u8 *addr, int key_idx,
  				  const u8 *key, size_t key_len);
};	

/**
 * enum wpa_event_type - Event type for wpa_supplicant_event() calls
 */
enum wpa_event_type {
	EVENT_ASSOC,
    EVENT_AUTH,
};

/**
 * union wpa_event_data - Additional data for wpa_supplicant_event() calls
 */
union wpa_event_data {
        /**
         * struct auth_info - Data for EVENT_AUTH events
         */
        struct auth_info {
                u8 peer[ETH_ALEN];
                u8 bssid[ETH_ALEN];
                u16 auth_type;
                u16 auth_transaction;
                u16 status_code;
                const u8 *ies;
                size_t ies_len;

				u8 apidx;
				u16 ethertype;
				int SockNum;
        } auth;

		struct assoc_info {
			u8 peer[ETH_ALEN];
			int reassoc;
            const u8 *frame;
            size_t frame_len;		

			u8 apidx;
			u16 ethertype;
			int SockNum;			
		} assoc_info;
};

#define WLAN_FC_GET_TYPE(fc)	(((fc) & 0x000c) >> 2)
#define WLAN_FC_GET_STYPE(fc)	(((fc) & 0x00f0) >> 4)

struct ieee80211_hdr {
	le16 frame_control;
	le16 duration_id;
	u8 addr1[6];
	u8 addr2[6];
	u8 addr3[6];
	le16 seq_ctrl;
	/* followed by 'u8 addr4[6];' if ToDS and FromDS is set in data frame
	 */
} STRUCT_PACKED;

#define IEEE80211_HDRLEN (sizeof(struct ieee80211_hdr))
#define IEEE80211_FC(type, stype) host_to_le16((type << 2) | (stype << 4))

struct ieee80211_mgmt {
	le16 frame_control;
	le16 duration;
	u8 da[6];
	u8 sa[6];
	u8 bssid[6];
	le16 seq_ctrl;
	union {
		struct {
			le16 auth_alg;
			le16 auth_transaction;
			le16 status_code;
			/* possibly followed by Challenge text */
			u8 variable[];
		} STRUCT_PACKED auth;
		struct {
			le16 reason_code;
			u8 variable[];
		} STRUCT_PACKED deauth;
		struct {
			le16 capab_info;
			le16 listen_interval;
			/* followed by SSID and Supported rates */
			u8 variable[];
		} STRUCT_PACKED assoc_req;
		struct {
			le16 capab_info;
			le16 status_code;
			le16 aid;
			/* followed by Supported rates */
			u8 variable[];
		} STRUCT_PACKED assoc_resp, reassoc_resp;
		struct {
			le16 capab_info;
			le16 listen_interval;
			u8 current_ap[6];
			/* followed by SSID and Supported rates */
			u8 variable[];
		} STRUCT_PACKED reassoc_req;
		struct {
			le16 reason_code;
			u8 variable[];
		} STRUCT_PACKED disassoc;
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			u8 variable[];
		} STRUCT_PACKED beacon;
		/* probe_req: only variable items: SSID, Supported rates */
		struct {
			u8 timestamp[8];
			le16 beacon_int;
			le16 capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params */
			u8 variable[];
		} STRUCT_PACKED probe_resp;
		struct {
			u8 category;
			union {
				struct {
					u8 action_code;
					u8 dialog_token;
					u8 status_code;
					u8 variable[];
				} STRUCT_PACKED wmm_action;
				struct{
					u8 action_code;
					u8 element_id;
					u8 length;
					u8 switch_mode;
					u8 new_chan;
					u8 switch_count;
				} STRUCT_PACKED chan_switch;
				struct {
					u8 action;
					u8 sta_addr[ETH_ALEN];
					u8 target_ap_addr[ETH_ALEN];
					u8 variable[]; /* FT Request */
				} STRUCT_PACKED ft_action_req;
				struct {
					u8 action;
					u8 sta_addr[ETH_ALEN];
					u8 target_ap_addr[ETH_ALEN];
					le16 status_code;
					u8 variable[]; /* FT Request */
				} STRUCT_PACKED ft_action_resp;
				struct {
					u8 action;
					u8 dialogtoken;
					u8 variable[];
				} STRUCT_PACKED wnm_sleep_req;
				struct {
					u8 action;
					u8 dialogtoken;
					le16 keydata_len;
					u8 variable[];
				} STRUCT_PACKED wnm_sleep_resp;
				struct {
					u8 action;
					u8 variable[];
				} STRUCT_PACKED public_action;
				struct {
					u8 action; /* 9 */
					u8 oui[3];
					/* Vendor-specific content */
					u8 variable[];
				} STRUCT_PACKED vs_public_action;
				struct {
					u8 action; /* 7 */
					u8 dialog_token;
					u8 req_mode;
					le16 disassoc_timer;
					u8 validity_interval;
					/* BSS Termination Duration (optional),
					 * Session Information URL (optional),
					 * BSS Transition Candidate List
					 * Entries */
					u8 variable[];
				} STRUCT_PACKED bss_tm_req;
				struct {
					u8 action; /* 8 */
					u8 dialog_token;
					u8 status_code;
					u8 bss_termination_delay;
					/* Target BSSID (optional),
					 * BSS Transition Candidate List
					 * Entries (optional) */
					u8 variable[];
				} STRUCT_PACKED bss_tm_resp;
				struct {
					u8 action; /* 6 */
					u8 dialog_token;
					u8 query_reason;
					/* BSS Transition Candidate List
					 * Entries (optional) */
					u8 variable[];
				} STRUCT_PACKED bss_tm_query;
				struct {
					u8 action; /* 15 */
					u8 variable[];
				} STRUCT_PACKED slf_prot_action;
				struct {
					u8 action;
					u8 variable[];
				} STRUCT_PACKED fst_action;
				struct {
					u8 action;
					u8 dialog_token;
					u8 variable[];
				} STRUCT_PACKED rrm;
			} u;
		} STRUCT_PACKED action;
	} u;
} STRUCT_PACKED;

int hostapd_ap_set_key(struct apd_data *hapd, u8 apidx, int vlan_id,
                                   enum wpa_alg alg, const u8 *addr, int idx,
                                   u8 *key, size_t key_len);

void hostapd_notify_assoc_fils_finish(struct apd_data *hapd,
                                      struct sta_info *sta);
int hostapd_sta_auth(struct apd_data *hapd, const u8 *addr,
                     u16 seq, u16 status, const u8 *ie, size_t len);

int hostapd_sta_assoc(struct apd_data *hapd, const u8 *own_addr, const u8 *addr,
                          int reassoc, u16 status, const u8 *ie, size_t len);  

void wpa_supplicant_event(struct apd_data *hapd, enum wpa_event_type event,
									  union wpa_event_data *data);

void Handle_mlme_event(struct apd_data *hapd, u8 *addr, 
	u8 *apidx, u16 ethertype, int SockNum, u8 *ie, size_t ie_len);

void Handle_aead_decr_event(struct apd_data *hapd, u8 *addr, 
	u8 *apidx, u16 ethertype, int SockNum, u8 *ie, size_t ie_len);

void Handle_aead_encr_event(struct apd_data *hapd, u8 *addr, 
	u8 *apidx, u16 ethertype, int SockNum, u8 *ie, size_t ie_len);

u16 hostapd_ap_capab_info(struct apd_data *hapd, struct sta_info *sta);

static inline int hostapd_get_seqnum(struct sta_info *sta,
                                      const u8 *addr, int idx, u8 *seq)
{
	struct apd_data *hapd = sta->priv;
	
    if (hapd->driver->get_seqnum == NULL)
            return -1;
	
    return hapd->driver->get_seqnum(hapd, sta->ApIdx, addr, idx, seq);
}

#endif
