/*
 * IEEE 802.11 Common routines
 * Copyright (c) 2002-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_11_COMMON_H
#define IEEE802_11_COMMON_H

#define MAX_NOF_MB_IES_SUPPORTED 5

struct mb_ies_info {
	struct {
		const u8 *ie;
		u8 ie_len;
	} ies[MAX_NOF_MB_IES_SUPPORTED];
	u8 nof_ies;
};

/* Parsed Information Elements */
struct ieee802_11_elems {
	const u8 *ssid;
	const u8 *supp_rates;
	const u8 *ds_params;
	const u8 *challenge;
	const u8 *erp_info;
	const u8 *ext_supp_rates;
	const u8 *wpa_ie;
	const u8 *rsn_ie;
	const u8 *wmm; /* WMM Information or Parameter Element */
	const u8 *wmm_tspec;
	const u8 *wps_ie;
	const u8 *supp_channels;
	const u8 *mdie;
	const u8 *ftie;
	const u8 *timeout_int;
	const u8 *ht_capabilities;
	const u8 *ht_operation;
	const u8 *mesh_config;
	const u8 *mesh_id;
	const u8 *peer_mgmt;
	const u8 *vht_capabilities;
	const u8 *vht_operation;
	const u8 *vht_opmode_notif;
	const u8 *vendor_ht_cap;
	const u8 *vendor_vht;
	const u8 *p2p;
	const u8 *wfd;
	const u8 *link_id;
	const u8 *interworking;
	const u8 *qos_map_set;
	const u8 *hs20;
	const u8 *ext_capab;
	const u8 *bss_max_idle_period;
	const u8 *ssid_list;
	const u8 *osen;
	const u8 *mbo;
	const u8 *ampe;
	const u8 *mic;
	const u8 *pref_freq_list;
	const u8 *supp_op_classes;
	const u8 *rrm_enabled;
	const u8 *cag_number;
	const u8 *ap_csn;
	const u8 *fils_indic;
	const u8 *dils;
	const u8 *assoc_delay_info;
	const u8 *fils_req_params;
	const u8 *fils_key_confirm;
	const u8 *fils_session;
	const u8 *fils_hlp;
	const u8 *fils_ip_addr_assign;
	const u8 *key_delivery;
		  u8 *fils_wrapped_data;
	const u8 *fils_pk;
	const u8 *fils_nonce;
	const u8 *owe_dh;
	const u8 *power_capab;
	const u8 *roaming_cons_sel;

	u8 ssid_len;
	u8 supp_rates_len;
	u8 challenge_len;
	u8 ext_supp_rates_len;
	u8 wpa_ie_len;
	u8 rsn_ie_len;
	u8 wmm_len; /* 7 = WMM Information; 24 = WMM Parameter */
	u8 wmm_tspec_len;
	u8 wps_ie_len;
	u8 supp_channels_len;
	u8 mdie_len;
	u8 ftie_len;
	u8 mesh_config_len;
	u8 mesh_id_len;
	u8 peer_mgmt_len;
	u8 vendor_ht_cap_len;
	u8 vendor_vht_len;
	u8 p2p_len;
	u8 wfd_len;
	u8 interworking_len;
	u8 qos_map_set_len;
	u8 hs20_len;
	u8 ext_capab_len;
	u8 ssid_list_len;
	u8 osen_len;
	u8 mbo_len;
	u8 ampe_len;
	u8 mic_len;
	u8 pref_freq_list_len;
	u8 supp_op_classes_len;
	u8 rrm_enabled_len;
	u8 cag_number_len;
	u8 fils_indic_len;
	u8 dils_len;
	u8 fils_req_params_len;
	u8 fils_key_confirm_len;
	u8 fils_hlp_len;
	u8 fils_ip_addr_assign_len;
	u8 key_delivery_len;
	u8 fils_wrapped_data_len;
	u8 fils_pk_len;
	u8 owe_dh_len;
	u8 power_capab_len;
	u8 roaming_cons_sel_len;

	struct mb_ies_info mb_ies;
};

typedef enum { ParseOK = 0, ParseUnknown = 1, ParseFailed = -1 } ParseRes;

ParseRes ieee802_11_parse_elems(const u8 *start, size_t len,
				struct ieee802_11_elems *elems,
				int show_errors);

#endif /* IEEE802_11_COMMON_H */
