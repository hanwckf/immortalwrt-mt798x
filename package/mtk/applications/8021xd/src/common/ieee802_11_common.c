/*
 * IEEE 802.11 Common routines
 * Copyright (c) 2002-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "ieee802_11_common.h"
#include "ap.h"
#include "rtdot1x.h"

static int ieee802_11_parse_extension(const u8 *pos, size_t elen,
				      struct ieee802_11_elems *elems,
				      int show_errors)
{
	u8 ext_id;

	if (elen < 1) {
		if (show_errors) {
			DBGPRINT(RT_DEBUG_ERROR,
				   "short information element (Ext)");
		}
		return -1;
	}

	ext_id = *pos++;
	elen--;

	switch (ext_id) {
	case WLAN_EID_EXT_ASSOC_DELAY_INFO:
		if (elen != 1)
			break;
		elems->assoc_delay_info = pos;
		break;
	case WLAN_EID_EXT_FILS_REQ_PARAMS:
		if (elen < 3)
			break;
		elems->fils_req_params = pos;
		elems->fils_req_params_len = elen;
		break;
	case WLAN_EID_EXT_FILS_KEY_CONFIRM:
		elems->fils_key_confirm = pos;
		elems->fils_key_confirm_len = elen;
		break;
	case WLAN_EID_EXT_FILS_SESSION:
		if (elen != FILS_SESSION_LEN)
			break;
		elems->fils_session = pos;
		break;
	case WLAN_EID_EXT_FILS_HLP_CONTAINER:
		if (elen < 2 * ETH_ALEN)
			break;
		elems->fils_hlp = pos;
		elems->fils_hlp_len = elen;
		break;
	case WLAN_EID_EXT_FILS_IP_ADDR_ASSIGN:
		if (elen < 1)
			break;
		elems->fils_ip_addr_assign = pos;
		elems->fils_ip_addr_assign_len = elen;
		break;
	case WLAN_EID_EXT_KEY_DELIVERY:
		if (elen < WPA_KEY_RSC_LEN)
			break;
		elems->key_delivery = pos;
		elems->key_delivery_len = elen;
		break;
	case WLAN_EID_EXT_FILS_WRAPPED_DATA:
		elems->fils_wrapped_data = pos;
		elems->fils_wrapped_data_len = elen;
		break;
	case WLAN_EID_EXT_FILS_PUBLIC_KEY:
		if (elen < 1)
			break;
		elems->fils_pk = pos;
		elems->fils_pk_len = elen;
		break;
	case WLAN_EID_EXT_FILS_NONCE:
		if (elen != FILS_NONCE_LEN)
			break;
		elems->fils_nonce = pos;
		break;
	case WLAN_EID_EXT_OWE_DH_PARAM:
		if (elen < 2)
			break;
		elems->owe_dh = pos;
		elems->owe_dh_len = elen;
		break;
	default:
		if (show_errors) {
			DBGPRINT(RT_DEBUG_INFO,
				   "IEEE 802.11 element parsing ignored unknown element extension (ext_id=%u elen=%u)",
				   ext_id, (unsigned int) elen);
		}
		return -1;
	}

	return 0;
}


/**
 * ieee802_11_parse_elems - Parse information elements in management frames
 * @start: Pointer to the start of IEs
 * @len: Length of IE buffer in octets
 * @elems: Data structure for parsed elements
 * @show_errors: Whether to show parsing errors in debug log
 * Returns: Parsing result
 */
ParseRes ieee802_11_parse_elems(const u8 *start, size_t len,
				struct ieee802_11_elems *elems,
				int show_errors)
{
	size_t left = len;
	const u8 *pos = start;
	int unknown = 0;

	memset(elems, 0, sizeof(*elems));

	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left) {
			if (show_errors) {
				DBGPRINT(RT_DEBUG_TRACE, "IEEE 802.11 element "
					   "parse failed (id=%d elen=%d "
					   "left=%lu)",
					   id, elen, (unsigned long) left);
			}
			return ParseFailed;
		}

		switch (id) {
#if 0
		case WLAN_EID_SSID:
			if (elen > SSID_MAX_LEN) {
				DBGPRINT(RT_DEBUG_TRACE,
					   "Ignored too long SSID element (elen=%u)",
					   elen);
				break;
			}
			elems->ssid = pos;
			elems->ssid_len = elen;
			break;
		case WLAN_EID_SUPP_RATES:
			elems->supp_rates = pos;
			elems->supp_rates_len = elen;
			break;
		case WLAN_EID_DS_PARAMS:
			if (elen < 1)
				break;
			elems->ds_params = pos;
			break;
		case WLAN_EID_CF_PARAMS:
		case WLAN_EID_TIM:
			break;
		case WLAN_EID_CHALLENGE:
			elems->challenge = pos;
			elems->challenge_len = elen;
			break;
		case WLAN_EID_ERP_INFO:
			if (elen < 1)
				break;
			elems->erp_info = pos;
			break;
		case WLAN_EID_EXT_SUPP_RATES:
			elems->ext_supp_rates = pos;
			elems->ext_supp_rates_len = elen;
			break;
#endif
		case WLAN_EID_VENDOR_SPECIFIC:
#if 0
			if (ieee802_11_parse_vendor_specific(pos, elen,
							     elems,
							     show_errors))
				unknown++;
#endif
			break;
		case WLAN_EID_RSN:
			elems->rsn_ie = pos;
			elems->rsn_ie_len = elen;
			break;
#if 0
		case WLAN_EID_PWR_CAPABILITY:
			if (elen < 2)
				break;
			elems->power_capab = pos;
			elems->power_capab_len = elen;
			break;
		case WLAN_EID_SUPPORTED_CHANNELS:
			elems->supp_channels = pos;
			elems->supp_channels_len = elen;
			break;
		case WLAN_EID_MOBILITY_DOMAIN:
			if (elen < sizeof(struct rsn_mdie))
				break;
			elems->mdie = pos;
			elems->mdie_len = elen;
			break;
		case WLAN_EID_FAST_BSS_TRANSITION:
			if (elen < sizeof(struct rsn_ftie))
				break;
			elems->ftie = pos;
			elems->ftie_len = elen;
			break;
		case WLAN_EID_TIMEOUT_INTERVAL:
			if (elen != 5)
				break;
			elems->timeout_int = pos;
			break;
		case WLAN_EID_HT_CAP:
			if (elen < sizeof(struct ieee80211_ht_capabilities))
				break;
			elems->ht_capabilities = pos;
			break;
		case WLAN_EID_HT_OPERATION:
			if (elen < sizeof(struct ieee80211_ht_operation))
				break;
			elems->ht_operation = pos;
			break;
		case WLAN_EID_MESH_CONFIG:
			elems->mesh_config = pos;
			elems->mesh_config_len = elen;
			break;
		case WLAN_EID_MESH_ID:
			elems->mesh_id = pos;
			elems->mesh_id_len = elen;
			break;
		case WLAN_EID_PEER_MGMT:
			elems->peer_mgmt = pos;
			elems->peer_mgmt_len = elen;
			break;
		case WLAN_EID_VHT_CAP:
			if (elen < sizeof(struct ieee80211_vht_capabilities))
				break;
			elems->vht_capabilities = pos;
			break;
		case WLAN_EID_VHT_OPERATION:
			if (elen < sizeof(struct ieee80211_vht_operation))
				break;
			elems->vht_operation = pos;
			break;
		case WLAN_EID_VHT_OPERATING_MODE_NOTIFICATION:
			if (elen != 1)
				break;
			elems->vht_opmode_notif = pos;
			break;
		case WLAN_EID_LINK_ID:
			if (elen < 18)
				break;
			elems->link_id = pos;
			break;
		case WLAN_EID_INTERWORKING:
			elems->interworking = pos;
			elems->interworking_len = elen;
			break;
		case WLAN_EID_QOS_MAP_SET:
			if (elen < 16)
				break;
			elems->qos_map_set = pos;
			elems->qos_map_set_len = elen;
			break;
		case WLAN_EID_EXT_CAPAB:
			elems->ext_capab = pos;
			elems->ext_capab_len = elen;
			break;
		case WLAN_EID_BSS_MAX_IDLE_PERIOD:
			if (elen < 3)
				break;
			elems->bss_max_idle_period = pos;
			break;
		case WLAN_EID_SSID_LIST:
			elems->ssid_list = pos;
			elems->ssid_list_len = elen;
			break;
		case WLAN_EID_AMPE:
			elems->ampe = pos;
			elems->ampe_len = elen;
			break;
		case WLAN_EID_MIC:
			elems->mic = pos;
			elems->mic_len = elen;
			/* after mic everything is encrypted, so stop. */
			left = elen;
			break;
		case WLAN_EID_MULTI_BAND:
			if (elems->mb_ies.nof_ies >= MAX_NOF_MB_IES_SUPPORTED) {
				DBGPRINT(RT_DEBUG_INFO,
					   "IEEE 802.11 element parse ignored MB IE (id=%d elen=%d)",
					   id, elen);
				break;
			}

			elems->mb_ies.ies[elems->mb_ies.nof_ies].ie = pos;
			elems->mb_ies.ies[elems->mb_ies.nof_ies].ie_len = elen;
			elems->mb_ies.nof_ies++;
			break;
		case WLAN_EID_SUPPORTED_OPERATING_CLASSES:
			elems->supp_op_classes = pos;
			elems->supp_op_classes_len = elen;
			break;
		case WLAN_EID_RRM_ENABLED_CAPABILITIES:
			elems->rrm_enabled = pos;
			elems->rrm_enabled_len = elen;
			break;
		case WLAN_EID_CAG_NUMBER:
			elems->cag_number = pos;
			elems->cag_number_len = elen;
			break;
		case WLAN_EID_AP_CSN:
			if (elen < 1)
				break;
			elems->ap_csn = pos;
			break;
		case WLAN_EID_FILS_INDICATION:
			if (elen < 2)
				break;
			elems->fils_indic = pos;
			elems->fils_indic_len = elen;
			break;
		case WLAN_EID_DILS:
			if (elen < 2)
				break;
			elems->dils = pos;
			elems->dils_len = elen;
			break;
		case WLAN_EID_FRAGMENT:
			/* TODO */
			break;
#endif
		case WLAN_EID_EXTENSION:
			if (ieee802_11_parse_extension(pos, elen, elems,
						       show_errors))
				unknown++;
			break;
		default:
			unknown++;
			if (!show_errors)
				break;
			DBGPRINT(RT_DEBUG_INFO, "IEEE 802.11 element parse "
				   "ignored unknown element (id=%d elen=%d)\n",
				   id, elen);
			break;
		}

		left -= elen;
		pos += elen;
	}

	if (left)
		return ParseFailed;

	return unknown ? ParseUnknown : ParseOK;
}
