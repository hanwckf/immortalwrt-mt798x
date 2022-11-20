
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <linux/if.h>			/* for IFNAMSIZ and co... */
#include <linux/wireless.h>

#include "rtdot1x.h"
#include "ieee802_1x.h"
#include "radius.h"
#include "radius_client.h"
#include "eapol_sm.h"
#include "md5.h"
#include "eloop.h"
#include "sta_info.h"
#include "ap/fils.h"
#include "os.h"

static void ieee802_1x_send(rtapd *rtapd, struct sta_info *sta, u8 type, u8 *data, size_t datalen)
{
	char *buf;
	struct ieee8023_hdr *hdr3;
	struct ieee802_1x_hdr *xhdr;
	size_t len;
	u8 *pos;

	len = sizeof(*hdr3) + 2+ sizeof(*xhdr) +datalen;
	buf = (char *) malloc(len);
	if (buf == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"malloc() failed for ieee802_1x_send(len=%lu)\n", len);
		return;
	}

	if (sta->ApIdx == 0)
	{
		DBGPRINT(RT_DEBUG_TRACE,"Send to Sta(%s) with Identifier %d\n", rtapd->main_wlan_name, *(data+1));
	}
	else
	{
		DBGPRINT(RT_DEBUG_TRACE,"Send to Sta(%s%d) with Identifier %d\n", rtapd->prefix_wlan_name, sta->ApIdx,*(data+1));
	}

	memset(buf, 0, len);
	hdr3 = (struct ieee8023_hdr *) buf;
	memcpy(hdr3->dAddr, sta->addr, ETH_ALEN);
	memcpy(hdr3->sAddr, rtapd->own_addr[sta->ApIdx], ETH_ALEN);

	if (sta->ethertype == ETH_P_PRE_AUTH)
		(hdr3->eth_type) = htons(ETH_P_PRE_AUTH);
	else
		(hdr3->eth_type) = htons(ETH_P_PAE);

	pos = (u8 *) (hdr3 + 1);
	xhdr = (struct ieee802_1x_hdr *) pos;
	if (sta->ethertype == ETH_P_PRE_AUTH)
		xhdr->version = EAPOL_VERSION_2;
	else
		xhdr->version = EAPOL_VERSION;
	xhdr->type = type;
	xhdr->length = htons(datalen);

	if (datalen > 0 && data != NULL)
		memcpy(pos + LENGTH_8021X_HDR, data, datalen);

	//If (ethertype==ETH_P_PRE_AUTH), this means the packet is to or from ehternet socket(WPA2, pre-auth)
	if (sta->ethertype == ETH_P_PRE_AUTH)
	{
		if (send(sta->SockNum/*rtapd->eth_sock*/, buf, len, 0) < 0)
			perror("send[WPA2 pre-auth]");
		DBGPRINT(RT_DEBUG_INFO,"ieee802_1x_send::WPA2, pre-auth, len=%lu\n", len);
	}
	else
	{
        if (RT_ioctl(rtapd->ioctl_sock,
					 RT_PRIV_IOCTL, buf, len,
					 rtapd->prefix_wlan_name, sta->ApIdx,
					 RT_OID_802_DOT1X_RADIUS_DATA))
        DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for ieee802_1x_send(len=%lu)\n", len);
	}

	free(buf);
}

void ieee802_1x_set_sta_authorized(rtapd *rtapd, struct sta_info *sta, int authorized)
{
	switch(authorized)
	{
		case 0:
			DBGPRINT(RT_DEBUG_TRACE,"IEEE802_1X_Set_Sta_Authorized FAILED \n");
//			  Ap_free_sta(rtapd, sta);
			break;

		case 1:
			DBGPRINT(RT_DEBUG_TRACE,"IEEE802_1X_Set_Sta_Authorized SUCCESSED  \n");

			// This connection completed without transmitting EAPoL-Key
			// Notify driver to set-up pairwise key based on its shared key
			if( sta->eapol_sm->authSuccess && sta->eapol_key_sign_len == 0 && sta->eapol_key_crypt_len == 0 )
			{
				UCHAR	MacAddr[MAC_ADDR_LEN];

				memcpy(MacAddr, sta->addr, MAC_ADDR_LEN);
				if (RT_ioctl(rtapd->ioctl_sock,
							 RT_PRIV_IOCTL,
							 (char *)&MacAddr, sizeof(MacAddr),
							 rtapd->prefix_wlan_name, sta->ApIdx,
							 RT_OID_802_DOT1X_STATIC_WEP_COPY))
				{
                	DBGPRINT(RT_DEBUG_ERROR,"Failed to RT_OID_802_DOT1X_STATIC_WEP_COPY\n");
                	return;
				}
	    	}
			break;
	}
}

void ieee802_1x_request_identity(rtapd *rtapd, struct sta_info *sta, u8 id)
{
	u8 *buf;
	struct eap_hdr *eap;
	int tlen;
	u8 *pos;

	ieee802_1x_new_auth_session(rtapd, sta);

	tlen = sizeof(*eap) + 1 ;

	buf = (u8 *) malloc(tlen);
	if (buf == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, "Could not allocate memory for identity request\n");
		return;
	}

	memset(buf, 0, tlen);

	eap = (struct eap_hdr *) buf;
	eap->code = EAP_CODE_REQUEST;
	eap->identifier = id;
	eap->length = htons(tlen);
	pos = (u8 *) (eap + 1);
	*pos++ = EAP_TYPE_IDENTITY;

	DBGPRINT(RT_DEBUG_INFO, "IEEE802_1X_Request_Identity %d bytes: \n",tlen);
	ieee802_1x_send(rtapd, sta, IEEE802_1X_TYPE_EAP_PACKET, buf, tlen);
	free(buf);
}

void ieee802_1x_tx_canned_eap(rtapd *rtapd, struct sta_info *sta, u8 id, int success)
{
	struct eap_hdr eap;

	memset(&eap, 0, sizeof(eap));

	eap.code = success ? EAP_CODE_SUCCESS : EAP_CODE_FAILURE;
	eap.identifier = id;
	eap.length = htons(sizeof(eap));
	DBGPRINT(RT_DEBUG_TRACE,"ieee802_1x_tx_canned_eap : Send to Sta with Identifier %d\n",id);

	ieee802_1x_send(rtapd, sta, IEEE802_1X_TYPE_EAP_PACKET, (u8 *) &eap, sizeof(eap));
}

void ieee802_1x_tx_req(rtapd *rtapd, struct sta_info *sta, u8 id)
{
	struct eap_hdr *eap;

	if (sta->last_eap_radius == NULL)
	{
		DBGPRINT(RT_DEBUG_WARN, "TxReq called for station " MACSTR ", but there "
			   "is no EAP request from the authentication server\n", MAC2STR(sta->addr));
		return;
	}

	eap = (struct eap_hdr *) sta->last_eap_radius;
	if (eap->identifier != id)
	{
		DBGPRINT(RT_DEBUG_WARN,"IEEE 802.1X: TxReq(%d) - changing id from %d\n", id, eap->identifier);
		eap->identifier = id;
	}

	ieee802_1x_send(rtapd, sta, IEEE802_1X_TYPE_EAP_PACKET,	sta->last_eap_radius, sta->last_eap_radius_len);
}

static void ieee802_1x_tx_key_one(rtapd *hapd, struct sta_info *sta,
				  int index, int broadcast,
				  u8 *key_data, size_t key_len)
{
	u8 *buf, *ekey;
	struct ieee802_1x_hdr *hdr;
	struct ieee802_1x_eapol_key *key;
	struct timeval now;
	size_t len, ekey_len;
	u32 ntp_hi, ntp_lo, sec, usec;

	len = sizeof(*key) + key_len;
	buf = malloc(sizeof(*hdr) + len);
	if (buf == NULL)
		return;

	memset(buf, 0, sizeof(*hdr) + len);
	hdr = (struct ieee802_1x_hdr *) buf;
	key = (struct ieee802_1x_eapol_key *) (hdr + 1);
	key->type = EAPOL_KEY_TYPE_RC4;
	key->key_length = htons(key_len);

	/* Set the NTP timestamp as the replay counter */
	gettimeofday(&now, NULL);
	sec = now.tv_sec;
	usec = now.tv_usec;

#define JAN_1970 0x83aa7e80UL /* seconds from 1900 to 1970 */
	ntp_hi = htonl(sec + JAN_1970);
	/* approximation of 2^32/1000000 * usec */
	ntp_lo = htonl(4295 * usec - (usec >> 5) - (usec >> 9));

	memcpy(&key->replay_counter[0], &ntp_hi, sizeof(u32));
	memcpy(&key->replay_counter[4], &ntp_lo, sizeof(u32));
	if (hostapd_get_rand(key->key_iv, sizeof(key->key_iv)))
	{
		DBGPRINT(RT_DEBUG_ERROR, "Could not get random numbers\n");
		free(buf);
		return;
	}

	key->key_index = index | (broadcast ? 0 : BIT(7));
//	if (hapd->conf->eapol_key_index_workaround) {
		/* According to some information, WinXP Supplicant seems to
		 * interrept bit7 as an indication whether the key is to be
		 * activated, so make it possible to enable workaround that
		 * sets this bit for all keys. */
//		key->key_index |= BIT(7);
//	}
	DBGPRINT(RT_DEBUG_TRACE, "key_index= %d key_length= %lu \n",index, key_len);

	/* Key is encrypted using "Key-IV + sta->eapol_key_crypt" as the
	 * RC4-key */
	memcpy((u8 *) (key + 1), key_data, key_len);
	ekey_len = sizeof(key->key_iv) + sta->eapol_key_crypt_len;
	ekey = malloc(ekey_len);
	if (ekey == NULL)
	{
		DBGPRINT(RT_DEBUG_TRACE,"Could not encrypt key\n");
		free(buf);
		return;
	}
	memcpy(ekey, key->key_iv, sizeof(key->key_iv));
	memcpy(ekey + sizeof(key->key_iv), sta->eapol_key_crypt, sta->eapol_key_crypt_len);
	rc4((u8 *) (key + 1), key_len, ekey, ekey_len);
	free(ekey);

	/* This header is needed here for HMAC-MD5, but it will be regenerated in ieee802_1x_send() */
	hdr->version = EAPOL_VERSION;
	hdr->type = IEEE802_1X_TYPE_EAPOL_KEY;
	hdr->length = htons(len);
	hmac_md5(sta->eapol_key_sign, sta->eapol_key_sign_len, buf, sizeof(*hdr) + len, key->key_signature);

	ieee802_1x_send(hapd, sta, IEEE802_1X_TYPE_EAPOL_KEY, (u8 *) key, len);
	free(buf);
}

void ieee802_1x_tx_key(rtapd *rtapd, struct sta_info *sta, u8 id)
{
	NDIS_802_11_KEY WepKey;
	char individual_wep_key[WEP8021X_KEY_LEN] = {0};

	if (!sta) {
		DBGPRINT(RT_DEBUG_ERROR, "(%s): sta is null\n", __func__);
		return;
	}
#ifdef CONFIG_FILS
	if (sta &&
	  (sta->auth_alg == WLAN_AUTH_FILS_SK ||
	  sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
	  sta->auth_alg == WLAN_AUTH_FILS_PK)) {
		DBGPRINT(RT_DEBUG_WARN, "(%s) - skip for FILS\n", __func__);
		return;
	}
#endif /* CONFIG_FILS */

	if (!sta->eapol_key_sign || !sta->eapol_key_crypt)
		return;

	memset(&WepKey, 0, sizeof(NDIS_802_11_KEY));

	// prepare EAPoL-key for broadcast key and send to STA
	ieee802_1x_tx_key_one(rtapd, sta, rtapd->conf->DefaultKeyID[sta->ApIdx], 1, (u8*)rtapd->conf->IEEE8021X_ikey[sta->ApIdx], rtapd->conf->individual_wep_key_len[sta->ApIdx]);

	// use IOCTL cmd to add WEP key
	WepKey.KeyIndex =  0x80000000 | (rtapd->conf->DefaultKeyID[sta->ApIdx]);
	WepKey.KeyLength = rtapd->conf->individual_wep_key_len[sta->ApIdx];
	memcpy(WepKey.KeyMaterial, rtapd->conf->IEEE8021X_ikey[sta->ApIdx], rtapd->conf->individual_wep_key_len[sta->ApIdx]);
	memcpy(WepKey.addr, sta->addr, 6);

	// WPA2(pre-auth)
	if (sta->ethertype== ETH_P_PRE_AUTH)
	{
		if (RT_ioctl(rtapd->ioctl_sock,
					 RT_PRIV_IOCTL,
					 (char *)&WepKey,
					 sizeof(NDIS_802_11_KEY),
					 rtapd->prefix_wlan_name, sta->ApIdx,
					 RT_OID_802_DOT1X_PMKID_CACHE))
		{
			DBGPRINT(RT_DEBUG_ERROR, "ieee802_1x_tx_key:RT_OID_802_DOT1X_PMKID_CACHE\n");
			return;
		}
	}
	else
	{
		if (RT_ioctl(rtapd->ioctl_sock,
					 RT_PRIV_IOCTL,
					 (char *)&WepKey,
					 sizeof(NDIS_802_11_KEY),
					 rtapd->prefix_wlan_name,
					 sta->ApIdx,
					 RT_OID_802_DOT1X_WPA_KEY))
		{
			DBGPRINT(RT_DEBUG_ERROR,"ieee802_1x_tx_key:RT_OID_802_DOT1X_WPA_KEY\n");
			return;
		}
	}

	/* Generate random unicast key and send to STA */
	hostapd_get_rand((u8 *)individual_wep_key, rtapd->conf->individual_wep_key_len[sta->ApIdx]);
	ieee802_1x_tx_key_one(rtapd, sta, rtapd->conf->individual_wep_key_idx[sta->ApIdx], 0, (u8 *)individual_wep_key,
			      rtapd->conf->individual_wep_key_len[sta->ApIdx]);

	// use IOCTL cmd to add WEP key
	WepKey.KeyIndex =  rtapd->conf->individual_wep_key_idx[sta->ApIdx];
	WepKey.KeyLength = rtapd->conf->individual_wep_key_len[sta->ApIdx];
	memcpy(WepKey.KeyMaterial, individual_wep_key, rtapd->conf->individual_wep_key_len[sta->ApIdx]);
	memcpy(WepKey.addr, sta->addr, 6);

	// WPA2(pre-auth)
	if (sta->ethertype == ETH_P_PRE_AUTH)
	{
		if (RT_ioctl(rtapd->ioctl_sock,
					 RT_PRIV_IOCTL,
					 (char *)&WepKey,
					 sizeof(NDIS_802_11_KEY),
					 rtapd->prefix_wlan_name, sta->ApIdx,
					 RT_OID_802_DOT1X_PMKID_CACHE))
		{
			DBGPRINT(RT_DEBUG_ERROR,"ieee802_1x_tx_key:RT_OID_802_DOT1X_PMKID_CACHE\n");
			return;
		}
	}
	else
	{
		if (RT_ioctl(rtapd->ioctl_sock,
					 RT_PRIV_IOCTL,
					 (char *)&WepKey,
					 sizeof(NDIS_802_11_KEY),
					 rtapd->prefix_wlan_name,
					 sta->ApIdx,
					 RT_OID_802_DOT1X_WPA_KEY))
		{
			DBGPRINT(RT_DEBUG_ERROR,"ieee802_1x_tx_key:RT_OID_802_DOT1X_WPA_KEY\n");
			return;
		}
	}
}

static u32 wpa_cipher_to_suite(int proto, u32 cipher)
{
	if (IS_CIPHER_CCMP256(cipher))
		return RSN_CIPHER_SUITE_CCMP_256;
	if (IS_CIPHER_GCMP256(cipher))
		return RSN_CIPHER_SUITE_GCMP_256;
	if (IS_CIPHER_CCMP128(cipher))
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_CCMP : WPA_CIPHER_SUITE_CCMP);
	if (IS_CIPHER_GCMP128(cipher))
		return RSN_CIPHER_SUITE_GCMP;
	if (IS_CIPHER_TKIP(cipher))
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_TKIP : WPA_CIPHER_SUITE_TKIP);
	if (IS_CIPHER_NONE(cipher))
		return (proto == WPA_PROTO_RSN ?
			RSN_CIPHER_SUITE_NONE : WPA_CIPHER_SUITE_NONE);
	if (IS_CIPHER_BIP_CMAC128(cipher))
		return RSN_CIPHER_SUITE_AES_128_CMAC;
	if (IS_CIPHER_BIP_GMAC128(cipher))
		return RSN_CIPHER_SUITE_BIP_GMAC_128;
	if (IS_CIPHER_BIP_GMAC256(cipher))
		return RSN_CIPHER_SUITE_BIP_GMAC_256;
	if (IS_CIPHER_BIP_CMAC256(cipher))
		return RSN_CIPHER_SUITE_BIP_CMAC_256;

	DBGPRINT(RT_DEBUG_ERROR, "unknown cipher = %x\n", cipher);
	return 0;
}

static u32 wpa_akm_to_suite(u32 akm)
{
	if (IS_AKM_FT_WPA2(akm))
		return RSN_AUTH_KEY_MGMT_FT_802_1X;
	if (IS_AKM_FT_WPA2PSK(akm))
		return RSN_AUTH_KEY_MGMT_FT_PSK;
	if (IS_AKM_WPA2_SHA256(akm))
		return RSN_AUTH_KEY_MGMT_802_1X_SHA256;
	if (IS_AKM_WPA2(akm))
		return RSN_AUTH_KEY_MGMT_UNSPEC_802_1X;
	if (IS_AKM_WPA2PSK_SHA256(akm))
		return RSN_AUTH_KEY_MGMT_PSK_SHA256;
	if (IS_AKM_WPA2PSK(akm))
		return RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
	if (IS_AKM_SUITEB_SHA256(akm))
		return RSN_AUTH_KEY_MGMT_802_1X_SUITE_B;
	if (IS_AKM_SUITEB_SHA384(akm))
		return RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192;
	DBGPRINT(RT_DEBUG_ERROR, "unknown akm = %x\n", akm);
	return 0;
}

static int add_common_radius_sta_attr_rsn(struct sta_info *sta,
					  struct radius_msg *msg)
{
	u32 suite;
	int ver;

	if (IS_AKM_WPA1(sta->akm) || IS_AKM_WPA1PSK(sta->akm) || IS_AKM_WPANONE(sta->akm))
		ver = WPA_PROTO_WPA;
	else if (!IS_AKM_OPEN(sta->akm)
		&& !IS_AKM_SHARED(sta->akm)
		&& !IS_AKM_AUTOSWITCH(sta->akm))
		ver = WPA_PROTO_RSN;
	else
		ver = 0;

	suite = wpa_cipher_to_suite(ver, sta->pairwise_cipher);
	if (suite != 0 &&
	    !Radius_msg_add_attr_int32(msg, RADIUS_ATTR_WLAN_PAIRWISE_CIPHER,
				       suite)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add WLAN-Pairwise-Cipher\n");
		return -1;
	}

	suite = wpa_cipher_to_suite(ver, sta->group_cipher);
	if (suite != 0 &&
		!Radius_msg_add_attr_int32(msg, RADIUS_ATTR_WLAN_GROUP_CIPHER,
				       suite)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add WLAN-Group-Cipher\n");
		return -1;
	}

	suite = wpa_akm_to_suite(sta->akm);
	if (suite != 0 &&
	    !Radius_msg_add_attr_int32(msg, RADIUS_ATTR_WLAN_AKM_SUITE,
				       suite)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add WLAN-AKM-Suite\n");
		return -1;
	}

	suite = wpa_cipher_to_suite(WPA_PROTO_RSN, sta->group_mgmt_cipher);
	if (suite != 0 &&
		!Radius_msg_add_attr_int32(
		    msg, RADIUS_ATTR_WLAN_GROUP_MGMT_CIPHER, suite)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add WLAN-Group-Mgmt-Cipher\n");
		return -1;
	}

	return 0;
}

int erp_parse_tlvs(const u8 *pos, const u8 *end, struct erp_tlvs *tlvs,
                   int stop_at_keyname)
{
    memset(tlvs, 0, sizeof(*tlvs));

    while (pos < end) {
        u8 tlv_type, tlv_len;

        tlv_type = *pos++;
        switch (tlv_type) {
        case EAP_ERP_TV_RRK_LIFETIME:
        case EAP_ERP_TV_RMSK_LIFETIME:
            /* 4-octet TV */
            if (pos + 4 > end) {
                    DBGPRINT(RT_DEBUG_ERROR,
						"EAP: Too short TLV(%d)\n", __LINE__);
                    return -1;
            }
            pos += 4;
            break;
        case EAP_ERP_TLV_DOMAIN_NAME:
        case EAP_ERP_TLV_KEYNAME_NAI:
        case EAP_ERP_TLV_CRYPTOSUITES:
        case EAP_ERP_TLV_AUTHORIZATION_INDICATION:
        case EAP_ERP_TLV_CALLED_STATION_ID:
        case EAP_ERP_TLV_CALLING_STATION_ID:
        case EAP_ERP_TLV_NAS_IDENTIFIER:
        case EAP_ERP_TLV_NAS_IP_ADDRESS:
        case EAP_ERP_TLV_NAS_IPV6_ADDRESS:
			if (pos >= end) {
					DBGPRINT(RT_DEBUG_ERROR,
						"EAP: Too short TLV(%d)\n", __LINE__);
					return -1;
			}
			tlv_len = *pos++;
			if (tlv_len > (unsigned) (end - pos)) {
					DBGPRINT(RT_DEBUG_ERROR, "EAP: Truncated TLV(%d)\n", __LINE__);
					return -1;
			}
			if (tlv_type == EAP_ERP_TLV_KEYNAME_NAI) {
					if (tlvs->keyname) {
							DBGPRINT(RT_DEBUG_ERROR,
									   "EAP: More than one keyName-NAI");
							return -1;
					}
					tlvs->keyname = pos;
					tlvs->keyname_len = tlv_len;
					if (stop_at_keyname)
							return 0;
			} else if (tlv_type == EAP_ERP_TLV_DOMAIN_NAME) {
					tlvs->domain = pos;
					tlvs->domain_len = tlv_len;
			}
			pos += tlv_len;
			break;

		default:
			if (tlv_type >= 128 && tlv_type <= 191) {
					/* Undefined TLV */
					if (pos >= end) {
							DBGPRINT(RT_DEBUG_ERROR,
									   "EAP: Too short TLV(%d)\n", __LINE__);
							return -1;
					}
					tlv_len = *pos++;
					if (tlv_len > (unsigned) (end - pos)) {
							DBGPRINT(RT_DEBUG_ERROR,
									   "EAP: Truncated TLV(%d)\n", __LINE__);
							return -1;
					}
					pos += tlv_len;
					break;
			}
			DBGPRINT(RT_DEBUG_ERROR, "EAP: Unknown TV/TLV type %u",
					   tlv_type);
			pos = end;
			break;
		}
	}

	return 0;
}

void eap_erp_update_identity(struct sta_info *sta, const u8 *eap, size_t len)
{
	const struct eap_hdr *hdr;
	const u8 *pos, *end;
	struct erp_tlvs parse;

	if (len < sizeof(*hdr) + 1)
			return;
	hdr = (const struct eap_hdr *) eap;
	end = eap + len;
	pos = (const u8 *) (hdr + 1);
	if (hdr->code != EAP_CODE_INITIATE || *pos != EAP_ERP_TYPE_REAUTH)
			return;
	pos++;
	if (pos + 3 > end)
			return;

	/* Skip Flags and SEQ */
	pos += 3;

	if (erp_parse_tlvs(pos, end, &parse, 1) < 0 || !parse.keyname) {
		DBGPRINT(RT_DEBUG_ERROR,"%s: erp_parse_tlvs FAIL\n", __func__);
		return;
	}

	hex_dump("EAP: Update identity based on EAP-Initiate/Re-auth keyName-NAI",
					  parse.keyname, parse.keyname_len);

	if (sta->identity) {
		free(sta->identity);
		sta->identity = NULL;
	}

	sta->identity = malloc(parse.keyname_len);
	if (sta->identity) {
		memcpy(sta->identity, parse.keyname, parse.keyname_len);
		sta->identity_len = parse.keyname_len;
	} else {
		sta->identity_len = 0;
	}
}

static void ieee802_1x_learn_identity(rtapd *rtapd, struct sta_info *sta, const u8 *eap, size_t len)
{
	const struct eap_hdr *hdr = (const struct eap_hdr *) eap;

	if (len <= sizeof(struct eap_hdr) ||
		(hdr->code == EAP_CODE_RESPONSE &&
		 eap[sizeof(struct eap_hdr)] != EAP_TYPE_IDENTITY) ||
		(hdr->code == EAP_CODE_INITIATE &&
		 eap[sizeof(struct eap_hdr)] != EAP_ERP_TYPE_REAUTH) ||
		(hdr->code != EAP_CODE_RESPONSE &&
		 hdr->code != EAP_CODE_INITIATE)) {
			return;
	}

	eap_erp_update_identity(sta, eap, len);
	if (sta->identity == NULL) {
			DBGPRINT(RT_DEBUG_ERROR,"%s: identity NULL\n", __func__);
			return;
	}

	DBGPRINT(RT_DEBUG_TRACE, "STA " MACSTR
		" ERP identity '%s'\n", MAC2STR(sta->addr), sta->identity);
}

void ieee802_1x_encapsulate_radius(rtapd *rtapd, struct sta_info *sta, u8 *eap, size_t len)
{
	struct radius_msg *msg;
	u8 buf[128] = {0};
	int res = 0;

	ieee802_1x_learn_identity(rtapd, sta, eap, len);

	sta->radius_identifier = Radius_client_get_id(rtapd);
	msg = Radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, sta->radius_identifier);
	if (msg == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, "Could not create net RADIUS packet\n");
		return;
	}

	Radius_msg_make_authenticator(msg, (u8 *) sta, sizeof(*sta));

	if (sta->identity &&
		!Radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, sta->identity, sta->identity_len))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add User-Name\n");
		goto fail;
	}
	   // apd->conf->own_ip_addr is filled according to configuration file
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS, (u8 *) &rtapd->conf->own_ip_addr, 4))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add NAS-IP-Address\n");
		goto fail;
	}

	if ((rtapd->conf->nasId_len[sta->ApIdx] > 0) &&
	    !Radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IDENTIFIER,
				 rtapd->conf->nasId[sta->ApIdx],
				 rtapd->conf->nasId_len[sta->ApIdx]))
	{
		DBGPRINT(RT_DEBUG_ERROR, "Could not add NAS-Identifier\n");
		goto fail;
	}

	if (!Radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT, sta->aid))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add NAS-Port\n");
		goto fail;
	}

	res = snprintf((char *)&buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT, RADIUS_MAC2STR(rtapd->own_addr[sta->ApIdx]));
	if (os_snprintf_error(sizeof(buf), res)) {
		DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
		goto fail;
	}
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_CALLED_STATION_ID, buf, strlen((char *)&buf)))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add Called-Station-Id\n");
		goto fail;
	}

	res = snprintf((char *)&buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT, RADIUS_MAC2STR(sta->addr));
	if (os_snprintf_error(sizeof(buf), res)) {
		DBGPRINT(RT_DEBUG_ERROR, "[%d]Unexpected snprintf fail\n", __LINE__);
		goto fail;
	}
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID, buf, strlen((char *)&buf)))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add Calling-Station-Id\n");
		goto fail;
	}

	/* Ellis: updated for WPA3 SUITEB*/
	if (add_common_radius_sta_attr_rsn(sta, msg) < 0)
		goto fail;

	/* TODO: should probably check MTU from driver config; 2304 is max for
	 * IEEE 802.11, but use 1400 to avoid problems with too large packets
	 */
	if (!Radius_msg_add_attr_int32(msg, RADIUS_ATTR_FRAMED_MTU, 1400))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add Framed-MTU\n");
		goto fail;
	}

	if (!Radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT_TYPE, RADIUS_NAS_PORT_TYPE_IEEE_802_11))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add NAS-Port-Type\n");
		goto fail;
	}
/*
	snprintf(buf, sizeof(buf), "CONNECT 11Mbps 802.11b");
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_CONNECT_INFO, buf, strlen(buf)))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add Connect-Info\n");
		goto fail;
	}
*/
	if (eap && !Radius_msg_add_eap(msg, eap, len))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not add EAP-Message\n");
		goto fail;
	}

#if HOTSPOT_R2
	{
		u32 vendor_id = htonl(RADIUS_VENDOR_ID_WFA);
		u8 *pos;
		struct radius_attr_vendor *vhdr;

		pos = buf;
		memcpy(pos, &vendor_id, sizeof(vendor_id));
		pos += sizeof(vendor_id);
		vhdr = (struct radius_attr_vendor *) pos;
		vhdr->vendor_type = RADIUS_VENDOR_ATTR_WFA_HS2AP;
		pos = (u8 *) (vhdr + 1);
		*pos = 2;
		pos += 1;

		vhdr->vendor_length = 3; //hlen + elen - sizeof(vendor_id);

		if (!Radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, buf, 3+sizeof(vendor_id))) //vhdr->vendor_length+sizeof(vendor_id)))
		{
			DBGPRINT(RT_DEBUG_ERROR,"Could not add WFA-Vendor Message\n");
		}
	}
	if (sta->hs_ie_exist)
	{
		u32 vendor_id = htonl(RADIUS_VENDOR_ID_WFA);
		u8 *pos;
		struct radius_attr_vendor *vhdr;

		DBGPRINT(RT_DEBUG_TRACE, "STA HS IE exists\n");

		pos = buf;
		memcpy(pos, &vendor_id, sizeof(vendor_id));
		pos += sizeof(vendor_id);
		vhdr = (struct radius_attr_vendor *) pos;
		vhdr->vendor_type = RADIUS_VENDOR_ATTR_WFA_HS2STA;
		pos = (u8 *) (vhdr + 1);
		*pos = sta->hs_version;
		pos += 1;
		printf("ppsmod=%x\n", sta->ppsmo_id);
		*pos = (sta->ppsmo_id >> 8)& 0xff;
		*(pos+1) = sta->ppsmo_id & 0xff;

		vhdr->vendor_length = 5; //hlen + elen - sizeof(vendor_id);

		if (!Radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, buf, 5+sizeof(vendor_id))) //vhdr->vendor_length+sizeof(vendor_id)))
		{
			DBGPRINT(RT_DEBUG_ERROR,"Could not add WFA-Vendor Message\n");
		}
	}
#endif
#if HOTSPOT_R3
	if (sta->hs_roaming_oi.oi_len == 3 || sta->hs_roaming_oi.oi_len == 5)
	{
		u32 vendor_id = htonl(RADIUS_VENDOR_ID_WFA);
		u8 *pos;
		struct radius_attr_vendor *vhdr;

		pos = buf;
		memcpy(pos, &vendor_id, sizeof(vendor_id));
		pos += sizeof(vendor_id);
		vhdr = (struct radius_attr_vendor *) pos;
		vhdr->vendor_type = RADIUS_VENDOR_ATTR_WFA_HS2_ROAMING_CONSORTIUM;
		pos = (u8 *) (vhdr + 1);
		memcpy(pos, sta->hs_roaming_oi.selected_roaming_consortium_oi, sta->hs_roaming_oi.oi_len);

		vhdr->vendor_length = sizeof(struct radius_attr_vendor) + sta->hs_roaming_oi.oi_len;

		if (!Radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, buf, vhdr->vendor_length+sizeof(vendor_id)))
		{
			DBGPRINT(RT_DEBUG_OFF,"Could not add Roaming Consortium WFA-Vendor Message\n");
		}
	}

	if (rtapd->conf->hs_TandC_filename_len > 1)
	{
		u32 vendor_id = htonl(RADIUS_VENDOR_ID_WFA);
		u8 *pos;
		struct radius_attr_vendor *vhdr;

		pos = buf;
		memcpy(pos, &vendor_id, sizeof(vendor_id));
		pos += sizeof(vendor_id);
		vhdr = (struct radius_attr_vendor *) pos;
		vhdr->vendor_type = RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_FILENAME;
		pos = (u8 *) (vhdr + 1);
		memcpy(pos, rtapd->conf->hs_TandC_filename, rtapd->conf->hs_TandC_filename_len);

		vhdr->vendor_length = sizeof(struct radius_attr_vendor) + rtapd->conf->hs_TandC_filename_len;

		if (!Radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, buf, vhdr->vendor_length+sizeof(vendor_id)))
		{
			 DBGPRINT(RT_DEBUG_ERROR,"Could not add Terms and condition filename WFA-Vendor Message\n");
		}
	}

	if (rtapd->conf->hs_TandC_timestamp && rtapd->conf->hs_TandC_filename_len > 1)
	{
		u32 vendor_id = htonl(RADIUS_VENDOR_ID_WFA);
		u8 *pos;
		struct radius_attr_vendor *vhdr;

		pos = buf;
		memcpy(pos, &vendor_id, sizeof(vendor_id));
		pos += sizeof(vendor_id);
		vhdr = (struct radius_attr_vendor *) pos;
		vhdr->vendor_type = RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_TIMESTAMP;
		pos = (u8 *) (vhdr + 1);
		memcpy(pos, rtapd->conf->hs_TandC_timestamp, strlen(rtapd->conf->hs_TandC_timestamp));

		vhdr->vendor_length = sizeof(struct radius_attr_vendor) + strlen(rtapd->conf->hs_TandC_timestamp);

		if (!Radius_msg_add_attr(msg, RADIUS_ATTR_VENDOR_SPECIFIC, buf, vhdr->vendor_length+sizeof(vendor_id)))
		{
			DBGPRINT(RT_DEBUG_ERROR,"Could not add Terms and condition timestamp  WFA-Vendor Message\n");
		}
	}
#endif
	/* State attribute must be copied if and only if this packet is
	 * Access-Request reply to the previous Access-Challenge */
	if (sta->last_recv_radius && sta->last_recv_radius->hdr->code == RADIUS_CODE_ACCESS_CHALLENGE)
	{
		int res = Radius_msg_copy_attr(msg, sta->last_recv_radius, RADIUS_ATTR_STATE);
		if (res < 0)
		{
			DBGPRINT(RT_DEBUG_ERROR,"Could not copy State attribute from previous Access-Challenge\n");
			goto fail;
		}
	}

	res = Radius_client_send(rtapd, msg, RADIUS_AUTH, sta->ApIdx);
	if (res < 0)
		DBGPRINT(RT_DEBUG_TRACE, "Radius_client_send fail..(%d)\n", res);

	DBGPRINT(RT_DEBUG_TRACE, "Finish Radius_client_send..(%d)\n", res);

	return;

fail:
	Radius_msg_free(msg);
	free(msg);
}

static void handle_eap_response(struct sta_info *sta, struct eap_hdr *eap, u8 *data, size_t len)
{
	u8 type;

	assert(sta->eapol_sm != NULL);

	if (eap->identifier != sta->eapol_sm->currentId)
	{
		DBGPRINT(RT_DEBUG_INFO,"EAP Identifier of the Response-Identity from " MACSTR
			   " does not match (was %d, expected %d)\n",
			   MAC2STR(sta->addr), eap->identifier,
			   sta->eapol_sm->currentId);
		// didn't check identifier..  reasonable ?
		return;
	}

	if (len < 1)
	{
		DBGPRINT(RT_DEBUG_WARN,"too short response data\n");
		return;
	}

	if (sta->last_eap_supp != NULL)
		free(sta->last_eap_supp);
	       sta->last_eap_supp_len = sizeof(*eap) + len;
	       sta->last_eap_supp = (u8 *) malloc(sta->last_eap_supp_len);
	if (sta->last_eap_supp == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Could not alloc memory for last EAP Response\n");
		return;
	}

	memcpy(sta->last_eap_supp, eap, sizeof(*eap));
	memcpy(sta->last_eap_supp + sizeof(*eap), data, len);

	type = data[0];
	data++;
	len--;

	/* TODO: IEEE 802.1aa/D4: should use auth_pae.initialEAPMsg to check
	 * which EAP packet is accepted as response; currently, hostapd only
	 * supports EAP Response-Identity, so this can be hardcoded */
	if (type == EAP_TYPE_IDENTITY)
	{
		char *buf, *pos;
		int res = 0, i;

		buf = malloc(4 * len + 1);
		if (buf)
		{
			pos = buf;
			for (i = 0; i < len; i++)
			{
				if (data[i] >= 32 && data[i] < 127)
					*pos++ = data[i];
				else
				{
					res = snprintf(pos, 5, "{%02x}", data[i]);
					if (os_snprintf_error(5, res))
						DBGPRINT(RT_DEBUG_ERROR, "Unexpected snprintf fail\n");

					pos += 4;
				}
			}
			*pos = '\0';
			free(buf);
		}

		sta->eapol_sm->auth_pae.rxInitialRsp = TRUE;

		/* Save station identity for future RADIUS packets */
		if (sta->identity)
			free(sta->identity);
		sta->identity = (u8 *) malloc(len);
		if (sta->identity)
		{
			memcpy(sta->identity, data, len);
			sta->identity_len = len;
		}
	}
	else
	{
		if (type != EAP_TYPE_NAK)
			sta->eapol_sm->be_auth.backendNonNakResponsesFromSupplicant++;
		sta->eapol_sm->be_auth.rxResp = TRUE;
	}
}

/* Process incoming EAP packet from Supplicant */
static void handle_eap(struct sta_info *sta, u8 *buf, size_t len)
{
	struct eap_hdr *eap;
	u16 eap_len;

	if (len < sizeof(*eap))
	{
		DBGPRINT(RT_DEBUG_ERROR," too short EAP packet\n");
		return;
	}

	eap = (struct eap_hdr *) buf;

	eap_len = ntohs(eap->length);
	DBGPRINT(RT_DEBUG_INFO," Receive EAP: code=%d identifier=%d length=%d from Supplicant ra%d\n",
			  eap->code, eap->identifier, eap_len,sta->ApIdx);
	if (eap_len < sizeof(*eap))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Invalid EAP length\n");
		return;
	}
	else if (eap_len > len)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Too short frame to contain this EAP packet\n");
		return;
	}
	else if (eap_len < len)
	{
		DBGPRINT(RT_DEBUG_WARN,"Ignoring %lu extra bytes after EAP packet\n", len - eap_len);
	}

	eap_len -= LENGTH_8021X_HDR;

	switch (eap->code)
	{
		case EAP_CODE_REQUEST:
			return;

		case EAP_CODE_RESPONSE:
			handle_eap_response( sta, eap, (u8 *) (eap + 1), eap_len);
			break;

		case EAP_CODE_SUCCESS:
			return;

		case EAP_CODE_FAILURE:
			return;

		case EAP_CODE_INITIATE:
			DBGPRINT(RT_DEBUG_OFF,"(EAP_CODE_INITIATE)\n");
			return;

		case EAP_CODE_FINISH:
			DBGPRINT(RT_DEBUG_OFF,"(EAP_CODE_FINISH)\n");
			return;

		default:
			DBGPRINT(RT_DEBUG_OFF,"(unknown code)\n");
			return;
	}
}

/* called from handle_read(). Process the EAPOL frames from the Supplicant */
void ieee802_1x_receive(
		rtapd *rtapd,
		u8 *sa,
		u8 *apidx,
		u8 *buf,
		size_t len,
		u16 ethertype,
		int	SockNum)
{
	struct sta_info *sta;
	struct ieee802_1x_hdr *hdr;
	char SNAP_802_1H[] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};
	u16 datalen;

	DBGPRINT(RT_DEBUG_TRACE,"IEEE802_1X_RECEIVE : from Supplicant\n");

	sta = Ap_get_sta(rtapd, sa, apidx, ethertype, SockNum);
	if (!sta)
	{
		return;
	}
	if (RTMPCompareMemory(buf, SNAP_802_1H, 6) == 0)
		buf += LENGTH_802_1_H;
	hdr = (struct ieee802_1x_hdr *) buf;
	datalen = ntohs(hdr->length);

	if (len - sizeof(*hdr) < datalen)
	{
		DBGPRINT(RT_DEBUG_ERROR,"Frame too short for this IEEE 802.1X packet\n");
		return;
	}

	if (len - sizeof(*hdr) > datalen)
	{
	}

	if (!sta->eapol_sm)
	{
		sta->eapol_sm = eapol_sm_alloc(rtapd, sta);
		if (!sta->eapol_sm)
			return;
	}

	/* Check protocol type */
	if ((ethertype != ETH_P_PAE) && (ethertype != ETH_P_PRE_AUTH))
	{
		DBGPRINT(RT_DEBUG_ERROR, "Unsupported Protocol Type (%d)\n", ethertype);
		return;
	}

	/* Check EAPoL Protocol Version */
	if ((hdr->version != EAPOL_VERSION) && (hdr->version != EAPOL_VERSION_2))
	{
		DBGPRINT(RT_DEBUG_ERROR, "Unsupported EAPoL Protocol Version (%d)\n", hdr->version);
		return;
	}

	switch (hdr->type)
	{
		case IEEE802_1X_TYPE_EAP_PACKET:

			if (sta->ApIdx == 0)
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle EAP_PACKET from %s\n", rtapd->main_wlan_name);
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle EAP_PACKET from %s%d\n", rtapd->prefix_wlan_name, sta->ApIdx);
			}

#if HOTSPOT_R2
			if ((len - sizeof(*hdr) > (datalen+3)) && (buf[len-8]==0x50) && (buf[len-7]==0x6f) && (buf[len-6]==0x9a) && (buf[len-5] == 0x12))
			{
				printf("HS2 PPSMO :len:%lu\n", len - sizeof(*hdr));
				printf("%02x:%02x:%02x:%02x\n", buf[len-4], buf[len-3], buf[len-2], buf[len-1]);
				sta->hs_version = buf[len-4];
				sta->hs_ie_exist = buf[len-3];
				sta->ppsmo_id = (buf[len-1] << 8) | buf[len-2];

			}
#endif
			handle_eap(sta, (buf + LENGTH_8021X_HDR), datalen);
			break;

		case IEEE802_1X_TYPE_EAPOL_START:
			if (sta->ApIdx == 0)
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle EAPOL_START from %s\n", rtapd->main_wlan_name);
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle EAPOL_START from %s%d\n", rtapd->prefix_wlan_name, sta->ApIdx);
			}
#if HOTSPOT_R2
			if ((len - sizeof(*hdr) > (datalen+3)) && (buf[len-8]==0x50) && (buf[len-7]==0x6f) && (buf[len-6]==0x9a) && (buf[len-5] == 0x12))
			{
				printf("HS2 PPSMO :len:%lu\n", len - sizeof(*hdr));
				printf("%02x:%02x:%02x:%02x\n", buf[len-4], buf[len-3], buf[len-2], buf[len-1]);
				sta->hs_version = buf[len-4];
	            sta->hs_ie_exist = buf[len-3];
    	        sta->ppsmo_id = (buf[len-1] << 8) | buf[len-2];

			}
#endif
			sta->eapol_sm->auth_pae.eapStart = TRUE;
			eapol_sm_step(sta->eapol_sm);
			break;

		case IEEE802_1X_TYPE_EAPOL_LOGOFF:
			sta->eapol_sm->auth_pae.eapLogoff = TRUE;
			eapol_sm_step(sta->eapol_sm);
			break;

		case IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT:
			/* TODO: */
			if (sta->ApIdx == 0)
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle EAPOL_ALERT from %s\n", rtapd->main_wlan_name);
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle EAPOL_ALERT from %s%d\n", rtapd->prefix_wlan_name, sta->ApIdx);
			}
			break;

		default:
			if (sta->ApIdx == 0)
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle Unknown EAP message(Type:%d) from %s\n",hdr->type, rtapd->main_wlan_name);
			}
			else
			{
				DBGPRINT(RT_DEBUG_TRACE,"Handle Unknown EAP message(Type:%d) from %s%d\n",hdr->type, rtapd->prefix_wlan_name, sta->ApIdx);
			}
			break;
	}

	eapol_sm_step(sta->eapol_sm);
}

void ieee802_1x_new_station(rtapd *rtapd, struct sta_info *sta)
{
	if (sta->eapol_sm)
	{
		sta->eapol_sm->portEnabled = TRUE;
		eapol_sm_step(sta->eapol_sm);
		return;
	}

	sta->eapol_sm = eapol_sm_alloc(rtapd, sta);
	if (sta->eapol_sm)
		sta->eapol_sm->portEnabled = TRUE;
}

void ieee802_1x_free_station(struct sta_info *sta)
{
	if (sta->last_recv_radius)
	{
		Radius_msg_free(sta->last_recv_radius);
		free(sta->last_recv_radius);
		sta->last_recv_radius = NULL;
	}

	free(sta->last_eap_supp);
	sta->last_eap_supp = NULL;

	free(sta->last_eap_radius);
	sta->last_eap_radius = NULL;

	free(sta->identity);
	sta->identity = NULL;

	free(sta->eapol_key_sign);
	sta->eapol_key_sign = NULL;

	free(sta->eapol_key_crypt);
	sta->eapol_key_crypt = NULL;

	eapol_sm_free(sta->eapol_sm);
	sta->eapol_sm = NULL;
}

static void ieee802_1x_decapsulate_radius(struct sta_info *sta)
{
	u8 *eap;
	size_t len;
	struct eap_hdr *hdr;
	int eap_type = -1;
	struct radius_msg *msg;

	if (sta->last_recv_radius == NULL)
		return;

	msg = sta->last_recv_radius;
	eap = Radius_msg_get_eap(msg, &len);
	if (eap == NULL)
	{
		/* draft-aboba-radius-rfc2869bis-20.txt, Chap. 2.6.3:
		 * RADIUS server SHOULD NOT send Access-Reject/no EAP-Message
		 * attribute */
		free(sta->last_eap_radius);
		sta->last_eap_radius = NULL;
		sta->last_eap_radius_len = 0;
		return;
	}

	if (len < sizeof(*hdr))
	{
		free(eap);
		return;
	}

	if (len > sizeof(*hdr))
		eap_type = eap[sizeof(*hdr)];

	hdr = (struct eap_hdr *) eap;

	sta->eapol_sm->be_auth.idFromServer = hdr->identifier;

	if (sta->last_eap_radius)
		free(sta->last_eap_radius);
	sta->last_eap_radius = eap;
	sta->last_eap_radius_len = len;
}

static void ieee802_1x_get_keys(rtapd *rtapd, struct sta_info *sta,
				struct radius_msg *msg, struct radius_msg *req,
				u8 *shared_secret, size_t shared_secret_len)
{
	struct radius_ms_mppe_keys *keys;
	NDIS_802_11_KEY 	WepKey;

	memset(&WepKey, 0,sizeof(NDIS_802_11_KEY));
	keys = Radius_msg_get_ms_keys(msg, req, shared_secret, shared_secret_len);
	if (keys == NULL) {
		DBGPRINT(RT_DEBUG_INFO, "Radius_msg_get_ms_keys fail\n");
		return;
	}

	if(keys->recv_len != 0)
	{
		/* 	draft-ietf-eap-keying-01.txt
			Appendix C. MSK and EMSK Hierarchy

			In EAP-TLS [RFC2716], the MSK is divided into two halves,
			corresponding to the "Peer to Authenticator Encryption Key"
			(Enc-RECV-Key, 32 octets, also known as the PMK) and "Authenticator
			to Peer Encryption Key" (Enc-SEND-Key, 32 octets). In [RFC2548], the
			Enc-RECV-Key (the PMK) is transported in the MS-MPPE-Recv-Key
			attribute, and the Enc-SEND-Key is transported in the
			MS-MPPE-Send-Key attribute.
		*/

		DBGPRINT(RT_DEBUG_INFO, "IEEE802_1x_Get_Keys, PMK_len = %lu\n",keys->recv_len );
		hex_dump("PMK =>", keys->recv, keys->recv_len);

		WepKey.KeyLength = keys->recv_len;
		memcpy(WepKey.KeyMaterial, keys->recv, (keys->recv_len== 32?32:1));
		memcpy(WepKey.addr, sta->addr, 6);

		// WPA2(pre-auth)
		if (sta->ethertype == ETH_P_PRE_AUTH)
		{
			if (RT_ioctl(rtapd->ioctl_sock,
						 RT_PRIV_IOCTL,
						 (char *)&WepKey,
						 sizeof(NDIS_802_11_KEY),
						 rtapd->prefix_wlan_name, sta->ApIdx,
						 RT_OID_802_DOT1X_PMKID_CACHE))
			{
				DBGPRINT(RT_DEBUG_ERROR,"ieee802_1x_get_keys:RT_OID_802_DOT1X_PMKID_CACHE\n");
				if (keys->send)
					free(keys->send);
				if (keys->recv)
					free(keys->recv);
				if (keys)
					free(keys);
				return;
			}
		}
		else
		{
			if (keys->recv_len == 32 && keys->send_len == 32)
			{
				WepKey.KeyLength += keys->send_len;
				memcpy(&WepKey.KeyMaterial[32], keys->send, 32);
			}

			if (RT_ioctl(rtapd->ioctl_sock,
						 RT_PRIV_IOCTL,
						 (char *)&WepKey,
						 sizeof(NDIS_802_11_KEY),
						 rtapd->prefix_wlan_name,
						 sta->ApIdx,
						 RT_OID_802_DOT1X_WPA_KEY))
			{
				DBGPRINT(RT_DEBUG_ERROR,"ieee802_1x_get_keys:RT_OID_802_DOT1X_WPA_KEY\n");
				if (keys->send)
					free(keys->send);
				if (keys->recv)
					free(keys->recv);
				if (keys)
					free(keys);
				return;
			}
		}


		if (keys->send && keys->recv)
		{
			free(sta->eapol_key_sign);
			free(sta->eapol_key_crypt);
			sta->eapol_key_sign = keys->send;
			sta->eapol_key_sign_len = keys->send_len;
			sta->eapol_key_crypt = keys->recv;
			sta->eapol_key_crypt_len = keys->recv_len;
			sta->eapol_sm->keyAvailable = TRUE;
		}
		else
		{
			free(keys->send);
			free(keys->recv);
		}
	}
	free(keys);
}

/* Process the RADIUS frames from Authentication Server */
static RadiusRxResult
ieee802_1x_receive_auth(rtapd *rtapd, struct radius_msg *msg, struct radius_msg *req,
			u8 *shared_secret, size_t shared_secret_len, void *data)
{
	struct sta_info *sta;
	u32 session_timeout = 0, idle_timeout = 0, termination_action;
	int session_timeout_set, idle_timeout_set;
	int	free_flag = 0;

	DBGPRINT(RT_DEBUG_TRACE,"Receive IEEE802_1X Response Packet From Radius Server. \n");

	sta = Ap_get_sta_radius_identifier(rtapd, msg->hdr->identifier);
	if (sta == NULL)
	{
		return RADIUS_RX_UNKNOWN;
	}

	/* RFC 2869, Ch. 5.13: valid Message-Authenticator attribute MUST be
	 * present when packet contains an EAP-Message attribute */
	if (msg->hdr->code == RADIUS_CODE_ACCESS_REJECT && Radius_msg_get_attr(msg,
		RADIUS_ATTR_MESSAGE_AUTHENTICATOR, NULL, 0) < 0 &&
		Radius_msg_get_attr(msg, RADIUS_ATTR_EAP_MESSAGE, NULL, 0) < 0)
	{
	}
	else if (Radius_msg_verify(msg, shared_secret, shared_secret_len, req))
	{
		DBGPRINT(RT_DEBUG_ERROR,"Incoming RADIUS packet did not have correct Message-Authenticator - dropped\n");
		return RADIUS_RX_UNKNOWN;
	}

	if (msg->hdr->code != RADIUS_CODE_ACCESS_ACCEPT &&
		msg->hdr->code != RADIUS_CODE_ACCESS_REJECT &&
		msg->hdr->code != RADIUS_CODE_ACCESS_CHALLENGE)
	{
		DBGPRINT(RT_DEBUG_WARN,"Unknown RADIUS message code\n");
		return RADIUS_RX_UNKNOWN;
	}

	sta->radius_identifier = -1;

	if (sta->last_recv_radius)
	{
		Radius_msg_free(sta->last_recv_radius);
		free(sta->last_recv_radius);
		sta->last_recv_radius = NULL;
	}

	sta->last_recv_radius = msg;

	/* Extract the Session-Timeout attrubute */
	session_timeout_set = !Radius_msg_get_attr_int32(msg, RADIUS_ATTR_SESSION_TIMEOUT, &session_timeout);

	/* Extrace the Termination-Action attribute */
	if (Radius_msg_get_attr_int32(msg, RADIUS_ATTR_TERMINATION_ACTION, &termination_action))
		termination_action = RADIUS_TERMINATION_ACTION_DEFAULT;

	/* Extrace Idle-Timeout attribute */
	idle_timeout_set = !Radius_msg_get_attr_int32(msg, RADIUS_ATTR_IDLE_TIMEOUT, &idle_timeout);

	switch (msg->hdr->code)
	{
		case RADIUS_CODE_ACCESS_ACCEPT:
			/* draft-congdon-radius-8021x-22.txt, Ch. 3.17 */
			if (session_timeout_set && termination_action == RADIUS_TERMINATION_ACTION_RADIUS_REQUEST)
			{
				DBGPRINT(RT_DEBUG_TRACE,"AP_REAUTH_TIMEOUT %d seconds \n", session_timeout);
				sta->eapol_sm->reauth_timer.reAuthPeriod =	session_timeout;
			}
			else if (session_timeout_set && (rtapd->conf->session_timeout_set == 1))   // 1 1
			{
				Ap_sta_session_timeout(rtapd, sta, ((session_timeout<rtapd->conf->session_timeout_interval) ? session_timeout : rtapd->conf->session_timeout_interval));
			}
			else if (session_timeout_set )   // 1 0
			{
				Ap_sta_session_timeout(rtapd, sta, session_timeout);
			}
			else if (rtapd->conf->session_timeout_set == 1)   // 0 1
			{
				Ap_sta_session_timeout(rtapd, sta, rtapd->conf->session_timeout_interval);
			}
			else  // 0 0
			{
#ifdef CONFIG_FILS
				if (sta &&
					(sta->auth_alg == WLAN_AUTH_FILS_SK ||
					 sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
					 sta->auth_alg == WLAN_AUTH_FILS_PK)) {
					 free_flag = 0; /* keep it and delete entry by driver */
				} else
#endif /* CONFIG_FILS */
					free_flag = 1;
			}

			sta->eapol_sm->be_auth.aSuccess = TRUE;

			/* Set idle timeout */
			if (idle_timeout_set)
				dot1x_set_IdleTimeoutAction(rtapd, sta, idle_timeout);

			printf("!!!access accept\n");
			ieee802_1x_get_keys(rtapd, sta, msg, req, shared_secret, shared_secret_len);

#if HOTSPOT_R2
			{
				struct wnm_req_data wnmreq;
				struct btm_req_data btmreq;
				u32	session_len = 0;
				char *buf;
				//char tt[] = "https:// remediation-server.R2-testbed.wi-fi.org";
				buf = Radius_msg_get_wfa_attr(msg, RADIUS_VENDOR_ATTR_WFA_REMEDIATION, &wnmreq.req_len);


				if (buf)
				{
					int k = 0;
					wnmreq.ifindex = sta->ApIdx;
					memcpy(wnmreq.peer_mac_addr, sta->addr, 6);

					if ((buf[0] == 0x00) || (buf[0] == 0x01))
					{
						printf("!!found Server Method,%d!!\n", buf[0]);
						if ((wnmreq.req_len-1) != 0)
							memcpy(wnmreq.req, &buf[1], wnmreq.req_len-1);

						wnmreq.req[wnmreq.req_len-1] = buf[0];
						wnmreq.type = 2;
					}
					else
					{
						memcpy(wnmreq.req, buf, wnmreq.req_len);
						wnmreq.type = 0;
					}
					printf("got remediation message,len=%d,type=%d!!\n",wnmreq.req_len, wnmreq.type);
					//for(k=0;k<wnmreq.req_len;k++)
					//	printf("%c", buf[k]);
					//printf("\n");
					//printf("%02x.%02x.%02x.%02x.%02x.%02x\n",wnmreq.req[0],wnmreq.req[1],wnmreq.req[2],wnmreq.req[3],wnmreq.req[4],wnmreq.req[5]);
					if (RT_ioctl(rtapd->ioctl_sock,
								RT_PRIV_IOCTL, (char *)&wnmreq, sizeof(struct wnm_req_data),
					 			rtapd->prefix_wlan_name, sta->ApIdx,
								RT_OID_802_11_WNM_NOTIFY_REQ))
        				DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for ieee802_1x_send remediation url(len=%d)\n", wnmreq.req_len);
					free(buf);
				}

				buf = NULL;
				buf = Radius_msg_get_wfa_attr(msg, RADIUS_VENDOR_ATTR_WFA_DEAUTH, &wnmreq.req_len);

				if (buf)
				{
					int k = 0;
					//u8 auth_delay[2];
					wnmreq.ifindex = sta->ApIdx;
					memcpy(wnmreq.peer_mac_addr, sta->addr, 6);
					//auth_delay[0] = buf[1];
					//buf[1] = buf[2];
					//buf[2] = auth_delay[0];
					memcpy(wnmreq.req, buf, wnmreq.req_len);
					wnmreq.type = 1;
					printf("got deauth imminent notice,len=%d!!\n",wnmreq.req_len);
					//for(k=0;k<wnmreq.req_len;k++)
					//	printf("%c", buf[k]);
					//printf("\n");
					//printf("%02x.%02x.%02x.%02x.%02x.%02x\n",wnmreq.req[0],wnmreq.req[1],wnmreq.req[2],wnmreq.req[3],wnmreq.req[4],wnmreq.req[5]);
					if (RT_ioctl(rtapd->ioctl_sock,
								RT_PRIV_IOCTL, (char *)&wnmreq, sizeof(struct wnm_req_data),
					 			rtapd->prefix_wlan_name, sta->ApIdx,
								RT_OID_802_11_WNM_NOTIFY_REQ))
        				DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for ieee802_1x_send remediation url(len=%d)\n", wnmreq.req_len);
					free(buf);
				}

				buf = NULL;

				printf("wfa session info\n");
                buf = Radius_msg_get_wfa_attr(msg, RADIUS_VENDOR_ATTR_WFA_SESSION_INFO, &session_len);
				if (buf)
				{
					printf("!!!!!got session information len=%d,%d\n", session_len, buf[0]);
					btmreq.ifindex = sta->ApIdx;
					memcpy(btmreq.peer_mac_addr, sta->addr, 6);
					btmreq.req_len = 4+session_len;
					btmreq.req[0] = 0x14; //mode
					btmreq.req[1] = (buf[0]*60*10) & 0xff;
					btmreq.req[2] = ((buf[0]*60*10) >> 8) & 0xff;
					btmreq.req[3] = 200; //valid_interval;
					btmreq.req[4] = session_len-1; //url len
					memcpy(&btmreq.req[5], &buf[1], session_len-1); //url

					if (RT_ioctl(rtapd->ioctl_sock,
								RT_PRIV_IOCTL, (char *)&btmreq, sizeof(struct btm_req_data),
					 			rtapd->prefix_wlan_name, sta->ApIdx,
								RT_OID_802_11_WNM_BTM_REQ))
        				DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for ieee802_1x_send btm url(len=%d)\n", btmreq.req_len);
					free(buf);
				}
#endif
#if HOTSPOT_R3
				buf = NULL;
			 buf = Radius_msg_get_wfa_attr(msg, RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_URL, &wnmreq.req_len);
				if (buf)
				{
					int k = 0;
					wnmreq.ifindex = sta->ApIdx;
					memcpy(wnmreq.peer_mac_addr, sta->addr, 6);

					memcpy(wnmreq.req, buf, wnmreq.req_len);
					wnmreq.type = 3;
					printf("got terms and condition url,len=%d!!\n",wnmreq.req_len);
					if (RT_ioctl(rtapd->ioctl_sock,
								RT_PRIV_IOCTL, (char *)&wnmreq, sizeof(struct wnm_req_data),
								rtapd->prefix_wlan_name, sta->ApIdx,
								RT_OID_802_11_WNM_NOTIFY_REQ))
					DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for ieee802_1x_send terms and condition url (len=%d)\n", wnmreq.req_len);
					free(buf);
				}
			}
#endif
			break;

		case RADIUS_CODE_ACCESS_REJECT:
			DBGPRINT(RT_DEBUG_WARN, "AS send RADIUS_CODE_ACCESS_REJECT\n");
			sta->eapol_sm->be_auth.aFail = TRUE;
			break;

		case RADIUS_CODE_ACCESS_CHALLENGE:
			if (session_timeout_set)
			{
				/* RFC 2869, Ch. 2.3.2
				 * draft-congdon-radius-8021x-22.txt, Ch. 3.17 */
				sta->eapol_sm->be_auth.suppTimeout = session_timeout;
			}
			sta->eapol_sm->be_auth.aReq = TRUE;
			break;
	}

	ieee802_1x_decapsulate_radius(sta);

#ifdef CONFIG_FILS
	if (sta->flags & WLAN_STA_PENDING_FILS_ERP) {
			/* TODO: Add a PMKSA entry on success? */
			ieee802_11_finish_fils_auth(
					rtapd, sta, msg->hdr->code == RADIUS_CODE_ACCESS_ACCEPT);
	}
#endif /* CONFIG_FILS */

	eapol_sm_step(sta->eapol_sm);


	if (free_flag == 1)
		Ap_free_sta(rtapd, sta);
	return RADIUS_RX_QUEUED;
}


/* Handler for EAPOL Backend Authentication state machine sendRespToServer.
 * Forward the EAP Response from Supplicant to Authentication Server. */
void ieee802_1x_send_resp_to_server(rtapd *rtapd, struct sta_info *sta)
{
	ieee802_1x_encapsulate_radius(rtapd, sta, sta->last_eap_supp, sta->last_eap_supp_len);
}

int ieee802_1x_init(rtapd *rtapd)
{
	if (Radius_client_register(rtapd, RADIUS_AUTH, ieee802_1x_receive_auth, NULL))
		return -1;

	return 0;
}

void ieee802_1x_new_auth_session(rtapd *rtapd, struct sta_info *sta)
{
	if (!sta->last_recv_radius)
		return;

	Radius_msg_free(sta->last_recv_radius);
	free(sta->last_recv_radius);
	sta->last_recv_radius = NULL;
}
