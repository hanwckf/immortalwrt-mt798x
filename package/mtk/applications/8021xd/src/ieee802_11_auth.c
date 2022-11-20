/*
 * hostapd / IEEE 802.11 authentication (ACL)
 * Copyright (c) 2003-2009, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * Access control list for IEEE 802.11 authentication can uses statically
 * configured ACL from configuration files or an external RADIUS server.
 * Results from external RADIUS queries are cached to allow faster
 * authentication frame processing.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <linux/if.h>
#include <linux/wireless.h>

#include "rtdot1x.h"
#include "radius.h"
#include "radius_client.h"

#include "eloop.h"
#include "sta_info.h"
#include "ieee802_11_auth.h"

struct hostapd_cached_radius_acl {
	long timestamp;
	macaddr addr;
	int accepted; /* HOSTAPD_ACL_* */
	struct hostapd_cached_radius_acl *next;
	u32 session_timeout;
	u32 acct_interim_interval;
	int vlan_id;
	u8 apIdx; /* Which MBSSID */
};


struct hostapd_acl_query_data {
	long timestamp;
	u8 radius_id;
	macaddr addr;
	u8 apIdx; /* Which MBSSID */
	u8 *auth_msg; /* IEEE 802.11 authentication frame from station */
	size_t auth_msg_len;
	struct hostapd_acl_query_data *next;
};


#ifndef CONFIG_NO_RADIUS
static void hostapd_acl_cache_free(struct hostapd_cached_radius_acl *acl_cache)
{
	struct hostapd_cached_radius_acl *prev;

	while (acl_cache) {
		prev = acl_cache;
		acl_cache = acl_cache->next;
		free(prev);
	}
}


static int hostapd_acl_cache_get(rtapd *hapd, const u8 *addr,
				 u32 *session_timeout,
				 u32 *acct_interim_interval, int *vlan_id, u8 apIdx)
{
	struct hostapd_cached_radius_acl *entry;
	struct timeval now;

	gettimeofday(&now, NULL);
	entry = hapd->acl_cache;

	while (entry) {
		if ((memcmp(entry->addr, addr, ETH_ALEN) == 0) && (entry->apIdx == apIdx)) {
			if (now.tv_sec - entry->timestamp > hapd->conf->AclCacheTimeout[entry->apIdx])
				return -1; /* entry has expired */
			if (entry->accepted == HOSTAPD_ACL_ACCEPT_TIMEOUT)
				if (session_timeout)
					*session_timeout =
						entry->session_timeout;
			if (acct_interim_interval)
				*acct_interim_interval =
					entry->acct_interim_interval;
			if (vlan_id)
				*vlan_id = entry->vlan_id;
			return entry->accepted;
		}

		entry = entry->next;
	}

	return -1;
}
#endif /* CONFIG_NO_RADIUS */


static void hostapd_acl_query_free(struct hostapd_acl_query_data *query)
{
	if (query == NULL)
		return;
	free(query->auth_msg);
	free(query);
}


#ifndef CONFIG_NO_RADIUS
static int hostapd_radius_acl_query(rtapd *hapd, u8 *addr,
				    struct hostapd_acl_query_data *query)
{
	struct radius_msg *msg;
	char buf[128];
	u8 quApIdx = query->apIdx;

	query->radius_id = Radius_client_get_id(hapd);
	msg = Radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, query->radius_id);
	if (msg == NULL)
		return -1;

	Radius_msg_make_authenticator(msg, addr, ETH_ALEN);


	snprintf(buf, sizeof(buf), RADIUS_ADDR_FORMAT, MAC2STR(addr));
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, (u8 *) buf,
				 strlen(buf))) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add User-Name\n");
		goto fail;
	
	}

#if MULTIPLE_RADIUS
	if (!Radius_msg_add_attr_user_password(
		    msg, (u8 *) buf, strlen(buf),
		    hapd->conf->mbss_auth_server[quApIdx]->shared_secret,
		    hapd->conf->mbss_auth_server[quApIdx]->shared_secret_len)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add User-Password\n");
		goto fail;
	}
#else
	 if (!Radius_msg_add_attr_user_password(
                msg, (u8 *) buf, strlen(buf),
		hapd->conf->auth_server->shared_secret,
		hapd->conf->auth_server->shared_secret_len)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add User-Password\n");	
	}	

#endif
	if ( /*hapd->conf->own_ip_addr.af == AF_INET &&*/
	    !Radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
				 (u8 *) &hapd->conf->own_ip_addr, 4)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add NAS-IP-Address\n");
		goto fail;
	}

#if 0
	if (hapd->conf->own_ip_addr.af == AF_INET6 &&
	    !radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IPV6_ADDRESS,
				 (u8 *) &hapd->conf->own_ip_addr.u.v6, 16)) {
		wpa_printf(MSG_DEBUG, "Could not add NAS-IPv6-Address");
		goto fail;
	}
#endif /* CONFIG_IPV6 */

	if ((hapd->conf->nasId_len[quApIdx] > 0) &&
	    !Radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IDENTIFIER,
				 (u8 *) hapd->conf->nasId[quApIdx],
				 hapd->conf->nasId_len[quApIdx])) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add NAS-Identifier\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT ":%s",
		    MAC2STR(hapd->own_addr[quApIdx]), hapd->conf->Ssid[quApIdx]);
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_CALLED_STATION_ID,
				 (u8 *) buf, strlen(buf))) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add Called-Station-Id\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT,
		    MAC2STR(addr));
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID,
				 (u8 *) buf, strlen(buf))) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add Calling-Station-Id\n");
		goto fail;
	}

	if (!Radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT_TYPE,
				       RADIUS_NAS_PORT_TYPE_IEEE_802_11)) {
		DBGPRINT(RT_DEBUG_ERROR, "Could not add NAS-Port-Type\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), "CONNECT 11Mbps 802.11b");
	if (!Radius_msg_add_attr(msg, RADIUS_ATTR_CONNECT_INFO,
				 (u8 *) buf, strlen(buf))) {
	        DBGPRINT(RT_DEBUG_ERROR, "Could not add Connect-Info\n");
		goto fail;
	}
 
	if (Radius_client_send(hapd, msg, RADIUS_AUTH, quApIdx) < 0)
		goto fail;
	return 0;

 fail:
	Radius_msg_free(msg);
	free(msg);
	return -1;
}
#endif /* CONFIG_NO_RADIUS */


/**
 * hostapd_allowed_address - Check whether a specified STA can be authenticated
 * @hapd: hostapd BSS data
 * @addr: MAC address of the STA
 * @msg: Authentication message
 * @len: Length of msg in octets
 * @session_timeout: Buffer for returning session timeout (from RADIUS)
 * @acct_interim_interval: Buffer for returning account interval (from RADIUS)
 * @vlan_id: Buffer for returning VLAN ID
 * Returns: HOSTAPD_ACL_ACCEPT, HOSTAPD_ACL_REJECT, or HOSTAPD_ACL_PENDING
 */
int hostapd_allowed_address(rtapd *hapd, u8 *addr,
			    u8 *apidx, u16 ethertype, int SockNum,		
			    const u8 *msg, size_t len, u32 *session_timeout,
			    u32 *acct_interim_interval, int *vlan_id)
{
	u8 apIdx;
	apIdx = *apidx;

	if (session_timeout)
		*session_timeout = 0;
	if (acct_interim_interval)
		*acct_interim_interval = 0;
	if (vlan_id)
		*vlan_id = 0;


#ifdef CONFIG_NO_RADIUS
	return HOSTAPD_ACL_REJECT;
#else /* CONFIG_NO_RADIUS */
	struct hostapd_acl_query_data *query;
	struct timeval t;

	/* The cache should be consist with driver Cache */
#if 0
	/* Check whether ACL cache has an entry for this station */
	int res = hostapd_acl_cache_get(hapd, addr, session_timeout,
					acct_interim_interval,
					vlan_id, apIdx);
	if (res == HOSTAPD_ACL_ACCEPT ||
	    res == HOSTAPD_ACL_ACCEPT_TIMEOUT)
	{
		DBGPRINT(RT_DEBUG_TRACE, "ACL_ACCEPT: FROM cache\n");
		return res;
	}
	if (res == HOSTAPD_ACL_REJECT) {
		DBGPRINT(RT_DEBUG_TRACE, "ACL_REJECT: FROM cache\n");
		return HOSTAPD_ACL_REJECT;
	}
#endif
	query = hapd->acl_queries;
	while (query) {
		if (memcmp(query->addr, addr, ETH_ALEN) == 0) {
			/* pending query in RADIUS retransmit queue;
			 * do not generate a new one */
			DBGPRINT(RT_DEBUG_TRACE, "ACL_PENDING: Wait Radius Server\n");
			return HOSTAPD_ACL_PENDING;
		}
		query = query->next;
	}

#if MULTIPLE_RADIUS
	if (!hapd->conf->mbss_auth_server[apIdx]) {
		DBGPRINT(RT_DEBUG_ERROR, "ACL_REJECT: ra%d Sever PATH NULL\n", apIdx);
		return HOSTAPD_ACL_REJECT;
	}
#else
	if (!hapd->conf->auth_server) {
		DBGPRINT(RT_DEBUG_ERROR, "ACL_REJECT: ra%d Sever PATH NULL\n", apIdx);
		return HOSTAPD_ACL_REJECT;
	}
#endif
	/* No entry in the cache - query external RADIUS server */
	query = malloc(sizeof(*query));
	if (query) memset(query, 0, sizeof(*query));	
		
	if (query == NULL) {
		DBGPRINT(RT_DEBUG_ERROR, "ACL_REJECT: malloc for query data failed\n");
		return HOSTAPD_ACL_REJECT;
	}
	gettimeofday(&t, NULL);
	query->timestamp = t.tv_sec;
	memcpy(query->addr, addr, ETH_ALEN);
	query->apIdx = apIdx;
	if (hostapd_radius_acl_query(hapd, addr, query)) {
		hostapd_acl_query_free(query);
		DBGPRINT(RT_DEBUG_ERROR, "ACL_REJECT: Failed to send Access-Request for ACL query.\n");
		return HOSTAPD_ACL_REJECT;
	}

	query->next = hapd->acl_queries;
	hapd->acl_queries = query;

	/* Queued data will be processed in hostapd_acl_recv_radius()
	 * when RADIUS server replies to the sent Access-Request. */
	DBGPRINT(RT_DEBUG_TRACE, "ACL_PENDING: Sending Access-Request Now\n");
	return HOSTAPD_ACL_PENDING;
#endif /* CONFIG_NO_RADIUS */

	return HOSTAPD_ACL_REJECT;
}


#ifndef CONFIG_NO_RADIUS
static void hostapd_acl_expire_cache(rtapd *hapd, long now)
{
	struct hostapd_cached_radius_acl *prev, *entry, *tmp;
	char macBuf[MAC_ADDR_LEN];	

	prev = NULL;
	entry = hapd->acl_cache;

	while (entry) {
		if (now - entry->timestamp > hapd->conf->AclCacheTimeout[entry->apIdx]) {
			DBGPRINT(RT_DEBUG_TRACE, "Cached ACL entry for " MACSTR
				   " has expired. [%d]\n", MAC2STR(entry->addr), 
					hapd->conf->AclCacheTimeout[entry->apIdx]);
			if (prev)
				prev->next = entry->next;
			else
				hapd->acl_cache = entry->next;
			/* Notify Driver this Cache has expired */
			memcpy(macBuf, entry->addr, MAC_ADDR_LEN);
			RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, macBuf, MAC_ADDR_LEN, 
				 hapd->prefix_wlan_name, entry->apIdx, RT_OID_802_DOT1X_RADIUS_ACL_DEL_CACHE);

			tmp = entry;
			entry = entry->next;
			free(tmp);
			continue;
		}

		prev = entry;
		entry = entry->next;
	}
}


static void hostapd_acl_expire_queries(rtapd *hapd,
				       long now)
{
	struct hostapd_acl_query_data *prev, *entry, *tmp;

	prev = NULL;
	entry = hapd->acl_queries;

	while (entry) {
		if (now - entry->timestamp > hapd->conf->AclCacheTimeout[entry->apIdx]) {
			DBGPRINT(RT_DEBUG_TRACE, "ACL query for " MACSTR
				   " has expired. [%d]\n", MAC2STR(entry->addr),
					hapd->conf->AclCacheTimeout[entry->apIdx]);
			if (prev)
				prev->next = entry->next;
			else
				hapd->acl_queries = entry->next;

			tmp = entry;
			entry = entry->next;
			hostapd_acl_query_free(tmp);
			continue;
		}

		prev = entry;
		entry = entry->next;
	}
}


/**
 * hostapd_acl_expire - ACL cache expiration callback
 * @eloop_ctx: struct hostapd_data *
 * @timeout_ctx: Not used
 */
static void hostapd_acl_expire(void *eloop_ctx, void *timeout_ctx)
{
	rtapd *hapd = eloop_ctx;
	struct timeval now;

	gettimeofday(&now, NULL);
	hostapd_acl_expire_cache(hapd, now.tv_sec);
	hostapd_acl_expire_queries(hapd, now.tv_sec);
	eloop_register_timeout(10, 0, hostapd_acl_expire, hapd, NULL);
}


/**
 * hostapd_acl_recv_radius - Process incoming RADIUS Authentication messages
 * @msg: RADIUS response message
 * @req: RADIUS request message
 * @shared_secret: RADIUS shared secret
 * @shared_secret_len: Length of shared_secret in octets
 * @data: Context data (struct hostapd_data *)
 * Returns: RADIUS_RX_PROCESSED if RADIUS message was a reply to ACL query (and
 * was processed here) or RADIUS_RX_UNKNOWN if not.
 */
static RadiusRxResult
hostapd_acl_recv_radius(rtapd *hapd, struct radius_msg *msg, struct radius_msg *req,
			u8 *shared_secret, size_t shared_secret_len,
			void *data)
{
	struct hostapd_acl_query_data *query, *prev;
	struct hostapd_cached_radius_acl *cache;
	struct radius_hdr *hdr;
	struct timeval t;

	hdr = msg->hdr;
	query = hapd->acl_queries;
	prev = NULL;
	while (query) {
		if (query->radius_id == hdr->identifier)
			break;
		prev = query;
		query = query->next;
	}
	if (query == NULL)
		return RADIUS_RX_UNKNOWN;

	DBGPRINT(RT_DEBUG_TRACE, "Found matching Access-Request for RADIUS "
		   "message (id=%d)\n", query->radius_id);

	if (Radius_msg_verify(msg, shared_secret, shared_secret_len, req)) {
		DBGPRINT(RT_DEBUG_ERROR, "Incoming RADIUS packet did not have "
			   "correct authenticator - dropped\n");
		return RADIUS_RX_INVALID_AUTHENTICATOR;
	}

	if (hdr->code != RADIUS_CODE_ACCESS_ACCEPT &&
	    hdr->code != RADIUS_CODE_ACCESS_REJECT) {
		DBGPRINT(RT_DEBUG_ERROR,"Unknown RADIUS message code %d to ACL "
			   "query\n", hdr->code);
		return RADIUS_RX_UNKNOWN;
	}

	/* Insert Accept/Reject info into ACL cache */
	cache = malloc(sizeof(*cache));
	if (cache) memset(cache, 0, sizeof(*cache));
	if (cache == NULL) {
		DBGPRINT(RT_DEBUG_ERROR,"Failed to add ACL cache entry\n");
		goto done;
	}
	gettimeofday(&t, NULL);
	cache->timestamp = t.tv_sec;
	cache->apIdx = query->apIdx;
	memcpy(cache->addr, query->addr, sizeof(cache->addr));
	if (hdr->code == RADIUS_CODE_ACCESS_ACCEPT) {
		if (Radius_msg_get_attr_int32(msg, RADIUS_ATTR_SESSION_TIMEOUT,
					      &cache->session_timeout) == 0)
			cache->accepted = HOSTAPD_ACL_ACCEPT_TIMEOUT;
		else
			cache->accepted = HOSTAPD_ACL_ACCEPT;

		if (Radius_msg_get_attr_int32(
			    msg, RADIUS_ATTR_ACCT_INTERIM_INTERVAL,
			    &cache->acct_interim_interval) == 0 &&
		    cache->acct_interim_interval < 60) {
			DBGPRINT(RT_DEBUG_ERROR, "Ignored too small "
				   "Acct-Interim-Interval %d for STA \n" MACSTR,
				   cache->acct_interim_interval,
				   MAC2STR(query->addr));
			cache->acct_interim_interval = 0;
		}
		//YF Todo:
		//cache->vlan_id = radius_msg_get_vlanid(msg);
	} else {
		cache->accepted = HOSTAPD_ACL_REJECT;
	}

	cache->next = hapd->acl_cache;
	hapd->acl_cache = cache;

	/* Notify Driver the New Cache for Auth Frame */
	DBGPRINT(RT_DEBUG_TRACE, "From Radius Sever Result ==> \n STA " MACSTR " --> res %d", MAC2STR(cache->addr), cache->accepted); 

	RT_802_11_ACL_ENTRY newDriverCache;
	memset(&newDriverCache, 0, sizeof(RT_802_11_ACL_ENTRY));
	memcpy(newDriverCache.Addr, cache->addr, MAC_ADDR_LEN);
	newDriverCache.Rsv = cache->accepted;

	RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&newDriverCache, sizeof(RT_802_11_ACL_ENTRY),
		hapd->prefix_wlan_name, cache->apIdx, RT_OID_802_DOT1X_RADIUS_ACL_NEW_CACHE);

 done:
	if (prev == NULL)
		hapd->acl_queries = query->next;
	else
		prev->next = query->next;

	hostapd_acl_query_free(query);

	return RADIUS_RX_PROCESSED;
}
#endif /* CONFIG_NO_RADIUS */


/**
 * hostapd_acl_init: Initialize IEEE 802.11 ACL
 * @hapd: hostapd BSS data
 * Returns: 0 on success, -1 on failure
 */
int hostapd_acl_init(rtapd *hapd)
{
#ifndef CONFIG_NO_RADIUS
	if (Radius_client_register(hapd, RADIUS_AUTH,
				   hostapd_acl_recv_radius, NULL))
		return -1;

	eloop_register_timeout(10, 0, hostapd_acl_expire, hapd, NULL);
#endif /* CONFIG_NO_RADIUS */

	return 0;
}


/**
 * hostapd_acl_deinit - Deinitialize IEEE 802.11 ACL
 * @hapd: hostapd BSS data
 */
void hostapd_acl_deinit(rtapd *hapd)
{
	struct hostapd_acl_query_data *query, *prev;

#ifndef CONFIG_NO_RADIUS
	eloop_cancel_timeout(hostapd_acl_expire, hapd, NULL);

	hostapd_acl_cache_free(hapd->acl_cache);
#endif /* CONFIG_NO_RADIUS */

	query = hapd->acl_queries;
	while (query) {
		prev = query;
		query = query->next;
		hostapd_acl_query_free(prev);
	}
}

