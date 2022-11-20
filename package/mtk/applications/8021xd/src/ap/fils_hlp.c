/*
 * FILS HLP request processing
 * Copyright (c) 2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "common/dhcp.h"
#include "sta_info.h"
#include "fils_hlp.h"
#include "rtdot1x.h"
#include "os.h"
#include "wpabuf.h"
#include "drvcallbak/drv_hook.h"
#include "fils.h"

void fils_hlp_finish_assoc(struct apd_data *hapd, struct sta_info *sta)
{
	u16 reply_res;

	DBGPRINT(RT_DEBUG_OFF, "FILS: Finish association with " MACSTR "\n",
		   MAC2STR(sta->addr));

	eloop_cancel_timeout(fils_hlp_timeout, hapd, sta);
	if (!sta->fils_pending_assoc_req)
		return;

	reply_res = send_assoc_resp(hapd, sta, sta->addr, WLAN_STATUS_SUCCESS,
				    sta->fils_pending_assoc_is_reassoc,
				    sta->fils_pending_assoc_req,
				    sta->fils_pending_assoc_req_len);
	if (reply_res != WLAN_STATUS_SUCCESS)
		DBGPRINT(RT_DEBUG_ERROR, "send_assoc_resp fail! fail reason: %d\n", reply_res)

	if (sta->fils_pending_assoc_req)
		free(sta->fils_pending_assoc_req);

	sta->fils_pending_assoc_req = NULL;
	sta->fils_pending_assoc_req_len = 0;
	wpabuf_free(sta->fils_hlp_resp);
	sta->fils_hlp_resp = NULL;
	wpabuf_free(sta->hlp_dhcp_discover);
	sta->hlp_dhcp_discover = NULL;

	/*
	 * Remove the station in case transmission of a success response fails.
	 * At this point the station was already added associated to the driver.
	 */
	//if (reply_res != WLAN_STATUS_SUCCESS)
	//	hostapd_drv_sta_remove(hapd, sta->addr);
}

static be16 ip_checksum(const void *buf, size_t len)
{
	u32 sum = 0;
	const u16 *pos;

	for (pos = buf; len >= 2; len -= 2)
		sum += ntohs(*pos++);
	if (len)
		sum += ntohs(*pos << 8);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;
	return htons(~sum);
}

static int fils_dhcp_request(rtapd *hapd, struct sta_info *sta,
			     struct dhcp_data *dhcpoffer, u8 *dhcpofferend)
{
	u8 *pos, *end;
	struct dhcp_data *dhcp;
	struct sockaddr_in addr;
	ssize_t res;
	const u8 *server_id = NULL;

	if (!sta->hlp_dhcp_discover) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: No pending HLP DHCPDISCOVER available\n");
		return -1;
	}

	/* Convert to DHCPREQUEST, remove rapid commit option, replace requested
	 * IP address option with yiaddr. */
	pos = wpabuf_mhead(sta->hlp_dhcp_discover);
	end = pos + wpabuf_len(sta->hlp_dhcp_discover);
	dhcp = (struct dhcp_data *) pos;
	pos = (u8 *) (dhcp + 1);
	pos += 4; /* skip magic */
	while (pos < end && *pos != DHCP_OPT_END) {
		u8 opt, olen;

		opt = *pos++;
		if (opt == DHCP_OPT_PAD)
			continue;
		if (pos >= end)
			break;
		olen = *pos++;
		if (olen > end - pos)
			break;

		switch (opt) {
		case DHCP_OPT_MSG_TYPE:
			if (olen > 0)
				*pos = DHCPREQUEST;
			break;
		case DHCP_OPT_RAPID_COMMIT:
		case DHCP_OPT_REQUESTED_IP_ADDRESS:
		case DHCP_OPT_SERVER_ID:
			/* Remove option */
			pos -= 2;
			os_memmove(pos, pos + 2 + olen, end - pos - 2 - olen);
			end -= 2 + olen;
			olen = 0;
			break;
		}
		pos += olen;
	}
	if (pos >= end || *pos != DHCP_OPT_END) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: Could not update DHCPDISCOVER\n");
		return -1;
	}

	sta->hlp_dhcp_discover->used = (pos - (u8 *) dhcp);

	/* Copy Server ID option from DHCPOFFER to DHCPREQUEST */
	pos = (u8 *) (dhcpoffer + 1);
	end = dhcpofferend;
	pos += 4; /* skip magic */
	while (pos < end && *pos != DHCP_OPT_END) {
		u8 opt, olen;

		opt = *pos++;
		if (opt == DHCP_OPT_PAD)
			continue;
		if (pos >= end)
			break;
		olen = *pos++;
		if (olen > end - pos)
			break;

		switch (opt) {
		case DHCP_OPT_SERVER_ID:
			server_id = pos - 2;
			break;
		}
		pos += olen;
	}

	if (wpabuf_resize(&sta->hlp_dhcp_discover,
			  6 + 1 + (server_id ? 2 + server_id[1] : 0)))
		return -1;
	if (server_id)
		wpabuf_put_data(sta->hlp_dhcp_discover, server_id,
				2 + server_id[1]);
	wpabuf_put_u8(sta->hlp_dhcp_discover, DHCP_OPT_REQUESTED_IP_ADDRESS);
	wpabuf_put_u8(sta->hlp_dhcp_discover, 4);
	wpabuf_put_data(sta->hlp_dhcp_discover, &dhcpoffer->your_ip, 4);
	wpabuf_put_u8(sta->hlp_dhcp_discover, DHCP_OPT_END);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = hapd->conf->dhcp_server.u.v4.s_addr;
	addr.sin_port = htons(hapd->conf->dhcp_server_port);
	res = sendto(hapd->dhcp_sock, (const void *)wpabuf_head(sta->hlp_dhcp_discover),
		     wpabuf_len(sta->hlp_dhcp_discover), 0,
		     (const struct sockaddr *) &addr, sizeof(addr));
	if (res < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: DHCP sendto failed: %s\n",
			   strerror(errno));

		/* Close the socket to try to recover from error */
		eloop_unregister_read_sock(hapd->dhcp_sock);
		close(hapd->dhcp_sock);
		hapd->dhcp_sock = -1;

		return -1;
	}
	DBGPRINT(RT_DEBUG_OFF,
		   "FILS: Acting as DHCP rapid commit proxy for %s:%d\n",
		   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	wpabuf_free(sta->hlp_dhcp_discover);
	sta->hlp_dhcp_discover = NULL;
	sta->fils_dhcp_rapid_commit_proxy = 1;
	return 0;
}


static void fils_dhcp_handler(int sd, void *eloop_ctx, void *sock_ctx)
{
	rtapd *hapd = sock_ctx;
	struct sta_info *sta;
	u8 buf[1500], *pos, *end, *end_opt = NULL;
	struct dhcp_data *dhcp;
	struct sockaddr_in addr;
	socklen_t addr_len;
	ssize_t res;
	u8 msgtype = 0;
	int rapid_commit = 0;
	struct iphdr *iph;
	struct udphdr *udph;
	struct wpabuf *resp;
	const u8 *rpos;
	size_t left, len;

	addr_len = sizeof(addr);
	res = recvfrom(sd, buf, sizeof(buf), 0,
		       (struct sockaddr *) &addr, &addr_len);
	if (res < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "FILS: DHCP read failed: %s\n",
			   strerror(errno));
		return;
	}
	DBGPRINT(RT_DEBUG_TRACE, "FILS: DHCP response from server %s:%d (len=%d)\n",
		   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), (int) res);

	hex_dump("FILS: HLP - DHCP server response", buf, res);

	if ((size_t) res < sizeof(*dhcp))
		return;
	dhcp = (struct dhcp_data *) buf;
	if (dhcp->op != 2)
		return; /* Not a BOOTREPLY */
	if (dhcp->relay_ip != hapd->conf->own_ip_addr.s_addr) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: HLP - DHCP response to unknown relay address 0x%x\n",
			   dhcp->relay_ip);
		return;
	}
	dhcp->relay_ip = 0;
	pos = (u8 *) (dhcp + 1);
	end = &buf[res];

	if (end - pos < 4 || WPA_GET_BE32(pos) != DHCP_MAGIC) {
		DBGPRINT(RT_DEBUG_TRACE, "FILS: HLP - no DHCP magic in response\n");
		return;
	}
	pos += 4;

	hex_dump("FILS: HLP - DHCP options in response",
		    pos, end - pos);

	while (pos < end && *pos != DHCP_OPT_END) {
		u8 opt, olen;

		opt = *pos++;
		if (opt == DHCP_OPT_PAD)
			continue;
		if (pos >= end)
			break;
		olen = *pos++;
		if (olen > end - pos)
			break;

		switch (opt) {
		case DHCP_OPT_MSG_TYPE:
			if (olen > 0)
				msgtype = pos[0];
			break;
		case DHCP_OPT_RAPID_COMMIT:
			rapid_commit = 1;
			break;
		}
		pos += olen;
	}
	if (pos < end && *pos == DHCP_OPT_END)
		end_opt = pos;

	DBGPRINT(RT_DEBUG_OFF,
		   "FILS: HLP - DHCP message type %u (rapid_commit=%d hw_addr="
		   MACSTR ")\n",
		   msgtype, rapid_commit, MAC2STR(dhcp->hw_addr));

	sta = Ap_get_sta_instance(hapd, dhcp->hw_addr);
	if (!sta || !sta->fils_pending_assoc_req) {
		DBGPRINT(RT_DEBUG_TRACE,
			   "FILS: No pending HLP DHCP exchange with hw_addr "
			   MACSTR "\n", MAC2STR(dhcp->hw_addr));
		return;
	}

	if (hapd->conf->dhcp_rapid_commit_proxy && msgtype == DHCPOFFER &&
	    !rapid_commit) {
		/* Use hostapd to take care of 4-message exchange and convert
		 * the final DHCPACK to rapid commit version. */
		if (fils_dhcp_request(hapd, sta, dhcp, end) == 0)
			return;
		/* failed, so send the server response as-is */
	} else if (msgtype != DHCPACK) {
		DBGPRINT(RT_DEBUG_TRACE,
			   "FILS: No DHCPACK available from the server and cannot do rapid commit proxying\n");
	}

	pos = buf;
	resp = wpabuf_alloc(2 * ETH_ALEN + 6 + 2 +
			    sizeof(*iph) + sizeof(*udph) + (end - pos) + 2);
	if (!resp)
		return;
	wpabuf_put_data(resp, sta->addr, ETH_ALEN);
	wpabuf_put_data(resp, hapd->own_addr[sta->ApIdx], ETH_ALEN);
	wpabuf_put_data(resp, "\xaa\xaa\x03\x00\x00\x00", 6);
	wpabuf_put_be16(resp, ETH_P_IP);
	iph = wpabuf_put(resp, sizeof(*iph));
	iph->version = 4;
	iph->ihl = sizeof(*iph) / 4;
	iph->tot_len = htons(sizeof(*iph) + sizeof(*udph) + (end - pos));
	iph->ttl = 1;
	iph->protocol = 17; /* UDP */
	iph->saddr = hapd->conf->dhcp_server.u.v4.s_addr;
	iph->daddr = dhcp->client_ip;
	iph->check = ip_checksum(iph, sizeof(*iph));
	udph = wpabuf_put(resp, sizeof(*udph));
	udph->uh_sport = htons(DHCP_SERVER_PORT);
	udph->uh_dport = htons(DHCP_CLIENT_PORT);
	udph->uh_ulen = htons(sizeof(*udph) + (end - pos));
	udph->uh_sum = htons(0x0000); /* TODO: calculate checksum */
	if (hapd->conf->dhcp_rapid_commit_proxy && msgtype == DHCPACK &&
	    !rapid_commit && sta->fils_dhcp_rapid_commit_proxy && end_opt) {
		/* Add rapid commit option */
		wpabuf_put_data(resp, pos, end_opt - pos);
		wpabuf_put_u8(resp, DHCP_OPT_RAPID_COMMIT);
		wpabuf_put_u8(resp, 0);
		wpabuf_put_data(resp, end_opt, end - end_opt);
	} else {
		wpabuf_put_data(resp, pos, end - pos);
	}
	if (wpabuf_resize(&sta->fils_hlp_resp, wpabuf_len(resp) +
			  2 * wpabuf_len(resp) / 255 + 100)) {
		wpabuf_free(resp);
		return;
	}

	rpos = wpabuf_head(resp);
	left = wpabuf_len(resp);

	wpabuf_put_u8(sta->fils_hlp_resp, WLAN_EID_EXTENSION); /* Element ID */
	if (left <= 254)
		len = 1 + left;
	else
		len = 255;
	wpabuf_put_u8(sta->fils_hlp_resp, len); /* Length */
	/* Element ID Extension */
	wpabuf_put_u8(sta->fils_hlp_resp, WLAN_EID_EXT_FILS_HLP_CONTAINER);
	/* Destination MAC Address, Source MAC Address, HLP Packet.
	 * HLP Packet is in MSDU format (i.e., including the LLC/SNAP header
	 * when LPD is used). */
	wpabuf_put_data(sta->fils_hlp_resp, rpos, len - 1);
	rpos += len - 1;
	left -= len - 1;
	while (left) {
		wpabuf_put_u8(sta->fils_hlp_resp, WLAN_EID_FRAGMENT);
		len = left > 255 ? 255 : left;
		wpabuf_put_u8(sta->fils_hlp_resp, len);
		wpabuf_put_data(sta->fils_hlp_resp, rpos, len);
		rpos += len;
		left -= len;
	}
	wpabuf_free(resp);

	fils_hlp_finish_assoc(hapd, sta);
}

static int fils_process_hlp_dhcp(rtapd *hapd,
				 struct sta_info *sta,
				 const u8 *msg, size_t len)
{
	const struct dhcp_data *dhcp;
	struct wpabuf *dhcp_buf;
	struct dhcp_data *dhcp_msg;
	u8 msgtype = 0;
	int rapid_commit = 0;
	const u8 *pos = msg, *end;
	struct sockaddr_in addr;
	ssize_t res;

	if (len < sizeof(*dhcp))
		return 0;
	dhcp = (const struct dhcp_data *) pos;
	end = pos + len;
	DBGPRINT(RT_DEBUG_OFF,
		   "FILS: HLP request DHCP: op=%u htype=%u hlen=%u hops=%u xid=0x%x\n",
		   dhcp->op, dhcp->htype, dhcp->hlen, dhcp->hops,
		   ntohl(dhcp->xid));
	pos += sizeof(*dhcp);
	if (dhcp->op != 1)
		return 0; /* Not a BOOTREQUEST */

	if (end - pos < 4)
		return 0;
	if (WPA_GET_BE32(pos) != DHCP_MAGIC) {
		DBGPRINT(RT_DEBUG_TRACE, "FILS: HLP - no DHCP magic\n");
		return 0;
	}
	pos += 4;

	hex_dump("FILS: HLP - DHCP options", pos, end - pos);
	while (pos < end && *pos != DHCP_OPT_END) {
		u8 opt, olen;

		opt = *pos++;
		if (opt == DHCP_OPT_PAD)
			continue;
		if (pos >= end)
			break;
		olen = *pos++;
		if (olen > end - pos)
			break;

		switch (opt) {
		case DHCP_OPT_MSG_TYPE:
			if (olen > 0)
				msgtype = pos[0];
			break;
		case DHCP_OPT_RAPID_COMMIT:
			rapid_commit = 1;
			break;
		}
		pos += olen;
	}

	DBGPRINT(RT_DEBUG_TRACE, "FILS: HLP - DHCP message type %u\n", msgtype);
	if (msgtype != DHCPDISCOVER)
		return 0;

	if (hapd->conf->dhcp_server.af != AF_INET ||
	    hapd->conf->dhcp_server.u.v4.s_addr == 0) {
		DBGPRINT(RT_DEBUG_TRACE,
			   "FILS: HLP - no DHCPv4 server configured - drop request\n");
		return 0;
	}

	if ((hapd->conf->dhcp_relay_port) &&
		 (hapd->conf->own_ip_addr.s_addr == 0)) {
		DBGPRINT(RT_DEBUG_TRACE,
			   "FILS: HLP - no IPv4 own_ip_addr configured - drop request\n");
		return 0;
	}

	if (hapd->dhcp_sock < 0) {
		int s;

		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0) {
			DBGPRINT(RT_DEBUG_ERROR,
				   "FILS: Failed to open DHCP socket: %s\n",
				   strerror(errno));
			return 0;
		}

		if (hapd->conf->dhcp_relay_port) {
			os_memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = hapd->conf->own_ip_addr.s_addr;
			addr.sin_port = htons(hapd->conf->dhcp_relay_port);

			if (bind(s, (struct sockaddr *) &addr, sizeof(addr))) {
				DBGPRINT(RT_DEBUG_ERROR,
					   "FILS: Failed to bind DHCP socket: %s\n",
					   strerror(errno));
				close(s);
				return 0;
			}
		}

		if (eloop_register_read_sock(s, fils_dhcp_handler, NULL, hapd)) {
			close(s);
			return 0;
		}

		hapd->dhcp_sock = s;
	}

	dhcp_buf = wpabuf_alloc(len);
	if (!dhcp_buf)
		return 0;
	dhcp_msg = wpabuf_put(dhcp_buf, len);
	memcpy(dhcp_msg, msg, len);
	dhcp_msg->relay_ip = hapd->conf->own_ip_addr.s_addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = hapd->conf->dhcp_server.u.v4.s_addr;
	addr.sin_port = htons(hapd->conf->dhcp_server_port);

	DBGPRINT(RT_DEBUG_OFF,
		   "FILS: %d DHCP %s:%d\n", hapd->dhcp_sock,
		   inet_ntoa(addr.sin_addr), ntohs(hapd->conf->dhcp_server_port));

	res = sendto(hapd->dhcp_sock, (const void *)dhcp_msg, len, 0,
		     (const struct sockaddr *) &addr, sizeof(addr));
	if (res < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "%s: DHCP sendto failed: %s\n",
			   __func__, strerror(errno));
		wpabuf_free(dhcp_buf);
		/* Close the socket to try to recover from error */
		eloop_unregister_read_sock(hapd->dhcp_sock);
		close(hapd->dhcp_sock);
		hapd->dhcp_sock = -1;
		hapd->dhcp_server_port_binded = 0;
		return 0;
	}

	DBGPRINT(RT_DEBUG_OFF,
		   "FILS: HLP relayed DHCP request to server %s:%d (rapid_commit=%d)\n",
		   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
		   rapid_commit);

	if (hapd->conf->dhcp_rapid_commit_proxy && rapid_commit) {
		/* Store a copy of the DHCPDISCOVER for rapid commit proxying
		 * purposes if the server does not support the rapid commit
		 * option. */
		DBGPRINT(RT_DEBUG_TRACE,
			   "FILS: Store DHCPDISCOVER for rapid commit proxy\n");
		wpabuf_free(sta->hlp_dhcp_discover);
		sta->hlp_dhcp_discover = dhcp_buf;
	} else {
		wpabuf_free(dhcp_buf);
	}

	return 1;
}


static int fils_process_hlp_udp(rtapd *hapd,
				struct sta_info *sta, const u8 *dst,
				const u8 *pos, size_t len)
{
	const struct iphdr *iph;
	const struct udphdr *udph;
	u16 sport, dport, ulen;

	if (len < sizeof(*iph) + sizeof(*udph))
		return 0;
	iph = (const struct iphdr *) pos;
	udph = (const struct udphdr *) (iph + 1);
	sport = ntohs(udph->uh_sport);
	dport = ntohs(udph->uh_dport);
	ulen = ntohs(udph->uh_ulen);
	DBGPRINT(RT_DEBUG_OFF,
		   "FILS: HLP request UDP: sport=%u dport=%u ulen=%u sum=0x%x\n",
		   sport, dport, ulen, ntohs(udph->uh_sum));
	/* TODO: Check UDP checksum */
	if (ulen < sizeof(*udph) || ulen > len - sizeof(*iph))
		return 0;

	if (dport == DHCP_SERVER_PORT && sport == DHCP_CLIENT_PORT) {
		return fils_process_hlp_dhcp(hapd, sta, (const u8 *) (udph + 1),
					     ulen - sizeof(*udph));
	}

	return 0;
}


static int fils_process_hlp_ip(rtapd *hapd,
			       struct sta_info *sta, const u8 *dst,
			       const u8 *pos, size_t len)
{
	const struct iphdr *iph;
	u16 tot_len;

	if (len < sizeof(*iph))
		return 0;
	iph = (const struct iphdr *) pos;
	if (ip_checksum(iph, sizeof(*iph)) != 0) {
		DBGPRINT(RT_DEBUG_ERROR,
			   "FILS: HLP request IPv4 packet had invalid header checksum - dropped\n");
		return 0;
	}
	tot_len = ntohs(iph->tot_len);
	if (tot_len > len)
		return 0;
	DBGPRINT(RT_DEBUG_TRACE,
		   "FILS: HLP request IPv4: saddr=%08x daddr=%08x protocol=%u\n",
		   iph->saddr, iph->daddr, iph->protocol);
	switch (iph->protocol) {
	case 17:
		return fils_process_hlp_udp(hapd, sta, dst, pos, len);
	}

	return 0;
}


static int fils_process_hlp_req(rtapd *hapd,
				struct sta_info *sta,
				const u8 *pos, size_t len)
{
	const u8 *pkt, *end;

	DBGPRINT(RT_DEBUG_TRACE,"FILS: HLP request from " MACSTR " (dst=" MACSTR
		   " src=" MACSTR " len=%u)\n",
		   MAC2STR(sta->addr), MAC2STR(pos), MAC2STR(pos + ETH_ALEN),
		   (unsigned int) len);
	if (os_memcmp(sta->addr, pos + ETH_ALEN, ETH_ALEN) != 0) {
		DBGPRINT(RT_DEBUG_TRACE,
			   "FILS: Ignore HLP request with unexpected source address"
			   MACSTR, MAC2STR(pos + ETH_ALEN));
		return 0;
	}

	end = pos + len;
	pkt = pos + 2 * ETH_ALEN;
	if (end - pkt >= 6 &&
	    os_memcmp(pkt, "\xaa\xaa\x03\x00\x00\x00", 6) == 0)
		pkt += 6; /* Remove SNAP/LLC header */

	//wpa_hexdump(MSG_MSGDUMP, "FILS: HLP request packet", pkt, end - pkt);

	if (end - pkt < 2)
		return 0;

	switch (WPA_GET_BE16(pkt)) {
	case ETH_P_IP:
		return fils_process_hlp_ip(hapd, sta, pos, pkt + 2,
					   end - pkt - 2);
	}

	return 0;
}


int fils_process_hlp(rtapd *hapd, struct sta_info *sta,
		     const u8 *pos, int left)
{
	const u8 *end = pos + left;
	u8 *tmp, *tmp_pos;
	int ret = 0;

	/* Old DHCPDISCOVER is not needed anymore, if it was still pending */
	wpabuf_free(sta->hlp_dhcp_discover);
	sta->hlp_dhcp_discover = NULL;
	sta->fils_dhcp_rapid_commit_proxy = 0;

	/* Check if there are any FILS HLP Container elements */
	while (end - pos >= 2) {
		if (2 + pos[1] > end - pos)
			return 0;
		if (pos[0] == WLAN_EID_EXTENSION &&
		    pos[1] >= 1 + 2 * ETH_ALEN &&
		    pos[2] == WLAN_EID_EXT_FILS_HLP_CONTAINER)
			break;
		pos += 2 + pos[1];
	}
	if (end - pos < 2)
		return 0; /* No FILS HLP Container elements */

	tmp = (u8 *)os_malloc(end - pos);
	if (!tmp)
		return 0;

	while (end - pos >= 2) {
		if (2 + pos[1] > end - pos ||
		    pos[0] != WLAN_EID_EXTENSION ||
		    pos[1] < 1 + 2 * ETH_ALEN ||
		    pos[2] != WLAN_EID_EXT_FILS_HLP_CONTAINER)
			break;
		tmp_pos = tmp;
		os_memcpy(tmp_pos, pos + 3, pos[1] - 1);
		tmp_pos += pos[1] - 1;
		pos += 2 + pos[1];

		/* Add possible fragments */
		while (end - pos >= 2 && pos[0] == WLAN_EID_FRAGMENT &&
		       2 + pos[1] <= end - pos) {
			os_memcpy(tmp_pos, pos + 2, pos[1]);
			tmp_pos += pos[1];
			pos += 2 + pos[1];
		}

		if (fils_process_hlp_req(hapd, sta, tmp, tmp_pos - tmp) > 0)
			ret = 1;
	}

	os_free(tmp);

	return ret;
}

void fils_hlp_timeout(void *eloop_ctx, void *eloop_data)
{
	struct apd_data *hapd = eloop_ctx;
	struct sta_info *sta = eloop_data;

	DBGPRINT(RT_DEBUG_OFF,
		   "FILS: HLP response timeout - continue with association response for "
		   MACSTR "\n", MAC2STR(sta->addr));

	fils_hlp_finish_assoc(hapd, sta);
}

void fils_hlp_deinit(rtapd *hapd)
{
	if (hapd->dhcp_sock >= 0) {
		eloop_unregister_read_sock(hapd->dhcp_sock);
		close(hapd->dhcp_sock);
		hapd->dhcp_sock = -1;
	}
}
