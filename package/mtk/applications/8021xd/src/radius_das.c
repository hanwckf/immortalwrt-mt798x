/*
 * RFC 5176
 * RADIUS Dynamic Authorization Server (DAS)
 */

#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "common.h"
#include "eloop.h"
#include "radius.h"
#include "rtdot1x.h"
#include "config.h"

#include "os.h"

#ifdef RADIUS_DAS_SUPPORT

#define DAS_EVENT_REQUIRE_TIMESTAMP 0

static struct radius_msg *radius_das_peer_COA_req(struct apd_data *rtapd,struct radius_msg *msg)
{
	struct radius_msg *reply;
	char *parsing_buf = NULL;
	int result = 0;
	size_t attr_len = 0;
	struct radius_hdr hdr;
	struct sta_info *sta;

	parsing_buf = (u8 *)Radius_msg_get_wfa_attr(msg, RADIUS_VENDOR_ATTR_WFA_HS2_T_AND_C_FILTERING, &attr_len);

	if(parsing_buf) {
		result = *parsing_buf;
		DBGPRINT(RT_DEBUG_ERROR, "Recv DAS_COA_REQUEST, result [%d] COA filtering [%s]\n",result,result?"Enable":"Disable");

		hdr.identifier = Radius_client_get_id(rtapd);
		sta = (struct sta_info *)Ap_get_sta_radius_identifier(rtapd, hdr.identifier);
		if(sta != NULL)
			printf("\033[1;32m %s, %u sta mac "MACSTR"\033[0m\n", __FUNCTION__, __LINE__, MAC2STR(sta->addr));	/* Kyle Debug Print (G) */

		/* reply COA ack to das */
		hdr.identifier = Radius_client_get_id(rtapd);
		reply = Radius_msg_new(RADIUS_CODE_COA_ACK, hdr.identifier);
	} else {
		DBGPRINT(RT_DEBUG_ERROR, "Can't get WFA TandC Filtering Attr in COA Req\n");
		/* reply COA NAK to dac */
		hdr.identifier = Radius_client_get_id(rtapd);
		reply = Radius_msg_new(RADIUS_CODE_COA_NAK, hdr.identifier);
	}

	if (parsing_buf)
		free(parsing_buf);

	return reply;
}

static void radius_das_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct apd_data *rtapd = eloop_ctx;
	struct radius_das_data *das = &rtapd->conf->radius_das;
	u8 buf[1500];
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in sin;
	} from;
	char abuf[50];
	int from_port = 0;
	socklen_t fromlen;
	int len;
	struct radius_msg *msg, *reply = NULL;
	struct radius_hdr *hdr;
	u32 val;
	int res;
	struct timeval now;

	DBGPRINT(RT_DEBUG_ERROR, "!!!!radius_das_receive\n");

	fromlen = sizeof(from);
	len = recvfrom(sock, buf, sizeof(buf), 0,
		       (struct sockaddr *) &from.ss, &fromlen);
	if (len < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "DAS: recvfrom error\n");
		return;
	}

	printf("radius_das_receive!!!!!\n");
	hex_dump("DAS rcv:", buf, len);

	os_strlcpy(abuf, inet_ntoa(from.sin.sin_addr), sizeof(abuf));
	from_port = ntohs(from.sin.sin_port);

	printf("DAS: Received %d bytes from %s:%d\n",
		   len, abuf, from_port);

	if (das->client_addr.s_addr != from.sin.sin_addr.s_addr) {
		printf("DAS: Drop message from unknown client\n");
		return;
	}

	msg = Radius_msg_parse(buf, len);
	if (msg == NULL) {
		printf("DAS: Parsing incoming RADIUS packet "
			   "from %s:%d failed\n", abuf, from_port);
		return;
	}

	gettimeofday(&now,NULL);
	(void)Radius_msg_get_attr(msg, RADIUS_ATTR_EVENT_TIMESTAMP,
				  (u8 *) &val, 4);

	hdr = msg->hdr;

	switch (hdr->code) {
	case RADIUS_CODE_DISCONNECT_REQUEST:
		DBGPRINT(RT_DEBUG_ERROR, "Recv DAS_DISCONNECT_REQUEST (not support now)\n");
		break;
	case RADIUS_CODE_COA_REQUEST:
		DBGPRINT(RT_DEBUG_ERROR, "Recv DAS_COA_REQUEST\n");
		reply = radius_das_peer_COA_req(rtapd, msg);
		if (reply == NULL) {
			printf("DAS: radius_das_peer_COA_req failed\n");
			Radius_msg_free(msg);
			free(msg);
			return;
		}

		break;
	default:
		DBGPRINT(RT_DEBUG_ERROR, "DAS: Unexpected RADIUS code %u in "
			   "packet from %s:%d",
			   hdr->code, abuf, from_port);
	}

	if (reply) {
		DBGPRINT(RT_DEBUG_TRACE, "DAS: Reply to %s:%d\n", abuf, from_port);

		if (!Radius_msg_add_attr_int32(reply,
					       RADIUS_ATTR_EVENT_TIMESTAMP,
					       now.tv_sec)) {
			DBGPRINT(RT_DEBUG_TRACE, "DAS: Failed to add "
				   "Event-Timestamp attribute\n");
		}

		if (Radius_msg_finish_das_rsp(reply, das->shared_secret, das->shared_secret_len, hdr) < 0) {
			DBGPRINT(RT_DEBUG_TRACE, "DAS: Failed to add "
				   "Message-Authenticator attribute\n");
		}

		res = sendto(das->sock, reply->buf, reply->buf_used, 0,
			     (struct sockaddr *) &from.ss, fromlen);
		if (res < 0) {
			DBGPRINT(RT_DEBUG_ERROR, "DAS: sendto(to %s:%d) ERROR\n",
				   abuf, from_port);
		}
	}

	Radius_msg_free(msg);
	free(msg);
	if (reply) {
		Radius_msg_free(reply);
		free(reply);
	}
}

static int radius_das_open_socket(int port)
{
	int s;
	struct sockaddr_in addr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "RADIUS DAS: socket open ERROR\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "RADIUS DAS: bind ERROR\n");
		close(s);
		return -1;
	}

	return s;
}


int radius_das_init(rtapd *rtapd)
{
	struct radius_das_data *das = &rtapd->conf->radius_das;

	if (das == NULL)
		return 1;

	das->require_event_timestamp = DAS_EVENT_REQUIRE_TIMESTAMP;

	das->sock = radius_das_open_socket(das->port);
	if (das->sock < 0) {
		DBGPRINT(RT_DEBUG_ERROR, "open UDP socket for RADIUS DAS failed\n");
		radius_das_deinit(rtapd->conf);
		return 1;
	}
	printf("DAS UP!!!!!!!!!!!!!!!\n");
	printf("!!!!!!!! radius das port = %d, radius das sock = %d\n", das->port, das->sock);
	if (eloop_register_read_sock(das->sock, radius_das_receive, rtapd, NULL))
	{
		radius_das_deinit(rtapd->conf);
		return 1;
	}

	return 0;
}


void radius_das_deinit(struct rtapd_config *conf)
{
	struct radius_das_data *das = &conf->radius_das;
	if (das == NULL)
		return;

	if (das->sock >= 0) {
		//eloop_unregister_sock(das->sock, EVENT_TYPE_READ);
		close(das->sock);
	}

	free(das->shared_secret);
}
/*
void hex_dump(char *str, char *pSrcBufVA, int SrcBufLen)
{

	unsigned char *pt;
	int x;

	if(RTDebugLevel < RT_DEBUG_TRACE)
		return;
	pt = pSrcBufVA;
	printf("%s: %p, len = %d\n", str, pSrcBufVA, SrcBufLen);
	for (x = 0; x < SrcBufLen; x++) {
		if (x % 16 == 0)
			printf("0x%04x : ", x);
		printf("%02x ", ((unsigned char)pt[x]));
		if (x % 16 == 15)
			printf("\n");
	}
	printf("\n");

}*/

#endif /* RADIUS_DAS */

#if 0

static struct radius_msg * radius_das_disconnect(struct radius_das_data *das,
						 struct radius_msg *msg,
						 const char *abuf,
						 int from_port)
{
	struct radius_hdr *hdr;
	struct radius_msg *reply;
	u8 allowed[] = {
		RADIUS_ATTR_USER_NAME,
		RADIUS_ATTR_NAS_IP_ADDRESS,
		RADIUS_ATTR_CALLING_STATION_ID,
		RADIUS_ATTR_NAS_IDENTIFIER,
		RADIUS_ATTR_ACCT_SESSION_ID,
		RADIUS_ATTR_ACCT_MULTI_SESSION_ID,
		RADIUS_ATTR_EVENT_TIMESTAMP,
		RADIUS_ATTR_MESSAGE_AUTHENTICATOR,
		RADIUS_ATTR_CHARGEABLE_USER_IDENTITY,
#ifdef CONFIG_IPV6
		RADIUS_ATTR_NAS_IPV6_ADDRESS,
#endif /* CONFIG_IPV6 */
		0
	};

	u8 err = 1;
	u8 attr;
	enum radius_das_res res;
	struct radius_das_attrs attrs;
	u8 *buf;
	size_t len;
	char tmp[100];
	u8 sta_addr[ETH_ALEN];

	hdr = radius_msg_get_hdr(msg);

	attr = radius_msg_find_unlisted_attr(msg, allowed);
	if (attr) {
		DBGPRINT(RT_DEBUG_TRACE, "DAS: Unsupported attribute %u in "
			   "Disconnect-Request from %s:%d", attr,
			   abuf, from_port);

		goto fail;
	}

	os_memset(&attrs, 0, sizeof(attrs));

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
				    &buf, &len, NULL) == 0) {
		if (len != 4) {
			DBGPRINT(RT_DEBUG_TRACE, "DAS: Invalid NAS-IP-Address from %s:%d",
				   abuf, from_port);

			goto fail;
		}
		attrs.nas_ip_addr = buf;
	}

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_NAS_IDENTIFIER,
				    &buf, &len, NULL) == 0) {
		attrs.nas_identifier = buf;
		attrs.nas_identifier_len = len;
	}

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_CALLING_STATION_ID,
				    &buf, &len, NULL) == 0) {
		if (len >= sizeof(tmp))
			len = sizeof(tmp) - 1;
		os_memcpy(tmp, buf, len);
		tmp[len] = '\0';
		if (hwaddr_aton2(tmp, sta_addr) < 0) {
			DBGPRINT(RT_DEBUG_TRACE, "DAS: Invalid Calling-Station-Id "
				   "'%s' from %s:%d", tmp, abuf, from_port);

			goto fail;
		}
		attrs.sta_addr = sta_addr;
	}

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_USER_NAME,
				    &buf, &len, NULL) == 0) {
		attrs.user_name = buf;
		attrs.user_name_len = len;
	}

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_ACCT_SESSION_ID,
				    &buf, &len, NULL) == 0) {
		attrs.acct_session_id = buf;
		attrs.acct_session_id_len = len;
	}

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_ACCT_MULTI_SESSION_ID,
				    &buf, &len, NULL) == 0) {
		attrs.acct_multi_session_id = buf;
		attrs.acct_multi_session_id_len = len;
	}

	if (radius_msg_get_attr_ptr(msg, RADIUS_ATTR_CHARGEABLE_USER_IDENTITY,
				    &buf, &len, NULL) == 0) {
		attrs.cui = buf;
		attrs.cui_len = len;
	}

	res = das->disconnect(das->ctx, &attrs);
	switch (res) {
	case RADIUS_DAS_NAS_MISMATCH:
		DBGPRINT(RT_DEBUG_TRACE, "DAS: NAS mismatch from %s:%d",
			   abuf, from_port);

		break;
	case RADIUS_DAS_SESSION_NOT_FOUND:
		DBGPRINT(RT_DEBUG_TRACE, "DAS: Session not found for request from "
			   "%s:%d", abuf, from_port);

		break;
	case RADIUS_DAS_MULTI_SESSION_MATCH:
		DBGPRINT(RT_DEBUG_TRACE,
			   "DAS: Multiple sessions match for request from %s:%d",
			   abuf, from_port);

		break;
	case RADIUS_DAS_SUCCESS:
		err = 0;
		break;
	}

fail:
	reply = radius_msg_new(err ? RADIUS_CODE_DISCONNECT_NAK :
			       RADIUS_CODE_DISCONNECT_ACK, hdr->identifier);
	if (reply == NULL)
		return NULL;

	return reply;
}


int radius_msg_verify_das_req(struct radius_msg *msg, const u8 *secret,
			      size_t secret_len,
			      int require_message_authenticator)
{
	const u8 *addr[4];
	size_t len[4];
	u8 zero[MD5_MAC_LEN];
	u8 hash[MD5_MAC_LEN];
	u8 auth[MD5_MAC_LEN], orig[MD5_MAC_LEN];
	u8 orig_authenticator[16];

	struct radius_attr_hdr *attr = NULL, *tmp;
	size_t i;

	os_memset(zero, 0, sizeof(zero));
	addr[0] = (u8 *) msg->hdr;
	len[0] = sizeof(struct radius_hdr) - MD5_MAC_LEN;
	addr[1] = zero;
	len[1] = MD5_MAC_LEN;
	addr[2] = (u8 *) (msg->hdr + 1);
	len[2] = wpabuf_len(msg->buf) - sizeof(struct radius_hdr);
	addr[3] = secret;
	len[3] = secret_len;
	md5_vector(4, addr, len, hash);
	if (os_memcmp_const(msg->hdr->authenticator, hash, MD5_MAC_LEN) != 0)
		return 1;

	for (i = 0; i < msg->attr_used; i++) {
		tmp = radius_get_attr_hdr(msg, i);
		if (tmp->type == RADIUS_ATTR_MESSAGE_AUTHENTICATOR) {
			if (attr != NULL) {
				wpa_printf(MSG_WARNING, "Multiple "
					   "Message-Authenticator attributes "
					   "in RADIUS message");
				return 1;
			}
			attr = tmp;
		}
	}

	if (attr == NULL) {
		if (require_message_authenticator) {
			wpa_printf(MSG_WARNING,
				   "Missing Message-Authenticator attribute in RADIUS message");
			return 1;
		}
		return 0;
	}

	os_memcpy(orig, attr + 1, MD5_MAC_LEN);
	os_memset(attr + 1, 0, MD5_MAC_LEN);
	os_memcpy(orig_authenticator, msg->hdr->authenticator,
		  sizeof(orig_authenticator));
	os_memset(msg->hdr->authenticator, 0,
		  sizeof(msg->hdr->authenticator));
	hmac_md5(secret, secret_len, wpabuf_head(msg->buf),
		 wpabuf_len(msg->buf), auth);
	os_memcpy(attr + 1, orig, MD5_MAC_LEN);
	os_memcpy(msg->hdr->authenticator, orig_authenticator,
		  sizeof(orig_authenticator));

	return os_memcmp_const(orig, auth, MD5_MAC_LEN) != 0;
}

#endif

