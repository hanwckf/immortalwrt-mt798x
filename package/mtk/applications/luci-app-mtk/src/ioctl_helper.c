#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/wireless.h>
#include <lua.h>							   /* Always include this */
#include <lauxlib.h>						   /* Always include this */
#include <lualib.h>							/* Always include this */

#define PACKED  __attribute__ ((packed))
#define USHORT  unsigned short
#define UCHAR   unsigned char
#define UCHAR   unsigned char
typedef struct PACKED _WSC_CONFIGURED_VALUE {
	USHORT WscConfigured; // 1 un-configured; 2 configured
	UCHAR   WscSsid[32 + 1];
	USHORT WscAuthMode; // mandatory, 0x01: open, 0x02: wpa-psk, 0x04: shared, 0x08:wpa, 0x10: wpa2, 0x
	USHORT  WscEncrypType;  // 0x01: none, 0x02: wep, 0x04: tkip, 0x08: aes
	UCHAR   DefaultKeyIdx;
	UCHAR   WscWPAKey[64 + 1];
}WSC_CONFIGURED_VALUE;

typedef struct PACKED _NDIS80211SSID
{
	unsigned int	SsidLength;   // length of SSID field below, in bytes;
								  // this can be zero.
	unsigned char   Ssid[32]; // SSID information field
} NDIS80211SSID;

// WSC configured credential
typedef struct  _WSC_CREDENTIAL
{
	NDIS80211SSID	SSID;			   // mandatory
	USHORT			  AuthType;		   // mandatory, 1: open, 2: wpa-psk, 4: shared, 8:wpa, 0x10: wpa2, 0x20: wpa-psk2
	USHORT			  EncrType;		   // mandatory, 1: none, 2: wep, 4: tkip, 8: aes
	UCHAR			   Key[64];			// mandatory, Maximum 64 byte
	USHORT			  KeyLength;
	UCHAR			   MacAddr[6];		 // mandatory, AP MAC address
	UCHAR			   KeyIndex;		   // optional, default is 1
	UCHAR			   Rsvd[3];			// Make alignment
}   WSC_CREDENTIAL, *PWSC_CREDENTIAL;

// WSC configured profiles
typedef struct  _WSC_PROFILE
{
#ifndef UINT
#define UINT	unsigned int
#endif
	UINT		   	ProfileCnt;
	UINT		ApplyProfileIdx;  // add by johnli, fix WPS test plan 5.1.1
	WSC_CREDENTIAL  	Profile[8];			 // Support up to 8 profiles
}   WSC_PROFILE, *PWSC_PROFILE;

typedef union _MACHTTRANSMIT_SETTING {
	struct  {
		unsigned short  MCS:6;  // MCS
		unsigned short  rsv:1;
		unsigned short  BW:2;   //channel bandwidth 20MHz or 40 MHz
		unsigned short  ShortGI:1;
		unsigned short  STBC:1; //SPACE
		unsigned short  eTxBF:1;
		unsigned short  iTxBF:1;
		unsigned short  MODE:3; // Use definition MODE_xxx.
	} field;
	unsigned short      word;
} MACHTTRANSMIT_SETTING;

typedef struct _RT_802_11_MAC_ENTRY {
	unsigned char           ApIdx;
	unsigned char           Addr[6];
	unsigned char           Aid;
	unsigned char           Psm;     // 0:PWR_ACTIVE, 1:PWR_SAVE
	unsigned char           MimoPs;  // 0:MMPS_STATIC, 1:MMPS_DYNAMIC, 3:MMPS_Enabled
	signed char             AvgRssi0;
	signed char             AvgRssi1;
	signed char             AvgRssi2;
	signed char             AvgRssi3;
	unsigned int            ConnectedTime;
	MACHTTRANSMIT_SETTING   TxRate;
	unsigned int            LastRxRate;
	short                   StreamSnr[3];
	short                   SoundingRespSnr[3];
#if 0
	short                   TxPER;
	short                   reserved;
#endif
} RT_802_11_MAC_ENTRY;

#define MAX_NUMBER_OF_MAC               554

typedef struct _RT_802_11_MAC_TABLE {
	unsigned long            Num;
	RT_802_11_MAC_ENTRY      Entry[MAX_NUMBER_OF_MAC]; //MAX_LEN_OF_MAC_TABLE = 32
} RT_802_11_MAC_TABLE;

#define IF_NAMESIZE	 16
#define SIOCIWFIRSTPRIV	0x8BE0
#define RTPRIV_IOCTL_WSC_PROFILE			(SIOCIWFIRSTPRIV + 0x12)
#define RT_PRIV_IOCTL				(SIOCIWFIRSTPRIV + 0x0E)
#define OID_GEN_MEDIA_CONNECT_STATUS				0x060B
#define RT_OID_802_11_WSC_QUERY_PROFILE				0x0750
#define RT_OID_APCLI_WSC_PIN_CODE			0x074A

#define RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT	(SIOCIWFIRSTPRIV + 0x1F)

/* for WPS --YY  */
#define RT_OID_SYNC_RT61							0x0D010750
#define RT_OID_WSC_QUERY_STATUS					 ((RT_OID_SYNC_RT61 + 0x01) & 0xffff)
#define RT_OID_WSC_PIN_CODE							((RT_OID_SYNC_RT61 + 0x02) & 0xffff)
#if defined (RT2860_APCLI_SUPPORT) || defined (RTDEV_APCLI_SUPPORT)
#define RT_OID_APCLI_WSC_PIN_CODE			0x074A
#endif
#define OID_GET_WMODE	0x099E
#define RTPRIV_IOCTL_GSITESURVEY                                        (SIOCIWFIRSTPRIV + 0x0D)

int getCurrentWscProfile(lua_State *L);
int getApPin(lua_State *L);
int get_macaddr(lua_State *L);
int apcli_get_wps_status(lua_State *L);
int apcli_wps_get_pincode(lua_State *L);
int convert_string_display(lua_State *L);
int StaInfo(lua_State *L);
int getWMOde(lua_State *L);
int scanResult(lua_State *L);

int luaopen_ioctl_helper(lua_State *L)
{
	lua_register(L,"c_getCurrentWscProfile",getCurrentWscProfile);
	lua_register(L,"c_getApPin",getApPin);
	lua_register(L,"c_get_macaddr",get_macaddr);
	lua_register(L,"c_apcli_get_wps_status",apcli_get_wps_status);
	lua_register(L,"c_apcli_wps_get_pincode",apcli_wps_get_pincode);
	lua_register(L,"c_convert_string_display",convert_string_display);
	lua_register(L,"c_StaInfo",StaInfo);
	lua_register(L,"c_getWMode",getWMOde);
	lua_register(L,"c_scanResult",scanResult);
	return 0;
}

int scanResult(lua_State *L)
{
	int socket_id;
	const char *interface = luaL_checkstring(L, 1);
	const char *tmp_idx = luaL_checkstring(L, 2);
	struct iwreq wrq;
	char *data = NULL;
	unsigned int data_len = 5000;

	if((data = (char *)malloc(data_len)) == NULL){
		fprintf(stderr, "%s: malloc failed\n", __func__);
		return -1;
	}
	memset(data, 0, data_len);
	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_id < 0) {
		perror("socket() failed");
		free(data);
		return socket_id;
	}

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	snprintf(data, data_len, "%s", tmp_idx);
	wrq.u.data.length = data_len;
	wrq.u.data.pointer = (caddr_t)data;
	wrq.u.data.flags = 0;
	if (ioctl(socket_id, RTPRIV_IOCTL_GSITESURVEY, &wrq) < 0) {
		fprintf(stderr, "ioctl -> RTPRIV_IOCTL_GSITESURVEY Fail !");
		close(socket_id);
		free(data);
		return -1;
	}
	lua_newtable(L);
	lua_pushstring(L, "scanresult");  /* push key */
	lua_pushstring(L, data);  /* push value */
	lua_settable(L, -3);
	close(socket_id);
	free(data);

	return 1;
}

static unsigned int get_ap_pin(const char *interface)
{
	int socket_id;
	struct iwreq wrq;
	unsigned int data = 0;
	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_id < 0) {
		perror("socket() failed");
		return socket_id;
	}

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) &data;
	wrq.u.data.flags = RT_OID_WSC_PIN_CODE;
	if( ioctl(socket_id, RT_PRIV_IOCTL, &wrq) == -1)
		fprintf(stderr, "%s: ioctl fail\n", __func__);
	close(socket_id);

	return data;
}

static unsigned int get_w_mode(const char *interface)
{
	int socket_id;
	struct iwreq wrq;
	unsigned char data = 0;
	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_id < 0) {
		perror("socket() failed");
		return socket_id;
	}

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) &data;
	wrq.u.data.flags = OID_GET_WMODE;
	if( ioctl(socket_id, RT_PRIV_IOCTL, &wrq) == -1)
		fprintf(stderr, "%s: ioctl fail\n", __func__);
	close(socket_id);

	return data;
}

void getWPSAuthMode(WSC_CONFIGURED_VALUE *result, char *ret_str, size_t size)
{
	if(result->WscAuthMode & 0x1)
		strncat(ret_str, "Open", size - 1);
	if(result->WscAuthMode & 0x2)
		strncat(ret_str, "WPA-PSK", size - 1);
	if(result->WscAuthMode & 0x4)
		strncat(ret_str, "Shared", size - 1);
	if(result->WscAuthMode & 0x8)
		strncat(ret_str, "WPA", size - 1);
	if(result->WscAuthMode & 0x10)
		strncat(ret_str, "WPA2", size - 1);
	if(result->WscAuthMode & 0x20)
		strncat(ret_str, "WPA2-PSK", size - 1);
}

void getWPSEncrypType(WSC_CONFIGURED_VALUE *result, char *ret_str, size_t size)
{
	if(result->WscEncrypType & 0x1)
		strncat(ret_str, "None", size - 1);
	if(result->WscEncrypType & 0x2)
		strncat(ret_str, "WEP", size - 1);
	if(result->WscEncrypType & 0x4)
		strncat(ret_str, "TKIP", size - 1);
	if(result->WscEncrypType & 0x8)
		strncat(ret_str, "AES", size - 1);
}

/*
 *  * these definitions are from rt2860v2 driver include/wsc.h
 *   */
char *getWscStatusStr(int status)
{
	switch(status){
	case 0:
		return "Not used";
	case 1:
		return "Idle";
	case 2:
		return "WSC Fail(Ignore this if Intel/Marvell registrar used)";
	case 3:
		return "Start WSC Process";
	case 4:
		return "Received EAPOL-Start";
	case 5:
		return "Sending EAP-Req(ID)";
	case 6:
		return "Receive EAP-Rsp(ID)";
	case 7:
		return "Receive EAP-Req with wrong WSC SMI Vendor Id";
	case 8:
		return "Receive EAPReq with wrong WSC Vendor Type";
	case 9:
		return "Sending EAP-Req(WSC_START)";
	case 10:
		return "Send M1";
	case 11:
		return "Received M1";
	case 12:
		return "Send M2";
	case 13:
		return "Received M2";
	case 14:
		return "Received M2D";
	case 15:
		return "Send M3";
	case 16:
		return "Received M3";
	case 17:
		return "Send M4";
	case 18:
		return "Received M4";
	case 19:
		return "Send M5";
	case 20:
		return "Received M5";
	case 21:
		return "Send M6";
	case 22:
		return "Received M6";
	case 23:
		return "Send M7";
	case 24:
		return "Received M7";
	case 25:
		return "Send M8";
	case 26:
		return "Received M8";
	case 27:
		return "Processing EAP Response (ACK)";
	case 28:
		return "Processing EAP Request (Done)";
	case 29:
		return "Processing EAP Response (Done)";
	case 30:
		return "Sending EAP-Fail";
	case 31:
		return "WSC_ERROR_HASH_FAIL";
	case 32:
		return "WSC_ERROR_HMAC_FAIL";
	case 33:
		return "WSC_ERROR_DEV_PWD_AUTH_FAIL";
	case 34:
		return "Configured";
	case 35:
		return "SCAN AP";
	case 36:
		return "EAPOL START SENT";
	case 37:
		return "WSC_EAP_RSP_DONE_SENT";
	case 38:
		return "WAIT PINCODE";
	case 39:
		return "WSC_START_ASSOC";
	case 0x101:
		return "PBC:TOO MANY AP";
	case 0x102:
		return "PBC:NO AP";
	case 0x103:
		return "EAP_FAIL_RECEIVED";
	case 0x104:
		return "EAP_NONCE_MISMATCH";
	case 0x105:
		return "EAP_INVALID_DATA";
	case 0x106:
		return "PASSWORD_MISMATCH";
	case 0x107:
		return "EAP_REQ_WRONG_SMI";
	case 0x108:
		return "EAP_REQ_WRONG_VENDOR_TYPE";
	case 0x109:
		return "PBC_SESSION_OVERLAP";
	default:
		return "Unknown";
	}
}

int getWscStatus(const char *interface)
{
	int socket_id;
	struct iwreq wrq;
	int data = 0;
	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_id < 0) {
		perror("socket() failed");
		return socket_id;
	}

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) &data;
	wrq.u.data.flags = RT_OID_WSC_QUERY_STATUS;
	if( ioctl(socket_id, RT_PRIV_IOCTL, &wrq) == -1)
	{
		fprintf(stderr, "%s: ioctl fail\n", __func__);
	}
	close(socket_id);


	return data;
}

int get_macaddr(lua_State *L)
{
	const char *ifname = luaL_checkstring(L, 1);
	struct ifreq ifr;
	char *ptr;
	int skfd;
	static char if_hw[18] = {0};

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		//printf(stderr, "%s: open socket error\n", __func__);
		return skfd;
	}
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", ifname);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		close(skfd);
		fprintf(stderr, "%s: ioctl fail\n", __func__);
		return -1;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	sprintf(if_hw, "%02X:%02X:%02X:%02X:%02X:%02X",
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
	close(skfd);

	lua_newtable(L);
	lua_pushstring(L, "macaddr");  /* push key */
	lua_pushstring(L, if_hw);  /* push value */
	lua_settable(L, -3);
	/* Returning one table which is already on top of Lua stack. */
	return 1;
}

int getApPin(lua_State *L)
{
	char new_pin[9];
	const char *interface = luaL_checkstring(L, 1);
	snprintf(new_pin, sizeof(new_pin), "%08d", get_ap_pin(interface));
	//printf("{\"genpincode\":\"%s\"}", new_pin);
	lua_newtable(L);
	lua_pushstring(L, "genpincode");  /* push key */
	lua_pushstring(L, new_pin);  /* push value */
	lua_settable(L, -3);
	/* Returning one table which is already on top of Lua stack. */
	return 1;
}

int getWMOde(lua_State *L)
{
	char w_mode[5];
	const char *interface = luaL_checkstring(L, 1);
	snprintf(w_mode, sizeof(w_mode), "%d", get_w_mode(interface));
	lua_newtable(L);
	lua_pushstring(L, "getwmode");  /* push key */
	lua_pushstring(L, w_mode);  /* push value */
	lua_settable(L, -3);
	/* Returning one table which is already on top of Lua stack. */
	return 1;
}

int getCurrentWscProfile(lua_State *L)
{
	int status, WscResult = 0;
	char tmp_str[128];
	int socket_id;
	struct iwreq wrq;
	const char *interface = luaL_checkstring(L, 1);
	WSC_CONFIGURED_VALUE *data;
	if((data = (WSC_CONFIGURED_VALUE *)malloc(sizeof(WSC_CONFIGURED_VALUE))) == NULL){
		fprintf(stderr, "%s: malloc failed\n", __func__);
		return -1;
	}

	if ((socket_id = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		fprintf(stderr, "%s: Unable to open a socket\n", __func__);
		free(data);
		return -1;
	}
	snprintf((char *)data, sizeof(WSC_CONFIGURED_VALUE), "%s", "get_wsc_profile");
	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	wrq.u.data.length = sizeof( WSC_CONFIGURED_VALUE);
	wrq.u.data.pointer = data;
	wrq.u.data.flags = 0;
	if (ioctl(socket_id, RTPRIV_IOCTL_WSC_PROFILE, &wrq) < 0) {
		fprintf(stderr, "ioctl -> RTPRIV_IOCTL_WSC_PROFILE Fail !");
		close(socket_id);
		free(data);
		return -1;
	}

	lua_newtable(L);
	lua_pushstring(L, "Conf");  /* push key */
	lua_pushnumber(L, data->WscConfigured);  /* push value */
	lua_settable(L, -3);

	lua_pushstring(L, "SSID");  /* push key */
	lua_pushstring(L, (char *)data->WscSsid);  /* push value */
	lua_settable(L, -3);

	lua_pushstring(L, "DefKey");  /* push key */
	lua_pushnumber(L, data->DefaultKeyIdx);  /* push value */
	lua_settable(L, -3);

	//WPSAuthMode
	tmp_str[0] = '\0';
	getWPSAuthMode(data, tmp_str, 128);
	lua_pushstring(L, "AuthMode");  /* push key */
	lua_pushstring(L, tmp_str);  /* push value */
	lua_settable(L, -3);

	//EncrypType
	tmp_str[0] = '\0';
	getWPSEncrypType(data, tmp_str, 128);
	lua_pushstring(L, "EncType");  /* push key */
	lua_pushstring(L, tmp_str);  /* push value */
	lua_settable(L, -3);

	lua_pushstring(L, "WscWPAKey");  /* push key */
	lua_pushstring(L, (char *)data->WscWPAKey);  /* push value */
	lua_settable(L, -3);

	//7. WSC Status
	status = getWscStatus(interface);
	lua_pushstring(L, "WscStatus");  /* push key */
	lua_pushstring(L, getWscStatusStr(status));  /* push value */
	lua_settable(L, -3);

	//8. WSC Result
	if (status == 0x2 || status == 0x109)
		WscResult = -1;
	else if (status == 34)
		WscResult = 1;

	lua_pushstring(L, "WscResult");  /* push key */
	lua_pushnumber(L, WscResult);  /* push value */
	lua_settable(L, -3);

	close(socket_id);
	/* Returning one table which is already on top of Lua stack. */
	return 1;
}

int getWscProfile(const char *interface, WSC_PROFILE *wsc_profile)
{
	int socket_id;
	struct iwreq wrq;

	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_id < 0) {
		perror("socket() failed");
		return socket_id;
	}

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	wrq.u.data.length = sizeof(WSC_PROFILE);
	wrq.u.data.pointer = (caddr_t) wsc_profile;
	wrq.u.data.flags = RT_OID_802_11_WSC_QUERY_PROFILE;
	if( ioctl(socket_id, RT_PRIV_IOCTL, &wrq) == -1){
		fprintf(stderr, "ioctl error\n");
		close(socket_id);
		return -1;
	}
	close(socket_id);

	return 0;
}

int OidQueryInformation(unsigned long OidQueryCode, int socket_id, const char *DeviceName, void *ptr, unsigned long PtrLength)
{
	struct iwreq wrq;

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", DeviceName);
	wrq.u.data.length = PtrLength;
	wrq.u.data.pointer = (caddr_t) ptr;
	wrq.u.data.flags = OidQueryCode;

	return (ioctl(socket_id, RT_PRIV_IOCTL, &wrq));
}

static unsigned int apcli_get_pincode_ioctl(const char *interface)
{
	int socket_id;
	struct iwreq wrq;
	unsigned int data = 0;
	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_id < 0) {
		perror("socket() failed");
		return socket_id;
	}

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	wrq.u.data.length = sizeof(data);
	wrq.u.data.pointer = (caddr_t) &data;
	wrq.u.data.flags = RT_OID_APCLI_WSC_PIN_CODE;
	if( ioctl(socket_id, RT_PRIV_IOCTL, &wrq) == -1)
		fprintf(stderr, "RT_PRIV_IOCTL ioctl error");
	close(socket_id);

	return data;
}

int apcli_wps_get_pincode(lua_State *L)
{
	char new_pin[9];

	const char *interface = luaL_checkstring(L, 1);
	lua_newtable(L);

	snprintf(new_pin, sizeof(new_pin), "%08d", apcli_get_pincode_ioctl(interface));

	lua_pushstring(L, "getpincode");  /* push key */
	lua_pushstring(L, new_pin);  /* push value */
	lua_settable(L, -3);

	return 1;
}

int port_secured(const char *ifname)
{
	int s;
	unsigned int ConnectStatus = 0;

	if (ifname == NULL)
		return -1;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket() failed");
		return s;
	}

	if (OidQueryInformation(OID_GEN_MEDIA_CONNECT_STATUS, s, ifname, &ConnectStatus, sizeof(ConnectStatus)) < 0) {
		fprintf(stderr, "Query OID_GEN_MEDIA_CONNECT_STATUS error!");
		close(s);
		return -1;
	}
	close(s);
	if (ConnectStatus == 1)
		return 1;
	else
		return 0;
}

int convert_string_display(lua_State *L)
{
#define BUF_SIZE	199
	int  len, i;
	char buffer[BUF_SIZE];		// 33(characters in SSID) * 6(maximum length of a HTML entity)  = 198 + 1(null character) = 199
	char *pOut,*pBufLimit;
	const char *str = luaL_checkstring(L, 1);

	memset(buffer,0,BUF_SIZE);
	len = strlen(str);
	pOut = &buffer[0];
	pBufLimit = &buffer[BUF_SIZE - 1];
	for (i = 0; i < len && (pBufLimit - pOut) >=7; i++) { // 6(maximum length of a HTML entity) + 1(null character) = 7
		switch (str[i]) {
		case 38:
			strncpy(pOut, "&amp;", BUF_SIZE - 1);		// '&'
			pOut += 5;
			break;

		case 60:
			strncpy(pOut, "&lt;", BUF_SIZE - 1);		// '<'
			pOut += 4;
			break;

		case 62:
			strncpy(pOut, "&gt;", BUF_SIZE - 1);		// '>'
			pOut += 4;
			break;

		case 34:
			strncpy(pOut, "&#34;", BUF_SIZE - 1);		// '"'
			pOut += 5;
			break;

		case 39:
			strncpy(pOut, "&#39;", BUF_SIZE - 1);		// '''
			pOut += 5;
			break;
		case 32:
			strncpy(pOut, "&nbsp;", BUF_SIZE - 1);	// ' '
			pOut += 6;
			break;

		default:
			if ((str[i]>=0) && (str[i]<=31)) {
				//Device Control Characters
				sprintf(pOut, "&#%02d;", str[i]);
				pOut += 5;
			} else if ((str[i]==39) || (str[i]==47) || (str[i]==59) || (str[i]==92)) {
				// ' / ; (backslash)
				sprintf(pOut, "&#%02d;", str[i]);
				pOut += 5;
			} else if (str[i]>=127) {
				//Device Control Characters
				sprintf(pOut, "&#%03d;", str[i]);
				pOut += 6;
			} else {
				*pOut = str[i];
				pOut++;
			}
			break;
		}
	}
	*pOut = '\0';
	lua_newtable(L);
	lua_pushstring(L, "output");  /* push key */
	lua_pushstring(L, buffer);  /* push value */
	lua_settable(L, -3);
	return 1;
}

int StaInfo(lua_State *L)
{
	int i, s;
	struct iwreq iwr;
	RT_802_11_MAC_TABLE *table;
	char tmpBuff[128];
	char *phyMode[12] = {"CCK", "OFDM", "MM", "GF", "VHT", "HE",
		"HE5G", "HE2G", "HE_SU", "HE_EXT_SU", "HE_TRIG", "HE_MU"};
	const char *interface = luaL_checkstring(L, 1);

	table = (RT_802_11_MAC_TABLE *)calloc(1, sizeof(RT_802_11_MAC_TABLE));
	if (!table)
		return -ENOMEM;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	snprintf(iwr.ifr_name, IFNAMSIZ, "%s", interface);

	iwr.u.data.pointer = (caddr_t) &table;

	if (s < 0) {
		free(table);
		return 0;
	}

	if (ioctl(s, RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT, &iwr) < 0) {
		free(table);
		close(s);
		return 0;
	}

	close(s);


	/* Creates parent table of size table.Num array elements: */
	lua_createtable(L, table->Num, 0);

	for (i = 0; i < table->Num; i++) {

		lua_pushnumber(L, i);

		RT_802_11_MAC_ENTRY *pe = &(table->Entry[i]);
		unsigned int lastRxRate = pe->LastRxRate;
		unsigned int mcs = pe->LastRxRate & 0x7F;
		unsigned int vht_nss;
		unsigned int vht_mcs = pe->TxRate.field.MCS;
		unsigned int vht_nss_r;
		unsigned int vht_mcs_r = pe->LastRxRate & 0x3F;
		int hr, min, sec;

		hr = pe->ConnectedTime/3600;
		min = (pe->ConnectedTime % 3600)/60;
		sec = pe->ConnectedTime - hr*3600 - min*60;

		 /*Creates first child table of size 28 non-array elements: */
		lua_createtable(L, 0, 28);

		// MAC Address
		snprintf(tmpBuff, sizeof(tmpBuff), "%02X:%02X:%02X:%02X:%02X:%02X", pe->Addr[0], pe->Addr[1], pe->Addr[2], pe->Addr[3],
				pe->Addr[4], pe->Addr[5]);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "MacAddr");

		// AID, Power Save mode, MIMO Power Save
		snprintf(tmpBuff, sizeof(tmpBuff), "%d", pe->Aid);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "Aid");

		snprintf(tmpBuff, sizeof(tmpBuff), "%d", pe->Psm);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "Psm");

		snprintf(tmpBuff, sizeof(tmpBuff), "%d", pe->MimoPs);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "MimoPs");

		// TX Rate
		if (pe->TxRate.field.MODE == 4){
			vht_nss = ((vht_mcs & (0x3 << 4)) >> 4) + 1;
			vht_mcs = vht_mcs & 0xF;
			snprintf(tmpBuff, sizeof(tmpBuff), "%dS-M%d/", vht_nss, vht_mcs);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "Mcs");
		} else{
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", pe->TxRate.field.MCS);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "Mcs");
		}

		if (pe->TxRate.field.BW == 0){
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", 20);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "Bw");
		} else if (pe->TxRate.field.BW == 1){
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", 40);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "Bw");
		} else if (pe->TxRate.field.BW == 2){
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", 80);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "Bw");
		}

		snprintf(tmpBuff, sizeof(tmpBuff), "%c", pe->TxRate.field.ShortGI? 'S': 'L');
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "Gi");

		snprintf(tmpBuff, sizeof(tmpBuff), "%s", phyMode[pe->TxRate.field.MODE]);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "PhyMode");

		snprintf(tmpBuff, sizeof(tmpBuff), "%s", pe->TxRate.field.STBC? "STBC": " ");
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "Stbc");

		// TxBF configuration
		snprintf(tmpBuff, sizeof(tmpBuff), "%c", pe->TxRate.field.iTxBF? 'I': '-');
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "iTxBF");

		snprintf(tmpBuff, sizeof(tmpBuff), "%c", pe->TxRate.field.eTxBF? 'E': '-');
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "eTxBF");

		// RSSI
		snprintf(tmpBuff, sizeof(tmpBuff), "%d", (int)(pe->AvgRssi0));
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "AvgRssi0");

		snprintf(tmpBuff, sizeof(tmpBuff), "%d", (int)(pe->AvgRssi1));
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "AvgRssi1");

		snprintf(tmpBuff, sizeof(tmpBuff), "%d", (int)(pe->AvgRssi2));
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "AvgRssi2");

		snprintf(tmpBuff, sizeof(tmpBuff), "%d", (int)(pe->AvgRssi3));
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "AvgRssi3");

		// Per Stream SNR
		snprintf(tmpBuff, sizeof(tmpBuff), "%0.1f", pe->StreamSnr[0]*0.25);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "StreamSnr0");
		snprintf(tmpBuff, sizeof(tmpBuff), "%0.1f", pe->StreamSnr[1]*0.25); //mcs>7? pe->StreamSnr[1]*0.25: 0.0);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "StreamSnr1");
		snprintf(tmpBuff, sizeof(tmpBuff), "%0.1f", pe->StreamSnr[2]*0.25); //mcs>15? pe->StreamSnr[2]*0.25: 0.0);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "StreamSnr2");

		// Sounding Response SNR
		if (pe->TxRate.field.eTxBF) {
			snprintf(tmpBuff, sizeof(tmpBuff), "%0.1f", pe->SoundingRespSnr[0]*0.25);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "SoundingRespSnr0");
			snprintf(tmpBuff, sizeof(tmpBuff), "%0.1f", pe->SoundingRespSnr[1]*0.25);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "SoundingRespSnr1");
			snprintf(tmpBuff, sizeof(tmpBuff), "%0.1f", pe->SoundingRespSnr[2]*0.25);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "SoundingRespSnr2");
		}

		// Last RX Rate
		if (((lastRxRate>>13) & 0x7) == 4){
			vht_nss_r = ((vht_mcs_r & (0x3 << 4)) >> 4) + 1;
			vht_mcs_r = vht_mcs_r & 0xF;
			snprintf(tmpBuff, sizeof(tmpBuff), "%dS-M%d", vht_nss_r, vht_mcs_r);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "LastMcs");
		} else{
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", mcs);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "LastMcs");
		}

		if (((lastRxRate>>7) & 0x3) == 0){
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", 20);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "LastBw");
		} else if (((lastRxRate>>7) & 0x3) == 1){
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", 40);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "LastBw");
		} else if (((lastRxRate>>7) & 0x3) == 2){
			snprintf(tmpBuff, sizeof(tmpBuff), "%d", 80);
			lua_pushstring(L, tmpBuff);
			lua_setfield(L, -2, "LastBw");
		}

		snprintf(tmpBuff, sizeof(tmpBuff), "%c", ((lastRxRate>>8) & 0x1)? 'S': 'L');
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "LastGi");

		snprintf(tmpBuff, sizeof(tmpBuff), "%s", phyMode[(lastRxRate>>13) & 0x7]);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "LastPhyMode");

		snprintf(tmpBuff, sizeof(tmpBuff), "%s", ((lastRxRate>>9) & 0x3)? "STBC": " ");
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "LastStbc");

		// Connect time
		snprintf(tmpBuff, sizeof(tmpBuff), "%02d", hr);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "Hr");

		snprintf(tmpBuff, sizeof(tmpBuff), "%02d", min);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "Min");

		snprintf(tmpBuff, sizeof(tmpBuff), "%02d", sec);
		lua_pushstring(L, tmpBuff);
		lua_setfield(L, -2, "Sec");

		lua_settable(L, -3);
	}
	free(table);
	return 1;
}

int apcli_get_wps_status(lua_State *L)
{
	int status;
	unsigned int profile_idx = 0;
	char tmp_str[68] = {0};
	const char *interface = luaL_checkstring(L, 1);
	lua_newtable(L);

	//7. WSC Status
	status = getWscStatus(interface);

	//8. WSC Result
	if (status == 0x2 || status == 0x109) {
		lua_pushstring(L, "wps_result");  /* push key */
		lua_pushstring(L, "Failed");  /* push value */
		lua_settable(L, -3);
	} else if (status == 34) {
		lua_pushstring(L, "wps_result");  /* push key */
		lua_pushstring(L, "Success");  /* push value */
		lua_settable(L, -3);
	} else {
		lua_pushstring(L, "wps_result");  /* push key */
		lua_pushstring(L, "Continuing");  /* push value */
		lua_settable(L, -3);
	}

	//9. WSC Status Index
	lua_pushstring(L, "wps_status_code");  /* push key */
	lua_pushnumber(L, status);  /* push value */
	lua_settable(L, -3);

	lua_pushstring(L, "wps_status");  /* push key */
	lua_pushstring(L, getWscStatusStr(status));  /* push value */
	lua_settable(L, -3);

	if (port_secured(interface) <= 0) {
		lua_pushstring(L, "wps_port_secured");  /* push key */
		lua_pushstring(L, "NO");  /* push value */
		lua_settable(L, -3);
		lua_pushstring(L, "apcli_get_wps_status");  /* push key */
		lua_pushstring(L, "OK");  /* push value */
		lua_settable(L, -3);
		lua_pushstring(L, "Error");  /* push key */
		lua_pushstring(L, "Port is not secured");  /* push value */
		lua_settable(L, -3);
		return 1;
	}

	lua_pushstring(L, "wps_port_secured");  /* push key */
	lua_pushstring(L, "YES");  /* push value */
	lua_settable(L, -3);

	if (strstr(interface,"apcli") != NULL) {
		WSC_PROFILE *wsc_profile;

		if ((wsc_profile = (WSC_PROFILE *)malloc(sizeof(WSC_PROFILE))) == NULL) {
			lua_pushstring(L, "apcli_get_wps_status");  /* push key */
			lua_pushstring(L, "NG");  /* push value */
			lua_settable(L, -3);
			lua_pushstring(L, "Error");  /* push key */
			lua_pushstring(L, "Interface name does not contain apcli");  /* push value */
			lua_settable(L, -3);
			return 1;
		}

		getWscProfile(interface, wsc_profile);
		if (wsc_profile != NULL) {
			lua_pushstring(L, "enr_profile_cnt");  /* push key */
			lua_pushnumber(L, wsc_profile->ProfileCnt);  /* push value */
			lua_settable(L, -3);
			lua_pushstring(L, "enr_profile_idx");  /* push key */
			lua_pushnumber(L, wsc_profile->ApplyProfileIdx);  /* push value */
			lua_settable(L, -3);
			lua_pushstring(L, "enr_SSID");  /* push key */
			lua_pushstring(L, (char *)wsc_profile->Profile[profile_idx].SSID.Ssid);  /* push value */
			lua_settable(L, -3);

			profile_idx = wsc_profile->ApplyProfileIdx;
			switch (wsc_profile->Profile[profile_idx].AuthType) {
				case 0x0002:
					lua_pushstring(L, "enr_AuthMode");  /* push key */
					lua_pushstring(L, "WPAPSK");  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0004:
					lua_pushstring(L, "enr_AuthMode");  /* push key */
					lua_pushstring(L, "SHARED");  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0008:
					lua_pushstring(L, "enr_AuthMode");  /* push key */
					lua_pushstring(L, "WPA");  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0010:
					lua_pushstring(L, "enr_AuthMode");  /* push key */
					lua_pushstring(L, "WPA2");  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0020:
					lua_pushstring(L, "enr_AuthMode");  /* push key */
					lua_pushstring(L, "WPA2PSK");  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0022:
					lua_pushstring(L, "enr_AuthMode");  /* push key */
					lua_pushstring(L, "WPAPSKWPA2PSK");  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0001:
				default:
					lua_pushstring(L, "enr_AuthMode");  /* push key */
					lua_pushstring(L, "OPEN");  /* push value */
					lua_settable(L, -3);
			}

			switch (wsc_profile->Profile[profile_idx].EncrType) {
				case 0x0002:
					lua_pushstring(L, "enr_EncrypType");  /* push key */
					lua_pushstring(L, "WEP");  /* push value */
					lua_settable(L, -3);

					if ((wsc_profile->Profile[profile_idx].KeyLength == 10) ||
							(wsc_profile->Profile[profile_idx].KeyLength == 26)) {
						/* Key Entry Method == HEX */
						lua_pushstring(L, "enr_Key1Type");  /* push key */
						lua_pushstring(L, "0");  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_Key2Type");  /* push key */
						lua_pushstring(L, "0");  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_Key3Type");  /* push key */
						lua_pushstring(L, "0");  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_Key4Type");  /* push key */
						lua_pushstring(L, "0");  /* push value */
						lua_settable(L, -3);
					} else {
						/* Key Entry Method == ASCII */
						lua_pushstring(L, "enr_Key1Type");  /* push key */
						lua_pushstring(L, "1");  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_Key2Type");  /* push key */
						lua_pushstring(L, "1");  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_Key3Type");  /* push key */
						lua_pushstring(L, "1");  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_Key4Type");  /* push key */
						lua_pushstring(L, "1");  /* push value */
						lua_settable(L, -3);
					}
					if (wsc_profile->Profile[profile_idx].KeyIndex == 1) {
						lua_pushstring(L, "enr_KeyStr");  /* push key */
						lua_pushstring(L, (char *)wsc_profile->Profile[profile_idx].Key);  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
						lua_pushstring(L, "1");  /* push value */
						lua_settable(L, -3);
					} else if (wsc_profile->Profile[profile_idx].KeyIndex == 2) {
						lua_pushstring(L, "enr_KeyStr");  /* push key */
						lua_pushstring(L, (char *)wsc_profile->Profile[profile_idx].Key);  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
						lua_pushstring(L, "2");  /* push value */
						lua_settable(L, -3);
					} else if (wsc_profile->Profile[profile_idx].KeyIndex == 3) {
						lua_pushstring(L, "enr_KeyStr");  /* push key */
						lua_pushstring(L, (char *)wsc_profile->Profile[profile_idx].Key);  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
						lua_pushstring(L, "3");  /* push value */
						lua_settable(L, -3);
					} else if (wsc_profile->Profile[profile_idx].KeyIndex == 4) {
						lua_pushstring(L, "enr_KeyStr");  /* push key */
						lua_pushstring(L, (char *)wsc_profile->Profile[profile_idx].Key);  /* push value */
						lua_settable(L, -3);

						lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
						lua_pushstring(L, "4");  /* push value */
						lua_settable(L, -3);
					}
					break;
				case 0x0004:
					lua_pushstring(L, "enr_EncrypType");  /* push key */
					lua_pushstring(L, "TKIP");  /* push value */
					lua_settable(L, -3);

					lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
					lua_pushstring(L, "2");  /* push value */
					lua_settable(L, -3);

					memset(tmp_str, 0, 65);
					memcpy(tmp_str, wsc_profile->Profile[profile_idx].Key, wsc_profile->Profile[profile_idx].KeyLength);

					lua_pushstring(L, "enr_WPAPSK");  /* push key */
					lua_pushstring(L, tmp_str);  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0008:
					lua_pushstring(L, "enr_EncrypType");  /* push key */
					lua_pushstring(L, "AES");  /* push value */
					lua_settable(L, -3);

					lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
					lua_pushstring(L, "2");  /* push value */
					lua_settable(L, -3);

					memset(tmp_str, 0, 65);
					memcpy(tmp_str, wsc_profile->Profile[profile_idx].Key, wsc_profile->Profile[profile_idx].KeyLength);

					lua_pushstring(L, "enr_WPAPSK");  /* push key */
					lua_pushstring(L, tmp_str);  /* push value */
					lua_settable(L, -3);
					break;
				case 0x000C:
					lua_pushstring(L, "enr_EncrypType");  /* push key */
					lua_pushstring(L, "TKIPAES");  /* push value */
					lua_settable(L, -3);
					lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
					lua_pushstring(L, "2");  /* push value */
					lua_settable(L, -3);

					memset(tmp_str, 0, 65);
					memcpy(tmp_str, wsc_profile->Profile[profile_idx].Key, wsc_profile->Profile[profile_idx].KeyLength);

					lua_pushstring(L, "enr_WPAPSK");  /* push key */
					lua_pushstring(L, tmp_str);  /* push value */
					lua_settable(L, -3);
					break;
				case 0x0001:
				default:
				//printf("Default case");
					lua_pushstring(L, "enr_EncrypType");  /* push key */
					lua_pushstring(L, "NONE");  /* push value */
					lua_settable(L, -3);

					lua_pushstring(L, "enr_DefaultKeyID");  /* push key */
					lua_pushstring(L, "1");  /* push value */
					lua_settable(L, -3);
			}

			if (wsc_profile->Profile[profile_idx].AuthType == 0x0002 &&
					wsc_profile->Profile[profile_idx].EncrType == 0x0004) {
				lua_pushstring(L, "enr_AuthMode");  /* push key */
				lua_pushstring(L, "WPAPSKWPA2PSK");  /* push value */
				lua_settable(L, -3);

				lua_pushstring(L, "enr_EncrypType");  /* push key */
				lua_pushstring(L, "TKIPAES");  /* push value */
				lua_settable(L, -3);
			}
		}

		lua_pushstring(L, "apcli_get_wps_status");  /* push key */
		lua_pushstring(L, "OK");  /* push value */
		lua_settable(L, -3);
	}
	return 1;
}
