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

#define USHORT  unsigned short
#define UCHAR   unsigned char

typedef union _HTTRANSMIT_SETTING {
	struct {
		USHORT MCS:6;
		USHORT ldpc:1;
		USHORT BW:2;
		USHORT ShortGI:1;
		USHORT STBC:1;
		USHORT eTxBF:1;
		USHORT iTxBF:1;
		USHORT MODE:3;
	} field;
	USHORT word;
} HTTRANSMIT_SETTING, *PHTTRANSMIT_SETTING;

typedef struct _RT_802_11_MAC_ENTRY {
	unsigned char           ApIdx;
	unsigned char           Addr[6];
	unsigned short          Aid;
	unsigned char           Psm;     // 0:PWR_ACTIVE, 1:PWR_SAVE
	unsigned char           MimoPs;  // 0:MMPS_STATIC, 1:MMPS_DYNAMIC, 3:MMPS_Enabled
	signed char             AvgRssi0;
	signed char             AvgRssi1;
	signed char             AvgRssi2;
	unsigned int            ConnectedTime;
	HTTRANSMIT_SETTING      TxRate;
	unsigned int            LastRxRate;
	short                   StreamSnr[3];
	short                   SoundingRespSnr[3];
	//short                   TxPER;
	//short                   reserved;
} RT_802_11_MAC_ENTRY;

#define MAX_NUMBER_OF_MAC               544

typedef struct _RT_802_11_MAC_TABLE {
	unsigned long            Num;
	RT_802_11_MAC_ENTRY      Entry[MAX_NUMBER_OF_MAC];
} RT_802_11_MAC_TABLE;

#define IF_NAMESIZE			16
#define SIOCIWFIRSTPRIV			0x8BE0
#define RT_PRIV_IOCTL				(SIOCIWFIRSTPRIV + 0x0E)
#define RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT	(SIOCIWFIRSTPRIV + 0x1F)
#define RTPRIV_IOCTL_GSITESURVEY		(SIOCIWFIRSTPRIV + 0x0D)
#define OID_GET_WMODE			0x099E
#define OID_GET_CPU_TEMPERATURE		0x09A1

int get_macaddr(lua_State *L);
int convert_string_display(lua_State *L);
int StaInfo(lua_State *L);
int getWMOde(lua_State *L);
int getTempature(lua_State *L);
int scanResult(lua_State *L);

int luaopen_ioctl_helper(lua_State *L)
{
	lua_register(L,"c_get_macaddr",get_macaddr);
	lua_register(L,"c_convert_string_display",convert_string_display);
	lua_register(L,"c_StaInfo",StaInfo);
	lua_register(L,"c_getWMode",getWMOde);
	lua_register(L,"c_getTempature",getTempature);
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
	wrq.u.data.pointer = data;
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

static unsigned int get_temp(const char *interface)
{
	int socket_id;
	struct iwreq wrq;
	unsigned int tempature = 0;
	socket_id = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_id < 0) {
		perror("socket() failed");
		return socket_id;
	}

	snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", interface);
	wrq.u.data.length = sizeof(tempature);
	wrq.u.data.pointer = &tempature;
	wrq.u.data.flags = OID_GET_CPU_TEMPERATURE;
	if( ioctl(socket_id, RT_PRIV_IOCTL, &wrq) == -1)
		fprintf(stderr, "%s: ioctl fail\n", __func__);
	close(socket_id);

	return tempature;
}

int getTempature(lua_State *L)
{
	char tempstr[5] = {0};
	const char *interface = luaL_checkstring(L, 1);
	snprintf(tempstr, sizeof(tempstr), "%d", get_temp(interface));
	lua_newtable(L);
	lua_pushstring(L, "tempature");  /* push key */
	lua_pushstring(L, tempstr);  /* push value */
	lua_settable(L, -3);
	/* Returning one table which is already on top of Lua stack. */
	return 1;
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
	wrq.u.data.pointer = &data;
	wrq.u.data.flags = OID_GET_WMODE;
	if( ioctl(socket_id, RT_PRIV_IOCTL, &wrq) == -1)
		fprintf(stderr, "%s: ioctl fail\n", __func__);
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

int convert_string_display(lua_State *L)
{
#define BUF_SIZE	256
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
			sprintf(pOut, "&amp;");		// '&'
			pOut += 5;
			break;

		case 60:
			sprintf(pOut, "&lt;");		// '<'
			pOut += 4;
			break;

		case 62:
			sprintf(pOut, "&gt;");		// '>'
			pOut += 4;
			break;

		case 34:
			sprintf(pOut, "&#34;");		// '"'
			pOut += 5;
			break;

		case 39:
			sprintf(pOut, "&#39;");		// '''
			pOut += 5;
			break;
		case 32:
			sprintf(pOut, "&nbsp;");	// ' '
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

	table = (RT_802_11_MAC_TABLE *)malloc(sizeof(RT_802_11_MAC_TABLE));
	if (!table)
		return -ENOMEM;

	memset(table, 0, sizeof(RT_802_11_MAC_TABLE));

	s = socket(AF_INET, SOCK_DGRAM, 0);

	snprintf(iwr.ifr_name, IFNAMSIZ, "%s", interface);

	iwr.u.data.pointer = table;

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

