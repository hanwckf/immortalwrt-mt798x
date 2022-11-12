#ifndef __MTWIFI_H
#define __MTWIFI_H

#define USHORT  unsigned short
#define UCHAR   unsigned char
#define ULONG	unsigned long
#define UINT8	unsigned char
#define UINT16	unsigned short
#define INT32	int
#define INT 	int

#include <lua.h>							   /* Always include this */
#include <lauxlib.h>						   /* Always include this */
#include <lualib.h>							/* Always include this */

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

#define MODE_CCK 0
#define MODE_OFDM 1
#define MODE_HTMIX 2
#define MODE_HTGREENFIELD 3
#define MODE_VHT 4
#define MODE_HE 5
#define MODE_HE_5G 6
#define MODE_HE_24G 7
#define MODE_HE_SU	8
#define MODE_HE_EXT_SU	9
#define MODE_HE_TRIG	10
#define MODE_HE_MU	11

#define TMI_TX_RATE_OFDM_6M     11
#define TMI_TX_RATE_OFDM_9M     15
#define TMI_TX_RATE_OFDM_12M    10
#define TMI_TX_RATE_OFDM_18M    14
#define TMI_TX_RATE_OFDM_24M    9
#define TMI_TX_RATE_OFDM_36M    13
#define TMI_TX_RATE_OFDM_48M    8
#define TMI_TX_RATE_OFDM_54M    12

#define TMI_TX_RATE_CCK_1M_LP   0
#define TMI_TX_RATE_CCK_2M_LP   1
#define TMI_TX_RATE_CCK_5M_LP   2
#define TMI_TX_RATE_CCK_11M_LP  3

#define TMI_TX_RATE_CCK_2M_SP   5
#define TMI_TX_RATE_CCK_5M_SP   6
#define TMI_TX_RATE_CCK_11M_SP  7

enum oid_bw {
	BAND_WIDTH_20,
	BAND_WIDTH_40,
	BAND_WIDTH_80,
	BAND_WIDTH_160,
	BAND_WIDTH_10,
	BAND_WIDTH_5,
	BAND_WIDTH_8080,
	BAND_WIDTH_BOTH,
	BAND_WIDTH_25,
	BAND_WIDTH_20_242TONE,
	BAND_WIDTH_NUM
};

#define BW_20		BAND_WIDTH_20
#define BW_40		BAND_WIDTH_40
#define BW_80		BAND_WIDTH_80
#define BW_160		BAND_WIDTH_160
#define BW_10		BAND_WIDTH_10
#define BW_5		BAND_WIDTH_5
#define BW_8080		BAND_WIDTH_8080
#define BW_25		BAND_WIDTH_25
#define BW_20_242TONE	BAND_WIDTH_20_242TONE
#define BW_NUM		BAND_WIDTH_NUM

int get_macaddr(lua_State *L);
int convert_string_display(lua_State *L);
int StaInfo(lua_State *L);
int getWMOde(lua_State *L);
int getTempature(lua_State *L);
int scanResult(lua_State *L);
void getRate(HTTRANSMIT_SETTING HTSetting, ULONG *fLastTxRxRate);
void get_rate_he(UINT8 mcs, UINT8 bw, UINT8 nss, UINT8 dcm, ULONG *last_tx_rate);
#endif