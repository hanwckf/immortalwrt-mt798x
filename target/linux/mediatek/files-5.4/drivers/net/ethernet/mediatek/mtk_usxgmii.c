/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2022 MediaTek Inc.
 * Author: Henry Yen <henry.yen@mediatek.com>
 */

#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/regmap.h>
#include "mtk_eth_soc.h"

int mtk_usxgmii_init(struct mtk_xgmii *ss, struct device_node *r)
{
	struct device_node *np;
	int i;

	for (i = 0; i < MTK_MAX_DEVS; i++) {
		np = of_parse_phandle(r, "mediatek,usxgmiisys", i);
		if (!np)
			break;

		ss->regmap_usxgmii[i] = syscon_node_to_regmap(np);
		if (IS_ERR(ss->regmap_usxgmii[i]))
			return PTR_ERR(ss->regmap_usxgmii[i]);

		ss->flags[i] &= ~(MTK_USXGMII_INT_2500);
		if (of_property_read_bool(np, "internal_2500"))
			ss->flags[i] |= MTK_USXGMII_INT_2500;
	}

	return 0;
}

int mtk_xfi_pextp_init(struct mtk_xgmii *ss, struct device_node *r)
{
	struct device_node *np;
	int i;

	for (i = 0; i < MTK_MAX_DEVS; i++) {
		np = of_parse_phandle(r, "mediatek,xfi_pextp", i);
		if (!np)
			break;

		ss->regmap_pextp[i] = syscon_node_to_regmap(np);
		if (IS_ERR(ss->regmap_pextp[i]))
			return PTR_ERR(ss->regmap_pextp[i]);
	}

	return 0;
}

int mtk_xfi_pll_init(struct mtk_xgmii *ss, struct device_node *r)
{
	struct device_node *np;

	np = of_parse_phandle(r, "mediatek,xfi_pll", 0);
	if (!np)
		return -1;

	ss->regmap_pll = syscon_node_to_regmap(np);
	if (IS_ERR(ss->regmap_pll))
		return PTR_ERR(ss->regmap_pll);

	return 0;
}

int mtk_toprgu_init(struct mtk_eth *eth, struct device_node *r)
{
	struct device_node *np;

	np = of_parse_phandle(r, "mediatek,toprgu", 0);
	if (!np)
		return -1;

	eth->toprgu = syscon_node_to_regmap(np);
	if (IS_ERR(eth->toprgu))
		return PTR_ERR(eth->toprgu);

	return 0;
}

int mtk_xfi_pll_enable(struct mtk_xgmii *ss)
{
	u32 val = 0;

	if (!ss->regmap_pll)
		return -EINVAL;

	/* Add software workaround for USXGMII PLL TCL issue */
	regmap_write(ss->regmap_pll, XFI_PLL_ANA_GLB8, RG_XFI_PLL_ANA_SWWA);

	regmap_read(ss->regmap_pll, XFI_PLL_DIG_GLB8, &val);
	val |= RG_XFI_PLL_EN;
	regmap_write(ss->regmap_pll, XFI_PLL_DIG_GLB8, val);

	return 0;
}

int mtk_mac2xgmii_id(struct mtk_eth *eth, int mac_id)
{
	u32 xgmii_id = mac_id;

	if (MTK_HAS_CAPS(eth->soc->caps, MTK_NETSYS_V3)) {
		switch (mac_id) {
		case MTK_GMAC1_ID:
		case MTK_GMAC2_ID:
			xgmii_id = 1;
			break;
		case MTK_GMAC3_ID:
			xgmii_id = 0;
			break;
		default:
			pr_info("[%s] Warning: get illegal mac_id=%d !=!!!\n",
				__func__, mac_id);
		}
	}

	return xgmii_id;
}

void mtk_usxgmii_setup_phya_an_10000(struct mtk_xgmii *ss, int mac_id)
{
	u32 id = mtk_mac2xgmii_id(ss->eth, mac_id);

	if (id < 0 || id >= MTK_MAX_DEVS ||
	    !ss->regmap_usxgmii[id] || !ss->regmap_pextp[id])
		return;

	regmap_update_bits(ss->regmap_usxgmii[id], 0x810, GENMASK(31, 0), 0x000FFE6D);
	regmap_update_bits(ss->regmap_usxgmii[id], 0x818, GENMASK(31, 0), 0x07B1EC7B);
	regmap_update_bits(ss->regmap_usxgmii[id], 0x80C, GENMASK(31, 0), 0x30000000);
	ndelay(1020);
	regmap_update_bits(ss->regmap_usxgmii[id], 0x80C, GENMASK(31, 0), 0x10000000);
	ndelay(1020);
	regmap_update_bits(ss->regmap_usxgmii[id], 0x80C, GENMASK(31, 0), 0x00000000);

	regmap_update_bits(ss->regmap_pextp[id], 0x9024, GENMASK(31, 0), 0x00C9071C);
	regmap_update_bits(ss->regmap_pextp[id], 0x2020, GENMASK(31, 0), 0xAA8585AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x2030, GENMASK(31, 0), 0x0C020707);
	regmap_update_bits(ss->regmap_pextp[id], 0x2034, GENMASK(31, 0), 0x0E050F0F);
	regmap_update_bits(ss->regmap_pextp[id], 0x2040, GENMASK(31, 0), 0x00140032);
	regmap_update_bits(ss->regmap_pextp[id], 0x50F0, GENMASK(31, 0), 0x00C014AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E0, GENMASK(31, 0), 0x3777C12B);
	regmap_update_bits(ss->regmap_pextp[id], 0x506C, GENMASK(31, 0), 0x005F9CFF);
	regmap_update_bits(ss->regmap_pextp[id], 0x5070, GENMASK(31, 0), 0x9D9DFAFA);
	regmap_update_bits(ss->regmap_pextp[id], 0x5074, GENMASK(31, 0), 0x27273F3F);
	regmap_update_bits(ss->regmap_pextp[id], 0x5078, GENMASK(31, 0), 0xA7883C68);
	regmap_update_bits(ss->regmap_pextp[id], 0x507C, GENMASK(31, 0), 0x11661166);
	regmap_update_bits(ss->regmap_pextp[id], 0x5080, GENMASK(31, 0), 0x0E000AAF);
	regmap_update_bits(ss->regmap_pextp[id], 0x5084, GENMASK(31, 0), 0x08080D0D);
	regmap_update_bits(ss->regmap_pextp[id], 0x5088, GENMASK(31, 0), 0x02030909);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E4, GENMASK(31, 0), 0x0C0C0000);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E8, GENMASK(31, 0), 0x04040000);
	regmap_update_bits(ss->regmap_pextp[id], 0x50EC, GENMASK(31, 0), 0x0F0F0C06);
	regmap_update_bits(ss->regmap_pextp[id], 0x50A8, GENMASK(31, 0), 0x506E8C8C);
	regmap_update_bits(ss->regmap_pextp[id], 0x6004, GENMASK(31, 0), 0x18190000);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F8, GENMASK(31, 0), 0x01423342);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F20);
	regmap_update_bits(ss->regmap_pextp[id], 0x0030, GENMASK(31, 0), 0x00050C00);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x02002800);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000020);
	regmap_update_bits(ss->regmap_pextp[id], 0x3028, GENMASK(31, 0), 0x00008A01);
	regmap_update_bits(ss->regmap_pextp[id], 0x302C, GENMASK(31, 0), 0x0000A884);
	regmap_update_bits(ss->regmap_pextp[id], 0x3024, GENMASK(31, 0), 0x00083002);
	regmap_update_bits(ss->regmap_pextp[id], 0x3010, GENMASK(31, 0), 0x00022220);
	regmap_update_bits(ss->regmap_pextp[id], 0x5064, GENMASK(31, 0), 0x0F020A01);
	regmap_update_bits(ss->regmap_pextp[id], 0x50B4, GENMASK(31, 0), 0x06100600);
	regmap_update_bits(ss->regmap_pextp[id], 0x3048, GENMASK(31, 0), 0x40704000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3050, GENMASK(31, 0), 0xA8000000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3054, GENMASK(31, 0), 0x000000AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x306C, GENMASK(31, 0), 0x00000F00);
	regmap_update_bits(ss->regmap_pextp[id], 0xA060, GENMASK(31, 0), 0x00040000);
	regmap_update_bits(ss->regmap_pextp[id], 0x90D0, GENMASK(31, 0), 0x00000001);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200E800);
	udelay(150);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C101);
	udelay(15);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0202C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0202C101);
	udelay(100);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000030);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F00);
	regmap_update_bits(ss->regmap_pextp[id], 0x3040, GENMASK(31, 0), 0x30000000);
	udelay(400);
}

void mtk_usxgmii_setup_phya_force(struct mtk_xgmii *ss, int mac_id, int max_speed)
{
	unsigned int val;
	u32 id = mtk_mac2xgmii_id(ss->eth, mac_id);

	if (id < 0 || id >= MTK_MAX_DEVS ||
	    !ss->regmap_usxgmii[id] || !ss->regmap_pextp[id])
		return;

	/* Decide USXGMII speed */
	switch (max_speed) {
	case SPEED_5000:
		val = FIELD_PREP(RG_XFI_RX_MODE, RG_XFI_RX_MODE_5G) |
		      FIELD_PREP(RG_XFI_TX_MODE, RG_XFI_TX_MODE_5G);
		break;
	case SPEED_10000:
	default:
		val = FIELD_PREP(RG_XFI_RX_MODE, RG_XFI_RX_MODE_10G) |
		      FIELD_PREP(RG_XFI_TX_MODE, RG_XFI_TX_MODE_10G);
		break;
	};
	regmap_write(ss->regmap_usxgmii[id], RG_PHY_TOP_SPEED_CTRL1, val);

	/* Disable USXGMII AN mode */
	regmap_read(ss->regmap_usxgmii[id], RG_PCS_AN_CTRL0, &val);
	val &= ~RG_AN_ENABLE;
	regmap_write(ss->regmap_usxgmii[id], RG_PCS_AN_CTRL0, val);

	/* Gated USXGMII */
	regmap_read(ss->regmap_usxgmii[id], RG_PHY_TOP_SPEED_CTRL1, &val);
	val |= RG_MAC_CK_GATED;
	regmap_write(ss->regmap_usxgmii[id], RG_PHY_TOP_SPEED_CTRL1, val);

	ndelay(1020);

	/* USXGMII force mode setting */
	regmap_read(ss->regmap_usxgmii[id], RG_PHY_TOP_SPEED_CTRL1, &val);
	val |= RG_USXGMII_RATE_UPDATE_MODE;
	val |= RG_IF_FORCE_EN;
	val |= FIELD_PREP(RG_RATE_ADAPT_MODE, RG_RATE_ADAPT_MODE_X1);
	regmap_write(ss->regmap_usxgmii[id], RG_PHY_TOP_SPEED_CTRL1, val);

	/* Un-gated USXGMII */
	regmap_read(ss->regmap_usxgmii[id], RG_PHY_TOP_SPEED_CTRL1, &val);
	val &= ~RG_MAC_CK_GATED;
	regmap_write(ss->regmap_usxgmii[id], RG_PHY_TOP_SPEED_CTRL1, val);

	ndelay(1020);

	regmap_update_bits(ss->regmap_pextp[id], 0x9024, GENMASK(31, 0), 0x00C9071C);
	regmap_update_bits(ss->regmap_pextp[id], 0x2020, GENMASK(31, 0), 0xAA8585AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x2030, GENMASK(31, 0), 0x0C020707);
	regmap_update_bits(ss->regmap_pextp[id], 0x2034, GENMASK(31, 0), 0x0E050F0F);
	regmap_update_bits(ss->regmap_pextp[id], 0x2040, GENMASK(31, 0), 0x00140032);
	regmap_update_bits(ss->regmap_pextp[id], 0x50F0, GENMASK(31, 0), 0x00C014AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E0, GENMASK(31, 0), 0x3777C12B);
	regmap_update_bits(ss->regmap_pextp[id], 0x506C, GENMASK(31, 0), 0x005F9CFF);
	regmap_update_bits(ss->regmap_pextp[id], 0x5070, GENMASK(31, 0), 0x9D9DFAFA);
	regmap_update_bits(ss->regmap_pextp[id], 0x5074, GENMASK(31, 0), 0x27273F3F);
	regmap_update_bits(ss->regmap_pextp[id], 0x5078, GENMASK(31, 0), 0xA7883C68);
	regmap_update_bits(ss->regmap_pextp[id], 0x507C, GENMASK(31, 0), 0x11661166);
	regmap_update_bits(ss->regmap_pextp[id], 0x5080, GENMASK(31, 0), 0x0E000AAF);
	regmap_update_bits(ss->regmap_pextp[id], 0x5084, GENMASK(31, 0), 0x08080D0D);
	regmap_update_bits(ss->regmap_pextp[id], 0x5088, GENMASK(31, 0), 0x02030909);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E4, GENMASK(31, 0), 0x0C0C0000);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E8, GENMASK(31, 0), 0x04040000);
	regmap_update_bits(ss->regmap_pextp[id], 0x50EC, GENMASK(31, 0), 0x0F0F0C06);
	regmap_update_bits(ss->regmap_pextp[id], 0x50A8, GENMASK(31, 0), 0x506E8C8C);
	regmap_update_bits(ss->regmap_pextp[id], 0x6004, GENMASK(31, 0), 0x18190000);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F8, GENMASK(31, 0), 0x01423342);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F20);
	regmap_update_bits(ss->regmap_pextp[id], 0x0030, GENMASK(31, 0), 0x00050C00);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x02002800);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000020);
	regmap_update_bits(ss->regmap_pextp[id], 0x3028, GENMASK(31, 0), 0x00008A01);
	regmap_update_bits(ss->regmap_pextp[id], 0x302C, GENMASK(31, 0), 0x0000A884);
	regmap_update_bits(ss->regmap_pextp[id], 0x3024, GENMASK(31, 0), 0x00083002);
	regmap_update_bits(ss->regmap_pextp[id], 0x3010, GENMASK(31, 0), 0x00022220);
	regmap_update_bits(ss->regmap_pextp[id], 0x5064, GENMASK(31, 0), 0x0F020A01);
	regmap_update_bits(ss->regmap_pextp[id], 0x50B4, GENMASK(31, 0), 0x06100600);
	regmap_update_bits(ss->regmap_pextp[id], 0x3048, GENMASK(31, 0), 0x49664100);
	regmap_update_bits(ss->regmap_pextp[id], 0x3050, GENMASK(31, 0), 0x00000000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3054, GENMASK(31, 0), 0x00000000);
	regmap_update_bits(ss->regmap_pextp[id], 0x306C, GENMASK(31, 0), 0x00000F00);
	regmap_update_bits(ss->regmap_pextp[id], 0xA060, GENMASK(31, 0), 0x00040000);
	regmap_update_bits(ss->regmap_pextp[id], 0x90D0, GENMASK(31, 0), 0x00000001);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200E800);
	udelay(150);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C101);
	udelay(15);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0202C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0202C101);
	udelay(100);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000030);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F00);
	regmap_update_bits(ss->regmap_pextp[id], 0x3040, GENMASK(31, 0), 0x30000000);
	udelay(400);
}

void mtk_usxgmii_reset(struct mtk_xgmii *ss, int mac_id)
{
	struct mtk_eth *eth = ss->eth;
	u32 id = mtk_mac2xgmii_id(eth, mac_id);

	if (id < 0 || id >= MTK_MAX_DEVS || !eth->toprgu)
		return;

	switch (mac_id) {
	case MTK_GMAC2_ID:
		regmap_update_bits(eth->toprgu, 0xFC, GENMASK(31, 0), 0x0000A004);
		regmap_update_bits(eth->toprgu, 0x18, GENMASK(31, 0), 0x88F0A004);
		regmap_update_bits(eth->toprgu, 0xFC, GENMASK(31, 0), 0x00000000);
		regmap_update_bits(eth->toprgu, 0x18, GENMASK(31, 0), 0x88F00000);
		regmap_update_bits(eth->toprgu, 0x18, GENMASK(31, 0), 0x00F00000);
		break;
	case MTK_GMAC3_ID:
		regmap_update_bits(eth->toprgu, 0xFC, GENMASK(31, 0), 0x00005002);
		regmap_update_bits(eth->toprgu, 0x18, GENMASK(31, 0), 0x88F05002);
		regmap_update_bits(eth->toprgu, 0xFC, GENMASK(31, 0), 0x00000000);
		regmap_update_bits(eth->toprgu, 0x18, GENMASK(31, 0), 0x88F00000);
		regmap_update_bits(eth->toprgu, 0x18, GENMASK(31, 0), 0x00F00000);
		break;
	}

	udelay(100);
}

int mtk_usxgmii_setup_mode_an(struct mtk_xgmii *ss, int mac_id, int max_speed)
{
	if (mac_id < 0 || mac_id >= MTK_MAX_DEVS)
		return -EINVAL;

	if ((max_speed != SPEED_10000) && (max_speed != SPEED_5000))
		return -EINVAL;

	mtk_xfi_pll_enable(ss);
	mtk_usxgmii_reset(ss, mac_id);
	mtk_usxgmii_setup_phya_an_10000(ss, mac_id);

	return 0;
}

int mtk_usxgmii_setup_mode_force(struct mtk_xgmii *ss, int mac_id, int max_speed)
{
	if (mac_id < 0 || mac_id >= MTK_MAX_DEVS)
		return -EINVAL;

	if ((max_speed != SPEED_10000) && (max_speed != SPEED_5000))
		return -EINVAL;

	mtk_xfi_pll_enable(ss);
	mtk_usxgmii_reset(ss, mac_id);
	mtk_usxgmii_setup_phya_force(ss, mac_id, max_speed);

	return 0;
}
