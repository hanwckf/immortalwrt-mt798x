// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-2019 MediaTek Inc.

/* A library for MediaTek SGMII circuit
 *
 * Author: Sean Wang <sean.wang@mediatek.com>
 *
 */

#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/regmap.h>

#include "mtk_eth_soc.h"

int mtk_sgmii_init(struct mtk_xgmii *ss, struct device_node *r, u32 ana_rgc3)
{
	struct device_node *np;
	int i;

	ss->ana_rgc3 = ana_rgc3;

	for (i = 0; i < MTK_MAX_DEVS; i++) {
		np = of_parse_phandle(r, "mediatek,sgmiisys", i);
		if (!np)
			break;

		ss->regmap_sgmii[i] = syscon_node_to_regmap(np);
		if (IS_ERR(ss->regmap_sgmii[i]))
			return PTR_ERR(ss->regmap_sgmii[i]);

		ss->flags[i] &= ~(MTK_SGMII_PN_SWAP);
		if (of_property_read_bool(np, "pn_swap"))
			ss->flags[i] |= MTK_SGMII_PN_SWAP;
	}

	return 0;
}

void mtk_sgmii_setup_phya_gen1(struct mtk_xgmii *ss, int mac_id)
{
	u32 id = mtk_mac2xgmii_id(ss->eth, mac_id);

	if (id < 0 || id >= MTK_MAX_DEVS ||
	    !ss->regmap_sgmii[id] || !ss->regmap_pextp[id])
		return;

	regmap_update_bits(ss->regmap_pextp[id], 0x9024, GENMASK(31, 0), 0x00D9071C);
	regmap_update_bits(ss->regmap_pextp[id], 0x2020, GENMASK(31, 0), 0xAA8585AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x2030, GENMASK(31, 0), 0x0C020207);
	regmap_update_bits(ss->regmap_pextp[id], 0x2034, GENMASK(31, 0), 0x0E05050F);
	regmap_update_bits(ss->regmap_pextp[id], 0x2040, GENMASK(31, 0), 0x00200032);
	regmap_update_bits(ss->regmap_pextp[id], 0x50F0, GENMASK(31, 0), 0x00C014BA);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E0, GENMASK(31, 0), 0x3777C12B);
	regmap_update_bits(ss->regmap_pextp[id], 0x506C, GENMASK(31, 0), 0x005F9CFF);
	regmap_update_bits(ss->regmap_pextp[id], 0x5070, GENMASK(31, 0), 0x9D9DFAFA);
	regmap_update_bits(ss->regmap_pextp[id], 0x5074, GENMASK(31, 0), 0x27273F3F);
	regmap_update_bits(ss->regmap_pextp[id], 0x5078, GENMASK(31, 0), 0xA7883C68);
	regmap_update_bits(ss->regmap_pextp[id], 0x507C, GENMASK(31, 0), 0x11661166);
	regmap_update_bits(ss->regmap_pextp[id], 0x5080, GENMASK(31, 0), 0x0E000EAF);
	regmap_update_bits(ss->regmap_pextp[id], 0x5084, GENMASK(31, 0), 0x08080E0D);
	regmap_update_bits(ss->regmap_pextp[id], 0x5088, GENMASK(31, 0), 0x02030B09);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E4, GENMASK(31, 0), 0x0C0C0000);
	regmap_update_bits(ss->regmap_pextp[id], 0x50E8, GENMASK(31, 0), 0x04040000);
	regmap_update_bits(ss->regmap_pextp[id], 0x50EC, GENMASK(31, 0), 0x0F0F0606);
	regmap_update_bits(ss->regmap_pextp[id], 0x50A8, GENMASK(31, 0), 0x506E8C8C);
	regmap_update_bits(ss->regmap_pextp[id], 0x6004, GENMASK(31, 0), 0x18190000);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F8, GENMASK(31, 0), 0x00FA32FA);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F21);
	regmap_update_bits(ss->regmap_pextp[id], 0x0030, GENMASK(31, 0), 0x00050C00);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x02002800);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000020);
	regmap_update_bits(ss->regmap_pextp[id], 0x3028, GENMASK(31, 0), 0x00008A01);
	regmap_update_bits(ss->regmap_pextp[id], 0x302C, GENMASK(31, 0), 0x0000A884);
	regmap_update_bits(ss->regmap_pextp[id], 0x3024, GENMASK(31, 0), 0x00083002);
	regmap_update_bits(ss->regmap_pextp[id], 0x3010, GENMASK(31, 0), 0x00011110);
	regmap_update_bits(ss->regmap_pextp[id], 0x3048, GENMASK(31, 0), 0x40704000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3064, GENMASK(31, 0), 0x0000C000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3050, GENMASK(31, 0), 0xA8000000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3054, GENMASK(31, 0), 0x000000AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x306C, GENMASK(31, 0), 0x20200F00);
	regmap_update_bits(ss->regmap_pextp[id], 0xA060, GENMASK(31, 0), 0x00050000);
	regmap_update_bits(ss->regmap_pextp[id], 0x90D0, GENMASK(31, 0), 0x00000007);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200E800);
	udelay(150);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C101);
	udelay(15);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0201C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0201C101);
	udelay(100);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000030);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F01);
	regmap_update_bits(ss->regmap_pextp[id], 0x3040, GENMASK(31, 0), 0x30000000);
	udelay(400);
}

void mtk_sgmii_setup_phya_gen2(struct mtk_xgmii *ss, int mac_id)
{
	u32 id = mtk_mac2xgmii_id(ss->eth, mac_id);

	if (id < 0 || id >= MTK_MAX_DEVS ||
	    !ss->regmap_sgmii[id] || !ss->regmap_pextp[id])
		return;

	regmap_update_bits(ss->regmap_pextp[id], 0x9024, GENMASK(31, 0), 0x00D9071C);
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
	regmap_update_bits(ss->regmap_pextp[id], 0x00F8, GENMASK(31, 0), 0x009C329C);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F21);
	regmap_update_bits(ss->regmap_pextp[id], 0x0030, GENMASK(31, 0), 0x00050C00);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x02002800);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000020);
	regmap_update_bits(ss->regmap_pextp[id], 0x3028, GENMASK(31, 0), 0x00008A01);
	regmap_update_bits(ss->regmap_pextp[id], 0x302C, GENMASK(31, 0), 0x0000A884);
	regmap_update_bits(ss->regmap_pextp[id], 0x3024, GENMASK(31, 0), 0x00083002);
	regmap_update_bits(ss->regmap_pextp[id], 0x3010, GENMASK(31, 0), 0x00011110);
	regmap_update_bits(ss->regmap_pextp[id], 0x3048, GENMASK(31, 0), 0x40704000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3050, GENMASK(31, 0), 0xA8000000);
	regmap_update_bits(ss->regmap_pextp[id], 0x3054, GENMASK(31, 0), 0x000000AA);
	regmap_update_bits(ss->regmap_pextp[id], 0x306C, GENMASK(31, 0), 0x22000F00);
	regmap_update_bits(ss->regmap_pextp[id], 0xA060, GENMASK(31, 0), 0x00050000);
	regmap_update_bits(ss->regmap_pextp[id], 0x90D0, GENMASK(31, 0), 0x00000005);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200E800);
	udelay(150);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0200C101);
	udelay(15);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0201C111);
	ndelay(1020);
	regmap_update_bits(ss->regmap_pextp[id], 0x0070, GENMASK(31, 0), 0x0201C101);
	udelay(100);
	regmap_update_bits(ss->regmap_pextp[id], 0x30B0, GENMASK(31, 0), 0x00000030);
	regmap_update_bits(ss->regmap_pextp[id], 0x00F4, GENMASK(31, 0), 0x80201F01);
	regmap_update_bits(ss->regmap_pextp[id], 0x3040, GENMASK(31, 0), 0x30000000);
	udelay(400);
}

int mtk_sgmii_setup_mode_an(struct mtk_xgmii *ss, unsigned int mac_id)
{
	struct mtk_eth *eth = ss->eth;
	unsigned int val;
	u32 id = mtk_mac2xgmii_id(ss->eth, mac_id);

	if (!ss->regmap_sgmii[id])
		return -EINVAL;

	if (MTK_HAS_CAPS(eth->soc->caps, MTK_NETSYS_V3))
		mtk_xfi_pll_enable(ss);

	/* Assert PHYA power down state */
	regmap_write(ss->regmap_sgmii[id], SGMSYS_QPHY_PWR_STATE_CTRL, SGMII_PHYA_PWD);

	/* Reset SGMII PCS state */
	regmap_write(ss->regmap_sgmii[id], SGMII_RESERVED_0, SGMII_SW_RESET);

	regmap_read(ss->regmap_sgmii[id], ss->ana_rgc3, &val);
	val &= ~RG_PHY_SPEED_3_125G;
	regmap_write(ss->regmap_sgmii[id], ss->ana_rgc3, val);

	/* Setup the link timer and QPHY power up inside SGMIISYS */
	regmap_write(ss->regmap_sgmii[id], SGMSYS_PCS_LINK_TIMER,
		     SGMII_LINK_TIMER_DEFAULT);

	regmap_read(ss->regmap_sgmii[id], SGMSYS_SGMII_MODE, &val);
	val |= SGMII_REMOTE_FAULT_DIS;
	regmap_write(ss->regmap_sgmii[id], SGMSYS_SGMII_MODE, val);

	/* SGMII AN mode setting */
	regmap_read(ss->regmap_sgmii[id], SGMSYS_SGMII_MODE, &val);
	val &= ~SGMII_IF_MODE_MASK;
	val |= SGMII_SPEED_DUPLEX_AN;
	regmap_write(ss->regmap_sgmii[id], SGMSYS_SGMII_MODE, val);

	/* Enable SGMII AN */
	regmap_read(ss->regmap_sgmii[id], SGMSYS_PCS_CONTROL_1, &val);
	val |= SGMII_AN_ENABLE;
	regmap_write(ss->regmap_sgmii[id], SGMSYS_PCS_CONTROL_1, val);

	if(MTK_HAS_FLAGS(ss->flags[id],MTK_SGMII_PN_SWAP))
		regmap_update_bits(ss->regmap_sgmii[id], SGMSYS_QPHY_WRAP_CTRL,
				   SGMII_PN_SWAP_MASK, SGMII_PN_SWAP_TX_RX);

	/* Release PHYA power down state */
	regmap_write(ss->regmap_sgmii[id], SGMSYS_QPHY_PWR_STATE_CTRL, 0);

	if (MTK_HAS_CAPS(eth->soc->caps, MTK_NETSYS_V3))
		mtk_sgmii_setup_phya_gen1(ss, mac_id);

	return 0;
}

int mtk_sgmii_setup_mode_force(struct mtk_xgmii *ss, unsigned int mac_id,
			       const struct phylink_link_state *state)
{
	struct mtk_eth *eth = ss->eth;
	unsigned int val;
	u32 id = mtk_mac2xgmii_id(eth, mac_id);

	if (!ss->regmap_sgmii[id])
		return -EINVAL;

	if (MTK_HAS_CAPS(eth->soc->caps, MTK_NETSYS_V3))
		mtk_xfi_pll_enable(ss);

	/* Assert PHYA power down state */
	regmap_write(ss->regmap_sgmii[id], SGMSYS_QPHY_PWR_STATE_CTRL, SGMII_PHYA_PWD);

	/* Reset SGMII PCS state */
	regmap_write(ss->regmap_sgmii[id], SGMII_RESERVED_0, SGMII_SW_RESET);

	regmap_read(ss->regmap_sgmii[id], ss->ana_rgc3, &val);
	val &= ~RG_PHY_SPEED_MASK;
	if (state->interface == PHY_INTERFACE_MODE_2500BASEX)
		val |= RG_PHY_SPEED_3_125G;
	regmap_write(ss->regmap_sgmii[id], ss->ana_rgc3, val);

	/* Disable SGMII AN */
	regmap_read(ss->regmap_sgmii[id], SGMSYS_PCS_CONTROL_1, &val);
	val &= ~SGMII_AN_ENABLE;
	regmap_write(ss->regmap_sgmii[id], SGMSYS_PCS_CONTROL_1, val);

	/* SGMII force mode setting */
	regmap_read(ss->regmap_sgmii[id], SGMSYS_SGMII_MODE, &val);
	val &= ~SGMII_IF_MODE_MASK;
	val &= ~SGMII_REMOTE_FAULT_DIS;

	switch (state->speed) {
	case SPEED_10:
		val |= SGMII_SPEED_10;
		break;
	case SPEED_100:
		val |= SGMII_SPEED_100;
		break;
	case SPEED_2500:
	case SPEED_1000:
	default:
		val |= SGMII_SPEED_1000;
		break;
	};

	/* SGMII 1G and 2.5G force mode can only work in full duplex
	 * mode, no matter SGMII_FORCE_HALF_DUPLEX is set or not.
	 */
	if (state->duplex != DUPLEX_FULL)
		val |= SGMII_DUPLEX_FULL;

	regmap_write(ss->regmap_sgmii[id], SGMSYS_SGMII_MODE, val);

	if(MTK_HAS_FLAGS(ss->flags[id],MTK_SGMII_PN_SWAP))
		regmap_update_bits(ss->regmap_sgmii[id], SGMSYS_QPHY_WRAP_CTRL,
				   SGMII_PN_SWAP_MASK, SGMII_PN_SWAP_TX_RX);

	/* Release PHYA power down state */
	regmap_write(ss->regmap_sgmii[id], SGMSYS_QPHY_PWR_STATE_CTRL, 0);

	if (MTK_HAS_CAPS(eth->soc->caps, MTK_NETSYS_V3))
		mtk_sgmii_setup_phya_gen2(ss, mac_id);

	return 0;
}

void mtk_sgmii_restart_an(struct mtk_eth *eth, int mac_id)
{
	struct mtk_xgmii *ss = eth->xgmii;
	unsigned int val, sid = mtk_mac2xgmii_id(eth, mac_id);

	/* Decide how GMAC and SGMIISYS be mapped */
	sid = (MTK_HAS_CAPS(eth->soc->caps, MTK_SHARED_SGMII)) ?
	       0 : sid;

	if (!ss->regmap_sgmii[sid])
		return;

	regmap_read(ss->regmap_sgmii[sid], SGMSYS_PCS_CONTROL_1, &val);
	val |= SGMII_AN_RESTART;
	regmap_write(ss->regmap_sgmii[sid], SGMSYS_PCS_CONTROL_1, val);
}
