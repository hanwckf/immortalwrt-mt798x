// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018-2019 MediaTek Inc.

/* A library for configuring path from GMAC/GDM to target PHY
 *
 * Author: Sean Wang <sean.wang@mediatek.com>
 *
 */

#include <linux/phy.h>
#include <linux/regmap.h>

#include "mtk_eth_soc.h"

struct mtk_eth_muxc {
	const char	*name;
	u64		cap_bit;
	int		(*set_path)(struct mtk_eth *eth, u64 path);
};

static const char *mtk_eth_path_name(u64 path)
{
	switch (path) {
	case MTK_ETH_PATH_GMAC1_RGMII:
		return "gmac1_rgmii";
	case MTK_ETH_PATH_GMAC1_TRGMII:
		return "gmac1_trgmii";
	case MTK_ETH_PATH_GMAC1_SGMII:
		return "gmac1_sgmii";
	case MTK_ETH_PATH_GMAC2_RGMII:
		return "gmac2_rgmii";
	case MTK_ETH_PATH_GMAC2_SGMII:
		return "gmac2_sgmii";
	case MTK_ETH_PATH_GMAC2_GEPHY:
		return "gmac2_gephy";
	case MTK_ETH_PATH_GMAC3_SGMII:
		return "gmac3_sgmii";
	case MTK_ETH_PATH_GDM1_ESW:
		return "gdm1_esw";
	case MTK_ETH_PATH_GMAC1_USXGMII:
		return "gmac1_usxgmii";
	case MTK_ETH_PATH_GMAC2_USXGMII:
		return "gmac2_usxgmii";
	case MTK_ETH_PATH_GMAC3_USXGMII:
		return "gmac3_usxgmii";
	default:
		return "unknown path";
	}
}

static int set_mux_gdm1_to_gmac1_esw(struct mtk_eth *eth, u64 path)
{
	bool updated = true;
	u32 val, mask, set;

	switch (path) {
	case MTK_ETH_PATH_GMAC1_SGMII:
		mask = ~(u32)MTK_MUX_TO_ESW;
		set = 0;
		break;
	case MTK_ETH_PATH_GDM1_ESW:
		mask = ~(u32)MTK_MUX_TO_ESW;
		set = MTK_MUX_TO_ESW;
		break;
	default:
		updated = false;
		break;
	};

	if (updated) {
		val = mtk_r32(eth, MTK_MAC_MISC);
		val = (val & mask) | set;
		mtk_w32(eth, val, MTK_MAC_MISC);
	}

	dev_dbg(eth->dev, "path %s in %s updated = %d\n",
		mtk_eth_path_name(path), __func__, updated);

	return 0;
}

static int set_mux_gmac2_gmac0_to_gephy(struct mtk_eth *eth, u64 path)
{
	unsigned int val = 0;
	bool updated = true;

	switch (path) {
	case MTK_ETH_PATH_GMAC2_GEPHY:
		val = ~(u32)GEPHY_MAC_SEL;
		break;
	default:
		updated = false;
		break;
	}

	if (updated)
		regmap_update_bits(eth->infra, INFRA_MISC2, GEPHY_MAC_SEL, val);

	dev_dbg(eth->dev, "path %s in %s updated = %d\n",
		mtk_eth_path_name(path), __func__, updated);

	return 0;
}

static int set_mux_u3_gmac2_to_qphy(struct mtk_eth *eth, u64 path)
{
	unsigned int val = 0,mask=0,reg=0;
	bool updated = true;

	switch (path) {
	case MTK_ETH_PATH_GMAC2_SGMII:
		if (MTK_HAS_CAPS(eth->soc->caps, MTK_U3_COPHY_V2)) {
			reg = USB_PHY_SWITCH_REG;
			val = SGMII_QPHY_SEL;
			mask = QPHY_SEL_MASK;
		} else {
			reg = INFRA_MISC2;
			val = CO_QPHY_SEL;
			mask = val;
		}
		break;
	default:
		updated = false;
		break;
	}

	if (updated)
		regmap_update_bits(eth->infra, reg, mask, val);

	dev_dbg(eth->dev, "path %s in %s updated = %d\n",
		mtk_eth_path_name(path), __func__, updated);

	return 0;
}

static int set_mux_gmac1_gmac2_to_sgmii_rgmii(struct mtk_eth *eth, u64 path)
{
	unsigned int val = 0;
	bool updated = true;

	spin_lock(&eth->syscfg0_lock);

	switch (path) {
	case MTK_ETH_PATH_GMAC1_SGMII:
		val = SYSCFG0_SGMII_GMAC1;
		break;
	case MTK_ETH_PATH_GMAC2_SGMII:
		val = SYSCFG0_SGMII_GMAC2;
		break;
	case MTK_ETH_PATH_GMAC1_RGMII:
	case MTK_ETH_PATH_GMAC2_RGMII:
		regmap_read(eth->ethsys, ETHSYS_SYSCFG0, &val);
		val &= SYSCFG0_SGMII_MASK;

		if ((path == MTK_GMAC1_RGMII && val == SYSCFG0_SGMII_GMAC1) ||
		    (path == MTK_GMAC2_RGMII && val == SYSCFG0_SGMII_GMAC2))
			val = 0;
		else
			updated = false;
		break;
	default:
		updated = false;
		break;
	};

	if (updated)
		regmap_update_bits(eth->ethsys, ETHSYS_SYSCFG0,
				   SYSCFG0_SGMII_MASK, val);

	spin_unlock(&eth->syscfg0_lock);

	dev_dbg(eth->dev, "path %s in %s updated = %d\n",
		mtk_eth_path_name(path), __func__, updated);

	return 0;
}

static int set_mux_gmac123_to_usxgmii(struct mtk_eth *eth, u64 path)
{
	unsigned int val = 0;
	bool updated = true;
	int mac_id = 0, id = 0;

	dev_dbg(eth->dev, "path %s in %s updated = %d\n",
		mtk_eth_path_name(path), __func__, updated);

	/* Disable SYSCFG1 SGMII */
	regmap_read(eth->ethsys, ETHSYS_SYSCFG0, &val);

	switch (path) {
	case MTK_ETH_PATH_GMAC1_USXGMII:
		val &= ~(u32)SYSCFG0_SGMII_GMAC1_V2;
		mac_id = MTK_GMAC1_ID;
		break;
	case MTK_ETH_PATH_GMAC2_USXGMII:
		val &= ~(u32)SYSCFG0_SGMII_GMAC2_V2;
		mac_id = MTK_GMAC2_ID;
		break;
	case MTK_ETH_PATH_GMAC3_USXGMII:
		val &= ~(u32)SYSCFG0_SGMII_GMAC3_V2;
		mac_id = MTK_GMAC3_ID;
		break;
	default:
		updated = false;
	};

	if (updated) {
		regmap_update_bits(eth->ethsys, ETHSYS_SYSCFG0,
				   SYSCFG0_SGMII_MASK, val);

		if (MTK_HAS_CAPS(eth->soc->caps, MTK_NETSYS_V3) &&
		    mac_id == MTK_GMAC2_ID) {
			id = mtk_mac2xgmii_id(eth, mac_id);
			if (MTK_HAS_FLAGS(eth->xgmii->flags[id],
					  MTK_USXGMII_INT_2500)) {
				val = mtk_r32(eth, MTK_XGMAC_STS(mac_id));
				mtk_w32(eth,
					val | (MTK_XGMAC_FORCE_LINK << 16),
					MTK_XGMAC_STS(mac_id));
			} else {
				regmap_update_bits(eth->infra,
						   TOP_MISC_NETSYS_PCS_MUX,
						   NETSYS_PCS_MUX_MASK,
						   MUX_G2_USXGMII_SEL);
			}
		}
	}

	/* Enable XGDM Path */
	val = mtk_r32(eth, MTK_GDMA_EG_CTRL(mac_id));
	val |= MTK_GDMA_XGDM_SEL;
	mtk_w32(eth, val, MTK_GDMA_EG_CTRL(mac_id));

	dev_dbg(eth->dev, "path %s in %s updated = %d\n",
		mtk_eth_path_name(path), __func__, updated);


	return 0;
}

static int set_mux_gmac123_to_gephy_sgmii(struct mtk_eth *eth, u64 path)
{
	unsigned int val = 0;
	bool updated = true;

	spin_lock(&eth->syscfg0_lock);

	regmap_read(eth->ethsys, ETHSYS_SYSCFG0, &val);

	switch (path) {
	case MTK_ETH_PATH_GMAC1_SGMII:
		val |= SYSCFG0_SGMII_GMAC1_V2;
		break;
	case MTK_ETH_PATH_GMAC2_GEPHY:
		val &= ~(u32)SYSCFG0_SGMII_GMAC2_V2;
		break;
	case MTK_ETH_PATH_GMAC2_SGMII:
		val |= SYSCFG0_SGMII_GMAC2_V2;
		break;
	case MTK_ETH_PATH_GMAC3_SGMII:
		val |= SYSCFG0_SGMII_GMAC3_V2;
		break;
	default:
		updated = false;
	};

	if (updated)
		regmap_update_bits(eth->ethsys, ETHSYS_SYSCFG0,
				   SYSCFG0_SGMII_MASK, val);

	spin_unlock(&eth->syscfg0_lock);

	dev_dbg(eth->dev, "path %s in %s updated = %d\n",
		mtk_eth_path_name(path), __func__, updated);

	return 0;
}

static const struct mtk_eth_muxc mtk_eth_muxc[] = {
	{
		.name = "mux_gdm1_to_gmac1_esw",
		.cap_bit = MTK_ETH_MUX_GDM1_TO_GMAC1_ESW,
		.set_path = set_mux_gdm1_to_gmac1_esw,
	}, {
		.name = "mux_gmac2_gmac0_to_gephy",
		.cap_bit = MTK_ETH_MUX_GMAC2_GMAC0_TO_GEPHY,
		.set_path = set_mux_gmac2_gmac0_to_gephy,
	}, {
		.name = "mux_u3_gmac2_to_qphy",
		.cap_bit = MTK_ETH_MUX_U3_GMAC2_TO_QPHY,
		.set_path = set_mux_u3_gmac2_to_qphy,
	}, {
		.name = "mux_gmac1_gmac2_to_sgmii_rgmii",
		.cap_bit = MTK_ETH_MUX_GMAC1_GMAC2_TO_SGMII_RGMII,
		.set_path = set_mux_gmac1_gmac2_to_sgmii_rgmii,
	}, {
		.name = "mux_gmac12_to_gephy_sgmii",
		.cap_bit = MTK_ETH_MUX_GMAC12_TO_GEPHY_SGMII,
		.set_path = set_mux_gmac123_to_gephy_sgmii,
	}, {
		.name = "mux_gmac123_to_gephy_sgmii",
		.cap_bit = MTK_ETH_MUX_GMAC123_TO_GEPHY_SGMII,
		.set_path = set_mux_gmac123_to_gephy_sgmii,
	}, {
		.name = "mux_gmac123_to_usxgmii",
		.cap_bit = MTK_ETH_MUX_GMAC123_TO_USXGMII,
		.set_path = set_mux_gmac123_to_usxgmii,
	},
};

static int mtk_eth_mux_setup(struct mtk_eth *eth, u64 path)
{
	int i, err = 0;

	if (!MTK_HAS_CAPS(eth->soc->caps, path)) {
		dev_err(eth->dev, "path %s isn't support on the SoC\n",
			mtk_eth_path_name(path));
		return -EINVAL;
	}

	if (!MTK_HAS_CAPS(eth->soc->caps, MTK_MUX))
		return 0;

	/* Setup MUX in path fabric */
	for (i = 0; i < ARRAY_SIZE(mtk_eth_muxc); i++) {
		if (MTK_HAS_CAPS(eth->soc->caps, mtk_eth_muxc[i].cap_bit)) {
			err = mtk_eth_muxc[i].set_path(eth, path);
			if (err)
				goto out;
		} else {
			dev_dbg(eth->dev, "mux %s isn't present on the SoC\n",
				mtk_eth_muxc[i].name);
		}
	}

out:
	return err;
}

int mtk_gmac_usxgmii_path_setup(struct mtk_eth *eth, int mac_id)
{
	int err;
	u64 path;

	path = (mac_id == MTK_GMAC1_ID) ?  MTK_ETH_PATH_GMAC1_USXGMII :
	       (mac_id == MTK_GMAC2_ID) ?  MTK_ETH_PATH_GMAC2_USXGMII :
					   MTK_ETH_PATH_GMAC3_USXGMII;

	dev_err(eth->dev, "%s path %s in\n", __func__,
		mtk_eth_path_name(path));

	/* Setup proper MUXes along the path */
	err = mtk_eth_mux_setup(eth, path);
	if (err)
		return err;

	return 0;
}

int mtk_gmac_sgmii_path_setup(struct mtk_eth *eth, int mac_id)
{
	int err;
	u64 path;

	path = (mac_id == MTK_GMAC1_ID) ? MTK_ETH_PATH_GMAC1_SGMII :
	       (mac_id == MTK_GMAC2_ID) ? MTK_ETH_PATH_GMAC2_SGMII :
					  MTK_ETH_PATH_GMAC3_SGMII;

	/* Setup proper MUXes along the path */
	err = mtk_eth_mux_setup(eth, path);
	if (err)
		return err;

	return 0;
}

int mtk_gmac_gephy_path_setup(struct mtk_eth *eth, int mac_id)
{
	int err;
	u64 path = 0;

	if (mac_id == 1)
		path = MTK_ETH_PATH_GMAC2_GEPHY;

	if (!path)
		return -EINVAL;

	/* Setup proper MUXes along the path */
	err = mtk_eth_mux_setup(eth, path);
	if (err)
		return err;

	return 0;
}

int mtk_gmac_rgmii_path_setup(struct mtk_eth *eth, int mac_id)
{
	int err;
	u64 path;

	path = (mac_id == 0) ?  MTK_ETH_PATH_GMAC1_RGMII :
				MTK_ETH_PATH_GMAC2_RGMII;

	/* Setup proper MUXes along the path */
	err = mtk_eth_mux_setup(eth, path);
	if (err)
		return err;

	return 0;
}

