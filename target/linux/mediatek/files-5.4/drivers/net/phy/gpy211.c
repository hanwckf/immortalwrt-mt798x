// SPDX-License-Identifier: GPL-2.0+
#include <linux/bitfield.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/init.h>

struct t_phydev {
	// struct timer_list timer;
	struct phy_device *phydev;
	struct delayed_work dw;
};

#define PHY_MIISTAT 0x18

#define PHY_MIISTAT_SPD_MASK	GENMASK(2, 0)
#define PHY_MIISTAT_DPX		BIT(3)
#define PHY_MIISTAT_LS		BIT(10)

#define PHY_MIISTAT_SPD_10	0
#define PHY_MIISTAT_SPD_100	1
#define PHY_MIISTAT_SPD_1000	2
#define PHY_MIISTAT_SPD_2500	4

void gpy211_status_timer(struct work_struct *t);

// Starder Magament Registers
#define MDIO_MMD_STD              0x0
#define VSPEC1_NBT_DS_CTRL        0xA
#define DOWNSHIFT_THR_MASK    GENMASK(6, 2)
#define DOWNSHIFT_EN          BIT(1)

#define DEFAULT_INTEL_GPY211_PHYID1_VALUE	0x67c9

#define MAXLINEAR_MAX_LED_INDEX 4

static int gpy211_phy_config_init(struct phy_device *phydev)
{
	return 0;
}

#define MAX_RETRY_TIMES	80
#define RETRY_INTERVAL	10 // unit is ms
int gpy211_phy_probe(struct phy_device *phydev)
{
	int sgmii_reg = phy_read_mmd(phydev, MDIO_MMD_VEND1, 8);
	struct device_node *of_node = phydev->mdio.dev.of_node;
	u32 reg_value[MAXLINEAR_MAX_LED_INDEX] = {0};
	int ret;
	int i=0;
	u32 phyid1;
	int buf = 0;

	/*
	 * After reset signal to GPY211B1VC(SSTEP SLN8A), the chip may take 600 ms to bootup complete.
	 * driver can successfully read/write the register after bootup complete.
	 * If phy is ready, the STD_PHYID1(Register 0.2) should be 0x67c9.
	 */
	i = MAX_RETRY_TIMES;
	while (i) {
		phyid1 = phy_read_mmd(phydev, MDIO_MMD_STD, MDIO_DEVID1);
		if ( phyid1 == DEFAULT_INTEL_GPY211_PHYID1_VALUE )
			break;

		msleep(RETRY_INTERVAL);
		i--;
	}
	if (!i) {
		phydev_err(phydev, "phy is not ready over %d ms!\n", (MAX_RETRY_TIMES-i)*10);
	}else {
		phydev_info(phydev, "driver wait %d ms for phy ready!\n", (MAX_RETRY_TIMES-i)*10);
	}

	ret = of_property_read_u32_array(of_node, "maxlinear,led-reg", reg_value, MAXLINEAR_MAX_LED_INDEX);

	if (ret < 0) {
		phydev_info(phydev, "not config \"maxlinear,led-reg\" parameter\n");
	} else {
		for(i=0;i<MAXLINEAR_MAX_LED_INDEX;i++) {
			phydev_dbg(phydev, "led-reg %d is %x.\n", i, reg_value[i]);
			phy_write_mmd(phydev, MDIO_MMD_VEND1, i+1, reg_value[i]);
		}
	}

	/* enable 2.5G SGMII rate adaption */
	phy_write_mmd(phydev, MDIO_MMD_VEND1, 8, 0x24e2);

	buf = phy_read_mmd(phydev, MDIO_MMD_VEND1, VSPEC1_NBT_DS_CTRL);
	//enable downshift and set training counter threshold to 3
	phy_write_mmd(phydev, MDIO_MMD_VEND1, VSPEC1_NBT_DS_CTRL, buf | FIELD_PREP(DOWNSHIFT_THR_MASK, 0x3) | DOWNSHIFT_EN);

	return 0;
}

static int gpy211_get_features(struct phy_device *phydev)
{
	struct t_phydev *t_phy;
	t_phy = kzalloc(sizeof(*t_phy), GFP_KERNEL);
	t_phy->phydev = phydev;

	int ret;

	ret = genphy_read_abilities(phydev);
	if (ret)
		return ret;

	/* GPY211 with rate adaption supports 100M/1G/2.5G speed. */

	linkmode_clear_bit(ETHTOOL_LINK_MODE_10baseT_Half_BIT,
			   phydev->supported);
	linkmode_clear_bit(ETHTOOL_LINK_MODE_10baseT_Full_BIT,
			   phydev->supported);
	linkmode_set_bit(ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
			 phydev->supported);

	//set timer to query status
	// timer_setup(&t_phy->timer, gpy211_status_timer, 0);
	// mod_timer(&t_phy->timer, jiffies + 20*HZ);
	INIT_DELAYED_WORK(&t_phy->dw, gpy211_status_timer);
	schedule_delayed_work(&t_phy->dw, msecs_to_jiffies(2000));

	return 0;
}

static int gpy_read_status(struct phy_device *phydev)
{
	int old_link = phydev->link;
	const char *speed;
	const char *duplex;

	phydev_dbg(phydev, "### line[%d] addr[%d] link[%d] phyid[0x%x]\n", __LINE__, phydev->mdio.addr, phydev->link, phydev->phy_id);
	struct device_node *of_node = phydev->mdio.dev.of_node;

	// int ret = phydev->mdio.bus->read(phydev->mdio.bus, phydev->mdio.addr, PHY_MIISTAT);
	int ret = phy_read_mmd(phydev, MDIO_MMD_STD, PHY_MIISTAT);

	if(ret)
	{
		phydev_dbg(phydev, "### line[%d] addr[%d] val=[0x%x] link[%d] phyid[0x%x]\n", __LINE__, phydev->mdio.addr, ret, phydev->link, phydev->phy_id);
		phydev->link = (ret & PHY_MIISTAT_LS) ? 1 : 0;
		phydev->duplex = (ret & PHY_MIISTAT_DPX) ? DUPLEX_FULL : DUPLEX_HALF;
		duplex = (phydev->duplex == DUPLEX_FULL) ? "F" : "H";
		switch (FIELD_GET(PHY_MIISTAT_SPD_MASK, ret)) {
			case PHY_MIISTAT_SPD_10:
				phydev->speed = SPEED_10;
				speed = "10";
				break;
			case PHY_MIISTAT_SPD_100:
				phydev->speed = SPEED_100;
				speed = "100";
				break;
			case PHY_MIISTAT_SPD_1000:
				phydev->speed = SPEED_1000;
				speed = "1000";
				break;
			case PHY_MIISTAT_SPD_2500:
				phydev->speed = SPEED_2500;
				speed = "2500";
				break;
		}

		phydev_dbg(phydev, "### line[%d] addr[%d] old[%d] newlink[%d] \n", __LINE__, phydev->mdio.addr, old_link, phydev->link);

		if(old_link != phydev->link)
		{
			if(phydev->link)
				phydev_info(phydev, "###phy_addr[%d] link up speed[%s]\n", phydev->mdio.addr, speed);
			else
				phydev_info(phydev, "###phy_addr[%d] link down \n", phydev->mdio.addr);
		}
	}

	return 0;
}

void gpy211_status_timer(struct work_struct *t)
{
	struct t_phydev *t_phy = container_of(t, struct t_phydev, dw.work);
	gpy_read_status(t_phy->phydev);

	//trigger timer again
	// mod_timer(&t_phy->timer, jiffies + HZ);
	schedule_delayed_work(&t_phy->dw, msecs_to_jiffies(2000));
}

static struct phy_driver gpy211_phy_driver[] = {
	{
		PHY_ID_MATCH_MODEL(0x67c9de0a),
		.name		= "Intel GPY211 PHY",
		.config_init	= gpy211_phy_config_init,
		.probe		= gpy211_phy_probe,
		.get_features	= gpy211_get_features,
		.read_status	= gpy_read_status,
	}
};

module_phy_driver(gpy211_phy_driver);

static struct mdio_device_id __maybe_unused gpy211_phy_tbl[] = {
	{ PHY_ID_MATCH_VENDOR(0x67c9de00) },
	{ }
};

MODULE_DESCRIPTION("Intel GPY211 PHY driver with rate adaption");
MODULE_AUTHOR("Landen Chao <landen.chao@mediatek.com>");
MODULE_LICENSE("GPL");

MODULE_DEVICE_TABLE(mdio, gpy211_phy_tbl);
