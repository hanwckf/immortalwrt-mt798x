#
# Copyright (C) 2016 MediaTek
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bpir3_mini-properties
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/bpir3_mini-properties
  SECTION:=BPI-R3-MINI Properties
  CATEGORY:=BPI-R3-MINI Properties
  TITLE:=PHYs firmware & fan control for BPI-R3-MINI 
  MENU:=1
endef

define Package/bpir3_mini-properties/description
  This package install PHYs firmware & fan control for BPI-R3-MINI.
endef

define Package/bpir3_mini-properties/config
endef

define Build/Compile
endef

define Package/bpir3_mini-properties/install
	$(INSTALL_DIR) $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/rc.d/
	$(INSTALL_DIR) $(1)/lib/firmware/
	$(INSTALL_BIN) ./files/etc/init.d/fanspeed $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/etc/rc.d/S99xfanspeed $(1)/etc/rc.d/
	$(INSTALL_BIN) ./files/etc/init.d/ltecalling $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/etc/rc.d/S25xltecalling $(1)/etc/rc.d/
	$(INSTALL_BIN) ./files/lib/firmware/EthMD32.dm.bin $(1)/lib/firmware/
	$(INSTALL_BIN) ./files/lib/firmware/EthMD32.DSP.bin $(1)/lib/firmware/
endef

$(eval $(call BuildPackage,bpir3_mini-properties))
