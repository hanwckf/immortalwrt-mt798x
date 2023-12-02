include $(TOPDIR)/rules.mk

PKG_NAME:=mtwifi-cfg
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/mtwifi-cfg
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  SUBMENU:=Applications
  TITLE:=mtwifi configure scripts for mt798x
  DEPENDS:=+iwinfo +wifi-dats +lua-cjson +datconf-lua @!PACKAGE_luci-app-mtk @!PACKAGE_wifi-profile
endef

define Package/mtwifi-cfg-luci
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  SUBMENU:=Applications
  TITLE:=luci files for mtwifi configure scripts
  DEPENDS:=+mtwifi-cfg +luci
endef

define Build/Compile
endef

define Package/mtwifi-cfg/install
	$(INSTALL_DIR) $(1)/sbin $(1)/usr/lib/lua
	$(INSTALL_DIR) $(1)/lib/netifd/wireless/ $(1)/lib/wifi/

	$(INSTALL_DIR) $(1)/etc/hotplug.d/net/

	$(INSTALL_BIN) ./files/netifd/mtwifi.sh $(1)/lib/netifd/wireless/
	$(INSTALL_BIN) ./files/mtwifi.sh $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/mtwifi-cfg/mtwifi_cfg $(1)/sbin/
	$(INSTALL_BIN) ./files/mtwifi-cfg/inspect.lua $(1)/usr/lib/lua/
	$(INSTALL_BIN) ./files/mtwifi-cfg/mtwifi_defs.lua $(1)/usr/lib/lua/
	$(INSTALL_BIN) ./files/mtwifi-cfg/mtwifi_utils.lua $(1)/usr/lib/lua/
	$(INSTALL_BIN) ./files/l1util/l1util $(1)/sbin/
	$(INSTALL_BIN) ./files/l1util/l1dat_parser.lua $(1)/usr/lib/lua/
	$(INSTALL_DATA) ./files/hotplug/10-mtwifi-detect $(1)/etc/hotplug.d/net/
endef

define Package/mtwifi-cfg-luci/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults/ $(1)/usr/share/mtwifi-cfg-luci

	$(INSTALL_DATA) ./files/luci/wireless-mtk.js  $(1)/usr/share/mtwifi-cfg-luci
	$(INSTALL_DATA) ./files/luci/luci-mod-status.json  $(1)/usr/share/mtwifi-cfg-luci
	$(INSTALL_DATA) ./files/luci/mtwifi-cfg-luci.default $(1)/etc/uci-defaults/20-mtwifi-cfg-luci.default
endef

$(eval $(call BuildPackage,mtwifi-cfg))
$(eval $(call BuildPackage,mtwifi-cfg-luci))
