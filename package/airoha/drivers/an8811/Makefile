# SPDX-License-Identifier: GPL-2.0

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=airoha_an8811
PKG_RELEASE:=1.2.5

include $(INCLUDE_DIR)/package.mk

define KernelPackage/phy-airoha-en8811h
  CATEGORY:=Airoha Properties
  SUBMENU:=Drivers
	TITLE:=Airoha EN8811H PHY driver
	DEPENDS:=+kmod-libphy
	FILES:=$(PKG_BUILD_DIR)/mtk/air_en8811h.ko
	AUTOLOAD:=$(call AutoLoad,10,air_en8811h)
	KCONFIG:= \
	CONFIG_AIROHA_EN8811H_PHY=m \
	CONFIG_AIROHA_EN8811H_PHY_DEBUGFS=n
endef

define KernelPackage/phy-airoha-en8811h/description
	Kernel module for Airoha EN8811H PHY driver
endef

MAKE_OPTS_AIR8811:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	M="$(PKG_BUILD_DIR)/mtk/"

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
@( \
	if [ -f ./src/mtk/Makefile ]; then \
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS_AIR8811) \
		modules; \
	else \
	echo "Failed to compile mtk/air_en8811h"; \
	fi; \
)
endef

$(eval $(call KernelPackage,phy-airoha-en8811h))
