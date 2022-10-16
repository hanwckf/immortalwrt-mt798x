#
# Copyright (C) 2021 MediaTek Inc. All rights reserved.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=crc32sum
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/host-build.mk

define Host/Prepare
	mkdir -p $(HOST_BUILD_DIR)
	$(CP) -a ./src/* $(HOST_BUILD_DIR)/
endef

define Host/Install
	$(INSTALL_BIN) $(HOST_BUILD_DIR)/crc32sum $(STAGING_DIR_HOST)/bin/
endef

$(eval $(call HostBuild))
