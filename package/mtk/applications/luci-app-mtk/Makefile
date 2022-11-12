#
# Copyright (C) Hua Shao <nossiac@163.com>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=MediaTek Proprietary Configuration.
LUCI_DEPENDS:=+datconf-lua
LUCI_MK_PATH_OLD:=$(shell test -e ../luci.mk && echo "old")
LUCI_MK_PATH_FEEDS:=$(shell test -e $(TOPDIR)/feeds/luci/luci.mk && echo "feeds")
ifeq ($(LUCI_MK_PATH_OLD),old)
include ../luci.mk
else ifeq ($(LUCI_MK_PATH_FEEDS),feeds)
include $(TOPDIR)/feeds/luci/luci.mk
else
include $(TOPDIR)/package/luci/luci.mk
endif

# call BuildPackage - OpenWrt buildroot signature
