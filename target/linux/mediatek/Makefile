# Copyright (c) 2015 OpenWrt.org
#
include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=mediatek
BOARDNAME:=MediaTek Ralink ARM
SUBTARGETS:=mt7986 mt7981
FEATURES:=squashfs nand emmc ramdisk fpu

KERNEL_PATCHVER:=5.4
KERNEL_TESTING_PATCHVER:=5.4

include $(INCLUDE_DIR)/target.mk
DEFAULT_PACKAGES += \
	kmod-leds-gpio kmod-gpio-button-hotplug \
	autocore-arm uboot-envtools mtk-smp zoneinfo-core zoneinfo-asia

$(eval $(call BuildTarget))
