# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2010 OpenWrt.org

include $(TOPDIR)/rules.mk

ARCH:=powerpc
BOARD:=mpc85xx
BOARDNAME:=Freescale MPC85xx
CPU_TYPE:=8540
FEATURES:=squashfs ramdisk
SUBTARGETS:=p1010 p1020 p2020

KERNEL_PATCHVER:=5.4

KERNELNAME:=zImage

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES += \
	kmod-input-core kmod-input-gpio-keys kmod-button-hotplug \
	kmod-leds-gpio swconfig kmod-ath9k wpad-basic-openssl kmod-usb2

$(eval $(call BuildTarget))
