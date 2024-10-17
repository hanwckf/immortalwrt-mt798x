#!/usr/bin/env bash
#
# Copyright (C) 2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

set -ex
[ $# -eq 4 ] || {
    echo "SYNTAX: $0 <file> <bl2 image> <fip image> <ubi image>"
    exit 1
}

OUTPUT_FILE="$1"
BL2_FILE="$2"
FIP_FILE="$3"
UBI_FILE="$4"

BS=512
BL2_OFFSET=0          # 0x00000000
FIP_OFFSET=7168       # 0x00380000
UBI_OFFSET=11264      # 0x00580000

dd bs="$BS" if="$BL2_FILE"            of="$OUTPUT_FILE"    seek="$BL2_OFFSET"
dd bs="$BS" if="$FIP_FILE"            of="$OUTPUT_FILE"    seek="$FIP_OFFSET"
dd bs="$BS" if="$UBI_FILE"            of="$OUTPUT_FILE"    seek="$UBI_OFFSET" 
