#
# Copyright (C) 2021 MediaTek Inc. All rights reserved.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

all: crc32sum

crc32sum: crc32sum.c
	$(CC) $(CFLAGS) -O2 -ggdb -MD -o $@ $< $(LDFLAGS)

clean:
	rm -f crc32sum crc32sum.d

.PHONY: clean

-include crc32sum.d