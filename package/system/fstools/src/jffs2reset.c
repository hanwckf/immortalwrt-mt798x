/*
 * Copyright (C) 2014 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <libubox/ulog.h>

#include <fcntl.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <mtd/ubi-user.h>

#include "libfstools/libfstools.h"
#include "libfstools/volume.h"

static int jffs2_mark(struct volume *v);

static int
ask_user(void)
{
	ULOG_WARN("This will erase all settings and remove any installed packages. Are you sure? [N/y]\n");
	if (getchar() != 'y')
		return -1;
	return 0;
}

static int jffs2_reset(struct volume *v, int reset, int keep)
{
	char *mp;

	mp = find_mount_point(v->blk, 1);
	if (mp) {
		ULOG_INFO("%s is mounted as %s, only erasing files\n", v->blk, mp);
		fs_state_set("/overlay", FS_STATE_PENDING);
		overlay_delete(mp, keep);
		mount(mp, "/", NULL, MS_REMOUNT, 0);
	} else {
		ULOG_INFO("%s is not mounted\n", v->blk);
		return jffs2_mark(v);
	}

	if (reset) {
		sync();
		sleep(2);
		reboot(RB_AUTOBOOT);
		while (1)
			;
	}

	return 0;
}

static int jffs2_mark(struct volume *v)
{
	__u32 deadc0de = __cpu_to_be32(0xdeadc0de);
	size_t sz;
	int fd;

	fd = open(v->blk, O_WRONLY);
	ULOG_INFO("%s will be erased on next mount\n", v->blk);
	if (!fd) {
		ULOG_ERR("opening %s failed\n", v->blk);
		return -1;
	}

	if (volume_identify(v) == FS_UBIFS) {
		uint64_t llz = 0;
		int ret = ioctl(fd, UBI_IOCVOLUP, &llz);
		close(fd);
		return ret;
	}

	sz = write(fd, &deadc0de, sizeof(deadc0de));
	close(fd);

	if (sz != 4) {
		ULOG_ERR("writing %s failed: %m\n", v->blk);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct volume *v;
	int ch, yes = 0, reset = 0, keep = 0;
	while ((ch = getopt(argc, argv, "yrk")) != -1) {
		switch(ch) {
		case 'y':
			yes = 1;
			break;
		case 'r':
			reset = 1;
			break;
		case 'k':
			keep = 1;
			break;
		}

	}

	if (!yes && ask_user())
		return -1;

	/*
	 * TODO: Currently this only checks if kernel supports OverlayFS. We
	 * should check if there is a mount point using it with rootfs_data
	 * as upperdir.
	 */
	if (find_filesystem("overlay")) {
		ULOG_ERR("overlayfs not supported by kernel\n");
		return -1;
	}

	v = volume_find("rootfs_data");
	if (!v) {
		ULOG_ERR("MTD partition 'rootfs_data' not found\n");
		return -1;
	}

	volume_init(v);
	if (!strcmp(*argv, "jffs2mark"))
		return jffs2_mark(v);
	return jffs2_reset(v, reset, keep);
}
