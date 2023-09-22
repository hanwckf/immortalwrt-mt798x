/*
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 John Crispin <blogic@openwrt.org>
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

#define _DEFAULT_SOURCE

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <dirent.h>
#include <limits.h>
#include <fnmatch.h>

#include "libblkid-tiny.h"

#include <syslog.h>

static char buf[PATH_MAX + 1];
static char buf2[PATH_MAX];
static unsigned int mode = 0600;

static void make_dev(const char *path, bool block, int major, int minor)
{
	unsigned int _mode = mode | (block ? S_IFBLK : S_IFCHR);

	mknod(path, _mode, makedev(major, minor));
}

static void find_devs(bool block)
{
	char *path = block ? "/sys/dev/block" : "/sys/dev/char";
	struct dirent *dp;
	DIR *dir;

	dir = opendir(path);
	if (!dir)
		return;

	path = buf2 + sprintf(buf2, "%s/", path);
	while ((dp = readdir(dir)) != NULL) {
		char *c;
		int major = 0, minor = 0;
		int len;

		if (dp->d_type != DT_LNK)
			continue;

		if (sscanf(dp->d_name, "%d:%d", &major, &minor) != 2)
			continue;

		strcpy(path, dp->d_name);
		len = readlink(buf2, buf, sizeof(buf));
		if (len <= 0 || len == sizeof(buf))
			continue;

		buf[len] = 0;

		c = strrchr(buf, '/');
		if (!c)
			continue;


		c++;
		make_dev(c, block, major, minor);
	}
	closedir(dir);
}

int mkblkdev(void)
{
	if (chdir("/dev"))
		return 1;

	mode = 0600;
	find_devs(true);

	return chdir("/");
}
