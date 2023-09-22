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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "libfstools.h"

int
find_overlay_mount(char *overlay)
{
	FILE *fp = fopen("/proc/mounts", "r");
	size_t len = strlen(overlay);
	static char line[256];
	int ret = -1;

	if(!fp)
		return ret;

	while (ret && fgets(line, sizeof(line), fp))
		if (len < sizeof(line) && !strncmp(line, overlay, len) && line[len] == ' ')
			ret = 0;

	fclose(fp);

	return ret;
}

/*
 * Find path of a device mounted to the given point.
 */
char*
find_mount(char *mp)
{
	FILE *fp = fopen("/proc/mounts", "r");
	static char line[256];

	if(!fp)
		return NULL;

	while (fgets(line, sizeof(line), fp)) {
		char *s, *t = strstr(line, " ");

		if (!t) {
			fclose(fp);
			return NULL;
		}
		*t = '\0';
		t++;
		s = strstr(t, " ");
		if (!s) {
			fclose(fp);
			return NULL;
		}
		*s = '\0';

		if (!strcmp(t, mp)) {
			fclose(fp);
			return line;
		}
	}

	fclose(fp);

	return NULL;
}

/*
 * Match filesystem type against a bunch of valid types
 *
 * jffs2reset may ask if the filesystem type is actually ready for use
 * with overlayfs before wiping it...
 */
static int fs_rootfs_only(char *fstype)
{
	if (strncmp(fstype, "ext4", 4) &&
	    strncmp(fstype, "f2fs", 4) &&
	    strncmp(fstype, "jffs2", 5) &&
	    strncmp(fstype, "ubifs", 5)) {
		ULOG_ERR("block is mounted with wrong fs\n");
		return 1;
	}
	return 0;
}

/*
 * Check if a given device is mounted and return its mountpoint
 */
char*
find_mount_point(char *block, int root_only)
{
	FILE *fp = fopen("/proc/self/mountinfo", "r");
	static char line[256];
	char *point = NULL, *pos, *tmp, *cpoint, *devname, *fstype;
	struct stat s;
	int rstat;
	unsigned int minor, major;

	if (!block)
		return NULL;

	if (!fp)
		return NULL;

	rstat = stat(block, &s);

	while (fgets(line, sizeof(line), fp)) {
		/* skip first two columns */
		pos = strchr(line, ' ');
		if (!pos)
			continue;

		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

		/* extract block device major:minor */
		tmp = ++pos;
		pos = strchr(pos, ':');
		if (!pos)
			continue;

		*pos = '\0';
		major = atoi(tmp);

		tmp = ++pos;
		pos = strchr(pos, ' ');
		if (!pos)
			continue;

		*pos = '\0';
		minor = atoi(tmp);

		/* skip another column */
		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

		/* get mountpoint */
		tmp = ++pos;
		pos = strchr(pos, ' ');
		if (!pos)
			continue;

		*pos = '\0';
		cpoint = tmp;

		/* skip another two columns */
		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

		/* get fstype */
		tmp = ++pos;
		pos = strchr(pos, ' ');
		if (!pos)
			continue;

		*pos = '\0';
		fstype = tmp;

		/* get device name */
		tmp = ++pos;
		pos = strchr(pos, ' ');
		if (!pos)
			continue;

		*pos = '\0';
		devname = tmp;

		/* if device name matches */
		if (!strcmp(block, devname)) {
			if (root_only && fs_rootfs_only(fstype))
				break;

			/* found, return mountpoint */
			point = strdup(cpoint);
			break;
		}

		/* last chance: check if major:minor of block device match */
		if (rstat)
			continue;

		if (!S_ISBLK(s.st_mode))
			continue;

		if (major == major(s.st_rdev) &&
		    minor == minor(s.st_rdev)) {
			if (root_only && fs_rootfs_only(fstype))
				break;

			/* found, return mountpoint */
			point = strdup(cpoint);
			break;
		}
	}

	fclose(fp);

	return point;
}

int
find_filesystem(char *fs)
{
	FILE *fp = fopen("/proc/filesystems", "r");
	static char line[256];
	int ret = -1;

	if (!fp) {
		ULOG_ERR("opening /proc/filesystems failed: %m\n");
		goto out;
	}

	while (ret && fgets(line, sizeof(line), fp))
		if (strstr(line, fs))
			ret = 0;

	fclose(fp);

out:
	return ret;
}
