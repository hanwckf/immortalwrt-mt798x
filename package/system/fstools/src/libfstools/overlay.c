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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>

#include <asm/byteorder.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <glob.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include "libfstools.h"
#include "volume.h"

#ifndef GLOB_ONLYDIR
#define GLOB_ONLYDIR 0x100
#endif

#define SWITCH_JFFS2 "/tmp/.switch_jffs2"
#define OVERLAYDIR "/rom/overlay"

static bool keep_sysupgrade;

static int
handle_rmdir(const char *dir)
{
	struct dirent *dt;
	struct stat st;
	DIR *d;
	int fd;

	d = opendir(dir);
	if (!d)
		return -1;

	fd = dirfd(d);

	while ((dt = readdir(d)) != NULL) {
		if (fstatat(fd, dt->d_name, &st, AT_SYMLINK_NOFOLLOW) || S_ISDIR(st.st_mode))
			continue;

		if (keep_sysupgrade && !strcmp(dt->d_name, "sysupgrade.tgz"))
			continue;

		unlinkat(fd, dt->d_name, 0);
	}

	closedir(d);
	rmdir(dir);

	return 0;
}

void
foreachdir(const char *dir, int (*cb)(const char*))
{
	static char *globdir = NULL;
	static size_t globdirlen = 0;
	struct stat s = { 0 };
	size_t dirlen = strlen(dir);
	glob_t gl;
	int j;

	if (dirlen + sizeof("/*") > globdirlen) {
		/* Alloc extra 256 B to avoid too many reallocs */
		size_t len = dirlen + sizeof("/*") + 256;
		char *tmp;

		tmp = realloc(globdir, len);
		if (!tmp)
			return;
		globdir = tmp;
		globdirlen = len;
	}

	sprintf(globdir, "%s/*", dir);

	/* Include GLOB_MARK as callbacks expect a trailing slash */
	if (!glob(globdir, GLOB_NOESCAPE | GLOB_MARK | GLOB_ONLYDIR, NULL, &gl))
		for (j = 0; j < gl.gl_pathc; j++) {
			char *dir = gl.gl_pathv[j];
			int len = strlen(gl.gl_pathv[j]);
			int err;

			/* Quick way of skipping files */
			if (dir[len - 1] != '/')
				continue;

			/* lstat needs path without a trailing slash */
			if (len > 1)
				dir[len - 1] = '\0';
			err = lstat(gl.gl_pathv[j], &s);
			if (len > 1)
				dir[len - 1] = '/';

			if (!err && !S_ISLNK(s.st_mode))
				foreachdir(gl.gl_pathv[j], cb);
	}
	cb(dir);
}

static void foreach_mount(int (*cb)(const char *, const char *))
{
	FILE *fp = fopen("/proc/mounts", "r");
	static char line[256];

	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		char device[32], mount_point[32];

		if (sscanf(line, "%31s %31s %*s %*s %*u %*u", device, mount_point) == 2)
			cb(device, mount_point);
	}

	fclose(fp);
}

void
overlay_delete(const char *dir, bool _keep_sysupgrade)
{
	keep_sysupgrade = _keep_sysupgrade;
	foreachdir(dir, handle_rmdir);
}

static int
overlay_mount(struct volume *v, char *fs)
{
	if (mkdir("/tmp/overlay", 0755)) {
		ULOG_ERR("failed to mkdir /tmp/overlay: %m\n");
		return -1;
	}

	if (mount(v->blk, "/tmp/overlay", fs, MS_NOATIME, NULL)) {
		ULOG_ERR("failed to mount -t %s %s /tmp/overlay: %m\n", fs, v->blk);
		return -1;
	}

	return 0;
}

/**
 * ovl_move_mount - move mount point to the new root
 */
static int ovl_move_mount(const char *device, const char *mount_point)
{
	static const char *prefix = "/tmp/root/";

	if (strncmp(mount_point, prefix, strlen(prefix)))
		return 0;

	return mount_move(prefix, "/", mount_point + strlen(prefix));
}

static int
switch2jffs(struct volume *v)
{
	struct stat s;
	int ret, fd;

	if (!stat(SWITCH_JFFS2, &s)) {
		ULOG_ERR("jffs2 switch already running\n");
		return -1;
	}

	fd = creat(SWITCH_JFFS2, 0600);
	if (fd == -1) {
		ULOG_ERR("failed - cannot create jffs2 switch mark: %m\n");
		return -1;
	}
	close(fd);

	ret = mount(v->blk, OVERLAYDIR, "jffs2", MS_NOATIME, NULL);
	unlink(SWITCH_JFFS2);
	if (ret) {
		ULOG_ERR("failed - mount -t jffs2 %s %s: %m\n", v->blk, OVERLAYDIR);
		return -1;
	}
	selinux_restorecon(OVERLAYDIR);

	if (mount("none", "/", NULL, MS_NOATIME | MS_REMOUNT, 0)) {
		ULOG_ERR("failed - mount -o remount,ro none: %m\n");
		return -1;
	}

	if (system("cp -a /tmp/root/* /rom/overlay")) {
		ULOG_ERR("failed - cp -a /tmp/root/* /rom/overlay: %m\n");
		return -1;
	}

	if (pivot("/rom", "/mnt")) {
		ULOG_ERR("failed - pivot /rom /mnt: %m\n");
		return -1;
	}

	if (mount_move("/mnt", "/tmp/root", "")) {
		ULOG_ERR("failed - mount -o move /mnt /tmp/root %m\n");
		return -1;
	}

	ret = fopivot("/overlay", "/rom");

	/*
	 * Besides copying overlay data from "tmpfs" to "jffs2" we should also
	 * move mount points that user could create during JFFS2 formatting.
	 * This has to happen after fopivot call because:
	 * 1) It's trivial to find mount points to move then (/tmp/root/...).
	 * 2) We can't do that earlier using /rom/overlay/upper/ as overlay(fs)
	 *    doesn't support mounts. Mounting to upper dir don't make overlay
	 *    /propagate/ files to the target dir.
	 */
	foreach_mount(ovl_move_mount);

	return ret;
}

int
handle_whiteout(const char *dir)
{
	struct stat s;
	char link[256];
	ssize_t sz;
	struct dirent **namelist;
	int n;

	n = scandir(dir, &namelist, NULL, NULL);

	if (n < 1)
		return -1;

	while (n--) {
		char file[256];

		snprintf(file, sizeof(file), "%s%s", dir, namelist[n]->d_name);
		if (!lstat(file, &s) && S_ISLNK(s.st_mode)) {
			sz = readlink(file, link, sizeof(link) - 1);
			if (sz > 0) {
				char *orig;

				link[sz] = '\0';
				orig = strstr(&file[1], "/");
				if (orig && !strcmp(link, "(overlay-whiteout)"))
					unlink(orig);
			}
		}
		free(namelist[n]);
	}
	free(namelist);

	return 0;
}

static char *overlay_fs_name(int type)
{
	switch (type) {
		case FS_EXT4:
			return "ext4";
		case FS_F2FS:
			return "f2fs";
		case FS_UBIFS:
			return "ubifs";
		case FS_JFFS2:
		default:
			return "jffs2";
	}
}

int
jffs2_switch(struct volume *v)
{
	char *mp, *fs_name;
	int type;

	if (find_overlay_mount("overlayfs:/tmp/root"))
		return -1;

	if (find_filesystem("overlay")) {
		ULOG_ERR("overlayfs not supported by kernel\n");
		return -1;
	}

	volume_init(v);
	mp = find_mount_point(v->blk, 0);
	if (mp) {
		ULOG_ERR("rootfs_data:%s is already mounted as %s\n", v->blk, mp);
		return -1;
	}

	type = volume_identify(v);
	fs_name = overlay_fs_name(type);

	switch (type) {
	case FS_NONE:
		ULOG_ERR("no jffs2 marker found\n");
		/* fall through */

	case FS_DEADCODE:
		if (switch2jffs(v))
			return -1;

		ULOG_INFO("performing overlay whiteout\n");
		umount2("/tmp/root", MNT_DETACH);
		foreachdir("/overlay/", handle_whiteout);

		/* try hard to be in sync */
		ULOG_INFO("synchronizing overlay\n");
		if (system("cp -a /tmp/root/upper/* / 2>/dev/null"))
			ULOG_ERR("failed to sync jffs2 overlay\n");
		break;

	case FS_EXT4:
	case FS_F2FS:
	case FS_UBIFS:
		if (overlay_mount(v, fs_name))
			return -1;
		if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
			ULOG_ERR("switching to %s failed\n", fs_name);
			return -1;
		}
		break;
	}

	sync();
	fs_state_set("/overlay", FS_STATE_READY);
	return 0;
}

static int overlay_mount_fs(struct volume *v, const char *overlay_mp)
{
	char *fstype = overlay_fs_name(volume_identify(v));

	if (mkdir(overlay_mp, 0755)) {
		ULOG_ERR("failed to mkdir /tmp/overlay: %m\n");
		return -1;
	}

	if (mount(v->blk, overlay_mp, fstype,
#ifdef OVL_MOUNT_FULL_ACCESS_TIME
		MS_RELATIME,
#else
		MS_NOATIME,
#endif
#ifdef OVL_MOUNT_COMPRESS_ZLIB
		"compr=zlib"
#else
		NULL
#endif
		)) {
		ULOG_ERR("failed to mount -t %s %s /tmp/overlay: %m\n",
		         fstype, v->blk);
		return -1;
	}

	return 0;
}

enum fs_state fs_state_get(const char *dir)
{
	char *path;
	char valstr[16];
	uint32_t val;
	ssize_t len;

	path = alloca(strlen(dir) + 1 + sizeof("/.fs_state"));
	sprintf(path, "%s/.fs_state", dir);
	len = readlink(path, valstr, sizeof(valstr) - 1);
	if (len < 0)
		return FS_STATE_UNKNOWN;

	valstr[len] = 0;
	val = atoi(valstr);

	if (val > __FS_STATE_LAST)
		return FS_STATE_UNKNOWN;

	return val;
}


int fs_state_set(const char *dir, enum fs_state state)
{
	char valstr[16];
	char *path;

	if (fs_state_get(dir) == state)
		return 0;

	path = alloca(strlen(dir) + 1 + sizeof("/.fs_state"));
	sprintf(path, "%s/.fs_state", dir);
	unlink(path);
	snprintf(valstr, sizeof(valstr), "%d", state);

	return symlink(valstr, path);
}


int mount_overlay(struct volume *v)
{
	const char *overlay_mp = "/tmp/overlay";
	char *mp, *fs_name;
	int err;

	if (!v)
		return -1;

	mp = find_mount_point(v->blk, 0);
	if (mp) {
		ULOG_ERR("rootfs_data:%s is already mounted as %s\n", v->blk, mp);
		return -1;
	}

	err = overlay_mount_fs(v, overlay_mp);
	if (err)
		return err;

	/*
	 * Check for extroot config in overlay (rootfs_data) and if present then
	 * prefer it over rootfs_data.
	 */
	if (!mount_extroot(overlay_mp)) {
		ULOG_INFO("switched to extroot\n");
		return 0;
	}

	switch (fs_state_get(overlay_mp)) {
	case FS_STATE_UNKNOWN:
		fs_state_set(overlay_mp, FS_STATE_PENDING);
		if (fs_state_get(overlay_mp) != FS_STATE_PENDING) {
			ULOG_ERR("unable to set filesystem state\n");
			break;
		}
	case FS_STATE_PENDING:
		ULOG_INFO("overlay filesystem has not been fully initialized yet\n");
		overlay_delete(overlay_mp, true);
		break;
	case FS_STATE_READY:
		break;
	}

	fs_name = overlay_fs_name(volume_identify(v));
	ULOG_INFO("switching to %s overlay\n", fs_name);
	if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
		ULOG_ERR("switching to %s failed - fallback to ramoverlay\n", fs_name);
		return ramoverlay();
	}

	return -1;
}
