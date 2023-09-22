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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "libfstools.h"

/* this is a raw syscall - man 2 pivot_root */
extern int pivot_root(const char *new_root, const char *put_old);

/**
 * mount_move - move mounted point to the new location
 *
 * @oldroot: directory that is current location of mount point
 * @newroot: new directory for the mount point
 */
int
mount_move(const char *oldroot, const char *newroot, const char *dir)
{
#ifndef MS_MOVE
#define MS_MOVE	(1 << 13)
#endif
	struct stat s;
	char olddir[64];
	char newdir[64];
	int ret;

	snprintf(olddir, sizeof(olddir), "%s%s", oldroot, dir);
	snprintf(newdir, sizeof(newdir), "%s%s", newroot, dir);

	if (stat(olddir, &s) || !S_ISDIR(s.st_mode))
		return -1;

	if (stat(newdir, &s) || !S_ISDIR(s.st_mode))
		return -1;

	ret = mount(olddir, newdir, NULL, MS_NOATIME | MS_MOVE, NULL);

/*	if (ret)
		ULOG_ERR("failed %s %s: %m\n", olddir, newdir);*/

	return ret;
}

int
pivot(char *new, char *old)
{
	char pivotdir[64];
	int ret;

	if (mount_move("", new, "/proc"))
		return -1;

	snprintf(pivotdir, sizeof(pivotdir), "%s%s", new, old);

	ret = pivot_root(new, pivotdir);

	if (ret < 0) {
		ULOG_ERR("pivot_root failed %s %s: %m\n", new, pivotdir);
		return -1;
	}

	mount_move(old, "", "/dev");
	mount_move(old, "", "/tmp");
	mount_move(old, "", "/sys");
	mount_move(old, "", "/overlay");

	return 0;
}

void
selinux_restorecon(char *overlaydir)
{
	struct stat s;
	pid_t restorecon_pid;
	int status;

	/* on non-SELinux system we don't have /sbin/restorecon, return */
	if (stat("/sbin/restorecon", &s))
		return;

	restorecon_pid = fork();
	if (!restorecon_pid)
		exit(execl("/sbin/restorecon", "restorecon", overlaydir, (char *) NULL));
	else if (restorecon_pid > 0)
		waitpid(restorecon_pid, &status, 0);
}

/**
 * fopivot - switch to overlay using passed dir as upper one
 *
 * @rw_root: writable directory that will be used as upper dir
 * @ro_root: directory where old root will be put
 */
int
fopivot(char *rw_root, char *ro_root)
{
	char overlay[64], mount_options[64], upperdir[64], workdir[64], upgrade[64], upgrade_dest[64];
	struct stat st;

	if (find_filesystem("overlay")) {
		ULOG_ERR("BUG: no suitable fs found\n");
		return -1;
	}

	snprintf(overlay, sizeof(overlay), "overlayfs:%s", rw_root);
	snprintf(upperdir, sizeof(upperdir), "%s/upper", rw_root);
	snprintf(workdir, sizeof(workdir), "%s/work", rw_root);
	snprintf(upgrade, sizeof(upgrade), "%s/sysupgrade.tgz", rw_root);
	snprintf(upgrade_dest, sizeof(upgrade_dest), "%s/sysupgrade.tgz", upperdir);
	snprintf(mount_options, sizeof(mount_options), "lowerdir=/,upperdir=%s,workdir=%s",
		 upperdir, workdir);

	/*
	 * Initialize SELinux security label on newly created overlay
	 * filesystem where /upper doesn't yet exist
	 */
	if (stat(upperdir, &st))
		selinux_restorecon(rw_root);

	/*
	 * Overlay FS v23 and later requires both a upper and
	 * a work directory, both on the same filesystem, but
	 * not part of the same subtree.
	 * We can't really deal with these constraints without
	 * creating two new subdirectories in /overlay.
	 */
	if (mkdir(upperdir, 0755) == -1 && errno != EEXIST)
		return -1;

	if (mkdir(workdir, 0755) == -1 && errno != EEXIST)
		return -1;

	if (stat(upgrade, &st) == 0)
		rename(upgrade, upgrade_dest);

	if (mount(overlay, "/mnt", "overlay", MS_NOATIME, mount_options)) {
		ULOG_ERR("mount failed: %m, options %s\n", mount_options);
		return -1;
	}

	return pivot("/mnt", ro_root);
}

/**
 * ramoverlay - use RAM to store filesystem changes on top of RO root
 */
int
ramoverlay(void)
{
	mkdir("/tmp/root", 0755);
	mount("tmpfs", "/tmp/root", "tmpfs", MS_NOATIME, "mode=0755");

	return fopivot("/tmp/root", "/rom");
}
