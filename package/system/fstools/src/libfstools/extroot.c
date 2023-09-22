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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libgen.h>

#include "libfstools.h"

/*
 * This will execute "block extroot" and make use of mounted extroot or return
 * an error.
 */
int mount_extroot(char const *extroot_prefix)
{
	char ldlib_path[32];
	char block_path[32];
	char kmod_loader[64];
	struct stat s;
	pid_t pid;

	/* try finding the library directory */
	snprintf(ldlib_path, sizeof(ldlib_path), "%s/upper/lib", extroot_prefix);

	if (stat(ldlib_path, &s) || !S_ISDIR(s.st_mode))
		snprintf(ldlib_path, sizeof(ldlib_path), "%s/lib", extroot_prefix);

	/* try finding the block executable */
	snprintf(block_path, sizeof(block_path), "%s/upper/sbin/block", extroot_prefix);

	if (stat(block_path, &s) || !S_ISREG(s.st_mode))
		snprintf(block_path, sizeof(block_path), "%s/sbin/block", extroot_prefix);

	if (stat(block_path, &s) || !S_ISREG(s.st_mode))
		snprintf(block_path, sizeof(block_path), "/sbin/block");

	if (stat(block_path, &s) || !S_ISREG(s.st_mode))
		return -1;

	/* set LD_LIBRARY_PATH env var and load kmods from overlay if we found a lib directory there */
	if (!stat(ldlib_path, &s) && S_ISDIR(s.st_mode)) {
		ULOG_INFO("loading kmods from internal overlay\n");
		setenv("LD_LIBRARY_PATH", ldlib_path, 1);
		snprintf(kmod_loader, sizeof(kmod_loader),
		         "/sbin/kmodloader %s/etc/modules-boot.d/", dirname(ldlib_path));
		if (system(kmod_loader))
			ULOG_ERR("failed to launch kmodloader from internal overlay\n");
	}

	pid = fork();
	if (!pid) {
		mkdir("/tmp/extroot", 0755);
		execl(block_path, block_path, "extroot", NULL);
		exit(-1);
	} else if (pid > 0) {
		int status;

		waitpid(pid, &status, 0);
		if (!WEXITSTATUS(status)) {
			if (find_mount("/tmp/extroot/mnt")) {
				mount("/dev/root", "/", NULL, MS_NOATIME | MS_REMOUNT | MS_RDONLY, 0);

				mkdir("/tmp/extroot/mnt/proc", 0755);
				mkdir("/tmp/extroot/mnt/dev", 0755);
				mkdir("/tmp/extroot/mnt/sys", 0755);
				mkdir("/tmp/extroot/mnt/tmp", 0755);
				mkdir("/tmp/extroot/mnt/rom", 0755);

				if (mount_move("/tmp/extroot", "", "/mnt")) {
					ULOG_ERR("moving pivotroot failed - continue normal boot\n");
					umount("/tmp/extroot/mnt");
				} else if (pivot("/mnt", "/rom")) {
					ULOG_ERR("switching to pivotroot failed - continue normal boot\n");
					umount("/mnt");
				} else {
					umount("/tmp/overlay");
					rmdir("/tmp/overlay");
					rmdir("/tmp/extroot/mnt");
					rmdir("/tmp/extroot");
					return 0;
				}
			} else if (find_mount("/tmp/extroot/overlay")) {
				if (mount_move("/tmp/extroot", "", "/overlay")) {
					ULOG_ERR("moving extroot failed - continue normal boot\n");
					umount("/tmp/extroot/overlay");
				} else if (fopivot("/overlay", "/rom")) {
					ULOG_ERR("switching to extroot failed - continue normal boot\n");
					umount("/overlay");
				} else {
					umount("/tmp/overlay");
					rmdir("/tmp/overlay");
					rmdir("/tmp/extroot/overlay");
					rmdir("/tmp/extroot");
					return 0;
				}
			}
		}
	}
	return -1;
}
