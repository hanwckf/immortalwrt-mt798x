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

#ifndef _FS_STATE_H__
#define _FS_STATE_H__

#include <libubox/list.h>
#include <libubox/blob.h>
#include <libubox/ulog.h>
#include <libubox/utils.h>

struct volume;

enum {
	FS_NONE,
	FS_SNAPSHOT,
	FS_JFFS2,
	FS_DEADCODE,
	FS_UBIFS,
	FS_F2FS,
	FS_EXT4,
	FS_TARGZ,
};

enum fs_state {
	FS_STATE_UNKNOWN,
	FS_STATE_PENDING,
	FS_STATE_READY,
	__FS_STATE_LAST = FS_STATE_READY,
};

extern int mount_extroot(char const *extroot_prefix);
extern int mount_snapshot(struct volume *v);
extern int mount_overlay(struct volume *v);

extern int mount_move(const char *oldroot, const char *newroot, const char *dir);
extern int pivot(char *new, char *old);
extern int fopivot(char *rw_root, char *ro_root);
extern int ramoverlay(void);

extern int find_overlay_mount(char *overlay);
extern char* find_mount(char *mp);
extern char* find_mount_point(char *block, int root_only);
extern int find_filesystem(char *fs);

extern int jffs2_switch(struct volume *v);

extern int handle_whiteout(const char *dir);
extern void foreachdir(const char *dir, int (*cb)(const char*));

extern void overlay_delete(const char *dir, bool keep_sysupgrade);

enum fs_state fs_state_get(const char *dir);
int fs_state_set(const char *dir, enum fs_state state);
void selinux_restorecon(char *overlaydir);

#endif
