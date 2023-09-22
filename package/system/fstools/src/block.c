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

#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <libgen.h>
#include <glob.h>
#include <dirent.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/swap.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>

#include <uci.h>
#include <uci_blob.h>

#include <libubox/avl-cmp.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>
#include <libubox/ulog.h>
#include <libubox/utils.h>
#include <libubox/vlist.h>
#include <libubus.h>

#include "probe.h"

#define AUTOFS_MOUNT_PATH       "/tmp/run/blockd/"

#ifdef UBIFS_EXTROOT
#include "libubi/libubi.h"
#endif

enum {
	TYPE_MOUNT,
	TYPE_SWAP,
};

enum {
	TYPE_DEV,
	TYPE_HOTPLUG,
	TYPE_AUTOFS,
};

struct mount {
	struct vlist_node node;
	int type;

	char *target;
	char *path;
	char *options;
	uint32_t flags;
	char *uuid;
	char *label;
	char *device;
	int extroot;
	int autofs;
	int overlay;
	int disabled_fsck;
	unsigned int prio;
};

static struct vlist_tree mounts;
static struct blob_buf b;
static LIST_HEAD(devices);
static int anon_mount, anon_swap, auto_mount, auto_swap, check_fs;
static unsigned int delay_root;

enum {
	CFG_ANON_MOUNT,
	CFG_ANON_SWAP,
	CFG_AUTO_MOUNT,
	CFG_AUTO_SWAP,
	CFG_DELAY_ROOT,
	CFG_CHECK_FS,
	__CFG_MAX
};

static const struct blobmsg_policy config_policy[__CFG_MAX] = {
	[CFG_ANON_SWAP] = { .name = "anon_swap", .type = BLOBMSG_TYPE_INT32 },
	[CFG_ANON_MOUNT] = { .name = "anon_mount", .type = BLOBMSG_TYPE_INT32 },
	[CFG_AUTO_SWAP] = { .name = "auto_swap", .type = BLOBMSG_TYPE_INT32 },
	[CFG_AUTO_MOUNT] = { .name = "auto_mount", .type = BLOBMSG_TYPE_INT32 },
	[CFG_DELAY_ROOT] = { .name = "delay_root", .type = BLOBMSG_TYPE_INT32 },
	[CFG_CHECK_FS] = { .name = "check_fs", .type = BLOBMSG_TYPE_INT32 },
};

enum {
	MOUNT_UUID,
	MOUNT_LABEL,
	MOUNT_ENABLE,
	MOUNT_TARGET,
	MOUNT_DEVICE,
	MOUNT_OPTIONS,
	MOUNT_AUTOFS,
	__MOUNT_MAX
};

static const struct uci_blob_param_list config_attr_list = {
	.n_params = __CFG_MAX,
	.params = config_policy,
};

static const struct blobmsg_policy mount_policy[__MOUNT_MAX] = {
	[MOUNT_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_LABEL] = { .name = "label", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_TARGET] = { .name = "target", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_OPTIONS] = { .name = "options", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_ENABLE] = { .name = "enabled", .type = BLOBMSG_TYPE_INT32 },
	[MOUNT_AUTOFS] = { .name = "autofs", .type = BLOBMSG_TYPE_INT32 },
};

static const struct uci_blob_param_list mount_attr_list = {
	.n_params = __MOUNT_MAX,
	.params = mount_policy,
};

enum {
	SWAP_ENABLE,
	SWAP_UUID,
	SWAP_LABEL,
	SWAP_DEVICE,
	SWAP_PRIO,
	__SWAP_MAX
};

static const struct blobmsg_policy swap_policy[__SWAP_MAX] = {
	[SWAP_ENABLE] = { .name = "enabled", .type = BLOBMSG_TYPE_INT32 },
	[SWAP_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_STRING },
	[SWAP_LABEL] = { .name = "label", .type = BLOBMSG_TYPE_STRING },
	[SWAP_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
	[SWAP_PRIO] = { .name = "priority", .type = BLOBMSG_TYPE_INT32 },
};

static const struct uci_blob_param_list swap_attr_list = {
	.n_params = __SWAP_MAX,
	.params = swap_policy,
};

struct mount_flag {
	const char *name;
	int32_t flag;
};

static const struct mount_flag mount_flags[] = {
	{ "sync",		MS_SYNCHRONOUS	},
	{ "async",		~MS_SYNCHRONOUS	},
	{ "dirsync",		MS_DIRSYNC	},
	{ "mand",		MS_MANDLOCK	},
	{ "nomand",		~MS_MANDLOCK	},
	{ "atime",		~MS_NOATIME	},
	{ "noatime",		MS_NOATIME	},
	{ "dev",		~MS_NODEV	},
	{ "nodev",		MS_NODEV	},
	{ "diratime",		~MS_NODIRATIME	},
	{ "nodiratime",		MS_NODIRATIME	},
	{ "exec",		~MS_NOEXEC	},
	{ "noexec",		MS_NOEXEC	},
	{ "suid",		~MS_NOSUID	},
	{ "nosuid",		MS_NOSUID	},
	{ "rw",			~MS_RDONLY	},
	{ "ro",			MS_RDONLY	},
	{ "relatime",		MS_RELATIME	},
	{ "norelatime",		~MS_RELATIME	},
	{ "strictatime",	MS_STRICTATIME	},
	{ "acl",		MS_POSIXACL	},
	{ "noacl",		~MS_POSIXACL	},
	{ "nouser_xattr",	MS_NOUSER	},
	{ "user_xattr",		~MS_NOUSER	},
};

static char *blobmsg_get_strdup(struct blob_attr *attr)
{
	if (!attr)
		return NULL;

	return strdup(blobmsg_get_string(attr));
}

static char *blobmsg_get_basename(struct blob_attr *attr)
{
	if (!attr)
		return NULL;

	return strdup(basename(blobmsg_get_string(attr)));
}

static void parse_mount_options(struct mount *m, char *optstr)
{
	int i;
	bool is_flag;
	char *p, *opts, *last;

	m->flags = 0;
	m->options = NULL;

	if (!optstr || !*optstr)
		return;

	m->options = opts = calloc(1, strlen(optstr) + 1);

	if (!m->options)
		return;

	p = last = optstr;

	do {
		p = strchr(p, ',');

		if (p)
			*p++ = 0;

		for (i = 0, is_flag = false; i < ARRAY_SIZE(mount_flags); i++) {
			if (!strcmp(last, mount_flags[i].name)) {
				if (mount_flags[i].flag < 0)
					m->flags &= (uint32_t)mount_flags[i].flag;
				else
					m->flags |= (uint32_t)mount_flags[i].flag;
				is_flag = true;
				break;
			}
		}

		if (!is_flag)
			opts += sprintf(opts, "%s%s", (opts > m->options) ? "," : "", last);

		last = p;

	} while (p);

	free(optstr);
}

static int mount_add(struct uci_section *s)
{
	struct blob_attr *tb[__MOUNT_MAX] = { 0 };
	struct mount *m;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &mount_attr_list);
	blobmsg_parse(mount_policy, __MOUNT_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (!tb[MOUNT_LABEL] && !tb[MOUNT_UUID] && !tb[MOUNT_DEVICE])
		return -1;

	if (tb[MOUNT_ENABLE] && !blobmsg_get_u32(tb[MOUNT_ENABLE]))
		return -1;

	m = malloc(sizeof(struct mount));
	m->type = TYPE_MOUNT;
	m->uuid = blobmsg_get_strdup(tb[MOUNT_UUID]);
	m->label = blobmsg_get_strdup(tb[MOUNT_LABEL]);
	m->target = blobmsg_get_strdup(tb[MOUNT_TARGET]);
	m->device = blobmsg_get_basename(tb[MOUNT_DEVICE]);
	if (tb[MOUNT_AUTOFS])
		m->autofs = blobmsg_get_u32(tb[MOUNT_AUTOFS]);
	else
		m->autofs = 0;
	parse_mount_options(m, blobmsg_get_strdup(tb[MOUNT_OPTIONS]));

	m->overlay = m->extroot = 0;
	if (m->target && !strcmp(m->target, "/"))
		m->extroot = 1;
	if (m->target && !strcmp(m->target, "/overlay"))
		m->extroot = m->overlay = 1;

	if (m->target && *m->target != '/') {
		ULOG_WARN("ignoring mount section %s due to invalid target '%s'\n",
		          s->e.name, m->target);
		free(m);
		return -1;
	}

	if (m->uuid)
		vlist_add(&mounts, &m->node, m->uuid);
	else if (m->label)
		vlist_add(&mounts, &m->node, m->label);
	else if (m->device)
		vlist_add(&mounts, &m->node, m->device);

	return 0;
}

static int swap_add(struct uci_section *s)
{
	struct blob_attr *tb[__SWAP_MAX] = { 0 };
	struct mount *m;

        blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &swap_attr_list);
	blobmsg_parse(swap_policy, __SWAP_MAX, tb, blob_data(b.head), blob_len(b.head));

	if (!tb[SWAP_UUID] && !tb[SWAP_LABEL] && !tb[SWAP_DEVICE])
		return -1;

	m = malloc(sizeof(struct mount));
	memset(m, 0, sizeof(struct mount));
	m->type = TYPE_SWAP;
	m->uuid = blobmsg_get_strdup(tb[SWAP_UUID]);
	m->label = blobmsg_get_strdup(tb[SWAP_LABEL]);
	m->device = blobmsg_get_basename(tb[SWAP_DEVICE]);
	if (tb[SWAP_PRIO])
		m->prio = blobmsg_get_u32(tb[SWAP_PRIO]);
	if (m->prio)
		m->prio = ((m->prio << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK) | SWAP_FLAG_PREFER;

	if ((!tb[SWAP_ENABLE]) || blobmsg_get_u32(tb[SWAP_ENABLE])) {
		/* store complete swap path */
		if (tb[SWAP_DEVICE])
			m->target = blobmsg_get_strdup(tb[SWAP_DEVICE]);

		if (m->uuid)
			vlist_add(&mounts, &m->node, m->uuid);
		else if (m->label)
			vlist_add(&mounts, &m->node, m->label);
		else if (m->device)
			vlist_add(&mounts, &m->node, m->device);
	}

	return 0;
}

static int global_add(struct uci_section *s)
{
	struct blob_attr *tb[__CFG_MAX] = { 0 };

        blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &config_attr_list);
	blobmsg_parse(config_policy, __CFG_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((tb[CFG_ANON_MOUNT]) && blobmsg_get_u32(tb[CFG_ANON_MOUNT]))
		anon_mount = 1;
	if ((tb[CFG_ANON_SWAP]) && blobmsg_get_u32(tb[CFG_ANON_SWAP]))
		anon_swap = 1;

	if ((tb[CFG_AUTO_MOUNT]) && blobmsg_get_u32(tb[CFG_AUTO_MOUNT]))
		auto_mount = 1;
	if ((tb[CFG_AUTO_SWAP]) && blobmsg_get_u32(tb[CFG_AUTO_SWAP]))
		auto_swap = 1;

	if (tb[CFG_DELAY_ROOT])
		delay_root = blobmsg_get_u32(tb[CFG_DELAY_ROOT]);

	if ((tb[CFG_CHECK_FS]) && blobmsg_get_u32(tb[CFG_CHECK_FS]))
		check_fs = 1;

	return 0;
}

static struct mount* find_swap(const char *uuid, const char *label, const char *device)
{
	struct mount *m;

	vlist_for_each_element(&mounts, m, node) {
		if (m->type != TYPE_SWAP)
			continue;
		if (uuid && m->uuid && !strcasecmp(m->uuid, uuid))
			return m;
		if (label && m->label && !strcmp(m->label, label))
			return m;
		if (device && m->device && !strcmp(m->device, device))
			return m;
	}

	return NULL;
}

static struct mount* find_block(const char *uuid, const char *label, const char *device,
				const char *target)
{
	struct mount *m;

	vlist_for_each_element(&mounts, m, node) {
		if (m->type != TYPE_MOUNT)
			continue;
		if (m->uuid && uuid && !strcasecmp(m->uuid, uuid))
			return m;
		if (m->label && label && !strcmp(m->label, label))
			return m;
		if (m->target && target && !strcmp(m->target, target))
			return m;
		if (m->device && device && !strcmp(m->device, device))
			return m;
	}

	return NULL;
}

static void mounts_update(struct vlist_tree *tree, struct vlist_node *node_new,
			  struct vlist_node *node_old)
{
}

static struct uci_package * config_try_load(struct uci_context *ctx, char *path)
{
	char *file = basename(path);
	char *dir = dirname(path);
	char *err;
	struct uci_package *pkg;

	uci_set_confdir(ctx, dir);
	ULOG_INFO("attempting to load %s/%s\n", dir, file);

	if (uci_load(ctx, file, &pkg)) {
		uci_get_errorstr(ctx, &err, file);
		ULOG_ERR("unable to load configuration (%s)\n", err);

		free(err);
		return NULL;
	}

	return pkg;
}

static int config_load(char *cfg)
{
	struct uci_context *ctx = uci_alloc_context();
	struct uci_package *pkg = NULL;
	struct uci_element *e;
	char path[64];

	vlist_init(&mounts, avl_strcmp, mounts_update);

	if (cfg) {
		snprintf(path, sizeof(path), "%s/upper/etc/config/fstab", cfg);
		pkg = config_try_load(ctx, path);

		if (!pkg) {
			snprintf(path, sizeof(path), "%s/etc/config/fstab", cfg);
			pkg = config_try_load(ctx, path);
		}
	}

	if (!pkg) {
		snprintf(path, sizeof(path), "/etc/config/fstab");
		pkg = config_try_load(ctx, path);
	}

	if (!pkg) {
		ULOG_ERR("no usable configuration\n");
		return -1;
	}

	vlist_update(&mounts);
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "mount"))
			mount_add(s);
		if (!strcmp(s->type, "swap"))
			swap_add(s);
		if (!strcmp(s->type, "global"))
			global_add(s);
	}
	vlist_flush(&mounts);

	return 0;
}

static bool mtdblock_is_nand(char *mtdnum)
{
	char tmppath[64];
	char buf[16];
	FILE *fp;

	snprintf(tmppath, sizeof(tmppath) - 1, "/sys/class/mtd/mtd%s/type", mtdnum);
	fp = fopen(tmppath, "r");
	if (!fp)
		return false;

	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return false;
	}
	fclose(fp);
	buf[sizeof(buf) - 1] = '\0'; /* make sure buf is 0-terminated */
	buf[strlen(buf) - 1] = '\0'; /* strip final char (newline) */

	if (strcmp(buf, "nand"))
		return false;

	/*
	 * --- CUT HERE ---
	 * Keep probing rootfs and rootfs_data in the meantime to not break
	 * devices using JFFS2 on NAND but only trigger the kernel warnings.
	 * Remove this once all devices using JFFS2 and squashfs directly on
	 * NAND have been converted to UBI.
	 */
	snprintf(tmppath, sizeof(tmppath) - 1, "/sys/class/mtd/mtd%s/name", mtdnum);
	fp = fopen(tmppath, "r");
	if (!fp)
		return false;

	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return false;
	}
	fclose(fp);
	buf[sizeof(buf) - 1] = '\0'; /* make sure buf is 0-terminated */
	buf[strlen(buf) - 1] = '\0'; /* strip final char (newline) */

	/* only return true if name differs from 'rootfs' and 'rootfs_data' */
	if (strcmp(buf, "rootfs") && strcmp(buf, "rootfs_data"))
		return true;

	/* --- CUT HERE --- */
	return false;
}

static struct probe_info* _probe_path(char *path)
{
	struct probe_info *pr, *epr;
	char tmppath[64];

	if (!strncmp(path, "/dev/mtdblock", 13) && mtdblock_is_nand(path + 13))
		return NULL;

	pr = probe_path(path);
	if (!pr)
		return NULL;

	if (path[5] == 'u' && path[6] == 'b' && path[7] == 'i' &&
	    path[8] >= '0' && path[8] <= '9' ) {
		/* skip ubi device if not UBIFS (as it requires ubiblock) */
		if (strcmp("ubifs", pr->type))
			return NULL;

		/* skip ubi device if ubiblock device is present */
		snprintf(tmppath, sizeof(tmppath), "/dev/ubiblock%s", path + 8);
		list_for_each_entry(epr, &devices, list)
			if (!strcmp(epr->dev, tmppath))
				return NULL;
	}

	return pr;
}

static int _cache_load(const char *path)
{
	int gl_flags = GLOB_NOESCAPE | GLOB_MARK;
	int j;
	glob_t gl;

	if (glob(path, gl_flags, NULL, &gl) < 0)
		return -1;

	for (j = 0; j < gl.gl_pathc; j++) {
		struct probe_info *pr = _probe_path(gl.gl_pathv[j]);
		if (pr)
			list_add_tail(&pr->list, &devices);
	}

	globfree(&gl);

	return 0;
}

static void cache_load(int mtd)
{
	if (mtd) {
		_cache_load("/dev/mtdblock*");
		_cache_load("/dev/ubiblock*");
		_cache_load("/dev/ubi[0-9]*");
	}
	_cache_load("/dev/loop*");
	_cache_load("/dev/mmcblk*");
	_cache_load("/dev/sd*");
	_cache_load("/dev/hd*");
	_cache_load("/dev/md*");
	_cache_load("/dev/nvme*");
	_cache_load("/dev/vd*");
	_cache_load("/dev/xvd*");
	_cache_load("/dev/dm-*");
}


static struct probe_info* find_block_info(char *uuid, char *label, char *path)
{
	struct probe_info *pr = NULL;

	if (uuid)
		list_for_each_entry(pr, &devices, list)
			if (pr->uuid && !strcasecmp(pr->uuid, uuid))
				return pr;

	if (label)
		list_for_each_entry(pr, &devices, list)
			if (pr->label && !strcmp(pr->label, label))
				return pr;

	if (path)
		list_for_each_entry(pr, &devices, list)
			if (pr->dev && !strcmp(basename(pr->dev), basename(path)))
				return pr;

	return NULL;
}

static char* find_mount_point(char *block)
{
	FILE *fp = fopen("/proc/self/mountinfo", "r");
	static char line[256];
	char *point = NULL, *pos, *tmp, *cpoint, *devname;
	struct stat s;
	int rstat;
	unsigned int minor, major;

	if (!fp)
		return NULL;

	rstat = stat(block, &s);

	while (fgets(line, sizeof(line), fp)) {
		pos = strchr(line, ' ');
		if (!pos)
			continue;

		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

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
		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;
		tmp = ++pos;

		pos = strchr(pos, ' ');
		if (!pos)
			continue;
		*pos = '\0';
		cpoint = tmp;

		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

		pos = strchr(pos + 1, ' ');
		if (!pos)
			continue;

		tmp = ++pos;
		pos = strchr(pos, ' ');
		if (!pos)
			continue;

		*pos = '\0';
		devname = tmp;
		if (!strcmp(block, devname)) {
			point = strdup(cpoint);
			break;
		}

		if (rstat)
			continue;

		if (!S_ISBLK(s.st_mode))
			continue;

		if (major == major(s.st_rdev) &&
		    minor == minor(s.st_rdev)) {
			point = strdup(cpoint);
			break;
		}
	}

	fclose(fp);

	return point;
}

static int print_block_uci(struct probe_info *pr)
{
	if (!strcmp(pr->type, "swap")) {
		printf("config 'swap'\n");
	} else {
		char *mp = find_mount_point(pr->dev);

		printf("config 'mount'\n");
		if (mp) {
			printf("\toption\ttarget\t'%s'\n", mp);
			free(mp);
		} else {
			printf("\toption\ttarget\t'/mnt/%s'\n", basename(pr->dev));
		}
	}
	if (pr->uuid)
		printf("\toption\tuuid\t'%s'\n", pr->uuid);
	else
		printf("\toption\tdevice\t'%s'\n", pr->dev);
	printf("\toption\tenabled\t'0'\n\n");

	return 0;
}

static int print_block_info(struct probe_info *pr)
{
	static char *mp;

	mp = find_mount_point(pr->dev);
	printf("%s:", pr->dev);
	if (pr->uuid)
		printf(" UUID=\"%s\"", pr->uuid);

	if (pr->label)
		printf(" LABEL=\"%s\"", pr->label);

	if (pr->version)
		printf(" VERSION=\"%s\"", pr->version);

	if (mp) {
		printf(" MOUNT=\"%s\"", mp);
		free(mp);
	}

	printf(" TYPE=\"%s\"\n", pr->type);

	return 0;
}

static void check_filesystem(struct probe_info *pr)
{
	pid_t pid;
	struct stat statbuf;
	const char *e2fsck = "/usr/sbin/e2fsck";
	const char *f2fsck = "/usr/sbin/fsck.f2fs";
	const char *fatfsck = "/usr/sbin/fsck.fat";
	const char *btrfsck = "/usr/bin/btrfsck";
	const char *ntfsck = "/usr/bin/ntfsfix";
	const char *ckfs;

	/* UBIFS does not need stuff like fsck */
	if (!strncmp(pr->type, "ubifs", 5))
		return;

	if (!strncmp(pr->type, "vfat", 4)) {
		ckfs = fatfsck;
	} else if (!strncmp(pr->type, "f2fs", 4)) {
		ckfs = f2fsck;
	} else if (!strncmp(pr->type, "ext", 3)) {
		ckfs = e2fsck;
	} else if (!strncmp(pr->type, "btrfs", 5)) {
		ckfs = btrfsck;
	} else if (!strncmp(pr->type, "ntfs", 4)) {
		ckfs = ntfsck;
	} else {
		ULOG_ERR("check_filesystem: %s is not supported\n", pr->type);
		return;
	}

	if (stat(ckfs, &statbuf) < 0) {
		ULOG_ERR("check_filesystem: %s not found\n", ckfs);
		return;
	}

	pid = fork();
	if (!pid) {
		if(!strncmp(pr->type, "f2fs", 4)) {
			execl(ckfs, ckfs, "-f", pr->dev, NULL);
			exit(EXIT_FAILURE);
		} else if(!strncmp(pr->type, "btrfs", 5)) {
			execl(ckfs, ckfs, "--repair", pr->dev, NULL);
			exit(EXIT_FAILURE);
		} else if(!strncmp(pr->type, "ntfs", 4)) {
			execl(ckfs, ckfs, "-b", pr->dev, NULL);
			exit(EXIT_FAILURE);
		} else {
			execl(ckfs, ckfs, "-p", pr->dev, NULL);
			exit(EXIT_FAILURE);
		}
	} else if (pid > 0) {
		int status;

		waitpid(pid, &status, 0);
		if (WIFEXITED(status) && WEXITSTATUS(status))
			ULOG_ERR("check_filesystem: %s returned %d\n", ckfs, WEXITSTATUS(status));
		if (WIFSIGNALED(status))
			ULOG_ERR("check_filesystem: %s terminated by %s\n", ckfs, strsignal(WTERMSIG(status)));
	}
}

static void handle_swapfiles(bool on)
{
	struct stat s;
	struct mount *m;
	struct probe_info *pr;

	vlist_for_each_element(&mounts, m, node)
	{
		if (m->type != TYPE_SWAP || !m->target)
			continue;

		if (stat(m->target, &s) || !S_ISREG(s.st_mode))
			continue;

		pr = _probe_path(m->target);

		if (!pr)
			continue;

		if (!strcmp(pr->type, "swap")) {
			if (on)
				swapon(pr->dev, m->prio);
			else
				swapoff(pr->dev);
		}

		free(pr);
	}
}

static void to_devnull(int fd)
{
	int devnull = open("/dev/null", fd ? O_WRONLY : O_RDONLY);

	if (devnull >= 0)
		dup2(devnull, fd);

	if (devnull > STDERR_FILENO)
		close(devnull);
}

static int exec_mount(const char *source, const char *target,
                      const char *fstype, const char *options)
{
	pid_t pid;
	struct stat s;
	FILE *mount_fd;
	int err, status, pfds[2];
	char errmsg[128], cmd[sizeof("/sbin/mount.XXXXXXXXXXXXXXXX\0")];

	snprintf(cmd, sizeof(cmd), "/sbin/mount.%s", fstype);

	if (stat(cmd, &s) < 0 || !S_ISREG(s.st_mode) || !(s.st_mode & S_IXUSR)) {
		ULOG_ERR("No \"mount.%s\" utility available\n", fstype);
		return -1;
	}

	if (pipe(pfds) < 0)
		return -1;

	fcntl(pfds[0], F_SETFD, fcntl(pfds[0], F_GETFD) | FD_CLOEXEC);
	fcntl(pfds[1], F_SETFD, fcntl(pfds[1], F_GETFD) | FD_CLOEXEC);

	pid = vfork();

	switch (pid) {
	case -1:
		close(pfds[0]);
		close(pfds[1]);

		return -1;

	case 0:
		to_devnull(STDIN_FILENO);
		to_devnull(STDOUT_FILENO);

		dup2(pfds[1], STDERR_FILENO);
		close(pfds[0]);
		close(pfds[1]);

		if (options && *options)
			execl(cmd, cmd, "-o", options, source, target, NULL);
		else
			execl(cmd, cmd, source, target, NULL);

		return -1;

	default:
		close(pfds[1]);

		mount_fd = fdopen(pfds[0], "r");

		while (fgets(errmsg, sizeof(errmsg), mount_fd))
			ULOG_ERR("mount.%s: %s", fstype, errmsg);

		fclose(mount_fd);

		err = waitpid(pid, &status, 0);

		if (err != -1) {
			if (status != 0) {
				ULOG_ERR("mount.%s: failed with status %d\n", fstype, status);
				errno = EINVAL;
				err = -1;
			} else {
				errno = 0;
				err = 0;
			}
		}

		break;
	}

	return err;
}

static const char * const ntfs_fs[] = { "ntfs3", "ntfs-3g", "antfs", "ntfs" };

static int handle_mount(const char *source, const char *target,
                        const char *fstype, struct mount *m)
{
	size_t mount_opts_len;
	char *mount_opts = NULL, *ptr;
	const char * const *filesystems;
	int err = -EINVAL;
	size_t count;
	int i;

	if (!strcmp(fstype, "ntfs")) {
		filesystems = ntfs_fs;
		count = ARRAY_SIZE(ntfs_fs);
	} else {
		filesystems = &fstype;
		count = 1;
	}

	for (i = 0; i < count; i++) {
		const char *fs = filesystems[i];

		err = mount(source, target, fs, m ? m->flags : 0,
			    (m && m->options) ? m->options : "");
		if (!err || errno != ENODEV)
			break;
	}

	/* Requested file system type is not available in kernel,
	   attempt to call mount helper. */
	if (err == -1 && errno == ENODEV) {
		if (m) {
			/* Convert mount flags back into string representation,
			   first calculate needed length of string buffer... */
			mount_opts_len = 1 + (m->options ? strlen(m->options) : 0);

			for (i = 0; i < ARRAY_SIZE(mount_flags); i++)
				if ((mount_flags[i].flag > 0) &&
				    (mount_flags[i].flag < INT_MAX) &&
				    (m->flags & (uint32_t)mount_flags[i].flag))
					mount_opts_len += strlen(mount_flags[i].name) + 1;

			/* ... then now allocate and fill it ... */
			ptr = mount_opts = calloc(1, mount_opts_len);

			if (!ptr) {
				errno = ENOMEM;
				return -1;
			}

			if (m->options)
				ptr += sprintf(ptr, "%s,", m->options);

			for (i = 0; i < ARRAY_SIZE(mount_flags); i++)
				if ((mount_flags[i].flag > 0) &&
				    (mount_flags[i].flag < INT_MAX) &&
				    (m->flags & (uint32_t)mount_flags[i].flag))
					ptr += sprintf(ptr, "%s,", mount_flags[i].name);

			mount_opts[mount_opts_len - 1] = 0;
		}

		/* ... and now finally invoke the external mount program */
		for (i = 0; i < count; i++) {
			const char *fs = filesystems[i];

			err = exec_mount(source, target, fs, mount_opts);
			if (!err)
				break;
		}
	}

	free(mount_opts);

	return err;
}

static int blockd_notify(const char *method, char *device, struct mount *m,
			 struct probe_info *pr)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	uint32_t id;
	int err;

	if (!ctx)
		return -ENXIO;

	if (!ubus_lookup_id(ctx, "block", &id)) {
		struct blob_buf buf = { 0 };
		char *d = strrchr(device, '/');

		if (d)
			d++;
		else
			d = device;

		blob_buf_init(&buf, 0);

		if (m) {

			blobmsg_add_string(&buf, "device", d);
			if (m->uuid)
				blobmsg_add_string(&buf, "uuid", m->uuid);
			if (m->label)
				blobmsg_add_string(&buf, "label", m->label);
			if (m->target)
				blobmsg_add_string(&buf, "target", m->target);
			if (m->options)
				blobmsg_add_string(&buf, "options", m->options);
			if (m->autofs)
				blobmsg_add_u32(&buf, "autofs", m->autofs);
			if (pr->type)
				blobmsg_add_string(&buf, "type", pr->type);
			if (pr->version)
				blobmsg_add_string(&buf, "version", pr->version);
		} else if (pr) {
			blobmsg_add_string(&buf, "device", d);
			if (pr->uuid)
				blobmsg_add_string(&buf, "uuid", pr->uuid);
			if (pr->label)
				blobmsg_add_string(&buf, "label", pr->label);
			if (pr->type)
				blobmsg_add_string(&buf, "type", pr->type);
			if (pr->version)
				blobmsg_add_string(&buf, "version", pr->version);
			blobmsg_add_u32(&buf, "anon", 1);
		} else {
			blobmsg_add_string(&buf, "device", d);
			blobmsg_add_u32(&buf, "remove", 1);
		}

		err = ubus_invoke(ctx, id, method, buf.head, NULL, NULL, 3000);
	} else {
		err = -ENOENT;
	}

	ubus_free(ctx);

	return err;
}

static int mount_device(struct probe_info *pr, int type)
{
	struct mount *m;
	struct stat st;
	char *_target = NULL;
	char *target;
	char *device;
	char *mp;
	int err;

	if (!pr)
		return -1;

	device = basename(pr->dev);

	if (!strcmp(pr->type, "swap")) {
		if ((type == TYPE_HOTPLUG) && !auto_swap)
			return -1;
		m = find_swap(pr->uuid, pr->label, device);
		if (m || anon_swap)
			swapon(pr->dev, (m) ? (m->prio) : (0));

		return 0;
	}

	m = find_block(pr->uuid, pr->label, device, NULL);
	if (m && m->extroot)
		return -1;

	mp = find_mount_point(pr->dev);
	if (mp) {
		if (m && m->type == TYPE_MOUNT && m->target && strcmp(m->target, mp)) {
			ULOG_ERR("%s is already mounted on %s\n", pr->dev, mp);
			err = -1;
		} else
			err = 0;
		free(mp);
		return err;
	}

	if (type == TYPE_HOTPLUG)
		blockd_notify("hotplug", device, m, pr);

	/* Check if device should be mounted & set the target directory */
	if (m) {
		switch (type) {
		case TYPE_HOTPLUG:
			if (m->autofs)
				return 0;
			if (!auto_mount)
				return -1;
			break;
		case TYPE_AUTOFS:
			if (!m->autofs)
				return -1;
			break;
		case TYPE_DEV:
			if (m->autofs)
				return -1;
			break;
		}

		if (m->autofs) {
			if (asprintf(&_target, "/tmp/run/blockd/%s", device) == -1)
				exit(ENOMEM);

			target = _target;
		} else if (m->target) {
			target = m->target;
		} else {
			if (asprintf(&_target, "/mnt/%s", device) == -1)
				exit(ENOMEM);

			target = _target;
		}
	} else if (anon_mount) {
		if (asprintf(&_target, "/mnt/%s", device) == -1)
			exit(ENOMEM);

		target = _target;
	} else {
		/* No reason to mount this device */
		return 0;
	}

	/* Mount the device */

	if (check_fs)
		check_filesystem(pr);

	mkdir_p(target, 0755);
	if (!lstat(target, &st) && S_ISLNK(st.st_mode))
		unlink(target);

	err = handle_mount(pr->dev, target, pr->type, m);
	if (err) {
		ULOG_ERR("mounting %s (%s) as %s failed (%d) - %m\n",
				pr->dev, pr->type, target, errno);

		if (_target)
			free(_target);

		return err;
	}

	if (_target)
		free(_target);

	handle_swapfiles(true);

	if (type != TYPE_AUTOFS)
		blockd_notify("mount", device, NULL, NULL);

	return 0;
}

static int umount_device(char *path, int type, bool all)
{
	char *mp, *devpath;
	int err;

	if (strlen(path) > 5 && !strncmp("/dev/", path, 5)) {
		mp = find_mount_point(path);
	} else {
		devpath = malloc(strlen(path) + 6);
		strcpy(devpath, "/dev/");
		strcat(devpath, path);
		mp = find_mount_point(devpath);
		free(devpath);
	}

	if (!mp)
		return -1;
	if (!strcmp(mp, "/") && !all) {
		free(mp);
		return 0;
	}
	if (type != TYPE_AUTOFS)
		blockd_notify("umount", basename(path), NULL, NULL);

	err = umount2(mp, MNT_DETACH);
	if (err) {
		ULOG_ERR("unmounting %s (%s) failed (%d) - %m\n", path, mp,
			 errno);
	} else {
		ULOG_INFO("unmounted %s (%s)\n", path, mp);
		rmdir(mp);
	}

	free(mp);
	return err;
}

static int mount_action(char *action, char *device, int type)
{
	char *path = NULL;
	struct probe_info *pr;

	if (!action || !device)
		return -1;

	if (!strcmp(action, "remove")) {
		if (type == TYPE_HOTPLUG)
			blockd_notify("hotplug", device, NULL, NULL);

		umount_device(device, type, true);

		return 0;
	} else if (strcmp(action, "add")) {
		ULOG_ERR("Unkown action %s\n", action);

		return -1;
	}

	if (config_load(NULL))
		return -1;

	cache_load(1);

	list_for_each_entry(pr, &devices, list)
		if (!strcmp(basename(pr->dev), device))
			path = pr->dev;

	if (!path)
		return -1;

	return mount_device(find_block_info(NULL, NULL, path), type);
}

static int main_hotplug(int argc, char **argv)
{
	return mount_action(getenv("ACTION"), getenv("DEVNAME"), TYPE_HOTPLUG);
}

static int main_autofs(int argc, char **argv)
{
	int err = 0;

	if (argc < 3)
		return -1;

	if (!strcmp(argv[2], "start")) {
		struct probe_info *pr;

		if (config_load(NULL))
			return -1;

		cache_load(1);
		list_for_each_entry(pr, &devices, list) {
			struct mount *m;
			char *mp;

			if (!strcmp(pr->type, "swap"))
				continue;

			m = find_block(pr->uuid, pr->label, NULL, NULL);
			if (m && m->extroot)
				continue;

			blockd_notify("hotplug", pr->dev, m, pr);
			if ((!m || !m->autofs) && (mp = find_mount_point(pr->dev))) {
				blockd_notify("mount", pr->dev, NULL, NULL);
				free(mp);
			}
		}
	} else {
		if (argc < 4)
			return -EINVAL;

		err = mount_action(argv[2], argv[3], TYPE_AUTOFS);
	}

	if (err) {
		ULOG_ERR("autofs: \"%s\" action has failed: %d\n", argv[2], err);
	}

	return err;
}

static int find_block_mtd(char *name, char *part, int plen)
{
	FILE *fp = fopen("/proc/mtd", "r");
	static char line[256];
	char *index = NULL;

	if(!fp)
		return -1;

	while (!index && fgets(line, sizeof(line), fp)) {
		if (strstr(line, name)) {
			char *eol = strstr(line, ":");

			if (!eol)
				continue;

			*eol = '\0';
			index = &line[3];
		}
	}

	fclose(fp);

	if (!index)
		return -1;

	snprintf(part, plen, "/dev/mtdblock%s", index);

	return 0;
}

#ifdef UBIFS_EXTROOT
static int find_ubi_vol(libubi_t libubi, char *name, int *dev_num, int *vol_id)
{
	int dev = 0;

	while (ubi_dev_present(libubi, dev))
	{
		struct ubi_dev_info dev_info;
		struct ubi_vol_info vol_info;

		if (ubi_get_dev_info1(libubi, dev++, &dev_info))
			continue;
		if (ubi_get_vol_info1_nm(libubi, dev_info.dev_num, name, &vol_info))
			continue;

		*dev_num = dev_info.dev_num;
		*vol_id = vol_info.vol_id;

		return 0;
	}

	return -1;
}

static int find_block_ubi(libubi_t libubi, char *name, char *part, int plen)
{
	int dev_num;
	int vol_id;
	int err = -1;

	err = find_ubi_vol(libubi, name, &dev_num, &vol_id);
	if (!err)
		snprintf(part, plen, "/dev/ubi%d_%d", dev_num, vol_id);

	return err;
}

static int find_block_ubi_RO(libubi_t libubi, char *name, char *part, int plen)
{
	int dev_num;
	int vol_id;
	int err = -1;

	err = find_ubi_vol(libubi, name, &dev_num, &vol_id);
	if (!err)
		snprintf(part, plen, "/dev/ubiblock%d_%d", dev_num, vol_id);

	return err;
}
#endif

static int find_dev(const char *path, char *buf, int len)
{
	DIR *d;
	dev_t root;
	struct stat s;
	struct dirent *e;

	if (stat(path, &s))
		return -1;

	if (!(d = opendir("/dev")))
		return -1;

	root = s.st_dev;

	while ((e = readdir(d)) != NULL) {
		snprintf(buf, len, "/dev/%s", e->d_name);

		if (stat(buf, &s) || s.st_rdev != root)
			continue;

		closedir(d);
		return 0;
	}

	closedir(d);
	return -1;
}

static int find_root_dev(char *buf, int len)
{
	int err = find_dev("/", buf, len);
	if (err)
	    err = find_dev("/rom", buf, len);

	return err;
}

static int test_fs_support(const char *name)
{
	char line[128], *p;
	int rv = -1;
	FILE *f;

	if ((f = fopen("/proc/filesystems", "r")) != NULL) {
		while (fgets(line, sizeof(line), f)) {
			p = strtok(line, "\t\n");

			if (p && !strcmp(p, "nodev"))
				p = strtok(NULL, "\t\n");

			if (p && !strcmp(p, name)) {
				rv = 0;
				break;
			}
		}
		fclose(f);
	}

	return rv;
}

/**
 * Check if mounted partition is a valid extroot
 *
 * @path target mount point
 *
 * Valid extroot partition has to contain /etc/.extroot-uuid with UUID of root
 * device. This function reads UUID and verifies it OR writes UUID to
 * .extroot-uuid if it doesn't exist yet (first extroot usage).
 */
static int check_extroot(char *path)
{
	struct probe_info *pr = NULL;
	struct probe_info *tmp;
	struct stat s;
	char uuid[64] = { 0 };
	char devpath[32];
	char tag[64];
	FILE *fp;
	int err;

	snprintf(tag, sizeof(tag), "%s/etc/.extroot-default", path);
	if (stat(tag, &s))
		return 0;

	err = find_root_dev(devpath, sizeof(devpath));
	if (err)
		err = find_block_mtd("\"rootfs\"", devpath, sizeof(devpath));
#ifdef UBIFS_EXTROOT
	if (err) {
		libubi_t libubi;

		libubi = libubi_open();
		err = find_block_ubi_RO(libubi, "rootfs", devpath, sizeof(devpath));
		libubi_close(libubi);
	}
#endif
	if (err) {
		ULOG_ERR("extroot: unable to determine root device\n");
		return -1;
	}

	/* Find root device probe_info so we know its UUID */
	list_for_each_entry(tmp, &devices, list) {
		if (!strcmp(tmp->dev, devpath)) {
			pr = tmp;
			break;
		}
	}
	if (!pr) {
		ULOG_ERR("extroot: unable to lookup root device %s\n", devpath);
		return -1;
	}

	snprintf(tag, sizeof(tag), "%s/etc", path);
	if (stat(tag, &s))
		mkdir_p(tag, 0755);

	snprintf(tag, sizeof(tag), "%s/etc/.extroot-uuid", path);
	if (stat(tag, &s)) {
		fp = fopen(tag, "w+");
		if (!fp) {
			ULOG_ERR("extroot: failed to write UUID to %s: %d (%m)\n",
				 tag, errno);
			/* return 0 to continue boot regardless of error */
			return 0;
		}
		fputs(pr->uuid, fp);
		fclose(fp);
		return 0;
	}

	fp = fopen(tag, "r");
	if (!fp) {
		ULOG_ERR("extroot: failed to read UUID from %s: %d (%m)\n", tag,
			 errno);
		return -1;
	}

	if (!fgets(uuid, sizeof(uuid), fp))
		ULOG_ERR("extroot: failed to read UUID from %s: %d (%m)\n", tag,
			 errno);
	fclose(fp);

	if (*uuid && !strcasecmp(uuid, pr->uuid))
		return 0;

	ULOG_ERR("extroot: UUID mismatch (root: %s, %s: %s)\n", pr->uuid,
		 basename(path), uuid);
	return -1;
}

/*
 * Read info about extroot from UCI (using prefix) and mount it.
 */
static int mount_extroot(char *cfg)
{
	char overlay[] = "/tmp/extroot/overlay";
	char mnt[] = "/tmp/extroot/mnt";
	char *path = mnt;
	struct probe_info *pr;
	struct mount *m;
	int err = -1;

	/* Load @cfg/etc/config/fstab */
	if (config_load(cfg))
		return -2;

	/* See if there is extroot-specific mount config */
	m = find_block(NULL, NULL, NULL, "/");
	if (!m)
		m = find_block(NULL, NULL, NULL, "/overlay");

	if (!m || !m->extroot)
	{
		ULOG_INFO("extroot: not configured\n");
		return -1;
	}

	/* Find block device pointed by the mount config */
	pr = find_block_info(m->uuid, m->label, m->device);

	if (!pr && delay_root){
		ULOG_INFO("extroot: device not present, retrying in %u seconds\n", delay_root);
		sleep(delay_root);
		make_devs();
		cache_load(1);
		pr = find_block_info(m->uuid, m->label, m->device);
	}
	if (pr) {
		if (strncmp(pr->type, "ext", 3) &&
		    strncmp(pr->type, "f2fs", 4) &&
		    strncmp(pr->type, "btrfs", 5) &&
		    strncmp(pr->type, "ntfs", 4) &&
		    strncmp(pr->type, "ubifs", 5)) {
			ULOG_ERR("extroot: unsupported filesystem %s, try ext4, f2fs, btrfs, ntfs or ubifs\n", pr->type);
			return -1;
		}

		if (test_fs_support(pr->type)) {
			ULOG_ERR("extroot: filesystem %s not supported by kernel\n", pr->type);
			return -1;
		}

		if (m->overlay)
			path = overlay;
		mkdir_p(path, 0755);

		if (check_fs)
			check_filesystem(pr);

		err = mount(pr->dev, path, pr->type, m->flags,
		            (m->options) ? (m->options) : (""));

		if (err) {
			ULOG_ERR("extroot: mounting %s (%s) on %s failed: %d (%m)\n",
			         pr->dev, pr->type, path, errno);
		} else if (m->overlay) {
			err = check_extroot(path);
			if (err)
				umount(path);
		}
	} else {
		ULOG_ERR("extroot: cannot find device %s%s\n",
		         (m->uuid ? "with UUID " : (m->label ? "with label " : "")),
		         (m->uuid ? m->uuid : (m->label ? m->label : m->device)));
	}

	return err;
}

/**
 * Look for extroot config and mount it if present
 *
 * Look for /etc/config/fstab on all supported partitions and use it for
 * mounting extroot if specified.
 */
static int main_extroot(int argc, char **argv)
{
	struct probe_info *pr;
	char blkdev_path[32] = { 0 };
	int err = -1;
#ifdef UBIFS_EXTROOT
	libubi_t libubi;
#endif

	if (!getenv("PREINIT"))
		return -1;

	if (argc != 2) {
		ULOG_ERR("Usage: block extroot\n");
		return -1;
	}

	make_devs();
	cache_load(1);

	/* enable LOG_INFO messages */
	ulog_threshold(LOG_INFO);

	/* try the currently mounted overlay if exists */
	err = mount_extroot("/tmp/overlay");
	if (!err)
	    return err;

	/*
	 * Look for "rootfs_data". We will want to mount it and check for
	 * extroot configuration.
	 */

	/* Start with looking for MTD partition */
	find_block_mtd("\"rootfs_data\"", blkdev_path, sizeof(blkdev_path));
	if (blkdev_path[0]) {
		pr = find_block_info(NULL, NULL, blkdev_path);
		if (pr && !strcmp(pr->type, "jffs2")) {
			char cfg[] = "/tmp/jffs_cfg";

			/*
			 * Mount MTD part and try extroot (using
			 * /etc/config/fstab from that partition)
			 */
			mkdir_p(cfg, 0755);
			if (!mount(blkdev_path, cfg, "jffs2", MS_NOATIME, NULL)) {
				err = mount_extroot(cfg);
				umount2(cfg, MNT_DETACH);
			}
			if (err < 0)
				rmdir("/tmp/overlay");
			rmdir(cfg);
			return err;
		}
	}

#ifdef UBIFS_EXTROOT
	/* ... but it also could be an UBI volume */
	memset(blkdev_path, 0, sizeof(blkdev_path));
	libubi = libubi_open();
	find_block_ubi(libubi, "rootfs_data", blkdev_path, sizeof(blkdev_path));
	libubi_close(libubi);
	if (blkdev_path[0]) {
		char cfg[] = "/tmp/ubifs_cfg";

		/* Mount volume and try extroot (using fstab from that vol) */
		mkdir_p(cfg, 0755);
		if (!mount(blkdev_path, cfg, "ubifs", MS_NOATIME, NULL)) {
			err = mount_extroot(cfg);
			umount2(cfg, MNT_DETACH);
		}
		if (err < 0)
			rmdir("/tmp/overlay");
		rmdir(cfg);
		return err;
       }
#endif

	/* As a last resort look for /etc/config/fstab on "rootfs" partition */
	return mount_extroot(NULL);
}

static int main_mount(int argc, char **argv)
{
	struct probe_info *pr;

	if (config_load(NULL))
		return -1;

	cache_load(1);
	list_for_each_entry(pr, &devices, list)
		mount_device(pr, TYPE_DEV);

	handle_swapfiles(true);

	return 0;
}

static int main_umount(int argc, char **argv)
{
	struct probe_info *pr;
	bool all = false;

	if (config_load(NULL))
		return -1;

	handle_swapfiles(false);

	cache_load(1);

	if (argc == 3)
		all = !strcmp(argv[2], "-a");

	list_for_each_entry(pr, &devices, list) {
		struct mount *m;

		if (!strcmp(pr->type, "swap"))
			continue;

		m = find_block(pr->uuid, pr->label, basename(pr->dev), NULL);
		if (m && m->extroot)
			continue;

		umount_device(pr->dev, TYPE_DEV, all);
	}

	return 0;
}

static int main_detect(int argc, char **argv)
{
	struct probe_info *pr;

	cache_load(0);
	printf("config 'global'\n");
	printf("\toption\tanon_swap\t'0'\n");
	printf("\toption\tanon_mount\t'0'\n");
	printf("\toption\tauto_swap\t'1'\n");
	printf("\toption\tauto_mount\t'1'\n");
	printf("\toption\tdelay_root\t'5'\n");
	printf("\toption\tcheck_fs\t'0'\n\n");
	list_for_each_entry(pr, &devices, list)
		print_block_uci(pr);

	return 0;
}

static int main_info(int argc, char **argv)
{
	int i;
	struct probe_info *pr;

	cache_load(1);
	if (argc == 2) {
		list_for_each_entry(pr, &devices, list)
			print_block_info(pr);

		return 0;
	};

	for (i = 2; i < argc; i++) {
		struct stat s;

		if (stat(argv[i], &s)) {
			ULOG_ERR("failed to stat %s\n", argv[i]);
			continue;
		}
		if (!S_ISBLK(s.st_mode) && !(S_ISCHR(s.st_mode) && major(s.st_rdev) == 250)) {
			ULOG_ERR("%s is not a block device\n", argv[i]);
			continue;
		}
		pr = find_block_info(NULL, NULL, argv[i]);
		if (pr)
			print_block_info(pr);
	}

	return 0;
}

static int swapon_usage(void)
{
	fprintf(stderr, "Usage: swapon [-s] [-a] [[-p pri] DEVICE]\n\n"
		"\tStart swapping on [DEVICE]\n"
		" -a\tStart swapping on all swap devices\n"
		" -p pri\tSet priority of swap device\n"
		" -s\tShow summary\n");
	return -1;
}

static int main_swapon(int argc, char **argv)
{
	int ch;
	FILE *fp;
	char *lineptr;
	size_t s;
	struct probe_info *pr;
	int flags = 0;
	int pri;
	struct stat st;
	int err;

	while ((ch = getopt(argc, argv, "ap:s")) != -1) {
		switch(ch) {
		case 's':
			fp = fopen("/proc/swaps", "r");
			lineptr = NULL;

			if (!fp) {
				ULOG_ERR("failed to open /proc/swaps\n");
				return -1;
			}
			while (getline(&lineptr, &s, fp) > 0)
				printf("%s", lineptr);
			if (lineptr)
				free(lineptr);
			fclose(fp);
			return 0;
		case 'a':
			cache_load(0);
			list_for_each_entry(pr, &devices, list) {
				if (strcmp(pr->type, "swap"))
					continue;
				if (swapon(pr->dev, 0))
					ULOG_ERR("failed to swapon %s\n", pr->dev);
			}
			return 0;
		case 'p':
			pri = atoi(optarg);
			if (pri >= 0)
				flags = ((pri << SWAP_FLAG_PRIO_SHIFT) & SWAP_FLAG_PRIO_MASK) | SWAP_FLAG_PREFER;
			break;
		default:
			return swapon_usage();
		}
	}

	if (optind != (argc - 1))
		return swapon_usage();

	if (stat(argv[optind], &st) || (!S_ISBLK(st.st_mode) && !S_ISREG(st.st_mode))) {
		ULOG_ERR("%s is not a block device or file\n", argv[optind]);
		return -1;
	}
	err = swapon(argv[optind], flags);
	if (err) {
		ULOG_ERR("failed to swapon %s (%d)\n", argv[optind], err);
		return err;
	}

	return 0;
}

static int main_swapoff(int argc, char **argv)
{
	if (argc != 2) {
		ULOG_ERR("Usage: swapoff [-a] [DEVICE]\n\n"
			"\tStop swapping on DEVICE\n"
			" -a\tStop swapping on all swap devices\n");
		return -1;
	}

	if (!strcmp(argv[1], "-a")) {
		FILE *fp = fopen("/proc/swaps", "r");
		char line[256];

		if (!fp) {
			ULOG_ERR("failed to open /proc/swaps\n");
			return -1;
		}
		if (fgets(line, sizeof(line), fp))
			while (fgets(line, sizeof(line), fp)) {
				char *end = strchr(line, ' ');
				int err;

				if (!end)
					continue;
				*end = '\0';
				err = swapoff(line);
				if (err)
					ULOG_ERR("failed to swapoff %s (%d)\n", line, err);
			}
		fclose(fp);
	} else {
		struct stat s;
		int err;

		if (stat(argv[1], &s) || (!S_ISBLK(s.st_mode) && !S_ISREG(s.st_mode))) {
			ULOG_ERR("%s is not a block device or file\n", argv[1]);
			return -1;
		}
		err = swapoff(argv[1]);
		if (err) {
			ULOG_ERR("failed to swapoff %s (%d)\n", argv[1], err);
			return err;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *base = basename(*argv);

	umask(0);

	ulog_open(-1, -1, "block");
	ulog_threshold(LOG_NOTICE);

	if (!strcmp(base, "swapon"))
		return main_swapon(argc, argv);

	if (!strcmp(base, "swapoff"))
		return main_swapoff(argc, argv);

	if ((argc > 1) && !strcmp(base, "block")) {
		if (!strcmp(argv[1], "info"))
			return main_info(argc, argv);

		if (!strcmp(argv[1], "detect"))
			return main_detect(argc, argv);

		if (!strcmp(argv[1], "hotplug"))
			return main_hotplug(argc, argv);

		if (!strcmp(argv[1], "autofs"))
			return main_autofs(argc, argv);

		if (!strcmp(argv[1], "extroot"))
			return main_extroot(argc, argv);

		if (!strcmp(argv[1], "mount"))
			return main_mount(argc, argv);

		if (!strcmp(argv[1], "umount"))
			return main_umount(argc, argv);

		if (!strcmp(argv[1], "remount")) {
			int ret = main_umount(argc, argv);

			if (!ret)
				ret = main_mount(argc, argv);
			return ret;
		}
	}

	ULOG_ERR("Usage: block <info|mount|umount|detect>\n");

	return -1;
}
