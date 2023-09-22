/*
 * Copyright (C) 2014 Daniel Golle <daniel@makrotopia.org>
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

#include "common.h"

/* fit for UBI_MAX_VOLUME_NAME and sysfs path lengths */
#define BUFLEN		128

/* could use libubi-tiny instead, but already had the code directly reading
 * from sysfs */
const char *const ubi_dir_name = "/sys/class/ubi";

struct ubi_volume {
	struct volume v;
	int		ubi_num;
	int		ubi_volid;
};

static struct driver ubi_driver;

static unsigned int
test_open(char *filename)
{
	FILE *f;

	f = fopen(filename, "r");
	if (!f)
		return 0;

	fclose(f);
	return 1;
}

static int ubi_volume_init(struct volume *v)
{
	struct ubi_volume *p = container_of(v, struct ubi_volume, v);
	char voldir[BUFLEN], voldev[BUFLEN], volname[BUFLEN];
	unsigned int volsize;

	snprintf(voldir, sizeof(voldir), "%s/ubi%u_%u",
		ubi_dir_name, p->ubi_num, p->ubi_volid);

	snprintf(voldev, sizeof(voldev), "/dev/ubi%u_%u",
		p->ubi_num, p->ubi_volid);

	if (!read_string_from_file(voldir, "name", volname, sizeof(volname)))
		return -1;

	if (read_uint_from_file(voldir, "data_bytes", &volsize))
		return -1;

	v->name = volname;
	v->type = UBIVOLUME;
	v->size = volsize;
	v->blk = strdup(voldev);

	return 0;
}

static struct volume *ubi_volume_match(char *name, int ubi_num, int volid)
{
	char voldir[BUFLEN], volblkdev[BUFLEN], volname[BUFLEN];
	struct ubi_volume *p;

	snprintf(voldir, sizeof(voldir), "%s/ubi%u_%u",
		ubi_dir_name, ubi_num, volid);

	snprintf(volblkdev, sizeof(volblkdev), "/dev/ubiblock%u_%u",
		ubi_num, volid);

	/* skip if ubiblock device exists */
	if (test_open(volblkdev))
		return NULL;

	/* todo: skip existing gluebi device for legacy support */

	if (!read_string_from_file(voldir, "name", volname, sizeof(volname))) {
		ULOG_ERR("Couldn't read %s/name\n", voldir);
		return NULL;
	}

	if (strcmp(name, volname))
		return NULL;

	p = calloc(1, sizeof(struct ubi_volume));
	if (!p)
		return NULL;

	p->v.drv = &ubi_driver;
	p->ubi_num = ubi_num;
	p->ubi_volid = volid;

	return &p->v;
}

static struct volume *ubi_part_match(char *name, unsigned int ubi_num)
{
	DIR *ubi_dir;
	struct dirent *ubi_dirent;
	unsigned int volid;
	char devdir[BUFLEN];
	struct volume *ret = NULL;

	snprintf(devdir, sizeof(devdir), "%s/ubi%u",
		ubi_dir_name, ubi_num);

	ubi_dir = opendir(devdir);
	if (!ubi_dir)
		return ret;

	while ((ubi_dirent = readdir(ubi_dir)) != NULL) {
		if (strncmp(ubi_dirent->d_name, "ubi", 3))
			continue;

		if (sscanf(ubi_dirent->d_name, "ubi%*u_%u", &volid) != 1)
			continue;

		ret = ubi_volume_match(name, ubi_num, volid);
		if (ret)
			break;
	}
	closedir(ubi_dir);

	return ret;
}

static struct volume *ubi_volume_find(char *name)
{
	struct volume *ret = NULL;
	DIR *ubi_dir;
	struct dirent *ubi_dirent;
	unsigned int ubi_num;

	if (find_filesystem("ubifs"))
		return ret;

	ubi_dir = opendir(ubi_dir_name);
	/* check for os ubi support */
	if (!ubi_dir)
		return ret;

	/* probe ubi devices and volumes */
	while ((ubi_dirent = readdir(ubi_dir)) != NULL) {
		if (ubi_dirent->d_name[0] == '.')
			continue;

		sscanf(ubi_dirent->d_name, "ubi%u", &ubi_num);
		ret = ubi_part_match(name, ubi_num);
		if (ret)
			break;
	}
	closedir(ubi_dir);
	return ret;
}

static int ubi_volume_identify(struct volume *v)
{
	/* Todo: use libblkid-tiny on the ubi chardev */
	return FS_UBIFS;
}

static struct driver ubi_driver = {
	.name = "ubi",
	.find = ubi_volume_find,
	.init = ubi_volume_init,
	.identify = ubi_volume_identify,
};

DRIVER(ubi_driver);
