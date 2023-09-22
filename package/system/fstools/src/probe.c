/*
 * Copyright (C) 2016 Jo-Philipp Wich <jo@mein.io>
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

#include <string.h>
#include <libubox/utils.h>

#include "probe.h"
#include "libblkid-tiny/libblkid-tiny.h"

static struct probe_info *
probe_path_tiny(const char *path)
{
	struct probe_info *info = NULL;
	struct blkid_struct_probe *pr;
	char *type, *dev, *uuid, *label, *version;

	pr = blkidtiny_new_probe();
	if (!pr)
		return NULL;

	if (probe_block((char *)path, pr) == 0 && pr->id && !pr->err) {
		info = calloc_a(sizeof(*info),
		                &type,    strlen(pr->id->name) + 1,
		                &dev,     strlen(path)         + 1,
		                &uuid,    strlen(pr->uuid)     + 1,
		                &label,   strlen(pr->label)    + 1,
		                &version, strlen(pr->version)  + 1);

		if (info) {
			info->type = strcpy(type, pr->id->name);
			info->dev = strcpy(dev, path);

			if (pr->uuid[0])
				info->uuid = strcpy(uuid, pr->uuid);

			if (pr->label[0])
				info->label = strcpy(label, pr->label);

			if (pr->version[0])
				info->version = strcpy(version, pr->version);
		}
	}

	blkidtiny_free_probe(pr);

	return info;
}

struct probe_info *
probe_path(const char *path)
{
	struct probe_info *info;

	info = probe_path_tiny(path);

	if (!info)
		info = probe_path_libblkid(path);

	return info;
}

int
make_devs(void)
{
	return mkblkdev();
}
