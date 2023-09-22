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

#include <dlfcn.h>
#include <string.h>
#include <stdbool.h>
#include <blkid/blkid.h>
#include <libubox/utils.h>

#include "probe.h"


static struct {
	bool loaded;
	blkid_probe (*alloc)(const char *);
	int (*probe)(blkid_probe);
	int (*lookup)(blkid_probe, const char *, const char **, size_t *);
	void (*free)(blkid_probe);
} libblkid = { };


static bool
load_libblkid(void)
{
	void *lib;

	if (!libblkid.loaded) {
		lib = dlopen("libblkid.so", RTLD_GLOBAL);

		if (lib == NULL)
			lib = dlopen("libblkid.so.1", RTLD_GLOBAL);

		if (lib) {
			libblkid.alloc  = dlsym(lib, "blkid_new_probe_from_filename");
			libblkid.probe  = dlsym(lib, "blkid_do_probe");
			libblkid.lookup = dlsym(lib, "blkid_probe_lookup_value");
			libblkid.free   = dlsym(lib, "blkid_free_probe");
		}

		libblkid.loaded = true;
	}

	return (libblkid.alloc && libblkid.probe && libblkid.lookup && libblkid.free);
}

struct probe_info *
probe_path_libblkid(const char *path)
{
	blkid_probe pr;
	struct probe_info *info = NULL;
	size_t type_len, uuid_len, label_len, version_len;
	char *dev_ptr, *type_ptr, *uuid_ptr, *label_ptr, *version_ptr;
	const char *type_val, *uuid_val, *label_val, *version_val;

	if (!load_libblkid())
		return NULL;

	pr = libblkid.alloc(path);

	if (!pr)
		return NULL;

	if (libblkid.probe(pr) == 0) {
		if (libblkid.lookup(pr, "TYPE", &type_val, &type_len))
			type_len = 0;

		if (libblkid.lookup(pr, "UUID", &uuid_val, &uuid_len))
			uuid_len = 0;

		if (libblkid.lookup(pr, "LABEL", &label_val, &label_len))
			label_len = 0;

		if (libblkid.lookup(pr, "VERSION", &version_val, &version_len))
			version_len = 0;

		if (type_len) {
			info = calloc_a(sizeof(*info),
			                &dev_ptr,     strlen(path) + 1,
			                &type_ptr,    type_len,
			                &uuid_ptr,    uuid_len,
			                &label_ptr,   label_len,
			                &version_ptr, version_len);

			if (info) {
				info->dev = strcpy(dev_ptr, path);
				info->type = strcpy(type_ptr, type_val);

				if (uuid_len)
					info->uuid = strcpy(uuid_ptr, uuid_val);

				if (label_len)
					info->label = strcpy(label_ptr, label_val);

				if (version_len)
					info->version = strcpy(version_ptr, version_val);
			}
		}
	}

	libblkid.free(pr);

	return info;
}
