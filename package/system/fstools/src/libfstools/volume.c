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

#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>

#include "libfstools.h"
#include "volume.h"

static LIST_HEAD(drivers);

void
volume_register_driver(struct driver *d)
{
	list_add(&d->list, &drivers);
}

struct volume* volume_find(char *name)
{
	struct volume *v;
	struct driver *d;

	list_for_each_entry(d, &drivers, list) {
		if (d->find) {
			v = d->find(name);
			if (v)
				return v;
		}
	}

	return NULL;
}
