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

#ifndef _PROBE_H
#define _PROBE_H

#include <libubox/list.h>

struct probe_info {
	struct list_head list;

	char *type;
	char *dev;
	char *uuid;
	char *label;
	char *version;
};

struct probe_info * probe_path(const char *path);
struct probe_info * probe_path_libblkid(const char *path);

int make_devs(void);

#endif /* _PROBE_H */
