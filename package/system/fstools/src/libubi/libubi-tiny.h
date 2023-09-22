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

#ifndef _LIBUBI_TINY_H__
#define _LIBUBI_TINY_H__

#include "libubi.h"

int ubiattach(libubi_t libubi, char *mtd);
int ubidetach(libubi_t libubi, char *mtd);
int ubirsvol(libubi_t libubi, char *node, char *name, int bytes);
int ubirmvol(libubi_t libubi, char *node, char *name);
int ubimkvol(libubi_t libubi, char *node, char *name, int maxavs);
int ubiupdatevol(libubi_t libubi, char *node, char *file);
int ubitruncatevol(libubi_t libubi, char *node);

#endif
