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

#ifndef _VOLUME_H__
#define _VOLUME_H__

#include <asm/byteorder.h>

struct volume;

typedef int (*volume_probe_t)(void);
typedef int (*volume_init_t)(struct volume *v);
typedef void (*volume_stop_t)(struct volume *v);
typedef struct volume *(*volume_find_t)(char *name);
typedef int (*volume_identify_t)(struct volume *v);
typedef int (*volume_read_t)(struct volume *v, void *buf, int offset, int length);
typedef int (*volume_write_t)(struct volume *v, void *buf, int offset, int length);
typedef int (*volume_erase_t)(struct volume *v, int start, int len);
typedef int (*volume_erase_all_t)(struct volume *v);

struct driver {
	struct list_head	list;
	char			*name;
	volume_probe_t		probe;
	volume_init_t		init;
	volume_stop_t		stop;
	volume_find_t		find;
	volume_identify_t	identify;
	volume_read_t		read;
	volume_write_t		write;
	volume_erase_t		erase;
	volume_erase_all_t	erase_all;
};

enum {
	UNKNOWN_TYPE,
	NANDFLASH,
	NORFLASH,
	UBIVOLUME,
	BLOCKDEV,
};

struct volume {
	struct driver	*drv;
	char		*name;
	char		*blk;

	__u64		size;
	__u32		block_size;
	int		type;
};

extern struct volume* volume_find(char *name);
extern void volume_register_driver(struct driver *drv);

static inline int volume_init(struct volume *v)
{
	if (v && v->drv->init)
		return v->drv->init(v);
	return -1;
}

static inline int volume_identify(struct volume *v)
{
	if (v && v->drv->identify)
		return v->drv->identify(v);
	return -1;
}

static inline int volume_erase(struct volume *v, int offset, int len)
{
	if (v && v->drv->erase)
		return v->drv->erase(v, offset, len);
	return -1;
}

static inline int volume_erase_all(struct volume *v)
{
	if (v && v->drv->erase_all)
		return v->drv->erase_all(v);
	return -1;
}

static inline int volume_read(struct volume *v, void *buf, int offset, int length)
{
	if (v && v->drv->read)
		return v->drv->read(v, buf, offset, length);
	return -1;
}

static inline int volume_write(struct volume *v, void *buf, int offset, int length)
{
	if (v && v->drv->write)
		return v->drv->write(v, buf, offset, length);
	return -1;
}

#define DRIVER(x)					\
	static void __attribute__((constructor))	\
	drv_register_##x(void) {			\
		volume_register_driver(&x);		\
	}

#endif
