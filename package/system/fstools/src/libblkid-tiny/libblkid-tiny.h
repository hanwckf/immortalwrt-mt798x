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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef _LIBBLKID_TINY_H
#define _LIBBLKID_TINY_H

#include <libubox/list.h>

struct blkid_struct_probe;

/*
 * Filesystem / Raid magic strings
 */
struct blkid_idmag
{
	const char	*magic;		/* magic string */
	unsigned int	len;		/* length of magic */

	long		kboff;		/* kilobyte offset of superblock */
	unsigned int	sboff;		/* byte offset within superblock */
};

/*
 * Filesystem / Raid description
 */
struct blkid_idinfo
{
	const char	*name;		/* fs, raid or partition table name */
	int		usage;		/* BLKID_USAGE_* flag */
	int		flags;		/* BLKID_IDINFO_* flags */
	int		minsz;		/* minimal device size */

					/* probe function */
	int		(*probefunc)(struct blkid_struct_probe *pr, const struct blkid_idmag *mag);

	struct blkid_idmag	magics[];	/* NULL or array with magic strings */
};

/* Smaller version of the struct provided in blkidP.h */
struct blkid_struct_probe
{
	const struct blkid_idinfo	*id;
	struct list_head		list;

	int	fd;
	int	err;
	char	dev[32];
	char	uuid[64];
	char	label[1025];
	char	version[64];

	struct list_head	buffers;	/* list of buffers */
};

struct blkid_struct_probe *blkidtiny_new_probe(void);
void blkidtiny_free_probe(struct blkid_struct_probe *pr);

extern int probe_block(char *block, struct blkid_struct_probe *pr);
extern int mkblkdev(void);

#endif /* _LIBBLKID_TINY_H */
