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

#ifndef _SNAPSHOT_H__
#define _SNAPSHOT_H__

#define PATH_MAX	256
#define OWRT		0x4f575254
#define DATA		0x44415441
#define CONF		0x434f4e46

struct file_header {
	uint32_t magic;
	uint32_t type;
	uint32_t seq;
	uint32_t length;
	uint32_t md5[4];
};

static inline int
is_config(struct file_header *h)
{
	return ((h->magic == OWRT) && (h->type == CONF));
}

static inline int
valid_file_size(int fs)
{
	if ((fs > 8 * 1024 * 1204) || (fs <= 0))
		return -1;

	return 0;
}

static inline void
hdr_to_be32(struct file_header *hdr)
{
	uint32_t *h = (uint32_t *) hdr;
	int i;

	for (i = 0; i < sizeof(struct file_header) / sizeof(uint32_t); i++)
		h[i] = cpu_to_be32(h[i]);
}

static inline void
be32_to_hdr(struct file_header *hdr)
{
	uint32_t *h = (uint32_t *) hdr;
	int i;

	for (i = 0; i < sizeof(struct file_header) / sizeof(uint32_t); i++)
		h[i] = be32_to_cpu(h[i]);
}

static inline int
pad_file_size(struct volume *v, int size)
{
	int mod;

	size += sizeof(struct file_header);
	mod = size % v->block_size;
	if (mod) {
		size -= mod;
		size += v->block_size;
	}

	return size;
}

int verify_file_hash(char *file, uint32_t *hash);
int snapshot_next_free(struct volume *v, uint32_t *seq);
int config_find(struct volume *v, struct file_header *conf, struct file_header *sentinel);
int snapshot_write_file(struct volume *v, int block, char *file, uint32_t seq, uint32_t type);
int snapshot_read_file(struct volume *v, int block, char *file, uint32_t type);
int sentinel_write(struct volume *v, uint32_t _seq);
int volatile_write(struct volume *v, uint32_t _seq);

#endif
