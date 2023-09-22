/*
 * Copyright (C) 2008 Karel Zak <kzak@redhat.com>
 *
 * Inspired by libvolume_id by
 *     Kay Sievers <kay.sievers@vrfy.org>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "bitops.h"	/* swab16() */
#include "superblocks.h"

#include <libubox/md5.h>

struct squashfs_super_block {
	uint32_t s_magic;
	uint32_t inodes;
	uint32_t mkfs_time;
	uint32_t block_size;
	uint32_t fragments;
	uint16_t compression;
	uint16_t block_log;
	uint16_t flags;
	uint16_t no_ids;
	uint16_t s_major;
	uint16_t s_minor;
	uint64_t root_inode;
	uint64_t bytes_used;
	uint64_t id_table_start;
	uint64_t xattr_id_table_start;
	uint64_t inode_table_start;
	uint64_t directory_table_start;
	uint64_t fragment_table_start;
	uint64_t lookup_table_start;
} __attribute__((packed));

static int probe_squashfs(blkid_probe pr, const struct blkid_idmag *mag)
{
	md5_ctx_t ctx = { 0 };
	uint32_t md5[4];
	struct squashfs_super_block *sq;

	sq = blkid_probe_get_sb(pr, mag, struct squashfs_super_block);
	if (!sq)
		return -1;

	if (strcmp(mag->magic, "sqsh") == 0 ||
	    strcmp(mag->magic, "qshs") == 0)
		blkid_probe_sprintf_version(pr, "%u.%u",
				be16_to_cpu(sq->s_major),
				be16_to_cpu(sq->s_minor));
	else
		blkid_probe_sprintf_version(pr, "%u.%u",
				le16_to_cpu(sq->s_major),
				le16_to_cpu(sq->s_minor));
	md5_begin(&ctx);
	md5_hash(sq, sizeof(*sq), &ctx);
	md5_end(&md5, &ctx);
	blkid_probe_sprintf_uuid(pr, NULL, 4, "%08x-%08x-%08x-%08x",
			md5[3], md5[2], md5[1], md5[0]);
	return 0;
}

const struct blkid_idinfo squashfs_idinfo =
{
	.name		= "squashfs",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_squashfs,
	.magics		=
	{
		{ .magic = "sqsh", .len = 4 }, /* BE legacy squashfs */
		{ .magic = "hsqs", .len = 4 }, /* LE / v4 squashfs */

		/* LZMA version */
		{ .magic = "qshs", .len = 4 }, /* BE legacy squashfs with LZMA */
		{ .magic = "shsq", .len = 4 }, /* LE / v4 squashfs with LZMA */
		{ NULL }
	}
};


