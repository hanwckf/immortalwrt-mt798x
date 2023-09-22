/*
 * Copyright (C) 2017 Rafał Miłecki <rafal@milecki.pl>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "superblocks.h"

struct ubi_ec_hdr {
	uint32_t	magic;
	uint8_t		version;
	uint8_t		padding1[3];
	uint64_t	ec;
	uint32_t	vid_hdr_offset;
	uint32_t	data_offset;
	uint32_t	image_seq;
	uint8_t		padding2[32];
	uint32_t	hdr_crc;
} __attribute__((packed));

static int probe_ubi(blkid_probe pr, const struct blkid_idmag *mag)
{
	struct ubi_ec_hdr *hdr;

	hdr = blkid_probe_get_sb(pr, mag, struct ubi_ec_hdr);
	if (!hdr)
		return -1;

	blkid_probe_sprintf_version(pr, "%u", hdr->version);
	blkid_probe_sprintf_uuid(pr, (unsigned char *)&hdr->image_seq, 4, "%u",
				 be32_to_cpu(hdr->image_seq));
	return 0;
}

const struct blkid_idinfo ubi_idinfo =
{
	.name		= "ubi",
	.usage		= BLKID_USAGE_RAID,
	.probefunc	= probe_ubi,
	.magics		=
	{
		{ .magic = "UBI#", .len = 4 },
		{ NULL }
	}
};
