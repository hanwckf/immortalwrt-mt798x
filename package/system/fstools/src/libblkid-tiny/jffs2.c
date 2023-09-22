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

static int probe_jffs2(blkid_probe pr, const struct blkid_idmag *mag)
{
	return 0;
}

const struct blkid_idinfo jffs2_idinfo =
{
	.name		= "jffs2",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_jffs2,
	.magics		=
	{
		{ .magic = "\x19\x85", .len = 2 },
		{ .magic = "\x85\x19", .len = 2 },
		{ NULL }
	}
};
