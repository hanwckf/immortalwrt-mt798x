/*
 * Low-level libblkid probing API
 *
 * Copyright (C) 2008-2009 Karel Zak <kzak@redhat.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */

#include <stdlib.h>

#include "blkidP.h"
#include "libblkid-tiny.h"

static int blkid_probe_reset_buffers(struct blkid_struct_probe *pr);

struct blkid_struct_probe *blkidtiny_new_probe(void)
{
	struct blkid_struct_probe *pr;

	pr = calloc(1, sizeof(struct blkid_struct_probe));
	if (!pr)
		return NULL;

	INIT_LIST_HEAD(&pr->buffers);

	return pr;
}

void blkidtiny_free_probe(struct blkid_struct_probe *pr)
{
	if (!pr)
		return;

	blkid_probe_reset_buffers(pr);

	free(pr);
}

static int blkid_probe_reset_buffers(struct blkid_struct_probe *pr)
{
	if (list_empty(&pr->buffers))
		return 0;

	while (!list_empty(&pr->buffers)) {
		struct blkid_bufinfo *bf = list_first_entry(&pr->buffers, struct blkid_bufinfo, bufs);

		list_del(&bf->bufs);

		free(bf);
	}

	return 0;
}
