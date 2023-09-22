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

#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <mtd/mtd-user.h>

#include <glob.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <libubox/list.h>
#include <libubox/blob.h>
#include <libubox/md5.h>
#include <libubox/ulog.h>

#include "libfstools/libfstools.h"
#include "libfstools/volume.h"
#include "libfstools/snapshot.h"

static int
config_write(int argc, char **argv)
{
	struct volume *v = volume_find("rootfs_data");
	int ret;

	if (!v)
		return -1;

	volume_init(v);
	ret = volatile_write(v, 0);
	if (!ret)
		ret = sentinel_write(v, 0);

	return ret;
}

static int
config_read(int argc, char **argv)
{
	struct volume *v = volume_find("rootfs_data");
	struct file_header conf, sentinel;
	int next, block, ret = 0;
	uint32_t seq;

	if (!v)
		return -1;

	volume_init(v);
	block = config_find(v, &conf, &sentinel);
	next = snapshot_next_free(v, &seq);
	if (is_config(&conf) && conf.seq == seq)
		block = next;
	else if (!is_config(&sentinel) || sentinel.seq != seq)
		return -1;

	unlink("/tmp/config.tar.gz");
	ret = snapshot_read_file(v, block, "/tmp/config.tar.gz", CONF);

	if (ret < 1)
		ULOG_ERR("failed to read /tmp/config.tar.gz\n");

	return ret;
}

static int
snapshot_write(int argc, char **argv)
{
	struct volume *v = volume_find("rootfs_data");
	int block, ret;
	uint32_t seq;

	if (!v)
		return -1;

	volume_init(v);
	block = snapshot_next_free(v, &seq);
	if (block < 0)
		block = 0;

	ret = snapshot_write_file(v, block, "/tmp/snapshot.tar.gz", seq + 1, DATA);
	if (ret)
		ULOG_ERR("failed to write /tmp/snapshot.tar.gz\n");
	else
		ULOG_INFO("wrote /tmp/snapshot.tar.gz\n");

	return ret;
}

static int
snapshot_mark(int argc, char **argv)
{
	__be32 owrt = cpu_to_be32(OWRT);
	struct volume *v;
	size_t sz;
	int fd;

	ULOG_WARN("This will remove all snapshot data stored on the system. Are you sure? [N/y]\n");
	if (getchar() != 'y')
		return -1;

	v = volume_find("rootfs_data");
	if (!v) {
		ULOG_ERR("MTD partition 'rootfs_data' not found\n");
		return -1;
	}

	volume_init(v);

	fd = open(v->blk, O_WRONLY);
	ULOG_INFO("%s - marking with 0x%08x\n", v->blk, owrt);
	if (fd < 0) {
		ULOG_ERR("opening %s failed\n", v->blk);
		return -1;
	}

	sz = write(fd, &owrt, sizeof(owrt));
	close(fd);

	if (sz != 1) {
		ULOG_ERR("writing %s failed: %m\n", v->blk);
		return -1;
	}

	return 0;
}

static int
snapshot_read(int argc, char **argv)
{
	struct volume *v = volume_find("rootfs_data");;
	int block = 0, ret = 0;
	char file[64];

	if (!v)
		return -1;

	volume_init(v);
	if (argc > 2) {
		block = atoi(argv[2]);
		if (block >= (v->size / v->block_size)) {
			ULOG_ERR("invalid block %d > %" PRIu64 "\n",
			         block, (uint64_t) v->size / v->block_size);
			goto out;
		}
		snprintf(file, sizeof(file), "/tmp/snapshot/block%d.tar.gz", block);

		ret = snapshot_read_file(v, block, file, DATA);
		goto out;
	}

	do {
		snprintf(file, sizeof(file), "/tmp/snapshot/block%d.tar.gz", block);
		block = snapshot_read_file(v, block, file, DATA);
	} while (block > 0);

out:
	return ret;
}

static int
snapshot_info(void)
{
	struct volume *v = volume_find("rootfs_data");
	struct file_header hdr = { 0 }, conf;
	int block = 0;

	if (!v)
		return -1;

	volume_init(v);
	ULOG_INFO("sectors:\t%" PRIu64 ", block_size:\t%dK\n",
		  (uint64_t) v->size / v->block_size, v->block_size / 1024);
	do {
		if (volume_read(v, &hdr, block * v->block_size, sizeof(struct file_header))) {
			ULOG_ERR("scanning for next free block failed\n");
			return 0;
		}

		be32_to_hdr(&hdr);

		if (hdr.magic != OWRT)
			break;

		if (hdr.type == DATA)
			ULOG_INFO("block %d:\tsnapshot entry, size: %d, sectors: %d, sequence: %d\n", block,  hdr.length, pad_file_size(v, hdr.length) / v->block_size, hdr.seq);
		else if (hdr.type == CONF)
			ULOG_INFO("block %d:\tvolatile entry, size: %d, sectors: %d, sequence: %d\n", block,  hdr.length, pad_file_size(v, hdr.length) / v->block_size, hdr.seq);

		if (hdr.type == DATA && !valid_file_size(hdr.length))
			block += pad_file_size(v, hdr.length) / v->block_size;
	} while (hdr.type == DATA);
	block = config_find(v, &conf, &hdr);
	if (block > 0)
		ULOG_INFO("block %d:\tsentinel entry, size: %d, sectors: %d, sequence: %d\n", block, hdr.length, pad_file_size(v, hdr.length) / v->block_size, hdr.seq);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return -1;

	if (!strcmp(argv[1], "config_read"))
		return config_read(argc, argv);
	if (!strcmp(argv[1], "config_write"))
		return config_write(argc, argv);
	if (!strcmp(argv[1], "read"))
		return snapshot_read(argc, argv);
	if (!strcmp(argv[1], "write"))
		return snapshot_write(argc, argv);
	if (!strcmp(argv[1], "mark"))
		return snapshot_mark(argc, argv);
	if (!strcmp(argv[1], "info"))
		return snapshot_info();
	return -1;
}
