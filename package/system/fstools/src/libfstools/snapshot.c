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

#include <libubox/list.h>
#include <libubox/blob.h>
#include <libubox/md5.h>

#include "libfstools.h"
#include "volume.h"
#include "snapshot.h"

int
verify_file_hash(char *file, uint32_t *hash)
{
	uint32_t md5[4];

	if (md5sum(file, md5) <= 0) {
		ULOG_ERR("failed to generate md5 sum\n");
		return -1;
	}

	if (memcmp(md5, hash, sizeof(md5))) {
		ULOG_ERR("failed to verify hash of %s.\n", file);
		return -1;
	}

	return 0;
}

int
snapshot_next_free(struct volume *v, uint32_t *seq)
{
	struct file_header hdr = { 0 };
	int block = 0;

	*seq = rand();

	do {
		if (volume_read(v, &hdr, block * v->block_size, sizeof(struct file_header))) {
			ULOG_ERR("scanning for next free block failed\n");
			return 0;
		}

		be32_to_hdr(&hdr);

		if (hdr.magic != OWRT)
			break;

		if (hdr.type == DATA && !valid_file_size(hdr.length)) {
			if (*seq + 1 != hdr.seq && block)
				return block;
			*seq = hdr.seq;
			block += pad_file_size(v, hdr.length) / v->block_size;
		}
	} while (hdr.type == DATA);

	return block;
}

int
config_find(struct volume *v, struct file_header *conf, struct file_header *sentinel)
{
	uint32_t seq;
	int i, next = snapshot_next_free(v, &seq);

	conf->magic = sentinel->magic = 0;

	if (!volume_read(v, conf, next, sizeof(*conf)))
		be32_to_hdr(conf);

	for (i = (v->size / v->block_size) - 1; i > 0; i--) {
		if (volume_read(v, sentinel,  i * v->block_size, sizeof(*sentinel))) {
			ULOG_ERR("failed to read header\n");
			return -1;
		}
		be32_to_hdr(sentinel);

		if (sentinel->magic == OWRT && sentinel->type == CONF && !valid_file_size(sentinel->length)) {
			if (next == i)
				return -1;
			return i;
		}
	}

	return -1;
}

int
snapshot_write_file(struct volume *v, int block, char *file, uint32_t seq, uint32_t type)
{
	uint32_t md5[4] = { 0 };
	struct file_header hdr;
	struct stat s;
        char buffer[256];
	int in = 0, len, offset;
	int ret = -1;

	if (stat(file, &s) || md5sum(file, md5) != s.st_size) {
		ULOG_ERR("stat failed on %s\n", file);
		goto out;
	}

	if ((block * v->block_size) + pad_file_size(v, s.st_size) > v->size) {
		ULOG_ERR("upgrade is too big for the flash\n");
		goto out;
	}
	volume_erase(v, block * v->block_size, pad_file_size(v, s.st_size));
	volume_erase(v, block * v->block_size + pad_file_size(v, s.st_size), v->block_size);

	hdr.length = s.st_size;
	hdr.magic = OWRT;
	hdr.type = type;
	hdr.seq = seq;
	memcpy(hdr.md5, md5, sizeof(md5));
	hdr_to_be32(&hdr);

	if (volume_write(v, &hdr, block * v->block_size, sizeof(struct file_header))) {
		ULOG_ERR("failed to write header\n");
		goto out;
	}

	in = open(file, O_RDONLY);
	if (in < 0) {
		ULOG_ERR("failed to open %s\n", file);
		goto out;
	}

	offset = (block * v->block_size) + sizeof(struct file_header);

	while ((len = read(in, buffer, sizeof(buffer))) > 0) {
		if (volume_write(v, buffer, offset, len) < 0)
			goto out;
		offset += len;
	}

	ret = 0;

out:
	if (in >= 0)
		close(in);

	return ret;
}

int
snapshot_read_file(struct volume *v, int block, char *file, uint32_t type)
{
	struct file_header hdr;
	char buffer[256];
	int out, offset = 0;

	if (volume_read(v, &hdr, block * v->block_size, sizeof(struct file_header))) {
		ULOG_ERR("failed to read header\n");
		return -1;
	}
	be32_to_hdr(&hdr);

	if (hdr.magic != OWRT)
		return -1;

	if (hdr.type != type)
		return -1;

	if (valid_file_size(hdr.length))
		return -1;

	out = open(file, O_WRONLY | O_CREAT, 0700);
	if (out < 0) {
		ULOG_ERR("failed to open %s\n", file);
		return -1;
	}

	offset = block * v->block_size + sizeof(hdr);

	while (hdr.length > 0) {
		int len = sizeof(buffer);

		if (hdr.length < len)
			len = hdr.length;

		if (volume_read(v, buffer, offset, len)) {
			close(out);
			return -1;
		}
		if (write(out, buffer, len) != len) {
			close(out);
			return -1;
		}
		offset += len;
		hdr.length -= len;
	}

	close(out);

	if (verify_file_hash(file, hdr.md5)) {
		ULOG_ERR("md5 verification failed\n");
		unlink(file);
		return 0;
	}

	block += pad_file_size(v, hdr.length) / v->block_size;

	return block;
}

int
sentinel_write(struct volume *v, uint32_t _seq)
{
	int ret, block;
	struct stat s;
	uint32_t seq;

	if (stat("/tmp/config.tar.gz", &s)) {
		ULOG_ERR("failed to stat /tmp/config.tar.gz\n");
		return -1;
	}

	snapshot_next_free(v, &seq);
	if (_seq)
		seq = _seq;
	block = v->size / v->block_size;
	block -= pad_file_size(v, s.st_size) / v->block_size;
	if (block < 0)
		block = 0;

	ret = snapshot_write_file(v, block, "/tmp/config.tar.gz", seq, CONF);
	if (ret)
		ULOG_ERR("failed to write sentinel\n");
	else
		ULOG_INFO("wrote /tmp/config.tar.gz sentinel\n");
	return ret;
}

int
volatile_write(struct volume *v, uint32_t _seq)
{
	int block, ret;
	uint32_t seq;

	block = snapshot_next_free(v, &seq);
	if (_seq)
		seq = _seq;
	if (block < 0)
		block = 0;

	ret = snapshot_write_file(v, block, "/tmp/config.tar.gz", seq, CONF);
	if (ret)
		ULOG_ERR("failed to write /tmp/config.tar.gz\n");
	else
		ULOG_INFO("wrote /tmp/config.tar.gz\n");
	return ret;
}

static int
snapshot_sync(struct volume *v)
{
	struct file_header sentinel, conf;
	int next, block = 0;
	uint32_t seq;

	next = snapshot_next_free(v, &seq);
	block = config_find(v, &conf, &sentinel);
	if (is_config(&conf) && conf.seq != seq) {
		conf.magic = 0;
		volume_erase(v, next * v->block_size, 2 * v->block_size);
	}

	if (is_config(&sentinel) && (sentinel.seq != seq)) {
		sentinel.magic = 0;
		volume_erase(v, block * v->block_size, v->block_size);
	}

	if (!is_config(&conf) && !is_config(&sentinel)) {
	//	ULOG_ERR("no config found\n");
	} else if (((is_config(&conf) && is_config(&sentinel)) &&
				(memcmp(conf.md5, sentinel.md5, sizeof(conf.md5)) || (conf.seq != sentinel.seq))) ||
			(is_config(&conf) && !is_config(&sentinel))) {
		uint32_t seq;
		int next = snapshot_next_free(v, &seq);
		int ret = snapshot_read_file(v, next, "/tmp/config.tar.gz", CONF);
		if (ret > 0) {
			if (sentinel_write(v, conf.seq))
				ULOG_ERR("failed to write sentinel data");
		}
	} else if (!is_config(&conf) && is_config(&sentinel) && next) {
		int ret = snapshot_read_file(v, block, "/tmp/config.tar.gz", CONF);
		if (ret > 0)
			if (volatile_write(v, sentinel.seq))
				ULOG_ERR("failed to write sentinel data");
	} else
		ULOG_INFO("config in sync\n");

	unlink("/tmp/config.tar.gz");

	return 0;
}

static int
_ramoverlay(char *rom, char *overlay)
{
	mount("tmpfs", overlay, "tmpfs", MS_NOATIME, "mode=0755");
	return fopivot(overlay, rom);
}

int
mount_snapshot(struct volume *v)
{
	snapshot_sync(v);
	setenv("SNAPSHOT", "magic", 1);
	_ramoverlay("/rom", "/overlay");
	if (system("/sbin/snapshot unpack") == -1) {
		perror("system");
		return -1;
	}
	foreachdir("/overlay/", handle_whiteout);
	if (mkdir("/volatile", 0700) == -1 && errno != EEXIST) {
		perror("mkdir");
		return -1;
	}
	_ramoverlay("/rom", "/volatile");
	mount_move("/rom/volatile", "/volatile", "");
	mount_move("/rom/rom", "/rom", "");
	if (system("/sbin/snapshot config_unpack")) {
		perror("system");
		return -1;
	}
	foreachdir("/volatile/", handle_whiteout);
	unsetenv("SNAPSHOT");
	return -1;
}
