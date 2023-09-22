/*
 * Copyright (C) 2007 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * An utility to delete UBI devices (detach MTD devices from UBI).
 *
 * Author: Artem Bityutskiy
 */

#define PROGRAM_NAME    "ubidetach"
#define VERSION	"owrt-fstools"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libubi-tiny.h"

#define DEFAULT_CTRL_DEV "/dev/ubi_ctrl"

static int ubi_write(char *node, int fd, const void *buf, int len)
{
	int ret;

	while (len) {
		ret = write(fd, buf, len);
		if (ret < 0) {
			if (errno == EINTR) {
				fprintf(stderr, "do not interrupt me!");
				continue;
			}
			fprintf(stderr, "cannot write %d bytes to volume \"%s\"", len, node);
			return -1;
		}

		if (ret == 0) {
			fprintf(stderr, "cannot write %d bytes to volume \"%s\"", len, node);
			return -1;
		}
		len -= ret;
		buf += ret;
	}

	return 0;
}

static int update_volume(libubi_t libubi, struct ubi_vol_info *vol_info, char *node, char *img, int skip)
{
	int err, fd, ifd;
	long long bytes;
	char *buf;
	struct stat st;

	buf = malloc(vol_info->leb_size);
	if (!buf) {
		fprintf(stderr, "cannot allocate %d bytes of memory", vol_info->leb_size);
		return -1;
	}
	err = stat(img, &st);
	if (err < 0) {
		fprintf(stderr, "stat failed on \"%s\"", img);
		goto out_free;
	}

	bytes = st.st_size - skip;

	if (bytes > vol_info->rsvd_bytes) {
		fprintf(stderr, "\"%s\" (size %lld) will not fit volume \"%s\" (size %lld)",
		       img, bytes, node, vol_info->rsvd_bytes);
		goto out_free;
	}

	fd = open(node, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "cannot open UBI volume \"%s\"", node);
		goto out_free;
	}

	ifd = open(img, O_RDONLY);
	if (ifd == -1) {
		fprintf(stderr, "cannot open \"%s\"", img);
		goto out_close1;
	}

	if (skip && lseek(ifd, skip, SEEK_CUR) == -1) {
		fprintf(stderr, "lseek input by %d failed", skip);
		goto out_close;
	}

	err = ubi_update_start(libubi, fd, bytes);
	if (err) {
		fprintf(stderr, "cannot start volume \"%s\" update", node);
		goto out_close;
	}

	while (bytes) {
		ssize_t ret;
		int to_copy = vol_info->leb_size;
		if (to_copy > bytes)
			to_copy = bytes;

		ret = read(ifd, buf, to_copy);
		if (ret <= 0) {
			if (errno == EINTR) {
				fprintf(stderr, "do not interrupt me!");
				continue;
			} else {
				fprintf(stderr, "cannot read %d bytes from \"%s\"",
						to_copy, img);
				goto out_close;
			}
		}

		err = ubi_write(node, fd, buf, ret);
		if (err)
			goto out_close;
		bytes -= ret;
	}

	close(ifd);
	close(fd);
	free(buf);
	return 0;

out_close:
	close(ifd);
out_close1:
	close(fd);
out_free:
	free(buf);
	return -1;
}

int ubiattach(libubi_t libubi, char *mtd)
{
	struct ubi_attach_request req = {
		.dev_num = UBI_DEV_NUM_AUTO,
		.mtd_num = -1,
		.vid_hdr_offset = 0,
		.max_beb_per1024 = 0,
		.mtd_dev_node = mtd,
	};
	int err = ubi_attach(libubi, DEFAULT_CTRL_DEV, &req);

	if (err) {
		fprintf(stderr, "cannot attach \"%s\"", mtd);
		return err;
	}

	return 0;
}

int ubidetach(libubi_t libubi, char *mtd)
{
	return ubi_detach(libubi, DEFAULT_CTRL_DEV, mtd);
}

int ubirsvol(libubi_t libubi, char *node, char *name, int bytes)
{
	struct ubi_dev_info dev_info;
	struct ubi_vol_info vol_info;
	int err = ubi_get_dev_info(libubi, node, &dev_info);

	if (err) {
		fprintf(stderr, "cannot get information about UBI device \"%s\"",
			node);
		return -1;
	}
	err = ubi_get_vol_info1_nm(libubi, dev_info.dev_num, name, &vol_info);
	if (err) {
		fprintf(stderr, "cannot find UBI volume \"%s\"", name);
		return -1;
	}

	err = ubi_rsvol(libubi, node, vol_info.vol_id, bytes);
	if (err) {
		fprintf(stderr, "cannot UBI resize volume");
		return -1;
	}

	return 0;
}

int ubirmvol(libubi_t libubi, char *node, char *name)
{
	struct ubi_dev_info dev_info;
	struct ubi_vol_info vol_info;
	int err = ubi_get_dev_info(libubi, node, &dev_info);

	if (err) {
		fprintf(stderr, "cannot get information about UBI device \"%s\"",
			node);
		return -1;
	}

	err = ubi_get_vol_info1_nm(libubi, dev_info.dev_num, name, &vol_info);
	if (err) {
		fprintf(stderr, "cannot find UBI volume \"%s\"", name);
		return -1;
	}

	err = ubi_rmvol(libubi, node, vol_info.vol_id);
	if (err) {
		fprintf(stderr, "cannot UBI remove volume");
		return -1;
	}

	return 0;
}

int ubimkvol(libubi_t libubi, char *node, char *name, int maxavs)
{
	struct ubi_dev_info dev_info;
	struct ubi_vol_info vol_info;
	struct ubi_mkvol_request req;
	int err = ubi_get_dev_info(libubi, node, &dev_info);

	if (err) {
		fprintf(stderr, "cannot get information about UBI device \"%s\"",
			node);
		return -1;
	}

	if (dev_info.avail_bytes == 0) {
		fprintf(stderr, "UBI device does not have free logical eraseblocks");
		return -1;
	}

	if (maxavs)
		printf("Set volume size to %lld\n", dev_info.avail_bytes);

	req.vol_id = UBI_VOL_NUM_AUTO;
	req.alignment = 1;
	req.bytes = dev_info.avail_bytes;
	req.vol_type = UBI_DYNAMIC_VOLUME;
	req.name = name;

	err = ubi_mkvol(libubi, node, &req);
	if (err < 0) {
		fprintf(stderr, "cannot UBI create volume");
		return -1;
	}

	/* Print information about the created device */
	err = ubi_get_vol_info1(libubi, dev_info.dev_num, req.vol_id, &vol_info);
	if (err) {
		fprintf(stderr, "cannot get information about newly created UBI volume");
		return -1;
	}

	printf("Volume ID %d, size %d LEBs (", vol_info.vol_id, vol_info.rsvd_lebs);
	ubiutils_print_bytes(vol_info.rsvd_bytes, 0);
	printf("), LEB size ");
	ubiutils_print_bytes(vol_info.leb_size, 1);
	printf(", %s, name \"%s\", alignment %d\n",
		req.vol_type == UBI_DYNAMIC_VOLUME ? "dynamic" : "static",
		vol_info.name, vol_info.alignment);

	return 0;
}

int ubiupdatevol(libubi_t libubi, char *node, char *file)
{
	struct ubi_vol_info vol_info;
	int err = ubi_get_vol_info(libubi, node, &vol_info);

	if (err) {
		fprintf(stderr, "cannot get information about UBI volume \"%s\"",
			node);
		return -1;
	}

	return update_volume(libubi, &vol_info, node, file, 0);
}

int ubitruncatevol(libubi_t libubi, char *node)
{
	int err, fd;

	fd = open(node, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "cannot open \"%s\"", node);
		return -1;
	}

	err = ubi_update_start(libubi, fd, 0);
	if (err) {
		fprintf(stderr, "cannot truncate volume \"%s\"", node);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}
