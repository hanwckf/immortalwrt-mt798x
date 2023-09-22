// SPDX-License-Identifier: GPL-2.0-or-later

#include "common.h"
#define BUFLEN 128

int
read_uint_from_file(char *dirname, char *filename, unsigned int *i)
{
	FILE *f;
	char fname[BUFLEN];
	int ret = -1;

	snprintf(fname, sizeof(fname), "%s/%s", dirname, filename);

	f = fopen(fname, "r");
	if (!f)
		return ret;

	if (fscanf(f, "%u", i) == 1)
		ret = 0;

	fclose(f);
	return ret;
}

char
*read_string_from_file(const char *dirname, const char *filename, char *buf, size_t bufsz)
{
	FILE *f;
	char fname[BUFLEN];
	int i;

	snprintf(fname, sizeof(fname), "%s/%s", dirname, filename);

	f = fopen(fname, "r");
	if (!f)
		return NULL;

	if (fgets(buf, bufsz, f) == NULL) {
		fclose(f);
		return NULL;
	}

	fclose(f);

	/* make sure the string is \0 terminated */
	buf[bufsz - 1] = '\0';

	/* remove trailing whitespace */
	i = strlen(buf) - 1;
	while (i > 0 && buf[i] <= ' ')
		buf[i--] = '\0';

	return buf;
}

int block_file_identify(FILE *f, uint64_t offset)
{
	uint32_t magic = 0;
	size_t n;

	if (fseeko(f, offset, SEEK_SET) < 0)
		return -1;

	n = fread(&magic, sizeof(magic), 1, f);
	if (magic == cpu_to_le32(0x88b1f))
		return FS_TARGZ;

	if (magic == cpu_to_be32(0xdeadc0de))
		return FS_DEADCODE;

	if (fseeko(f, offset + 0x400, SEEK_SET) < 0)
		return -1;

	n = fread(&magic, sizeof(magic), 1, f);
	if (n != 1)
		return -1;

	if (magic == cpu_to_le32(0xF2F52010))
		return FS_F2FS;

	magic = 0;
	if (fseeko(f, offset + 0x438, SEEK_SET) < 0)
		return -1;

	n = fread(&magic, sizeof(magic), 1, f);
	if (n != 1)
		return -1;

	if ((le32_to_cpu(magic) & 0xffff) == 0xef53)
		return FS_EXT4;

	return FS_NONE;
}

static bool use_f2fs(struct volume *v, uint64_t offset, const char *bdev)
{
	uint64_t size = 0;
	bool ret = false;
	int fd;

	fd = open(bdev, O_RDONLY);
	if (fd < 0)
		return false;

	if (ioctl(fd, BLKGETSIZE64, &size) == 0)
		ret = size - offset > F2FS_MINSIZE;

	close(fd);

	return ret;
}

int block_volume_format(struct volume *v, uint64_t offset, const char *bdev)
{
	int ret = 0;
	char str[128];
	unsigned int skip_blocks = 0;
	int fd;
	__u32 deadc0de;
	size_t sz;

	switch (volume_identify(v)) {
	case FS_DEADCODE:
		/* skip padding */
		fd = open(v->blk, O_RDONLY);
		if (fd < 0) {
			ret = EIO;
			break;
		}
		do {
			if (lseek(fd, (skip_blocks + 1) * 512, SEEK_SET) == (off_t) -1) {
				ret = EIO;
				break;
			}
			sz = read(fd, &deadc0de, sizeof(deadc0de));
			if (sz != sizeof(deadc0de)) {
				ret = EIO;
				break;
			}
		} while(++skip_blocks <= 512 &&
			(deadc0de == cpu_to_be32(0xdeadc0de) || deadc0de == 0xffffffff));

		close(fd);
		if (ret)
			break;

		/* only try extracting in case gzip header is present */
		if (deadc0de != cpu_to_le32(0x88b1f))
			goto do_format;

		/* fall-through */
	case FS_TARGZ:
		snprintf(str, sizeof(str),
			 "dd if=%s bs=512 skip=%u 2>/dev/null | gzip -cd > /tmp/sysupgrade.tar 2>/dev/null",
			 v->blk, skip_blocks);
		ret = system(str);
		if (ret < 0) {
			ULOG_ERR("failed extracting config backup from %s\n", v->blk);
			break;
		}
		/* fall-through */
	case FS_NONE:
do_format:
		ULOG_INFO("overlay filesystem in %s has not been formatted yet\n", v->blk);
		if (use_f2fs(v, offset, bdev))
			snprintf(str, sizeof(str), "mkfs.f2fs -q -l rootfs_data %s", v->blk);
		else
			snprintf(str, sizeof(str), "mkfs.ext4 -q -L rootfs_data %s", v->blk);

		ret = system(str);
		break;
	default:
		break;
	}

	return ret;
}
