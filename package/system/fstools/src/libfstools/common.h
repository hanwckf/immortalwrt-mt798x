// SPDX-License-Identifier: GPL-2.0-or-later

#define _FILE_OFFSET_BITS 64

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <glob.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>

#include "libfstools.h"
#include "volume.h"

#define F2FS_MINSIZE		(100ULL * 1024ULL * 1024ULL)

int read_uint_from_file(char *dirname, char *filename, unsigned int *i);
char *read_string_from_file(const char *dirname, const char *filename, char *buf, size_t bufsz);
int block_file_identify(FILE *f, uint64_t offset);
int block_volume_format(struct volume *v, uint64_t offset, const char *bdev);
