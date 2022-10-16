// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 MediaTek Inc. All Rights Reserved.
 *
 * Author: Weijie Gao <weijie.gao@mediatek.com>
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#define SET_BINARY_MODE(_f)		_setmode(_fileno(_f, O_BINARY)
#else
#define SET_BINARY_MODE(_f)		((void)0)
#endif

#define CRC32_LE_POLY_DEFAULT		0xedb88320
#define CRC32_BE_POLY_DEFAULT		0x04c11db7
#define CRC32_TABLE_ITEMS		256

static uint32_t crc32_le_calc(uint32_t crc, const uint8_t *data, size_t length,
			      const uint32_t *crc_table)
{
	while (length--)
		crc = crc_table[(uint8_t)(crc ^ *data++)] ^ (crc >> 8);

	return crc;
}

static void crc32_le_init(uint32_t *crc_table, uint32_t poly)
{
	uint32_t i, j, v;

	for (i = 0; i < CRC32_TABLE_ITEMS; i++) {
		v = i;

		for (j = 0; j < 8; j++)
			v = (v >> 1) ^ ((v & 1) ? poly : 0);

		crc_table[i] = v;
	}
}

static uint32_t crc32_be_calc(uint32_t crc, const uint8_t *data, size_t length,
			      const uint32_t *crc_table)
{
	while (length--)
		crc = crc_table[(uint8_t)((crc >> 24) ^ *data++)] ^ (crc << 8);

	return crc;
}

static void crc32_be_init(uint32_t *crc_table, uint32_t poly)
{
	uint32_t i, j, v;

	for (i = 0; i < CRC32_TABLE_ITEMS; i++) {
		v = i << 24;

		for (j = 0; j < 8; j++)
			v = (v << 1) ^ ((v & (1 << 31)) ? poly : 0);

		crc_table[i] = v;
	}
}

struct crc_funcs {
	uint32_t poly;

	void (*init)(uint32_t *crc_table, uint32_t poly);
	uint32_t (*calc)(uint32_t crc, const uint8_t *data, size_t length,
			 const uint32_t *crc_table);
};

static const struct crc_funcs crc32_le = {
	.poly = CRC32_LE_POLY_DEFAULT,
	.init = crc32_le_init,
	.calc = crc32_le_calc,
};

static const struct crc_funcs crc32_be = {
	.poly = CRC32_BE_POLY_DEFAULT,
	.init = crc32_be_init,
	.calc = crc32_be_calc,
};

static const struct crc_funcs *crc32_algo = &crc32_le;
static uint32_t crc32_poly;
static uint32_t crc32_val;
static const char *input_file;
static bool output_decimal;
static bool no_comp;

static void err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void usage(FILE *con, const char *progname, int exitcode)
{
	const char *prog;
	size_t len;

	len = strlen(progname);
	prog = progname + len - 1;

	while (prog > progname) {
		if (*prog == '\\' || *prog == '/') {
			prog++;
			break;
		}

		prog--;
	}

	fprintf(con, "CRC32 checksum tool\n");
	fprintf(con, "\n");
	fprintf(con, "Usage: %s [options] <input_file>\n", prog);
	fprintf(con, "\n");
	fprintf(con, "Options:\n");
	fprintf(con, "\t-h         display help message\n");
	fprintf(con, "\t-i <val>   crc value for incremental calculation\n");
	fprintf(con, "\t           (default is 0)\n");
	fprintf(con, "\t-p <val>   polynomial for calculation\n");
	fprintf(con, "\t           (default is 0x%08x for LE, 0x%08x for BE)\n",
		crc32_le.poly, crc32_be.poly);
	fprintf(con, "\t-b         use big-endian mode\n");
	fprintf(con, "\t-n         do not use one's complement\n");
	fprintf(con, "\t-d         use decimal output\n");
	fprintf(con, "\n");

	exit(exitcode);
}

static int parse_args(int argc, char *argv[])
{
	int opt;

	static const char *optstring = "i:p:bndh";

	opterr = 0;

	while ((opt = getopt(argc, argv, optstring)) >= 0) {
		switch (opt) {
		case 'i':
			if (!isxdigit(optarg[0])) {
				err("Invalid crc value - %s\n", optarg);
				return -EINVAL;
			}

			crc32_val = strtoul(optarg, NULL, 0);
			break;

		case 'p':
			if (!isxdigit(optarg[0])) {
				err("Invalid polynomial value - %s\n", optarg);
				return -EINVAL;
			}

			crc32_poly = strtoul(optarg, NULL, 0);
			break;

		case 'b':
			crc32_algo = &crc32_be;
			break;

		case 'n':
			no_comp = true;
			break;

		case 'd':
			output_decimal = true;
			break;

		case 'h':
			usage(stdout, argv[0], 0);
			break;

		default:
			usage(stderr, argv[0], EXIT_FAILURE);
		}
	}

	if (!crc32_poly)
		crc32_poly = crc32_algo->poly;

	if (optind >= argc)
		input_file = "-";
	else
		input_file = argv[optind];

	if (!input_file[0]) {
		err("Input file must not be empty\n");
		return -EINVAL;
	}

	return 0;
}

static int crc32_calc(void)
{
	uint32_t crc_table[CRC32_TABLE_ITEMS];
	bool using_stdin = false;
	uint8_t buf[4096];
	size_t size;
	int ret, i;
	FILE *f;

	if (!strcmp(input_file, "-")) {
		SET_BINARY_MODE(stdin);
		using_stdin = true;
		f = stdin;
	} else {
		f = fopen(input_file, "rb");
	}

	if (!f) {
		err("Failed to open file '%s'\n", input_file);
		return -EINVAL;
	}

	crc32_algo->init(crc_table, crc32_poly);

	if (!no_comp)
		crc32_val ^= 0xffffffff;

	do {
		size = fread(buf, 1, sizeof(buf), f);

		if (size) {
			crc32_val = crc32_algo->calc(crc32_val, buf, size,
						     crc_table);
		}

		if (size < sizeof(buf)) {
			ret = ferror(f);

			if (!ret && feof(f))
				break;

			err("Error while reading file: %d\n", ret);
			break;
		}
	} while (true);

	if (!using_stdin)
		fclose(f);

	if (ret)
		return ret;

	if (!no_comp)
		crc32_val ^= 0xffffffff;

	if (output_decimal)
		printf("%u\n", crc32_val);
	else
		printf("%08x\n", crc32_val);

	return 0;
}

int main(int argc, char *argv[])
{
	if (parse_args(argc, argv))
		return 1;

	return crc32_calc();
}
