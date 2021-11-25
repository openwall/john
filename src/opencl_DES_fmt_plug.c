/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_fmt.c in jtr-v1.7.9
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_DES;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_DES);
#else

#include <string.h>
#include <stdlib.h>

#include "arch.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "opencl_DES_bs.h"
#include "../run/opencl/opencl_DES_hst_dev_shared.h"
#include "logger.h"

#define FORMAT_NAME			"traditional crypt(3)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define CIPHERTEXT_LENGTH_1		13
#define CIPHERTEXT_LENGTH_2		24

static struct fmt_tests tests[] = {
	{"CCNf8Sbh3HDfQ", "U*U*U*U*"},
	{"CCX.K.MFy4Ois", "U*U***U"},
	{"CC4rMpbg9AMZ.", "U*U***U*"},
	{"XXxzOu6maQKqQ", "*U*U*U*U"},
	{"SDbsugeBiC58A", ""},
	{"..X8NBuQ4l6uQ", ""},
	{NULL}
};

#define ALGORITHM_NAME			DES_BS_OPENCL_ALGORITHM_NAME

#define BINARY_SIZE			(2 * sizeof(WORD))
#define SALT_SIZE			sizeof(WORD)

#define USE_FULL_UNROLL 		(amd_gcn(device_info[gpu_id]) || nvidia_sm_5plus(device_info[gpu_id]))
#define USE_BASIC_KERNEL		(cpu(device_info[gpu_id]) || platform_apple(platform_id))

void (*opencl_DES_bs_init_global_variables)(void);
void (*opencl_DES_bs_select_device)(struct fmt_main *);

static  unsigned char DES_IP[64] = {
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
	56, 48, 40, 32, 24, 16, 8, 0,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6
};

static unsigned char DES_atoi64[0x100] = {
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
	34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
	50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1,
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 5, 6, 7, 8, 9, 10,
	11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
	27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 32, 33, 34, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
	53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1, 2, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
	53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1, 2, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
	37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
	53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1, 2, 3, 4
};

static void init(struct fmt_main *pFmt)
{
	char *force_kernel = getenv("JOHN_DES_KERNEL");

	opencl_prepare_dev(gpu_id);

	if (force_kernel && !strcmp(force_kernel, "bs_b")) {
		fprintf(stderr, "Using basic kernel (bs_b)\n");
		opencl_DES_bs_b_register_functions(pFmt);
	} else if (force_kernel && !strcmp(force_kernel, "bs_f")) {
		fprintf(stderr, "Using fully unrolled, salt-specific kernels (bs_f)\n");
		opencl_DES_bs_f_register_functions(pFmt);
	} else if (force_kernel && !strcmp(force_kernel, "bs_h")) {
		fprintf(stderr, "Using salt-specific kernels (bs_h)\n");
		opencl_DES_bs_h_register_functions(pFmt);
	} else if ((USE_BASIC_KERNEL && !OVERRIDE_AUTO_CONFIG) ||
	    (OVERRIDE_AUTO_CONFIG && !HARDCODE_SALT && !FULL_UNROLL)) {
		log_event("- Using basic kernel (bs_b)");
		opencl_DES_bs_b_register_functions(pFmt);
	} else if ((USE_FULL_UNROLL && !OVERRIDE_AUTO_CONFIG) ||
	           (OVERRIDE_AUTO_CONFIG && HARDCODE_SALT && FULL_UNROLL)) {
		log_event("- Using fully unrolled and salt-specific kernels (bs_f)");
		opencl_DES_bs_f_register_functions(pFmt);
	} else {
		log_event("- Using salt-specific kernels (bs_h)");
		opencl_DES_bs_h_register_functions(pFmt);
	}

	// Check if specific LWS/GWS was requested
	opencl_get_user_preferences(FORMAT_LABEL);

	opencl_DES_bs_init_global_variables();

	if (local_work_size & (local_work_size - 1)) {
		if (local_work_size < 4) local_work_size = 4;
		else if (local_work_size < 8) local_work_size = 8;
		else if (local_work_size < 16) local_work_size = 16;
		else if (local_work_size < 32) local_work_size = 32;
		else local_work_size = 64;
	}
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos;

	if (!ciphertext[0] || !ciphertext[1]) return 0;

	for (pos = &ciphertext[2]; atoi64[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos && *pos != ',') return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 3) return 0;

	switch (pos - ciphertext) {
	case CIPHERTEXT_LENGTH_1:
		return 1;

	case CIPHERTEXT_LENGTH_2:
		if (atoi64[ARCH_INDEX(ciphertext[12])] & 3) return 0;
		return 2;

	default:
		return 0;
	}
}

static WORD *do_IP(WORD in[2])
{
	static WORD out[2];
	int src, dst;

	out[0] = out[1] = 0;
	for (dst = 0; dst < 64; dst++) {
		src = DES_IP[dst ^ 0x20];

		if (in[src >> 5] & (1 << (src & 0x1F)))
			out[dst >> 5] |= 1 << (dst & 0x1F);
	}

	return out;
}

static WORD *raw_get_binary(char *ciphertext)
{
	WORD block[3];
	WORD mask;
	int ofs, chr, src, dst, value;

	if (ciphertext[13]) ofs = 9; else ofs = 2;

	block[0] = block[1] = 0;
	dst = 0;
	for (chr = 0; chr < 11; chr++) {
		value = DES_atoi64[ARCH_INDEX(ciphertext[chr + ofs])];
		mask = 0x20;

		for (src = 0; src < 6; src++) {
			if (value & mask)
				block[dst >> 5] |= 1 << (dst & 0x1F);
			mask >>= 1;
			dst++;
		}
	}

	return do_IP(block);
}

static WORD *get_binary_raw(WORD *raw, int count)
{
	static WORD out[2];

/* For odd iteration counts, swap L and R here instead of doing it one
 * more time in DES_bs_crypt(). */
	count &= 1;
	out[count] = raw[0];
	out[count ^ 1] = raw[1];

	return out;
}


static WORD raw_get_count(char *ciphertext)
{
	if (ciphertext[13]) return DES_atoi64[ARCH_INDEX(ciphertext[1])] |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[2])] << 6) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[3])] << 12) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[4])] << 18);
	else return 25;
}

static WORD *get_binary(char *ciphertext)
{
	return get_binary_raw(
		raw_get_binary(ciphertext),
		raw_get_count(ciphertext));
}

static WORD raw_get_salt(char *ciphertext)
{
	if (ciphertext[13]) return DES_atoi64[ARCH_INDEX(ciphertext[5])] |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[6])] << 6) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[7])] << 12) |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[8])] << 18);
	else return DES_atoi64[ARCH_INDEX(ciphertext[0])] |
		((WORD)DES_atoi64[ARCH_INDEX(ciphertext[1])] << 6);
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[14];

	if (index) {
		memcpy(out, &ciphertext[2], 2);
		memcpy(&out[2], &ciphertext[13], 11);
	} else
		memcpy(out, ciphertext, 13);
	out[13] = 0;

/* Replace potential invalid salts with their valid counterparts */
	unsigned int salt = raw_get_salt(out);
	out[0] = itoa64[salt & 0x3f];
	out[1] = itoa64[salt >> 6];

	return out;
}

static void *get_salt(char *ciphertext)
{
	static WORD out;

	out = raw_get_salt(ciphertext);

	return &out;
}

#define get_hash_0 opencl_DES_bs_get_hash_0
#define get_hash_1 opencl_DES_bs_get_hash_1
#define get_hash_2 opencl_DES_bs_get_hash_2
#define get_hash_3 opencl_DES_bs_get_hash_3
#define get_hash_4 opencl_DES_bs_get_hash_4
#define get_hash_5 opencl_DES_bs_get_hash_5
#define get_hash_6 opencl_DES_bs_get_hash_6

static int salt_hash(void *salt)
{
	return *(WORD *)salt & (SALT_HASH_SIZE - 1);
}

static int cmp_all(WORD *binary, int count)
{
	return 1;
}

struct fmt_main fmt_opencl_DES = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		sizeof(WORD),
		SALT_SIZE,
		sizeof(WORD),
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_TRUNC | FMT_BS | FMT_REMOVE | FMT_MASK,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		NULL,
		NULL,
		fmt_default_prepare,
		valid,
		split,
		(void *(*)(char *))

			get_binary,

		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		NULL,
		opencl_DES_bs_set_key,
		opencl_DES_bs_get_key,
		opencl_DES_bs_clear_keys,
		NULL,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},

		(int (*)(void *, int))cmp_all,

		opencl_DES_bs_cmp_one,
		opencl_DES_bs_cmp_exact
	}
};
#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
