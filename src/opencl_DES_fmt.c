/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_fmt.c in jtr-v1.7.9 
 */

#include <string.h>

#include "arch.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"des-opencl"
#define FORMAT_NAME			"Traditional DES"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		8
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

#include "opencl_DES_bs.h"

#define ALGORITHM_NAME			DES_BS_OPENCL_ALGORITHM_NAME

#define BINARY_SIZE			ARCH_SIZE
#define SALT_SIZE			ARCH_SIZE


static void init(struct fmt_main *pFmt)
{
unsigned int i;
for(i=0;i<MULTIPLIER;i++)
	opencl_DES_bs_init(0, DES_bs_cpt,i);

DES_bs_select_device(platform_id,ocl_gpu_id);
	
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

#if FMT_MAIN_VERSION > 9
static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
#else
static char *split(char *ciphertext, int index)
#endif
{
	static char out[14];

	if (index) {
		memcpy(out, &ciphertext[2], 2);
		memcpy(&out[2], &ciphertext[13], 11);
	} else
		memcpy(out, ciphertext, 13);

	out[13] = 0;
	return out;
}

static void *salt(char *ciphertext)
{
	static WORD out;

	out = opencl_DES_raw_get_salt(ciphertext);

	return &out;
}

static int binary_hash_0(void *binary)
{
	return *(WORD *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(WORD *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(WORD *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(WORD *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(WORD *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(WORD *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(WORD *)binary & 0x7FFFFFF;
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

static void set_salt(void *salt)
{
	opencl_DES_bs_set_salt(*(WORD *)salt);
}

static int cmp_one(void *binary, int index)
{
	return opencl_DES_bs_cmp_one((WORD *)binary, 32, index);
}

static int cmp_exact(char *source, int index)
{
	return opencl_DES_bs_cmp_one(opencl_DES_bs_get_binary(source), 64, index);
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int sector,block;
	unsigned char *src;
	char *dst;
	sector = index/DES_BS_DEPTH;
	block  = index%DES_BS_DEPTH;
	init_t();

	src = opencl_DES_bs_all[sector].pxkeys[block];
	dst = out;
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {
		src += sizeof(DES_bs_vector) * 8;
		dst++;
	}
	*dst = 0;


	return out;
}

struct fmt_main fmt_opencl_DES = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(WORD),
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(WORD),
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_BS,
		tests
	}, {
		init,

		fmt_default_prepare,
		valid,
		split,
		(void *(*)(char *))

			opencl_DES_bs_get_binary,

		salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		set_salt,

		opencl_DES_bs_set_key,

		get_key,
		fmt_default_clear_keys,

		opencl_DES_bs_crypt_25,

		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},

		(int (*)(void *, int))opencl_DES_bs_cmp_all,

		cmp_one,
		cmp_exact
	}
};
