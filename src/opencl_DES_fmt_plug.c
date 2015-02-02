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

#include "arch.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "opencl_DES_bs.h"
#include "memdbg.h"

#define FORMAT_LABEL			"descrypt-opencl"
#define FORMAT_NAME			"traditional crypt(3)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

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

static void done()
{
	DES_opencl_clean_all_buffer();
}

static void init(struct fmt_main *pFmt)
{
	unsigned int i;

	// Check if specific LWS/GWS was requested
	opencl_get_user_preferences(FORMAT_LABEL);

	opencl_DES_bs_init_global_variables();

	for(i=0;i<MULTIPLIER;i++)
		opencl_DES_bs_init(0, DES_bs_cpt,i);

	DES_bs_select_device(pFmt);
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

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
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

static int cmp_exact(char *source, int index)
{
	return opencl_DES_bs_cmp_one_b(opencl_DES_bs_get_binary(source), 64, index);
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
		FMT_CASE | FMT_BS,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		opencl_DES_reset,
		fmt_default_prepare,
		valid,
		split,
		(void *(*)(char *))

			opencl_DES_bs_get_binary,

		salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		set_salt,
		opencl_DES_bs_set_key,
		opencl_DES_bs_get_key,
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

		opencl_DES_bs_cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
