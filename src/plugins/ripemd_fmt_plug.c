/* ripemd cracker patch for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ripemd_160;
extern struct fmt_main fmt_ripemd_128;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ripemd_160);
john_register_one(&fmt_ripemd_128);
#else

#include <string.h>

#include "arch.h"
#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "sph_ripemd.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#ifndef OMP_SCALE
#ifdef __MIC__
#define OMP_SCALE  1
#else
#define OMP_SCALE  32 // tuned w/ MKPC for core i7
#endif
#endif

#define FORMAT_TAG		"$ripemd$"
#define TAG_LENGTH		(sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE160		20
#define BINARY_SIZE128		16
#define SALT_SIZE		0
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64
#define BINARY_ALIGN		4
#define SALT_ALIGN		1

static struct fmt_tests ripemd_160_tests[] = {
	{"9c1185a5c5e9fc54612808977ee8f548b2258d31", ""},
	{"$ripemd$9c1185a5c5e9fc54612808977ee8f548b2258d31", ""},
	{"56e11fdd5479b30020fc010551536af074e1b82f", "thisisalongstring"},
	{"$ripemd$56e11fdd5479b30020fc010551536af074e1b82f", "thisisalongstring"},
	{"a1a94e392ce7d861a4fdcaa291e453c082807f50", "string with space"},
	{"$ripemd$a1a94e392ce7d861a4fdcaa291e453c082807f50", "string with space"},
	{"98f3860a474d986964df9c1fd3621e68eaf76a25", "UPPERCASE"},
	{"$ripemd$98f3860a474d986964df9c1fd3621e68eaf76a25", "UPPERCASE"},
	{"d3d0379126c1e5e0ba70ad6e5e53ff6aeab9f4fa", "123456789"},
	{"$ripemd$d3d0379126c1e5e0ba70ad6e5e53ff6aeab9f4fa", "123456789"},
	{NULL}
};

static struct fmt_tests ripemd_128_tests[] = {
	{"cdf26213a150dc3ecb610f18f6b38b46", ""},
	{"$ripemd$cdf26213a150dc3ecb610f18f6b38b46", ""},
	{"060d8817be332f6e6a9a09a209ea453e", "thisisalongstring"},
	{"$ripemd$060d8817be332f6e6a9a09a209ea453e", "thisisalongstring"},
	{"ed402bdf044344c34935ac93a2d90a13", "string with space"},
	{"$ripemd$ed402bdf044344c34935ac93a2d90a13", "string with space"},
	{"5e71f949a0d5c69f3c1aeaf245ba527a", "UPPERCASE"},
	{"$ripemd$5e71f949a0d5c69f3c1aeaf245ba527a", "UPPERCASE"},
	{"1886db8acdcbfeab1e7ee3780400536f", "123456789"},
	{"$ripemd$1886db8acdcbfeab1e7ee3780400536f", "123456789"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE160 / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	if (!saved_key) {
		saved_key = mem_calloc(self->params.max_keys_per_crypt,
		                       sizeof(*saved_key));
		crypt_out = mem_calloc(self->params.max_keys_per_crypt,
		                       sizeof(*crypt_out));
	}
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self, int len)
{
	char *p;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	if (strlen(p) != len)
		return 0;

	while(*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
			return 0;

	return 1;
}

static int valid160(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 40);
}
static int valid128(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 32);
}

static void *get_binary_160(char *ciphertext)
{
	static union {
		unsigned char c[20];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < 20; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *get_binary_128(char *ciphertext)
{
	static union {
		unsigned char c[16];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < 16; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int crypt_160(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		sph_ripemd160_context ctx;

		sph_ripemd160_init(&ctx);
		sph_ripemd160(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_ripemd160_close(&ctx, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int crypt_128(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		sph_ripemd128_context ctx;

		sph_ripemd128_init(&ctx);
		sph_ripemd128(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_ripemd128_close(&ctx, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one128(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE128);
}

static int cmp_one160(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE160);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void ripemd_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + 2 * BINARY_SIZE160 + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	strcpy(out, FORMAT_TAG);
	strcpy(&out[TAG_LENGTH], ciphertext);
	strlwr(&out[TAG_LENGTH]);

	return out;
}

struct fmt_main fmt_ripemd_160 = {
	{
		"ripemd-160",
		"RIPEMD 160",
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE160,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		ripemd_160_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid160,
		split,
		get_binary_160,
		fmt_default_salt,
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		ripemd_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_160,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one160,
		cmp_exact
	}
};


struct fmt_main fmt_ripemd_128 = {
	{
		"ripemd-128",
		"RIPEMD 128",
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE128,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		ripemd_128_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid128,
		split,
		get_binary_128,
		fmt_default_salt,
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		ripemd_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_128,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one128,
		cmp_exact
	}
};

#endif /* plugin stanza */
