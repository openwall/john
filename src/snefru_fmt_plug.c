/* Snefru cracker patch for JtR. Hacked together during May of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_snefru_256;
extern struct fmt_main fmt_snefru_128;
#elif FMT_REGISTERS_H
john_register_one(&fmt_snefru_256);
john_register_one(&fmt_snefru_128);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "snefru.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

// Snefru-128 and Snefru-256 are the real format labels
#define FORMAT_LABEL		"Snefru"
#define FORMAT_TAG		"$snefru$"
#define TAG_LENGTH		(sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE128		16
#define BINARY_SIZE256		32
#define BINARY_ALIGN		4
#define CMP_SIZE		16
#define SALT_SIZE		0
#define SALT_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	32

#ifndef OMP_SCALE
#define OMP_SCALE  16 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests snefru_128_tests[] = {
	{"53b8a9b1c9ed00174d88d705fb7bae30", "mystrongpassword"},
	{"$snefru$53b8a9b1c9ed00174d88d705fb7bae30", "mystrongpassword"},
	{NULL}
};

static struct fmt_tests snefru_256_tests[] = {
	{"$snefru$4170e04e900e6221562ceb5ff6ea27fa9b9b0d9587add44a4379a02619c5a106", "mystrongpassword"},
	{"4170e04e900e6221562ceb5ff6ea27fa9b9b0d9587add44a4379a02619c5a106", "mystrongpassword"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE256 / sizeof(uint32_t)];

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
	int extra;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	if (hexlenl(p, &extra) != len || extra)
		return 0;

	return 1;
}

static int valid256(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 64);
}

static int valid128(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 32);
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + BINARY_SIZE256 * 2 + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	strnzcpy(out + TAG_LENGTH, ciphertext, BINARY_SIZE256 * 2 + 1);
	return out;
}

static void *get_binary_256(char *ciphertext)
{
	static union {
		unsigned char c[32];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < 32; i++) {
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

static int crypt_256(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		snefru_ctx ctx;;

		rhash_snefru256_init(&ctx);
		rhash_snefru_update(&ctx, (unsigned char*)saved_key[index], strlen(saved_key[index]));
		rhash_snefru_final(&ctx, (unsigned char*)crypt_out[index]);
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
		snefru_ctx ctx;;

		rhash_snefru128_init(&ctx);
		rhash_snefru_update(&ctx, (unsigned char*)saved_key[index], strlen(saved_key[index]));
		rhash_snefru_final(&ctx, (unsigned char*)crypt_out[index]);

	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], CMP_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], CMP_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void snefru_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_snefru_256 = {
	{
		"Snefru-256",
		"",
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE256,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		snefru_256_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid256,
		split,
		get_binary_256,
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
		snefru_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_256,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};


struct fmt_main fmt_snefru_128 = {
	{
		"Snefru-128",
		"",
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		snefru_128_tests
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
		snefru_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_128,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
