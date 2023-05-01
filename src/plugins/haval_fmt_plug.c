/*
 * HAVAL cracker patch for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_haval_256_3;
extern struct fmt_main fmt_haval_128_4;
#elif FMT_REGISTERS_H
john_register_one(&fmt_haval_256_3);
john_register_one(&fmt_haval_128_4);
#else

#include <string.h>

#include "arch.h"
#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif

#ifdef _OPENMP
#include <omp.h>
#endif // _OPENMP

#include "arch.h"
#include "sph_haval.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define FORMAT_TAG		"$haval$"
#define TAG_LENGTH		(sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE256		32
#define BINARY_SIZE128		16
#define SALT_SIZE		0
#define BINARY_ALIGN		4
#define SALT_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64

#ifndef OMP_SCALE
#ifdef __MIC__
#define OMP_SCALE  4
#else
#define OMP_SCALE  16
#endif // __MIC__
#endif // OMP_SCALE

static struct fmt_tests haval_256_3_tests[] = {
	{"91850C6487C9829E791FC5B58E98E372F3063256BB7D313A93F1F83B426AEDCC", "HAVAL"},
	{"$haval$91850C6487C9829E791FC5B58E98E372F3063256BB7D313A93F1F83B426AEDCC", "HAVAL"},
	// john.pot uses lower case hex, so repeat that hash with lower case hex
	{"$haval$91850c6487c9829e791fc5b58e98e372f3063256bb7d313a93f1f83b426aedcc", "HAVAL"},
	{"8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c", "abc"},
	{"$haval$8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c", "abc"},
	{"cd43bec91c50e5f781fc50a78a3e9c8c48b407fa35a20c972178d63867dbe158", "john"},
	{"$haval$cd43bec91c50e5f781fc50a78a3e9c8c48b407fa35a20c972178d63867dbe158", "john"},
	{"5aa9c913463f82260071629c8ac2c54d73b3af016ffd8e8ce128558d909fab06", "passweird"},
	{"$haval$5aa9c913463f82260071629c8ac2c54d73b3af016ffd8e8ce128558d909fab06", "passweird"},
	{NULL}
};

static struct fmt_tests haval_128_4_tests[] = {
	{"EE6BBF4D6A46A679B3A856C88538BB98", ""},
	{"$haval$ee6bbf4d6a46a679b3a856c88538bb98", ""},
	{"6f2132867c9648419adcd5013e532fa2", "abc"},
	{"$haval$6f2132867c9648419adcd5013e532fa2", "abc"},
	{"c98232b4ae6e7ef3235e838387111f23", "john"},
	{"$haval$c98232b4ae6e7ef3235e838387111f23", "john"},
	{"50683b38df349781b2ef29e7720eb730", "passweird"},
	{"$haval$50683b38df349781b2ef29e7720eb730", "passweird"},
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

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	if (strnlen(p, len + 1) != len)
		return 0;

	while(*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
			return 0;
	return 1;
}

/*
 * We need independent valids, since the $haval$ signature is the same.
 * Otherwise, if we have input with a mix of both types, then ALL of them
 * will validate, even though only the ones of the proper type will actually be
 * tested. If we had a singleton crypt function (which both 128-4 and
 * 256-3 used, then a single valid would also work. But since each have
 * their own crypt, and they are NOT compatible, then we need separate valids.
 */
static int valid3(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 64);
}

static int valid4(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 32);
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

static int crypt_256_3(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		sph_haval256_3_context ctx;

		sph_haval256_3_init(&ctx);
		sph_haval256_3(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_haval256_3_close(&ctx, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int crypt_128_4(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		sph_haval128_4_context ctx;

		sph_haval128_4_init(&ctx);
		sph_haval128_4(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_haval128_4_close(&ctx, (unsigned char*)crypt_out[index]);
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

static int cmp_one256(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE256);
}

static int cmp_one128(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE128);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void haval_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + 2 * BINARY_SIZE256 + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	strcpy(out, FORMAT_TAG);
	strcpy(&out[TAG_LENGTH], ciphertext);
	strlwr(&out[TAG_LENGTH]);

	return out;
}

struct fmt_main fmt_haval_256_3 = {
	{
		"HAVAL-256-3",
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		haval_256_3_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid3,
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
		haval_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_256_3,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one256,
		cmp_exact
	}
};


struct fmt_main fmt_haval_128_4 = {
	{
		"HAVAL-128-4",
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ NULL },
		haval_128_4_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid4,
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
		haval_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_128_4,
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
