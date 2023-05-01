/*
 * Skein cracker patch for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_skein_256;
extern struct fmt_main fmt_skein_512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_skein_256);
john_register_one(&fmt_skein_512);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sph_skein.h"

// Skein-256 or Skein-512 are the real format labels.
#define FORMAT_LABEL            "Skein"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$skein$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "Skein 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE256          32
#define BINARY_SIZE512          64
#define BINARY_ALIGN            4
#define CMP_SIZE                28 // skein224
#define SALT_SIZE               0
#define SALT_ALIGN              1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      128

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests skein_256_tests[] = {
	{"39CCC4554A8B31853B9DE7A1FE638A24CCE6B35A55F2431009E18780335D2621", ""},
	{"$skein$39CCC4554A8B31853B9DE7A1FE638A24CCE6B35A55F2431009E18780335D2621", ""},
	// john.pot uses lower case
	{"$skein$39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621", ""},
	{"$skein$0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527", "abc"},
	{"$skein$8adf4f8a6fabd34384c661e6c0f91efe9750a18ec6c4d02bcaf05b8246a10dcc", "john"},
	{"$skein$f2bf66b04f3e3e234d59f8126e52ba60baf2b0bca9aff437d87a6cf3675fe41a", "passweird"},
	{NULL}
};

static struct fmt_tests skein_512_tests[] = {
	{"71b7bce6fe6452227b9ced6014249e5bf9a9754c3ad618ccc4e0aae16b316cc8ca698d864307ed3e80b6ef1570812ac5272dc409b5a012df2a579102f340617a", "\xff"},
	{"$skein$BC5B4C50925519C290CC634277AE3D6257212395CBA733BBAD37A4AF0FA06AF41FCA7903D06564FEA7A2D3730DBDB80C1F85562DFCC070334EA4D1D9E72CBA7A", ""},
	// john.pot uses lower case
	{"$skein$bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a", ""},
	{"$skein$8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f93893ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75", "abc"},
	{"$skein$a2f4cbc67def0c97b3b47deeab86e116293db0220ad9953064d40fc4aeabf243d41040efb4e02b4b4883ae19b5c40129926cb5282ad450e1267f126de40224b7", "john"},
	{"$skein$88fcd3b1d6b019c74b8853798b1fa7a1b92314748b79d4a8cf822646104b4aefedb7af721ec07bf1302df031411af55bda48d2177a69537f3e0bfb5d2fb1d656", "passweird"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE512 / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
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
		if (atoi16[ARCH_INDEX(*p++)]==0x7f)
			return 0;
	return 1;
}

static int valid256(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 64);
}
static int valid512(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, 128);
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + BINARY_SIZE512*2 + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	strnzcpylwr(out + TAG_LENGTH, ciphertext, BINARY_SIZE512*2 + 1);
	return out;
}

static void *get_binary_256(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE256];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < BINARY_SIZE256; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *get_binary_512(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE512];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		p = strrchr(ciphertext, '$') + 1;
	else
		p = ciphertext;
	for (i = 0; i < BINARY_SIZE512; i++) {
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
		sph_skein256_context ctx;

		sph_skein256_init(&ctx);
		sph_skein256(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_skein256_close(&ctx, (unsigned char*)crypt_out[index]);
	}

	return count;
}

static int crypt_512(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		sph_skein512_context ctx;

		sph_skein512_init(&ctx);
		sph_skein512(&ctx, saved_key[index], strlen(saved_key[index]));
		sph_skein512_close(&ctx, (unsigned char*)crypt_out[index]);
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

static void skein_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_skein_256 = {
	{
		"skein-256",
		"Skein 256",
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE256,
		BINARY_ALIGN,
		SALT_SIZE,
		BINARY_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD |
		FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		skein_256_tests
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
		skein_set_key,
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

struct fmt_main fmt_skein_512 = {
	{
		"skein-512",
		"Skein 512",
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE512,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD |
		FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{ FORMAT_TAG },
		skein_512_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid512,
		split,
		get_binary_512,
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
		skein_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_512,
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
