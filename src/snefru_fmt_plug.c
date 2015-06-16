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
#include "arch.h"
#include "snefru.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
// OMP_SCALE tuned on core i7 quad core HT
//        128kb   256kb
// 1   -  214k    215k
// 64  - 1435k   1411k
// 128 - 1474k   1902k *** this was chosen
// 256 - 1508k   1511k
// 512 - 1649k   1564k
#ifndef OMP_SCALE
#define OMP_SCALE  128
#endif
#endif

#include "memdbg.h"

// Snefru-128 and Snefru-256 are the real format labels
#define FORMAT_LABEL		"Snefru"
#define FORMAT_TAG		"$snefru$"
#define TAG_LENGTH		8
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE128		16
#define BINARY_SIZE256		32
#define CMP_SIZE		16
#define SALT_SIZE		0
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BINARY_ALIGN		4
#define SALT_ALIGN		1

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
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE256 / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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
		if(atoi16[ARCH_INDEX(*p++)]==0x7f)
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

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static int crypt_256(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
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
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		snefru_ctx ctx;;

		rhash_snefru128_init(&ctx);
		rhash_snefru_update(&ctx, (unsigned char*)saved_key[index], strlen(saved_key[index]));
		rhash_snefru_final(&ctx, (unsigned char*)crypt_out[index]);

	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
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
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static char *prepare(char *fields[10], struct fmt_main *self) {
	static char buf[64+TAG_LENGTH+1];
	char *hash = fields[1];
	int len = strlen(hash);
	if ( (len == 64 || len == 32) && valid(hash, self, len) ) {
		sprintf(buf, "%s%s", FORMAT_TAG, hash);
		return buf;
	}
	return hash;
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		snefru_256_tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid256,
		fmt_default_split,
		get_binary_256,
		fmt_default_salt,
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		snefru_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_256,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		snefru_128_tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid128,
		fmt_default_split,
		get_binary_128,
		fmt_default_salt,
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		snefru_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_128,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
