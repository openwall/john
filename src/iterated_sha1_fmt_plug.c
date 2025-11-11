/*
 * Copyright (c) 2025, magnum
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define FMT_STRUCT fmt_sha1_iterated

#if FMT_EXTERNS_H
extern struct fmt_main FMT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FMT_STRUCT);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "options.h"
#include "johnswap.h"
#include "iterated_sha1_common.h"
#include "simd-intrinsics.h"
#include "common.h"
#include "sha.h"
#include "base64_convert.h"

#define FORMAT_LABEL        "Iterated-SHA1"
#define ALGORITHM_NAME      "SHA1 ($s.$p) " SHA1_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS              (SIMD_COEF_32 * SIMD_PARA_SHA1)
#define FMT_IS_BE
#include "common-simd-getpos.h"
#define MIN_KEYS_PER_CRYPT  NBKEYS
#define MAX_KEYS_PER_CRYPT  (NBKEYS * 512)
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  512
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           1
#endif

static salt_t *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
#ifdef SIMD_COEF_32
static uint32_t (*simd_keybuf)[SHA_BUF_SIZ * NBKEYS];
static uint32_t (*crypt_key)[BINARY_SIZE / 4 * NBKEYS];
static unsigned int *saved_len;
#else
static uint32_t (*crypt_key)[BINARY_SIZE / 4];
static unsigned int *saved_len;
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
#ifdef SIMD_COEF_32
	simd_keybuf = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                               sizeof(*simd_keybuf), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
#else
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#endif
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
#ifdef SIMD_COEF_32
	MEM_FREE(simd_keybuf);
#endif
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	return strnzcpy(out, saved_key[index], saved_len[index] + 1);
}

static void set_salt(void *salt) {
	cur_salt = salt;
}

#ifdef SIMD_COEF_32
static inline void salt_keys2vector(int base)
{
	for (unsigned int idx = 0; idx < NBKEYS; idx++) {
		unsigned int index = base + idx;
		unsigned int i;
		unsigned char *sk = (unsigned char*)&simd_keybuf[index / NBKEYS];
		uint8_t *salt = (uint8_t*)cur_salt->salt;
		char *key = saved_key[index];

		for (i = 0; i < cur_salt->len; ++i)
			sk[GETPOS(i, idx)] = *salt++;
		for (; i < cur_salt->len + saved_len[index]; ++i)
			sk[GETPOS(i, idx)] = *key++;
		sk[GETPOS(i, idx)] = 0x80;
		while (++i < 56)
			sk[GETPOS(i, idx)] = 0;

		simd_keybuf[index / NBKEYS][15 * SIMD_COEF_32 + (index & (SIMD_COEF_32 - 1)) + idx / SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32] = (cur_salt->len + saved_len[index]) << 3;
	}
}

static inline void out2in(int base)
{
	for (unsigned int idx = 0; idx < NBKEYS; idx++) {
		unsigned int index = base + idx;

		simd_keybuf[index / NBKEYS][5 * SIMD_COEF_32 + (index & (SIMD_COEF_32 - 1)) + idx / SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32] = 0x80000000;

		simd_keybuf[index / NBKEYS][15 * SIMD_COEF_32 + (index & (SIMD_COEF_32 - 1)) + idx / SIMD_COEF_32 * SHA_BUF_SIZ * SIMD_COEF_32] = 20 << 3;
	}
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	int inc = 1;

#ifdef SIMD_COEF_32
	inc = NBKEYS;
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += inc) {
		int iter = cur_salt->iter;
#ifdef SIMD_COEF_32

		salt_keys2vector(index);

		while (--iter) {
			SIMDSHA1body(simd_keybuf[index / NBKEYS], simd_keybuf[index / NBKEYS], NULL, SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT);
			out2in(index);
		}
		SIMDSHA1body(simd_keybuf[index / NBKEYS], crypt_key[index / NBKEYS], NULL, SSEi_MIXED_IN);
#else
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char*)cur_salt->salt, cur_salt->len);
		SHA1_Update(&ctx, (unsigned char*)saved_key[index], saved_len[index]);
		SHA1_Final((unsigned char*)crypt_key[index], &ctx);
		while (--iter) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, (unsigned char*)crypt_key[index], 20);
			SHA1_Final((unsigned char*)crypt_key[index], &ctx);
		}
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count) {
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
		if (((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[(index & (SIMD_COEF_32 - 1)) + index / SIMD_COEF_32 * 5 * SIMD_COEF_32])
#else
		if (((uint32_t*)binary)[0] == ((uint32_t*)&(crypt_key[index][0]))[0])
#endif
			return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
	int i;

	for (i = 0; i < BINARY_SIZE / sizeof(uint32_t); i++)
		if (((uint32_t*)binary)[i] != ((uint32_t*)crypt_key)[(index & (SIMD_COEF_32 - 1)) + (unsigned int)index / SIMD_COEF_32 * 5 * SIMD_COEF_32 + i * SIMD_COEF_32])
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

#define COMMON_GET_HASH_SIMD32 5
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main FMT_STRUCT = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ "iterations" },
		{ FORMAT_TAG },
		iterated_sha1_tests
	}, {
		init,
		done,
		fmt_default_reset,
		iterated_sha1_prepare,
		iterated_sha1_valid,
		fmt_default_split,
		iterated_sha1_get_binary,
		iterated_sha1_get_salt,
		{
			iterated_sha1_iterations
		},
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
		iterated_sha1_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
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
