/*
 * This software is Copyright (c) 2026 Dhiru Kholia and it is hereby released
 * to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Algorithm:
 *   digest = SHA256(salt || password)
 *   repeat N times: digest = SHA256(digest)
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_iterated_sha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_iterated_sha256);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "johnswap.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "sha2.h"
#include "iterated_sha256_common.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "Iterated-SHA256"
#define ALGORITHM_NAME          "SHA256 ($s.$p) " SHA256_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS                  (SIMD_COEF_32 * SIMD_PARA_SHA256)
#define FMT_IS_BE
#include "common-simd-getpos.h"
#define MIN_KEYS_PER_CRYPT      NBKEYS
#define MAX_KEYS_PER_CRYPT      (NBKEYS * 512)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      16
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               256
#endif

static salt_t *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);

#ifdef SIMD_COEF_32
static uint32_t(*simd_keybuf)[SHA_BUF_SIZ * NBKEYS];
static uint32_t(*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
#else
static uint32_t(*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
#ifdef SIMD_COEF_32
	simd_keybuf = mem_calloc_align(self->params.max_keys_per_crypt / NBKEYS,
	                               sizeof(*simd_keybuf), MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*crypt_out), MEM_ALIGN_SIMD);
#else
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
#ifdef SIMD_COEF_32
	MEM_FREE(simd_keybuf);
#endif
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
	uint32_t b0 = *(uint32_t *) binary;
	int i;

	for (i = 0; i < count; i++) {
		if (b0 != crypt_out[i][0])
			continue;
		if (!memcmp(binary, crypt_out[i], BINARY_SIZE))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef SIMD_COEF_32
	int simd_count = count / NBKEYS * NBKEYS;

#ifdef _OPENMP
	#pragma omp parallel for
#endif
	for (index = 0; index < simd_count; index += NBKEYS) {
		SHA256_CTX ctx;
		unsigned char digest[BINARY_SIZE];
		unsigned char *keys;
		uint32_t *keys32;
		int iter, i, j;

		iter = cur_salt->iter;
		keys = (unsigned char *)simd_keybuf[index / NBKEYS];
		keys32 = (uint32_t *) keys;
		memset(keys, 0, 64 * NBKEYS);

		for (i = 0; i < NBKEYS; i++) {
			int idx = index + i;

			SHA256_Init(&ctx);
			SHA256_Update(&ctx, (unsigned char *)cur_salt->salt,
			              cur_salt->len);
			SHA256_Update(&ctx, saved_key[idx], saved_len[idx]);
			SHA256_Final(digest, &ctx);

			if (iter == 1) {
				memcpy(crypt_out[idx], digest, BINARY_SIZE);
				continue;
			}

			for (j = 0; j < 32; j++)
				keys[GETPOS(j, i)] = digest[j];
			keys[GETPOS(j, i)] = 0x80;
			keys[GETPOS(62, i)] = 0x01;
		}

		if (iter > 1) {
			int remaining = iter - 1;
			uint32_t *out = (uint32_t *) crypt_out[index];

			if (remaining == 1) {
				SIMDSHA256body(keys32, out, NULL,
				               SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT | SSEi_FLAT_OUT);
			} else {
				for (i = 0; i < remaining - 1; i++)
					SIMDSHA256body(keys32, keys32, NULL,
					               SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT);
				SIMDSHA256body(keys32, out, NULL,
				               SSEi_MIXED_IN | SSEi_OUTPUT_AS_INP_FMT | SSEi_FLAT_OUT);
			}
		}
	}

	for (index = simd_count; index < count; index++) {
		SHA256_CTX ctx;
		unsigned char digest[BINARY_SIZE];
		int iter;

		iter = cur_salt->iter;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (unsigned char *)cur_salt->salt, cur_salt->len);
		SHA256_Update(&ctx, saved_key[index], saved_len[index]);
		SHA256_Final(digest, &ctx);

		while (--iter) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, digest, BINARY_SIZE);
			SHA256_Final(digest, &ctx);
		}

		memcpy(crypt_out[index], digest, BINARY_SIZE);
	}
#else
#ifdef _OPENMP
	#pragma omp parallel for default(none) private(index) shared(count, saved_key, saved_len, crypt_out, cur_salt)
#endif
	for (index = 0; index < count; index++) {
		SHA256_CTX ctx;
		unsigned char digest[BINARY_SIZE];
		int iter;

		iter = cur_salt->iter;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (unsigned char *)cur_salt->salt, cur_salt->len);
		SHA256_Update(&ctx, saved_key[index], saved_len[index]);
		SHA256_Final(digest, &ctx);

		while (--iter) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, digest, BINARY_SIZE);
			SHA256_Final(digest, &ctx);
		}

		memcpy(crypt_out[index], digest, BINARY_SIZE);
	}
#endif

	return count;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

struct fmt_main fmt_iterated_sha256 = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ "iterations"},
		{
			FORMAT_TAG,
			""
		},
		iterated_sha256_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		iterated_sha256_valid,
		fmt_default_split,
		iterated_sha256_get_binary,
		iterated_sha256_get_salt,
		{
			iterated_sha256_iterations
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
		iterated_sha256_salt_hash,
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

#endif
