/*
 * This software is Copyright (c) 2019 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_zed;
#elif FMT_REGISTERS_H
john_register_one(&fmt_zed);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "loader.h"
#include "options.h"
#include "simd-intrinsics.h"
#include "pkcs12.h"
#include "zed_common.h"

#define FORMAT_LABEL            "zed"
#define FORMAT_NAME             "Prim'X Zed! encrypted archives"
#define ALGORITHM_NAME          "PKCS#12 PBE (SHA1/SHA256) " SHA1_ALGORITHM_NAME

#define PLAINTEXT_LENGTH        48 // Do not bump without a corresponding test vector
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507

#if !defined(SIMD_COEF_32)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#else
#define MIN_KEYS_PER_CRYPT	SIMD_COEF_32
// The below is ideally the LCM of SHA1/SHA256
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA1 * SSE_GROUP_SZ_SHA256 / SIMD_COEF_32
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           1
#endif

static struct custom_salt *cur_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
			sizeof(*crypt_out));

	/* The third test vector only works for UTF-8 as-is */
	if (options.target_enc == CP1252) {
		/* it can also work for CP1252 if modifed */
		zed_tests[2].plaintext = "Op\x80nwal\xa3";
		zed_tests[3].plaintext = "Op\x80nwal\xa3";
	} else if (options.target_enc != UTF_8)
		zed_tests[2].ciphertext = zed_tests[2].plaintext = NULL;
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int index;
	const int count = *pcount;
	int inc = 1;
#if !defined(SIMD_COEF_32)
	int algo = 0;
#endif

	if (cur_salt->algo == 21) {
#if defined(SIMD_COEF_32)
		inc = SSE_GROUP_SZ_SHA1;
#else
		algo = 1;
#endif
	} else if (cur_salt->algo == 22) {
#if defined(SIMD_COEF_32)
		inc = SSE_GROUP_SZ_SHA256;
#else
		algo = 256;
#endif
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += inc) {
#if !defined(SIMD_COEF_32)
		pkcs12_pbe_derive_key(algo, cur_salt->iteration_count,
		                      MBEDTLS_PKCS12_DERIVE_MAC_KEY,
		                      (unsigned char*)saved_key[index],
		                      saved_len[index], cur_salt->salt,
		                      salt_len,
		                      (unsigned char*)crypt_out[index],
		                      BINARY_SIZE);
#else
		int j;

		if (cur_salt->algo == 21) {
			unsigned char *mackey[SSE_GROUP_SZ_SHA1];
			const unsigned char *keys[SSE_GROUP_SZ_SHA1];
			size_t lens[SSE_GROUP_SZ_SHA1];

			for (j = 0; j < SSE_GROUP_SZ_SHA1; j++) {
				mackey[j] = (unsigned char*)(crypt_out[index + j]);
				lens[j] = saved_len[index + j];
				keys[j] = (const unsigned char*)(saved_key[index + j]);
			}
			pkcs12_pbe_derive_key_simd_sha1(cur_salt->iteration_count,
			                           MBEDTLS_PKCS12_DERIVE_MAC_KEY, keys,
			                           lens, cur_salt->salt,
			                           salt_len, mackey,
			                           BINARY_SIZE);
		} else if (cur_salt->algo == 22) {
			unsigned char *mackey[SSE_GROUP_SZ_SHA256];
			const unsigned char *keys[SSE_GROUP_SZ_SHA256];
			size_t lens[SSE_GROUP_SZ_SHA256];

			for (j = 0; j < SSE_GROUP_SZ_SHA256; j++) {
				mackey[j] = (unsigned char*)(crypt_out[index + j]);
				lens[j] = saved_len[index + j];
				keys[j] = (const unsigned char*)(saved_key[index + j]);
			}
			pkcs12_pbe_derive_key_simd_sha256(cur_salt->iteration_count,
			                           MBEDTLS_PKCS12_DERIVE_MAC_KEY, keys,
			                           lens, cur_salt->salt,
			                           salt_len, mackey,
			                           BINARY_SIZE);
		}
#endif
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++) {
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
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

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_zed = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP,
		{
			"iteration count",
			"hash-func [21:SHA1 22:SHA256]",
		},
		{ FORMAT_TAG },
		zed_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		zed_valid,
		fmt_default_split,
		zed_common_get_binary,
		zed_common_get_salt,
		{
			zed_iteration_count,
			zed_get_mac_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		zed_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
