/*
 * JtR format to crack iWork '09, and '13 / '14 files.
 *
 * This software is Copyright (c) 2015, Dhiru Kholia <kholia at kth.se> and
 * Maxime Hulliger <hulliger at kth.se>, and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This code may be freely used and modified for any purpose.
 *
 * Big thanks to Sean Patrick O'Brien for making this format possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_iwork;
#elif FMT_REGISTERS_H
john_register_one(&fmt_iwork);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "jumbo.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "iwork_common.h"
#include "pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL            "iwork"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*fctx)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)

#ifndef OMP_SCALE
#define OMP_SCALE               4
#endif

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;
static struct format_context *fctx;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	fctx = (struct format_context *)salt;
}

static void iwork_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int iwork_decrypt(struct format_context *fctx, unsigned char *key, unsigned char *iv, unsigned char *data)
{
	unsigned char out[BLOBLEN];
	unsigned char ivec[IVLEN];
	uint8_t hash[32];
	SHA256_CTX ctx;
	AES_KEY aes_decrypt_key;

	AES_set_decrypt_key(key, 128, &aes_decrypt_key);
	memcpy(ivec, iv, 16);
	AES_cbc_encrypt(fctx->blob, out, BLOBLEN, &aes_decrypt_key, ivec, AES_DECRYPT);

	// The last 32 bytes should be equal to the SHA256 of the first 32 bytes (IWPasswordVerifier.m)
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, out, 32);
	SHA256_Final(hash, &ctx);

	return memcmp(hash, &out[32], 32) == 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char master[MIN_KEYS_PER_CRYPT][16];
		int i;
#ifdef SIMD_COEF_32
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char**)pin, lens, fctx->salt, fctx->salt_length, fctx->iterations, pout, 16, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha1((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]), fctx->salt, fctx->salt_length, fctx->iterations, master[i], 16, 0);
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			cracked[index+i] = iwork_decrypt(fctx, master[i], fctx->iv, fctx->blob);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_iwork = {
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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		iwork_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		iwork_common_valid,
		fmt_default_split,
		fmt_default_binary,
		iwork_common_get_salt,
		{
			iwork_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		iwork_set_key,
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
