/*
 * JtR format to crack password protected Ethereum Wallets.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ethereum;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ethereum);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "pbkdf2_hmac_sha256.h"
#include "ethereum_common.h"
#include "escrypt/crypto_scrypt.h"
#include "KeccakHash.h"
#include "jumbo.h"
#include "memdbg.h"

#define FORMAT_NAME             "Ethereum Wallet"
#define FORMAT_LABEL            "ethereum"
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA256/scrypt Keccak " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256/scrypt Keccak 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             32
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

custom_salt  *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (custom_salt *)salt;
}

static void ethereum_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int i;
		if (cur_salt->type == 0) {
#ifdef SIMD_COEF_64
			int lens[MAX_KEYS_PER_CRYPT];
			unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
				lens[i] = strlen(saved_key[index+i]);
				pin[i] = (unsigned char*)saved_key[index+i];
				pout[i] = master[i];
			}
			pbkdf2_sha256_sse((const unsigned char**)pin, lens, cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, pout, 32, 0);
#else
			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
				pbkdf2_sha256((unsigned char *)saved_key[index+i],
						strlen(saved_key[index+i]),
						cur_salt->salt, cur_salt->saltlen,
						cur_salt->iterations, master[i], 32,
						0);
#endif
		} else if (cur_salt->type == 1) {
			for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
				crypto_scrypt((unsigned char *)saved_key[index+i],
						strlen(saved_key[index+i]),
						cur_salt->salt,
						cur_salt->saltlen, cur_salt->N,
						cur_salt->r, cur_salt->p,
						master[i], 32);
		}

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			Keccak_HashInstance hash;
			Keccak_HashInitialize(&hash, 1088, 512, 256, 0x01); // delimitedSuffix is 0x06 for SHA-3, and 0x01 for Keccak
			Keccak_HashUpdate(&hash, master[i] + 16, 16 * 8);
			Keccak_HashUpdate(&hash, cur_salt->ct, cur_salt->ctlen * 8);
			Keccak_HashFinal(&hash, (unsigned char*)crypt_out[index+i]);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
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

struct fmt_main fmt_ethereum = {
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
		ethereum_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		ethereum_common_valid,
		fmt_default_split,
		get_binary,
		ethereum_common_get_salt,
		{
			ethereum_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		ethereum_set_key,
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
