/*
 * Format for cracking blockchain.info "My Wallet" format wallets. Hacked
 * together during June of 2013 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * See https://blockchain.info/wallet/wallet-format
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Improved detection, added iteration count and handle v2 hashes, Feb, 2015, JimF.
 *
 * Usage of https://github.com/gurnec/btcrecover is recommended for cases we
 * don't handle yet.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_blockchain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_blockchain);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "jumbo.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "pbkdf2_hmac_sha1.h"
#include "blockchain_common.h"

#define FORMAT_LABEL            "Blockchain"
#define FORMAT_NAME             "My Wallet"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       " (v2 x5000)"
#define BENCHMARK_LENGTH        0x507 // Iteration count differs
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               32 // MKPC & scale tuned for i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_align(sizeof(*cracked),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		unsigned char master[MIN_KEYS_PER_CRYPT][32];
		int lens[MIN_KEYS_PER_CRYPT], i;
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens,
			cur_salt->data, 16, cur_salt->iter, pout, 32, 0);
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			if (blockchain_decrypt(master[i], cur_salt->data) == 0)
				cracked[i+index] = 1;
			else
				cracked[i+index] = 0;
		}
#else
		unsigned char master[32];
		pbkdf2_sha1((unsigned char *)saved_key[index],
			strlen(saved_key[index]),
			cur_salt->data, 16,
			cur_salt->iter, master, 32, 0);
		if (blockchain_decrypt(master, cur_salt->data) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
#endif
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

static void blockchain_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_blockchain = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
/* FIXME: Should report iteration count as a tunable cost */
		{ NULL },
		{ FORMAT_TAG },
		blockchain_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		blockchain_common_valid,
		fmt_default_split,
		fmt_default_binary,
		blockchain_common_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		blockchain_set_key,
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
