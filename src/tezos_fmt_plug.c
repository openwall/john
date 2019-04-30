/*
 * JtR format to crack password protected Tezos keys.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Special thanks goes to https://github.com/NODESPLIT/tz-brute and Michael
 * Senn (@MikeSenn on Telegram) for helping me bootstrap this project.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_tezos;
#elif FMT_REGISTERS_H
john_register_one(&fmt_tezos);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "jumbo.h"
#include "ed25519.h"
#include "blake2.h"
#include "tezos_common.h"
#define PBKDF2_HMAC_SHA512_VARYING_SALT 1
#include "pbkdf2_hmac_sha512.h"

#define FORMAT_NAME             "Tezos Key"
#define FORMAT_LABEL            "tezos"
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA512 " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME          "PBKDF2-SHA512 64/" ARCH_BITS_STR SHA2_LIB
#else
#define ALGORITHM_NAME          "PBKDF2-SHA512 32/" ARCH_BITS_STR SHA2_LIB
#endif
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        125
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA512 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
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

static void tezos_set_key(char *key, int index)
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
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char seed[MIN_KEYS_PER_CRYPT][64];
		char salt[MIN_KEYS_PER_CRYPT][16 + 256 + PLAINTEXT_LENGTH];
		int i;
#ifdef SIMD_COEF_64
		int lens[MIN_KEYS_PER_CRYPT];
		int slens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		unsigned char *sin[MIN_KEYS_PER_CRYPT];
#endif
		// create varying salt(s)
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			memcpy(salt[i], "mnemonic", 8);
			memcpy(salt[i] + 8, cur_salt->email, cur_salt->email_length + 1);
			strcat(salt[i], saved_key[index+i]);
		}

		// kdf
#ifdef SIMD_COEF_64
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = cur_salt->mnemonic_length;
			pin[i] = (unsigned char*)cur_salt->mnemonic;
			sin[i] = (unsigned char*)salt[i];
			pout[i] = seed[i];
			slens[i] = strlen(salt[i]);
		}
		pbkdf2_sha512_sse_varying_salt((const unsigned char**)pin, lens, sin, slens, 2048, pout, 64, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha512((unsigned char*)cur_salt->mnemonic,
					cur_salt->mnemonic_length, (unsigned char*)salt[i], strlen(salt[i]), 2048,
					seed[i], 64, 0);
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			unsigned char buffer[20];
			ed25519_public_key pk;
			ed25519_secret_key sk;

			// asymmetric stuff
			memcpy(sk, seed[i], 32);
			ed25519_publickey(sk, pk);

			blake2b((uint8_t *)buffer, (unsigned char*)pk, NULL, 20, 32, 0); // pk is pkh (pubkey hash)

			if (memmem(cur_salt->raw_address, cur_salt->raw_address_length, (void*)buffer, 8)) {
				cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_tezos = {
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
		tezos_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		tezos_valid,
		fmt_default_split,
		fmt_default_binary,
		tezos_get_salt,
		{
			tezos_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		tezos_set_key,
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
