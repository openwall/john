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
#include <errno.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#define PBKDF2_HMAC_SHA256_VARYING_SALT 1
#include "pbkdf2_hmac_sha256.h"
#include "ethereum_common.h"
#include "yescrypt/yescrypt.h"
#include "KeccakHash.h"
#include "aes.h"
#include "jumbo.h"

#define FORMAT_NAME             "Ethereum Wallet"
#define FORMAT_LABEL            "ethereum"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA256/scrypt Keccak " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256/scrypt Keccak 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define BINARY_SIZE             16
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(uint64_t)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#define OMP_SCALE		1

static int max_threads;
static yescrypt_local_t *local;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE * 2 / sizeof(uint32_t)];
static unsigned char (*saved_presale)[32];
static int new_keys;

static custom_salt *cur_salt;

static union {
	uint64_t dummy;
	unsigned char data[8];
} dpad;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
#else
	max_threads = 1;
#endif

	local = mem_alloc(sizeof(*local) * max_threads);
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_init_local(&local[i]);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_presale =
		mem_calloc(sizeof(*saved_presale), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);

	memcpy(dpad.data, "\x02\x00\x00\x00\x00\x00\x00\x00", 8);
}

static void done(void)
{
	int i;
	for (i = 0; i < max_threads; i++)
		yescrypt_free_local(&local[i]);
	MEM_FREE(local);

	MEM_FREE(saved_presale);
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static void set_salt(void *salt)
{
	cur_salt = (custom_salt *)salt;
}

static void ethereum_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	int failed = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char master[MIN_KEYS_PER_CRYPT][32];
		int i;
		if (cur_salt->type == 0) {
#ifdef SIMD_COEF_32
			int lens[MIN_KEYS_PER_CRYPT];
			unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				lens[i] = strlen(saved_key[index+i]);
				pin[i] = (unsigned char*)saved_key[index+i];
				pout[i] = master[i];
			}
			pbkdf2_sha256_sse((const unsigned char**)pin, lens, cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, pout, 32, 0);
#else
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
				pbkdf2_sha256((unsigned char *)saved_key[index+i],
						strlen(saved_key[index+i]),
						cur_salt->salt, cur_salt->saltlen,
						cur_salt->iterations, master[i], 32,
						0);
#endif
		} else if (cur_salt->type == 1) {
#ifdef _OPENMP
			int t = omp_get_thread_num();
			if (t >= max_threads) {
				failed = -1;
				continue;
			}
#else
			const int t = 0;
#endif
			yescrypt_params_t params = { .N = cur_salt->N, .r = cur_salt->r, .p = cur_salt->p };
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				if (yescrypt_kdf(NULL, &local[t],
				    (const uint8_t *)saved_key[index + i],
				    strlen(saved_key[index + i]),
				    (const uint8_t *)cur_salt->salt,
				    strlen((const char *)cur_salt->salt),
				    &params,
				    master[i], 32)) {
					failed = errno ? errno : EINVAL;
#ifndef _OPENMP
					goto fail_with_errno;
#endif
				}
			}
		} else if (cur_salt->type == 2) {
			if (new_keys) {
				/* Presale. No salt! */
#ifdef SIMD_COEF_32
				int lens[MIN_KEYS_PER_CRYPT];
				int slens[MIN_KEYS_PER_CRYPT];
				unsigned char *sin[MIN_KEYS_PER_CRYPT];
				unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
				for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
					lens[i] = strlen(saved_key[index+i]);
					pin[i] = (unsigned char*)saved_key[index+i];
					pout[i] = master[i];
					sin[i] = pin[i];
					slens[i] = lens[i];
				}
				pbkdf2_sha256_sse_varying_salt((const unsigned char**)pin, lens, sin, slens, 2000, pout, 16, 0);
				for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
					memcpy(saved_presale[index + i], pout[i], 32);
				}
#else

				for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
					pbkdf2_sha256((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]), (unsigned char *)saved_key[index+i], strlen(saved_key[index+i]), 2000, master[i], 16, 0);
				}
				for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
					memcpy(saved_presale[index + i], master[i], 32);
				}
#endif
			} else {
				for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
					memcpy(master[i], saved_presale[index + i], 32);
			}
		}

		if (cur_salt->type == 0 || cur_salt->type == 1) {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				Keccak_HashInstance hash;
				Keccak_HashInitialize(&hash, 1088, 512, 256, 0x01); // delimitedSuffix is 0x06 for SHA-3, and 0x01 for Keccak
				Keccak_HashUpdate(&hash, master[i] + 16, 16 * 8);
				Keccak_HashUpdate(&hash, cur_salt->ct, cur_salt->ctlen * 8);
				Keccak_HashFinal(&hash, (unsigned char*)crypt_out[index+i]);
			}
		} else {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				AES_KEY akey;
				Keccak_HashInstance hash;
				unsigned char iv[16];
				unsigned char seed[4096];
				int padbyte;
				int datalen;

				AES_set_decrypt_key(master[i], 128, &akey);
				memcpy(iv, cur_salt->encseed, 16);
				AES_cbc_encrypt(cur_salt->encseed + 16, seed, cur_salt->eslen - 16, &akey, iv, AES_DECRYPT);
				if (check_pkcs_pad(seed, cur_salt->eslen - 16, 16) < 0) {
					memset(crypt_out[index+i], 0, BINARY_SIZE);
					continue;
				}
				padbyte = seed[cur_salt->eslen - 16 - 1];
				datalen = cur_salt->eslen - 16 - padbyte;
				if (datalen < 0) {
					memset(crypt_out[index+i], 0, BINARY_SIZE);
					continue;
				}
				Keccak_HashInitialize(&hash, 1088, 512, 256, 0x01);
				Keccak_HashUpdate(&hash, seed, datalen * 8);
				Keccak_HashUpdate(&hash, dpad.data, 1 * 8);
				Keccak_HashFinal(&hash, (unsigned char*)crypt_out[index+i]);
			}
		}
	}
	new_keys = 0;

	if (failed) {
#ifdef _OPENMP
		if (failed < 0) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
#ifndef _OPENMP
fail_with_errno:
#endif
		fprintf(stderr, "scrypt failed: %s\n", strerror(failed));
		error();
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"iteration count",
			"kdf [0:PBKDF2-SHA256 1:scrypt 2:PBKDF2-SHA256 presale]",
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
		ethereum_get_binary,
		ethereum_common_get_salt,
		{
			ethereum_common_iteration_count,
			ethereum_common_kdf_type,
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
