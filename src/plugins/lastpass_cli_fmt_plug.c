/*
 * LastPass CLI cracker patch for JtR.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lastpass_cli;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lastpass_cli);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "pbkdf2_hmac_sha256.h"
#include "lastpass_cli_common.h"

#define FORMAT_LABEL            "lpcli"
#define FORMAT_TAG              "$lpcli$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA256 " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7 // FIXME: add costs (but this is OK)
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)

#ifndef OMP_SCALE
#define OMP_SCALE              1 // MKPC and scale tuned for i7
#endif

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[32 / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#define AGENT_VERIFICATION_STRING "`lpass` was written by LastPass.\n"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		uint32_t key[MIN_KEYS_PER_CRYPT][8];
		int i;

		if (cur_salt->iterations != 1) {
#ifdef SIMD_COEF_32
			int lens[MIN_KEYS_PER_CRYPT];
			unsigned char *pin[MIN_KEYS_PER_CRYPT];
			union {
				uint32_t *pout[MIN_KEYS_PER_CRYPT];
				unsigned char *poutc;
			} x;
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				lens[i] = strlen(saved_key[i+index]);
				pin[i] = (unsigned char*)saved_key[i+index];
				x.pout[i] = key[i];
			}
			pbkdf2_sha256_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, &(x.poutc), 32, 0);

#else
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				pbkdf2_sha256((unsigned char*)saved_key[i+index], strlen(saved_key[i+index]), cur_salt->salt, cur_salt->salt_length, cur_salt->iterations, (unsigned char*)key[i], 32, 0);
			}
#endif
		} else {
			for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
				SHA256_CTX ctx;

				SHA256_Init(&ctx);
				SHA256_Update(&ctx, cur_salt->salt, cur_salt->salt_length);
				SHA256_Update(&ctx, saved_key[i+index], strlen(saved_key[i+index]));
				SHA256_Final((unsigned char*)key[i], &ctx);
			}
		}
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			unsigned char iv[16];
			AES_KEY akey;

			memcpy(iv, cur_salt->iv, 16);
			AES_set_encrypt_key((unsigned char*)key[i], 256, &akey);
			AES_cbc_encrypt((const unsigned char*)AGENT_VERIFICATION_STRING, (unsigned char*)crypt_out[i+index], BINARY_SIZE, &akey, iv, AES_ENCRYPT);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
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

static void lastpass_cli_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_lastpass_cli = {
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
		lastpass_cli_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		lastpass_cli_common_valid,
		fmt_default_split,
		lastpass_cli_common_get_binary,
		lastpass_cli_common_get_salt,
		{
			lastpass_cli_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		lastpass_cli_set_key,
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
