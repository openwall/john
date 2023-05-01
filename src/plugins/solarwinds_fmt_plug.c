/*
 * JtR format to crack SolarWinds Orion hashes.
 *
 * These hashes can be dumped from the "Accounts" table.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * References:
 *
 * + https://github.com/atredispartners/solarwinds-orion-cryptography
 *
 * + https://www.atredis.com/blog/2018/10/24/fun-with-the-solarwinds-orion-platform
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_solarwinds;
#elif FMT_REGISTERS_H
john_register_one(&fmt_solarwinds);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1  // MKPC and OMP_SCALE tuned on Core i5-6500

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha.h"
#include "sha2.h"
#include "jumbo.h"
#include "johnswap.h"
#include "solarwinds_common.h"
#include "pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL         "solarwinds"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME       "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME       "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0x107
#define PLAINTEXT_LENGTH     125
#define BINARY_ALIGN         4
#define SALT_SIZE            sizeof(struct custom_salt)
#define SALT_ALIGN           sizeof(unsigned int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT   SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT   SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void solarwinds_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
		unsigned char master[MAX_KEYS_PER_CRYPT][1024];
		int i;

#ifdef SIMD_COEF_32
		int len[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, (unsigned char *)cur_salt->salt, 8, 1000, pout, 1024, 0);
#else
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha1((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]),
				(unsigned char *)cur_salt->salt, 8, 1000, master[i], 1024, 0);
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			SHA512_CTX ctx;

			SHA512_Init(&ctx);
			SHA512_Update(&ctx, master[i], 1024);
			SHA512_Final((unsigned char*)crypt_out[index+i], &ctx);
		}
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
	return !memcmp(binary, crypt_out[index], 12);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_solarwinds = {
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
		{ NULL },
		{ FORMAT_TAG },
		solarwinds_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		solarwinds_valid,
		fmt_default_split,
		solarwinds_get_binary,
		solarwinds_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		solarwinds_set_key,
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
