/*
 * Format for cracking NetIQ SSPR hashes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Special thanks goes to https://github.com/crypticgeek for documenting the
 * "SHA1_SALT" hashing scheme.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sspr;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sspr);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               1  // MKPC and OMP_SCALE tuned on Core i7-6600U

#include "formats.h"
#include "md5.h"
#include "sha.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "sspr_common.h"

#define FORMAT_LABEL            "sspr"
#define ALGORITHM_NAME          "MD5/SHA1/SHA256/SHA512 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4

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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		uint32_t c;
		SHA_CTX ctx;
		SHA256_CTX sctx;
		SHA512_CTX sctx2;
		MD5_CTX mctx;
		unsigned char buf[64];

		if (cur_salt->fmt == 0) {
			MD5_Init(&mctx);
			MD5_Update(&mctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			MD5_Final(buf, &mctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				MD5_Init(&mctx);
				MD5_Update(&mctx, buf, 16);
				MD5_Final(buf, &mctx);
			}
		} else if (cur_salt->fmt == 1) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA1_Final(buf, &ctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, buf, 20);
				SHA1_Final(buf, &ctx);
			}
		} else if (cur_salt->fmt == 2) {
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, cur_salt->salt, cur_salt->saltlen);
			SHA1_Update(&ctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA1_Final(buf, &ctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, buf, 20);
				SHA1_Final(buf, &ctx);
			}
		} else if (cur_salt->fmt == 3) {
			SHA256_Init(&sctx);
			SHA256_Update(&sctx, cur_salt->salt, cur_salt->saltlen);
			SHA256_Update(&sctx, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA256_Final(buf, &sctx);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA256_Init(&sctx);
				SHA256_Update(&sctx, buf, 32);
				SHA256_Final(buf, &sctx);
			}
		} else if (cur_salt->fmt == 4) {
			SHA512_Init(&sctx2);
			SHA512_Update(&sctx2, cur_salt->salt, cur_salt->saltlen);
			SHA512_Update(&sctx2, (const unsigned char*)saved_key[index], strlen(saved_key[index]));
			SHA512_Final(buf, &sctx2);
			for (c = 1; c < cur_salt->iterations; c++) {
				SHA512_Init(&sctx2);
				SHA512_Update(&sctx2, buf, 64);
				SHA512_Final(buf, &sctx2);
			}
		}
		memcpy(crypt_out[index], buf, BINARY_SIZE_MIN);
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
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_MIN);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void sspr_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_sspr = {
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
			"KDF [0:MD5 1:SHA1 2:SHA1_SALT 3:SHA256_SALT 4:SHA512_SALT]",
			"iteration count",
		},
		{ FORMAT_TAG },
		sspr_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		sspr_valid,
		fmt_default_split,
		sspr_get_binary,
		sspr_get_salt,
		{
			sspr_get_kdf_type,
			sspr_get_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		sspr_set_key,
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
