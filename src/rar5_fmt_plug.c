/*
 * RAR 5.0 cracker patch for JtR. Hacked together during May of 2013 by Dhiru
 * Kholia.
 *
 * http://www.rarlab.com/technote.htm
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com> and
 * it is hereby released to the general public under the
 * following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * $rar5$<salt_len>$<salt>$<iter_log2>$<iv>$<pswcheck_len>$<pswcheck>
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rar5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rar5);
#else

#include <stdint.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "johnswap.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "rar5_common.h"
#include "pbkdf2_hmac_sha256.h"

#define FORMAT_LABEL            "RAR5"
#define FORMAT_NAME             ""
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA256 " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        32
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SSE_GROUP_SZ_SHA256
		int lens[SSE_GROUP_SZ_SHA256], i, j;
		unsigned char PswCheck[SIZE_PSWCHECK],
		              PswCheckValue[SSE_GROUP_SZ_SHA256][SHA256_DIGEST_SIZE];
		unsigned char *pin[SSE_GROUP_SZ_SHA256];
		union {
			uint32_t *pout[SSE_GROUP_SZ_SHA256];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA256; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = (uint32_t*)PswCheckValue[i];
		}
		pbkdf2_sha256_sse((const unsigned char **)pin, lens, cur_salt->salt, SIZE_SALT50, cur_salt->iterations+32, &(x.poutc), SHA256_DIGEST_SIZE, 0);
		// special wtf processing
		for (j = 0; j < SSE_GROUP_SZ_SHA256; ++j) {
			memset(PswCheck, 0, sizeof(PswCheck));
			for (i = 0; i < SHA256_DIGEST_SIZE; i++)
				PswCheck[i % SIZE_PSWCHECK] ^= PswCheckValue[j][i];
			memcpy((void*)crypt_out[index+j], PswCheck, SIZE_PSWCHECK);
		}
#else
		unsigned char PswCheckValue[SHA256_DIGEST_SIZE];
		unsigned char PswCheck[SIZE_PSWCHECK];
		int i;
		pbkdf2_sha256((unsigned char*)saved_key[index], strlen(saved_key[index]), cur_salt->salt, SIZE_SALT50, cur_salt->iterations+32, PswCheckValue, SHA256_DIGEST_SIZE, 0);
		// special wtf processing
		memset(PswCheck, 0, sizeof(PswCheck));
		for (i = 0; i < SHA256_DIGEST_SIZE; i++)
			PswCheck[i % SIZE_PSWCHECK] ^= PswCheckValue[i];
		memcpy((void*)crypt_out[index], PswCheck, SIZE_PSWCHECK);
#endif
	}
	return count;
}

static void rar5_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
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

static int get_hash_0(int index)
{
#ifdef RARDEBUG
	dump_stuff_msg("get_hash", crypt_out[index], BINARY_SIZE);
#endif
	return crypt_out[index][0] & PH_MASK_0;
}
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }

struct fmt_main fmt_rar5 = {
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
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			iteration_count,
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
		fmt_default_salt_hash,
		NULL,
		set_salt,
		rar5_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
