/*
 * JtR format to crack password protected FreeBSD GELI volumes.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_geli;
#elif FMT_REGISTERS_H
john_register_one(&fmt_geli);
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
#include "hmac_sha.h"
#include "aes.h"
#include "pbkdf2_hmac_sha512.h"
#include "jumbo.h"
#include "memdbg.h"
#include "geli_common.h"

#define FORMAT_LABEL            "geli"
#define FORMAT_NAME             "FreeBSD GELI"
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA512 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA512 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;
static custom_salt *cur_salt;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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
	cur_salt = (custom_salt *)salt;
}

static void geli_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		unsigned char master[MAX_KEYS_PER_CRYPT][G_ELI_USERKEYLEN];
		unsigned char key[MAX_KEYS_PER_CRYPT][G_ELI_USERKEYLEN];
		int i;
#ifdef SIMD_COEF_64
		int lens[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha512_sse((const unsigned char**)pin, lens, cur_salt->md_salt, G_ELI_SALTLEN, cur_salt->md_iterations, pout, G_ELI_USERKEYLEN, 0);
#else
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha512((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]), cur_salt->md_salt, G_ELI_SALTLEN, cur_salt->md_iterations, master[i], G_ELI_USERKEYLEN, 0);
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			JTR_hmac_sha512((const unsigned char*)"", 0, master[i], G_ELI_USERKEYLEN, key[i], G_ELI_USERKEYLEN);
			cracked[index+i] = geli_decrypt_verify(cur_salt, key[i]);
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

struct fmt_main fmt_geli = {
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
		geli_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		geli_common_valid,
		fmt_default_split,
		fmt_default_binary,
		geli_common_get_salt,
		{
			geli_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		geli_set_key,
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
