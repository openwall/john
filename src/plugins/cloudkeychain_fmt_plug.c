/*
 * 1Password Cloud Keychain cracker patch for JtR. Hacked together during
 * April of 2013 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru.kholia at gmail.com>,
 * Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net> and Copyright (c) 2012
 * magnum, and it is hereby released to the general public under the following
 * terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This software is based on "onepasswordpy" project but no actual code is
 * borrowed from it.
 *
 * "onepasswordpy" project is at https://github.com/Roguelazer/onepasswordpy.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cloud_keychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cloud_keychain);
#else

#include <stdint.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "sha2.h"
#include "hmac_sha.h"
#include "pbkdf2_hmac_sha512.h"
#include "cloudkeychain_common.h"

#define FORMAT_LABEL            "cloudkeychain"
#define FORMAT_NAME             "1Password Cloud Keychain"
#define FORMAT_TAG              "$cloudkeychain$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA512 " SHA512_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA512 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define PLAINTEXT_LENGTH        111
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA512
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#define HASH_LENGTH             64

#ifndef OMP_SCALE
#define OMP_SCALE               1 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	cracked   = mem_calloc(self->params.max_keys_per_crypt, sizeof(*cracked));
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

static int ckcdecrypt(unsigned char *key)
{
	unsigned char tmp[32];

	JTR_hmac_sha256(key + 32, 32, cur_salt->hmacdata, cur_salt->hmacdatalen, tmp, 32);

	if (!memcmp(tmp, cur_salt->expectedhmac, 16))
		return 1;
	else
		return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$cloudkeychain$" */
	p = strtokm(ctcopy, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.iterations = atou(p);
	p = strtokm(NULL, "$");
	cs.masterkeylen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.masterkeylen; i++)
		cs.masterkey[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.plaintextlen = atou(p);
	p = strtokm(NULL, "$");
	cs.ivlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.ivlen; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.cryptextlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.cryptextlen; i++)
		cs.cryptext[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.expectedhmaclen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.expectedhmaclen; i++)
		cs.expectedhmac[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "$");
		cs.hmacdatalen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.hmacdatalen; i++)
		cs.hmacdata[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SSE_GROUP_SZ_SHA512
		int lens[SSE_GROUP_SZ_SHA512], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA512];
		uint64_t key[SSE_GROUP_SZ_SHA512][8];
		union {
			uint32_t *pout[SSE_GROUP_SZ_SHA512];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA512; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = (uint32_t*)(key[i]);
		}
		pbkdf2_sha512_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, &(x.poutc), HASH_LENGTH, 0);
		for (i = 0; i < SSE_GROUP_SZ_SHA512; ++i)
			cracked[index+i] = ckcdecrypt((unsigned char*)(key[i]));
#else
		uint64_t key[8];
		pbkdf2_sha512((const unsigned char*)(saved_key[index]), strlen(saved_key[index]),
			cur_salt->salt, cur_salt->saltlen,
			cur_salt->iterations, (unsigned char*)key, HASH_LENGTH, 0);
		cracked[index] = ckcdecrypt((unsigned char*)key);
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

static void cloud_keychain_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int)my_salt->iterations;
}

struct fmt_main fmt_cloud_keychain = {
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
		},
		{ FORMAT_TAG },
		cloudkeychain_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		cloudkeychain_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		cloud_keychain_set_key,
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
