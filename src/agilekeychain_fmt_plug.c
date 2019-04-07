/*
 * 1Password Agile Keychain cracker patch for JtR. Hacked together during
 * July of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This software is based on "agilekeychain" project but no actual code is
 * borrowed from it.
 *
 * "agilekeychain" project is at https://bitbucket.org/gwik/agilekeychain.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_agile_keychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_agile_keychain);
#else

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
#include "aes.h"
#include "jumbo.h"
#include "johnswap.h"
#include "pbkdf2_hmac_sha1.h"
#include "agilekeychain_common.h"

#ifndef OMP_SCALE
#define OMP_SCALE               4	// MKPC and OMP_SCALE tuned for core i7
#endif

#define FORMAT_LABEL            "agilekeychain"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
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

static int akcdecrypt(unsigned char *derived_key, unsigned char *data)
{
	unsigned char out[CTLEN];
	int n, key_size;
	AES_KEY akey;
	unsigned char iv[16];

	memcpy(iv, data + CTLEN - 32, 16);

	AES_set_decrypt_key(derived_key, 128, &akey);
	AES_cbc_encrypt(data + CTLEN - 16, out + CTLEN - 16, 16, &akey, iv, AES_DECRYPT);

	n = check_pkcs_pad(out, CTLEN, 16);
	if (n < 0)
		return -1;

	key_size = n / 8;
	if (key_size != 128 && key_size != 192 && key_size != 256)
		// "invalid key size"
		return -1;

	return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_32
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int lens[MAX_KEYS_PER_CRYPT], i;
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, cur_salt->salt[0], cur_salt->saltlen[0], cur_salt->iterations[0], pout, 16, 0);
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			if (akcdecrypt(master[i], cur_salt->ct[0]) == 0)
				cracked[i+index] = 1;
			else
				cracked[i+index] = 0;
		}
#else
		unsigned char master[32];
		pbkdf2_sha1((unsigned char *)saved_key[index],
		       strlen(saved_key[index]),
		       cur_salt->salt[0], cur_salt->saltlen[0],
		       cur_salt->iterations[0], master, 16, 0);
		if (akcdecrypt(master, cur_salt->ct[0]) == 0)
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

static void agile_keychain_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations[0];
}

struct fmt_main fmt_agile_keychain = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		agilekeychain_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		agilekeychain_valid,
		fmt_default_split,
		fmt_default_binary,
		agilekeychain_get_salt,
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
		agile_keychain_set_key,
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
