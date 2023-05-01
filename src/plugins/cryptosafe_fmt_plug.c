/*
 * This software is Copyright (c) 2021, magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modifications, are permitted.
 *
 * Cracker for cryptoSafe vaults, as found at https://github.com/Anubis901/SafeCrypto
 * Vault file is loaded as-is; there's no "cryptosafe2john" or such involved.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cryptosafe;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cryptosafe);
#else

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "aes.h"
#include "jumbo.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "cryptosafe_common.h"
#include "loader.h"
#include "jumbo.h"

#define FORMAT_LABEL        "cryptoSafe"
#define ALGORITHM_NAME      "AES-256-CBC"
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  16

#ifndef OMP_SCALE
#define OMP_SCALE           16384 // MKPC and scale tuned for i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *saved_len, *cracked, cracked_count;
static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_len = mem_calloc_align(sizeof(*saved_len),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_align(sizeof(*cracked),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void cryptosafe_set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
	memset(saved_key[index] + saved_len[index], '0', 32 - saved_len[index]);
	saved_key[index][32] = 0;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	strcpy(out, saved_key[index]);
	out[saved_len[index]] = 0;

	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, sizeof(cracked[0]) * cracked_count);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		AES_KEY aes_decrypt_key;
		unsigned char plain[16], iv[16] = { 0 };

		AES_set_decrypt_key((unsigned char*)saved_key[index], 256, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->ciphertext, plain, 16, &aes_decrypt_key, iv, AES_DECRYPT);
		if (!memcmp(plain, "[{\"coinName\":\"", 14)) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
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

struct fmt_main fmt_cryptosafe = {
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
		FMT_CASE | FMT_8_BIT | FMT_UTF8 | FMT_OMP | FMT_HUGE_INPUT,
		{
			NULL
		},
		{ FORMAT_TAG },
		cryptosafe_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		cryptosafe_valid,
		cryptosafe_split,
		fmt_default_binary,
		cryptosafe_get_salt,
		{
			NULL
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		cryptosafe_set_key,
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
#endif /* HAVE_LIBCRYPTO */
