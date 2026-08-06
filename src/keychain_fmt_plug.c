/*
 * Mac OS X Keychain cracker patch for JtR. Hacked together during Summer of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This code is based on the "extractkeychain" program which is (c) 2004 Matt
 * Johnston <matt @ ucc asn au>, and distributed under the following licensing
 * terms: This code may be freely used and modified for any purpose.
 *
 * See https://matt.ucc.asn.au/apple/ for more information.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_keychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_keychain);
#else

#include <string.h>
#include <openssl/des.h>

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
#include "keychain_common.h"
#include "pbkdf2_hmac_sha1.h"
#include "jumbo.h"

#define FORMAT_LABEL            "keychain"

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 3DES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 3DES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        MAX_PLAINTEXT_LENGTH
#define SALT_SIZE               sizeof(*cur_salt)
#define BINARY_ALIGN            1
#define SALT_ALIGN              1

#ifndef OMP_SCALE
#define OMP_SCALE               16
#endif

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

	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
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

static int kcdecrypt(unsigned char *key, unsigned char *iv, unsigned char *data,
                     unsigned char *out)
{
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;

	memset(out, 0, CTLEN);
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	DES_set_key_unchecked((DES_cblock *) key1, &ks1);
	DES_set_key_unchecked((DES_cblock *) key2, &ks2);
	DES_set_key_unchecked((DES_cblock *) key3, &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, CTLEN, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

	/* possible bug here, is this assumption (pad of 4) always valid? */
	if (out[47] != 4 || check_pkcs_pad(out, CTLEN, 8) < 0)
		return -1;

	return 0;
}

/* magicCmsIV from Apple's wrapKeyCms.cpp */
static const unsigned char MAGIC_CMS_IV[8] = {
	0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05
};

static int symkey_verify(unsigned char *dbkey, unsigned char *data, int len)
{
	unsigned char out[SYMKEY_MAX_CTLEN];
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;

	memcpy(key1, dbkey, 8);
	memcpy(key2, dbkey + 8, 8);
	memcpy(key3, dbkey + 16, 8);
	DES_set_key_unchecked((DES_cblock *) key1, &ks1);
	DES_set_key_unchecked((DES_cblock *) key2, &ks2);
	DES_set_key_unchecked((DES_cblock *) key3, &ks3);
	memcpy(ivec, MAGIC_CMS_IV, 8);
	DES_ede3_cbc_encrypt(data, out, len, &ks1, &ks2, &ks3, &ivec, DES_DECRYPT);

	if (check_pkcs_pad(out, len, 8) < 0)
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
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char master[MIN_KEYS_PER_CRYPT][32];
		int i;
#ifdef SIMD_COEF_32
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char**)pin, lens, cur_salt->salt, SALTLEN, 1000, pout, 24, 0);
#else
		pbkdf2_sha1((unsigned char *)saved_key[index],  strlen(saved_key[index]), cur_salt->salt, SALTLEN, 1000, master[0], 24, 0);
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			unsigned char dbblob_out[CTLEN];

			if (kcdecrypt(master[i], cur_salt->iv, cur_salt->ct,
			              dbblob_out) == 0) {
				if (cur_salt->has_symkey) {
					/* Use decrypted DB key to verify symmetric key blob */
					if (symkey_verify(dbblob_out, cur_salt->symkey_ct,
					                  cur_salt->symkey_ct_len) == 0)
						cracked[index+i] = 1;
					else
						cracked[index+i] = 0;
				} else {
					cracked[index+i] = 1;
				}
			} else {
				cracked[index+i] = 0;
			}
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

static void keychain_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_keychain = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
		{ FORMAT_TAG, FORMAT_TAG_V2 },
		keychain_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		keychain_valid,
		fmt_default_split,
		fmt_default_binary,
		keychain_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		keychain_set_key,
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
