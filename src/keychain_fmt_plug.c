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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_keychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_keychain);
#else

#include <string.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               64
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "pbkdf2_hmac_sha1.h"
#include "jumbo.h"
#include "memdbg.h"

#define FORMAT_LABEL            "keychain"
#define FORMAT_NAME             "Mac OS X Keychain"
#define FORMAT_TAG              "$keychain$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA1 3DES " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 3DES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(*salt_struct)
#define BINARY_ALIGN            1
#define SALT_ALIGN              1
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#define SALTLEN                 20
#define IVLEN                   8
#define CTLEN                   48

static struct fmt_tests keychain_tests[] = {
	{"$keychain$*10f7445c8510fa40d9ef6b4e0f8c772a9d37e449*f3d19b2a45cdcccb*8c3c3b1c7d48a24dad4ccbd4fd794ca9b0b3f1386a0a4527f3548bfe6e2f1001804b082076641bbedbc9f3a7c33c084b", "password"},
	// these were generated with pass_gen.pl.  NOTE, they ALL have the data (which gets encrypted) which was decrypted from the above hash.
	{"$keychain$*a88cd6fbaaf40bc5437eee015a0f95ab8ab70545*b12372b1b7cb5c1f*1f5c596bcdd015afc126bc86f42dd092cb9d531d14a0aafaa89283f1bebace60562d497332afbd952fd329cc864144ec", "password"},
	{"$keychain$*23328e264557b93204dc825c46a25f7fb1e17d4a*19a9efde2ca98d30*6ac89184134758a95c61bd274087ae0cffcf49f433c7f91edea98bd4fd60094e2936d99e4d985dec98284379f23259c0", "hhh"},
	{"$keychain$*927717d8509db73aa47c5e820e3a381928b5e048*eef33a4a1483ae45*a52691580f17e295b8c2320947968503c605b2784bfe4851077782139f0de46f71889835190c361870baa56e2f4e9e43", "JtR-Jumbo"},
	{"$keychain$*1fab88d0b8ea1a3d303e0aef519796eb29e46299*3358b0e77d60892f*286f975dcd191024227514ed9939d0fa94034294ba1eca6d5c767559e75e944b5a2fcb54fd696be64c64f9d069ce628a", "really long password -----------------------------"},
	/* Sample keychain from OS X El Capitan, November of 2015 */
	{"$keychain$*3a473dd308b1713ddc76fc976758eb543779a228*570b762ec2b177d0*a1f491231412ff74344244db4d98b1dab6e40a8fc63a11f0d5cdabf97fce5c4fa8ae0a1f95d0398d37e3d45e9fa07aa7", "El Capitan"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned char salt[SALTLEN];
	unsigned char iv[IVLEN];
	unsigned char ct[CTLEN];
} *salt_struct;

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_autotune(self, OMP_SCALE);
#endif
	saved_key = mem_calloc(sizeof(*saved_key),  self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}
static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) != IVLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if (hexlenl(p, &extra) != CTLEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;

	ctcopy += FORMAT_TAG_LEN;	/* skip over "$keychain$*" */
	salt_struct = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtokm(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		salt_struct->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < IVLEN; i++)
		salt_struct->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < CTLEN; i++)
		salt_struct->ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)salt_struct;
}


static void set_salt(void *salt)
{
	salt_struct = (struct custom_salt *)salt;
}

static int kcdecrypt(unsigned char *key, unsigned char *iv, unsigned char *data)
{
	unsigned char out[CTLEN];
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;

	memset(out, 0, sizeof(out));
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, CTLEN, &ks1, &ks2, &ks3, &ivec,  DES_DECRYPT);

	/* possible bug here, is this assumption (pad of 4) always valid? */
	if (out[47] != 4 || check_pkcs_pad(out, CTLEN, 8) < 0)
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
		unsigned char master[MAX_KEYS_PER_CRYPT][32];
		int i;
#ifdef SIMD_COEF_32
		int lens[MAX_KEYS_PER_CRYPT];
		unsigned char *pin[MAX_KEYS_PER_CRYPT], *pout[MAX_KEYS_PER_CRYPT];

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha1_sse((const unsigned char**)pin, lens, salt_struct->salt, SALTLEN, 1000, pout, 24, 0);
#else
		pbkdf2_sha1((unsigned char *)saved_key[index],  strlen(saved_key[index]), salt_struct->salt, SALTLEN, 1000, master[0], 24, 0);
#endif
		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			if (kcdecrypt(master[i], salt_struct->iv, salt_struct->ct) == 0)
				cracked[index+i] = 1;
			else
				cracked[index+i] = 0;
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
		{ FORMAT_TAG },
		keychain_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
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
