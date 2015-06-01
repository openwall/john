/* 1Password Cloud Keychain cracker patch for JtR. Hacked together during
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
 * "onepasswordpy" project is at https://github.com/Roguelazer/onepasswordpy
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cloud_keychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cloud_keychain);
#else

#include <string.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "stdint.h"
#include "sha2.h"
#include "pbkdf2_hmac_sha512.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"cloudkeychain"
#define FORMAT_NAME		"1Password Cloud Keychain"
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME		"PBKDF2-SHA512 " SHA512_ALGORITHM_NAME
#else
#define ALGORITHM_NAME		"PBKDF2-SHA512 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define HASH_LENGTH		64
#define BINARY_SIZE 		0
#define BINARY_ALIGN		1
#define PLAINTEXT_LENGTH	125
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA512
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#define SALTLEN 32
#define IVLEN 16
#define CTLEN 2048
#define EHMLEN 32
#define PAD_SIZE		128

static struct fmt_tests cloud_keychain_tests[] = {
	{"$cloudkeychain$16$2e57e8b57eda4d99df2fe02324960044$227272$336$6f706461746130310001000000000000881d65af6b863f6678d484ff551bc843a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b6fde10044103924d8275bf9bfadc98540ae61c5e59be06c5bca981460345bd29$256$16$881d65af6b863f6678d484ff551bc843$272$a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b$32$6fde10044103924d8275bf9bfadc98540ae61c5e59be06c5bca981460345bd29$304$6f706461746130310001000000000000881d65af6b863f6678d484ff551bc843a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b", "fred"},
	{NULL}
};

#if defined (_OPENMP)
static int omp_t = 1;
#endif
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	unsigned int saltlen;
	unsigned char salt[SALTLEN];
	unsigned int iterations;
	unsigned int masterkeylen;
	unsigned char masterkey[CTLEN];
	unsigned int plaintextlen;
	unsigned int ivlen;
	unsigned char iv[32];
	unsigned int cryptextlen;
	unsigned char cryptext[CTLEN];
	unsigned int expectedhmaclen;
	unsigned char expectedhmac[EHMLEN];
	unsigned int hmacdatalen;
	unsigned char hmacdata[CTLEN];
} *cur_salt;

static void init(struct fmt_main *self)
{

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked   = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len;

	if (strncmp(ciphertext,  "$cloudkeychain$", 15) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 15;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* salt length */
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (!ishex(p))
		goto err;
	if(strlen(p) != len * 2)	/* validates salt_len also */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* masterkey length */
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* masterkey */
		goto err;
	if (!ishex(p))
		goto err;
	if(strlen(p) != len * 2)	/* validates masterkey_len also */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* plaintext length */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iv length */
		goto err;
	len = atoi(p);
	if(len > IVLEN || len < 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iv */
		goto err;
	if(strlen(p) != len * 2)	/* validates iv_len */
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* cryptext length */
		goto err;
	len = atoi(p);
	if (len > CTLEN || len < 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* cryptext */
		goto err;
	if (!ishex(p))
		goto err;
	if(strlen(p) != len * 2)	/* validates cryptext_len */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* expectedhmac length */
		goto err;
	len = atoi(p);
	if (len > EHMLEN || len < 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* expectedhmac */
		goto err;
	if (!ishex(p))
		goto err;
	if(strlen(p) != len * 2)	/* validates expectedhmac_len */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* hmacdata length */
		goto err;
	len = atoi(p);
	if (len > CTLEN || len < 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* hmacdata */
		goto err;
	if (!ishex(p))
		goto err;
	if(strlen(p) != len * 2)	/* validates hmacdata_len */
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
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += 15;	/* skip over "$cloudkeychain$" */
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


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void hmac_sha256(uint8_t * pass, uint8_t passlen, uint8_t * salt,
                        uint32_t saltlen, uint32_t add, uint64_t * ret)
{
	uint8_t i, ipad[64], opad[64];
	SHA256_CTX ctx;
	memset(ipad, 0x36, 64);
	memset(opad, 0x5c, 64);

	for (i = 0; i < passlen; i++) {
		ipad[i] ^= pass[i];
		opad[i] ^= pass[i];
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ipad, 64);
	SHA256_Update(&ctx, salt, saltlen);
	if (add > 0) {
#if ARCH_LITTLE_ENDIAN
		add = JOHNSWAP(add);
#endif
		SHA256_Update(&ctx, &add, 4);	}
	SHA256_Final((uint8_t *) ret, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, opad, 64);
	SHA256_Update(&ctx, (uint8_t *) ret, 32);
	SHA256_Final((uint8_t *) ret, &ctx);
}

static int ckcdecrypt(unsigned char *key)
{
	uint64_t tmp[8];
	hmac_sha256(key + 32, 32, cur_salt->hmacdata, cur_salt->hmacdatalen, 0, tmp);

	if (!memcmp(tmp, cur_salt->expectedhmac, 32))
		return 1;
	else
		return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
#ifdef SSE_GROUP_SZ_SHA512
		int lens[SSE_GROUP_SZ_SHA512], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA512];
		uint64_t key[SSE_GROUP_SZ_SHA512][8];
		union {
			ARCH_WORD_32 *pout[SSE_GROUP_SZ_SHA512];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA512; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = (ARCH_WORD_32*)(key[i]);
		}
		pbkdf2_sha512_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, &(x.poutc), HASH_LENGTH, 0);
		for (i = 0; i < SSE_GROUP_SZ_SHA512; ++i)
			cracked[index+i] = ckcdecrypt((unsigned char*)(key[i]));
#else
		uint64_t key[8];
		pbkdf2_sha512((const unsigned char*)(saved_key[index]), strlen(saved_key[index]),
			cur_salt->salt, cur_salt->saltlen,
			cur_salt->iterations, (unsigned char*)key, HASH_LENGTH, 0);
#if ARCH_LITTLE_ENDIAN==0
		{
			int j;
			for (j = 0; j < 8; ++j)
				key[j] = JOHNSWAP64(key[j]);
		}
#endif
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

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->iterations;
}
#endif

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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		cloud_keychain_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
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
