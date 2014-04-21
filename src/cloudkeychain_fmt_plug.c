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
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               1
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"cloudkeychain"
#define FORMAT_NAME		"1Password Cloud Keychain"
#define ALGORITHM_NAME		"PBKDF2-SHA512 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define HASH_LENGTH		64
#define BINARY_SIZE 		0
#define BINARY_ALIGN		1
#define PLAINTEXT_LENGTH	32 /* FIXME */
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define SALTLEN 32
#define IVLEN 16
#define CTLEN 2048
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
	unsigned char expectedhmac[CTLEN]; // XXX this can't be that big
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
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
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
	if ((p = strtok(ctcopy, "$")) == NULL)	/* salt length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	len = atoi(p);
	if(len < 0 || len > SALTLEN) // FIXME: is saltlen 0 allowed?
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* salt */
		goto err;
	if(strlen(p) != len * 2)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if(strlen(p) > 10)
		goto err;
	len = atoi(p);
	if (len >= INT_MAX)	// FIXME: overflow; undefined atopi() behavior
		goto err;
	if (len < 0) //	FIXME: <= 0?
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* masterkey length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	len = atoi(p);
	if(len > CTLEN || len <= 0)	// FIXME: is 0 allowed?
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* masterkey */
		goto err;
	if(strlen(p) != len * 2)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* plaintext length */
		goto err;
	// FIXME: is plaintext length integer?
	if ((p = strtok(NULL, "$")) == NULL)	/* iv length */
		goto err;
	len = atoi(p);
	if(len > IVLEN || len < 0)	// FIXME: is 0 allowed?
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* iv */
		goto err;
	if(strlen(p) != len * 2)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* cryptext length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	len = atoi(p);
	if (len > CTLEN || len < 0)	// FIXME: is 0 allowed?
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* cryptext */
		goto err;
	if(strlen(p) != len * 2)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* expectedhmac length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	len = atoi(p);
	if (len > CTLEN || len < 0)	// FIXME: is 0 allowed?
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* expectedhmac */
		goto err;
	if(strlen(p) != len * 2)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* hmacdata length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	len = atoi(p);
	if (len > CTLEN || len < 0)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL)	/* hmacdata */
		goto err;
	if(strlen(p) != len * 2)
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
	ctcopy += 15;	/* skip over "$cloudkeychain$" */
	p = strtok(ctcopy, "$");
	cs.saltlen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$");
	cs.iterations = atoi(p);
	p = strtok(NULL, "$");
	cs.masterkeylen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs.masterkeylen; i++)
		cs.masterkey[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$");
	cs.plaintextlen = atoi(p);
	p = strtok(NULL, "$");
	cs.ivlen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs.ivlen; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$");
	cs.cryptextlen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs.cryptextlen; i++)
		cs.cryptext[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$");
	cs.expectedhmaclen = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs.expectedhmaclen; i++)
		cs.expectedhmac[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtok(NULL, "$");
		cs.hmacdatalen = atoi(p);
	p = strtok(NULL, "$");
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

static void hmac_sha512(uint8_t * pass, uint8_t passlen, uint8_t * salt,
                        uint8_t saltlen, uint32_t add, uint64_t * ret)
{
	uint8_t i, ipad[PAD_SIZE], opad[PAD_SIZE];
	SHA512_CTX ctx;
	memset(ipad, 0x36, PAD_SIZE);
	memset(opad, 0x5c, PAD_SIZE);

	for (i = 0; i < passlen; i++) {
		ipad[i] ^= pass[i];
		opad[i] ^= pass[i];
	}

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, ipad, PAD_SIZE);
	SHA512_Update(&ctx, salt, saltlen);
	if (add > 0) {
#if ARCH_LITTLE_ENDIAN
		add = JOHNSWAP(add);
#endif
		SHA512_Update(&ctx, &add, 4);	}
	SHA512_Final((uint8_t *) ret, &ctx);

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, opad, PAD_SIZE);
	SHA512_Update(&ctx, (uint8_t *) ret, HASH_LENGTH);
	SHA512_Final((uint8_t *) ret, &ctx);
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
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		uint64_t key[8];
		uint64_t tmp[8];
		int i, j, l;

		l = strlen(saved_key[index]);
		hmac_sha512((unsigned char*)saved_key[index], l,
		            (uint8_t *) cur_salt->salt, cur_salt->saltlen,
		            1, tmp);
		memcpy(key, tmp, HASH_LENGTH);

		for (i = 1; i < cur_salt->iterations; i++) {
			hmac_sha512((unsigned char*)saved_key[index], l,
			            (uint8_t *) tmp, HASH_LENGTH, 0, tmp);
			for (j = 0; j < 8; j++)
				key[j] ^= tmp[j];
		}
		cracked[index] = ckcdecrypt((unsigned char*)key);
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
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
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
		fmt_default_done,
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
