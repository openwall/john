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
#include "pbkdf2_hmac_sha512.h"
#include "memdbg.h"

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
#define BENCHMARK_LENGTH        -1
#define HASH_LENGTH             64
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

#ifndef OMP_SCALE
#define OMP_SCALE               1 // Tuned w/ MKPC for core i7
#endif

#define SALTLEN                 32
#define IVLEN                   16
#define CTLEN                   2048
#define EHMLEN                  32
#define PAD_SIZE                128

static struct fmt_tests cloud_keychain_tests[] = {
	{"$cloudkeychain$16$2e57e8b57eda4d99df2fe02324960044$227272$336$6f706461746130310001000000000000881d65af6b863f6678d484ff551bc843a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b6fde10044103924d8275bf9bfadc98540ae61c5e59be06c5bca981460345bd29$256$16$881d65af6b863f6678d484ff551bc843$272$a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b$32$6fde10044103924d8275bf9bfadc98540ae61c5e59be06c5bca981460345bd29$304$6f706461746130310001000000000000881d65af6b863f6678d484ff551bc843a95faf289b914e570a1993353789b66a9c6bd40b42c588923e8869862339d06ef3d5c091c0ba997a704619b3ffc121b4b126071e9e0a0812f722f95a2d7b80c22bc91fc237cb3dfaba1bee1c9d3cb4c94332335ab203bb0f07ca774c19729ce8182f91cd228ae18fb82b17535ecae012f14904a6ace90d9bab1d934eb957ea98a68b4b2db3c8e02d27f7aff9203cdbd91c2b7c6aaa6f9c2ca3c1d5f976fc9ed86b80082ae3e39c2f30a35d26c2c14dbd64386be9b5ae40851824dc5963b54703ba17d20b424deaaa452793a1ef8418db2dda669b064075e450404a46433f6533dfe0a13b34fa1f55238ffea5062a4f22e821b9e99639c9d0ece27df65caf0aaaad7200b0187e7b3134107e38582ef73b", "fred"},
	// https://cache.agilebits.com/security-kb/freddy-2013-12-04.tar.gz, This is a sample OPVault file. The Master Password for it is freddy.
	{"$cloudkeychain$16$3f4a4e30c37a3b0e7020a38e4ac69242$50000$336$6f706461746130310001000000000000237c26e13beb237a85b8eacc4bddd111a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dcb5bb5a07ad0315fd9742d7d0edc9b9ed685bfa76978e228fdaa237dae4152731$256$16$237c26e13beb237a85b8eacc4bddd111$272$a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dc$32$b5bb5a07ad0315fd9742d7d0edc9b9ed685bfa76978e228fdaa237dae4152731$304$6f706461746130310001000000000000237c26e13beb237a85b8eacc4bddd111a7bb7bee7cf71f019df9268cb3751d563d1bebf0331e7def4c26eeb90e61d2c2339b3c2d23ce75e969f250a1be823732823687950be19722f2dc92f02e614352c082d04358c421c1ddc90d07d8c6c9fb46255846ef950f14547e5b72b32a0e64cf3d24646d41b7fdd57534a1dd808d15e8dfe4299ef7ee8a3e923dc28496504cacb0be647a4600797ade6cb41694c2eb4d41b674ce762d66e98895fde98dda862b84720874b09b080b50ef9514b4ea0e3a19f5d51ccb8850cd26623e56dadef2bcbc625194dd107f663a7548f991803075874ecc4fc98b785b4cd56c3ce9bcb23ccf70f1908fc85a5b9520cd20d9d26a3bfb29ac289c1262302c82f6b0877d566369b98fb551fb9d044434c4cb1c50dc", "freddy"},
	{NULL}
};

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
	omp_autotune(self, OMP_SCALE);

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
	int len, extra;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* salt length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iterations */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* masterkey length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)	/* masterkey */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* plaintext length */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iv length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > IVLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) / 2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* cryptext length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > CTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* cryptext */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* expectedhmac length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > EHMLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* expectedhmac */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* hmacdata length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > CTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* hmacdata */
		goto err;
	if (hexlenl(p, &extra)/2 != len || extra)
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
