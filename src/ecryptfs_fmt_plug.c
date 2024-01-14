/*
 * Cracker for eCryptfs ~/.ecryptfs/wrapped-passphrase.
 *
 * We attack "login passphrase" instead of "mount passphrase" (and which could
 * be 128-bit random key!).
 *
 * "ecryptfs_unwrap_passphrase -> generate_passphrase_sig" in
 * src/libecryptfs/key_management.c is important.
 *
 * Do we need to do full decryption as done in "ecryptfs_unwrap_passphrase"?
 * I believe, 8 bytes of verification data ought to be enough for anybody!
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ecryptfs1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ecryptfs1);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64_convert.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

#define FORMAT_TAG              "$ecryptfs$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)
#define FORMAT_LABEL            "eCryptfs"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA512 " SHA512_ALGORITHM_NAME
#define BENCHMARK_COMMENT       " (65536 iterations)"  // good luck with that!
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define REAL_BINARY_SIZE        8
#define HEX_BINARY_SIZE         (REAL_BINARY_SIZE*2)
#define BINARY_SIZE             64
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512 * 2)
/* We use SSEi_HALF_IN, so can halve SHA_BUF_SIZ */
#undef SHA_BUF_SIZ
#define SHA_BUF_SIZ 8
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS_512(i, index)    ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64 *8 )
#else
#define GETPOS_512(i, index)    ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + ((i)&7) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64 *8 )
#endif
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      2
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

/* Taken from eCryptfs source code */
#define ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS 65536
#define ECRYPTFS_SALT_SIZE 8
#define ECRYPTFS_DEFAULT_SALT "\x00\x11\x22\x33\x44\x55\x66\x77"
#define ECRYPTFS_SIG_SIZE 8

static struct fmt_tests ecryptfs_tests[] = {
	/* hash ==> first 16 bytes of ~/.ecryptfs/wrapped-passphrase */
	{"$ecryptfs$0$92dc3db8feaf1676", "openwall"},
	{"$ecryptfs$0$ccb515ee115be591", "failpassword"},
	{"$ecryptfs$0$8acb10b9e061fcc7", "verylongbutstillfailpassword"},
	/* fake hash to test custom salt handling */
	{"$ecryptfs$0$1$0000000000000000$884ed410cd143bca", "fake"},
	{"$ecryptfs$0$1$544c39674737716a$a8307a01b2d1b008", "fake"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	int iterations; // really really unused (even in the original code)
	int salt_length;
	unsigned char salt[ECRYPTFS_SALT_SIZE + 1];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_align(sizeof(*crypt_out),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
		return 0;

	p = ciphertext + FORMAT_TAG_LENGTH;
	if (*p != '0' || *(p + 1) != '$')
		return 0;

	p += 2;
	if (*p == '1' && *(p + 1) == '$') {
		// handle salted variety
		p += 2;
		if (hexlenl(p, 0) != HEX_BINARY_SIZE || p[HEX_BINARY_SIZE] != '$')
			return 0;
		p += (HEX_BINARY_SIZE+1);
	}

	return hexlenl(p, &extra) == HEX_BINARY_SIZE && !extra;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p, *q;

	memset(&cs, 0, SALT_SIZE);

	p = ciphertext + FORMAT_TAG_LENGTH;
	p = p + 2; // skip over "0$"

	/* support for custom salt */
	if (*p == '1' && *(p + 1) == '$') {
		p = p + 2;
		q = strchr(p, '$');
		cs.salt_length = (q - p) / 2;
		for (i = 0; i < cs.salt_length; i++)
			cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) |
				atoi16[ARCH_INDEX(p[2 * i + 1])];
	} else {
		memcpy(cs.salt, ECRYPTFS_DEFAULT_SALT, ECRYPTFS_SALT_SIZE);
	}

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[REAL_BINARY_SIZE];
		uint64_t dummy;
	} buf;
	unsigned char *out = buf.c;
	int i;
	char *p = strrchr(ciphertext, '$') + 1;

	for (i = 0; i < REAL_BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if defined(SIMD_COEF_64) && !ARCH_LITTLE_ENDIAN
	alter_endianity_w64(out, REAL_BINARY_SIZE>>5);
#endif
	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

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
		int j;
		SHA512_CTX ctx;
#ifdef SIMD_COEF_64
		unsigned char tmpBuf[64];
		unsigned int i;
		unsigned char _IBuf[8*SHA_BUF_SIZ*MIN_KEYS_PER_CRYPT+MEM_ALIGN_CACHE], *keys;
		uint64_t *keys64;

		keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
		keys64 = (uint64_t*)keys;

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, cur_salt->salt, ECRYPTFS_SALT_SIZE);
			SHA512_Update(&ctx, saved_key[index+i], strlen(saved_key[index+i]));
			SHA512_Final((unsigned char *)tmpBuf, &ctx);
			for (j = 0; j < 64; ++j)
				keys[GETPOS_512(j, i)] = tmpBuf[j];
		}
		uint64_t rounds = ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS - 1;
		SIMDSHA512body(keys, keys64, &rounds, SSEi_HALF_IN|SSEi_LOOP);
		// Last one with FLAT_OUT
		SIMDSHA512body(keys, (uint64_t*)crypt_out[index], NULL, SSEi_HALF_IN|SSEi_FLAT_OUT);
#else
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, cur_salt->salt, ECRYPTFS_SALT_SIZE);
		SHA512_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA512_Final((unsigned char *)crypt_out[index], &ctx);
		/* now "h" (crypt_out[index] becomes our input, total SHA-512 calls => 65536 */
		for (j = 1; j <= ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS; j++) {
			SHA512_CTX ctx;
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
			SHA512_Final((unsigned char *)crypt_out[index], &ctx);
		}
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], REAL_BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], REAL_BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void ecryptfs_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_ecryptfs1 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		REAL_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		ecryptfs_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
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
		ecryptfs_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
