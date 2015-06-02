/* Cracker for eCryptfs ~/.ecryptfs/wrapped-passphrase.
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
#include <errno.h>
#include "sha2.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64_convert.h"
#include "johnswap.h"
#include "sse-intrinsics.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               8 // XXX
#endif
#endif
#include "memdbg.h"

//#undef SIMD_COEF_64

#define FORMAT_TAG 		"$ecryptfs$"
#define FORMAT_TAG_LENGTH	(sizeof(FORMAT_TAG) - 1)
#define FORMAT_LABEL 		"eCryptfs"
#define FORMAT_NAME 		""
#define ALGORITHM_NAME 		"SHA512 " SHA512_ALGORITHM_NAME
#define BENCHMARK_COMMENT	" (65536x)"  // good luck with that!
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	125
#define REAL_BINARY_SIZE	8
#define HEX_BINARY_SIZE     (REAL_BINARY_SIZE*2)
#define BINARY_SIZE		64
#define BINARY_ALIGN		4
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT		(SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define GETPOS_512(i, index)    ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64 *8 )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

/* taken from eCryptfs */
#define ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS 65536
#define ECRYPTFS_MAX_PASSWORD_LENGTH 64
#define ECRYPTFS_MAX_PASSPHRASE_BYTES ECRYPTFS_MAX_PASSWORD_LENGTH
#define ECRYPTFS_SALT_SIZE 8
#define ECRYPTFS_SALT_SIZE_HEX (ECRYPTFS_SALT_SIZE*2)
#define ECRYPTFS_DEFAULT_SALT "\x00\x11\x22\x33\x44\x55\x66\x77"
#define ECRYPTFS_DEFAULT_SALT_HEX "0011223344556677"
#define ECRYPTFS_DEFAULT_SALT_FNEK_HEX "9988776655443322"
#define ECRYPTFS_SIG_SIZE 8
#define ECRYPTFS_SIG_SIZE_HEX (ECRYPTFS_SIG_SIZE*2)
#define ECRYPTFS_PASSWORD_SIG_SIZE ECRYPTFS_SIG_SIZE_HEX
#define ECRYPTFS_MAX_KEY_BYTES 64
#define ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES 512
#define ECRYPTFS_DEFAULT_IV_BYTES 16

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
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int iterations; // really really unused (even in the original code)
	int salt_length;
	char unsigned salt[ECRYPTFS_SALT_SIZE + 1];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
		return 0;

	p = ciphertext + FORMAT_TAG_LENGTH;
	if (*p != '0' || *(p + 1) != '$')
		return 0;

	p += 2;
	if (*p == '1' && *(p + 1) == '$') {
		// handle salted variety
		p += 2;
		if (base64_valid_length(p, e_b64_hex, flg_Base64_NO_FLAGS) != HEX_BINARY_SIZE || p[HEX_BINARY_SIZE] != '$')
			return 0;
		p += (HEX_BINARY_SIZE+1);
	}

	return base64_valid_length(p, e_b64_hex, flg_Base64_NO_FLAGS) == HEX_BINARY_SIZE;
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
		ARCH_WORD_32 dummy;
	} buf;
	unsigned char *out = buf.c;
	int i;
	char *p = strrchr(ciphertext, '$') + 1;

	for (i = 0; i < REAL_BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
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
		int j;
		SHA512_CTX ctx;
#ifdef SIMD_COEF_64
		unsigned char tmpBuf[64];
		unsigned int i;
		unsigned char _IBuf[128*MAX_KEYS_PER_CRYPT+MEM_ALIGN_CACHE], *keys;
		ARCH_WORD_64 *keys64;

		keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
		keys64 = (ARCH_WORD_64*)keys;
		memset(keys, 0, 128*MAX_KEYS_PER_CRYPT);

		for (i = 0; i < MAX_KEYS_PER_CRYPT; ++i) {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, cur_salt->salt, ECRYPTFS_SALT_SIZE);
			SHA512_Update(&ctx, saved_key[index+i], strlen(saved_key[index+i]));
			SHA512_Final((unsigned char *)tmpBuf, &ctx);
			for (j = 0; j < 64; ++j)
				keys[GETPOS_512(j, i)] = tmpBuf[j];
			keys[GETPOS_512(j, i)] = 0x80;
			// 64 bytes of crypt data (0x200 bits).
			keys[GETPOS_512(126, i)] = 0x02;
		}
		for (j = 1; j < ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS; j++)
			SSESHA512body(keys, keys64, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);
		// Last one with FLAT_OUT
		SSESHA512body(keys, (ARCH_WORD_64*)crypt_out[index], NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT|SSEi_FLAT_OUT);
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
	int index = 0;
	for (; index < count; index++)
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		ecryptfs_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
