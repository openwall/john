/*
 * Description from Nicolas Ruff:
 * - Salt value is hashed as an hexadecimal string, not bytes.
 * - The trailing NULL byte of password string is taken into account during
 *   hashing.
 * - The leading '1' is actually the string length
 *   '1' = 49 = len('1') + len(hex_salt) + len(hex_sha1)
 *
 * ---------------------------------------
 * import hashlib
 *
 * def netscaler_hash( rand_bytes, pwd ):
 *    s = hashlib.sha1()
 *    s.update( rand_bytes )
 *    s.update( pwd )
 *    return "1" + rand_bytes + s.hexdigest()
 *
 * # TEST VECTOR
 * # 14dfca1e6c0f5f3d96526c3ce70849992b7fad3e324cf6b0f
 *
 * rand_bytes = "4dfca1e6"
 * pwd = "nsroot\x00"
 * print netscaler_hash( rand_bytes, pwd )
 * ---------------------------------------
 *
 * This software is Copyright (c) 2013 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * This version is hard coded for salt length 8 (for speed).
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ctrxns;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ctrxns);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "johnswap.h"

#ifdef SIMD_COEF_32
#define NBKEYS  (SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif
#include "simd-intrinsics.h"
#include "common.h"
#include "sha.h"

#define FORMAT_LABEL                    "Citrix_NS10"
#define FORMAT_NAME                     "Netscaler 10"

#define ALGORITHM_NAME                  "SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                7

#define PLAINTEXT_LENGTH                (55 - SALT_SIZE - 1)

#define BINARY_SIZE                     20
#define BINARY_ALIGN                    4
#define SALT_SIZE                       8
#define SALT_ALIGN                      4

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT              NBKEYS
#define MAX_KEYS_PER_CRYPT              (NBKEYS * 256)
#define FMT_IS_BE
#include "common-simd-getpos.h"
#else
#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT              256
#endif

#ifndef OMP_SCALE
#define OMP_SCALE                       4	// Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"100000000f1dc96f425971ba590a076fd0f8bccbf25c1ba0c", ""},
	{"14623718525fe334bbd9c0704e06ce134ef17b51f6b33548c", " "},
	{"15c5c5c5c6ccd884f6383f55a6aeba5f847775e57ab012675", "Tw"},
	{"13333333319143136ba9ff9e18d1cb022b63df0926de9509e", "333"},
	{"144434241d7ce89a7484cd202400639692258dde37efc29c5", "four"},
	{"100010203e09cefed1847b7a2a5e7a5d2cdc67e8a56ed0bdd", "fiver"},
	{"14dfca1e6c0f5f3d96526c3ce70849992b7fad3e324cf6b0f", "nsroot"},
	{"1deadcafe7587ea23b25a6ccf3fd53192e36ad3e9a2553b20", "magnum!"},
	{NULL}
};

#ifdef SIMD_COEF_32
static unsigned char (*saved_key)[SHA_BUF_SIZ * 4 * NBKEYS];
static unsigned char (*crypt_key)[BINARY_SIZE * NBKEYS];
static unsigned int kpc;
#else
static char saved_salt[SALT_SIZE];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[BINARY_SIZE / 4];
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef SIMD_COEF_32
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt / NBKEYS,
	                       sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt / NBKEYS,
	                       sizeof(*crypt_key), MEM_ALIGN_SIMD);
	kpc = self->params.max_keys_per_crypt;
#else
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#endif
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *realcipher;
	int i, len;

	if (!realcipher)
		realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	len = *ciphertext;

	ciphertext += len - 2 * BINARY_SIZE;

	for (i = 0; i < BINARY_SIZE; i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16
			+ atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	return (void*)realcipher;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int len;

	len = *ciphertext;

	if (len != (int)'1')
		return 0;

	if (strlen(ciphertext) != len)
		return 0;

	if (len != strspn(ciphertext, HEXCHARS_lc))
		return 0;

	return 1;
}

// this is a salt appended format. It also 'keeps' the trailing null byte.
#define SALT_PREPENDED SALT_SIZE
#define INCLUDE_TRAILING_NULL
#include "common-simd-setkey32.h"

static void *get_salt(char *ciphertext)
{
	static union {
		unsigned char c[SALT_SIZE];
		uint32_t w;
	} out;

	ciphertext++;
	memcpy(out.c, ciphertext, SALT_SIZE);

	return (void*)out.c;
}

static void set_salt(void *salt)
{
#ifdef SIMD_COEF_32
	int i, index;

	for (index = 0; index < kpc; index++) {
		int idx = index % NBKEYS;
		unsigned char *sk = saved_key[index/NBKEYS];
		for (i = 0; i < SALT_SIZE; i++)
			sk[GETPOS(i, idx)] = ((unsigned char*)salt)[i];
	}
#else
	memcpy(saved_salt, salt, SALT_SIZE);
#endif
}

static int cmp_all(void *binary, int count)
{
#ifdef SIMD_COEF_32
	unsigned int x, y;

	for (y = 0; y < kpc/SIMD_COEF_32; y++) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			if (((uint32_t*)binary)[0] ==
			   ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32*5])
				return 1;
		}
	}

	return 0;
#else
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_key[index][0])
			return 1;

	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x, y;
	x = index & (SIMD_COEF_32-1);
	y = (unsigned int)index / SIMD_COEF_32;

	if (((uint32_t*)binary)[0] != ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32*5])
		return 0;
	if (((uint32_t*)binary)[1] != ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32*5+SIMD_COEF_32*1])
		return 0;
	if (((uint32_t*)binary)[2] != ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32*5+SIMD_COEF_32*2])
		return 0;
	if (((uint32_t*)binary)[3] != ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32*5+SIMD_COEF_32*3])
		return 0;
	if (((uint32_t*)binary)[4] != ((uint32_t*)crypt_key)[x + y * SIMD_COEF_32*5+SIMD_COEF_32*4])
		return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	int loops = (count + MIN_KEYS_PER_CRYPT - 1) / MIN_KEYS_PER_CRYPT;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < loops; ++index) {
#ifdef SIMD_COEF_32
		SIMDSHA1body(saved_key[index], (unsigned int*)crypt_key[index], NULL, SSEi_MIXED_IN);
#else
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char*)saved_salt, SALT_SIZE);
		SHA1_Update(&ctx, (unsigned char*)saved_key[index], strlen(saved_key[index]) + 1);
		SHA1_Final((unsigned char*)crypt_key[index], &ctx);
#endif
	}

	return count;
}

#define COMMON_GET_HASH_SIMD32 5
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	return *(uint32_t*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_ctrxns = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ NULL },
		tests
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
		salt_hash,
		NULL,
		set_salt,
		set_key,
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
