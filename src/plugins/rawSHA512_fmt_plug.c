/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 *
 * Rewritten Spring 2013, JimF. SSE code added and released with the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2011 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_raw0_SHA512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_raw0_SHA512);
#else

#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "params.h"
#include "common.h"
#include "johnswap.h"
#include "formats.h"
#include "rawSHA512_common.h"
/*
 * Only effective for SIMD.
 * Undef to disable reversing steps for benchmarking.
 */
#define REVERSE_STEPS
#include "simd-intrinsics.h"

#define FORMAT_LABEL		"Raw-SHA512"
#define FORMAT_NAME		""

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          SHA512_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#endif

#ifdef SIMD_COEF_64
#define PLAINTEXT_LENGTH        111
#else
#define PLAINTEXT_LENGTH        125
#endif

#define BINARY_SIZE				8

#define SALT_SIZE				0
#define SALT_ALIGN				1

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT		(SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (64*SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		64
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               4 // MKPC and scale tuned for i7
#endif

#ifdef SIMD_COEF_64
#define FMT_IS_64BIT
#define FMT_IS_BE
#include "common-simd-getpos.h"
static uint64_t (*saved_key);
static uint64_t (*crypt_out);
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint64_t (*crypt_out)[DIGEST_SIZE / sizeof(uint64_t)];
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifndef SIMD_COEF_64
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
#else
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt * SHA_BUF_SIZ,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt * 8,
	                             sizeof(*crypt_out), MEM_ALIGN_SIMD);
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
#ifndef SIMD_COEF_64
	MEM_FREE(saved_len);
#endif
}

static void *get_binary(char *ciphertext)
{
	static uint64_t *outw;
	unsigned char *out;
	char *p;
	int i;

	if (!outw)
		outw = mem_calloc_tiny(DIGEST_SIZE, BINARY_ALIGN);

	out = (unsigned char*)outw;

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef SIMD_COEF_64
#if ARCH_LITTLE_ENDIAN==1
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
#endif
#ifdef REVERSE_STEPS
	sha512_reverse(outw);
#endif
#endif
	return out;
}

#ifdef SIMD_COEF_64
#define HASH_IDX (((unsigned int)index&(SIMD_COEF_64-1))+(unsigned int)index/SIMD_COEF_64*8*SIMD_COEF_64)
static int get_hash_0 (int index) { return crypt_out[HASH_IDX] & PH_MASK_0; }
static int get_hash_1 (int index) { return crypt_out[HASH_IDX] & PH_MASK_1; }
static int get_hash_2 (int index) { return crypt_out[HASH_IDX] & PH_MASK_2; }
static int get_hash_3 (int index) { return crypt_out[HASH_IDX] & PH_MASK_3; }
static int get_hash_4 (int index) { return crypt_out[HASH_IDX] & PH_MASK_4; }
static int get_hash_5 (int index) { return crypt_out[HASH_IDX] & PH_MASK_5; }
static int get_hash_6 (int index) { return crypt_out[HASH_IDX] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }
#endif

static int binary_hash_0(void *binary) { return ((uint64_t*)binary)[0] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((uint64_t*)binary)[0] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((uint64_t*)binary)[0] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((uint64_t*)binary)[0] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((uint64_t*)binary)[0] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((uint64_t*)binary)[0] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((uint64_t*)binary)[0] & PH_MASK_6; }

#define NON_SIMD_SET_SAVED_LEN
#include "common-simd-setkey64.h"

#ifndef REVERSE_STEPS
#undef SSEi_REVERSE_STEPS
#define SSEi_REVERSE_STEPS SSEi_NO_OP
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_64
		SIMDSHA512body(&saved_key[index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64],
		              &crypt_out[index/SIMD_COEF_64*8*SIMD_COEF_64],
		              NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);
#else
		SHA512_CTX ctx;
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, saved_key[index], saved_len[index]);
		SHA512_Final((unsigned char *)crypt_out[index], &ctx);
#endif
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_64
		if (((uint64_t*)binary)[0] == crypt_out[HASH_IDX])
#else
		if ( ((uint64_t*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
	return ((uint64_t*)binary)[0] == crypt_out[HASH_IDX];
#else
	return *(uint64_t*)binary == crypt_out[index][0];
#endif
}

static int cmp_exact(char *source, int index)
{
	uint64_t *binary = get_binary(source);
	char *key = get_key(index);
	SHA512_CTX ctx;
	uint64_t crypt_out[DIGEST_SIZE / sizeof(uint64_t)];

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, key, strlen(key));
	SHA512_Final((unsigned char*)crypt_out, &ctx);

#ifdef SIMD_COEF_64
#if ARCH_LITTLE_ENDIAN==1
	alter_endianity_to_BE64(crypt_out, DIGEST_SIZE/8);
#endif
#ifdef REVERSE_STEPS
	sha512_reverse(crypt_out);
#endif
#endif
	return !memcmp(binary, crypt_out, DIGEST_SIZE);
}

/*
 * The '0_' makes sure this format registers before others,
 * if ambiguous.  Do not copy it for other formats.
 */
struct fmt_main fmt_raw0_SHA512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"SHA512 " ALGORITHM_NAME,
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_OMP_BAD |
		FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		{
			FORMAT_TAG,
			XSHA512_FORMAT_TAG,
			NSLDAP_FORMAT_TAG
		},
		sha512_common_tests_rawsha512_111
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		sha512_common_valid,
		sha512_common_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
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
