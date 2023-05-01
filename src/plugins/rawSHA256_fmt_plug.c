/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 *
 * Understands hex hashes as well as Cisco "type 4" base64.
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
extern struct fmt_main fmt_rawSHA256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA256);
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
/*
 * Only effective for SIMD.
 * Undef to disable reversing steps for benchmarking.
 */
#define REVERSE_STEPS
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "Raw-SHA256"
#define FORMAT_NAME             ""

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#endif

/* Note: Cisco hashes are truncated at length 25. We currently ignore this. */
#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH        55
#else
#define PLAINTEXT_LENGTH        125
#endif
#define _RAWSHA256_H
#include "rawSHA256_common.h"
#undef _RAWSHA256_H

#define BINARY_SIZE             4
#define SALT_SIZE               0
#define SALT_ALIGN				1

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT      (64*SIMD_COEF_32*SIMD_PARA_SHA256)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               32 // MKPC and scale tuned for i7
#endif

#ifdef SIMD_COEF_32
#define FMT_IS_BE
#include "common-simd-getpos.h"
static uint32_t (*saved_key);
static uint32_t (*crypt_out);
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)
    [(DIGEST_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifndef SIMD_COEF_32
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
#else
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt * SHA_BUF_SIZ,
	                             sizeof(*saved_key),
	                             MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt * 8,
	                             sizeof(*crypt_out),
	                             MEM_ALIGN_SIMD);
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
#ifndef SIMD_COEF_32
	MEM_FREE(saved_len);
#endif
}

static void *get_binary(char *ciphertext)
{
	static unsigned int *outw;
	unsigned char *out;
	char *p;
	int i;

	if (!outw)
		outw = mem_calloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	out = (unsigned char*)outw;

	p = ciphertext + HEX_TAG_LEN;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN
	alter_endianity (out, DIGEST_SIZE);
#endif
#ifdef REVERSE_STEPS
	sha256_reverse(outw);
#endif
#endif
	return out;
}

#define COMMON_GET_HASH_SIMD32 8
#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

#define HASH_IDX ((((unsigned int)index)&(SIMD_COEF_32-1))+(((unsigned int)index)/SIMD_COEF_32)*SIMD_COEF_32*8)

#define NON_SIMD_SET_SAVED_LEN
#include "common-simd-setkey32.h"

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
#ifdef SIMD_COEF_32
		SIMDSHA256body(&saved_key[(unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32],
		              &crypt_out[(unsigned int)index/SIMD_COEF_32*8*SIMD_COEF_32],
		              NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);
#else
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], saved_len[index]);
		SHA256_Final((unsigned char *)crypt_out[index], &ctx);
#endif
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
		if (((uint32_t*) binary)[0] == crypt_out[HASH_IDX])
#else
		if ( ((uint32_t*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	return ((uint32_t*)binary)[0] == crypt_out[HASH_IDX];
#else
	return *(uint32_t*)binary == crypt_out[index][0];
#endif
}

static int cmp_exact(char *source, int index)
{
	uint32_t *binary = get_binary(source);
	char *key = get_key(index);
	SHA256_CTX ctx;
	uint32_t crypt_out[DIGEST_SIZE / sizeof(uint32_t)];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, key, strlen(key));
	SHA256_Final((unsigned char*)crypt_out, &ctx);

#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN
	alter_endianity(crypt_out, DIGEST_SIZE);
#endif
#ifdef REVERSE_STEPS
	sha256_reverse(crypt_out);
#endif
#endif
	return !memcmp(binary, crypt_out, DIGEST_SIZE);
}

struct fmt_main fmt_rawSHA256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"SHA256 " ALGORITHM_NAME,
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
			HEX_TAG,
			CISCO_TAG
		},
		sha256_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		sha256_common_prepare,
		sha256_common_valid,
		sha256_common_split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
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
