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

#include "arch.h"
#include "sha2.h"
#include "stdint.h"
#include "params.h"
#include "common.h"
#include "johnswap.h"
#include "formats.h"

//#undef SIMD_COEF_64
//#undef SIMD_PARA_SHA512

/*
 * Only effective for SIMD.
 * Undef to disable reversing steps for benchmarking.
 */
#define REVERSE_STEPS

#ifdef _OPENMP
#ifdef SIMD_COEF_64
#ifndef OMP_SCALE
#define OMP_SCALE               1024
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE				2048
#endif
#endif
#include <omp.h>
#endif
#include "simd-intrinsics.h"
#include "memdbg.h"

#define FORMAT_LABEL		"Raw-SHA512"
#define FORMAT_NAME		""

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          SHA512_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR " " SHA2_LIB
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
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif
#define __RAWSHA512_CREATE_PROPER_TESTS_ARRAY__
#include "rawSHA512_common.h"

#ifdef SIMD_COEF_64
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
static ARCH_WORD_64 (*saved_key);
static ARCH_WORD_64 (*crypt_out);
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_64 (*crypt_out)[DIGEST_SIZE / sizeof(ARCH_WORD_64)];
#endif

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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
	static ARCH_WORD_64 *outw;
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
	alter_endianity_to_BE64(out, DIGEST_SIZE/8);
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

static int binary_hash_0(void *binary) { return ((ARCH_WORD_64*)binary)[0] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_64*)binary)[0] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_64*)binary)[0] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_64*)binary)[0] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_64*)binary)[0] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_64*)binary)[0] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_64*)binary)[0] & PH_MASK_6; }

static void set_key(char *key, int index)
{
#ifdef SIMD_COEF_64
#if ARCH_ALLOWS_UNALIGNED
	const ARCH_WORD_64 *wkey = (ARCH_WORD_64*)key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint64_t));
	const ARCH_WORD_64 *wkey = is_aligned(key, sizeof(uint64_t)) ?
			(ARCH_WORD_64*)key : (ARCH_WORD_64*)strcpy(buf_aligned, key);
#endif
	ARCH_WORD_64 *keybuffer = &((ARCH_WORD_64*)saved_key)[(index&(SIMD_COEF_64-1)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64];
	ARCH_WORD_64 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_64 temp;

	len = 0;
	while((unsigned char)(temp = *wkey++)) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffff) | (0x80ULL << 24));
			len+=3;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffff) | (0x80ULL << 32));
			len+=4;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffULL) | (0x80ULL << 40));
			len+=5;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffffULL) | (0x80ULL << 48));
			len+=6;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffffffULL) | (0x80ULL << 56));
			len+=7;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP64(temp);
		len += 8;
		keybuf_word += SIMD_COEF_64;
	}
	*keybuf_word = 0x8000000000000000ULL;

key_cleaning:
	keybuf_word += SIMD_COEF_64;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_64;
	}
	keybuffer[15*SIMD_COEF_64] = len << 3;
#else
	int len = strlen(key);
	saved_len[index] = len;
	if (len > PLAINTEXT_LENGTH)
		len = saved_len[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
#endif
}

static char *get_key(int index)
{
#ifdef SIMD_COEF_64
	unsigned i;
	ARCH_WORD_64 s;
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned char *wucp = (unsigned char*)saved_key;

	s = ((ARCH_WORD_64*)saved_key)[15*SIMD_COEF_64 + (index&(SIMD_COEF_64-1)) + index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] >> 3;
	for(i = 0; i < (unsigned)s; i++)
		out[i] = wucp[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
#else
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
#endif
}

#ifndef REVERSE_STEPS
#undef SSEi_REVERSE_STEPS
#define SSEi_REVERSE_STEPS 0
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
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
		if (((ARCH_WORD_64*)binary)[0] == crypt_out[HASH_IDX])
#else
		if ( ((ARCH_WORD_64*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
	return ((ARCH_WORD_64*)binary)[0] == crypt_out[HASH_IDX];
#else
	return *(ARCH_WORD_64*)binary == crypt_out[index][0];
#endif
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD_64 *binary = get_binary(source);
	char *key = get_key(index);
	SHA512_CTX ctx;
	ARCH_WORD_64 crypt_out[DIGEST_SIZE / sizeof(ARCH_WORD_64)];

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, key, strlen(key));
	SHA512_Final((unsigned char*)crypt_out, &ctx);

#ifdef SIMD_COEF_64
	alter_endianity_to_BE64(crypt_out, DIGEST_SIZE/8);
#ifdef REVERSE_STEPS
	sha512_reverse(crypt_out);
#endif
#endif
	return !memcmp(binary, crypt_out, DIGEST_SIZE);
}

/*
 * The '0_' makes sure this format registers before others,
 * if ambigous.  Do not copy it for other formats.
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
		sha512_common_tests
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
