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
extern struct fmt_main fmt_rawSHA224;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA224);
#else

#include "arch.h"
#include "sha2.h"
#include "stdint.h"
#include "params.h"
#include "common.h"
#include "johnswap.h"
#include "formats.h"
#include "simd-intrinsics.h"

//#undef SIMD_COEF_32
//#undef SIMD_PARA_SHA256

/*
 * Only effective for SIMD.
 * Undef to disable reversing steps for benchmarking.
 */
#define REVERSE_STEPS

#ifdef _OPENMP
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE			1024
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE			2048
#endif
#endif
#include <omp.h>
#endif
#include "memdbg.h"

#define FORMAT_LABEL            "Raw-SHA224"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$SHA224$"
#define TAG_LENGTH              8

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME			SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " SHA2_LIB
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#else
#define PLAINTEXT_LENGTH		125
#endif
#define CIPHERTEXT_LENGTH       56

#define BINARY_SIZE             DIGEST_SIZE
#define DIGEST_SIZE             28
#define DIGEST_SIZE_256			32
#define BINARY_ALIGN			MEM_ALIGN_WORD
#define SALT_SIZE               0
#define SALT_ALIGN				1

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		(SIMD_COEF_32*SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", "password"},
	{"$SHA224$d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", "password"},
	{"$SHA224$7e6a4309ddf6e8866679f61ace4f621b0e3455ebac2e831a60f13cd1", "12345678"},
	{"$SHA224$d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", ""},
	{"b93ff16271aa688dbf671120817d75b895b874ab2b9bb9f71481d88d", "UPPERCASE"},
	{NULL}
};

#ifdef SIMD_COEF_32
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
static uint32_t (*saved_key);
static uint32_t (*crypt_out);
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)
    [(DIGEST_SIZE + sizeof(ARCH_WORD_32) - 1) / sizeof(ARCH_WORD_32)];
#endif

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
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
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt *
	                             DIGEST_SIZE_256 / sizeof(uint32_t),
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

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LENGTH);
	return out;
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

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef SIMD_COEF_32
	alter_endianity (out, DIGEST_SIZE);
#ifdef REVERSE_STEPS
	sha224_reverse(outw);
#endif
#endif
	return out;
}

#ifdef SIMD_COEF_32
#define HASH_IDX (((unsigned int)index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*8*SIMD_COEF_32 + 3*SIMD_COEF_32)
static int get_hash_0 (int index) { return crypt_out[HASH_IDX] & PH_MASK_0; }
static int get_hash_1 (int index) { return crypt_out[HASH_IDX] & PH_MASK_1; }
static int get_hash_2 (int index) { return crypt_out[HASH_IDX] & PH_MASK_2; }
static int get_hash_3 (int index) { return crypt_out[HASH_IDX] & PH_MASK_3; }
static int get_hash_4 (int index) { return crypt_out[HASH_IDX] & PH_MASK_4; }
static int get_hash_5 (int index) { return crypt_out[HASH_IDX] & PH_MASK_5; }
static int get_hash_6 (int index) { return crypt_out[HASH_IDX] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_out[index][3] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][3] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][3] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][3] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][3] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][3] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][3] & PH_MASK_6; }
#endif

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32*)binary)[3] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32*)binary)[3] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32*)binary)[3] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32*)binary)[3] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32*)binary)[3] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_32*)binary)[3] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_32*)binary)[3] & PH_MASK_6; }

#ifdef SIMD_COEF_32
static void set_key(char *key, int index) {
#if ARCH_ALLOWS_UNALIGNED
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
	const ARCH_WORD_32 *wkey = (uint32_t*)(is_aligned(key, sizeof(uint32_t)) ?
	                                       key : strcpy(buf_aligned, key));
#endif
	ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32 *)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
	while((unsigned char)(temp = *wkey++)) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP(temp | (0x80 << 24));
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP(temp);
		len += 4;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	keybuffer[15*SIMD_COEF_32] = len << 3;
}
#else
static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_len[index] = len;
	if (len > PLAINTEXT_LENGTH)
		len = saved_len[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
}
#endif

#ifdef SIMD_COEF_32
static char *get_key(int index) {
	unsigned int i,s;
	static char out[PLAINTEXT_LENGTH+1];
	unsigned char *wucp = (unsigned char*)saved_key;

	s = ((ARCH_WORD_32 *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] >> 3;
	for(i=0;i<s;i++)
		out[i] = wucp[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
}
#else
static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}
#endif

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
#ifdef SIMD_COEF_32
		SIMDSHA256body(&saved_key[(unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32],
		              &crypt_out[(unsigned int)index/SIMD_COEF_32*8*SIMD_COEF_32],
		              NULL, SSEi_REVERSE_STEPS|SSEi_MIXED_IN|SSEi_CRYPT_SHA224);
#else
		SHA256_CTX ctx;
		SHA224_Init(&ctx);
		SHA224_Update(&ctx, saved_key[index], saved_len[index]);
		SHA224_Final((unsigned char *)crypt_out[index], &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
		if (((ARCH_WORD_32*) binary)[3] == crypt_out[HASH_IDX])
#else
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	return ((ARCH_WORD_32*)binary)[3] == crypt_out[HASH_IDX];
#else
	return *(ARCH_WORD_32*)binary == crypt_out[index][0];
#endif
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD_32 *binary = get_binary(source);
	char *key = get_key(index);
	SHA256_CTX ctx;
	ARCH_WORD_32 crypt_out[DIGEST_SIZE / sizeof(ARCH_WORD_32)];

	SHA224_Init(&ctx);
	SHA224_Update(&ctx, key, strlen(key));
	SHA224_Final((unsigned char*)crypt_out, &ctx);

#ifdef SIMD_COEF_32
	alter_endianity(crypt_out, DIGEST_SIZE);
#ifdef REVERSE_STEPS
	sha224_reverse(crypt_out);
#endif
#endif
	return !memcmp(binary, crypt_out, DIGEST_SIZE);
}

struct fmt_main fmt_rawSHA224 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"SHA224 " ALGORITHM_NAME,
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
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
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
