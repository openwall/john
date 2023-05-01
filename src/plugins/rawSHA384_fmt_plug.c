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
extern struct fmt_main fmt_rawSHA384;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA384);
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
#define REVERSE_STEPS
#include "simd-intrinsics.h"

#define FORMAT_LABEL		"Raw-SHA384"
#define FORMAT_NAME		""
#define FORMAT_TAG              "$SHA384$"

#define TAG_LENGTH             (sizeof(FORMAT_TAG) - 1)

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          SHA512_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#ifdef SIMD_COEF_64
#define PLAINTEXT_LENGTH        111
#else
#define PLAINTEXT_LENGTH        125
#endif
#define CIPHERTEXT_LENGTH		96

#define BINARY_SIZE				DIGEST_SIZE
#define DIGEST_SIZE				48
#define DIGEST_SIZE_512			64
#define BINARY_ALIGN			8
#define SALT_SIZE				0
#define SALT_ALIGN				1

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT		(SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512 * 256)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		256
#endif

#ifndef OMP_SCALE
#define OMP_SCALE				4 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", "password"},
	{"$SHA384$a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", "password"},
	{"$SHA384$8cafed2235386cc5855e75f0d34f103ccc183912e5f02446b77c66539f776e4bf2bf87339b4518a7cb1c2441c568b0f8", "12345678"},
	{"$SHA384$38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", ""},
	{"94e75dd8e1f16d7df761d76c021ad98c283791008b98368e891f411fc5aa1a83ef289e348abdecf5e1ba6971604a0cb0", "UPPERCASE"},
	{"47f05d367b0c32e438fb63e6cf4a5f35c2aa2f90dc7543f8a41a0f95ce8a40a313ab5cf36134a2068c4c969cb50db776", "1"},
	{"1e237288d39d815abc653befcab0eb70966558a5bbc10a24739c116ed2f615be31e81670f02af48fe3cf5112f0fa03e8", "12"},
	{"9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f", "123"},
	{"504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c", "1234"},
	{"0fa76955abfa9dafd83facca8343a92aa09497f98101086611b0bfa95dbc0dcc661d62e9568a5a032ba81960f3e55d4a", "12345"},
	{"0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454", "123456"},
	{"826227b9dfb593ae4ddbd3f5b7e24b6cb92e342c951cce56546fa68a2e56557b5ebac824a5e778438a7f35c985dfe082", "1234567"},
	{"8cafed2235386cc5855e75f0d34f103ccc183912e5f02446b77c66539f776e4bf2bf87339b4518a7cb1c2441c568b0f8", "12345678"},
	{"eb455d56d2c1a69de64e832011f3393d45f3fa31d6842f21af92d2fe469c499da5e3179847334a18479c8d1dedea1be3", "123456789"},
	{NULL}
};

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
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt *
	                             DIGEST_SIZE_512 / sizeof(uint64_t),
	                             sizeof(*crypt_out),
	                             MEM_ALIGN_SIMD);
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

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

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
	memcpylwr(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

void *get_binary(char *ciphertext)
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
	sha384_reverse(outw);
#endif
#endif
	return out;
}

#ifdef SIMD_COEF_64
#define HASH_IDX (((unsigned int)index&(SIMD_COEF_64-1))+(unsigned int)index/SIMD_COEF_64*8*SIMD_COEF_64 + 3*SIMD_COEF_64)
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

static int binary_hash_0(void *binary) { return ((uint64_t*)binary)[3] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((uint64_t*)binary)[3] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((uint64_t*)binary)[3] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((uint64_t*)binary)[3] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((uint64_t*)binary)[3] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((uint64_t*)binary)[3] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((uint64_t*)binary)[3] & PH_MASK_6; }

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
		              NULL, SSEi_REVERSE_STEPS|SSEi_MIXED_IN|SSEi_CRYPT_SHA384);
#else
		SHA512_CTX ctx;
		SHA384_Init(&ctx);
		SHA384_Update(&ctx, saved_key[index], saved_len[index]);
		SHA384_Final((unsigned char *)crypt_out[index], &ctx);
#endif
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_64
		if (((uint64_t*)binary)[3] == crypt_out[HASH_IDX])
#else
		if ( ((uint64_t*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
	return ((uint64_t*)binary)[3] == crypt_out[HASH_IDX];
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

	SHA384_Init(&ctx);
	SHA384_Update(&ctx, key, strlen(key));
	SHA384_Final((unsigned char*)crypt_out, &ctx);

#ifdef SIMD_COEF_64
#if ARCH_LITTLE_ENDIAN==1
	alter_endianity_to_BE64(crypt_out, DIGEST_SIZE/8);
#endif
#ifdef REVERSE_STEPS
	sha384_reverse(crypt_out);
#endif
#endif
	return !memcmp(binary, crypt_out, DIGEST_SIZE);
}

struct fmt_main fmt_rawSHA384 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		"SHA384 " ALGORITHM_NAME,
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
		{ FORMAT_TAG },
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
