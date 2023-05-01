/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2008,2011 by Solar Designer
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_XSHA512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_XSHA512);
#else

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "simd-intrinsics.h"
#include "rawSHA512_common.h"

#define FORMAT_LABEL			"xsha512"
#define FORMAT_NAME			"Mac OS X 10.7"
#define ALGORITHM_NAME			"SHA512 " SHA512_ALGORITHM_NAME

#define PLAINTEXT_LENGTH		107

#define SALT_SIZE			4
#define SALT_ALIGN			sizeof(uint32_t)

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512 * 512)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		512
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

#if ARCH_BITS >= 64 || defined(__SSE2__)
/* 64-bitness happens to correlate with faster memcpy() */
#define PRECOMPUTE_CTX_FOR_SALT
#else
#undef PRECOMPUTE_CTX_FOR_SALT
#endif

#define BINARY_SIZE				DIGEST_SIZE

#ifdef SIMD_COEF_64
#define FMT_IS_64BIT
#define FMT_IS_BE
#include "common-simd-getpos.h"
static uint64_t (*saved_key)[SHA_BUF_SIZ*SIMD_COEF_64*SIMD_PARA_SHA512];
static uint64_t (*crypt_out);
static int max_keys;
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static uint32_t (*crypt_out)[DIGEST_SIZE/sizeof(uint32_t)];
#ifdef PRECOMPUTE_CTX_FOR_SALT
static SHA512_CTX ctx_salt;
#else
static uint32_t saved_salt;
#endif
#endif


static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef SIMD_COEF_64
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                             8 * sizeof(uint64_t), MEM_ALIGN_SIMD);
	max_keys = self->params.max_keys_per_crypt;
#else
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
#ifndef SIMD_COEF_64
	MEM_FREE(saved_len);
#endif
	MEM_FREE(saved_key);
}

static void *get_salt(char *ciphertext)
{
	static union {
		unsigned char c[SALT_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	ciphertext += XSHA512_TAG_LENGTH;
	p = ciphertext;
	for (i = 0; i < sizeof(buf.c); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

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
static int binary_hash_0 (void *p) { return *((uint64_t*)p) & PH_MASK_0; }
static int binary_hash_1 (void *p) { return *((uint64_t*)p) & PH_MASK_1; }
static int binary_hash_2 (void *p) { return *((uint64_t*)p) & PH_MASK_2; }
static int binary_hash_3 (void *p) { return *((uint64_t*)p) & PH_MASK_3; }
static int binary_hash_4 (void *p) { return *((uint64_t*)p) & PH_MASK_4; }
static int binary_hash_5 (void *p) { return *((uint64_t*)p) & PH_MASK_5; }
static int binary_hash_6 (void *p) { return *((uint64_t*)p) & PH_MASK_6; }
#else
static int get_hash_0(int index) { return crypt_out[index][0] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_out[index][0] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_out[index][0] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_out[index][0] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_out[index][0] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_out[index][0] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_out[index][0] & PH_MASK_6; }
#endif

static int salt_hash(void *salt)
{
	return *(uint32_t *)salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
#ifndef SIMD_COEF_64
#ifdef PRECOMPUTE_CTX_FOR_SALT
	SHA512_Init(&ctx_salt);
	SHA512_Update(&ctx_salt, salt, SALT_SIZE);
#else
	saved_salt = *(uint32_t *)salt;
#endif
#else
	int i;
	unsigned char *wucp = (unsigned char*)saved_key;
	for (i = 0; i < max_keys; ++i) {
		wucp[GETPOS(0, i)] = ((char*)salt)[0];
		wucp[GETPOS(1, i)] = ((char*)salt)[1];
		wucp[GETPOS(2, i)] = ((char*)salt)[2];
		wucp[GETPOS(3, i)] = ((char*)salt)[3];
	}
#endif
}

#define SALT_PREPENDED SALT_SIZE
#define NON_SIMD_SET_SAVED_LEN
#include "common-simd-setkey64.h"

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;

#ifdef _OPENMP
#ifndef SIMD_COEF_64
#ifdef PRECOMPUTE_CTX_FOR_SALT
#pragma omp parallel for default(none) private(index) shared(count, ctx_salt, saved_key, saved_len, crypt_out)
#else
#pragma omp parallel for default(none) private(index) shared(count, saved_salt, saved_key, saved_len, crypt_out)
#endif
#else
#pragma omp parallel for
#endif
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_64
		SIMDSHA512body(&saved_key[index/MIN_KEYS_PER_CRYPT], &crypt_out[HASH_IDX], NULL, SSEi_MIXED_IN);
#else
		SHA512_CTX ctx;
#ifdef PRECOMPUTE_CTX_FOR_SALT
		memcpy(&ctx, &ctx_salt, sizeof(ctx));
#else
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, &saved_salt, SALT_SIZE);
#endif
		SHA512_Update(&ctx, saved_key[index], saved_len[index]);
		SHA512_Final((unsigned char *)(crypt_out[index]), &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_64
        if (((uint64_t *) binary)[0] == crypt_out[HASH_IDX])
#else
		if ( ((uint32_t*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(uint64_t); i++)
        if (((uint64_t*) binary)[i] != crypt_out[HASH_IDX + i*SIMD_COEF_64])
            return 0;
	return 1;
#else
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_XSHA512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		XSHA512_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{ NULL },
		{ XSHA512_FORMAT_TAG },
		sha512_common_tests_xsha512
	}, {
		init,
		done,
		fmt_default_reset,
		sha512_common_prepare_xsha512,
		sha512_common_valid_xsha512,
		sha512_common_split_xsha512,
		sha512_common_binary_xsha512,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
#ifdef SIMD_COEF_64
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
#else
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
#endif
		},
		salt_hash,
		NULL,
		set_salt,
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
