/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2008,2011 by Solar Designer
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_XSHA512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_XSHA512);
#else

#include "sha2.h"

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "simd-intrinsics.h"

//#undef SIMD_COEF_64

#ifdef _OPENMP
#include <omp.h>
#ifdef SIMD_COEF_64
#ifndef OMP_SCALE
#define OMP_SCALE               4096
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               8192
#endif
#endif
#endif

#include "memdbg.h"

#define FORMAT_LABEL			"xsha512"
#define FORMAT_NAME			"Mac OS X 10.7"
#define ALGORITHM_NAME			"SHA512 " SHA512_ALGORITHM_NAME

#define PLAINTEXT_LENGTH		107

#define SALT_SIZE			4
#define SALT_ALIGN			sizeof(ARCH_WORD_32)

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#if ARCH_BITS >= 64 || defined(__SSE2__)
/* 64-bitness happens to correlate with faster memcpy() */
#define PRECOMPUTE_CTX_FOR_SALT
#else
#undef PRECOMPUTE_CTX_FOR_SALT
#endif

#define __XSHA512_CREATE_PROPER_TESTS_ARRAY__
#include "rawSHA512_common.h"

#define BINARY_SIZE				DIGEST_SIZE

#ifdef SIMD_COEF_64
#define GETPOS(i, index)        ( (index&(SIMD_COEF_64-1))*8 + ((i)&(0xffffffff-7))*SIMD_COEF_64 + (7-((i)&7)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64*8 )
static ARCH_WORD_64 (*saved_key)[SHA_BUF_SIZ*MAX_KEYS_PER_CRYPT];
static ARCH_WORD_64 (*crypt_out);
static int max_keys;
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static ARCH_WORD_32 (*crypt_out)[16];
#ifdef PRECOMPUTE_CTX_FOR_SALT
static SHA512_CTX ctx_salt;
#else
static ARCH_WORD_32 saved_salt;
#endif
#endif


static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef SIMD_COEF_64
#ifndef _OPENMP
	int omp_t = 1;
#endif
	saved_key = mem_calloc_align(omp_t, sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_align(self->params.max_keys_per_crypt,
	                             8 * sizeof(ARCH_WORD_64), MEM_ALIGN_SIMD);
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
		ARCH_WORD_32 dummy;
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
	return *(ARCH_WORD_32 *)salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
#ifndef SIMD_COEF_64
#ifdef PRECOMPUTE_CTX_FOR_SALT
	SHA512_Init(&ctx_salt);
	SHA512_Update(&ctx_salt, salt, SALT_SIZE);
#else
	saved_salt = *(ARCH_WORD_32 *)salt;
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

static void set_key(char *key, int index)
{
#ifndef SIMD_COEF_64
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	saved_len[index] = length;
	memcpy(saved_key[index], key, length);
#else
	// ok, first 4 bytes (if there are that many or more), we handle one offs.
	// this is because we already have 4 byte salt loaded into our saved_key.
	// IF there are more bytes of password, we drop into the multi loader.
#if ARCH_ALLOWS_UNALIGNED
	const ARCH_WORD_64 *wkey = (ARCH_WORD_64*)&(key[4]);
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint64_t));
	const ARCH_WORD_64 *wkey = is_aligned(key+4, sizeof(uint64_t)) ?
			(ARCH_WORD_64*)(key+4) : (ARCH_WORD_64*)strcpy(buf_aligned, key+4);
#endif
	ARCH_WORD_64 *keybuffer = &((ARCH_WORD_64 *)saved_key)[(index&(SIMD_COEF_64-1)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64];
	ARCH_WORD_64 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_64 temp;
	unsigned char *wucp = (unsigned char*)saved_key;
	len = 4;
	if (key[0] == 0) {wucp[GETPOS(4, index)] = 0x80; wucp[GETPOS(5, index)] = wucp[GETPOS(6, index)] = wucp[GETPOS(7, index)] = 0; goto key_cleaning; }
	wucp[GETPOS(4, index)] = key[0];
	++len;
	if (key[1] == 0) {wucp[GETPOS(5, index)] = 0x80; wucp[GETPOS(6, index)] = wucp[GETPOS(7, index)] = 0; goto key_cleaning; }
	wucp[GETPOS(5, index)] = key[1];
	++len;
	if (key[2] == 0) {wucp[GETPOS(6, index)] = 0x80; wucp[GETPOS(7, index)] = 0; goto key_cleaning; }
	wucp[GETPOS(6, index)] = key[2];
	++len;
	if (key[3] == 0) {wucp[GETPOS(7, index)] = 0x80; goto key_cleaning; }
	wucp[GETPOS(7, index)] = key[3];
	++len;
	keybuf_word += SIMD_COEF_64;
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
#endif
}

static char *get_key(int index)
{
#ifndef SIMD_COEF_64
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
#else
	static unsigned char key[PLAINTEXT_LENGTH+1];
	int i;
	unsigned char *wucp = (unsigned char*)saved_key;
	ARCH_WORD_64 *keybuffer = &((ARCH_WORD_64*)saved_key)[(index&(SIMD_COEF_64-1)) + (unsigned int)index/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64];
	int len = (keybuffer[15*SIMD_COEF_64] >> 3) - SALT_SIZE;

	for (i = 0; i < len; ++i)
		key[i] = wucp[GETPOS(SALT_SIZE + i, index)];
	key[i] = 0;
	return (char*)key;
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#ifndef SIMD_COEF_64
#ifdef PRECOMPUTE_CTX_FOR_SALT
#pragma omp parallel for default(none) private(index) shared(ctx_salt, saved_key, saved_len, crypt_out)
#else
#pragma omp parallel for default(none) private(index) shared(saved_salt, saved_key, saved_len, crypt_out)
#endif
#else
#pragma omp parallel for
#endif
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT) {
#ifdef SIMD_COEF_64
		SIMDSHA512body(&saved_key[index/MAX_KEYS_PER_CRYPT], &crypt_out[HASH_IDX], NULL, SSEi_MIXED_IN);
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
        if (((ARCH_WORD_64 *) binary)[0] == crypt_out[HASH_IDX])
#else
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_64
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(ARCH_WORD_64); i++)
        if (((ARCH_WORD_64*) binary)[i] != crypt_out[HASH_IDX + i*SIMD_COEF_64])
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
		sha512_common_tests_xsha512
	}, {
		init,
		done,
		fmt_default_reset,
		sha512_common_prepare_xsha,
		sha512_common_valid_xsha,
		sha512_common_split_xsha,
		sha512_common_binary_xsha,
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
