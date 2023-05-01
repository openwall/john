/*
 * SL3 unlocking. Password is always 15 digits. Run with "-mask=?d"
 *
 * Input format (IMEI is put in "login field"):
 *   IMEI:hash
 *
 * IMEI is 14 or 15 digits 0-9 (only 14 are used)
 * hash is hex lowercase (0-9, a-f)
 *
 * Copyright (c) 2017 magnum.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sl3;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sl3);
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
#include "simd-intrinsics.h"
#include "common.h"
#include "sha.h"
#include "sl3_common.h"
#include "base64_convert.h"

#define FORMAT_LABEL        "SL3"
#define ALGORITHM_NAME      "SHA1 " SHA1_ALGORITHM_NAME
#define BENCHMARK_LENGTH    15

#ifdef SIMD_COEF_32
#define NBKEYS	(SIMD_COEF_32 * SIMD_PARA_SHA1)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)    ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianity conversion
#else
#define GETPOS(i, index)    ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianity conversion
#endif
#define MIN_KEYS_PER_CRYPT  NBKEYS
#define MAX_KEYS_PER_CRYPT  (NBKEYS * 256)
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  256
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           8 // Tuned w/ MKPC for core i7
#endif

static unsigned char *saved_salt;

#ifdef SIMD_COEF_32
static uint32_t (*saved_key)[SHA_BUF_SIZ*NBKEYS];
static uint32_t (*crypt_key)[BINARY_SIZE/4*NBKEYS];
static unsigned int *saved_len;
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[BINARY_SIZE / 4];
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifndef SIMD_COEF_32
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#else
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
#endif
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
#ifdef SIMD_COEF_32
	MEM_FREE(saved_len);
#endif
}

static void *get_binary(char *ciphertext) {
	static char *out;

	if (!out)
		out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	ciphertext += SL3_MAGIC_LENGTH + 14 + 1;
	memset(out, 0, BINARY_SIZE);
	base64_convert(ciphertext, e_b64_hex, 2 * BINARY_SIZE,
	               out, e_b64_raw, BINARY_SIZE, 0, 0);
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity((unsigned char*)out, BINARY_SIZE);
#endif
	return (void*)out;
}

/* set_key() just fills saved_key[index][n] with key[n] - '0' */
static void set_key(char *_key, int index)
{
#ifdef SIMD_COEF_32
	char key[PLAINTEXT_LENGTH + 1];
	char *d = key;
	int i = PLAINTEXT_LENGTH;
#if ARCH_ALLOWS_UNALIGNED
	const uint32_t *wkey = (uint32_t*)key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
	const uint32_t *wkey = (uint32_t*)(is_aligned(key, sizeof(uint32_t)) ?
	                                       key : strcpy(buf_aligned, key));
#endif
	uint32_t *keybuffer = &((uint32_t*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
	uint32_t *keybuf_word = keybuffer;

/*
 * FIXME: Can we do this more efficiently? Perhaps using SIMD and 0x30303030.
 */
	do {
		*d++ = *_key++ - '0';
	} while (i--);

#if ARCH_LITTLE_ENDIAN==1
	*keybuf_word = JOHNSWAP(*wkey++);
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = JOHNSWAP(*wkey++);
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = JOHNSWAP(*wkey++);
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = JOHNSWAP(*wkey);
#else
	*keybuf_word = *wkey++;
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = *wkey++;
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = *wkey++;
	keybuf_word += SIMD_COEF_32;
	*keybuf_word = *wkey;
#endif

#else
	char *d = saved_key[index];
	int i = PLAINTEXT_LENGTH;

	do {
		*d++ = *_key++ - '0';
	} while (i--);
#endif
}

/* ...and get_key() reverses the (- '0'). */
static char *get_key(int index) {
	static char out[PLAINTEXT_LENGTH + 1];
#ifdef SIMD_COEF_32
	unsigned int i;

	for (i = 0; i < PLAINTEXT_LENGTH; i++)
		out[i] = ((char*)saved_key)[GETPOS(i, index)] + '0';
	out[PLAINTEXT_LENGTH] = 0;
#else
	char *s = saved_key[index], *d = out;
	int i = PLAINTEXT_LENGTH;

	while (i--) {
		*d++ = *s++ + '0';
	};
	*d = 0;
#endif

	return out;
}

static int cmp_all(void *binary, int count) {
	unsigned int index;

	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
        if (((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + index/SIMD_COEF_32*5*SIMD_COEF_32])
#else
		if ( ((uint32_t*)binary)[0] == ((uint32_t*)&(crypt_key[index][0]))[0] )
#endif
			return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(uint32_t); i++)
        if (((uint32_t*)binary)[i] != ((uint32_t*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32+i*SIMD_COEF_32])
            return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static void set_salt(void *salt) {
	saved_salt = salt;
}

#ifdef SIMD_COEF_32
inline static void set_onesalt(int index)
{
	unsigned int i, idx = index % NBKEYS;
	unsigned char *sk = (unsigned char*)&saved_key[index / NBKEYS];

	for (i = 0; i < SALT_SIZE; ++i)
		sk[GETPOS(PLAINTEXT_LENGTH + i, idx)] = saved_salt[i];
	sk[GETPOS(PLAINTEXT_LENGTH + SALT_SIZE, idx)] = 0x80;

	((unsigned int*)sk)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + idx/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = (PLAINTEXT_LENGTH + SALT_SIZE) << 3;
}
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
		unsigned int i;

		for (i=0;i<NBKEYS;i++)
			set_onesalt(i + index);
		SIMDSHA1body(saved_key[index/NBKEYS], crypt_key[index/NBKEYS], NULL, SSEi_MIXED_IN);
#else
		SHA_CTX ctx;
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, (unsigned char*)saved_key[index], PLAINTEXT_LENGTH);
		SHA1_Update( &ctx, (unsigned char*)saved_salt, SALT_SIZE);
		SHA1_Final( (unsigned char*)crypt_key[index], &ctx);
#endif
	}

	return count;
}

#define COMMON_GET_HASH_SIMD32 5
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_sl3 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_MINLEN,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_OMP | FMT_OMP_BAD,
		{ NULL },
		{ SL3_MAGIC },
		sl3_tests
	}, {
		init,
		done,
		fmt_default_reset,
		sl3_prepare,
		sl3_valid,
		fmt_default_split,
		get_binary,
		sl3_get_salt,
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
		sl3_salt_hash,
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
