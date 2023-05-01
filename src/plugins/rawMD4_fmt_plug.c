/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * Copyright (c) 2011, 2012 by magnum
 *
 * Use of Bartavelle's mmx/sse2/intrinsics and reduced binary size by
 * magnum in 2011-2012.
 *
 * OMP added May 2013, JimF
 * BE SIMD logic added 2017, JimF
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawMD4;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawMD4);
#else

#include <string.h>

#include "arch.h"


#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "md4.h"
#include "common.h"
#include "johnswap.h"
#include "formats.h"
#define REVERSE_STEPS
#include "simd-intrinsics.h"

#ifndef OMP_SCALE
#define OMP_SCALE				16
#endif

#define FORMAT_LABEL			"Raw-MD4"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"MD4 " MD4_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD4)
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107
#ifndef MD4_BUF_SIZ
#define MD4_BUF_SIZ				16
#endif

#define CIPHERTEXT_LENGTH		32

#define DIGEST_SIZE				16
#define BINARY_SIZE				DIGEST_SIZE
#define BINARY_ALIGN			4
#define SALT_SIZE				0
#define SALT_ALIGN				1

#define FORMAT_TAG				"$MD4$"
#define TAG_LENGTH				(sizeof(FORMAT_TAG) - 1)

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{FORMAT_TAG "6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"6D78785C44EA8DFA178748B245D8C3AE", "magnum" },
	{FORMAT_TAG "31d6cfe0d16ae931b73c59d7e0c089c0", "" },
	{FORMAT_TAG "934eb897904769085af8101ad9dabca2", "John the ripper" },
	{FORMAT_TAG "cafbb81fb64d9dd286bc851c4c6e0d21", "lolcode" },
	{FORMAT_TAG "585028aa0f794af812ee3be8804eb14a", "123456" },
	{FORMAT_TAG "23580e2a459f7ea40f9efa148b63cafb", "12345" },
	{FORMAT_TAG "2ae523785d0caf4d2fb557c12016185c", "123456789" },
	{FORMAT_TAG "f3e80e83b29b778bc092bf8a7c6907fe", "iloveyou" },
	{FORMAT_TAG "4d10a268a303379f224d8852f2d13f11", "princess" },
	{FORMAT_TAG "bf75555ca19051f694224f2f5e0b219d", "1234567" },
	{FORMAT_TAG "41f92cf74e3d2c3ba79183629a929915", "rockyou" },
	{FORMAT_TAG "012d73e0fab8d26e0f4d65e36077511e", "12345678" },
	{FORMAT_TAG "0ceb1fd260c35bd50005341532748de6", "abc123" },
	{"8be1ec697b14ad3a53b371436120641d", "1"},
	{"114c5a33b8d4127fbe492bd6583aeb4d", "12"},
	{"c58cda49f00748a3bc0fcfa511d516cb", "123"},
	{"f375f401ddc698af533f16f8ac1e91c1", "1234"},
	{NULL}
};

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		(NBKEYS * 32)
#include "common-simd-getpos.h"
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		256
#endif

#ifdef SIMD_COEF_32
static uint32_t (*saved_key)[MD4_BUF_SIZ*NBKEYS];
static uint32_t (*crypt_key)[DIGEST_SIZE/4*NBKEYS];
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[4];
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
#ifndef SIMD_COEF_32
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#else
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
#ifndef SIMD_COEF_32
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
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;

	if (ciphertext[0] == '$' &&
			!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	memcpylwr(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned long dummy;
		unsigned int i[DIGEST_SIZE/sizeof(unsigned int)];
	} _out;
	unsigned int *out = _out.i;
	unsigned int i;
	unsigned int temp;

	ciphertext += TAG_LENGTH;
	for (i=0; i<4; i++)
	{
		temp  = ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+0])]))<<4;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+1])]));

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+2])]))<<12;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+3])]))<<8;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+4])]))<<20;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+5])]))<<16;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+6])]))<<28;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+7])]))<<24;

#if ARCH_LITTLE_ENDIAN || defined(SIMD_COEF_32)
		out[i] = temp;
#else
		out[i] = JOHNSWAP(temp);
#endif
	}

#if defined(SIMD_COEF_32) && defined(REVERSE_STEPS)
	md4_reverse(out);
#endif

	return out;
}

static char *source(char *source, void *binary)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1] = FORMAT_TAG;
	uint32_t b[4];
	char *p;
	int i, j;

	memcpy(b, binary, sizeof(b));

#if SIMD_COEF_32 && defined(REVERSE_STEPS)
	md4_unreverse(b);
#endif

#if !ARCH_LITTLE_ENDIAN && !defined(SIMD_COEF_32)
	alter_endianity(b, 16);
#endif

	p = &out[TAG_LENGTH];
	for (i = 0; i < 4; i++)
		for (j = 0; j < 8; j++)
			*p++ = itoa16[(b[i] >> ((j ^ 1) * 4)) & 0xf];

	return out;
}

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
	int loops = (count + MIN_KEYS_PER_CRYPT - 1) / MIN_KEYS_PER_CRYPT;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < loops; index++) {
#if SIMD_COEF_32
		SIMDmd4body(saved_key[index], crypt_key[index], NULL, SSEi_REVERSE_STEPS | SSEi_MIXED_IN);
#else
		MD4_CTX ctx;
		MD4_Init(&ctx);
		MD4_Update(&ctx, saved_key[index], saved_len[index]);
		MD4_Final((unsigned char *)crypt_key[index], &ctx);
#endif
	}

	return count;
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;
	const unsigned int c = (count + SIMD_COEF_32 - 1) / SIMD_COEF_32;
	for (y = 0; y < c; y++)
		for (x = 0; x < SIMD_COEF_32; x++)
		{
			if ( ((uint32_t*)binary)[1] == ((uint32_t*)crypt_key)[y*SIMD_COEF_32*4+x+SIMD_COEF_32] )
				return 1;
		}

	return 0;
#else
	unsigned int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x = index&(SIMD_COEF_32-1);
	unsigned int y = (unsigned int)index/SIMD_COEF_32;

	return ((uint32_t*)binary)[1] == ((uint32_t*)crypt_key)[x+y*SIMD_COEF_32*4+SIMD_COEF_32];
#else
	return !memcmp(binary, crypt_key[index], DIGEST_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#ifdef SIMD_COEF_32
	uint32_t crypt_key[DIGEST_SIZE / 4];
	MD4_CTX ctx;
	char *key = get_key(index);

	MD4_Init(&ctx);
	MD4_Update(&ctx, key, strlen(key));
	MD4_Final((void*)crypt_key, &ctx);

#if !ARCH_LITTLE_ENDIAN
	alter_endianity(crypt_key, 16);
#endif
#if defined(REVERSE_STEPS)
	md4_reverse(crypt_key);
#endif
	return !memcmp(get_binary(source), crypt_key, DIGEST_SIZE);
#else
	return 1;
#endif
}

#ifdef SIMD_COEF_32
#define SIMD_INDEX (index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SIMD_COEF_32*4+SIMD_COEF_32
static int get_hash_0(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key)[SIMD_INDEX] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_0; }
static int get_hash_1(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_1; }
static int get_hash_2(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_2; }
static int get_hash_3(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_3; }
static int get_hash_4(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_4; }
static int get_hash_5(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_5; }
static int get_hash_6(int index) { return ((uint32_t*)crypt_key[index])[1] & PH_MASK_6; }
#endif

static int binary_hash_0(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_0; }
static int binary_hash_1(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_1; }
static int binary_hash_2(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_2; }
static int binary_hash_3(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_3; }
static int binary_hash_4(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_4; }
static int binary_hash_5(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_5; }
static int binary_hash_6(void * binary) { return ((uint32_t*)binary)[1] & PH_MASK_6; }

struct fmt_main fmt_rawMD4 = {
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
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
		source,
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
