/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * Copyright (c) 2011, 2012 by magnum
 *
 * Use of Bartavelle's mmx/sse2/intrinsics and reduced binary size by
 * magnum in 2011-2012.
 *
 * OMP added May 2013, JimF
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawMD4;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawMD4);
#else

#include <string.h>

#include "arch.h"

#include "md4.h"
#include "common.h"
#include "formats.h"

#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif

#ifdef _OPENMP
#ifdef SIMD_COEF_32
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
#include "sse-intrinsics.h"
#include "memdbg.h"

#define FORMAT_LABEL			"Raw-MD4"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"MD4 " MD4_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD4)
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1
#ifndef MD4_BUF_SIZ
#define MD4_BUF_SIZ				16
#endif

#define CIPHERTEXT_LENGTH		32

#define DIGEST_SIZE				16
#define BINARY_SIZE				16 // source()
#define BINARY_ALIGN			4
#define SALT_SIZE				0
#define SALT_ALIGN				1

#define FORMAT_TAG				"$MD4$"
#define TAG_LENGTH				(sizeof(FORMAT_TAG) - 1)

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{FORMAT_TAG "6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
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
	{NULL}
};

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*MD4_BUF_SIZ*4*SIMD_COEF_32 )
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifdef SIMD_COEF_32
static ARCH_WORD_32 (*saved_key)[MD4_BUF_SIZ*NBKEYS];
static ARCH_WORD_32 (*crypt_key)[DIGEST_SIZE/4*NBKEYS];
#else
static int (*saved_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_key)[4];
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
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < DIGEST_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#ifdef SIMD_COEF_32
#define HASH_OFFSET (index&(SIMD_COEF_32-1))+(((unsigned int)index%NBKEYS)/SIMD_COEF_32)*SIMD_COEF_32*4
static int get_hash_0(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index][0] & 0x7ffffff; }
#endif

#ifdef SIMD_COEF_32
static void set_key(char *_key, int index)
{
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*MD4_BUF_SIZ*SIMD_COEF_32];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
	while((temp = *key++) & 0xff) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = (temp & 0xff) | (0x80 << 8);
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = (temp & 0xffff) | (0x80 << 16);
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = temp | (0x80 << 24);
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = temp;
		len += 4;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	keybuffer[14*SIMD_COEF_32] = len << 3;
}
#else
static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_len[index] = len;
	memcpy(saved_key[index], key, len);
}
#endif

#ifdef SIMD_COEF_32
static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int i;
	ARCH_WORD_32 len = ((ARCH_WORD_32*)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*MD4_BUF_SIZ*SIMD_COEF_32] >> 3;

	for(i=0;i<len;i++)
		out[i] = ((char*)saved_key)[GETPOS(i, index)];
	out[i] = 0;
	return (char*)out;
}
#else
static char *get_key(int index)
{
	saved_key[index][saved_len[index]] = 0;
	return saved_key[index];
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
	int loops = (count + MAX_KEYS_PER_CRYPT - 1) / MAX_KEYS_PER_CRYPT;

#pragma omp parallel for
	for (index = 0; index < loops; ++index)
#endif
	{
#if SIMD_COEF_32
		SSEmd4body(saved_key[index], crypt_key[index], NULL, SSEi_MIXED_IN);
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
	int index;
	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
        if (((ARCH_WORD_32 *) binary)[0] == ((ARCH_WORD_32*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*4*SIMD_COEF_32])
#else
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_key[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(ARCH_WORD_32); i++)
        if (((ARCH_WORD_32 *) binary)[i] != ((ARCH_WORD_32*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*4*SIMD_COEF_32+i*SIMD_COEF_32])
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

static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH + TAG_LENGTH + 1];
	unsigned char *cpi;
	char *cpo;
	int i;

	strcpy(Buf, FORMAT_TAG);
	cpo = &Buf[TAG_LENGTH];

	cpi = (unsigned char*)(binary);

	for (i = 0; i < BINARY_SIZE; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

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
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		source,
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
