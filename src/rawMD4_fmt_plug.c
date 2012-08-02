/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * Copyright (c) 2011, 2012 by magnum
 *
 * Use of Bartavelle's mmx/sse2/intrinsics and reduced binary size by
 * magnum in 2011-2012.
 */

#include <string.h>

#include "arch.h"

#ifdef MD4_SSE_PARA
#define MMX_COEF			4
#define NBKEYS				(MMX_COEF * MD4_SSE_PARA)
#elif MMX_COEF
#define NBKEYS				MMX_COEF
#endif
#include "sse-intrinsics.h"

#include "md4.h"
#include "common.h"
#include "formats.h"
#include "params.h"

#define FORMAT_LABEL			"raw-md4"
#define FORMAT_NAME			"Raw MD4"

#define ALGORITHM_NAME			MD4_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			4
#define DIGEST_SIZE			16
#define SALT_SIZE			0

#define FORMAT_TAG			"$MD4$"
#define TAG_LENGTH			5

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{FORMAT_TAG "6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
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

#ifdef MMX_COEF
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*16*MMX_COEF*4 )
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawmd4_saved_key
#define crypt_key rawmd4_crypt_key
#if defined (_MSC_VER)
__declspec(align(16)) unsigned char saved_key[64*MAX_KEYS_PER_CRYPT];
__declspec(align(16)) unsigned char crypt_key[DIGEST_SIZE*MAX_KEYS_PER_CRYPT];
#else
unsigned char saved_key[64*MAX_KEYS_PER_CRYPT] __attribute__ ((aligned(MMX_COEF*4)));
unsigned char crypt_key[DIGEST_SIZE*MAX_KEYS_PER_CRYPT+1] __attribute__ ((aligned(MMX_COEF*4)));
#endif
#ifndef MD4_SSE_PARA
static unsigned int total_len;
#endif
#else
static MD4_CTX ctx;
static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[4];
#endif

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

static char *split(char *ciphertext, int index)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *binary(char *ciphertext)
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

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32*)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32*)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32*)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32*)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32*)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32*)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32*)binary & 0x7ffffff; }

#ifdef MMX_COEF
#define HASH_OFFSET (index&(MMX_COEF-1))+(index/MMX_COEF)*MMX_COEF*4
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_key[0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[0] & 0x7ffffff; }
#endif

static void set_key(char *_key, int index)
{
#ifdef MMX_COEF
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	ARCH_WORD_32 *keybuffer = (ARCH_WORD_32*)&saved_key[GETPOS(0, index)];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

#ifndef MD4_SSE_PARA
	if (!index)
		total_len = 0;
#endif
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
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	keybuffer[56] = len << 3;
#else
	total_len += len << ( (32/MMX_COEF) * index);
#endif
#else
	saved_key_length = strlen(_key);
	memcpy(saved_key, _key, saved_key_length);
#endif
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int i,len;

	len = (unsigned char)saved_key[GETPOS(56,index)] >> 3;
	for(i=0;i<len;i++)
		out[i] = saved_key[GETPOS(i, index)];
	out[i] = 0;
	return (char*)out;
#else
	saved_key[saved_key_length] = 0;
	return saved_key;
#endif
}

static void crypt_all(int count)
{
#ifdef MD4_SSE_PARA
	SSEmd4body(saved_key, (unsigned int*)crypt_key, 1);
#elif MMX_COEF
	mdfourmmx(crypt_key, saved_key, total_len);
#else
	MD4_Init(&ctx);
	MD4_Update(&ctx, saved_key, saved_key_length);
	MD4_Final((unsigned char *)crypt_key, &ctx);
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;
#ifdef MD4_SSE_PARA
	for(; y < MD4_SSE_PARA; y++)
#endif
		for(x = 0; x < MMX_COEF; x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+x] )
				return 1;
		}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	unsigned int x = index&(MMX_COEF-1);
	unsigned int y = index/MMX_COEF;

#if BINARY_SIZE < DIGEST_SIZE
	return ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*4];
#else
	int i;
	for(i=0;i<(DIGEST_SIZE/4);i++)
		if ( ((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+i*MMX_COEF+x] )
			return 0;
	return 1;
#endif
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#if BINARY_SIZE == DIGEST_SIZE
	return 1;
#else
#ifdef MMX_COEF
	unsigned int i, x, y;
	ARCH_WORD_32 *full_binary;

	full_binary = (ARCH_WORD_32*)binary(source);
	x = index&(MMX_COEF-1);
	y = index/MMX_COEF;
	for(i=0;i<(DIGEST_SIZE/4);i++)
		if (full_binary[i] != ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+i*MMX_COEF+x])
			return 0;
	return 1;
#else
	return !memcmp(binary(source), crypt_key, DIGEST_SIZE);
#endif
#endif
}

struct fmt_main fmt_rawMD4 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
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
