/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 *
 * Use of Bartavelle's mmx/sse2/intrinsics added by magnum in 2011,
 * no rights reserved
 */

#include <string.h>

#include "arch.h"

#ifdef MD4_SSE_PARA
#define MMX_COEF			4
#include "sse-intrinsics.h"
#define NBKEYS				(MMX_COEF * MD4_SSE_PARA)
#elif MMX_COEF
#define NBKEYS				MMX_COEF
#endif

#include "md4.h"
#include "common.h"
#include "formats.h"
#include "params.h"

#define FORMAT_LABEL			"raw-md4"
#define FORMAT_NAME			"Raw MD4"

#ifdef MD4_SSE_PARA
#define ALGORITHM_NAME			"SSE2i " MD4_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define ALGORITHM_NAME			"SSE2 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define ALGORITHM_NAME			"MMX 2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			0

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{"$MD4$6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"$MD4$31d6cfe0d16ae931b73c59d7e0c089c0", "" },
	{"$MD4$934eb897904769085af8101ad9dabca2", "John the ripper" },
	{"$MD4$cafbb81fb64d9dd286bc851c4c6e0d21", "lolcode" },
	{"$MD4$585028aa0f794af812ee3be8804eb14a", "123456" },
	{"$MD4$23580e2a459f7ea40f9efa148b63cafb", "12345" },
	{"$MD4$2ae523785d0caf4d2fb557c12016185c", "123456789" },
	{"$MD4$f3e80e83b29b778bc092bf8a7c6907fe", "iloveyou" },
	{"$MD4$4d10a268a303379f224d8852f2d13f11", "princess" },
	{"$MD4$bf75555ca19051f694224f2f5e0b219d", "1234567" },
	{"$MD4$41f92cf74e3d2c3ba79183629a929915", "rockyou" },
	{"$MD4$012d73e0fab8d26e0f4d65e36077511e", "12345678" },
	{"$MD4$0ceb1fd260c35bd50005341532748de6", "abc123" },
	{NULL}
};

#ifdef MMX_COEF
#define PLAINTEXT_LENGTH		54
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
__declspec(align(16)) unsigned char crypt_key[BINARY_SIZE*MAX_KEYS_PER_CRYPT];
#else
unsigned char saved_key[64*MAX_KEYS_PER_CRYPT] __attribute__ ((aligned(MMX_COEF*4)));
unsigned char crypt_key[BINARY_SIZE*MAX_KEYS_PER_CRYPT+1] __attribute__ ((aligned(MMX_COEF*4)));
#endif
#ifndef MD4_SSE_PARA
static unsigned int total_len;
#endif
#else
static MD4_CTX ctx;
static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_out[4];
#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, "$MD4$", 5))
		p += 5;

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
	static char out[5 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$MD4$", 5))
		return ciphertext;

	memcpy(out, "$MD4$", 5);
	memcpy(out + 5, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 5;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
}

#ifdef MMX_COEF
static int get_hash_0(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] & 0xfffff;
}
static int get_hash_5(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] & 0xffffff;
}
static int get_hash_6(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] & 0x7ffffff;
}
#else
static int get_hash_0(int index)
{
	return crypt_out[0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_out[0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_out[0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return crypt_out[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return crypt_out[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return crypt_out[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return crypt_out[0] & 0x7FFFFFF;
}
#endif

static void set_key(char *_key, int index)
{
#ifdef MMX_COEF
	const unsigned int *key = (unsigned int*)_key;
	unsigned int *keybuffer = (unsigned int*)&saved_key[GETPOS(0, index)];
	unsigned int *keybuf_word = keybuffer;
	unsigned int len, temp;

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
	MD4_Final((unsigned char *)crypt_out, &ctx);
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
#ifdef MD4_SSE_PARA
	unsigned int x,y=0;

	for(; y < MD4_SSE_PARA; y++)
		for(x = 0; x < MMX_COEF; x++)
		{
			if( ((unsigned int*)binary)[0] == ((unsigned int*)crypt_key)[x+y*MMX_COEF*4] )
				return 1;
		}
	return 0;
#else
	unsigned int x;

	for(x = 0; x < MMX_COEF; x++)
	{
		if( ((unsigned int*)binary)[0] == ((unsigned int*)crypt_key)[x] )
			return 1;
	}
	return 0;
#endif
#else
	return !memcmp(binary, crypt_out, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count){
	return (1);
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
#if MD4_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((unsigned int*)binary)[0] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*4] )
		return 0;
	if( ((unsigned int*)binary)[1] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*4+4] )
		return 0;
	if( ((unsigned int*)binary)[2] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*4+8] )
		return 0;
	if( ((unsigned int*)binary)[3] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*4+12] )
		return 0;
	return 1;
#else
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long*)binary)[i] != ((unsigned long*)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#endif
#else
	return !memcmp(binary, crypt_out, BINARY_SIZE);
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
		get_binary,
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
