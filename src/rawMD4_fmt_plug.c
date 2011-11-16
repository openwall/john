/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 *
 * Use of Bartavelle's intrinsics added by magnum in 2011,
 * no rights reserved
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"raw-md4"
#define FORMAT_NAME			"Raw MD4"

#ifdef MD4_SSE_PARA
#define MMX_COEF			4
#include "sse-intrinsics.h"
#define NBKEYS				(MMX_COEF * MD4_SSE_PARA)
#define ALGORITHM_NAME			"SSE2i " MD4_N_STR
#define PLAINTEXT_LENGTH		54
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*16*MMX_COEF*4 )
#else
#include "md4.h"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			0

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{"$MD4$8a9d093f14f8701df17732b2bb182c74", "password"},
	{NULL}
};

#ifdef MD4_SSE_PARA
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawmd4_saved_key
#define crypt_key rawmd4_crypt_key
#if defined (_MSC_VER)
__declspec(align(16)) char saved_key[64*MAX_KEYS_PER_CRYPT];
__declspec(align(16)) char crypt_key[BINARY_SIZE*MAX_KEYS_PER_CRYPT];
#else
char saved_key[64*MAX_KEYS_PER_CRYPT] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*MAX_KEYS_PER_CRYPT] __attribute__ ((aligned(16)));
#endif
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static MD4_CTX ctx;
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

#ifdef MD4_SSE_PARA
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

static void set_key(char *key, int index)
{
#ifdef MD4_SSE_PARA
	int i;

	if(index==0)
		memset(saved_key, 0, sizeof(saved_key));

	for(i=0;key[i];i++)
		saved_key[GETPOS(i, index)] = key[i];

	saved_key[GETPOS(i, index)] = 0x80;
	saved_key[GETPOS(56,index)] = i << 3;
#else
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
#endif
}

static char *get_key(int index)
{
#ifdef MD4_SSE_PARA
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
	SSEmd4body(saved_key, (unsigned int *)crypt_key, 1);
#else
	MD4_Init(&ctx);
	MD4_Update(&ctx, saved_key, saved_key_length);
	MD4_Final((unsigned char *)crypt_out, &ctx);
#endif
}

static int cmp_all(void *binary, int count)
{
#ifdef MD4_SSE_PARA
	unsigned int x,y;

	for(y=0;y<MD4_SSE_PARA;y++)
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((unsigned int *)binary)[0] == ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] )
			return 1;
	}
	return 0;
#else
	return !memcmp(binary, crypt_out, BINARY_SIZE);
#endif
}

static int cmp_one(void * binary, int index)
{
#ifdef MD4_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((unsigned int *)binary)[0] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*4] )
		return 0;
	if( ((unsigned int *)binary)[1] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*4+4] )
		return 0;
	if( ((unsigned int *)binary)[2] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*4+8] )
		return 0;
	if( ((unsigned int *)binary)[3] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*4+12] )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
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
