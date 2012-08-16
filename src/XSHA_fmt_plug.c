/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2008,2011 by Solar Designer
 *
 * Intrinsics support added by magnum 2011.
 */

#include <string.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define NBKEYS				(MMX_COEF * SHA1_SSE_PARA)

#ifdef _OPENMP
static unsigned int omp_t = 1;
#include <omp.h>
#define OMP_SCALE			128
#endif

#elif MMX_COEF
#define NBKEYS				MMX_COEF
#endif
#include "sse-intrinsics.h"

#include "params.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"

#define FORMAT_LABEL			"xsha"
#define FORMAT_NAME			"Mac OS X 10.4 - 10.6 salted SHA-1"

#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		51
#define CIPHERTEXT_LENGTH		48

#define BINARY_SIZE			20
#define SALT_SIZE			4

#ifdef MMX_COEF

#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion

#else

#define MIN_KEYS_PER_CRYPT		1
#ifdef _OPENMP
#define MAX_KEYS_PER_CRYPT		(0x200 * 3)
#else
#define MAX_KEYS_PER_CRYPT		0x100
#endif

#endif

static struct fmt_tests tests[] = {
	{"12345678F9083C7F66F46A0A102E4CC17EC08C8AF120571B", "abc"},
	{"12345678EB8844BFAF2A8CBDD587A37EF8D4A290680D5818", "azertyuiop1"},
	{"3234C32AAA335FD20E3F95870E5851BDBE942B79CE4FDD92", "azertyuiop2"},
	{"01295B67659E95F32931CEDB3BA50289E2826AF3D5A1422F", "apple"},
	{"0E6A48F765D0FFFFF6247FA80D748E615F91DD0C7431E4D9", "macintosh"},
	{"A320163F1E6DB42C3949F7E232888ACC7DB7A0A17E493DBA", "test"},
	{NULL}
};

#ifdef MMX_COEF
static ARCH_WORD_32 (*saved_key);
static ARCH_WORD_32 (*crypt_key);
static ARCH_WORD_32 cur_salt;

#else

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static int saved_key_length[MAX_KEYS_PER_CRYPT];
static SHA_CTX ctx_salt;
static ARCH_WORD_32 crypt_out[MAX_KEYS_PER_CRYPT][5];

#endif

static void init(struct fmt_main *self)
{
#ifdef MMX_COEF
#if defined(SHA1_SSE_PARA) && defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt = omp_t * NBKEYS;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt = omp_t * NBKEYS;
#endif
	saved_key = mem_calloc_tiny(SHA_BUF_SIZ*4 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_tiny(BINARY_SIZE * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	/* Require uppercase hex digits (assume ASCII) */
	pos = ciphertext;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && *pos < 'a')
		pos++;
	return !*pos && pos - ciphertext == CIPHERTEXT_LENGTH;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out)
		out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef MMX_COEF
	alter_endianity(out, BINARY_SIZE);
#endif
	return out;
}

static void *salt(char *ciphertext)
{
	static unsigned int outbuf[SALT_SIZE / sizeof(int)];
	unsigned char *out = (unsigned char*)outbuf;
	char *p;
	int i;

	p = ciphertext;
	for (i = 0; i < SALT_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

#ifdef MMX_COEF
	alter_endianity(out, SALT_SIZE);
#endif
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
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xfffff;
}
static int get_hash_5(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xffffff;
}
static int get_hash_6(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0x7ffffff;
}
#else
static int get_hash_0(int index)
{
	return crypt_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
	return crypt_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
	return crypt_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
	return crypt_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return crypt_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	return crypt_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return crypt_out[index][0] & 0x7FFFFFF;
}
#endif

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32 *)salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
#ifdef MMX_COEF
	cur_salt = *(ARCH_WORD_32*)salt;
#else
	SHA1_Init(&ctx_salt);
	SHA1_Update(&ctx_salt, salt, SALT_SIZE);
#endif
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuffer = &saved_key[(index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF + MMX_COEF];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 4;
	while((temp = *wkey++) & 0xff) {
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
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}
	keybuffer[14*MMX_COEF] = len << 3;
#else
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	saved_key_length[index] = length;
	memcpy(saved_key[index], key, length);
#endif
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int i,s;
	static char out[PLAINTEXT_LENGTH + 1];

	s = ((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] >> 3;

	for(i = 0; i < (s - SALT_SIZE); i++)
		out[i] = ((char*)saved_key)[ GETPOS((i + SALT_SIZE), index) ];
	out[i] = 0;

	return (char *) out;
#else
	saved_key[index][saved_key_length[index]] = 0;
	return saved_key[index];
#endif
}

static void crypt_all(int count)
{
#ifdef MMX_COEF
	int i = 0;
#if defined(SHA1_SSE_PARA) && defined(_OPENMP)
	#pragma omp parallel for
	for (i=0; i < omp_t; i++) {
#endif
		unsigned int *in = &saved_key[i*NBKEYS*SHA_BUF_SIZ];
		unsigned int *out = &crypt_key[i*NBKEYS*BINARY_SIZE/4];
		unsigned int j;
		for (j=0; j < NBKEYS; j++)
			in[(j&(MMX_COEF-1)) + (j>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF] = cur_salt;
#ifdef SHA1_SSE_PARA
		SSESHA1body(in, out, NULL, 0);
#else
		shammx_nosizeupdate_nofinalbyteswap((unsigned char*)out, (unsigned char*)in, 1);
#endif
#if defined(SHA1_SSE_PARA) && defined(_OPENMP)
	}
#endif
#else
	int i;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i) shared(ctx_salt, count, saved_key, saved_key_length, crypt_out)
#endif
	for (i = 0; i < count; i++) {
		SHA_CTX ctx;

		memcpy(&ctx, &ctx_salt, sizeof(ctx));

		SHA1_Update(&ctx, saved_key[i], saved_key_length[i]);
		SHA1_Final((unsigned char *)(crypt_out[i]), &ctx);
	}
#endif
}

static int cmp_all(void *binary, int count)
{
#ifdef MMX_COEF
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
#ifdef _OPENMP
	for(;y<SHA1_SSE_PARA*omp_t;y++)
#else
	for(;y<SHA1_SSE_PARA;y++)
#endif
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((ARCH_WORD_32 *)binary)[0] == ((ARCH_WORD_32 *)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	ARCH_WORD_32 b0 = *(ARCH_WORD_32 *)binary;
	int i;

	for (i = 0; i < count; i++) {
		if (b0 != crypt_out[i][0])
			continue;
		if (!memcmp(binary, crypt_out[i], BINARY_SIZE))
			return 1;
	}
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((ARCH_WORD_32 *)binary)[0] != ((ARCH_WORD_32 *)crypt_key)[x+y*MMX_COEF*5] )
		return 0;
	if( ((ARCH_WORD_32 *)binary)[1] != ((ARCH_WORD_32 *)crypt_key)[x+y*MMX_COEF*5+MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32 *)binary)[2] != ((ARCH_WORD_32 *)crypt_key)[x+y*MMX_COEF*5+2*MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32 *)binary)[3] != ((ARCH_WORD_32 *)crypt_key)[x+y*MMX_COEF*5+3*MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32 *)binary)[4] != ((ARCH_WORD_32 *)crypt_key)[x+y*MMX_COEF*5+4*MMX_COEF] )
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

struct fmt_main fmt_XSHA = {
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
#if !defined(MMX_COEF) || defined(SHA1_SSE_PARA)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
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
