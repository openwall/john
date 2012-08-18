/*
 * This software is Copyright (c) 2004 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

#define FORMAT_LABEL			"pix-md5"
#define FORMAT_NAME			"PIX MD5"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"pix-md5 MMX"
#else
#define ALGORITHM_NAME			"pix-md5 SSE2"
#endif
#else
#define ALGORITHM_NAME			"pix-md5"
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		16

#define SALT_SIZE			0

#ifdef MMX_COEF
#define BINARY_SIZE			16
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + ((i) & (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define BINARY_SIZE			(4 * sizeof(ARCH_WORD_32))
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests pixmd5_tests[] = {
	{"2KFQnbNIdI.2KYOU", "cisco"},
	{"TRPEas6f/aa6JSPL", "test1"},
	{"OMT6mXmAvGyzrCtp", "test2"},
	{"gTC7RIy1XJzagmLm", "test3"},
	{"oWC1WRwqlBlbpf/O", "test4"},
	{"NuLKvvWGg.x9HEKO", "password"},
	{"8Ry2YjIyt7RRXU24", ""},
	{".7nfVBEIEu4KbF/1","0123456789abcdef"},        // added a exact 16 byte password, to make sure it works properly
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key pixMD5_saved_key
#define crypt_key pixMD5_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) char saved_key[PLAINTEXT_LENGTH*MMX_COEF*2 + 1];
__declspec(align(16)) char crypt_key[BINARY_SIZE*MMX_COEF];
#else
char saved_key[PLAINTEXT_LENGTH*MMX_COEF*2 + 1] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
#endif
static unsigned long total_len;
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static MD5_CTX ctx;
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	unsigned int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;

	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		if(atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;
	return 1;
}

static void pixmd5_init(struct fmt_main *self)
{
#ifdef MMX_COEF
	unsigned int i;

	total_len = 0;
	for(i=0;i<MMX_COEF;i++)
		total_len += 16 << ( ( (32/MMX_COEF) * i ) );
#endif
}

static void pixmd5_set_key(char *key, int index) {
#ifdef MMX_COEF
	int i;
	if(index==0)
        {
		memset(saved_key, 0, sizeof(saved_key));
        }

	for(i=0;key[i];i++)
		saved_key[GETPOS(i, index)] = key[i];
	for(;i<16;i++)
		saved_key[GETPOS(i, index)] = 0;

	saved_key[GETPOS(i, index)] = 0x80;
#else
	strncpy(saved_key, key, 16);
/* NUL padding is needed because pixmd5_crypt_all() passes 16 bytes of
 * saved_key[] to MD5_Update() unconditionally. */
#endif
}

static char *pixmd5_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;

	s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*)out;
#else
	saved_key[16] = 0;
	return saved_key;
#endif
}

#define MASK 0x00ffffff

static int pixmd5_cmp_all(void *binary, int index) {
#ifdef MMX_COEF
	int i=0;
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((unsigned long *)binary)[i] != (((unsigned long *)crypt_key)[i*MMX_COEF] & MASK))
			&& ( ((unsigned long *)binary)[i] != (((unsigned long *)crypt_key)[i*MMX_COEF+1] & MASK))
#if (MMX_COEF > 3)
			&& ( ((unsigned long *)binary)[i] != (((unsigned long *)crypt_key)[i*MMX_COEF+2] & MASK))
			&& ( ((unsigned long *)binary)[i] != (((unsigned long *)crypt_key)[i*MMX_COEF+3] & MASK))
#endif
		)
			return 0;
		i++;
	}
#else
	if (((ARCH_WORD_32 *)binary)[1] != (ctx.b & MASK)) return 0;
	if (((ARCH_WORD_32 *)binary)[2] != (ctx.c & MASK)) return 0;
	if (((ARCH_WORD_32 *)binary)[3] != (ctx.d & MASK)) return 0;
	if (((ARCH_WORD_32 *)binary)[0] != (ctx.a & MASK)) return 0;
#endif
	return 1;
}

static int pixmd5_cmp_exact(char *source, int count){
  return (1);
}

#ifdef MMX_COEF
static int pixmd5_cmp_one(void * binary, int index)
{
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != (((unsigned long *)crypt_key)[i*MMX_COEF+index] & MASK ) )
			return 0;
	return 1;
}
#else
#define pixmd5_cmp_one pixmd5_cmp_all
#endif

static void pixmd5_crypt_all(int count) {
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF

	mdfivemmx((unsigned char*)crypt_key, (unsigned char*)saved_key, total_len);
#else
	MD5_Init( &ctx );
	MD5_Update( &ctx, saved_key, 16 );
	MD5_PreFinal(&ctx);
#endif
}

static void * pixmd5_binary(char *ciphertext)
{
	static ARCH_WORD_32 realcipher[4];
	int i;

	for(i = 0; i < 4; i++) {
		realcipher[i] =
			atoi64[ARCH_INDEX(ciphertext[i*4 + 0])] +
			(atoi64[ARCH_INDEX(ciphertext[i*4 + 1])] << 6) +
			(atoi64[ARCH_INDEX(ciphertext[i*4 + 2])] << 12) +
			(atoi64[ARCH_INDEX(ciphertext[i*4 + 3])] << 18);
	}
	return (void *)realcipher;
}

static int get_hash1(int index)
{
#ifdef MMX_COEF
	return (((unsigned char *)crypt_key)[index*4] & 0xf);
#else
	return ctx.a & 0xf;
#endif
}
static int get_hash2(int index)
{
#ifdef MMX_COEF
	return ((unsigned char *)crypt_key)[index*4];
#else
	return ctx.a & 0xff;
#endif
}
static int get_hash3(int index)
{
#ifdef MMX_COEF
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xfff;
#else
	return ctx.a & 0xfff;
#endif
}

static int binary_hash1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }

struct fmt_main fmt_pixMD5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		16, /* not exactly PLAINTEXT_LENGTH, the code is dirty */
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		pixmd5_tests
	}, {
		pixmd5_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		pixmd5_binary,
		fmt_default_salt,
		{
			binary_hash1,
			binary_hash2,
			binary_hash3,
			NULL,
			NULL
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		pixmd5_set_key,
		pixmd5_get_key,
		fmt_default_clear_keys,
		pixmd5_crypt_all,
		{
			get_hash1,
			get_hash2,
			get_hash3,
			NULL,
			NULL
		},
		pixmd5_cmp_all,
		pixmd5_cmp_one,
		pixmd5_cmp_exact
	}
};
