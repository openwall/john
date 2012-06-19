/*
 * Copyright (c) 2007 Marti Raudsepp <marti AT juffo org>
 *
 * Simple MySQL 4.1+ PASSWORD() hash cracker, rev 1.
 * Adapted from the original rawSHA1_fmt.c cracker.
 *
 * Note that many version 4.1 and 5.0 installations still use the old
 * homebrewn pre-4.1 hash for compatibility with older clients, notably all
 * Red Hat-based distributions.
 *
 * The new PASSWORD() function is unsalted and equivalent to
 * SHA1(SHA1(password)) where the inner is a binary digest (not hex!) This
 * means that with the SSE2-boosted SHA-1 implementation, it will be several
 * times faster than John's cracker for the old hash format. (though the old
 * hash had significant weaknesses, some of which are exploited with John's
 * format "mysql-fast")
 *
 * It's a slight improvement over the old hash, but still not something a
 * reasonable DBMS would use for password storage.
 *
 * Use of SSE2 intrinsics: Copyright magnum 2012 and hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted.
 *
 */

#include <string.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF	4
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS	MMX_COEF
#endif
#include "sse-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"

#define FORMAT_LABEL			"mysql-sha1"
#define FORMAT_NAME			"MySQL 4.1 double-SHA-1"

#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		41

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF

#include "johnswap.h"
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*4*MMX_COEF ) //for endianity conversion

#else

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#endif

static struct fmt_tests tests[] = {
	{"*5AD8F88516BD021DD43F171E2C785C69F8E54ADB", "tere"},
	{"*2C905879F74F28F8570989947D06A8429FB943E6", "verysecretpassword"},
	{"*A8A397146B1A5F8C8CF26404668EFD762A1B7B82", "________________________________"},
	{"*F9F1470004E888963FB466A5452C9CBD9DF6239C", "12345678123456781234567812345678"},
	{"*97CF7A3ACBE0CA58D5391AC8377B5D9AC11D46D9", "' OR 1 /*'"},
	{"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "password"},
	{"*7534F9EAEE5B69A586D1E9C1ACE3E3F9F6FCC446", "5"},
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mysqlSHA1_saved_key
#define crypt_key mysqlSHA1_crypt_key
#define interm_key mysqlSHA1_interm_key
#ifdef _MSC_VER
__declspec(align(16)) char saved_key[SHA_BUF_SIZ*4*NBKEYS];
__declspec(align(16)) char crypt_key[BINARY_SIZE*NBKEYS];
__declspec(align(16)) char interm_key[SHA_BUF_SIZ*4*NBKEYS];
#else
char saved_key[SHA_BUF_SIZ*4*NBKEYS] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
char interm_key[SHA_BUF_SIZ*4*NBKEYS] __attribute__ ((aligned(16)));
#endif

#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	if (ciphertext[0] != '*')
		return 0;
	for (i = 1; i < CIPHERTEXT_LENGTH; i++) {
		if (!( (('0' <= ciphertext[i])&&(ciphertext[i] <= '9'))
		       || (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		       || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
		{
			return 0;
		}
	}
	return 1;
}

static void init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	int i;

	/* input strings have to be terminated by 0x80. The input strings in
	 * interm_key have a static length (20 bytes) so we can set them just
	 * once. If intrinsics, we do the same for the length byte.
	 */
	for (i = 0; i < NBKEYS; i++) {
		interm_key[GETPOS(20,i)] = 0x80;
		((unsigned int *)interm_key)[15*MMX_COEF + (i&3) + (i>>2)*SHA_BUF_SIZ*MMX_COEF] = 20 << 3;
	}
#endif
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuf_word = (ARCH_WORD_32*)&saved_key[GETPOS(3, index)];
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
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
	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] = len << 3;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH + 1);
#endif
}

static char *get_key(int index) {
#ifdef MMX_COEF
	static char out[PLAINTEXT_LENGTH+1];
	unsigned int i, s;

	s = ((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] >> 3;
	for (i = 0; i < s; i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return out;
#else
	return saved_key;
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
	for(;y<SHA1_SSE_PARA;y++)
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((unsigned int*)binary)[0] ==
		    ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return (1);
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((unsigned int*)binary)[0] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] )
		return 0;
	if( ((unsigned int*)binary)[1] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*1] )
		return 0;
	if( ((unsigned int*)binary)[2] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*2] )
		return 0;
	if( ((unsigned int*)binary)[3] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*3] )
		return 0;
	if( ((unsigned int*)binary)[4] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*4] )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static void crypt_all(int count) {
#ifdef MMX_COEF
#ifdef SHA1_SSE_PARA
	unsigned int i;

	SSESHA1body(saved_key, (unsigned int *)crypt_key, NULL, 0);

	for (i = 0; i < SHA1_SSE_PARA; i++)
		memcpy(&interm_key[i*SHA_BUF_SIZ*4*MMX_COEF],
		       &crypt_key[i*BINARY_SIZE*MMX_COEF],
		       MMX_COEF*BINARY_SIZE);

	SSESHA1body(interm_key, (unsigned int *)crypt_key, NULL, 0);

#else
	shammx_nosizeupdate_nofinalbyteswap((unsigned char *) crypt_key, (unsigned char *) saved_key, 1);
	memcpy(interm_key, crypt_key, MMX_COEF*BINARY_SIZE);
	shammx_nosizeupdate_nofinalbyteswap((unsigned char *) crypt_key, (unsigned char *) interm_key, 1);
#endif
#else
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char *) saved_key, strlen(saved_key));
	SHA1_Final((unsigned char *) crypt_key, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char *) crypt_key, BINARY_SIZE);
	SHA1_Final((unsigned char *) crypt_key, &ctx);
#endif
}

static void *binary(char *ciphertext)
{
	static unsigned char *realcipher;
	int i;

	if (!realcipher)
		realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	// ignore first character '*'
	ciphertext += 1;
	for (i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
#ifdef MMX_COEF
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static int binary_hash_0(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFFF;
}

#ifdef SHA1_SSE_PARA
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
#else
static int get_hash_0(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xF;
}

static int get_hash_1(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFF;
}

static int get_hash_2(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFF;
}

static int get_hash_3(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFFF;
}
#endif

struct fmt_main fmt_mysqlSHA1 = {
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
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
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
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
