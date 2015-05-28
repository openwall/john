/*
 * New NSLDAP format based on NSLDAP_fmt.c and rawSHA1_fmt.c
 *
 * This software is Copyright (c) 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_nsldap;
#elif FMT_REGISTERS_H
john_register_one(&fmt_nsldap);
#else

#include <string.h>

#include "arch.h"

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif
#include "sse-intrinsics.h"

#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "base64.h"
#include "memdbg.h"

#define FORMAT_LABEL			"nsldap"
#define FORMAT_NAME			"Netscape LDAP {SHA}"

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		55
#define CIPHERTEXT_LENGTH		28

#define BINARY_SIZE			20
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{SHA}"
#define NSLDAP_MAGIC_LENGTH 5
#define BASE64_ALPHABET	  \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static struct fmt_tests tests[] = {
	{"{SHA}MtEMe4z5ZXDKBM438qGdhCQNOok=", "abcdefghijklmnopqrstuvwxyz"},
	{"{SHA}cMiB1KJphN3OeV9vcYF8nPRIDnk=", "aaaa"},
	{"{SHA}iu0TIuVFC62weOH7YKgXod8loso=", "bbbb"},
	{"{SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=", "ccccccccc"},
	{"{SHA}vNR9eUfJfcKmdkLDqNoKagho+qU=", "dddddddddd"},
	{"{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ=", "12345"},
	{"{SHA}IOq+XWSw4hZ5boNPUtYf0LcDMvw=", "1234567"},
	{"{SHA}fEqNCco3Yq9h5ZUglD3CZJT4lBs=", "123456"},
	{"{SHA}d1u5YbgdocpJIXpI5TPIMsM3FUo=", "princess"},
	{"{SHA}Y2fEjdGT1W6nsLqtJbGUVeUp9e4=", "abc123"},
	{"{SHA}fCIvspJ9goryL1khNOiTJIBjfA0=", "12345678"},
	{"{SHA}7o2HKPQ1/VUPg4Uqq6tSNM4dpSg=", "iloveyou"},
	{"{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "password"},
	{"{SHA}98O8HYCOBHMq32eZZczDTKeuNEE=", "123456789"},
	{"{SHA}X+4AI5lA+IPUwoVOQcf5iedSeKM=", "nicole"},
	{"{SHA}8c9lHOGiGRp2DAsvFhI095WOJuQ=", "rockyou"},
	{"{SHA}PQ87ndys7DDEAIxeAw5sE6R4y08=", "daniel"},
	{NULL}
};

#ifdef SIMD_COEF_32
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key nsldap_saved_key
#define crypt_key nsldap_crypt_key
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS];
JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char crypt_key[BINARY_SIZE*NBKEYS];
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH))
		return 0;

	ciphertext += NSLDAP_MAGIC_LENGTH;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH ||
	    strspn(ciphertext, BASE64_ALPHABET "=") != CIPHERTEXT_LENGTH)
		return 0;

	return 1;
}

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_32
	memset(saved_key, 0, sizeof(saved_key));
#endif
}

static void set_key(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	ARCH_WORD_32 *keybuffer = (ARCH_WORD_32*)&saved_key[GETPOS(3, index)];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
	while((temp = JOHNSWAP(*key++)) & 0xff000000) {
		if (!(temp & 0xff0000))
		{
			*keybuf_word = (temp & 0xff000000) | 0x800000;
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff00))
		{
			*keybuf_word = (temp & 0xffff0000) | 0x8000;
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff))
		{
			*keybuf_word = temp | 0x80;
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = temp;
		len += 4;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	((ARCH_WORD_32 *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = len << 3;
#else
	strnzcpy(saved_key, _key, PLAINTEXT_LENGTH + 1);
#endif
}

static char *get_key(int index) {
#ifdef SIMD_COEF_32
	unsigned int i, s;

	s = ((ARCH_WORD_32 *)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] >> 3;
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
#else
	return saved_key;
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x,y=0;

	for(;y<SIMD_PARA_SHA1;y++)
	for(x=0;x<SIMD_COEF_32;x++)
	{
		if( ((ARCH_WORD_32*)binary)[0] ==
		    ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*5] )
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
#ifdef SIMD_COEF_32
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = index/SIMD_COEF_32;

	if( ((ARCH_WORD_32*)binary)[0] != ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*5] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[1] != ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*1] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*2] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*3] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[4] != ((ARCH_WORD_32*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32*4] )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

#ifdef SIMD_COEF_32
	SSESHA1body(saved_key, (ARCH_WORD_32*)crypt_key, NULL, SSEi_MIXED_IN);
#else
	SHA_CTX ctx;
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char*) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char*) crypt_key, &ctx);
#endif
	return count;
}

static void * get_binary(char *ciphertext)
{
	static union {
		char c[BINARY_SIZE + 1 + 9];
		int dummy;
	} out;

	memset(out.c, 0, sizeof(out.c));
	base64_decode(ciphertext + NSLDAP_MAGIC_LENGTH,
	              CIPHERTEXT_LENGTH, out.c);

#ifdef SIMD_COEF_32
	alter_endianity((unsigned char*)out.c, BINARY_SIZE);
#endif
	return (void*)out.c;
}

#ifdef SIMD_COEF_32
#define HASH_IDX ((index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SIMD_COEF_32*5)
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0x7ffffff; }
#endif

struct fmt_main fmt_nsldap = {
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
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
