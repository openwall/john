/*
 * New NSLDAP format based on NSLDAP_fmt.c and rawSHA1_fmt.c
 *
 * This  software is Copyright © 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#include <string.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF			4
#define NBKEYS				(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS				MMX_COEF
#endif
#include "sse-intrinsics.h"

#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "base64.h"

#define FORMAT_LABEL			"nsldap"
#define FORMAT_NAME			"Netscape LDAP SHA-1"

#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		55
#define CIPHERTEXT_LENGTH		33

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{SHA}"
#define NSLDAP_MAGIC_LENGTH 5

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

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key nsldap_saved_key
#define crypt_key nsldap_crypt_key
#if defined (_MSC_VER)
__declspec(align(16)) unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS];
__declspec(align(16)) unsigned char crypt_key[BINARY_SIZE*NBKEYS];
#else
unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS] __attribute__ ((aligned(16)));
unsigned char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
#endif
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	if (ciphertext && strlen(ciphertext) == CIPHERTEXT_LENGTH)
		return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
	return 0;
}

static void init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	memset(saved_key, 0, sizeof(saved_key));
#endif
}

static void set_key(char *_key, int index)
{
#ifdef MMX_COEF
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
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}
	((ARCH_WORD_32 *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] = len << 3;
#else
	strnzcpy(saved_key, _key, PLAINTEXT_LENGTH + 1);
#endif
}

static char *get_key(int index) {
#ifdef MMX_COEF
	unsigned int i, s;

	s = ((ARCH_WORD_32 *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] >> 3;
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
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
		if( ((ARCH_WORD_32*)binary)[0] ==
		    ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count){
	return (1);
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((ARCH_WORD_32*)binary)[0] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[1] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*1] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*2] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*3] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[4] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*4] )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static void crypt_all(int count) {
#ifdef MMX_COEF

#if SHA1_SSE_PARA
	SSESHA1body(saved_key, (ARCH_WORD_32*)crypt_key, NULL, 0);
#else
	shammx_nosizeupdate_nofinalbyteswap((unsigned char*) crypt_key, (unsigned char*) saved_key, 1);
#endif

#else
	SHA_CTX ctx;
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char*) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char*) crypt_key, &ctx);
#endif
}

static void * binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE + 9];

	memset(realcipher, 0, sizeof(realcipher));
	base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);

#ifdef MMX_COEF
	alter_endianity((unsigned char*)realcipher, BINARY_SIZE);
#endif
	return (void*)realcipher;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0x7ffffff; }

#ifdef MMX_COEF
#define HASH_IDX ((index&3)+(index/4)*MMX_COEF*5)
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
