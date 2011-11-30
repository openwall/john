/*
 * New NSLDAP format based on NSLDAP_fmt.c (by Sun-Zero, 2004)
 * and rawSHA1_fmt.c (Copyright (c) 2004 bartavelle,
 * bartavelle at bandecon.com)
 *
 * Whipped together by magnum, 2011. No rights reserved.
 */

#include <string.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF			4
#include "sse-intrinsics.h"
#define NBKEYS				(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS				MMX_COEF
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "base64.h"

#define FORMAT_LABEL			"nsldap"
#define FORMAT_NAME			"Netscape LDAP SHA"

#ifdef SHA1_N_STR
#define ALGORITHM_NAME			"SSE2i " SHA1_N_STR
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

#define PLAINTEXT_LENGTH		55
#define CIPHERTEXT_LENGTH		33

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*80*MMX_COEF*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{SHA}"
#define NSLDAP_MAGIC_LENGTH 5

static struct fmt_tests tests[] = {
	{"{SHA}cMiB1KJphN3OeV9vcYF8nPRIDnk=", "aaaa"},
	{"{SHA}iu0TIuVFC62weOH7YKgXod8loso=", "bbbb"},
	{"{SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=", "ccccccccc"},
	{"{SHA}vNR9eUfJfcKmdkLDqNoKagho+qU=", "dddddddddd"},
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key nsldap_saved_key
#define crypt_key nsldap_crypt_key
#if defined (_MSC_VER)
__declspec(align(16)) unsigned char saved_key[80*4*NBKEYS];
__declspec(align(16)) unsigned char crypt_key[BINARY_SIZE*NBKEYS];
#else
unsigned char saved_key[80*4*NBKEYS] __attribute__ ((aligned(16)));
unsigned char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
#endif
#ifndef SHA1_SSE_PARA
static unsigned long total_len;
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
	const unsigned int *key = (unsigned int*)_key;
	unsigned int *keybuffer = (unsigned int*)&saved_key[GETPOS(3, index)];
	unsigned int *keybuf_word = keybuffer;
	unsigned ARCH_WORD len, temp;

#ifndef SHA1_SSE_PARA
	if (!index)
		total_len = 0;
#endif
	len = 0;
	while((temp = *key++) & 0xff) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = temp << 24 | 0x80 << 16;
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = temp << 24 | ((temp & 0xff00) | 0x80) << 8;
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = temp << 24 | (temp & 0xff00) << 8 | (temp & 0xff0000 >> 8) | 0x80;
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = temp << 24 | (temp & 0xff00) << 8 | (temp & 0xff0000 >> 8) | temp >> 24 ;
		len += 4;
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80 << 24;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef SHA1_SSE_PARA
	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] = len << 3;
#else
	total_len += len << ( (32/MMX_COEF) * index);
#endif
#else
	strnzcpy(saved_key, _key, PLAINTEXT_LENGTH + 1);
#endif
}

static char *get_key(int index) {
#ifdef MMX_COEF
	unsigned int i, s;

#ifdef SHA1_SSE_PARA
	s = ((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] >> 3;
#else
	s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
#endif
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
# ifdef SHA1_SSE_PARA
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
	for(;y<SHA1_SSE_PARA;y++)
#endif
		for(x=0;x<MMX_COEF;x++)
			{
				if( ((unsigned int*)binary)[0] == ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] )
					return 1;
			}
	return 0;
# else
	int i=0;
	while(i< (BINARY_SIZE/4) )
		{
			if (
			    ( ((unsigned long*)binary)[i] != ((unsigned long*)crypt_key)[i*MMX_COEF])
			    && ( ((unsigned long*)binary)[i] != ((unsigned long*)crypt_key)[i*MMX_COEF+1])
#   if (MMX_COEF > 3)
			    && ( ((unsigned long*)binary)[i] != ((unsigned long*)crypt_key)[i*MMX_COEF+2])
			    && ( ((unsigned long*)binary)[i] != ((unsigned long*)crypt_key)[i*MMX_COEF+3])
#   endif
			    )
				return 0;
			i++;
		}
	return 1;
# endif
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
# if SHA1_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((unsigned int*)binary)[0] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] )
		return 0;
	if( ((unsigned int*)binary)[1] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+4] )
		return 0;
	if( ((unsigned int*)binary)[2] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+8] )
		return 0;
	if( ((unsigned int*)binary)[3] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+12] )
		return 0;
	if( ((unsigned int*)binary)[4] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+16] )
		return 0;
	return 1;
# else
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long*)binary)[i] != ((unsigned long*)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
# endif
#else
	return cmp_all(binary, index);
#endif
}

static void crypt_all(int count) {
#ifdef MMX_COEF

# if SHA1_SSE_PARA
	SSESHA1body(saved_key, (unsigned int*)crypt_key, NULL, 0);
# else
	shammx_nofinalbyteswap((unsigned char*) crypt_key, (unsigned char*) saved_key, total_len);
# endif

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

#ifdef MMX_COEF
static int get_hash_0(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] & 0xfffff;
}
#else
static int get_hash_0(int index) { return ((unsigned int*)crypt_key)[0] & 0xf; }
static int get_hash_1(int index) { return ((unsigned int*)crypt_key)[0] & 0xff; }
static int get_hash_2(int index) { return ((unsigned int*)crypt_key)[0] & 0xfff; }
static int get_hash_3(int index) { return ((unsigned int*)crypt_key)[0] & 0xffff; }
static int get_hash_4(int index) { return ((unsigned int*)crypt_key)[0] & 0xfffff; }
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
