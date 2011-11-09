/*
 * Copyright (c) 2004 bartavelle
 * bartavelle at bandecon.com
 */

#include <string.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF	4
#include "sse-intrinsics.h"
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS	MMX_COEF
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"

#define FORMAT_LABEL			"raw-sha1"
#define FORMAT_NAME			"Raw SHA-1"

#ifdef SHA1_N_STR
#define ALGORITHM_NAME			SHA1_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define ALGORITHM_NAME			"4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define ALGORITHM_NAME			"2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		55
#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
//#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) ) //std getpos
//#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) ) //for endianity conversion
//#define GETPOS(i, index)		( (index&3)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) + (index>>2)*80*MMX_COEF*4 ) //for endianity conversion
// this version works properly for MMX, SSE2 (.S) and SSE2 intrinsic.
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*80*MMX_COEF*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests rawsha1_tests[] = {
	{"c3e337f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{"095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawSHA1_saved_key
#define crypt_key rawSHA1_crypt_key
#if defined (_MSC_VER)
__declspec(align(16)) char saved_key[80*4*NBKEYS];
__declspec(align(16)) char crypt_key[BINARY_SIZE*NBKEYS];
#else
char saved_key[80*4*NBKEYS] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
#endif
static unsigned long total_len;
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void rawsha1_init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	memset(saved_key, 0, sizeof(saved_key));
#endif
}

static void rawsha1_set_key(char *key, int index) {
#ifdef MMX_COEF
	int len;
	int i;

	if(index==0)
	{
		total_len = 0;
		//memset(saved_key, 0, sizeof(saved_key));
		i = 0;
#ifdef SHA1_SSE_PARA
		for (; i < SHA1_SSE_PARA; ++i)
#endif
			memset(&saved_key[i*4*80*MMX_COEF], 0, 56*MMX_COEF);
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];

	saved_key[GETPOS(i, index)] = 0x80;
#ifdef SHA1_SSE_PARA
	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] = i<<3;
#else
	total_len += len << ( ( (32/MMX_COEF) * index ) );
#endif

#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *rawsha1_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;

#ifdef SHA1_SSE_PARA
	s = ((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] >> 3;
#else
	s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
#endif
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
	return saved_key;
#endif
}

static int rawsha1_cmp_all(void *binary, int count) {
#ifdef MMX_COEF
// NOTE the cmp_all and cmp_one can likely work fine, using just the PARA blocks.  however, the original code has been kept (for now)
# ifdef SHA1_SSE_PARA
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
	for(;y<SHA1_SSE_PARA;y++)
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((unsigned int *)binary)[0] == ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
# else
	int i=0;
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+1])
#   if (MMX_COEF > 3)
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+2])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+3])
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

static int rawsha1_cmp_exact(char *source, int count){
  return (1);
}

static int rawsha1_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
# if SHA1_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((unsigned int *)binary)[0] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] )
		return 0;
	if( ((unsigned int *)binary)[1] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+4] )
		return 0;
	if( ((unsigned int *)binary)[2] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+8] )
		return 0;
	if( ((unsigned int *)binary)[3] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+12] )
		return 0;
	if( ((unsigned int *)binary)[4] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+16] )
		return 0;
	return 1;
# else
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
# endif
#else
	return rawsha1_cmp_all(binary, index);
#endif
}

static void rawsha1_crypt_all(int count) {
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF

# if SHA1_SSE_PARA
	SSESHA1body(saved_key, (unsigned int *)crypt_key, NULL, 0);
# else
	shammx((unsigned char *) crypt_key, (unsigned char *) saved_key, total_len);
# endif

#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif

}

static void * rawsha1_binary(char *ciphertext)
{
	static unsigned char realcipher[BINARY_SIZE];
	int i;

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
// if we try to unify the rawsha1_cmp_one() and and rawsha1_cmp_all() functions, we should endian alter for all MMX_COEF.
// Right now, for MMX/SSE non-para, we keep the older methods.
#ifdef SHA1_SSE_PARA
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }

#ifdef MMX_COEF
static int get_hash_0(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xfffff;
}
#else
static int get_hash_0(int index) { return ((unsigned int *)crypt_key)[0] & 0xf; }
static int get_hash_1(int index) { return ((unsigned int *)crypt_key)[0] & 0xff; }
static int get_hash_2(int index) { return ((unsigned int *)crypt_key)[0] & 0xfff; }
static int get_hash_3(int index) { return ((unsigned int *)crypt_key)[0] & 0xffff; }
static int get_hash_4(int index) { return ((unsigned int *)crypt_key)[0] & 0xfffff; }
#endif

struct fmt_main fmt_rawSHA1 = {
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
		rawsha1_tests
	}, {
		rawsha1_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		rawsha1_binary,
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
		rawsha1_set_key,
		rawsha1_get_key,
		fmt_default_clear_keys,
		rawsha1_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		rawsha1_cmp_all,
		rawsha1_cmp_one,
		rawsha1_cmp_exact
	}
};
