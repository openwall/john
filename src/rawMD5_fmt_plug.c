/*
 * Raw-MD5 (thick) based on Raw-MD4 w/ mmx/sse/intrinsics
 * This  software is Copyright © 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#include <string.h>

#include "arch.h"

#include "md5.h"
#include "common.h"
#include "formats.h"
#include "params.h"

#define FORMAT_LABEL		"raw-md5"
#define FORMAT_NAME			"Raw MD5"

#ifdef MD5_SSE_PARA
#  define MMX_COEF				4
#  include "sse-intrinsics.h"
#  define NBKEYS				(MMX_COEF * MD5_SSE_PARA)
#  define DO_MMX_MD5(in, out)	SSEmd5body(in, (unsigned int*)out, 1)
#  define ALGORITHM_NAME		"SSE2i " MD5_N_STR
#elif defined(MMX_COEF)
#  define NBKEYS				MMX_COEF
#  define DO_MMX_MD5(in, out)	mdfivemmx_nosizeupdate(out, in, 1)
#  if MMX_COEF == 4
#    define ALGORITHM_NAME		"SSE2 4x"
#  elif MMX_COEF == 2
#    define ALGORITHM_NAME		"MMX 2x"
#  elif defined(MMX_COEF)
#    define ALGORITHM_NAME		"?"
#  endif
#else
#  define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE				16
#define SALT_SIZE				0

#define FORMAT_TAG				"$dynamic_0$"
#define TAG_LENGTH				11

static struct fmt_tests tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a","test1"},
	{FORMAT_TAG "378e2c4a07968da2eca692320136433d","thatsworking"},
	{FORMAT_TAG "8ad8757baa8564dc136c1e07507f4a98","test3"},
	{"d41d8cd98f00b204e9800998ecf8427e", ""},
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
#define saved_key rawmd5_saved_key
#define crypt_key rawmd5_crypt_key
#if defined (_MSC_VER)
__declspec(align(16)) unsigned char saved_key[64*MAX_KEYS_PER_CRYPT];
__declspec(align(16)) unsigned char crypt_key[BINARY_SIZE*MAX_KEYS_PER_CRYPT];
#else
unsigned char saved_key[64*MAX_KEYS_PER_CRYPT] __attribute__ ((aligned(MMX_COEF*4)));
unsigned char crypt_key[BINARY_SIZE*MAX_KEYS_PER_CRYPT+1] __attribute__ ((aligned(MMX_COEF*4)));
#endif
#else
static MD5_CTX ctx;
static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_out[4];
#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
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

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

#ifdef MMX_COEF
#define HASH_OFFSET (index&(MMX_COEF-1))+(index/MMX_COEF)*MMX_COEF*4
static int get_hash_0(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { 	return crypt_out[0] & 0xf; }
static int get_hash_1(int index) { 	return crypt_out[0] & 0xff; }
static int get_hash_2(int index) { 	return crypt_out[0] & 0xfff; }
static int get_hash_3(int index) { 	return crypt_out[0] & 0xffff; }
static int get_hash_4(int index) { 	return crypt_out[0] & 0xfffff; }
static int get_hash_5(int index) { 	return crypt_out[0] & 0xffffff; }
static int get_hash_6(int index) { 	return crypt_out[0] & 0x7ffffff; }
#endif

static void set_key(char *_key, int index)
{
#ifdef MMX_COEF
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	ARCH_WORD_32 *keybuffer = (ARCH_WORD_32*)&saved_key[GETPOS(0, index)];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

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
	/*
	 * This works for MMX, SSE2 and SSE2i.  Note, for 32 bit MMX/SSE2, we now use
	 * mdfivemmx_nosizeupdate and not mdfivemmx function. Setting the size here,
	 * and calling the 'nosizeupdate' function is about 5% faster, AND it makes the
	 * code much more similar between SSE2i and older 32 bit SSE2
	 */
	keybuffer[14*MMX_COEF] = len << 3;
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

	len = ((ARCH_WORD_32*)&saved_key[GETPOS(0, index)])[14*MMX_COEF] >> 3;

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
#if MMX_COEF
	DO_MMX_MD5(saved_key, crypt_key);
#else
	MD5_Init(&ctx);
	MD5_Update(&ctx, saved_key, saved_key_length);
	MD5_Final((unsigned char *)crypt_out, &ctx);
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;
#ifdef MD5_SSE_PARA
	for(; y < MD5_SSE_PARA; y++)
#endif
		for(x = 0; x < MMX_COEF; x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+x] )
				return 1;
		}
	return 0;
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
	unsigned int i,x,y;
	x = index&(MMX_COEF-1);
	y = index/MMX_COEF;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+i*MMX_COEF+x] )
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_out, BINARY_SIZE);
#endif
}

struct fmt_main fmt_rawMD5 = {
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
		cmp_exact,
		fmt_default_get_source
	}
};
