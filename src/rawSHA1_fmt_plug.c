/*
 * Copyright (c) 2004 bartavelle
 * bartavelle at bandecon.com
 *
 * Optimised set_key() and reduced binary size by magnum, 2012
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
#include "johnswap.h"

#define FORMAT_LABEL			"raw-sha1"
#define FORMAT_NAME			"Raw SHA-1"

#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define FORMAT_TAG			"$dynamic_26$"
#define TAG_LENGTH			12

#define PLAINTEXT_LENGTH		55
#define HASH_LENGTH			40
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define DIGEST_SIZE			20
#define BINARY_SIZE			4
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
// this version works properly for MMX, SSE2 (.S) and SSE2 intrinsic.
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"c3e337f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{FORMAT_TAG "A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{"095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{NULL}
};

/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawSHA1_saved_key
#define crypt_key rawSHA1_crypt_key
#ifdef MMX_COEF
#if defined (_MSC_VER)
__declspec(align(16)) ARCH_WORD_32 saved_key[SHA_BUF_SIZ*NBKEYS];
__declspec(align(16)) ARCH_WORD_32 crypt_key[DIGEST_SIZE/4*NBKEYS];
#else
ARCH_WORD_32 saved_key[SHA_BUF_SIZ*NBKEYS] __attribute__ ((aligned(16)));
ARCH_WORD_32 crypt_key[DIGEST_SIZE/4*NBKEYS] __attribute__ ((aligned(16)));
#endif
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[DIGEST_SIZE / 4];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	if (strlen(ciphertext) != HASH_LENGTH)
		return 0;

	for (i = 0; i < HASH_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	strncpy(out, FORMAT_TAG, sizeof(out));

	memcpy(&out[TAG_LENGTH], ciphertext, HASH_LENGTH);
	out[CIPHERTEXT_LENGTH] = 0;

	strlwr(&out[TAG_LENGTH]);

	return out;
}

static void set_key(char *key, int index) {
#ifdef MMX_COEF
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuffer = &saved_key[(index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF];
	ARCH_WORD_32 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
	while((unsigned char)(temp = *wkey++)) {
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
	keybuffer[15*MMX_COEF] = len << 3;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;

	s = saved_key[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] >> 3;
	for(i=0;i<s;i++)
		out[i] = ((unsigned char*)saved_key)[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
#else
	return saved_key;
#endif
}

static void *binary(char *ciphertext)
{
	static unsigned char *realcipher;
	int i;

	if (!realcipher)
		realcipher = mem_alloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	ciphertext += TAG_LENGTH;

	for(i=0;i<DIGEST_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
#ifdef MMX_COEF
	alter_endianity(realcipher, DIGEST_SIZE);
#endif
	return (void*)realcipher;
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x, y=0;

#ifdef SHA1_SSE_PARA
	for(;y<SHA1_SSE_PARA;y++)
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((ARCH_WORD_32*)binary)[0] == crypt_key[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	unsigned int x, y;
	x = index&3;
	y = index/4;

	return ((ARCH_WORD_32*)binary)[0] == crypt_key[x+y*MMX_COEF*5];
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
#if BINARY_SIZE == DIGEST_SIZE
	return 1;
#else
#ifdef MMX_COEF
	unsigned int x, y;
	ARCH_WORD_32 *full_binary;

	full_binary = (ARCH_WORD_32*)binary(source);
	x = index&3;
	y = index/4;

	if( ((ARCH_WORD_32*)full_binary)[0] != crypt_key[x+y*MMX_COEF*5] )
		return 0;
	if( ((ARCH_WORD_32*)full_binary)[1] != crypt_key[x+y*MMX_COEF*5+MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)full_binary)[2] != crypt_key[x+y*MMX_COEF*5+2*MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)full_binary)[3] != crypt_key[x+y*MMX_COEF*5+3*MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)full_binary)[4] != crypt_key[x+y*MMX_COEF*5+4*MMX_COEF] )
		return 0;
	return 1;
#else
	return !memcmp(binary(source), crypt_key, DIGEST_SIZE);
#endif
#endif
}

static void crypt_all(int count) {
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF

# if SHA1_SSE_PARA
	SSESHA1body(saved_key, crypt_key, NULL, 0);
# else
	shammx_nosizeupdate_nofinalbyteswap((unsigned char*) crypt_key, (unsigned char*) saved_key, 1);
# endif

#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char*) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char*) crypt_key, &ctx);
#endif

}

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffffff; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0x7ffffff; }

#ifdef MMX_COEF
#define INDEX	((index&3)+(index>>2)*MMX_COEF*5)
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX] & 0x7ffffff; }
#undef INDEX
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0x7ffffff; }
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		split,
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
