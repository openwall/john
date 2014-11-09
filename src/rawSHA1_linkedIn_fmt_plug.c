/*
 * This software is Copyright (c) 2004 bartavelle, <simon at banquise.net>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Optimised set_key() by magnum, 2012
 *
 * This file 'hacked' to work with the LinkedIn hash leak. Those hashes had
 * a lot of partial hashes in there. 00000 was overwritten on hashes that
 * were cracked. In this change, we simply ignore the first 20 bits of the
 * hash, when doing a compare.  JimF June, 2012.
 *
 * NOTE! This format will write complete (repaired) SHA-1 hashes to the .pot
 * file. To show all cracked password properly, you need to *not* specify this
 * format but raw-sha1.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA1_LI;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA1_LI);
#else

#include <string.h>

#include "arch.h"

#ifdef MMX_COEF
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#endif
#include "sse-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include "loader.h"
#include "memdbg.h"

#define FORMAT_LABEL			"Raw-SHA1-Linkedin"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define FORMAT_TAG			"$dynamic_26$"
#define TAG_LENGTH			12

#define PLAINTEXT_LENGTH		55
#define HASH_LENGTH			40
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define BINARY_SIZE			20
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
// this version works properly for MMX, SSE2 (.S) and SSE2 intrinsic.
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

/* We can't have crippled hashes in the tests, due to how JtR core works */
static struct fmt_tests tests[] = {
	{"c3e337f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	//{"000007f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	//{"00000eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},

	// if we have these 2 (raw and same) we get a source error. NOTE, the code
	// works, the source error is a red-herring.
//	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{FORMAT_TAG "a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	//{FORMAT_TAG "00000E364706816ABA3E25717850C26C9CD0D89D", "abc"},

	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	//{"000008090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	//{"0000012f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{"095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	//{"00000c1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	//{"00000b0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{NULL}
};

/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawSHA1_saved_key_LI
#define crypt_key rawSHA1_crypt_key_LI
#ifdef MMX_COEF
JTR_ALIGN(16) ARCH_WORD_32 saved_key[SHA_BUF_SIZ*NBKEYS];
JTR_ALIGN(16) ARCH_WORD_32 crypt_key[BINARY_SIZE/4*NBKEYS];
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext, struct fmt_main *self)
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

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	strncpy(out, FORMAT_TAG, sizeof(out));

	memcpy(&out[TAG_LENGTH], ciphertext, HASH_LENGTH);
	out[CIPHERTEXT_LENGTH] = 0;

	// 'normalize' these hashes to all 'appear' to be 00000xxxxxx hashes.
	// on the source() function, we later 'fix' these up.
	memcpy(&out[TAG_LENGTH], "00000", 5);

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

	s = saved_key[15*MMX_COEF + (index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF] >> 3;
	for(i=0;i<s;i++)
		out[i] = ((unsigned char*)saved_key)[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
	return saved_key;
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;

	for(;y<SHA1_SSE_PARA;y++)
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((ARCH_WORD_32*)binary)[1] == crypt_key[x+y*MMX_COEF*5+MMX_COEF] )
			return 1;
	}
	return 0;
#else
	return !memcmp(&((ARCH_WORD_32*)binary)[1], &crypt_key[1], BINARY_SIZE - 4);
#endif
}

static int cmp_exact(char *source, int count)
{
	return (1);
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&3;
	y = index/4;

//	if( ((ARCH_WORD_32*)binary)[0] != crypt_key[x+y*MMX_COEF*5] )
//		return 0;
	if( ((ARCH_WORD_32*)binary)[1] != crypt_key[x+y*MMX_COEF*5+MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != crypt_key[x+y*MMX_COEF*5+2*MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != crypt_key[x+y*MMX_COEF*5+3*MMX_COEF] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[4] != crypt_key[x+y*MMX_COEF*5+4*MMX_COEF] )
		return 0;
	return 1;
#else
	if( ((ARCH_WORD_32*)binary)[1] != crypt_key[1] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != crypt_key[2] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != crypt_key[3] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[4] != crypt_key[4] )
		return 0;
	return 1;
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	SSESHA1body(saved_key, crypt_key, NULL, SSEi_MIXED_IN);
#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif
	return count;
}

static void *binary(char *ciphertext)
{
	static unsigned char *realcipher;
	int i;

	if (!realcipher)
		realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	ciphertext += TAG_LENGTH;

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
#ifdef MMX_COEF
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32*)binary)[1] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32*)binary)[1] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32*)binary)[1] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32*)binary)[1] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32*)binary)[1] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32*)binary)[1] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32*)binary)[1] & 0x7ffffff; }

#ifdef MMX_COEF
#define INDEX	((index&3)+(index>>2)*MMX_COEF*5)
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+MMX_COEF] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+MMX_COEF] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+MMX_COEF] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+MMX_COEF] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+MMX_COEF] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+MMX_COEF] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+MMX_COEF] & 0x7ffffff; }
#undef INDEX
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & 0x7ffffff; }
#endif

static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH + 1];
	unsigned char realcipher[BINARY_SIZE];
	unsigned char *cpi;
	char *cpo;
	int i;

#ifdef MMX_COEF
	for (i = 0; i < NBKEYS; ++i) {
		if (crypt_key[(i/MMX_COEF)*20+MMX_COEF+(i%MMX_COEF)] == ((ARCH_WORD_32*)binary)[1]) {
			// Ok, we may have found it.  Check the next 3 DWORDS
			if (crypt_key[(i/MMX_COEF)*20+MMX_COEF*2+(i%MMX_COEF)] == ((ARCH_WORD_32*)binary)[2] &&
			    crypt_key[(i/MMX_COEF)*20+MMX_COEF*3+(i%MMX_COEF)] == ((ARCH_WORD_32*)binary)[3] &&
			    crypt_key[(i/MMX_COEF)*20+MMX_COEF*4+(i%MMX_COEF)] == ((ARCH_WORD_32*)binary)[4]) {
				((ARCH_WORD_32*)binary)[0] = crypt_key[(i/MMX_COEF)*20+(i%MMX_COEF)];
				break;
			}
		}
	}
#else
	if (crypt_key[1] == ((ARCH_WORD_32*)binary)[1] &&
		crypt_key[2] == ((ARCH_WORD_32*)binary)[2] &&
		crypt_key[3] == ((ARCH_WORD_32*)binary)[3] &&
		crypt_key[4] == ((ARCH_WORD_32*)binary)[4])
		   ((ARCH_WORD_32*)binary)[0] = crypt_key[0];
#endif
	memcpy(realcipher, binary, BINARY_SIZE);
#ifdef MMX_COEF
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	strcpy(Buf, FORMAT_TAG);
	cpo = &Buf[TAG_LENGTH];

	cpi = realcipher;

	for (i = 0; i < BINARY_SIZE; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

struct fmt_main fmt_rawSHA1_LI = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		source,
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

#endif /* plugin stanza */
