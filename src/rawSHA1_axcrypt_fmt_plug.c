/* AxCrypt 1.x in-memory cached Key-Encryption-Key cracker
 * 2016 by Fist0urs <eddy.maaalou at gmail.com>.
 *
 * This software is Copyright (c) 2016, Fist0urs <eddy.maaalou at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. 
 *
 * Optimised set_key() by magnum, 2012
 *
 * This implementation is highly inspirated from bartavelle, <simon at banquise.net>, 
 * raw-sha1-linkedin one. 
 * It aims to crack AxCrypt in-memory cached keys which are stored in raw-sha1
 * format, reduced to 16bytes. */

#include "arch.h"

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA1_axcrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA1_axcrypt);
#else

#include <string.h>

#ifdef SIMD_COEF_32
#define NBKEYS	(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif
#include "simd-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include "loader.h"
#include "rawSHA1_common.h"
#include "base64_convert.h"
#include "memdbg.h"

#define FORMAT_LABEL			"Raw-SHA1-AxCrypt"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1


#define PLAINTEXT_LENGTH		55
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define BINARY_SIZE			20
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
// this version works properly for MMX, SSE2 (.S) and SSE2 intrinsic.
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"e5b1b15baef2fc90a5673262440a959200000000", "oHemeheme"},
	{"2fbf0eba37de1d1d633bc1ed943b907f00000000", "azertyuiop1"},
	{"ebb7d1eff90b09efb3b3dd996e33b96700000000", "Fist0urs"},
	{"c336d15500be1804021533cb9cc0ac2f00000000", "enerveAPZ"},
	{"2a53e6ef507fabede6032a934c21aafc00000000", "gArich1g0"},
	{"145595ef8b1d96d7bd9c5ea1c6d2876671e09b57", "BasicSHA1"},
	{"{SHA}VaiuD3vBn9alvHyZcuPY0/UulBo=", "base64test"},
	{"{SHA}COqO1HN3nVE2Fh45LQs05wAAAAA=", "base64test0truncated"},
	{NULL}
};

/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key rawSHA1_saved_key_AxCrypt
#define crypt_key rawSHA1_crypt_key_AxCrypt
#ifdef SIMD_COEF_32
JTR_ALIGN(MEM_ALIGN_SIMD) ARCH_WORD_32 saved_key[SHA_BUF_SIZ*NBKEYS];
JTR_ALIGN(MEM_ALIGN_SIMD) ARCH_WORD_32 crypt_key[BINARY_SIZE/4*NBKEYS];
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[40+1];

	if (strncmp(ciphertext, "{SHA}", 5)) {
		ciphertext = rawsha1_common_split(ciphertext, index, self);

		if (strncmp(ciphertext, "{SHA}", 5))
			return ciphertext;
	}

	ciphertext += 5;
	base64_convert(ciphertext, e_b64_mime, strlen(ciphertext), out, e_b64_hex, sizeof(out), 0);

	return rawsha1_common_split(out, index, self);
}

static void set_key(char *key, int index) {
#ifdef SIMD_COEF_32
#if ARCH_ALLOWS_UNALIGNED
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
#else
	char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
	const ARCH_WORD_32 *wkey = (uint32_t*)(is_aligned(key, sizeof(uint32_t)) ?
	                                       key : strcpy(buf_aligned, key));
#endif
	ARCH_WORD_32 *keybuffer = &saved_key[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
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
			*keybuf_word = JOHNSWAP(temp | (0x80U << 24));
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP(temp);
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
	keybuffer[15*SIMD_COEF_32] = len << 3;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *get_key(int index) {
#ifdef SIMD_COEF_32
	unsigned int i,s;

	s = saved_key[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] >> 3;
	for(i=0;i<s;i++)
		out[i] = ((unsigned char*)saved_key)[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
	return saved_key;
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x,y=0;
	for(;y<SIMD_PARA_SHA1;y++)
		for(x=0;x<SIMD_COEF_32;x++)
			if( ((ARCH_WORD_32*)binary)[1] == crypt_key[x+y*SIMD_COEF_32*5+SIMD_COEF_32] )
				return 1;
	return 0;
#else
	return !memcmp(&((ARCH_WORD_32*)binary)[1], &crypt_key[1], BINARY_SIZE - 4);
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
	y = (unsigned int)index/SIMD_COEF_32;

	if( ((ARCH_WORD_32*)binary)[0] != crypt_key[x+y*SIMD_COEF_32*5] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[1] != crypt_key[x+y*SIMD_COEF_32*5+SIMD_COEF_32] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != crypt_key[x+y*SIMD_COEF_32*5+2*SIMD_COEF_32] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != crypt_key[x+y*SIMD_COEF_32*5+3*SIMD_COEF_32] )
		return 0;
	return 1;
#else
	if( ((ARCH_WORD_32*)binary)[0] != crypt_key[0] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[1] != crypt_key[1] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != crypt_key[2] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != crypt_key[3] )
		return 0;
	return 1;
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef SIMD_COEF_32
	SIMDSHA1body(saved_key, crypt_key, NULL, SSEi_MIXED_IN);
#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif
	return count;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32*)binary)[1] & PH_MASK_0; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32*)binary)[1] & PH_MASK_1; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32*)binary)[1] & PH_MASK_2; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32*)binary)[1] & PH_MASK_3; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32*)binary)[1] & PH_MASK_4; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32*)binary)[1] & PH_MASK_5; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32*)binary)[1] & PH_MASK_6; }

#ifdef SIMD_COEF_32
#define INDEX	((index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SIMD_COEF_32*5)
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_0; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_1; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_2; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_3; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_4; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_5; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[INDEX+SIMD_COEF_32] & PH_MASK_6; }
#undef INDEX
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & PH_MASK_0; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & PH_MASK_1; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & PH_MASK_2; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & PH_MASK_3; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & PH_MASK_4; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & PH_MASK_5; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[1] & PH_MASK_6; }
#endif

static void *binary(char *ciphertext)
{
	ARCH_WORD_32 *bin = (ARCH_WORD_32*)rawsha1_common_get_binary(ciphertext);
#ifdef SIMD_COEF_32
	alter_endianity(bin, BINARY_SIZE);
#endif
	return (void*)bin;
}
static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH + 1];
	ARCH_WORD_32 out[BINARY_SIZE / 4];
	unsigned char *realcipher = (unsigned char*)out;

	memcpy(realcipher, binary, BINARY_SIZE);
#ifdef SIMD_COEF_32
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	strcpy(Buf, FORMAT_TAG);
	base64_convert(realcipher, e_b64_raw, 20, &Buf[TAG_LENGTH], e_b64_mime, sizeof(Buf)-TAG_LENGTH, flg_Base64_MIME_TRAIL_EQ);
	return Buf;
}

struct fmt_main fmt_rawSHA1_axcrypt = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		rawsha1_common_prepare,
		rawsha1_common_valid,
		split,
		binary,
		fmt_default_salt,
		{ NULL },
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

#endif

