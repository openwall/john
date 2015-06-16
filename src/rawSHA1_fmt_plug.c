/*
 * This software is Copyright (c) 2004 bartavelle, <simon at banquise.net>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Optimised set_key() and reduced binary size by magnum, 2012
 *
 * OMP added May 2013, JimF
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA1);
#else

#include <string.h>

#include "arch.h"

#include "sha.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"

#if !FAST_FORMATS_OMP
#undef _OPENMP
#endif

#ifdef _OPENMP
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE               1024
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE				2048
#endif
#endif
#include <omp.h>
#endif
#include "sse-intrinsics.h"
#include "memdbg.h"

#define FORMAT_LABEL			"Raw-SHA1"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"SHA1 " SHA1_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_SHA1)
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define FORMAT_TAG				"$dynamic_26$"
#define TAG_LENGTH				12

#define HASH_LENGTH				40
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define DIGEST_SIZE				20
#define BINARY_SIZE				20 // source()
#define BINARY_ALIGN			4
#define SALT_SIZE				0
#define SALT_ALIGN				1

static struct fmt_tests tests[] = {
	{"c3e337f070b64a50e9d31ac3f9eda35120e29d6c", "digipalmw221u"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	{FORMAT_TAG "A9993E364706816ABA3E25717850C26C9CD0D89D", "abc"},
	// repeat hash in exactly the same form that is used in john.pot (lower case)
	{FORMAT_TAG "a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{"095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{NULL}
};

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH		55
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 ) //for endianity conversion
#else
#define PLAINTEXT_LENGTH		125
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#ifdef SIMD_COEF_32
static ARCH_WORD_32 (*saved_key)[SHA_BUF_SIZ*NBKEYS];
static ARCH_WORD_32 (*crypt_key)[DIGEST_SIZE/4*NBKEYS];
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_key)[DIGEST_SIZE / 4];
#endif

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef SIMD_COEF_32
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*saved_key), MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#endif
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

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

	strlwr(&out[TAG_LENGTH]);

	return out;
}

#ifdef SIMD_COEF_32
#define HASH_OFFSET	(index&(SIMD_COEF_32-1))+(((unsigned int)index%NBKEYS)/SIMD_COEF_32)*SIMD_COEF_32*5
static int get_hash_0(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index/NBKEYS][HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index][0] & 0x7ffffff; }
#endif

#ifdef SIMD_COEF_32
static void set_key(char *key, int index)
{
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32*)saved_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32];
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
}
#else
static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
}
#endif

#ifdef SIMD_COEF_32
static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int i;
	ARCH_WORD_32 len = ((ARCH_WORD_32*)saved_key)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] >> 3;

	for(i=0;i<len;i++)
		out[i] = ((char*)saved_key)[GETPOS(i, index)];
	out[i] = 0;
	return (char*)out;
}
#else
static char *get_key(int index) {
	return saved_key[index];
}
#endif

static void *get_binary(char *ciphertext)
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
#ifdef SIMD_COEF_32
	alter_endianity(realcipher, DIGEST_SIZE);
#endif
	return (void*)realcipher;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
	int loops = (count + MAX_KEYS_PER_CRYPT - 1) / MAX_KEYS_PER_CRYPT;

#pragma omp parallel for
	for (index = 0; index < loops; ++index)
#endif
	{
#if SIMD_COEF_32
		SSESHA1body(saved_key[index], crypt_key[index], NULL, SSEi_MIXED_IN);
#else
		SHA_CTX ctx;
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, (unsigned char*) saved_key[index], strlen( saved_key[index] ) );
		SHA1_Final( (unsigned char*) crypt_key[index], &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count) {
	int index;
	for (index = 0; index < count; index++)
#ifdef SIMD_COEF_32
        if (((ARCH_WORD_32 *) binary)[0] == ((ARCH_WORD_32*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32])
#else
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_key[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(ARCH_WORD_32); i++)
        if (((ARCH_WORD_32 *) binary)[i] != ((ARCH_WORD_32*)crypt_key)[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32+i*SIMD_COEF_32])
            return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH + 1];
	unsigned char realcipher[BINARY_SIZE];
	unsigned char *cpi;
	char *cpo;
	int i;

	memcpy(realcipher, binary, BINARY_SIZE);
#ifdef SIMD_COEF_32
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

struct fmt_main fmt_rawSHA1 = {
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
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		source,
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
