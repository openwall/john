/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 * based on rawMD4_fmt.c code, with trivial changes by groszek.
 */

#include "arch.h"
#include "sha2.h"
#include "stdint.h"
#include "params.h"
#include "common.h"
#include "johnswap.h"
#include "formats.h"
#ifdef _OPENMP
#ifdef MMX_COEF_SHA256
#define OMP_SCALE			1024
#else
#define OMP_SCALE			2048
#endif
#include <omp.h>
#endif
#include "sse-intrinsics.h"

#define FORMAT_LABEL            "raw-sha256"
#define FORMAT_NAME             "Raw SHA-256"
#define FORMAT_TAG              "$SHA256$"
#define TAG_LENGTH              8

#ifdef MMX_COEF_SHA256
#define ALGORITHM_NAME			SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " SHA2_LIB
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#ifdef MMX_COEF_SHA256
#define PLAINTEXT_LENGTH		55
#else
#define PLAINTEXT_LENGTH		125
#endif
#define CIPHERTEXT_LENGTH		64

#define BINARY_SIZE				32
#define SALT_SIZE				0

#define MIN_KEYS_PER_CRYPT		1
#ifdef MMX_COEF_SHA256
//#define MAX_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256  // NOTE need to deal with para, when we get it!!
#define MAX_KEYS_PER_CRYPT      MMX_COEF_SHA256
#else
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
	{"$SHA256$ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
	{"$SHA256$e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
	{NULL}
};

#ifdef MMX_COEF_SHA256
#define GETPOS(i, index)		( (index&(MMX_COEF_SHA256-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF_SHA256 + (3-((i)&3)) + (index>>(MMX_COEF_SHA256>>1))*SHA256_BUF_SIZ*MMX_COEF_SHA256*4 )
static uint32_t (*saved_key)[SHA256_BUF_SIZ*MMX_COEF_SHA256];
static uint32_t (*crypt_out)[8*MMX_COEF_SHA256];
#else
static int (*saved_key_length);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)
    [(BINARY_SIZE + sizeof(ARCH_WORD_32) - 1) / sizeof(ARCH_WORD_32)];
#endif

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt = omp_t * MIN_KEYS_PER_CRYPT;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt = omp_t * MAX_KEYS_PER_CRYPT;
#endif
#ifndef MMX_COEF_SHA256
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
#else
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt/MMX_COEF_SHA256, MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt/MMX_COEF_SHA256, MEM_ALIGN_SIMD);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += 8;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[8 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	strlwr(out + TAG_LENGTH);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *out;
	int i;

	if (!out)
		out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	ciphertext += TAG_LENGTH;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                 atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];
	}
#ifdef MMX_COEF_SHA256
	alter_endianity (out, BINARY_SIZE);
#endif
	return out;
}

static int binary_hash_0 (void *binary) { return *(uint32_t *) binary & 0xf; }
static int binary_hash_1 (void *binary) { return *(uint32_t *) binary & 0xff; }
static int binary_hash_2 (void *binary) { return *(uint32_t *) binary & 0xfff; }
static int binary_hash_3 (void *binary) { return *(uint32_t *) binary & 0xffff; }
static int binary_hash_4 (void *binary) { return *(uint32_t *) binary & 0xfffff; }
static int binary_hash_5 (void *binary) { return *(uint32_t *) binary & 0xffffff; }
static int binary_hash_6 (void *binary) { return *(uint32_t *) binary & 0x7ffffff; }

#ifdef MMX_COEF_SHA256
static int get_hash_0 (int index) { return crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xf; }
static int get_hash_1 (int index) { return crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xff; }
static int get_hash_2 (int index) { return crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xfff; }
static int get_hash_3 (int index) { return crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xffff; }
static int get_hash_4 (int index) { return crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xfffff; }
static int get_hash_5 (int index) { return crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xffffff; }
static int get_hash_6 (int index) { return crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_out[index][0] & 0xF; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xFF; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xFFF; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xFFFF; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xFFFFF; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xFFFFFF; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7FFFFFF; }
#endif

#ifdef MMX_COEF_SHA256
static void set_key(char *key, int index) {
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32 *)saved_key)[(index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*SHA256_BUF_SIZ*MMX_COEF];
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
}
#else
static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_key_length[index] = len;
	if (len > PLAINTEXT_LENGTH)
		len = saved_key_length[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
}
#endif

#ifdef MMX_COEF_SHA256
static char *get_key(int index) {
	unsigned int i,s;
	static char out[64];
	unsigned char *wucp = (unsigned char*)saved_key;

	s = ((ARCH_WORD_32 *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA256_BUF_SIZ*MMX_COEF] >> 3;
	for(i=0;i<s;i++)
		out[i] = wucp[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
}
#else
static char *get_key(int index)
{
	saved_key[index][saved_key_length[index]] = 0;
	return saved_key[index];
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#ifdef MMX_COEF_SHA256
	//int inc = SSE_GROUP_SZ_SHA256;  // NOTE, need to deal with para, when we get it.
	int inc = MMX_COEF_SHA256;
#else
	int inc = 1;
#endif

#pragma omp parallel for
	for (index = 0; index < count; index += inc)
#endif
	{
#ifdef MMX_COEF_SHA256
		SSESHA256body(&saved_key[index/MMX_COEF_SHA256], crypt_out[index/MMX_COEF_SHA256], NULL, SHA256_MIXED_IN);
#else
		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], saved_key_length[index]);
		SHA256_Final((unsigned char *)crypt_out[index], &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
    int index;

    for (index = 0; index < count; index++)
#ifdef MMX_COEF_SHA256
        if (((uint32_t *) binary)[0] == crypt_out[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)])
#else
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
#endif
             return 1;
    return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF_SHA256
    int i;
    for (i=1; i < BINARY_SIZE/4; i++)
        if (((uint32_t *) binary)[i] != crypt_out[index>>(MMX_COEF_SHA256>>1)][(index&(MMX_COEF_SHA256-1))+i*MMX_COEF_SHA256])
            return 0;
    return 1;
#else
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_rawSHA256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		fmt_default_source,
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
