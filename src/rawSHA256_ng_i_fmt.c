/*
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 *
 * Code signficinatly changed, by Jim Fougeron, 2013, to move the crypt
 * logic into sse-intrinsics.c.  This code released with the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2011 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#include "arch.h"
#ifdef MMX_COEF_SHA256

#ifdef _OPENMP
#include <omp.h>
#if defined __XOP__
#define OMP_SCALE                 512 /* AMD */
#else
#define OMP_SCALE                 1024 /* Intel */
#endif
#endif

#include <string.h>
#include "stdint.h"
#include "common.h"
#include "formats.h"
#include "sse-intrinsics.h"
#include "johnswap.h"

// This format is easy to test (during developement) of SHA224 and SHA256.  We have a single
// #define that if uncommented, will 'morph' this format into sha224.  It will not work on
// both hash types at the same time, but it CAN flip back and forth in an instant.  The format_label
// IS kept the same (makes for easier running after a change).

//#define TEST_SHA224

#if __SSE4_1__
//#define MMX_LOAD SHA256_BUF_SIZ
#define REMOVE_TAIL_ADD
#else
#define MMX_LOAD SHA256_BUF_SIZ
#define REMOVE_TAIL_ADD
#endif

#define FORMAT_LABEL              "Raw-SHA256-ng-i"
#define TAG_LENGTH                8

#define NUMKEYS                   MMX_COEF_SHA256

#define BENCHMARK_COMMENT         ""
#define BENCHMARK_LENGTH          -1

#define MAXLEN                    55
#ifndef TEST_SHA224
#define CIPHERTEXT_LENGTH         64
#define BINARY_SIZE               32
#define FORMAT_TAG                "$SHA256$"
#define FORMAT_NAME               ""
#define ALGORITHM_NAME            "SHA256 " SHA256_ALGORITHM_NAME
#else
#define CIPHERTEXT_LENGTH         56
#define BINARY_SIZE               28
#define FORMAT_TAG                "$SHA224$"
#define FORMAT_NAME               ""
#define ALGORITHM_NAME            "SHA224 " SHA256_ALGORITHM_NAME
#endif
#define BINARY_ALIGN              4
#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        MMX_COEF_SHA256
#define MAX_KEYS_PER_CRYPT        MMX_COEF_SHA256

static struct fmt_tests tests[] = {
#ifdef TEST_SHA224
	/* SHA224 */
	{"5475c89bd2508afc95ecbc0ba90accbd0c2e5e9e8c8625a96389499f", "epixoip"},
	{"287b64fd40a2fb97b9f2615a3ef1ecfce06d27325d8f44637e4893c1", "doesthiswork"},
    {"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", "password"},
    {"621a5fcf3caf392b9a64f9eae25ee80a0a07f54fbd493c4b23f6ae30", "ALLCAPS"},
    {"6f0c6610fd1256ba63071315d8685affdba1d083c04b11704ba29822", "TestTESTt3st"},
    {FORMAT_TAG "7e6a4309ddf6e8866679f61ace4f621b0e3455ebac2e831a60f13cd1", "12345678"},
    {FORMAT_TAG "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", ""},
#else
    {"71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
    {"25b64f637b373d33a8aa2b7579784e99a20e6b7dfea99a71af124394b8958f27", "doesthiswork"},
    {"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
    {"27c6794c8aa2f70f5f6dc93d3bfb25ca6de9b0752c8318614cbd4ad203bea24c", "ALLCAPS"},
    {"04cdd6c523673bf448efe055711a9b184817d7843b0a76c2046f5398b5854152", "TestTESTt3st"},
    {FORMAT_TAG "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
    {FORMAT_TAG "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
#ifdef DEBUG
    {"9e7d3e56996c5a06a6a378567e62f5aa7138ebb0f55c0bdaf73666bf77f73380", "mot\xf6rhead"},
    {"0f46e4b0802fee6fed599682a16287d0397699cfd742025482c086a70979e56a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 31
    {"c62e4615bd39e222572f3a1bf7c2132ea1e65b17ec805047bd6b2842c593493f", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 32
    {"d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 55
#endif
#endif
    {NULL}
};

#ifdef MMX_LOAD
#define GETPOS(i, index)		( (index&(MMX_COEF_SHA256-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF_SHA256 + (3-((i)&3)) + (index>>(MMX_COEF_SHA256>>1))*MMX_LOAD*MMX_COEF_SHA256*4 )
static uint32_t (*saved_key)[SHA256_BUF_SIZ*MMX_COEF_SHA256];
#else
static uint32_t (*saved_key)[16];
#endif

static uint32_t (*crypt_key)[8*MMX_COEF_SHA256];


static void init(struct fmt_main *self)
{
#ifdef _OPENMP
    int omp_t;

    omp_t = omp_get_max_threads();
    self->params.min_keys_per_crypt *= omp_t;
    omp_t *= OMP_SCALE;
    self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef MMX_LOAD
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt/MMX_COEF_SHA256, MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
#endif
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * (self->params.max_keys_per_crypt/MMX_COEF_SHA256), MEM_ALIGN_SIMD);
}


static int valid (char *ciphertext, struct fmt_main *self)
{
    char *p, *q;

    p = ciphertext;

    if (! strncmp (p, FORMAT_TAG, TAG_LENGTH))
        p += TAG_LENGTH;

    q = p;
    while (atoi16[ARCH_INDEX(*q)] != 0x7F) q++;

    return !*q && q - p == CIPHERTEXT_LENGTH;
}


#if FMT_MAIN_VERSION > 9
static char *split (char *ciphertext, int index, struct fmt_main *self)
#else
static char *split (char *ciphertext, int index)
#endif
{
    static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

    if (!strncmp (ciphertext, FORMAT_TAG, TAG_LENGTH))
        return ciphertext;

    memcpy (out,  FORMAT_TAG, TAG_LENGTH);
    memcpy (out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
    strlwr (out + TAG_LENGTH);

    return out;
}


static void *get_binary (char *ciphertext)
{
    static unsigned char *out;
    int i;

    if (!out)
        out = mem_alloc_tiny (BINARY_SIZE, MEM_ALIGN_WORD);

    ciphertext += TAG_LENGTH;

    for(i=0; i < BINARY_SIZE; i++)
        out[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                 atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];

    alter_endianity (out, BINARY_SIZE);

#ifdef REMOVE_TAIL_ADD
#ifdef TEST_SHA224
    ((ARCH_WORD_32*)out)[0] -= 0xc1059ed8;
    ((ARCH_WORD_32*)out)[1] -= 0x367cd507;
    ((ARCH_WORD_32*)out)[2] -= 0x3070dd17;
    ((ARCH_WORD_32*)out)[3] -= 0xf70e5939;
    ((ARCH_WORD_32*)out)[4] -= 0xffc00b31;
    ((ARCH_WORD_32*)out)[5] -= 0x68581511;
    ((ARCH_WORD_32*)out)[6] -= 0x64f98fa7;
    ((ARCH_WORD_32*)out)[7] -= 0xbefa4fa4;
#else
    ((ARCH_WORD_32*)out)[0] -= 0x6a09e667;
    ((ARCH_WORD_32*)out)[1] -= 0xbb67ae85;
    ((ARCH_WORD_32*)out)[2] -= 0x3c6ef372;
    ((ARCH_WORD_32*)out)[3] -= 0xa54ff53a;
    ((ARCH_WORD_32*)out)[4] -= 0x510e527f;
    ((ARCH_WORD_32*)out)[5] -= 0x9b05688c;
    ((ARCH_WORD_32*)out)[6] -= 0x1f83d9ab;
    ((ARCH_WORD_32*)out)[7] -= 0x5be0cd19;
#endif
#endif

    return (void *) out;
}

static int get_hash_0 (int index) { return crypt_key[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xf; }
static int get_hash_1 (int index) { return crypt_key[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xff; }
static int get_hash_2 (int index) { return crypt_key[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xfff; }
static int get_hash_3 (int index) { return crypt_key[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xffff; }
static int get_hash_4 (int index) { return crypt_key[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xfffff; }
static int get_hash_5 (int index) { return crypt_key[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0xffffff; }
static int get_hash_6 (int index) { return crypt_key[index>>(MMX_COEF_SHA256>>1)][index&(MMX_COEF_SHA256-1)] & 0x7ffffff; }

#ifdef MMX_LOAD
static void set_key(char *key, int index) {
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32 *)saved_key)[(index&(MMX_COEF_SHA256-1)) + (index>>(MMX_COEF_SHA256>>1))*SHA256_BUF_SIZ*MMX_COEF_SHA256];
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
		keybuf_word += MMX_COEF_SHA256;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += MMX_COEF_SHA256;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF_SHA256;
	}
	keybuffer[15*MMX_COEF_SHA256] = len << 3;
}
#else
static void set_key (char *key, int index)
{
    uint32_t *buf32 = (uint32_t *) (saved_key[index]);
    uint8_t  *buf8  = (uint8_t *) buf32;
    int len = 0;

    while (*key)
	    buf8[len++] = *key++;
    buf32[15] = (len << 3);
    buf8[len++] = 0x80;
    while (buf8[len] && len <= MAXLEN)
        buf8[len++] = 0;

	//for (len=0; len<16; ++len)
	//	printf("%08x ", buf32[len]);
	//printf("\n");
}
#endif

#ifdef MMX_LOAD
static char *get_key(int index) {
	unsigned int i,s;
	static char out[64];
	unsigned char *wucp = (unsigned char*)saved_key;

	s = ((ARCH_WORD_32 *)saved_key)[15*MMX_COEF_SHA256 + (index&(MMX_COEF_SHA256-1)) + (index>>(MMX_COEF_SHA256>>1))*SHA256_BUF_SIZ*MMX_COEF_SHA256] >> 3;
	for(i=0;i<s;i++)
		out[i] = wucp[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
}
#else
static char *get_key (int index)
{
    uint32_t *buf = (uint32_t *) &saved_key[index];
    static char out[MAXLEN + 1];

    int len = buf[15] >> 3;

    memset (out, 0, MAXLEN + 1);
    memcpy (out, buf, len);

    return (char *) out;
}
#endif

#if FMT_MAIN_VERSION > 10
static int crypt_all (int *pcount, struct db_salt *salt)
#else
static void crypt_all (int count)
#endif
{
#if FMT_MAIN_VERSION > 10
    int count = *pcount;
#endif
    int i = 0;

#ifdef _OPENMP
#pragma omp parallel for
    for (i = 0; i < count; i += MMX_COEF_SHA256)
#endif
    {
#ifdef REMOVE_TAIL_ADD
 #ifdef MMX_LOAD
  #ifdef TEST_SHA224
	SSESHA256body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN|SSEi_CRYPT_SHA224|SSEi_SKIP_FINAL_ADD);
  #else
	SSESHA256body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN|SSEi_SKIP_FINAL_ADD);
  #endif
 #else
  #ifdef TEST_SHA224
		SSESHA256body(&saved_key[i], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_FLAT_IN|SSEi_CRYPT_SHA224|SSEi_SKIP_FINAL_ADD);
  #else
		SSESHA256body(&saved_key[i], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_FLAT_IN|SSEi_SKIP_FINAL_ADD);
  #endif
 #endif
#else
 #ifdef MMX_LOAD
  #ifdef TEST_SHA224
	SSESHA256body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN|SSEi_CRYPT_SHA224);
  #else
	SSESHA256body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN);
  #endif
 #else
  #ifdef TEST_SHA224
		SSESHA256body(&saved_key[i], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_FLAT_IN|SSEi_CRYPT_SHA224);
  #else
		SSESHA256body(&saved_key[i], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_FLAT_IN);
  #endif
 #endif
#endif
	}

#if FMT_MAIN_VERSION > 10
    return count;
#endif
}


static int cmp_all (void *binary, int count)
{
    int i;

    for (i = 0; i < count; i++)
        if (((uint32_t *) binary)[0] == crypt_key[i>>(MMX_COEF_SHA256>>1)][i&(MMX_COEF_SHA256-1)])
             return 1;
    return 0;
}


static int cmp_one (void *binary, int index)
{
    int i;

    for (i=1; i < BINARY_SIZE/4; i++)
        if (((uint32_t *) binary)[i] != crypt_key[index>>(MMX_COEF_SHA256>>1)][(index&(MMX_COEF_SHA256-1))+i*MMX_COEF_SHA256])
            return 0;

    return 1;
}


static int cmp_exact (char *source, int index)
{
    return 1;
}


struct fmt_main fmt_rawSHA256_ng_i = {
    {
        FORMAT_LABEL,
        FORMAT_NAME,
        ALGORITHM_NAME,
        BENCHMARK_COMMENT,
        BENCHMARK_LENGTH,
        MAXLEN,
        BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
        BINARY_ALIGN,
#endif
        SALT_SIZE,
#if FMT_MAIN_VERSION > 9
        SALT_ALIGN,
#endif
        MIN_KEYS_PER_CRYPT,
        MAX_KEYS_PER_CRYPT,
	0,
        FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
        tests
    }, {
        init,
#if FMT_MAIN_VERSION > 10
        fmt_default_done,
        fmt_default_reset,
#endif
        fmt_default_prepare,
        valid,
        split,
        get_binary,
        fmt_default_salt,
#if FMT_MAIN_VERSION > 9
        fmt_default_source,
#endif
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
