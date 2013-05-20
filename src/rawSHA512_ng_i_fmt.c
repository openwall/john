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
#ifdef MMX_COEF_SHA512

#ifdef _OPENMP
#include <omp.h>
#if defined __XOP__
#define OMP_SCALE                 768 /* AMD */
#else
#define OMP_SCALE                 2048 /* Intel */
#endif
#endif

#include <string.h>
#include "stdint.h"
#include "common.h"
#include "formats.h"
#include "sse-intrinsics.h"
#include "johnswap.h"

// This format is easy to test (during developement) of SHA384 and SHA512.  We have a single
// #define that if uncommented, will 'morph' this format into sha384.  It will not work on
// both hash types at the same time, but it CAN flip back and forth in an instant.  The format_label
// IS kept the same (makes for easier running after a change).

//#define TEST_SHA384
#define MMX_LOAD SHA512_BUF_SIZ
//#define REMOVE_TAIL_ADD

#define ALGORITHM_NAME            SHA512_ALGORITHM_NAME
#define TAG_LENGTH                8

#define NUMKEYS                   MMX_COEF_SHA512

#define BENCHMARK_COMMENT         ""
#define BENCHMARK_LENGTH          -1

#define MAXLEN                    111
#define FULL_BINARY_SIZE          64
#ifndef TEST_SHA384
#define CIPHERTEXT_LENGTH         128
#define BINARY_SIZE               64
#define FORMAT_TAG                "$SHA512$"
#define FORMAT_NAME               "Raw SHA-512"
#define FORMAT_LABEL              "raw-sha512-ng-i"
#else
#define CIPHERTEXT_LENGTH         96
#define BINARY_SIZE               48
#define FORMAT_TAG                "$SHA384$"
#define FORMAT_NAME               "Raw SHA-384"
#define FORMAT_LABEL              "raw-sha384-ng-i"
#endif
#define BINARY_ALIGN              8
#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        MMX_COEF_SHA512
#define MAX_KEYS_PER_CRYPT        MMX_COEF_SHA512

static struct fmt_tests tests[] = {
#ifdef TEST_SHA384
	/* SHA384 */
	{"f5260c125dedb0be1f9a1e67072db4fc9f41602827f5d3f7da8487a8821170a237afb9d09c7b3391cdbcabf81d2e04af", "epixoip"},
    {"a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", "password"},
    {"ab3943891e0e0631853877b5afc66eb39e5ffb08e71842c36dad1b6c2f88159f6527912f940d524305d5c6e9d636966e", "ALLCAPS"},
    {"879843fb506ee1034dc88d631df353eec61005d895f01056fc169d41af1dc791d3a373ee176dd746473b86f2773a9181", "TestTESTt3st"},
    {FORMAT_TAG "8cafed2235386cc5855e75f0d34f103ccc183912e5f02446b77c66539f776e4bf2bf87339b4518a7cb1c2441c568b0f8", "12345678"},
    {FORMAT_TAG "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", ""},
	{FORMAT_TAG "156b528027cb6dcc4af116cd69fb4beb3efb9c7ebcc51147debf16550b752c89d842d6ec9ab0a1b40bb69c95c5274ab4", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"},
#else
    {"f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
    {"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
    {"71ebcb1eccd7ea22bd8cebaec735a43f1f7164d003dacdeb06e0de4a6d9f64d123b00a45227db815081b1008d1a1bbad4c39bde770a2c23308ff1b09418dd7ed", "ALLCAPS"},
    {"82244918c2e45fbaa00c7c7d52eb61f309a37e2f33ea1fba78e61b4140efa95731eec849de02ee16aa31c82848b51fb7b7fbae62f50df6e150a8a85e70fa740c", "TestTESTt3st"},
    {FORMAT_TAG "fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
    {FORMAT_TAG "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
	{"7aba4411846c61b08b0f2282a8a4600232ace4dd96593c755ba9c9a4e7b780b8bdc437b5c55574b3e8409c7b511032f98ef120e25467678f0458643578eb60ff", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"},
#endif
    {NULL}
};

#ifdef MMX_LOAD
#define GETPOS(i, index)		( (index&(MMX_COEF_SHA512-1))*8 + ((i)&(0xffffffff-7))*MMX_COEF_SHA512 + (7-((i)&7)) + (index>>(MMX_COEF_SHA512>>1))*MMX_LOAD*MMX_COEF_SHA512*8 )
static uint64_t (*saved_key)[MMX_LOAD*MMX_COEF_SHA512];
#else
static uint64_t (*saved_key)[16];
#endif

static uint64_t (*crypt_key)[8*MMX_COEF_SHA512];


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
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt/MMX_COEF_SHA512, MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
#endif
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * (self->params.max_keys_per_crypt/MMX_COEF_SHA512), MEM_ALIGN_SIMD);
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
	static union {
        unsigned char c[FULL_BINARY_SIZE];
        uint64_t w[FULL_BINARY_SIZE / sizeof(uint64_t)];
    } *out;
    int i;

    if (!out)
        out = mem_alloc_tiny (FULL_BINARY_SIZE, BINARY_ALIGN);

    ciphertext += TAG_LENGTH;

    for(i=0; i < FULL_BINARY_SIZE; i++)
        out->c[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                    atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];

    alter_endianity_to_BE64 (out->c, (FULL_BINARY_SIZE>>3));

#ifdef REMOVE_TAIL_ADD
#ifdef TEST_SHA384
    out->w[0] -= 0xcbbb9d5dc1059ed8ull;
    out->w[1] -= 0x629a292a367cd507ull;
    out->w[2] -= 0x9159015a3070dd17ull;
    out->w[3] -= 0x152fecd8f70e5939ull;
    out->w[4] -= 0x67332667ffc00b31ull;
    out->w[5] -= 0x8eb44a8768581511ull;
    out->w[6] -= 0xdb0c2e0d64f98fa7ull;
    out->w[7] -= 0x47b5481dbefa4fa4ull;
#else
    out->w[0] -= 0x6a09e667f3bcc908ULL;
    out->w[1] -= 0xbb67ae8584caa73bULL;
    out->w[2] -= 0x3c6ef372fe94f82bULL;
    out->w[3] -= 0xa54ff53a5f1d36f1ULL;
    out->w[4] -= 0x510e527fade682d1ULL;
    out->w[5] -= 0x9b05688c2b3e6c1fULL;
    out->w[6] -= 0x1f83d9abfb41bd6bULL;
    out->w[7] -= 0x5be0cd19137e2179ULL;
#endif
#endif

    return (void *) out;
}


static int binary_hash_0 (void *binary) { return *(uint32_t *) binary & 0xf; }
static int binary_hash_1 (void *binary) { return *(uint32_t *) binary & 0xff; }
static int binary_hash_2 (void *binary) { return *(uint32_t *) binary & 0xfff; }
static int binary_hash_3 (void *binary) { return *(uint32_t *) binary & 0xffff; }
static int binary_hash_4 (void *binary) { return *(uint32_t *) binary & 0xfffff; }
static int binary_hash_5 (void *binary) { return *(uint32_t *) binary & 0xffffff; }
static int binary_hash_6 (void *binary) { return *(uint32_t *) binary & 0x7ffffff; }

static int get_hash_0 (int index) { return crypt_key[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xf; }
static int get_hash_1 (int index) { return crypt_key[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xff; }
static int get_hash_2 (int index) { return crypt_key[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xfff; }
static int get_hash_3 (int index) { return crypt_key[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xffff; }
static int get_hash_4 (int index) { return crypt_key[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xfffff; }
static int get_hash_5 (int index) { return crypt_key[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xffffff; }
static int get_hash_6 (int index) { return crypt_key[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0x7ffffff; }

#ifdef MMX_LOAD
static void set_key(char *key, int index) {
	const ARCH_WORD_64 *wkey = (ARCH_WORD_64*)key;
	ARCH_WORD_64 *keybuffer = &((ARCH_WORD_64 *)saved_key)[(index&(MMX_COEF_SHA512-1)) + (index>>(MMX_COEF_SHA512>>1))*MMX_LOAD*MMX_COEF_SHA512];
	ARCH_WORD_64 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_64 temp;

	len = 0;
	while((unsigned char)(temp = *wkey++)) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffff) | (0x80 << 24));
			len+=3;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffff) | (0x80ULL << 32));
			len+=4;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffULL) | (0x80ULL << 40));
			len+=5;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffffULL) | (0x80ULL << 48));
			len+=6;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffffffULL) | (0x80ULL << 56));
			len+=7;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP64(temp);
		len += 8;
		keybuf_word += MMX_COEF_SHA512;
	}
	*keybuf_word = 0x8000000000000000ULL;

key_cleaning:
	keybuf_word += MMX_COEF_SHA512;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF_SHA512;
	}
	keybuffer[15*MMX_COEF_SHA512] = len << 3;
}
#else
static void set_key (char *key, int index)
{
    uint64_t *buf64 = (uint64_t *) (saved_key[index]);
    uint8_t  *buf8  = (uint8_t *) buf64;
    int len = 0;

    while (*key)
	    buf8[len++] = *key++;
    buf64[15] = (len << 3);
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
	unsigned int i;
	uint64_t s;
	static char out[MAXLEN + 1];
	unsigned char *wucp = (unsigned char*)saved_key;

	s = ((ARCH_WORD_64 *)saved_key)[15*MMX_COEF_SHA512 + (index&3) + (index>>2)*MMX_LOAD*MMX_COEF_SHA512] >> 3;
	for(i=0;i<s;i++)
		out[i] = wucp[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*) out;
}
#else
static char *get_key (int index)
{
    uint64_t *buf64 = (uint64_t *) &saved_key[index];
	uint8_t  *buf8  = (uint8_t * ) buf64;

    static char out[MAXLEN + 1];
    int len = (int)(buf64[15] >> 3);

	out[len] = 0;

    for (len--; len > -1; len--)
        out[len] = buf8[len];

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
    for (i = 0; i < count; i += MMX_COEF_SHA512)
#endif
    {
#ifdef REMOVE_TAIL_ADD
 #ifdef MMX_LOAD
  #ifdef TEST_SHA384
	SSESHA512body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN|SSEi_CRYPT_SHA384|SSEi_SKIP_FINAL_ADD);
  #else
	SSESHA512body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN|SSEi_SKIP_FINAL_ADD);
  #endif
 #else
  #ifdef TEST_SHA384
		SSESHA512body(&saved_key[i], crypt_key[i/MMX_COEF_SHA512], NULL, SSEi_FLAT_IN|SSEi_CRYPT_SHA384|SSEi_SKIP_FINAL_ADD);
  #else
		SSESHA512body(&saved_key[i], crypt_key[i/MMX_COEF_SHA512], NULL, SSEi_FLAT_IN|SSEi_SKIP_FINAL_ADD);
  #endif
 #endif
#else
 #ifdef MMX_LOAD
  #ifdef TEST_SHA384
	SSESHA512body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN|SSEi_CRYPT_SHA384);
  #else
	SSESHA512body(&saved_key[i/MMX_COEF_SHA256], crypt_key[i/MMX_COEF_SHA256], NULL, SSEi_MIXED_IN);
  #endif
 #else
  #ifdef TEST_SHA384
		SSESHA512body(&saved_key[i], crypt_key[i/MMX_COEF_SHA512], NULL, SSEi_FLAT_IN|SSEi_CRYPT_SHA384);
  #else
		SSESHA512body(&saved_key[i], crypt_key[i/MMX_COEF_SHA512], NULL, SSEi_FLAT_IN);
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
        if (((uint64_t *) binary)[0] == crypt_key[i>>(MMX_COEF_SHA512>>1)][i&(MMX_COEF_SHA512-1)])
             return 1;
    return 0;
}


static int cmp_one (void *binary, int index)
{
    int i;

    for (i=1; i < BINARY_SIZE/sizeof(ARCH_WORD_64); i++)
        if (((uint64_t *) binary)[i] != crypt_key[index>>(MMX_COEF_SHA512>>1)][(index&(MMX_COEF_SHA512-1))+i*MMX_COEF_SHA512])
            return 0;

    return 1;
}


static int cmp_exact (char *source, int index)
{
    return 1;
}


struct fmt_main fmt_rawSHA512_ng_i = {
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

#endif
