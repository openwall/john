/*
 * Copyright 2013, epixoip.
 * AVX2 support, Copyright (c) 2015 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */

#include "arch.h"
#if __SSE2__ || __MIC__ || _MSC_VER

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA256_ng;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA256_ng);
#else

#if !FAST_FORMATS_OMP
#undef _OPENMP
#elif _OPENMP
#include <omp.h>
#if __XOP__
#define OMP_SCALE                 512 /* AMD */
#else
#define OMP_SCALE                 512 /* Intel */
#endif
#endif

// These compilers claim to be __GNUC__ but warn on gcc pragmas.
#if __GNUC__ && !__INTEL_COMPILER && !__clang__ && !__llvm__ && !_MSC_VER
#pragma GCC optimize 3
#endif

//#define DEBUG

#include <string.h>

#include "stdint.h"
#include "pseudo_intrinsics.h"
#include "common.h"
#include "formats.h"
#include "aligned.h"
#include "memdbg.h"

#if __MIC__
#define SIMD_TYPE                 "512/512 MIC 16x"
#elif __AVX512__
#define SIMD_TYPE                 "512/512 AVX512 16x"
#elif __AVX2__
#define SIMD_TYPE                 "256/256 AVX2 8x"
#elif __XOP__
#define SIMD_TYPE                 "128/128 XOP 4x"
#elif __SSE4_1__
#define SIMD_TYPE                 "128/128 SSE4.1 4x"
#elif __SSSE3__
#define SIMD_TYPE                 "128/128 SSSE3 4x"
#else
#define SIMD_TYPE                 "128/128 SSE2 4x"
#endif

#define FORMAT_LABEL              "Raw-SHA256-ng"
#define FORMAT_NAME               ""
#define ALGORITHM_NAME            "SHA256 " SIMD_TYPE

#define VWIDTH                    SIMD_COEF_32

#define MAXLEN                    55
#define PLAINTEXT_LENGTH	  MAXLEN
#define CIPHERTEXT_LENGTH         64
#define DIGEST_SIZE               32
#define _RAWSHA256_H
#include "rawSHA256_common.h"
#undef _RAWSHA256_H

#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        VWIDTH
#define MAX_KEYS_PER_CRYPT        VWIDTH

#if __SSE4_1__ && !__AVX2__
#undef GATHER
#define GATHER(x, y, z)                                 \
    {                                                   \
        x = _mm_cvtsi32_si128(   y[index][z]   );       \
        x = _mm_insert_epi32(x, y[index + 1][z], 1);    \
        x = _mm_insert_epi32(x, y[index + 2][z], 2);    \
        x = _mm_insert_epi32(x, y[index + 3][z], 3);    \
    }
#endif

#define S0(x)                                   \
    (                                           \
        vxor(                                   \
            vroti_epi32(x, -22),                \
            vxor(                               \
                vroti_epi32(x,  -2),            \
                vroti_epi32(x, -13)             \
                )                               \
            )                                   \
        )

#define S1(x)                                   \
    (                                           \
        vxor(                                   \
            vroti_epi32(x, -25),                \
            vxor(                               \
                vroti_epi32(x,  -6),            \
                vroti_epi32(x, -11)             \
                )                               \
            )                                   \
        )

#define s0(x)                                   \
    (                                           \
        vxor(                                   \
            vsrli_epi32(x, 3),                  \
            vxor(                               \
                vroti_epi32(x,  -7),            \
                vroti_epi32(x, -18)             \
                )                               \
            )                                   \
        )

#define s1(x)                                   \
    (                                           \
        vxor(                                   \
            vsrli_epi32(x, 10),                 \
            vxor(                               \
                vroti_epi32(x, -17),            \
                vroti_epi32(x, -19)             \
                )                               \
            )                                   \
        )

#define Maj(x,y,z) vcmov(x, y, vxor(z, y))

#define Ch(x,y,z) vcmov(y, z, x)

#define R(t)                                        \
    {                                               \
        w[t] = vadd_epi32(s1(w[t -  2]), w[t - 7]); \
        w[t] = vadd_epi32(s0(w[t - 15]), w[t]);     \
        w[t] = vadd_epi32(   w[t - 16],  w[t]);     \
    }

#define SHA256_STEP(a,b,c,d,e,f,g,h,x,K)            \
    {                                               \
        if (x > 15) R(x);                           \
        tmp1 = vadd_epi32(h,    S1(e));             \
        tmp1 = vadd_epi32(tmp1, Ch(e,f,g));         \
        tmp1 = vadd_epi32(tmp1, vset1_epi32(K));    \
        tmp1 = vadd_epi32(tmp1, w[x]);              \
        tmp2 = vadd_epi32(S0(a),Maj(a,b,c));        \
        d    = vadd_epi32(tmp1, d);                 \
        h    = vadd_epi32(tmp1, tmp2);              \
    }

static uint32_t (*saved_key)[64];
static uint32_t *crypt_key[ 8];


static void init(struct fmt_main *self)
{
    int i;
#ifdef _OPENMP
    int omp_t;

    omp_t = omp_get_max_threads();
    self->params.min_keys_per_crypt *= omp_t;
    omp_t *= OMP_SCALE;
    self->params.max_keys_per_crypt *= omp_t;
#endif
    saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
                                 sizeof(*saved_key), VWIDTH * 4);
    for (i = 0; i < 8; i++)
            crypt_key[i] = mem_calloc_align(self->params.max_keys_per_crypt,
                                            sizeof(uint32_t), VWIDTH * 4);
}

static void done(void)
{
    int i;
    for (i = 0; i < 8; i++)
            MEM_FREE(crypt_key[i]);
    MEM_FREE(saved_key);
}

static int get_hash_0(int index) { return crypt_key[0][index] & 0xf; }
static int get_hash_1(int index) { return crypt_key[0][index] & 0xff; }
static int get_hash_2(int index) { return crypt_key[0][index] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[0][index] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[0][index] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[0][index] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[0][index] & 0x7ffffff; }


static void set_key(char *key, int index)
{
    uint32_t *buf32 = (uint32_t*) &saved_key[index];
    uint8_t  *buf8  = (uint8_t*) buf32;
    int len = 0;

    while (*key)
	    buf8[len++] = *key++;
    buf32[15] = len << 3;
    buf8[len++] = 0x80;
    while (buf8[len] && len <= MAXLEN)
        buf8[len++] = 0;
}


static char *get_key(int index)
{
    uint32_t *buf = (uint32_t*) &saved_key[index];
    static char out[MAXLEN + 1];

    int len = buf[15] >> 3;

    memset(out, 0, MAXLEN + 1);
    memcpy(out, buf, len);

    return (char*) out;
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
    int count = *pcount;
    int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
    for (index = 0; index < count; index += VWIDTH)
#endif
    {
        vtype a, b, c, d, e, f, g, h;
        vtype w[64], tmp1, tmp2;
        int i;

#if __SSE4_1__ && !__AVX2__
        for (i=0; i < 16; i++) GATHER(w[i], saved_key, i);
        for (i=0; i < 15; i++) vswap32(w[i]);
#else
        JTR_ALIGN(VWIDTH * 4) uint32_t __w[16][VWIDTH];
        int j;

        for (i=0; i < VWIDTH; i++)
	        for (j=0; j < 16; j++)
		        __w[j][i] = saved_key[index + i][j];

        for (i=0; i < 15; i++)
        {
	        w[i] = vload((vtype*) __w[i]);
	        vswap32(w[i]);
        }

        w[15] = vload((vtype*) __w[15]);
#endif

        a = vset1_epi32(0x6a09e667);
        b = vset1_epi32(0xbb67ae85);
        c = vset1_epi32(0x3c6ef372);
        d = vset1_epi32(0xa54ff53a);
        e = vset1_epi32(0x510e527f);
        f = vset1_epi32(0x9b05688c);
        g = vset1_epi32(0x1f83d9ab);
        h = vset1_epi32(0x5be0cd19);

        SHA256_STEP(a, b, c, d, e, f, g, h,  0, 0x428a2f98);
        SHA256_STEP(h, a, b, c, d, e, f, g,  1, 0x71374491);
        SHA256_STEP(g, h, a, b, c, d, e, f,  2, 0xb5c0fbcf);
        SHA256_STEP(f, g, h, a, b, c, d, e,  3, 0xe9b5dba5);
        SHA256_STEP(e, f, g, h, a, b, c, d,  4, 0x3956c25b);
        SHA256_STEP(d, e, f, g, h, a, b, c,  5, 0x59f111f1);
        SHA256_STEP(c, d, e, f, g, h, a, b,  6, 0x923f82a4);
        SHA256_STEP(b, c, d, e, f, g, h, a,  7, 0xab1c5ed5);
        SHA256_STEP(a, b, c, d, e, f, g, h,  8, 0xd807aa98);
        SHA256_STEP(h, a, b, c, d, e, f, g,  9, 0x12835b01);
        SHA256_STEP(g, h, a, b, c, d, e, f, 10, 0x243185be);
        SHA256_STEP(f, g, h, a, b, c, d, e, 11, 0x550c7dc3);
        SHA256_STEP(e, f, g, h, a, b, c, d, 12, 0x72be5d74);
        SHA256_STEP(d, e, f, g, h, a, b, c, 13, 0x80deb1fe);
        SHA256_STEP(c, d, e, f, g, h, a, b, 14, 0x9bdc06a7);
        SHA256_STEP(b, c, d, e, f, g, h, a, 15, 0xc19bf174);

        SHA256_STEP(a, b, c, d, e, f, g, h, 16, 0xe49b69c1);
        SHA256_STEP(h, a, b, c, d, e, f, g, 17, 0xefbe4786);
        SHA256_STEP(g, h, a, b, c, d, e, f, 18, 0x0fc19dc6);
        SHA256_STEP(f, g, h, a, b, c, d, e, 19, 0x240ca1cc);
        SHA256_STEP(e, f, g, h, a, b, c, d, 20, 0x2de92c6f);
        SHA256_STEP(d, e, f, g, h, a, b, c, 21, 0x4a7484aa);
        SHA256_STEP(c, d, e, f, g, h, a, b, 22, 0x5cb0a9dc);
        SHA256_STEP(b, c, d, e, f, g, h, a, 23, 0x76f988da);
        SHA256_STEP(a, b, c, d, e, f, g, h, 24, 0x983e5152);
        SHA256_STEP(h, a, b, c, d, e, f, g, 25, 0xa831c66d);
        SHA256_STEP(g, h, a, b, c, d, e, f, 26, 0xb00327c8);
        SHA256_STEP(f, g, h, a, b, c, d, e, 27, 0xbf597fc7);
        SHA256_STEP(e, f, g, h, a, b, c, d, 28, 0xc6e00bf3);
        SHA256_STEP(d, e, f, g, h, a, b, c, 29, 0xd5a79147);
        SHA256_STEP(c, d, e, f, g, h, a, b, 30, 0x06ca6351);
        SHA256_STEP(b, c, d, e, f, g, h, a, 31, 0x14292967);

        SHA256_STEP(a, b, c, d, e, f, g, h, 32, 0x27b70a85);
        SHA256_STEP(h, a, b, c, d, e, f, g, 33, 0x2e1b2138);
        SHA256_STEP(g, h, a, b, c, d, e, f, 34, 0x4d2c6dfc);
        SHA256_STEP(f, g, h, a, b, c, d, e, 35, 0x53380d13);
        SHA256_STEP(e, f, g, h, a, b, c, d, 36, 0x650a7354);
        SHA256_STEP(d, e, f, g, h, a, b, c, 37, 0x766a0abb);
        SHA256_STEP(c, d, e, f, g, h, a, b, 38, 0x81c2c92e);
        SHA256_STEP(b, c, d, e, f, g, h, a, 39, 0x92722c85);
        SHA256_STEP(a, b, c, d, e, f, g, h, 40, 0xa2bfe8a1);
        SHA256_STEP(h, a, b, c, d, e, f, g, 41, 0xa81a664b);
        SHA256_STEP(g, h, a, b, c, d, e, f, 42, 0xc24b8b70);
        SHA256_STEP(f, g, h, a, b, c, d, e, 43, 0xc76c51a3);
        SHA256_STEP(e, f, g, h, a, b, c, d, 44, 0xd192e819);
        SHA256_STEP(d, e, f, g, h, a, b, c, 45, 0xd6990624);
        SHA256_STEP(c, d, e, f, g, h, a, b, 46, 0xf40e3585);
        SHA256_STEP(b, c, d, e, f, g, h, a, 47, 0x106aa070);

        SHA256_STEP(a, b, c, d, e, f, g, h, 48, 0x19a4c116);
        SHA256_STEP(h, a, b, c, d, e, f, g, 49, 0x1e376c08);
        SHA256_STEP(g, h, a, b, c, d, e, f, 50, 0x2748774c);
        SHA256_STEP(f, g, h, a, b, c, d, e, 51, 0x34b0bcb5);
        SHA256_STEP(e, f, g, h, a, b, c, d, 52, 0x391c0cb3);
        SHA256_STEP(d, e, f, g, h, a, b, c, 53, 0x4ed8aa4a);
        SHA256_STEP(c, d, e, f, g, h, a, b, 54, 0x5b9cca4f);
        SHA256_STEP(b, c, d, e, f, g, h, a, 55, 0x682e6ff3);
        SHA256_STEP(a, b, c, d, e, f, g, h, 56, 0x748f82ee);
        SHA256_STEP(h, a, b, c, d, e, f, g, 57, 0x78a5636f);
        SHA256_STEP(g, h, a, b, c, d, e, f, 58, 0x84c87814);
        SHA256_STEP(f, g, h, a, b, c, d, e, 59, 0x8cc70208);
        SHA256_STEP(e, f, g, h, a, b, c, d, 60, 0x90befffa);
        SHA256_STEP(d, e, f, g, h, a, b, c, 61, 0xa4506ceb);
        SHA256_STEP(c, d, e, f, g, h, a, b, 62, 0xbef9a3f7);
        SHA256_STEP(b, c, d, e, f, g, h, a, 63, 0xc67178f2);

        a = vadd_epi32(a, vset1_epi32(0x6a09e667));
        b = vadd_epi32(b, vset1_epi32(0xbb67ae85));
        c = vadd_epi32(c, vset1_epi32(0x3c6ef372));
        d = vadd_epi32(d, vset1_epi32(0xa54ff53a));
        e = vadd_epi32(e, vset1_epi32(0x510e527f));
        f = vadd_epi32(f, vset1_epi32(0x9b05688c));
        g = vadd_epi32(g, vset1_epi32(0x1f83d9ab));
        h = vadd_epi32(h, vset1_epi32(0x5be0cd19));

        vstore((vtype*) &crypt_key[0][index], a);
        vstore((vtype*) &crypt_key[1][index], b);
        vstore((vtype*) &crypt_key[2][index], c);
        vstore((vtype*) &crypt_key[3][index], d);
        vstore((vtype*) &crypt_key[4][index], e);
        vstore((vtype*) &crypt_key[5][index], f);
        vstore((vtype*) &crypt_key[6][index], g);
        vstore((vtype*) &crypt_key[7][index], h);
    }

    return count;
}


static int cmp_all(void *binary, int count)
{
	vtype bin;
	vtype digest;
	int i = 0;

#ifdef _OPENMP
	for (i = 0; i < count; i += VWIDTH)
#endif
	{
		digest = vload((vtype*) &crypt_key[0][i]);
		bin    = vset1_epi32(((uint32_t*) binary)[0]);

        if (vtesteq_epi32(bin, digest))
            return 1;
	}

	return 0;
}


static int cmp_one(void *binary, int index)
{
    int i;

    for (i = 0; i < 8; i++)
        if (((uint32_t*) binary)[i] != crypt_key[i][index])
            return 0;

    return 1;
}


static int cmp_exact(char *source, int index)
{
    return 1;
}


struct fmt_main fmt_rawSHA256_ng = {
    {
        FORMAT_LABEL,
        FORMAT_NAME,
        ALGORITHM_NAME,
        BENCHMARK_COMMENT,
        BENCHMARK_LENGTH,
        0,
        MAXLEN,
        BINARY_SIZE,
        BINARY_ALIGN,
        SALT_SIZE,
        SALT_ALIGN,
        MIN_KEYS_PER_CRYPT,
        MAX_KEYS_PER_CRYPT,
        FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
        sha256_common_tests
    }, {
        init,
        done,
        fmt_default_reset,
	sha256_common_prepare,
	sha256_common_valid,
	sha256_common_split,
	sha256_common_binary,
        fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
        fmt_default_source,
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

#endif /* __SSE2__ */
