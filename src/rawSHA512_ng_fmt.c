/*
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */


#include "arch.h"
#ifdef MMX_COEF

#pragma GCC optimize 3

#include <stdint.h>
#include <string.h>
#include <emmintrin.h>

#if defined __XOP__
#include <x86intrin.h>
#elif defined __SSSE3__
#include <tmmintrin.h>
#endif

#include "common.h"
#include "formats.h"


#if defined __XOP__
#define SIMD_TYPE                 "XOP"
#elif defined __SSSE3__
#define SIMD_TYPE                 "SSSE3"
#else
#define SIMD_TYPE                 "SSE2"
#endif

#define FORMAT_LABEL              "raw-sha512-ng"
#define FORMAT_NAME               "Raw SHA-512"
#define ALGORITHM_NAME            "128/128 " SIMD_TYPE " intrinsics 2x"
#define FORMAT_TAG                "$SHA512$"
#define TAG_LENGTH                8

#define VWIDTH                    2
#define NUMKEYS                   VWIDTH

#define BENCHMARK_COMMENT         ""
#define BENCHMARK_LENGTH          -1

#define MAXLEN                    55
#define CIPHERTEXT_LENGTH         128
#define DIGEST_SIZE               64
#define BINARY_SIZE               64
#define BINARY_ALIGN              8
#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        1
#define MAX_KEYS_PER_CRYPT        NUMKEYS


#ifndef __XOP__
#define _mm_roti_epi64(x, n)                                              \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_srli_epi64(x, ~n + 1),                                        \
        _mm_slli_epi64(x, 64 + n)                                         \
    )                                                                     \
)

#define _mm_cmov_si128(y, z, x)                                           \
(                                                                         \
    _mm_xor_si128 (z,                                                     \
        _mm_and_si128 (x,                                                 \
            _mm_xor_si128 (y, z)                                          \
        )                                                                 \
    )                                                                     \
)
#endif

#ifdef __SSSE3__
#define SWAP_ENDIAN(n)                                                    \
{                                                                         \
    n = _mm_shuffle_epi8 (n,                                              \
            _mm_set_epi64x (0x08090a0b0c0d0e0f, 0x0001020304050607)       \
        );                                                                \
}
#else
#define SWAP_ENDIAN(n)                                                    \
{                                                                         \
    n = _mm_shufflehi_epi16 (_mm_shufflelo_epi16 (n, 0xb1), 0xb1);        \
    n = _mm_xor_si128 (_mm_slli_epi16 (n, 8), _mm_srli_epi16 (n, 8));     \
    n = _mm_shuffle_epi32 (n, 0xb1);                                      \
}
#endif

#define GATHER(x,y,z)                                                     \
{                                                                         \
    x = _mm_setzero_si128 ();                                             \
    x = _mm_set_epi64x (y[1][z], y[0][z]);                                \
}

#define S0(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_roti_epi64 (x, -39),                                          \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi64 (x, -28),                                      \
            _mm_roti_epi64 (x, -34)                                       \
        )                                                                 \
    )                                                                     \
)

#define S1(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_roti_epi64 (x, -41),                                          \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi64 (x, -14),                                      \
            _mm_roti_epi64 (x, -18)                                       \
        )                                                                 \
    )                                                                     \
)

#define s0(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_srli_epi64 (x, 7),                                            \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi64 (x, -1),                                       \
            _mm_roti_epi64 (x, -8)                                        \
        )                                                                 \
    )                                                                     \
)

#define s1(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_srli_epi64 (x, 6),                                            \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi64 (x, -19),                                      \
            _mm_roti_epi64 (x, -61)                                       \
        )                                                                 \
    )                                                                     \
)

#define Maj(x,y,z) _mm_cmov_si128 (x, y, _mm_xor_si128 (z, y))

#define Ch(x,y,z)  _mm_cmov_si128 (y, z, x)

#define R(t)                                                              \
{                                                                         \
    w[t] = _mm_add_epi64 (s1(w[t -  2]), w[t - 7]);                       \
    w[t] = _mm_add_epi64 (s0(w[t - 15]), w[t    ]);                       \
    w[t] = _mm_add_epi64 (   w[t - 16],  w[t    ]);                       \
}

#define SHA512_STEP(a,b,c,d,e,f,g,h,x,K)                                  \
{                                                                         \
    tmp1 = _mm_add_epi64 (h,    S1(e));                                   \
    tmp1 = _mm_add_epi64 (tmp1, Ch(e,f,g));                               \
    tmp1 = _mm_add_epi64 (tmp1, _mm_set1_epi64x(K));                      \
    tmp1 = _mm_add_epi64 (tmp1, w[x]);                                    \
    tmp2 = _mm_add_epi64 (S0(a),Maj(a,b,c));                              \
    d    = _mm_add_epi64 (tmp1, d);                                       \
    h    = _mm_add_epi64 (tmp1, tmp2);                                    \
}


static struct fmt_tests tests[] = {
    {"f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
    {"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
    {"71ebcb1eccd7ea22bd8cebaec735a43f1f7164d003dacdeb06e0de4a6d9f64d123b00a45227db815081b1008d1a1bbad4c39bde770a2c23308ff1b09418dd7ed", "ALLCAPS"},
    {FORMAT_TAG "fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
    {FORMAT_TAG "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
    {"c96f1c1260074832bd3068ddd29e733090285dfc65939555dbbcafb27834957d15d9c509481cc7df0e2a7e21429783ba573036b78f5284f9928b5fef02a791ef", "mot\xf6rhead"},
    {"db9981645857e59805132f7699e78bbcf39f69380a41aac8e6fa158a0593f2017ffe48764687aa855dae3023fcceefd51a1551d57730423df18503e80ba381ba", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
    {NULL}
};

#ifdef _MSC_VER
__declspec(align(16)) static uint64_t saved_key[VWIDTH][80];
__declspec(align(16)) static uint64_t crypt_key[ 8][VWIDTH];
#else
static uint64_t saved_key[VWIDTH][80] __attribute__ ((aligned(16)));
static uint64_t crypt_key[ 8][VWIDTH] __attribute__ ((aligned(16)));
#endif


static inline void alter_endianity_64 (void *_x, unsigned int size)
{
    uint64_t *x = (uint64_t *) _x;
    int i;

    for (i=0; i < (size / sizeof(*x)); i++)
        x[i] = __builtin_bswap64 (x[i]);
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
        out = mem_alloc_tiny (DIGEST_SIZE, MEM_ALIGN_WORD);

    ciphertext += TAG_LENGTH;

    for (i=0; i < BINARY_SIZE; i++)
        out[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                 atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];

    alter_endianity_64 (out, DIGEST_SIZE);

    return (void *) out;
}


static int binary_hash_0 (void *binary) { return *(uint32_t *) binary & 0xf; }
static int binary_hash_1 (void *binary) { return *(uint32_t *) binary & 0xff; }
static int binary_hash_2 (void *binary) { return *(uint32_t *) binary & 0xfff; }
static int binary_hash_3 (void *binary) { return *(uint32_t *) binary & 0xffff; }
static int binary_hash_4 (void *binary) { return *(uint32_t *) binary & 0xfffff; }
static int binary_hash_5 (void *binary) { return *(uint32_t *) binary & 0xffffff; }
static int binary_hash_6 (void *binary) { return *(uint32_t *) binary & 0x7ffffff; }

static int get_hash_0 (int index) { return crypt_key[0][index] & 0xf; }
static int get_hash_1 (int index) { return crypt_key[0][index] & 0xff; }
static int get_hash_2 (int index) { return crypt_key[0][index] & 0xfff; }
static int get_hash_3 (int index) { return crypt_key[0][index] & 0xffff; }
static int get_hash_4 (int index) { return crypt_key[0][index] & 0xfffff; }
static int get_hash_5 (int index) { return crypt_key[0][index] & 0xffffff; }
static int get_hash_6 (int index) { return crypt_key[0][index] & 0x7ffffff; }


static void set_key (char *key, int index)
{
    uint64_t *buf64 = (uint64_t *) &saved_key[index];
    uint8_t  *buf8  = (uint8_t * ) buf64;
    int len = 0;

    memset(buf8, 0, 64);

    while (*key)
        buf8[len++] = *key++;

    buf64[15] = len << 3;
    buf8[len++] = 0x80;
}


static char *get_key (int index)
{
    uint64_t *buf64 = (uint64_t *) &saved_key[index];
    uint8_t  *buf8  = (uint8_t * ) buf64;

    static char out[MAXLEN + 1];
    int len = buf64[15] >> 3;

    out[len] = 0;

    for (len--; len > -1; len--)
        out[len] = buf8[len];

    return (char *) out;
}


#if FMT_MAIN_VERSION > 10
static int crypt_all (int *pcount, struct db_salt *salt)
#else
static void crypt_all (int count)
#endif
{
    int i;

    __m128i a, b, c, d, e, f, g, h;
    __m128i w[80], tmp1, tmp2;


    for (i=0; i < 16; i++) GATHER (w[i], saved_key, i);
    for (i=0; i < 15; i++) SWAP_ENDIAN (w[i]);
    for (i++; i < 80; i++) R(i);

    a = _mm_set1_epi64x (0x6a09e667f3bcc908);
    b = _mm_set1_epi64x (0xbb67ae8584caa73b);
    c = _mm_set1_epi64x (0x3c6ef372fe94f82b);
    d = _mm_set1_epi64x (0xa54ff53a5f1d36f1);
    e = _mm_set1_epi64x (0x510e527fade682d1);
    f = _mm_set1_epi64x (0x9b05688c2b3e6c1f);
    g = _mm_set1_epi64x (0x1f83d9abfb41bd6b);
    h = _mm_set1_epi64x (0x5be0cd19137e2179);

    SHA512_STEP(a, b, c, d, e, f, g, h,  0, 0x428a2f98d728ae22);
    SHA512_STEP(h, a, b, c, d, e, f, g,  1, 0x7137449123ef65cd);
    SHA512_STEP(g, h, a, b, c, d, e, f,  2, 0xb5c0fbcfec4d3b2f);
    SHA512_STEP(f, g, h, a, b, c, d, e,  3, 0xe9b5dba58189dbbc);
    SHA512_STEP(e, f, g, h, a, b, c, d,  4, 0x3956c25bf348b538);
    SHA512_STEP(d, e, f, g, h, a, b, c,  5, 0x59f111f1b605d019);
    SHA512_STEP(c, d, e, f, g, h, a, b,  6, 0x923f82a4af194f9b);
    SHA512_STEP(b, c, d, e, f, g, h, a,  7, 0xab1c5ed5da6d8118);
    SHA512_STEP(a, b, c, d, e, f, g, h,  8, 0xd807aa98a3030242);
    SHA512_STEP(h, a, b, c, d, e, f, g,  9, 0x12835b0145706fbe);
    SHA512_STEP(g, h, a, b, c, d, e, f, 10, 0x243185be4ee4b28c);
    SHA512_STEP(f, g, h, a, b, c, d, e, 11, 0x550c7dc3d5ffb4e2);
    SHA512_STEP(e, f, g, h, a, b, c, d, 12, 0x72be5d74f27b896f);
    SHA512_STEP(d, e, f, g, h, a, b, c, 13, 0x80deb1fe3b1696b1);
    SHA512_STEP(c, d, e, f, g, h, a, b, 14, 0x9bdc06a725c71235);
    SHA512_STEP(b, c, d, e, f, g, h, a, 15, 0xc19bf174cf692694);

    SHA512_STEP(a, b, c, d, e, f, g, h, 16, 0xe49b69c19ef14ad2);
    SHA512_STEP(h, a, b, c, d, e, f, g, 17, 0xefbe4786384f25e3);
    SHA512_STEP(g, h, a, b, c, d, e, f, 18, 0x0fc19dc68b8cd5b5);
    SHA512_STEP(f, g, h, a, b, c, d, e, 19, 0x240ca1cc77ac9c65);
    SHA512_STEP(e, f, g, h, a, b, c, d, 20, 0x2de92c6f592b0275);
    SHA512_STEP(d, e, f, g, h, a, b, c, 21, 0x4a7484aa6ea6e483);
    SHA512_STEP(c, d, e, f, g, h, a, b, 22, 0x5cb0a9dcbd41fbd4);
    SHA512_STEP(b, c, d, e, f, g, h, a, 23, 0x76f988da831153b5);
    SHA512_STEP(a, b, c, d, e, f, g, h, 24, 0x983e5152ee66dfab);
    SHA512_STEP(h, a, b, c, d, e, f, g, 25, 0xa831c66d2db43210);
    SHA512_STEP(g, h, a, b, c, d, e, f, 26, 0xb00327c898fb213f);
    SHA512_STEP(f, g, h, a, b, c, d, e, 27, 0xbf597fc7beef0ee4);
    SHA512_STEP(e, f, g, h, a, b, c, d, 28, 0xc6e00bf33da88fc2);
    SHA512_STEP(d, e, f, g, h, a, b, c, 29, 0xd5a79147930aa725);
    SHA512_STEP(c, d, e, f, g, h, a, b, 30, 0x06ca6351e003826f);
    SHA512_STEP(b, c, d, e, f, g, h, a, 31, 0x142929670a0e6e70);

    SHA512_STEP(a, b, c, d, e, f, g, h, 32, 0x27b70a8546d22ffc);
    SHA512_STEP(h, a, b, c, d, e, f, g, 33, 0x2e1b21385c26c926);
    SHA512_STEP(g, h, a, b, c, d, e, f, 34, 0x4d2c6dfc5ac42aed);
    SHA512_STEP(f, g, h, a, b, c, d, e, 35, 0x53380d139d95b3df);
    SHA512_STEP(e, f, g, h, a, b, c, d, 36, 0x650a73548baf63de);
    SHA512_STEP(d, e, f, g, h, a, b, c, 37, 0x766a0abb3c77b2a8);
    SHA512_STEP(c, d, e, f, g, h, a, b, 38, 0x81c2c92e47edaee6);
    SHA512_STEP(b, c, d, e, f, g, h, a, 39, 0x92722c851482353b);
    SHA512_STEP(a, b, c, d, e, f, g, h, 40, 0xa2bfe8a14cf10364);
    SHA512_STEP(h, a, b, c, d, e, f, g, 41, 0xa81a664bbc423001);
    SHA512_STEP(g, h, a, b, c, d, e, f, 42, 0xc24b8b70d0f89791);
    SHA512_STEP(f, g, h, a, b, c, d, e, 43, 0xc76c51a30654be30);
    SHA512_STEP(e, f, g, h, a, b, c, d, 44, 0xd192e819d6ef5218);
    SHA512_STEP(d, e, f, g, h, a, b, c, 45, 0xd69906245565a910);
    SHA512_STEP(c, d, e, f, g, h, a, b, 46, 0xf40e35855771202a);
    SHA512_STEP(b, c, d, e, f, g, h, a, 47, 0x106aa07032bbd1b8);

    SHA512_STEP(a, b, c, d, e, f, g, h, 48, 0x19a4c116b8d2d0c8);
    SHA512_STEP(h, a, b, c, d, e, f, g, 49, 0x1e376c085141ab53);
    SHA512_STEP(g, h, a, b, c, d, e, f, 50, 0x2748774cdf8eeb99);
    SHA512_STEP(f, g, h, a, b, c, d, e, 51, 0x34b0bcb5e19b48a8);
    SHA512_STEP(e, f, g, h, a, b, c, d, 52, 0x391c0cb3c5c95a63);
    SHA512_STEP(d, e, f, g, h, a, b, c, 53, 0x4ed8aa4ae3418acb);
    SHA512_STEP(c, d, e, f, g, h, a, b, 54, 0x5b9cca4f7763e373);
    SHA512_STEP(b, c, d, e, f, g, h, a, 55, 0x682e6ff3d6b2b8a3);
    SHA512_STEP(a, b, c, d, e, f, g, h, 56, 0x748f82ee5defb2fc);
    SHA512_STEP(h, a, b, c, d, e, f, g, 57, 0x78a5636f43172f60);
    SHA512_STEP(g, h, a, b, c, d, e, f, 58, 0x84c87814a1f0ab72);
    SHA512_STEP(f, g, h, a, b, c, d, e, 59, 0x8cc702081a6439ec);
    SHA512_STEP(e, f, g, h, a, b, c, d, 60, 0x90befffa23631e28);
    SHA512_STEP(d, e, f, g, h, a, b, c, 61, 0xa4506cebde82bde9);
    SHA512_STEP(c, d, e, f, g, h, a, b, 62, 0xbef9a3f7b2c67915);
    SHA512_STEP(b, c, d, e, f, g, h, a, 63, 0xc67178f2e372532b);

    SHA512_STEP(a, b, c, d, e, f, g, h, 64, 0xca273eceea26619c);
    SHA512_STEP(h, a, b, c, d, e, f, g, 65, 0xd186b8c721c0c207);
    SHA512_STEP(g, h, a, b, c, d, e, f, 66, 0xeada7dd6cde0eb1e);
    SHA512_STEP(f, g, h, a, b, c, d, e, 67, 0xf57d4f7fee6ed178);
    SHA512_STEP(e, f, g, h, a, b, c, d, 68, 0x06f067aa72176fba);
    SHA512_STEP(d, e, f, g, h, a, b, c, 69, 0x0a637dc5a2c898a6);
    SHA512_STEP(c, d, e, f, g, h, a, b, 70, 0x113f9804bef90dae);
    SHA512_STEP(b, c, d, e, f, g, h, a, 71, 0x1b710b35131c471b);
    SHA512_STEP(a, b, c, d, e, f, g, h, 72, 0x28db77f523047d84);
    SHA512_STEP(h, a, b, c, d, e, f, g, 73, 0x32caab7b40c72493);
    SHA512_STEP(g, h, a, b, c, d, e, f, 74, 0x3c9ebe0a15c9bebc);
    SHA512_STEP(f, g, h, a, b, c, d, e, 75, 0x431d67c49c100d4c);
    SHA512_STEP(e, f, g, h, a, b, c, d, 76, 0x4cc5d4becb3e42b6);
    SHA512_STEP(d, e, f, g, h, a, b, c, 77, 0x597f299cfc657e2a);
    SHA512_STEP(c, d, e, f, g, h, a, b, 78, 0x5fcb6fab3ad6faec);
    SHA512_STEP(b, c, d, e, f, g, h, a, 79, 0x6c44198c4a475817);

    a = _mm_add_epi64 (a, _mm_set1_epi64x (0x6a09e667f3bcc908));
    b = _mm_add_epi64 (b, _mm_set1_epi64x (0xbb67ae8584caa73b));
    c = _mm_add_epi64 (c, _mm_set1_epi64x (0x3c6ef372fe94f82b));
    d = _mm_add_epi64 (d, _mm_set1_epi64x (0xa54ff53a5f1d36f1));
    e = _mm_add_epi64 (e, _mm_set1_epi64x (0x510e527fade682d1));
    f = _mm_add_epi64 (f, _mm_set1_epi64x (0x9b05688c2b3e6c1f));
    g = _mm_add_epi64 (g, _mm_set1_epi64x (0x1f83d9abfb41bd6b));
    h = _mm_add_epi64 (h, _mm_set1_epi64x (0x5be0cd19137e2179));

    _mm_store_si128 ((__m128i *) crypt_key[0], a);
    _mm_store_si128 ((__m128i *) crypt_key[1], b);
    _mm_store_si128 ((__m128i *) crypt_key[2], c);
    _mm_store_si128 ((__m128i *) crypt_key[3], d);
    _mm_store_si128 ((__m128i *) crypt_key[4], e);
    _mm_store_si128 ((__m128i *) crypt_key[5], f);
    _mm_store_si128 ((__m128i *) crypt_key[6], g);
    _mm_store_si128 ((__m128i *) crypt_key[7], h);

#if FMT_MAIN_VERSION > 10
    return *pcount;
#endif
}


static int cmp_all (void *binary, int count)
{
    int i;

    for (i=0; i < 2; i++)
        if (((uint64_t *) binary)[0] == crypt_key[0][i])
            return 1;

    return 0;
}


static int cmp_one (void *binary, int index)
{
    return (((uint64_t *) binary)[0] == crypt_key[0][index]);
}


static int cmp_exact (char *source, int index)
{
    int i;
    uint64_t *bin;

    bin = (uint64_t *) get_binary (source);

    for (i=1; i < 8; i++)
        if (((uint64_t *) bin)[i] != crypt_key[i][index])
            return 0;

    return 1;
}


struct fmt_main fmt_rawSHA512_ng = {
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
        FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
        tests
    }, {
        fmt_default_init,
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
