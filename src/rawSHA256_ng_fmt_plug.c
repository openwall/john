/*
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */

#include "arch.h"
#if defined (__SSE2__)  || defined (_MSC_VER)

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA256_ng;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA256_ng);
#else

#ifdef _OPENMP
#include <omp.h>
#if defined __XOP__
#define OMP_SCALE                 512 /* AMD */
#else
#define OMP_SCALE                 512 /* Intel */
#endif
#endif

// These compilers claim to be __GNUC__ but warn on gcc pragmas.
#if defined(__GNUC__) && !defined(__INTEL_COMPILER) && !defined(__clang__) && !defined(__llvm__) && !defined (_MSC_VER)
#pragma GCC optimize 3
#endif

//#define DEBUG

#include <string.h>
#include "stdint.h"
#include <emmintrin.h>

#if defined __XOP__
#include <x86intrin.h>
#elif defined __SSE4_1__
#include <smmintrin.h>
#elif defined __SSSE3__
#include <tmmintrin.h>
#endif

#include "common.h"
#include "formats.h"
#include "aligned.h"
#include "rawSHA256_common.h"
#include "memdbg.h"

#if defined __XOP__
#define SIMD_TYPE                 "XOP"
#elif defined __SSE4_1__
#define SIMD_TYPE                 "SSE4.1"
#elif defined __SSSE3__
#define SIMD_TYPE                 "SSSE3"
#else
#define SIMD_TYPE                 "SSE2"
#endif

#define FORMAT_LABEL              "Raw-SHA256-ng"
#define FORMAT_NAME               ""
#define ALGORITHM_NAME            "SHA256 128/128 " SIMD_TYPE " 4x"

#define VWIDTH                    4
#define NUMKEYS                   VWIDTH

#define BENCHMARK_COMMENT         ""
#define BENCHMARK_LENGTH          -1

#define MAXLEN                    55
#define CIPHERTEXT_LENGTH         64
#define DIGEST_SIZE               32
#define BINARY_SIZE               32
#define BINARY_ALIGN              4
#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        NUMKEYS
#define MAX_KEYS_PER_CRYPT        NUMKEYS


#ifndef __XOP__
#define _mm_roti_epi32(x, n)                                              \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_srli_epi32(x, ~n + 1),                                        \
        _mm_slli_epi32(x, 32 + n)                                         \
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
            _mm_set_epi32 (0x0c0d0e0f, 0x08090a0b,                        \
                           0x04050607, 0x00010203                         \
            )                                                             \
        );                                                                \
}
#else
#define ROT16(n)                                                          \
(                                                                         \
    _mm_shufflelo_epi16 (                                                 \
        _mm_shufflehi_epi16 (n, 0xb1), 0xb1                               \
    )                                                                     \
)

#define SWAP_ENDIAN(n)                                                    \
(                                                                         \
    n = _mm_xor_si128 (                                                   \
            _mm_srli_epi16 (ROT16(n), 8),                                 \
            _mm_slli_epi16 (ROT16(n), 8)                                  \
        )                                                                 \
)
#endif

#ifdef __SSE4_1__
#define GATHER(x, y, z)                                                   \
{                                                                         \
    x = _mm_cvtsi32_si128 (   y[index][z]   );                            \
    x = _mm_insert_epi32  (x, y[index + 1][z], 1);                        \
    x = _mm_insert_epi32  (x, y[index + 2][z], 2);                        \
    x = _mm_insert_epi32  (x, y[index + 3][z], 3);                        \
}
#endif

#define S0(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_roti_epi32 (x, -22),                                          \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi32 (x,  -2),                                      \
            _mm_roti_epi32 (x, -13)                                       \
        )                                                                 \
    )                                                                     \
)

#define S1(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_roti_epi32 (x, -25),                                          \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi32 (x,  -6),                                      \
            _mm_roti_epi32 (x, -11)                                       \
        )                                                                 \
    )                                                                     \
)

#define s0(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_srli_epi32 (x, 3),                                            \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi32 (x,  -7),                                      \
            _mm_roti_epi32 (x, -18)                                       \
        )                                                                 \
    )                                                                     \
)

#define s1(x)                                                             \
(                                                                         \
    _mm_xor_si128 (                                                       \
        _mm_srli_epi32 (x, 10),                                           \
        _mm_xor_si128 (                                                   \
            _mm_roti_epi32 (x, -17),                                      \
            _mm_roti_epi32 (x, -19)                                       \
        )                                                                 \
    )                                                                     \
)

#define Maj(x,y,z) _mm_cmov_si128 (x, y, _mm_xor_si128 (z, y))

#define Ch(x,y,z) _mm_cmov_si128 (y, z, x)

#define R(t)                                                              \
{                                                                         \
    w[t] = _mm_add_epi32 (s1(w[t -  2]), w[t - 7]);                       \
    w[t] = _mm_add_epi32 (s0(w[t - 15]), w[t]);                           \
    w[t] = _mm_add_epi32 (   w[t - 16],  w[t]);                           \
}

#define SHA256_STEP(a,b,c,d,e,f,g,h,x,K)                                  \
{                                                                         \
    if (x > 15) R(x);                                                     \
    tmp1 = _mm_add_epi32 (h,    S1(e));                                   \
    tmp1 = _mm_add_epi32 (tmp1, Ch(e,f,g));                               \
    tmp1 = _mm_add_epi32 (tmp1, _mm_set1_epi32(K));                       \
    tmp1 = _mm_add_epi32 (tmp1, w[x]);                                    \
    tmp2 = _mm_add_epi32 (S0(a),Maj(a,b,c));                              \
    d    = _mm_add_epi32 (tmp1, d);                                       \
    h    = _mm_add_epi32 (tmp1, tmp2);                                    \
}


static struct fmt_tests tests[] = {
	{"71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{HEX_TAG "71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{"25b64f637b373d33a8aa2b7579784e99a20e6b7dfea99a71af124394b8958f27", "doesthiswork"},
	{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
	{"27c6794c8aa2f70f5f6dc93d3bfb25ca6de9b0752c8318614cbd4ad203bea24c", "ALLCAPS"},
	{"04cdd6c523673bf448efe055711a9b184817d7843b0a76c2046f5398b5854152", "TestTESTt3st"},
	{HEX_TAG "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
	{HEX_TAG "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
	{HEX_TAG "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", ""},
	{"LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{"$cisco4$LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{"a49c2c9d0c006c8cb55a9a7a38822b83e0cd442614cb416af952fa50156761dc", "openwall"},
	{"9e7d3e56996c5a06a6a378567e62f5aa7138ebb0f55c0bdaf73666bf77f73380", "mot\xf6rhead"},
	{"1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014", "test1"},
	{"fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13", "test3"},
	{"d150eb0383c8ef7478248d7e6cf18db333e8753d05e15a8a83714b7cf63922b3", "thatsworking"},
#ifdef DEBUG
	{"c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", "1234567890"},
	{"6ed645ef0e1abea1bf1e4e935ff04f9e18d39812387f63cda3415b46240f0405", "12345678901234567890"},
	{"f54e5c8f810648e7638d25eb7ed6d24b7e5999d588e88826f2aa837d2ee52ecd", "123456789012345678901234567890"},
	{"a4ebdd541454b84cc670c9f1f5508baf67ffd3fe59b883267808781f992a0b1d", "1234567890123456789012345678901234567890"},
	{"f58fffba129aa67ec63bf12571a42977c0b785d3b2a93cc0538557c91da2115d", "12345678901234567890123456789012345678901234567890"},
	{"3874d5c9cc5ab726e6bbebadee22c680ce530004d4f0bb32f765d42a0a6c6dc1", "123456789012345678901234567890123456789012345678901"},
	{"03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9", "1234567890123456789012345678901234567890123456789012345"},
	{"0f46e4b0802fee6fed599682a16287d0397699cfd742025482c086a70979e56a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 31
	{"c62e4615bd39e222572f3a1bf7c2132ea1e65b17ec805047bd6b2842c593493f", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 32
	{"d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 55
	{"$cisco4$OsOmQzwozC4ROs/CzpczJoShdCeW9lp7k/tGrPS5Kog", "1"},
	{"$cisco4$d7kgbEk.P6mpKdduC66fUy1BF0MImo3eyJ9uI/JbMRk", "openwall"},
	{"$cisco4$p5BSCWNS3ivUDpZlWthR.k4Q/xWqlFyEqXdaPikHenI", "2"},
	{"$cisco4$HwUf7ev9Fx84X2vvspULAeDbmwlg9jgm/Wk63kc3vfU", "11"},
	{"$cisco4$bsPEUMVATKKO9yeUlJfE3OCzHlgf0s6goJpg3P1k0UU", "test"},
	{"$cisco4$hUsuWZSE8dZERUBYNwRK8Aa8VxEGIHsuZFUCjNj2.Ac", "verylongbutweakpassword"},
	{"$cisco4$fLUL1VG98zYDf9Q.M40nZ5blVT3M6UBex74Blw.UDCc", "thismaximumpasswordlength"},
	{"$cisco4$Xq81UiuCj7bz9B..EX2BZumsU/d8pF5gs2NlRMW6sTk", "applesucks"},
	{"$cisco4$O/D/cn1nawcByQoJfBxrNnUx6jjfWV.FNFx5TzmzihU", "AppleSucks"},
#endif
	{NULL}
};


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
    saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
    for (i = 0; i < 8; i++)
        crypt_key[i] = mem_calloc_tiny(sizeof(uint32_t) * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
}


static void *get_binary (char *ciphertext)
{
    static unsigned char *out;
    int i;

    if (!out)
        out = mem_alloc_tiny (DIGEST_SIZE, MEM_ALIGN_WORD);

    ciphertext += HEX_TAG_LEN;

    for(i=0; i < BINARY_SIZE; i++)
        out[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                 atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];

    alter_endianity (out, DIGEST_SIZE);

    return (void *) out;
}

static int get_hash_0 (int index) { return crypt_key[0][index] & 0xf; }
static int get_hash_1 (int index) { return crypt_key[0][index] & 0xff; }
static int get_hash_2 (int index) { return crypt_key[0][index] & 0xfff; }
static int get_hash_3 (int index) { return crypt_key[0][index] & 0xffff; }
static int get_hash_4 (int index) { return crypt_key[0][index] & 0xfffff; }
static int get_hash_5 (int index) { return crypt_key[0][index] & 0xffffff; }
static int get_hash_6 (int index) { return crypt_key[0][index] & 0x7ffffff; }


static void set_key (char *key, int index)
{
    uint32_t *buf32 = (uint32_t *) &saved_key[index];
    uint8_t  *buf8  = (uint8_t *) buf32;
    int len = 0;

    while (*key)
	    buf8[len++] = *key++;
    buf32[15] = len << 3;
    buf8[len++] = 0x80;
    while (buf8[len] && len <= MAXLEN)
        buf8[len++] = 0;
}


static char *get_key (int index)
{
    uint32_t *buf = (uint32_t *) &saved_key[index];
    static char out[MAXLEN + 1];

    int len = buf[15] >> 3;

    memset (out, 0, MAXLEN + 1);
    memcpy (out, buf, len);

    return (char *) out;
}


#if FMT_MAIN_VERSION > 10
static int crypt_all (int *pcount, struct db_salt *salt)
#else
static void crypt_all (int count)
#endif
{
#if FMT_MAIN_VERSION > 10
    int count = *pcount;
#endif
    int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
    for (index = 0; index < count; index += VWIDTH)
#endif
    {
        __m128i a, b, c, d, e, f, g, h;
        __m128i w[64], tmp1, tmp2;

        int i;

#ifdef __SSE4_1__
        for (i=0; i < 16; i++) GATHER (w[i], saved_key, i);
        for (i=0; i < 15; i++) SWAP_ENDIAN (w[i]);
#else
        JTR_ALIGN(16) uint32_t __w[16][VWIDTH];
        int j;

        for (i=0; i < VWIDTH; i++)
	        for (j=0; j < 16; j++)
		        __w[j][i] = saved_key[index + i][j];

        for (i=0; i < 15; i++)
        {
	        w[i] = _mm_load_si128 ((__m128i *) __w[i]);
	        SWAP_ENDIAN (w[i]);
        }

        w[15] = _mm_load_si128 ((__m128i *) __w[15]);
#endif

        a = _mm_set1_epi32 (0x6a09e667);
        b = _mm_set1_epi32 (0xbb67ae85);
        c = _mm_set1_epi32 (0x3c6ef372);
        d = _mm_set1_epi32 (0xa54ff53a);
        e = _mm_set1_epi32 (0x510e527f);
        f = _mm_set1_epi32 (0x9b05688c);
        g = _mm_set1_epi32 (0x1f83d9ab);
        h = _mm_set1_epi32 (0x5be0cd19);

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

        a = _mm_add_epi32 (a, _mm_set1_epi32 (0x6a09e667));
        b = _mm_add_epi32 (b, _mm_set1_epi32 (0xbb67ae85));
        c = _mm_add_epi32 (c, _mm_set1_epi32 (0x3c6ef372));
        d = _mm_add_epi32 (d, _mm_set1_epi32 (0xa54ff53a));
        e = _mm_add_epi32 (e, _mm_set1_epi32 (0x510e527f));
        f = _mm_add_epi32 (f, _mm_set1_epi32 (0x9b05688c));
        g = _mm_add_epi32 (g, _mm_set1_epi32 (0x1f83d9ab));
        h = _mm_add_epi32 (h, _mm_set1_epi32 (0x5be0cd19));

        _mm_store_si128 ((__m128i *) &crypt_key[0][index], a);
        _mm_store_si128 ((__m128i *) &crypt_key[1][index], b);
        _mm_store_si128 ((__m128i *) &crypt_key[2][index], c);
        _mm_store_si128 ((__m128i *) &crypt_key[3][index], d);
        _mm_store_si128 ((__m128i *) &crypt_key[4][index], e);
        _mm_store_si128 ((__m128i *) &crypt_key[5][index], f);
        _mm_store_si128 ((__m128i *) &crypt_key[6][index], g);
        _mm_store_si128 ((__m128i *) &crypt_key[7][index], h);
    }
#if FMT_MAIN_VERSION > 10
    return count;
#endif
}


static int cmp_all (void *binary, int count)
{
#ifdef _OPENMP
    int i;

    for (i = 0; i < count; i++)
        if (((uint32_t *) binary)[0] == crypt_key[0][i])
             return 1;
    return 0;
#else
    static const __m128i zero = {0};

    __m128i tmp;
    __m128i bin;
    __m128i digest;

    digest = _mm_load_si128 ((__m128i *) crypt_key[0]);
    bin    = _mm_set1_epi32 (((uint32_t *) binary)[0]);
    tmp    = _mm_cmpeq_epi32 (bin, digest);

    return _mm_movemask_epi8 (_mm_cmpeq_epi32 (tmp, zero)) != 0xffff;
#endif
}


static int cmp_one (void *binary, int index)
{
    int i;

    for (i = 0; i < 8; i++)
        if (((uint32_t *) binary)[i] != crypt_key[i][index])
            return 0;

    return 1;
}


static int cmp_exact (char *source, int index)
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
        tests
    }, {
        init,
#if FMT_MAIN_VERSION > 10
        fmt_default_done,
        fmt_default_reset,
#endif
        prepare,
        valid,
        split,
        get_binary,
        fmt_default_salt,
#if FMT_MAIN_VERSION > 9
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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

#endif /* plugin stanza */

#endif /* __SSE2__ */
