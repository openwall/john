/*
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */

#include "arch.h"
#if defined __SSE2__

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA512_ng;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA512_ng);
#else

#ifdef _OPENMP
#include <omp.h>
#if defined __XOP__
#define OMP_SCALE                 768 /* AMD */
#else
#define OMP_SCALE                 2048 /* Intel */
#endif
#endif

// These compilers claim to be __GNUC__ but warn on gcc pragmas.
#if defined(__GNUC__) && !defined(__INTEL_COMPILER) && !defined(__clang__) && !defined(__llvm__) && !defined (_MSC_VER)
#pragma GCC optimize 3
#endif

#include "stdint.h"
#include <string.h>
#include <emmintrin.h>

#if defined __XOP__
#include <x86intrin.h>
#elif defined __SSSE3__
#include <tmmintrin.h>
#endif

#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "memdbg.h"

#if defined __XOP__
#define SIMD_TYPE                 "XOP"
#elif defined __SSSE3__
#define SIMD_TYPE                 "SSSE3"
#else
#define SIMD_TYPE                 "SSE2"
#endif

#define FORMAT_LABEL              "Raw-SHA512-ng"
#define FORMAT_NAME               ""
#define ALGORITHM_NAME            "SHA512 128/128 " SIMD_TYPE " 2x"
#define FORMAT_TAG                "$SHA512$"
#define TAG_LENGTH                8

#define BENCHMARK_COMMENT         ""
#define BENCHMARK_LENGTH          -1

// max length is not 119, but 8 less than this, or 111.  111 actually make sense.
// For SHA512 there are 14 'usable' 8 byte ints, minus 1 byte (for the 0x80).
// 14*8-1 is 111. This comment left for reference for future sha2 hackers within JtR.

//#define MAXLEN                    119
#define MAXLEN                    111
#define CIPHERTEXT_LENGTH         128
#define FULL_BINARY_SIZE          64
#define BINARY_SIZE               8
#define BINARY_ALIGN              8
#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        2
#define MAX_KEYS_PER_CRYPT        2

#if defined (_MSC_VER) && !defined (_M_X64)
// 32 bit VC does NOT define these intrinsics :((((
_inline __m128i _mm_set_epi64x(uint64_t a, uint64_t b) {
	__m128i x;
	x.m128i_u64[0] = b;
	x.m128i_u64[1] = a;
	return x;
}
_inline __m128i _mm_set1_epi64x(uint64_t a) {
	__m128i x;
	x.m128i_u64[0] = a;
	x.m128i_u64[1] = a;
	return x;
}
#endif

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
    x = _mm_set_epi64x (y[index + 1][z], y[index][z]);                    \
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
    tmp1 = _mm_add_epi64 (s1(w[t -  2]), w[t - 7]);                       \
    tmp2 = _mm_add_epi64 (s0(w[t - 15]), w[t - 16]);                      \
    w[t] = _mm_add_epi64 (tmp1, tmp2);                                    \
}

#define SHA512_STEP(a,b,c,d,e,f,g,h,x,K)                                  \
{                                                                         \
    tmp1 = _mm_add_epi64 (h,    w[x]);                                    \
    tmp2 = _mm_add_epi64 (S1(e),_mm_set1_epi64x(K));                      \
    tmp1 = _mm_add_epi64 (tmp1, Ch(e,f,g));                               \
    tmp1 = _mm_add_epi64 (tmp1, tmp2);                                    \
    tmp2 = _mm_add_epi64 (S0(a),Maj(a,b,c));                              \
    d    = _mm_add_epi64 (tmp1, d);                                       \
    h    = _mm_add_epi64 (tmp1, tmp2);                                    \
}


static struct fmt_tests tests[] = {
	{"f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{FORMAT_TAG "f342aae82952db35b8e02c30115e3deed3d80fdfdadacab336f0ba51ac54e297291fa1d6b201d69a2bd77e2535280f17a54fa1e527abc6e2eddba79ad3be11c0", "epixoip"},
	{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
	{"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
	{"71ebcb1eccd7ea22bd8cebaec735a43f1f7164d003dacdeb06e0de4a6d9f64d123b00a45227db815081b1008d1a1bbad4c39bde770a2c23308ff1b09418dd7ed", "ALLCAPS"},
	{"82244918c2e45fbaa00c7c7d52eb61f309a37e2f33ea1fba78e61b4140efa95731eec849de02ee16aa31c82848b51fb7b7fbae62f50df6e150a8a85e70fa740c", "TestTESTt3st"},
	{"fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "fa585d89c851dd338a70dcf535aa2a92fee7836dd6aff1226583e88e0996293f16bc009c652826e0fc5c706695a03cddce372f139eff4d13959da6f1f5d3eabe", "12345678"},
	{FORMAT_TAG "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", ""},
	{"c96f1c1260074832bd3068ddd29e733090285dfc65939555dbbcafb27834957d15d9c509481cc7df0e2a7e21429783ba573036b78f5284f9928b5fef02a791ef", "mot\xf6rhead"},
	{"aa3b7bdd98ec44af1f395bbd5f7f27a5cd9569d794d032747323bf4b1521fbe7725875a68b440abdf0559de5015baf873bb9c01cae63ecea93ad547a7397416e", "12345678901234567890"},
	{"db9981645857e59805132f7699e78bbcf39f69380a41aac8e6fa158a0593f2017ffe48764687aa855dae3023fcceefd51a1551d57730423df18503e80ba381ba", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"7aba4411846c61b08b0f2282a8a4600232ace4dd96593c755ba9c9a4e7b780b8bdc437b5c55574b3e8409c7b511032f98ef120e25467678f0458643578eb60ff", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901"},
	// this one DOES NOT work for a 1 limb. Only 111 bytes max can be used, unless we do 2 sha512 limbs.
//	{"a5fa73a3c9ca13df56c2cb3ae6f2e57671239a6b461ef5021a65d08f40336bfb458ec52a3003e1004f1a40d0706c27a9f4268fa4e1479382e2053c2b5b47b9b2", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"},
#ifdef DEBUG //Special test cases.
	{"12b03226a6d8be9c6e8cd5e55dc6c7920caaa39df14aab92d5e3ea9340d1c8a4d3d0b8e4314f1f6ef131ba4bf1ceb9186ab87c801af0d5c95b1befb8cedae2b9", "1234567890"},
	{"eba392e2f2094d7ffe55a23dffc29c412abd47057a0823c6c149c9c759423afde56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02", "123456789012345678901234567890"},
	{"3a8529d8f0c7b1ad2fa54c944952829b718d5beb4ff9ba8f4a849e02fe9a272daf59ae3bd06dde6f01df863d87c8ba4ab016ac576b59a19078c26d8dbe63f79e", "1234567890123456789012345678901234567890"},
	{"49c1faba580a55d6473f427174b62d8aa68f49958d70268eb8c7f258ba5bb089b7515891079451819aa4f8bf75b784dc156e7400ab0a04dfd2b75e46ef0a943e", "12345678901234567890123456789012345678901234567890"},
	{"8c5b51368ec88e1b1c4a67aa9de0aa0919447e142a9c245d75db07bbd4d00962b19112adb9f2b52c0a7b29fe2de661a872f095b6a1670098e5c7fde4a3503896", "123456789012345678901234567890123456789012345678901"},
	{"35ea7bc1d848db0f7ff49178392bf58acfae94bf74d77ae2d7e978df52aac250ff2560f9b98dc7726f0b8e05b25e5132074b470eb461c4ebb7b4d8bf9ef0d93f", "1234567890123456789012345678901234567890123456789012345"},
#endif
    {NULL}
};

static uint64_t (*saved_key)[16];
static uint64_t *crypt_key[ 8];


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
    saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_CACHE);
    for (i = 0; i < 8; i++)
	    crypt_key[i] = mem_calloc_tiny(sizeof(uint64_t) * self->params.max_keys_per_crypt, MEM_ALIGN_CACHE);
}


static inline void alter_endianity_64 (uint64_t *x, unsigned int size)
{
    int i;

    for (i=0; i < (size / sizeof(*x)); i++)
        x[i] = JOHNSWAP64(x[i]);
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

    for (i=0; i < FULL_BINARY_SIZE; i++)
        out->c[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                    atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];

    alter_endianity_64 (out->w, FULL_BINARY_SIZE);

    out->w[0] -= 0x6a09e667f3bcc908ULL;
    out->w[1] -= 0xbb67ae8584caa73bULL;
    out->w[2] -= 0x3c6ef372fe94f82bULL;
    out->w[3] -= 0xa54ff53a5f1d36f1ULL;
    out->w[4] -= 0x510e527fade682d1ULL;
    out->w[5] -= 0x9b05688c2b3e6c1fULL;
    out->w[6] -= 0x1f83d9abfb41bd6bULL;
    out->w[7] -= 0x5be0cd19137e2179ULL;

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
    uint64_t *buf64 = (uint64_t *) &saved_key[index];
    uint8_t  *buf8  = (uint8_t * ) buf64;
    int len = 0;

    while (*key && len < MAXLEN)
        buf8[len++] = *key++;
    buf64[15] = len << 3;
    buf8[len++] = 0x80;
    while (buf8[len] && len <= MAXLEN)
        buf8[len++] = 0;
}


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
    for (index = 0; index < count; index += 2)
#endif
    {
        int i;

        __m128i a, b, c, d, e, f, g, h;
        __m128i w[80], tmp1, tmp2;


        for (i = 0; i < 14; i += 2) {
            GATHER (tmp1, saved_key, i);
            GATHER (tmp2, saved_key, i + 1);
            SWAP_ENDIAN (tmp1);
            SWAP_ENDIAN (tmp2);
            w[i] = tmp1;
            w[i + 1] = tmp2;
        }
        GATHER (tmp1, saved_key, 14);
        SWAP_ENDIAN (tmp1);
        w[14] = tmp1;
        GATHER (w[15], saved_key, 15);
        for (i = 16; i < 80; i++) R(i);

        a = _mm_set1_epi64x (0x6a09e667f3bcc908ULL);
        b = _mm_set1_epi64x (0xbb67ae8584caa73bULL);
        c = _mm_set1_epi64x (0x3c6ef372fe94f82bULL);
        d = _mm_set1_epi64x (0xa54ff53a5f1d36f1ULL);
        e = _mm_set1_epi64x (0x510e527fade682d1ULL);
        f = _mm_set1_epi64x (0x9b05688c2b3e6c1fULL);
        g = _mm_set1_epi64x (0x1f83d9abfb41bd6bULL);
        h = _mm_set1_epi64x (0x5be0cd19137e2179ULL);

        SHA512_STEP(a, b, c, d, e, f, g, h,  0, 0x428a2f98d728ae22ULL);
        SHA512_STEP(h, a, b, c, d, e, f, g,  1, 0x7137449123ef65cdULL);
        SHA512_STEP(g, h, a, b, c, d, e, f,  2, 0xb5c0fbcfec4d3b2fULL);
        SHA512_STEP(f, g, h, a, b, c, d, e,  3, 0xe9b5dba58189dbbcULL);
        SHA512_STEP(e, f, g, h, a, b, c, d,  4, 0x3956c25bf348b538ULL);
        SHA512_STEP(d, e, f, g, h, a, b, c,  5, 0x59f111f1b605d019ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b,  6, 0x923f82a4af194f9bULL);
        SHA512_STEP(b, c, d, e, f, g, h, a,  7, 0xab1c5ed5da6d8118ULL);
        SHA512_STEP(a, b, c, d, e, f, g, h,  8, 0xd807aa98a3030242ULL);
        SHA512_STEP(h, a, b, c, d, e, f, g,  9, 0x12835b0145706fbeULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 10, 0x243185be4ee4b28cULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 11, 0x550c7dc3d5ffb4e2ULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 12, 0x72be5d74f27b896fULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 13, 0x80deb1fe3b1696b1ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 14, 0x9bdc06a725c71235ULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 15, 0xc19bf174cf692694ULL);

        SHA512_STEP(a, b, c, d, e, f, g, h, 16, 0xe49b69c19ef14ad2ULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 17, 0xefbe4786384f25e3ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 18, 0x0fc19dc68b8cd5b5ULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 19, 0x240ca1cc77ac9c65ULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 20, 0x2de92c6f592b0275ULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 21, 0x4a7484aa6ea6e483ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 22, 0x5cb0a9dcbd41fbd4ULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 23, 0x76f988da831153b5ULL);
        SHA512_STEP(a, b, c, d, e, f, g, h, 24, 0x983e5152ee66dfabULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 25, 0xa831c66d2db43210ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 26, 0xb00327c898fb213fULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 27, 0xbf597fc7beef0ee4ULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 28, 0xc6e00bf33da88fc2ULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 29, 0xd5a79147930aa725ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 30, 0x06ca6351e003826fULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 31, 0x142929670a0e6e70ULL);

        SHA512_STEP(a, b, c, d, e, f, g, h, 32, 0x27b70a8546d22ffcULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 33, 0x2e1b21385c26c926ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 34, 0x4d2c6dfc5ac42aedULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 35, 0x53380d139d95b3dfULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 36, 0x650a73548baf63deULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 37, 0x766a0abb3c77b2a8ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 38, 0x81c2c92e47edaee6ULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 39, 0x92722c851482353bULL);
        SHA512_STEP(a, b, c, d, e, f, g, h, 40, 0xa2bfe8a14cf10364ULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 41, 0xa81a664bbc423001ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 42, 0xc24b8b70d0f89791ULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 43, 0xc76c51a30654be30ULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 44, 0xd192e819d6ef5218ULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 45, 0xd69906245565a910ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 46, 0xf40e35855771202aULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 47, 0x106aa07032bbd1b8ULL);

        SHA512_STEP(a, b, c, d, e, f, g, h, 48, 0x19a4c116b8d2d0c8ULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 49, 0x1e376c085141ab53ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 50, 0x2748774cdf8eeb99ULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 51, 0x34b0bcb5e19b48a8ULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 52, 0x391c0cb3c5c95a63ULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 53, 0x4ed8aa4ae3418acbULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 54, 0x5b9cca4f7763e373ULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 55, 0x682e6ff3d6b2b8a3ULL);
        SHA512_STEP(a, b, c, d, e, f, g, h, 56, 0x748f82ee5defb2fcULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 57, 0x78a5636f43172f60ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 58, 0x84c87814a1f0ab72ULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 59, 0x8cc702081a6439ecULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 60, 0x90befffa23631e28ULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 61, 0xa4506cebde82bde9ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 62, 0xbef9a3f7b2c67915ULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 63, 0xc67178f2e372532bULL);

        SHA512_STEP(a, b, c, d, e, f, g, h, 64, 0xca273eceea26619cULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 65, 0xd186b8c721c0c207ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 66, 0xeada7dd6cde0eb1eULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 67, 0xf57d4f7fee6ed178ULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 68, 0x06f067aa72176fbaULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 69, 0x0a637dc5a2c898a6ULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 70, 0x113f9804bef90daeULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 71, 0x1b710b35131c471bULL);
        SHA512_STEP(a, b, c, d, e, f, g, h, 72, 0x28db77f523047d84ULL);
        SHA512_STEP(h, a, b, c, d, e, f, g, 73, 0x32caab7b40c72493ULL);
        SHA512_STEP(g, h, a, b, c, d, e, f, 74, 0x3c9ebe0a15c9bebcULL);
        SHA512_STEP(f, g, h, a, b, c, d, e, 75, 0x431d67c49c100d4cULL);
        SHA512_STEP(e, f, g, h, a, b, c, d, 76, 0x4cc5d4becb3e42b6ULL);
        SHA512_STEP(d, e, f, g, h, a, b, c, 77, 0x597f299cfc657e2aULL);
        SHA512_STEP(c, d, e, f, g, h, a, b, 78, 0x5fcb6fab3ad6faecULL);
        SHA512_STEP(b, c, d, e, f, g, h, a, 79, 0x6c44198c4a475817ULL);

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
    int i;

#ifdef _OPENMP
    for (i=0; i < count; i++)
#else
    for (i=0; i < 2; i++)
#endif
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
        fmt_default_prepare,
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
