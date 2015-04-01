/*
 * Copyright (c) 2013, epixoip.
 * Copyright (c) 2015, magnum (pseudo-intrinsics also supporting AVX2/AVX512)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 */

#include "arch.h"
#if __SSE2__ || __MIC__

#if FMT_EXTERNS_H
extern struct fmt_main fmt_rawSHA512_ng;
#elif FMT_REGISTERS_H
john_register_one(&fmt_rawSHA512_ng);
#else

#if !FAST_FORMATS_OMP
#undef _OPENMP
#elif _OPENMP
#include <omp.h>
#if __XOP__
#define OMP_SCALE                 768 /* AMD */
#else
#define OMP_SCALE                 2048 /* Intel */
#endif
#endif

// These compilers claim to be __GNUC__ but warn on gcc pragmas.
#if __GNUC__ && !__INTEL_COMPILER && !__clang__ && !__llvm__ && !_MSC_VER
#pragma GCC optimize 3
#endif

#include "stdint.h"
#include <string.h>

#include "pseudo_intrinsics.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "memdbg.h"

#if __MIC__
#define SIMD_TYPE                 "512/512 MIC 8x"
#elif __AVX512__
#define SIMD_TYPE                 "512/512 AVX512 8x"
#elif __AVX2__
#define SIMD_TYPE                 "256/256 AVX2 4x"
#elif __XOP__
#define SIMD_TYPE                 "128/128 XOP 2x"
#elif __SSSE3__
#define SIMD_TYPE                 "128/128 SSSE3 2x"
#else
#define SIMD_TYPE                 "128/128 SSE2 2x"
#endif

#define FORMAT_LABEL              "Raw-SHA512-ng"
#define FORMAT_NAME               ""
#define ALGORITHM_NAME            "SHA512 " SIMD_TYPE

#define VWIDTH                    SIMD_COEF_64

// max length is not 119, but 8 less than this, or 111.  111 actually make sense.
// For SHA512 there are 14 'usable' 8 byte ints, minus 1 byte (for the 0x80).
// 14*8-1 is 111. This comment left for reference for future sha2 hackers within JtR.

//#define MAXLEN                    119
#define MAXLEN                    111
#define PLAINTEXT_LENGTH	  MAXLEN
#define CIPHERTEXT_LENGTH         128
#define SHORT_BINARY_SIZE         8
#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        VWIDTH
#define MAX_KEYS_PER_CRYPT        VWIDTH
#define _RAWSHA512_H
#include "rawSHA512_common.h"
#undef _RAWSHA512_H

#if _MSC_VER && !_M_X64
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

#if __AVX512__
#define SWAP_ENDIAN(n)                                                    \
{                                                                         \
    n = vshuffle_epi8(n,                                                  \
            vset_epi64x(0x38393a3b3c3d3e3f, 0x3031323334353637,           \
                        0x28292a2b2c2d2e2f, 0x2021222324252627,           \
                        0x18191a1b1c1d1e1f, 0x1011121314151617,           \
                        0x08090a0b0c0d0e0f, 0x0001020304050607)           \
        );                                                                \
}
#elif __MIC__
#define SWAP_ENDIAN(n)                                                    \
{                                                                         \
    n = vshuffle_epi32(n, 0xb1);                                          \
    vswap32(n);                                                           \
}
#elif __AVX2__
#define SWAP_ENDIAN(n)                                                    \
{                                                                         \
    n = vshuffle_epi8(n,                                                  \
            vset_epi64x(0x18191a1b1c1d1e1f, 0x1011121314151617,           \
                        0x08090a0b0c0d0e0f, 0x0001020304050607)           \
        );                                                                \
}
#elif __SSSE3__
#define SWAP_ENDIAN(n)                                                    \
{                                                                         \
    n = vshuffle_epi8(n,                                                  \
            vset_epi64x(0x08090a0b0c0d0e0f, 0x0001020304050607)           \
        );                                                                \
}
#else
#define SWAP_ENDIAN(n)                                                    \
{                                                                         \
    n = vshufflehi_epi16(vshufflelo_epi16(n, 0xb1), 0xb1);                \
    n = vxor(vslli_epi16(n, 8), vsrli_epi16(n, 8));                       \
    n = vshuffle_epi32(n, 0xb1);                                          \
}
#endif

#undef GATHER /* This one is not like the shared ones in pseudo_intrinsics.h */

#if __AVX512__ || __MIC__
#define GATHER(x,y,z)                                                     \
{                                                                         \
    x = vset_epi64x(y[index + 7][z], y[index + 6][z],                     \
                    y[index + 5][z], y[index + 4][z],                     \
                    y[index + 3][z], y[index + 2][z],                     \
                    y[index + 1][z], y[index + 0][z]);                    \
}

#elif __AVX2__
#define GATHER(x,y,z)                                                     \
{                                                                         \
    x = vset_epi64x(y[index + 3][z], y[index + 2][z],                     \
                    y[index + 1][z], y[index    ][z]);                    \
}
#else
#define GATHER(x,y,z)                                                     \
{                                                                         \
    x = vset_epi64x(y[index + 1][z], y[index    ][z]);                    \
}
#endif

#define S0(x)                                                             \
(                                                                         \
    vxor(                                                                 \
        vroti_epi64(x, -39),                                              \
        vxor(                                                             \
            vroti_epi64(x, -28),                                          \
            vroti_epi64(x, -34)                                           \
        )                                                                 \
    )                                                                     \
)

#define S1(x)                                                             \
(                                                                         \
    vxor(                                                                 \
        vroti_epi64(x, -41),                                              \
        vxor(                                                             \
            vroti_epi64(x, -14),                                          \
            vroti_epi64(x, -18)                                           \
        )                                                                 \
    )                                                                     \
)

#define s0(x)                                                             \
(                                                                         \
    vxor(                                                                 \
        vsrli_epi64(x, 7),                                                \
        vxor(                                                             \
            vroti_epi64(x, -1),                                           \
            vroti_epi64(x, -8)                                            \
        )                                                                 \
    )                                                                     \
)

#define s1(x)                                                             \
(                                                                         \
    vxor(                                                                 \
        vsrli_epi64(x, 6),                                                \
        vxor(                                                             \
            vroti_epi64(x, -19),                                          \
            vroti_epi64(x, -61)                                           \
        )                                                                 \
    )                                                                     \
)

#define Maj(x,y,z) vcmov(x, y, vxor(z, y))

#define Ch(x,y,z)  vcmov(y, z, x)

#define R(t)                                                              \
{                                                                         \
    tmp1 = vadd_epi64(s1(w[t -  2]), w[t - 7]);                           \
    tmp2 = vadd_epi64(s0(w[t - 15]), w[t - 16]);                          \
    w[t] = vadd_epi64(tmp1, tmp2);                                        \
}

#define SHA512_STEP(a,b,c,d,e,f,g,h,x,K)                                  \
{                                                                         \
    tmp1 = vadd_epi64(h,    w[x]);                                        \
    tmp2 = vadd_epi64(S1(e),vset1_epi64x(K));                             \
    tmp1 = vadd_epi64(tmp1, Ch(e,f,g));                                   \
    tmp1 = vadd_epi64(tmp1, tmp2);                                        \
    tmp2 = vadd_epi64(S0(a),Maj(a,b,c));                                  \
    d    = vadd_epi64(tmp1, d);                                           \
    h    = vadd_epi64(tmp1, tmp2);                                        \
}

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
    saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
                           sizeof(*saved_key), MEM_ALIGN_SIMD);
    for (i = 0; i < 8; i++)
        crypt_key[i] = mem_calloc_align(self->params.max_keys_per_crypt,
	                          sizeof(uint64_t), MEM_ALIGN_SIMD);
}


static void done(void)
{
    int i;

    for (i = 0; i < 8; i++)
        MEM_FREE(crypt_key[i]);
    MEM_FREE(saved_key);
}


static inline void alter_endianity_64(uint64_t *x, unsigned int size)
{
    int i;

    for (i=0; i < (size / sizeof(*x)); i++)
        x[i] = JOHNSWAP64(x[i]);
}


static int valid(char *ciphertext, struct fmt_main *self)
{
    char *p, *q;

    p = ciphertext;

    if (! strncmp(p, FORMAT_TAG, TAG_LENGTH))
        p += TAG_LENGTH;

    q = p;
    while (atoi16[ARCH_INDEX(*q)] != 0x7F) q++;

    return !*q && q - p == CIPHERTEXT_LENGTH;
}


static char *split(char *ciphertext, int index, struct fmt_main *self)
{
    static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

    if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
        ciphertext += TAG_LENGTH;

    memcpy(out,  FORMAT_TAG, TAG_LENGTH);
    memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
    strlwr(out + TAG_LENGTH);

    return out;
}


static void *get_binary(char *ciphertext)
{
    static union {
        unsigned char c[BINARY_SIZE];
        uint64_t w[BINARY_SIZE / sizeof(uint64_t)];
    } *out;
    int i;

    if (!out)
        out = mem_alloc_tiny(BINARY_SIZE, BINARY_ALIGN);

    ciphertext += TAG_LENGTH;

    for (i=0; i < BINARY_SIZE; i++)
        out->c[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                    atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];

    alter_endianity_64(out->w, BINARY_SIZE);

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

static int get_hash_0(int index) { return crypt_key[0][index] & 0xf; }
static int get_hash_1(int index) { return crypt_key[0][index] & 0xff; }
static int get_hash_2(int index) { return crypt_key[0][index] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[0][index] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[0][index] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[0][index] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[0][index] & 0x7ffffff; }


static void set_key(char *key, int index)
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


static char *get_key(int index)
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


static int crypt_all(int *pcount, struct db_salt *salt)
{
    int count = *pcount;
    int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
    for (index = 0; index < count; index += VWIDTH)
#endif
    {
        int i;

        vtype a, b, c, d, e, f, g, h;
        vtype w[80], tmp1, tmp2;

        for (i = 0; i < 14; i += 2) {
            GATHER(tmp1, saved_key, i);
            GATHER(tmp2, saved_key, i + 1);
            vswap64(tmp1);
            vswap64(tmp2);
            w[i] = tmp1;
            w[i + 1] = tmp2;
        }
        GATHER(tmp1, saved_key, 14);
        vswap64(tmp1);
        w[14] = tmp1;
        GATHER(w[15], saved_key, 15);
        for (i = 16; i < 80; i++) R(i);

        a = vset1_epi64x(0x6a09e667f3bcc908ULL);
        b = vset1_epi64x(0xbb67ae8584caa73bULL);
        c = vset1_epi64x(0x3c6ef372fe94f82bULL);
        d = vset1_epi64x(0xa54ff53a5f1d36f1ULL);
        e = vset1_epi64x(0x510e527fade682d1ULL);
        f = vset1_epi64x(0x9b05688c2b3e6c1fULL);
        g = vset1_epi64x(0x1f83d9abfb41bd6bULL);
        h = vset1_epi64x(0x5be0cd19137e2179ULL);

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
    int i;

#ifdef _OPENMP
    for (i=0; i < count; i++)
#else
    for (i=0; i < VWIDTH; i++)
#endif
        if (((uint64_t *) binary)[0] == crypt_key[0][i])
            return 1;

    return 0;
}


static int cmp_one(void *binary, int index)
{
    return (((uint64_t *) binary)[0] == crypt_key[0][index]);
}


static int cmp_exact(char *source, int index)
{
    int i;
    uint64_t *bin;

    bin = (uint64_t *) get_binary(source);

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
        0,
        MAXLEN,
        SHORT_BINARY_SIZE,
        BINARY_ALIGN,
        SALT_SIZE,
        SALT_ALIGN,
        MIN_KEYS_PER_CRYPT,
        MAX_KEYS_PER_CRYPT,
        FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
        sha512_common_tests
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
