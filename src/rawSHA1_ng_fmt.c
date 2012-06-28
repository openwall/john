#if defined(__GNUC__) && defined(__SSE2__)

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <emmintrin.h>

#ifdef __SSE4_1__
# include <smmintrin.h>
#endif

#ifdef __XOP__
# include <x86intrin.h>
#endif

#include "params.h"
#include "formats.h"
#include "memory.h"
#include "sha.h"

//
// Alternative SSE2 optimised raw SHA-1 implementation for John The Ripper.
//
// This plugin requires -msse4 in CFLAGS.
//
// Copyright (C) 2012 Tavis Ormandy <taviso@cmpxchg8b.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Library General Public
// License as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Library General Public License for more details.
//
// You should have received a copy of the GNU Library General Public
// License along with this library; if not, write to the
// Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
// Boston, MA  02110-1301, USA.
//

#define SHA1_BLOCK_SIZE         64
#define SHA1_BLOCK_WORDS        16
#define SHA1_DIGEST_SIZE        20
#define SHA1_DIGEST_WORDS        5
#define SHA1_PARALLEL_HASH     512 // This must be a multiple of 4.

#define __aligned __attribute__((aligned(16)))

#ifndef __XOP__
# define _mm_slli_epi32a(a, s)                                                                          \
    ((s) == 1 ? _mm_add_epi32((a), (a)) : _mm_slli_epi32((a), (s)))
# define _mm_roti_epi32(a, s)                                                                           \
    ((s) == 16 ?                                                                                        \
    _mm_shufflelo_epi16(_mm_shufflehi_epi16((a), 0xb1), 0xb1) :                                         \
    _mm_xor_si128(_mm_slli_epi32a((a), (s)), _mm_srli_epi32((a), 32-(s))))
# define _mm_roti_epi16(a, s)                                                                           \
    _mm_xor_si128(_mm_srli_epi16((a), (s)), _mm_slli_epi16((a), 16-(s)))
#endif

#define X(X0, X2, X8, X13) do {                                                                         \
    X0  = _mm_xor_si128(X0, X8);                                                                        \
    X0  = _mm_xor_si128(X0, X13);                                                                       \
    X0  = _mm_xor_si128(X0, X2);                                                                        \
    X0  = _mm_roti_epi32(X0, 1);                                                                        \
} while (false)

#ifdef __XOP__
# define R1(W, A, B, C, D, E) do {                                                                      \
    E   = _mm_add_epi32(E, K);                                                                          \
    E   = _mm_add_epi32(E, _mm_cmov_si128(C, D, B));                                                    \
    E   = _mm_add_epi32(E, W);                                                                          \
    B   = _mm_roti_epi32(B, 30);                                                                        \
    E   = _mm_add_epi32(E, _mm_roti_epi32(A, 5));                                                       \
} while (false)
#else
# define R1(W, A, B, C, D, E) do {                                                                      \
    E   = _mm_add_epi32(E, K);                                                                          \
    E   = _mm_add_epi32(E, _mm_and_si128(C, B));                                                        \
    E   = _mm_add_epi32(E, _mm_andnot_si128(B, D));                                                     \
    E   = _mm_add_epi32(E, W);                                                                          \
    B   = _mm_roti_epi32(B, 30);                                                                        \
    E   = _mm_add_epi32(E, _mm_roti_epi32(A, 5));                                                       \
} while (false)
#endif

#define R2(W, A, B, C, D, E) do {                                                                       \
    E   = _mm_add_epi32(E, K);                                                                          \
    E   = _mm_add_epi32(E, _mm_xor_si128(_mm_xor_si128(B, C), D));                                      \
    E   = _mm_add_epi32(E, W);                                                                          \
    B   = _mm_roti_epi32(B, 30);                                                                        \
    E   = _mm_add_epi32(E, _mm_roti_epi32(A, 5));                                                       \
} while (false)

#define R3(W, A, B, C, D, E) do {                                                                       \
    E   = _mm_add_epi32(E, K);                                                                          \
    E   = _mm_add_epi32(E, _mm_or_si128(_mm_and_si128(_mm_or_si128(B, D), C), _mm_and_si128(B, D)));    \
    E   = _mm_add_epi32(E, W);                                                                          \
    B   = _mm_roti_epi32(B, 30);                                                                        \
    E   = _mm_add_epi32(E, _mm_roti_epi32(A, 5));                                                       \
} while (false)

#define _MM_TRANSPOSE4_EPI32(R0, R1, R2, R3) do {                                                       \
    __m128i T0, T1, T2, T3;                                                                             \
    T0  = _mm_unpacklo_epi32(R0, R1);                                                                   \
    T1  = _mm_unpacklo_epi32(R2, R3);                                                                   \
    T2  = _mm_unpackhi_epi32(R0, R1);                                                                   \
    T3  = _mm_unpackhi_epi32(R2, R3);                                                                   \
    R0  = _mm_unpacklo_epi64(T0, T1);                                                                   \
    R1  = _mm_unpackhi_epi64(T0, T1);                                                                   \
    R2  = _mm_unpacklo_epi64(T2, T3);                                                                   \
    R3  = _mm_unpackhi_epi64(T2, T3);                                                                   \
} while (false)

// Disable type checking for SIMD load and store operations.
#define _mm_load_si128(x) _mm_load_si128((void *)(x))
#define _mm_loadu_si128(x) _mm_loadu_si128((void *)(x))
#define _mm_store_si128(x, y) _mm_store_si128((void *)(x), (y))

#if (!defined(__INTEL_COMPILER) && defined(__GNUC__)) && \
	(__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4))
#pragma GCC optimize 3
#endif

// M and N contain the first and last 128bits of a 512bit SHA-1 message block
// respectively. The remaining 256bits are always zero, and so are not stored
// here to avoid the load overhead.
static uint32_t __aligned M[SHA1_PARALLEL_HASH][4];
static uint32_t __aligned N[SHA1_PARALLEL_HASH][4];

// MD contains the state of the SHA-1 A register at R75 for each of the input
// messages.
static uint32_t __aligned MD[SHA1_PARALLEL_HASH];

static const char kFormatTag[] = "$dynamic_26$";

static struct fmt_tests sha1_fmt_tests[] = {
    { "da39a3ee5e6b4b0d3255bfef95601890afd80709", ""                },
    { "AC80BAA235B7FB7BDFC593A976D40B24B851F924", "CAPSLOCK"        },
    { "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a"               },
    { "da23614e02469a0d7c7bd1bdab5c9c474b1904dc", "ab"              },
    { "a9993e364706816aba3e25717850c26c9cd0d89d", "abc"             },
    { "81fe8bfe87576c3ecb22426f8e57847382917acf", "abcd"            },
    { "03de6c570bfe24bfc328ccd7ca46b76eadaf4334", "abcde"           },
    { "1f8ac10f23c5b5bc1167bda84b833e5c057a77d2", "abcdef"          },
    { "2fb5e13419fc89246865e7a324f476ec624e8740", "abcdefg"         },
    { "425af12a0743502b322e93a015bcf868e324d56a", "abcdefgh"        },
    { "c63b19f1e4c8b5f76b25c49b8b87f57d8e4872a1", "abcdefghi"       },
    { "d68c19a0a345b7eab78d5e11e991c026ec60db63", "abcdefghij"      },
    { "5dfac39f71ad4d35a153ba4fc12d943a0e178e6a", "abcdefghijk"     },
    { "eb4608cebfcfd4df81410cbd06507ea6af978d9c", "abcdefghijkl"    },
    { "4b9892b6527214afc655b8aa52f4d203c15e7c9c", "abcdefghijklm"   },
    { "85d7c5ff403abe72df5b8a2708821ee33cd0bcce", "abcdefghijklmn"  },
    { "2938dcc2e3aa77987c7e5d4a0f26966706d06782", "abcdefghijklmno" },
    { "f8252c7b6035a71242b4047782247faabfccb47b", "taviso"          },
    { "b47f363e2b430c0647f14deea3eced9b0ef300ce", "is"              },
    { "03d67c263c27a453ef65b29e30334727333ccbcd", "awesome"         },
    { "7a73673e78669ea238ca550814dca7000d7026cc", "!!!!1111eleven"  },
    { NULL, NULL }
};

static inline uint32_t __attribute__((const)) rotateright(uint32_t value, uint8_t count)
{
    register uint32_t result;

    asm("ror    %%cl, %0"
        : "=r" (result)
        : "0"  (value),
          "c"  (count));

    return result;
}

static inline uint32_t __attribute__((const)) rotateleft(uint32_t value, uint8_t count)
{
    register uint32_t result;

    asm("rol    %%cl, %0"
        : "=r" (result)
        : "0"  (value),
          "c"  (count));

    return result;
}

// GCC < 4.3 does not have __builtin_bswap32(), provide an alternative.
#if !defined(__INTEL_COMPILER) && GCC_VERSION < 40300
# define __builtin_bswap32(x) bswap32(x)
static inline uint32_t __attribute__((const)) bswap32(uint32_t value)
{
    register uint32_t result;

    asm("bswap %0" : "=r" (result) : "0" (value));

    return result;
}
#endif


static int sha1_fmt_valid(char *ciphertext, struct fmt_main *format)
{
    // Test for tag prefix in ciphertext.
    if (!strncmp(ciphertext, kFormatTag, strlen(kFormatTag)))
        ciphertext += strlen(kFormatTag);

    // Verify this only contains hex digits.
    if (strspn(ciphertext, "0123456789aAbBcCdDeEfF") != SHA1_DIGEST_SIZE * 2)
        return 0;

    // Verify the length matches.
    return strlen(ciphertext) == SHA1_DIGEST_SIZE * 2;
}

static void * sha1_fmt_binary(char *ciphertext)
{
    static char byte[3];
    uint8_t    *binary;

    // Static buffer storing the binary representation of ciphertext.
    static uint32_t result[SHA1_DIGEST_WORDS];

    // Skip over tag.
    ciphertext  += strlen(kFormatTag);
    binary       = (void *)(result);

    // Convert ascii representation into binary. This routine is not hot, so
    // it's okay to keep this simple. We copy two digits out of ciphertext at a
    // time, which can be stored in one byte.
    for (; *ciphertext; ciphertext += 2, binary += 1) {
        *binary = strtoul(memcpy(byte, ciphertext, 2), NULL, 16);
    }

    // Now subtract the SHA-1 IV, returning this hash to the R80 state. This
    // means we save 4 SIMD additions for every crypt(), because we don't have
    // to do it there.
    result[0] = __builtin_bswap32(result[0]) - 0x67452301;
    result[1] = __builtin_bswap32(result[1]) - 0xEFCDAB89;
    result[2] = __builtin_bswap32(result[2]) - 0x98BADCFE;
    result[3] = __builtin_bswap32(result[3]) - 0x10325476;

    // One additional preprocessing step, if we calculate E80 rol 2 here, we
    // can compare it against A75 and save 5 rounds.
    result[4] = rotateleft(__builtin_bswap32(result[4]) - 0xC3D2E1F0, 2);

    return result;
}

static char *sha1_fmt_split(char *ciphertext, int index)
{
    static char result[sizeof(kFormatTag) + SHA1_DIGEST_SIZE * 2];

    // Test for tag prefix already present in ciphertext.
    if (strncmp(ciphertext, kFormatTag, strlen(kFormatTag)) == 0)
        ciphertext += strlen(kFormatTag);

    // Add the hash.
    strnzcpy(result, kFormatTag, sizeof result);
    strnzcat(result, ciphertext, sizeof result);

    // Return lowercase result.
    return strlwr(result);
}

// This function is called when John wants us to buffer a crypt() operation
// on the specified key. We also preprocess it for SHA-1 as we load it.
//
// This implementation is hardcoded to only accept passwords under 15
// characters. This is because we can create a new message block in just two
// MOVDQA instructions (we need 15 instead of 16 because we must append a bit
// to the message).
//
// This routine assumes that key is not on an unmapped page boundary, but
// doesn't require it to be 16 byte aligned (although that would be nice).
static void sha1_fmt_set_key(char *key, int index)
{
    __m128i  Z   = _mm_setzero_si128();
    __m128i  X   = _mm_loadu_si128(key);
    __m128i  B;
    uint32_t len = _mm_movemask_epi8(_mm_cmpeq_epi8(X, Z));

    // Create a lookup tables to find correct masks for each supported input
    // length. It would be nice if could use 128 bit shifts to produce these
    // dynamically, but they require an immediate operand.
    static const __aligned uint32_t kTrailingBitTable[][4] = {
        { 0x00000080, 0x00000000, 0x00000000, 0x00000000 },
        { 0x00008000, 0x00000000, 0x00000000, 0x00000000 },
        { 0x00800000, 0x00000000, 0x00000000, 0x00000000 },
        { 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
        { 0x00000000, 0x00000080, 0x00000000, 0x00000000 },
        { 0x00000000, 0x00008000, 0x00000000, 0x00000000 },
        { 0x00000000, 0x00800000, 0x00000000, 0x00000000 },
        { 0x00000000, 0x80000000, 0x00000000, 0x00000000 },
        { 0x00000000, 0x00000000, 0x00000080, 0x00000000 },
        { 0x00000000, 0x00000000, 0x00008000, 0x00000000 },
        { 0x00000000, 0x00000000, 0x00800000, 0x00000000 },
        { 0x00000000, 0x00000000, 0x80000000, 0x00000000 },
        { 0x00000000, 0x00000000, 0x00000000, 0x00000080 },
        { 0x00000000, 0x00000000, 0x00000000, 0x00008000 },
        { 0x00000000, 0x00000000, 0x00000000, 0x00800000 },
        { 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
    };

    static const __aligned uint32_t kUsedBytesTable[][4] = {
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x00000000, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x00000000, 0x00000000, 0xFFFFFF00, 0xFFFFFFFF },
        { 0x00000000, 0x00000000, 0xFFFF0000, 0xFFFFFFFF },
        { 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF },
        { 0x00000000, 0x00000000, 0x00000000, 0xFFFFFF00 },
        { 0x00000000, 0x00000000, 0x00000000, 0xFFFF0000 },
        { 0x00000000, 0x00000000, 0x00000000, 0xFF000000 },
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
    };

    // First, find the length of the key by scanning for a zero byte.
    len = __builtin_ctz(len);

    // Zero out the rest of the DQWORD in X by making a suitable mask.
    Z = _mm_load_si128(kUsedBytesTable[len]);

    // Find the correct position for the trailing bit required by SHA-1.
    B = _mm_load_si128(kTrailingBitTable[len]);

    // Now we have this:
    // B = 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00
    // Z = 00 00 00 00 00 ff ff ff ff ff ff ff ff ff ff
    // X = 41 41 41 41 41 00 12 34 56 78 12 34 56 78 9A
    //     <---------------> <------------------------>
    //      key bytes w/nul       junk from stack.

    // Use PANDN to apply the mask, then POR to append the trailing bit
    // required by SHA-1, which leaves us with this:
    // X = 41 41 41 41 41 80 00 00 00 00 00 00 00 00 00
    X = _mm_or_si128(_mm_andnot_si128(Z, X), B);

    // SHA-1 requires us to byte swap all the 32bit words in the message, which
    // we do here.
    //  X = 40 41 42 44 45 80 00 00 00 00 00 00 00 00 00    // What we have.
    //  X = 44 42 41 40 00 00 80 45 00 00 00 00 00 00 00    // What we want.
    X = _mm_roti_epi32(X, 16);
    X = _mm_roti_epi16(X, 8);

    // Store the result and it's length into the message buffer, we need the
    // length in bits because SHA-1 requires the length be part of the final
    // message block (or only message block, in this case). The << 3 is to find
    // the length in bits (multiply by 8).
    _mm_store_si128(&M[index], X);
    _mm_store_si128(&N[index], _mm_set_epi32(len << 3, 0, 0, 0));

    return;
}

static char * sha1_fmt_get_key(int index)
{
    static uint32_t key[5];

    // This function is not hot, we can do this slowly. First, restore
    // endianness.
    key[0] = __builtin_bswap32(M[index][0]);
    key[1] = __builtin_bswap32(M[index][1]);
    key[2] = __builtin_bswap32(M[index][2]);
    key[3] = __builtin_bswap32(M[index][3]);

    // Skip backwards until we hit the trailing bit, then remove it.
    memset(strrchr((char *)(key), 0x80), 0x00, 1);

    return (char *) key;
}

static void sha1_fmt_crypt_all(int count)
{
    __m128i W[SHA1_BLOCK_WORDS];
    __m128i A, B, C, D, E;
    __m128i K;
    int32_t i;

    // To reduce the overhead of multiple function calls, we buffer lots of
    // passwords, and then hash them in multiples of 4 all at once.
    for (i = 0; i < count; i += 4) {
        // Fetch the message, then use a 4x4 matrix transpose to shuffle them
        // into place.
        W[0]  = _mm_load_si128(&M[i + 0]);
        W[1]  = _mm_load_si128(&M[i + 1]);
        W[2]  = _mm_load_si128(&M[i + 2]);
        W[3]  = _mm_load_si128(&M[i + 3]);

        _MM_TRANSPOSE4_EPI32(W[0],  W[1],  W[2],  W[3]);

        A = _mm_set1_epi32(0x67452301);
        B = _mm_set1_epi32(0xEFCDAB89);
        C = _mm_set1_epi32(0x98BADCFE);
        D = _mm_set1_epi32(0x10325476);
        E = _mm_set1_epi32(0xC3D2E1F0);
        K = _mm_set1_epi32(0x5A827999);

        R1(W[0],  A, B, C, D, E);
        R1(W[1],  E, A, B, C, D);
        R1(W[2],  D, E, A, B, C);
        R1(W[3],  C, D, E, A, B); W[4]  = _mm_setzero_si128();
        R1(W[4],  B, C, D, E, A); W[5]  = _mm_setzero_si128();
        R1(W[5],  A, B, C, D, E); W[6]  = _mm_setzero_si128();      // 5
        R1(W[6],  E, A, B, C, D); W[7]  = _mm_setzero_si128();
        R1(W[7],  D, E, A, B, C); W[8]  = _mm_setzero_si128();
        R1(W[8],  C, D, E, A, B); W[9]  = _mm_setzero_si128();
        R1(W[9],  B, C, D, E, A); W[10] = _mm_setzero_si128();
        R1(W[10], A, B, C, D, E); W[11] = _mm_setzero_si128();      // 10

        // Fetch the message lengths, we can use a 4x4 matrix transpose to
        // shuffle the words into the correct position.
        W[12] = _mm_load_si128(&N[i + 0]);
        W[13] = _mm_load_si128(&N[i + 1]);
        W[14] = _mm_load_si128(&N[i + 2]);
        W[15] = _mm_load_si128(&N[i + 3]);

        _MM_TRANSPOSE4_EPI32(W[12], W[13], W[14], W[15]);

        R1(W[11], E, A, B, C, D);
        R1(W[12], D, E, A, B, C);
        R1(W[13], C, D, E, A, B);
        R1(W[14], B, C, D, E, A);
        R1(W[15], A, B, C, D, E);                                   // 15

        X(W[0],  W[2],  W[8],  W[13]);  R1(W[0],  E, A, B, C, D);
        X(W[1],  W[3],  W[9],  W[14]);  R1(W[1],  D, E, A, B, C);
        X(W[2],  W[4],  W[10], W[15]);  R1(W[2],  C, D, E, A, B);
        X(W[3],  W[5],  W[11], W[0]);   R1(W[3],  B, C, D, E, A);

        K = _mm_set1_epi32(0x6ED9EBA1);

        X(W[4],  W[6],  W[12], W[1]);   R2(W[4],  A, B, C, D, E);   // 20
        X(W[5],  W[7],  W[13], W[2]);   R2(W[5],  E, A, B, C, D);
        X(W[6],  W[8],  W[14], W[3]);   R2(W[6],  D, E, A, B, C);
        X(W[7],  W[9],  W[15], W[4]);   R2(W[7],  C, D, E, A, B);
        X(W[8],  W[10], W[0],  W[5]);   R2(W[8],  B, C, D, E, A);
        X(W[9],  W[11], W[1],  W[6]);   R2(W[9],  A, B, C, D, E);   // 25
        X(W[10], W[12], W[2],  W[7]);   R2(W[10], E, A, B, C, D);
        X(W[11], W[13], W[3],  W[8]);   R2(W[11], D, E, A, B, C);
        X(W[12], W[14], W[4],  W[9]);   R2(W[12], C, D, E, A, B);
        X(W[13], W[15], W[5],  W[10]);  R2(W[13], B, C, D, E, A);
        X(W[14], W[0],  W[6],  W[11]);  R2(W[14], A, B, C, D, E);   // 30
        X(W[15], W[1],  W[7],  W[12]);  R2(W[15], E, A, B, C, D);
        X(W[0],  W[2],  W[8],  W[13]);  R2(W[0],  D, E, A, B, C);
        X(W[1],  W[3],  W[9],  W[14]);  R2(W[1],  C, D, E, A, B);
        X(W[2],  W[4],  W[10], W[15]);  R2(W[2],  B, C, D, E, A);
        X(W[3],  W[5],  W[11], W[0]);   R2(W[3],  A, B, C, D, E);   // 35
        X(W[4],  W[6],  W[12], W[1]);   R2(W[4],  E, A, B, C, D);
        X(W[5],  W[7],  W[13], W[2]);   R2(W[5],  D, E, A, B, C);
        X(W[6],  W[8],  W[14], W[3]);   R2(W[6],  C, D, E, A, B);
        X(W[7],  W[9],  W[15], W[4]);   R2(W[7],  B, C, D, E, A);

        K = _mm_set1_epi32(0x8F1BBCDC);

        X(W[8],  W[10], W[0],  W[5]);   R3(W[8],  A, B, C, D, E);   // 40
        X(W[9],  W[11], W[1],  W[6]);   R3(W[9],  E, A, B, C, D);
        X(W[10], W[12], W[2],  W[7]);   R3(W[10], D, E, A, B, C);
        X(W[11], W[13], W[3],  W[8]);   R3(W[11], C, D, E, A, B);
        X(W[12], W[14], W[4],  W[9]);   R3(W[12], B, C, D, E, A);
        X(W[13], W[15], W[5],  W[10]);  R3(W[13], A, B, C, D, E);   // 45
        X(W[14], W[0],  W[6],  W[11]);  R3(W[14], E, A, B, C, D);
        X(W[15], W[1],  W[7],  W[12]);  R3(W[15], D, E, A, B, C);
        X(W[0],  W[2],  W[8],  W[13]);  R3(W[0],  C, D, E, A, B);
        X(W[1],  W[3],  W[9],  W[14]);  R3(W[1],  B, C, D, E, A);
        X(W[2],  W[4],  W[10], W[15]);  R3(W[2],  A, B, C, D, E);   // 50
        X(W[3],  W[5],  W[11], W[0]);   R3(W[3],  E, A, B, C, D);
        X(W[4],  W[6],  W[12], W[1]);   R3(W[4],  D, E, A, B, C);
        X(W[5],  W[7],  W[13], W[2]);   R3(W[5],  C, D, E, A, B);
        X(W[6],  W[8],  W[14], W[3]);   R3(W[6],  B, C, D, E, A);
        X(W[7],  W[9],  W[15], W[4]);   R3(W[7],  A, B, C, D, E);   // 55
        X(W[8],  W[10], W[0],  W[5]);   R3(W[8],  E, A, B, C, D);
        X(W[9],  W[11], W[1],  W[6]);   R3(W[9],  D, E, A, B, C);
        X(W[10], W[12], W[2],  W[7]);   R3(W[10], C, D, E, A, B);
        X(W[11], W[13], W[3],  W[8]);   R3(W[11], B, C, D, E, A);

        K = _mm_set1_epi32(0xCA62C1D6);

        X(W[12], W[14], W[4],  W[9]);   R2(W[12], A, B, C, D, E);   // 60
        X(W[13], W[15], W[5],  W[10]);  R2(W[13], E, A, B, C, D);
        X(W[14], W[0],  W[6],  W[11]);  R2(W[14], D, E, A, B, C);
        X(W[15], W[1],  W[7],  W[12]);  R2(W[15], C, D, E, A, B);
        X(W[0],  W[2],  W[8],  W[13]);  R2(W[0],  B, C, D, E, A);
        X(W[1],  W[3],  W[9],  W[14]);  R2(W[1],  A, B, C, D, E);   // 65
        X(W[2],  W[4],  W[10], W[15]);  R2(W[2],  E, A, B, C, D);
        X(W[3],  W[5],  W[11], W[0]);   R2(W[3],  D, E, A, B, C);
        X(W[4],  W[6],  W[12], W[1]);   R2(W[4],  C, D, E, A, B);
        X(W[5],  W[7],  W[13], W[2]);   R2(W[5],  B, C, D, E, A);
        X(W[6],  W[8],  W[14], W[3]);   R2(W[6],  A, B, C, D, E);   // 70
        X(W[7],  W[9],  W[15], W[4]);   R2(W[7],  E, A, B, C, D);
        X(W[8],  W[10], W[0],  W[5]);   R2(W[8],  D, E, A, B, C);
        X(W[9],  W[11], W[1],  W[6]);   R2(W[9],  C, D, E, A, B);
        X(W[10], W[12], W[2],  W[7]);   R2(W[10], B, C, D, E, A);
        X(W[11], W[13], W[3],  W[8]);   R2(W[11], A, B, C, D, E);   // 75

        // A75 has an interesting property, it is the first word that is (almost)
        // part of the final MD (E79 ror 2). The common case will be that this
        // doesn't match, so we stop here and save 5 rounds.
        //
        // Note that I'm using E due to the displacement caused by vectorization,
        // this is A in standard SHA-1.
        _mm_store_si128(&MD[i], E);
    }
    return;
}

#if defined(__SSE4_1__)

# if !defined(__INTEL_COMPILER)
// This intrinsic is not always available in GCC, so define it here.
static inline int _mm_testz_si128 (__m128i __M, __m128i __V)
{
    return __builtin_ia32_ptestz128 ((__v2di)__M, (__v2di)__V);
}
# endif

// This is a modified SSE2 port of Algorithm 6-2 from "Hackers Delight" by
// Henry Warren, ISBN 0-201-91465-4. Returns non-zero if any double word in X
// is zero using a branchless algorithm. -- taviso.
static inline int _mm_testz_epi32 (__m128i __X)
{
    __m128i M = _mm_cmpeq_epi32(__X, __X);
    __m128i Z = _mm_srli_epi32(M, 1);
    __m128i Y = _mm_andnot_si128(_mm_or_si128(_mm_or_si128(_mm_add_epi32(_mm_and_si128(__X, Z), Z), __X), Z), M);
    return ! _mm_testz_si128(Y, M);
}

#else
# warning not using optimized sse4.1 compare because -msse4 was not specified
static inline int _mm_testz_epi32 (__m128i __X)
{
    uint32_t __aligned words[4];
    _mm_store_si128(words, __X);
    return !words[0] || !words[1] || !words[2] || !words[3];
}
#endif

static int sha1_fmt_cmp_all(void *binary, int count)
{
    int32_t *input  = binary;
    int32_t  result = 0;
    int32_t  i;
    __m128i  B;

    // This function is hot, we need to do this quickly. We use PCMP to find
    // out if any of the dwords in A75 matched E in the input hash.
    // First, Load the target hash into an XMM register
    // B = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
    B = _mm_loadu_si128(&input[1]);

    // We only test the final dword here, so duplicate it.
    // B = cc dd ee ff cc dd ee ff cc dd ee ff cc dd ee ff
    B = _mm_shuffle_epi32(B, _MM_SHUFFLE(3, 3, 3, 3));

    // We can test these 4 at a time, and we may have many to test. As the
    // common case will be that there is _no_ match, we don't test it after
    // every compare, reducing the number of branches.
    //
    // This might seem counterintuitive, because if there is a match we could
    // of finished early, but saving a branch for the common case is a better
    // choice.
    for (i = 0; i < count; i += 4) {
        __m128i A = _mm_cmpeq_epi32(B, _mm_load_si128(&MD[i]));

        // We can actually check for any hits using a branchless algorithm.
        result |= _mm_testz_epi32(_mm_andnot_si128(A, _mm_cmpeq_epi32(A, A)));
    }

    return result;
}

static inline int sha1_fmt_get_hash(int index)
{
    return MD[index];
}

static int sha1_fmt_get_hash0(int index) { return sha1_fmt_get_hash(index) & 0x0000000F; }
static int sha1_fmt_get_hash1(int index) { return sha1_fmt_get_hash(index) & 0x000000FF; }
static int sha1_fmt_get_hash2(int index) { return sha1_fmt_get_hash(index) & 0x00000FFF; }
static int sha1_fmt_get_hash3(int index) { return sha1_fmt_get_hash(index) & 0x0000FFFF; }
static int sha1_fmt_get_hash4(int index) { return sha1_fmt_get_hash(index) & 0x000FFFFF; }
static int sha1_fmt_get_hash5(int index) { return sha1_fmt_get_hash(index) & 0x00FFFFFF; }
static int sha1_fmt_get_hash6(int index) { return sha1_fmt_get_hash(index) & 0x07FFFFFF; }

static inline int sha1_fmt_get_binary(void *binary)
{
    return ((uint32_t *)(binary))[4];
}

static int sha1_fmt_binary0(void *binary) { return sha1_fmt_get_binary(binary) & 0x0000000F; }
static int sha1_fmt_binary1(void *binary) { return sha1_fmt_get_binary(binary) & 0x000000FF; }
static int sha1_fmt_binary2(void *binary) { return sha1_fmt_get_binary(binary) & 0x00000FFF; }
static int sha1_fmt_binary3(void *binary) { return sha1_fmt_get_binary(binary) & 0x0000FFFF; }
static int sha1_fmt_binary4(void *binary) { return sha1_fmt_get_binary(binary) & 0x000FFFFF; }
static int sha1_fmt_binary5(void *binary) { return sha1_fmt_get_binary(binary) & 0x00FFFFFF; }
static int sha1_fmt_binary6(void *binary) { return sha1_fmt_get_binary(binary) & 0x07FFFFFF; }

static int sha1_fmt_cmp_one(void *binary, int index)
{
    // We can quickly check if it will be worth doing a full comparison here,
    // this lets us turn up SHA1_PARALLEL_HASH without too much overhead when a
    // partial match occurs.
    return sha1_fmt_get_binary(binary) == sha1_fmt_get_hash(index);
}

// This function is not hot, and will only be called for around 1:2^32 random
// crypts. Use a real SHA-1 implementation to verify the result exactly. This
// routine is only called by John when cmp_one succeeds.
static int sha1_fmt_cmp_exact(char *source, int index)
{
    uint32_t full_sha1_digest[SHA1_DIGEST_WORDS];
    SHA_CTX ctx;
    char *key;

    // Fetch the original input to hash.
    key = sha1_fmt_get_key(index);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, key, strlen(key));
    SHA1_Final((unsigned char *)(full_sha1_digest), &ctx);

    // Remove IV to match the format I generate in binary().
    full_sha1_digest[0] = __builtin_bswap32(full_sha1_digest[0]) - 0x67452301;
    full_sha1_digest[1] = __builtin_bswap32(full_sha1_digest[1]) - 0xEFCDAB89;
    full_sha1_digest[2] = __builtin_bswap32(full_sha1_digest[2]) - 0x98BADCFE;
    full_sha1_digest[3] = __builtin_bswap32(full_sha1_digest[3]) - 0x10325476;
    full_sha1_digest[4] = rotateleft(__builtin_bswap32(full_sha1_digest[4]) - 0xC3D2E1F0, 2);

    // Compare result.
    return memcmp(sha1_fmt_binary(source), full_sha1_digest, sizeof full_sha1_digest) == 0;
}

struct fmt_main sha1_fmt_ng = {
    .params                 = {
        .label              = "raw-sha1-ng",
        .format_name        = "Raw SHA-1 (pwlen <= 15)",
        .algorithm_name     = "128/128 "
#if defined(__XOP__)
    "XOP"
#elif defined(__AVX__)
    "AVX"
#elif defined(__SSE4_1__)
    "SSE4.1"
#else
    "SSE2"
#endif
    " intrinsics 4x",
        .benchmark_comment  = "",
        .benchmark_length   = -1,
        .plaintext_length   = sizeof(__m128i) - 1,
        .binary_size        = SHA1_DIGEST_SIZE,
        .salt_size          = 0,
        .min_keys_per_crypt = 4,
        .max_keys_per_crypt = SHA1_PARALLEL_HASH,
        .flags              = FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
        .tests              = sha1_fmt_tests,
    },
    .methods                = {
        .init               = fmt_default_init,
        .prepare            = fmt_default_prepare,
        .valid              = sha1_fmt_valid,
        .split              = sha1_fmt_split,
        .binary             = sha1_fmt_binary,
        .salt               = fmt_default_salt,
        .salt_hash          = fmt_default_salt_hash,
        .set_salt           = fmt_default_set_salt,
        .set_key            = sha1_fmt_set_key,
        .get_key            = sha1_fmt_get_key,
        .clear_keys         = fmt_default_clear_keys,
        .crypt_all          = sha1_fmt_crypt_all,
        .get_hash           = {
            [0] = sha1_fmt_get_hash0,
            [1] = sha1_fmt_get_hash1,
            [2] = sha1_fmt_get_hash2,
            [3] = sha1_fmt_get_hash3,
            [4] = sha1_fmt_get_hash4,
            [5] = sha1_fmt_get_hash5,
            [6] = sha1_fmt_get_hash6,
        },
        .binary_hash        = {
            [0] = sha1_fmt_binary0,
            [1] = sha1_fmt_binary1,
            [2] = sha1_fmt_binary2,
            [3] = sha1_fmt_binary3,
            [4] = sha1_fmt_binary4,
            [5] = sha1_fmt_binary5,
            [6] = sha1_fmt_binary6,
        },
        .cmp_all            = sha1_fmt_cmp_all,
        .cmp_one            = sha1_fmt_cmp_one,
        .cmp_exact          = sha1_fmt_cmp_exact,
    },
};

#endif // __GNUC__
