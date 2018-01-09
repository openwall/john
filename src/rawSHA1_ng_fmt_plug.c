//
// Alternative SSE2 optimised raw SHA-1 implementation for John The Ripper.
//
// This plugin requires -msse4 in CFLAGS.
//
// Copyright (C) 2012 Tavis Ormandy <taviso@cmpxchg8b.com>
// Copyright (c) 2015 magnum (AVX2/AVX512 support)
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

#include "arch.h"
#if defined(SIMD_COEF_32) && (SIMD_COEF_32 < 16 || ARCH_BITS >= 64) && !_MSC_VER && !__ARM_NEON && ARCH_LITTLE_ENDIAN==1

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sha1_ng;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sha1_ng);
#else

#include "misc.h"
#if !defined(DEBUG) && !defined(WITH_ASAN)
// These compilers claim to be __GNUC__ but warn on gcc pragmas.
#if __GNUC__ && !__INTEL_COMPILER && !__clang__ && !__llvm__ && !_MSC_VER
#pragma GCC optimize 3
#pragma GCC optimize "-fprefetch-loop-arrays"
#endif
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <string.h>
#include <stdint.h>

#if !FAST_FORMATS_OMP
#undef _OPENMP
#elif _OPENMP
#include <omp.h>
#endif

#include "stdbool.h"
#if SIMD_COEF_32 > 8
#include "int128.h"
#endif
#include "pseudo_intrinsics.h"
#include "params.h"
#include "formats.h"
#include "memory.h"
#include "sha.h"
#include "johnswap.h"
#include "aligned.h"
#include "rawSHA1_common.h"
#include "memdbg.h"

#define VWIDTH SIMD_COEF_32

#define SHA1_BLOCK_WORDS        16
#define SHA1_DIGEST_WORDS        5
#define SHA1_PARALLEL_HASH       (SIMD_COEF_32 * 32)

#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE              512
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE             8192 // Tuned w/ MKPC for core i7
#endif
#endif

#define X(X0, X2, X8, X13) do {                 \
        X0  = vxor(X0, X8);                     \
        X0  = vxor(X0, X13);                    \
        X0  = vxor(X0, X2);                     \
        X0  = vroti_epi32(X0, 1);               \
    } while (false)

#define R1(W, A, B, C, D, E) do {               \
        E   = vadd_epi32(E, K);                 \
        E   = vadd_epi32(E, vcmov(C, D, B));    \
        E   = vadd_epi32(E, W);                 \
        B   = vroti_epi32(B, 30);               \
        E   = vadd_epi32(E, vroti_epi32(A, 5)); \
    } while (false)

#define R2(W, A, B, C, D, E) do {                   \
        E   = vadd_epi32(E, K);                     \
        E   = vadd_epi32(E, vxor(vxor(B, C), D));   \
        E   = vadd_epi32(E, W);                     \
        B   = vroti_epi32(B, 30);                   \
        E   = vadd_epi32(E, vroti_epi32(A, 5));     \
    } while (false)

#define R4(W, A, B, C, D, E) do {                   \
        E   = vadd_epi32(E, K);                     \
        E   = vadd_epi32(E, vxor(vxor(B, C), D));   \
        E   = vadd_epi32(E, W);                     \
        E   = vadd_epi32(E, vroti_epi32(A, 5));     \
    } while (false)

#if !VCMOV_EMULATED
#define R3(W, A, B, C, D, E) do {                                   \
        E   = vadd_epi32(E, K);                                     \
        E   = vadd_epi32(E, vcmov(D, B, vxor(C, B)));               \
        E   = vadd_epi32(E, W);                                     \
        B   = vroti_epi32(B, 30);                                   \
        E   = vadd_epi32(E, vroti_epi32(A, 5));                     \
    } while (false)
#else
#define R3(W, A, B, C, D, E) do {                                   \
        E   = vadd_epi32(E, K);                                     \
        E   = vadd_epi32(E, vor(vand(D, B), vand(vor(D, B), C)));   \
        E   = vadd_epi32(E, W);                                     \
        B   = vroti_epi32(B, 30);                                   \
        E   = vadd_epi32(E, vroti_epi32(A, 5));                     \
    } while (false)
#endif

#if SIMD_COEF_32 == 4
// Not used for AVX2 and better, which has gather instructions.
#define _MM_TRANSPOSE4_EPI32(R0, R1, R2, R3) do {\
    vtype T0, T1, T2, T3;                        \
    T0  = vunpacklo_epi32(R0, R1);               \
    T1  = vunpacklo_epi32(R2, R3);               \
    T2  = vunpackhi_epi32(R0, R1);               \
    T3  = vunpackhi_epi32(R2, R3);               \
    R0  = vunpacklo_epi64(T0, T1);               \
    R1  = vunpackhi_epi64(T0, T1);               \
    R2  = vunpacklo_epi64(T2, T3);               \
    R3  = vunpackhi_epi64(T2, T3);               \
} while (false)
#endif

// M and N contain the first and last 128bits of a 512bit SHA-1 message block
// respectively. The remaining 256bits are always zero, and so are not stored
// here to avoid the load overhead.
// For AVX2, we have half a block and for AVX512/MIC we actually have a full
// block.
static uint32_t (*M)[VWIDTH];
static uint32_t *N;

// MD contains the state of the SHA-1 A register at R75 for each of the input
// messages.
static uint32_t *MD;

/* unused
inline static uint32_t __attribute__((const)) rotateright(uint32_t value, uint8_t count)
{
	register uint32_t result;

	asm("ror    %%cl, %0"
	    : "=r" (result)
	    : "0"  (value),
	      "c"  (count));

	return result;
}
*/

inline static uint32_t __attribute__((const)) rotateleft(uint32_t value, uint8_t count)
{
	register uint32_t result;
#if (__MINGW32__ || __MINGW64__) && __STRICT_ANSI__
	result = _rotl(value, count); //((value<<count)|((uint32_t)value>>(32-count)));
#elif __i386__ || __x86_64__
	asm("rol    %%cl, %0"
	    : "=r" (result)
	    : "0"  (value),
	      "c"  (count));
#else
	// assume count <= 32
	result = (value << count) | (value >> (32 - count));
#endif
	return result;
}

// GCC < 4.3 does not have __builtin_bswap32(), provide an alternative.
#if !__INTEL_COMPILER && GCC_VERSION < 40300
#define __builtin_bswap32 bswap32
inline static uint32_t __attribute__((const)) bswap32(uint32_t value)
{
	register uint32_t result;
#if (__MINGW32__ || __MINGW64__) && __STRICT_ANSI__
	result = _byteswap_ulong(value);
#elif __i386 || __x86_64__
	asm("bswap %0"
		: "=r" (result)
		: "0" (value));
#else
	result = (value << 24) | ((value << 8) & 0xFF0000) | (value >> 24) | ((value >> 8) & 0xFF00);
#endif
	return result;
}
#endif


static void sha1_fmt_init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	M   = mem_calloc_align(self->params.max_keys_per_crypt, sizeof(*M),
	                       MEM_ALIGN_CACHE);
	N   = mem_calloc_align(self->params.max_keys_per_crypt, sizeof(*N),
	                       MEM_ALIGN_CACHE);
	MD  = mem_calloc_align(self->params.max_keys_per_crypt, sizeof(*MD),
	                       MEM_ALIGN_CACHE);
}


static void done(void)
{
	MEM_FREE(MD);
	MEM_FREE(N);
	MEM_FREE(M);
}

static void *sha1_fmt_binary(char *ciphertext)
{
	// Static buffer storing the binary representation of ciphertext.
	static union {
		uint32_t w[SHA1_DIGEST_WORDS];
		vtype v;
	} result;
	uint32_t a75;

	// Convert ascii representation into binary.
	memcpy(result.w, rawsha1_common_get_binary(ciphertext), 20);

	// One preprocessing step, if we calculate E80 rol 2 here, we
	// can compare it against A75 and save 5 rounds in crypt_all().
	a75 = rotateleft(__builtin_bswap32(result.w[4]) - 0xC3D2E1F0, 2);

	// Fill the vector with it, so we can do a vectorized compare
	result.v = vset1_epi32(a75);

	return result.w;
}

// This function is called when John wants us to buffer a crypt() operation
// on the specified key. We also preprocess it for SHA-1 as we load it.
//
// This implementation is hardcoded to only accept passwords under 15
// characters. This is because we can create a new message block in just two
// MOVDQA instructions (we need 15 instead of 16 because we must append a bit
// to the message). For AVX2 it's 31 characters and for AVX-512+ it's 125.
//
// This routine assumes that key is not on an unmapped page boundary, but
// doesn't require it to be 16 byte aligned (although that would be nice).
static void sha1_fmt_set_key(char *key, int index)
{
	vtype  Z   = vsetzero();
	vtype  X   = vloadu(key);
	vtype  B;

	// First, find the length of the key by scanning for a zero byte.
#if (__AVX512F__ && !__AVX512BW__) || __MIC__ || __ALTIVEC__ || __ARM_NEON
	uint32_t len = strlen(key);
#else
	// FIXME: even uint64_t won't be long enough for AVX-1024
	uint64_t mask = vcmpeq_epi8_mask(X, Z);
	uint32_t len = __builtin_ctzl(mask);
#endif

	// Create a lookup tables to find correct masks for each supported input
	// length. It would be nice if we could use bit shifts to produce these
	// dynamically, but they require an immediate operand.
#if VWIDTH > 8
	// FIXME: a problem with using int128 here is it won't work at
	// all for 32-bit builds - but that may be academic.
#define XX ((((uint128_t)0xFFFFFFFFFFFFFFFFULL)<<64) + 0xFFFFFFFFFFFFFFFFULL)
#define YY ((uint128_t)0x80)
#define ZZ ((uint128_t)0x0)
	static const JTR_ALIGN(MEM_ALIGN_SIMD) uint128_t kTrailingBitTable[][4] = {
		{YY<<  0, ZZ, ZZ, ZZ}, {YY<<  8, ZZ, ZZ, ZZ}, {YY<< 16, ZZ, ZZ, ZZ}, {YY<< 24, ZZ, ZZ, ZZ},
		{YY<< 32, ZZ, ZZ, ZZ}, {YY<< 40, ZZ, ZZ, ZZ}, {YY<< 48, ZZ, ZZ, ZZ}, {YY<< 56, ZZ, ZZ, ZZ},
		{YY<< 64, ZZ, ZZ, ZZ}, {YY<< 72, ZZ, ZZ, ZZ}, {YY<< 80, ZZ, ZZ, ZZ}, {YY<< 88, ZZ, ZZ, ZZ},
		{YY<< 96, ZZ, ZZ, ZZ}, {YY<<104, ZZ, ZZ, ZZ}, {YY<<112, ZZ, ZZ, ZZ}, {YY<<120, ZZ, ZZ, ZZ},
		{ZZ, YY<<  0, ZZ, ZZ}, {ZZ, YY<<  8, ZZ, ZZ}, {ZZ, YY<< 16, ZZ, ZZ}, {ZZ, YY<< 24, ZZ, ZZ},
		{ZZ, YY<< 32, ZZ, ZZ}, {ZZ, YY<< 40, ZZ, ZZ}, {ZZ, YY<< 48, ZZ, ZZ}, {ZZ, YY<< 56, ZZ, ZZ},
		{ZZ, YY<< 64, ZZ, ZZ}, {ZZ, YY<< 72, ZZ, ZZ}, {ZZ, YY<< 80, ZZ, ZZ}, {ZZ, YY<< 88, ZZ, ZZ},
		{ZZ, YY<< 96, ZZ, ZZ}, {ZZ, YY<<104, ZZ, ZZ}, {ZZ, YY<<112, ZZ, ZZ}, {ZZ, YY<<120, ZZ, ZZ},
		{ZZ, ZZ, YY<<  0, ZZ}, {ZZ, ZZ, YY<<  8, ZZ}, {ZZ, ZZ, YY<< 16, ZZ}, {ZZ, ZZ, YY<< 24, ZZ},
		{ZZ, ZZ, YY<< 32, ZZ}, {ZZ, ZZ, YY<< 40, ZZ}, {ZZ, ZZ, YY<< 48, ZZ}, {ZZ, ZZ, YY<< 56, ZZ},
		{ZZ, ZZ, YY<< 64, ZZ}, {ZZ, ZZ, YY<< 72, ZZ}, {ZZ, ZZ, YY<< 80, ZZ}, {ZZ, ZZ, YY<< 88, ZZ},
		{ZZ, ZZ, YY<< 96, ZZ}, {ZZ, ZZ, YY<<104, ZZ}, {ZZ, ZZ, YY<<112, ZZ}, {ZZ, ZZ, YY<<120, ZZ},
		{ZZ, ZZ, ZZ, YY<<  0}, {ZZ, ZZ, ZZ, YY<<  8}, {ZZ, ZZ, ZZ, YY<< 16}, {ZZ, ZZ, ZZ, YY<< 24},
		{ZZ, ZZ, ZZ, YY<< 32}, {ZZ, ZZ, ZZ, YY<< 40}, {ZZ, ZZ, ZZ, YY<< 48}, {ZZ, ZZ, ZZ, YY<< 56},
		{ZZ, ZZ, ZZ, YY<< 64}, {ZZ, ZZ, ZZ, YY<< 72}, {ZZ, ZZ, ZZ, YY<< 80}, {ZZ, ZZ, ZZ, YY<< 88},
		{ZZ, ZZ, ZZ, YY<< 96}, {ZZ, ZZ, ZZ, YY<<104}, {ZZ, ZZ, ZZ, YY<<112}, {ZZ, ZZ, ZZ, YY<<120}
	};

	static const JTR_ALIGN(MEM_ALIGN_SIMD) uint128_t kUsedBytesTable[][4] = {
		{XX<<  0, XX, XX, XX}, {XX<<  8, XX, XX, XX}, {XX<< 16, XX, XX, XX}, {XX<< 24, XX, XX, XX},
		{XX<< 32, XX, XX, XX}, {XX<< 40, XX, XX, XX}, {XX<< 48, XX, XX, XX}, {XX<< 56, XX, XX, XX},
		{XX<< 64, XX, XX, XX}, {XX<< 72, XX, XX, XX}, {XX<< 80, XX, XX, XX}, {XX<< 88, XX, XX, XX},
		{XX<< 96, XX, XX, XX}, {XX<<104, XX, XX, XX}, {XX<<112, XX, XX, XX}, {XX<<120, XX, XX, XX},
		{ZZ, XX<<  0, XX, XX}, {ZZ, XX<<  8, XX, XX}, {ZZ, XX<< 16, XX, XX}, {ZZ, XX<< 24, XX, XX},
		{ZZ, XX<< 32, XX, XX}, {ZZ, XX<< 40, XX, XX}, {ZZ, XX<< 48, XX, XX}, {ZZ, XX<< 56, XX, XX},
		{ZZ, XX<< 64, XX, XX}, {ZZ, XX<< 72, XX, XX}, {ZZ, XX<< 80, XX, XX}, {ZZ, XX<< 88, XX, XX},
		{ZZ, XX<< 96, XX, XX}, {ZZ, XX<<104, XX, XX}, {ZZ, XX<<112, XX, XX}, {ZZ, XX<<120, XX, XX},
		{ZZ, ZZ, XX<<  0, XX}, {ZZ, ZZ, XX<<  8, XX}, {ZZ, ZZ, XX<< 16, XX}, {ZZ, ZZ, XX<< 24, XX},
		{ZZ, ZZ, XX<< 32, XX}, {ZZ, ZZ, XX<< 40, XX}, {ZZ, ZZ, XX<< 48, XX}, {ZZ, ZZ, XX<< 56, XX},
		{ZZ, ZZ, XX<< 64, XX}, {ZZ, ZZ, XX<< 72, XX}, {ZZ, ZZ, XX<< 80, XX}, {ZZ, ZZ, XX<< 88, XX},
		{ZZ, ZZ, XX<< 96, XX}, {ZZ, ZZ, XX<<104, XX}, {ZZ, ZZ, XX<<112, XX}, {ZZ, ZZ, XX<<120, XX},
		{ZZ, ZZ, ZZ, XX<<  0}, {ZZ, ZZ, ZZ, XX<<  8}, {ZZ, ZZ, ZZ, XX<< 16}, {ZZ, ZZ, ZZ, XX<< 24},
		{ZZ, ZZ, ZZ, XX<< 32}, {ZZ, ZZ, ZZ, XX<< 40}, {ZZ, ZZ, ZZ, XX<< 48}, {ZZ, ZZ, ZZ, XX<< 56},
		{ZZ, ZZ, ZZ, XX<< 64}, {ZZ, ZZ, ZZ, XX<< 72}, {ZZ, ZZ, ZZ, XX<< 80}, {ZZ, ZZ, ZZ, XX<< 88},
		{ZZ, ZZ, ZZ, XX<< 96}, {ZZ, ZZ, ZZ, XX<<104}, {ZZ, ZZ, ZZ, XX<<112}, {ZZ, ZZ, ZZ, XX<<120}
	};

#elif VWIDTH > 4
	static const JTR_ALIGN(MEM_ALIGN_SIMD) uint32_t kTrailingBitTable[][8] = {
		{ 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00008000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00008000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00008000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00800000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x00000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000080, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00008000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00800000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000, 0x00000000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000080 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00008000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00800000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000000 },
	};

	static const JTR_ALIGN(MEM_ALIGN_SIMD) uint32_t kUsedBytesTable[][8] = {
		{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFF00, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFF0000, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFF00, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFF0000, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFF00 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFF0000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFF000000 },
	};
#else
	static const JTR_ALIGN(MEM_ALIGN_SIMD) uint32_t kTrailingBitTable[][4] = {
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

	static const JTR_ALIGN(MEM_ALIGN_SIMD) uint32_t kUsedBytesTable[][4] = {
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
		{ 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFF },
		{ 0x00000000, 0x00000000, 0x00000000, 0xFFFFFF00 },
		{ 0x00000000, 0x00000000, 0x00000000, 0xFFFF0000 },
		{ 0x00000000, 0x00000000, 0x00000000, 0xFF000000 },
	};
#endif

	N[index] = len;

	// Zero out the rest of the DQWORD in X by making a suitable mask.
	Z = vload(kUsedBytesTable[len]);

	// Find the correct position for the trailing bit required by SHA-1.
	B = vload(kTrailingBitTable[len]);

	// Now we have this:
	// B = 00 00 00 00 00 80 00 00 00 00 00 00 00 00 00
	// Z = 00 00 00 00 00 ff ff ff ff ff ff ff ff ff ff
	// X = 41 41 41 41 41 00 12 34 56 78 12 34 56 78 9A
	//     <---------------> <------------------------>
	//      key bytes w/nul       junk from stack.

	// Use PANDN to apply the mask, then POR to append the trailing bit
	// required by SHA-1, which leaves us with this:
	// X = 41 41 41 41 41 80 00 00 00 00 00 00 00 00 00
	X = vor(vandnot(Z, X), B);

	// SHA-1 requires us to byte swap all the 32bit words in the message, which
	// we do here.
	//  X = 40 41 42 44 45 80 00 00 00 00 00 00 00 00 00    // What we have.
	//  X = 44 42 41 40 00 00 80 45 00 00 00 00 00 00 00    // What we want.
	vswap32(X);

	// Store the result into the message buffer.
	vstore(&M[index], X);

	return;
}

static char *sha1_fmt_get_key(int index)
{
	static uint32_t key[VWIDTH + 1];
	int i;

	// This function is not hot, we can do this slowly. First, restore
	// endianness.
	for (i = 0; i < SIMD_COEF_32; i++)
		key[i] = __builtin_bswap32(M[index][i]);

	// Skip backwards until we hit the trailing bit, then remove it.
	memset(strrchr((char*)(key), 0x80), 0x00, 1);

	return (char*) key;
}

static int sha1_fmt_crypt_all(int *pcount, struct db_salt *salt)
{
	uint32_t i;

	// Fetch crypt count from john.
	const int32_t count = *pcount;

	// To reduce the overhead of multiple function calls, we buffer lots of
	// passwords, and then hash them in multiples of VWIDTH all at once.
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i += VWIDTH) {
		vtype W[SHA1_BLOCK_WORDS];
		vtype A, B, C, D, E;
		vtype K;

#if __AVX512F__ || __MIC__
		const vtype indices = vset_epi32(15<<4,14<<4,13<<4,12<<4,
		                                 11<<4,10<<4, 9<<4, 8<<4,
		                                  7<<4, 6<<4, 5<<4, 4<<4,
		                                  3<<4, 2<<4, 1<<4, 0<<4);
#elif __AVX2__
		const vtype indices = vset_epi32( 7<<3, 6<<3, 5<<3, 4<<3,
		                                  3<<3, 2<<3, 1<<3, 0<<3);
#endif

#if __AVX2__ || __MIC__
		// Gather the message right into place.
		uint32_t j;
		for (j = 0; j < VWIDTH; ++j)
			W[j] = vgather_epi32(&M[i][j], indices, sizeof(uint32_t));
#else
		// AVX has no gather instructions, so load and transpose.
		W[0]  = vload(&M[i + 0]);
		W[1]  = vload(&M[i + 1]);
		W[2]  = vload(&M[i + 2]);
		W[3]  = vload(&M[i + 3]);

		_MM_TRANSPOSE4_EPI32(W[0],  W[1],  W[2],  W[3]);
#endif

		A = vset1_epi32(0x67452301);
		B = vset1_epi32(0xEFCDAB89);
		C = vset1_epi32(0x98BADCFE);
		D = vset1_epi32(0x10325476);
		E = vset1_epi32(0xC3D2E1F0);
		K = vset1_epi32(0x5A827999);

		R1(W[0],  A, B, C, D, E);
		R1(W[1],  E, A, B, C, D);
		R1(W[2],  D, E, A, B, C);
#if VWIDTH > 4
		R1(W[3],  C, D, E, A, B);
		R1(W[4],  B, C, D, E, A);
		R1(W[5],  A, B, C, D, E);                          // 5
		R1(W[6],  E, A, B, C, D);
#else
		R1(W[3],  C, D, E, A, B); W[4]  = vsetzero();
		R1(W[4],  B, C, D, E, A); W[5]  = vsetzero();
		R1(W[5],  A, B, C, D, E); W[6]  = vsetzero();      // 5
		R1(W[6],  E, A, B, C, D); W[7]  = vsetzero();
#endif
#if VWIDTH > 8
		R1(W[7],  D, E, A, B, C);
		R1(W[8],  C, D, E, A, B);
		R1(W[9],  B, C, D, E, A);
		R1(W[10], A, B, C, D, E);                          // 10
		R1(W[11], E, A, B, C, D);
		R1(W[12], D, E, A, B, C);
		R1(W[13], C, D, E, A, B);
		R1(W[14], B, C, D, E, A);
#else
		R1(W[7],  D, E, A, B, C); W[8]  = vsetzero();
		R1(W[8],  C, D, E, A, B); W[9]  = vsetzero();
		R1(W[9],  B, C, D, E, A); W[10] = vsetzero();
		R1(W[10], A, B, C, D, E); W[11] = vsetzero();      // 10
		R1(W[11], E, A, B, C, D); W[12] = vsetzero();
		R1(W[12], D, E, A, B, C); W[13] = vsetzero();
		R1(W[13], C, D, E, A, B); W[14] = vsetzero();
		R1(W[14], B, C, D, E, A);
#endif

		// Fetch the message lengths, multiply 8 (to get the length in bits).
		W[15] = vslli_epi32(vload(&N[i]), 3);

		R1(W[15], A, B, C, D, E);                                   // 15

		X(W[0],  W[2],  W[8],  W[13]);  R1(W[0],  E, A, B, C, D);
		X(W[1],  W[3],  W[9],  W[14]);  R1(W[1],  D, E, A, B, C);
		X(W[2],  W[4],  W[10], W[15]);  R1(W[2],  C, D, E, A, B);
		X(W[3],  W[5],  W[11], W[0]);   R1(W[3],  B, C, D, E, A);

		K = vset1_epi32(0x6ED9EBA1);

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

		K = vset1_epi32(0x8F1BBCDC);

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

		K = vset1_epi32(0xCA62C1D6);

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
		X(W[11], W[13], W[3],  W[8]);   R4(W[11], A, B, C, D, E);   // 75

		// A75 has an interesting property, it is the first word that's (almost)
		// part of the final MD (E79 ror 2). The common case will be that this
		// doesn't match, so we stop here and save 5 rounds.
		//
		// Note that I'm using E due to displacement caused by vectorization,
		// this is A in standard SHA-1.
		vstore(&MD[i], E);
	}
	return count;
}

static int sha1_fmt_cmp_all(void *binary, int count)
{
	uint32_t  M;
	uint32_t  i;
	vtype  B;

	// This function is hot, we need to do this quickly. We use PCMP to find
	// out if any of the dwords in A75 matched E in the input hash.
	// First, Load the target hash into an XMM register
	B = vloadu(binary);
	M = 0;

#ifdef _OPENMP
#pragma omp parallel for reduction(|:M)
#endif

	// We can test for matches 4/8 at a time. As the common case will be that
	// there is no match, we can avoid testing it after every compare, reducing
	// the number of branches.
	//
	// It's hard to convince GCC that it's safe to unroll this loop, so I've
	// manually unrolled it a little bit.
	for (i = 0; i < count; i += 64) {
		uint32_t R = 0;
#if __AVX512F__ || __MIC__
		R |= vanyeq_epi32(B, vload(&MD[i +  0]));
		R |= vanyeq_epi32(B, vload(&MD[i + 16]));
		R |= vanyeq_epi32(B, vload(&MD[i + 32]));
		R |= vanyeq_epi32(B, vload(&MD[i + 48]));
#elif __AVX2__
		R |= vanyeq_epi32(B, vload(&MD[i +  0]));
		R |= vanyeq_epi32(B, vload(&MD[i +  8]));
		R |= vanyeq_epi32(B, vload(&MD[i + 16]));
		R |= vanyeq_epi32(B, vload(&MD[i + 24]));
		R |= vanyeq_epi32(B, vload(&MD[i + 32]));
		R |= vanyeq_epi32(B, vload(&MD[i + 40]));
		R |= vanyeq_epi32(B, vload(&MD[i + 48]));
		R |= vanyeq_epi32(B, vload(&MD[i + 56]));
#else
		R |= vanyeq_epi32(B, vload(&MD[i +  0]));
		R |= vanyeq_epi32(B, vload(&MD[i +  4]));
		R |= vanyeq_epi32(B, vload(&MD[i +  8]));
		R |= vanyeq_epi32(B, vload(&MD[i + 12]));
		R |= vanyeq_epi32(B, vload(&MD[i + 16]));
		R |= vanyeq_epi32(B, vload(&MD[i + 20]));
		R |= vanyeq_epi32(B, vload(&MD[i + 24]));
		R |= vanyeq_epi32(B, vload(&MD[i + 28]));
		R |= vanyeq_epi32(B, vload(&MD[i + 32]));
		R |= vanyeq_epi32(B, vload(&MD[i + 36]));
		R |= vanyeq_epi32(B, vload(&MD[i + 40]));
		R |= vanyeq_epi32(B, vload(&MD[i + 44]));
		R |= vanyeq_epi32(B, vload(&MD[i + 48]));
		R |= vanyeq_epi32(B, vload(&MD[i + 52]));
		R |= vanyeq_epi32(B, vload(&MD[i + 56]));
		R |= vanyeq_epi32(B, vload(&MD[i + 60]));
#endif
		M |= R;
	}

	return M;
}

inline static int sha1_fmt_get_hash(int index)
{
	return MD[index];
}

static int sha1_fmt_get_hash0(int index) { return sha1_fmt_get_hash(index) & PH_MASK_0; }
static int sha1_fmt_get_hash1(int index) { return sha1_fmt_get_hash(index) & PH_MASK_1; }
static int sha1_fmt_get_hash2(int index) { return sha1_fmt_get_hash(index) & PH_MASK_2; }
static int sha1_fmt_get_hash3(int index) { return sha1_fmt_get_hash(index) & PH_MASK_3; }
static int sha1_fmt_get_hash4(int index) { return sha1_fmt_get_hash(index) & PH_MASK_4; }
static int sha1_fmt_get_hash5(int index) { return sha1_fmt_get_hash(index) & PH_MASK_5; }
static int sha1_fmt_get_hash6(int index) { return sha1_fmt_get_hash(index) & PH_MASK_6; }

inline static int sha1_fmt_get_binary(void *binary)
{
	return *(uint32_t*)(binary);
}

static int sha1_fmt_binary0(void *binary) { return sha1_fmt_get_binary(binary) & PH_MASK_0; }
static int sha1_fmt_binary1(void *binary) { return sha1_fmt_get_binary(binary) & PH_MASK_1; }
static int sha1_fmt_binary2(void *binary) { return sha1_fmt_get_binary(binary) & PH_MASK_2; }
static int sha1_fmt_binary3(void *binary) { return sha1_fmt_get_binary(binary) & PH_MASK_3; }
static int sha1_fmt_binary4(void *binary) { return sha1_fmt_get_binary(binary) & PH_MASK_4; }
static int sha1_fmt_binary5(void *binary) { return sha1_fmt_get_binary(binary) & PH_MASK_5; }
static int sha1_fmt_binary6(void *binary) { return sha1_fmt_get_binary(binary) & PH_MASK_6; }

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
	SHA1_Final((unsigned char*)(full_sha1_digest), &ctx);

	// Compare result.
	return !memcmp(rawsha1_common_get_binary(source), full_sha1_digest,
	               sizeof(full_sha1_digest));
}

struct fmt_main fmt_sha1_ng = {
	.params                 = {
		.label              = "Raw-SHA1-ng",
#if VWIDTH == 16
		.format_name        = "(pwlen <= 55)",
#if __MIC__
		.algorithm_name     = "SHA1 512/512 MIC 16x",
#else
		.algorithm_name     = "SHA1 512/512 AVX512 16x",
#endif
#elif VWIDTH == 8
		.format_name        = "(pwlen <= 31)",
		.algorithm_name     = "SHA1 256/256 AVX2 8x",
#else
		.format_name        = "(pwlen <= 15)",
		.algorithm_name     = "SHA1 128/128 "
#if __ALTIVEC__
		"AltiVec"
#elif __ARM_NEON
		"NEON"
#elif __XOP__
		"XOP"
#elif __AVX__
		"AVX"
#elif __SSE4_1__
		"SSE4.1"
#else
		"SSE2"
#endif
		" 4x",
#endif
		.benchmark_comment  = "",
		.benchmark_length   = -1,
#if VWIDTH * 4 - 1 > 55
		.plaintext_length   = 55,
#else
		.plaintext_length   = sizeof(vtype) - 1,
#endif
		.binary_size        = sizeof(vtype),
		.binary_align       = VWIDTH * 4,
		.salt_size          = 0,
		.salt_align         = 1,
		.min_keys_per_crypt = VWIDTH,
		.max_keys_per_crypt = SHA1_PARALLEL_HASH,
		.flags              =
#ifdef _OPENMP
		                      FMT_OMP | FMT_OMP_BAD |
#endif
		                      FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		.tunable_cost_name  = { NULL },
		.signature          = { FORMAT_TAG, FORMAT_TAG_OLD },
		.tests              = rawsha1_common_tests,
	},
	.methods                = {
		.init               = sha1_fmt_init,
		.done               = done,
		.reset              = fmt_default_reset,
		.prepare            = rawsha1_common_prepare,
		.valid              = rawsha1_common_valid,
		.split              = rawsha1_common_split,
		.binary             = sha1_fmt_binary,
		.salt               = fmt_default_salt,
		.tunable_cost_value = { NULL },
		.source             = fmt_default_source,
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
		.cmp_exact          = sha1_fmt_cmp_exact
	},
};

#endif /* plugin stanza */

#endif /* defined(SIMD_COEF_32) && (SIMD_COEF_32 < 16 || ARCH_BITS >= 64) && !_MSC_VER */
