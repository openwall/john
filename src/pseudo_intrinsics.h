/*
 * Minimalistic pseudo-instrinsics for width-agnostic x86 SIMD code.
 *
 * This software is Copyright (c) 2015 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 * Synopsis:
 *
 * SSE2:     __m128i a = _mm_add_epi32(b, c);
 * AVX2:     __m256i a = _mm256_add_epi32(b, c);
 * AVX512:   __m512i a = _mm512_add_epi32(b, c);
 * -> Pseudo:  vtype a = vadd_epi32(b, c);
 *
 * SSE2:     __m128i a = _mm_load_si128(p);
 * AVX2:     __m256i a = _mm256_load_si256(p);
 * AVX512:   __m512i a = _mm512_load_si512(p);
 * -> Pseudo:  vtype a = vload(p);
 *
 * intrinsics are emulated where the target does not support them.
 */

#ifndef _SSE_PSEUDO_H
#define _SSE_PSEUDO_H

#include "aligned.h"

#undef SIMD_COEF_32
#undef SIMD_COEF_64

/*************************** AVX512 and MIC ***************************/
#if __MIC__ || __AVX512__
#include <immintrin.h>

#define SIMD_COEF_32            16
#define SIMD_COEF_64            8

typedef __m512i vtype;

#define vadd_epi32              _mm512_add_epi32
#define vadd_epi64              _mm512_add_epi64
#define vand                    _mm512_and_si512
#define vandnot                 _mm512_andnot_si512
#define vcmov(y, z, x)          vxor(z, vand(x, vxor(y, z)))
#define vcmpeq_epi32            _mm512_cmpeq_epi32
#define vcmpeq_epi8             _mm512_cmpeq_epi8
#define vload(x)                _mm512_load_si512((void*)x)
#define vloadu(x)               _mm512_loadu_si512((void*)x)
#define vmovemask_epi8          _mm512_movemask_epi8
#define vor                     _mm512_or_si512
#define vset1_epi32             _mm512_set1_epi32
#define vset1_epi64x            _mm512_set1_epi64x
#define vset_epi64x             _mm512_set_epi64x
#define vsetzero                _mm512_setzero_si512
#define vshuffle_epi8           _mm512_shuffle_epi8
#define vshuffle_epi32          _mm512_shuffle_epi32
#define vshufflehi_epi16        _mm512_shufflehi_epi16
#define vshufflelo_epi16        _mm512_shufflelo_epi16
#define vslli_epi16             _mm512_slli_epi16
#define vslli_epi32             _mm512_slli_epi32
#define vslli_epi64             _mm512_slli_epi64
#define vsrli_epi16             _mm512_srli_epi16
#define vsrli_epi32             _mm512_srli_epi32
#define vsrli_epi64             _mm512_srli_epi64
#define vstore(x, y)            _mm512_store_si512((void*)x, y)
#define vunpackhi_epi32         _mm512_unpackhi_epi32
#define vunpackhi_epi64         _mm512_unpackhi_epi64
#define vunpacklo_epi32         _mm512_unpacklo_epi32
#define vunpacklo_epi64         _mm512_unpacklo_epi64
#define vxor                    _mm512_xor_si512
#define vpermute4x64_epi64      _mm512_permute4x64_epi64
#define vpermute2x128           _mm512_permute2x128_si512
#define vset_epi32              _mm512_set_epi32

#define vswap32(n)	  \
	n = _mm512_shuffle_epi8(n, _mm512_set_epi32(0x3c3d3e3f, 0x38393a3b, \
	                                            0x34353637, 0x30313233, \
	                                            0x2c2d2e2f, 0x28292a2b, \
	                                            0x24252627, 0x20212223, \
	                                            0x1c1d1e1f, 0x18191a1b, \
	                                            0x14151617, 0x10111213, \
	                                            0x0c0d0e0f, 0x08090a0b, \
	                                            0x04050607, 0x00010203))

static inline int vtestz_epi32(vtype __X)
{
    uint32_t JTR_ALIGN(SIMD_COEF_32 * 4) words[8];
    vstore(words, __X);
    return !words[0] || !words[1] || !words[2] || !words[3] ||
	    !words[4] || !words[5] || !words[6] || !words[7];
}

/******************************** AVX2 ********************************/
#elif __AVX2__
#include <immintrin.h>

#define SIMD_COEF_32            8
#define SIMD_COEF_64            4

typedef __m256i vtype;

#define vadd_epi32              _mm256_add_epi32
#define vadd_epi64              _mm256_add_epi64
#define vand                    _mm256_and_si256
#define vandnot                 _mm256_andnot_si256
#define vcmov(y, z, x)          vxor(z, vand(x, vxor(y, z)))
#define vcmpeq_epi32            _mm256_cmpeq_epi32
#define vcmpeq_epi8             _mm256_cmpeq_epi8
#define vload(x)                _mm256_load_si256((void*)x)
#define vloadu(x)               _mm256_loadu_si256((void*)x)
#define vmovemask_epi8          _mm256_movemask_epi8
#define vor                     _mm256_or_si256
#define vset1_epi32             _mm256_set1_epi32
#define vset1_epi64x            _mm256_set1_epi64x
#define vset_epi64x             _mm256_set_epi64x
#define vsetzero                _mm256_setzero_si256
#define vshuffle_epi8           _mm256_shuffle_epi8
#define vshuffle_epi32          _mm256_shuffle_epi32
#define vshufflehi_epi16        _mm256_shufflehi_epi16
#define vshufflelo_epi16        _mm256_shufflelo_epi16
#define vslli_epi16             _mm256_slli_epi16
#define vslli_epi32             _mm256_slli_epi32
#define vslli_epi64             _mm256_slli_epi64
#define vsrli_epi16             _mm256_srli_epi16
#define vsrli_epi32             _mm256_srli_epi32
#define vsrli_epi64             _mm256_srli_epi64
#define vstore(x, y)            _mm256_store_si256((void*)x, y)
#define vunpackhi_epi32         _mm256_unpackhi_epi32
#define vunpackhi_epi64         _mm256_unpackhi_epi64
#define vunpacklo_epi32         _mm256_unpacklo_epi32
#define vunpacklo_epi64         _mm256_unpacklo_epi64
#define vxor                    _mm256_xor_si256
#define vpermute4x64_epi64      _mm256_permute4x64_epi64
#define vpermute2x128           _mm256_permute2x128_si256
#define vset_epi32              _mm256_set_epi32

#define vswap32(n)	  \
	n = _mm256_shuffle_epi8(n, _mm256_set_epi32(0x1c1d1e1f, 0x18191a1b, \
	                                            0x14151617, 0x10111213, \
	                                            0x0c0d0e0f, 0x08090a0b, \
	                                            0x04050607, 0x00010203))

static inline void vmerge_epi32(const vtype v0, const vtype v1, vtype *vl, vtype *vh)
{
    vtype va = vpermute4x64_epi64(v0, _MM_SHUFFLE(3, 1, 2, 0));
    vtype vb = vpermute4x64_epi64(v1, _MM_SHUFFLE(3, 1, 2, 0));
    *vl = vunpacklo_epi32(va, vb);
    *vh = vunpackhi_epi32(va, vb);
}

static inline void vmerge_epi64(const vtype v0, const vtype v1, vtype *vl, vtype *vh)
{
    vtype va = vpermute4x64_epi64(v0, _MM_SHUFFLE(3, 1, 2, 0));
    vtype vb = vpermute4x64_epi64(v1, _MM_SHUFFLE(3, 1, 2, 0));
    *vl = vunpacklo_epi64(va, vb);
    *vh = vunpackhi_epi64(va, vb);
}

static inline void vmerge(const vtype v0, const vtype v1, vtype *vl, vtype *vh)
{
    *vl = vpermute2x128(v0, v1, _MM_SHUFFLE(0, 2, 0, 0));
    *vh = vpermute2x128(v0, v1, _MM_SHUFFLE(0, 3, 0, 1));
}

#define vtranspose_epi32(R) do {	  \
		vtype T0, T1, T2, T3, T4, T5, T6, T7; \
		vtype t0, t1, t2, t3, t4, t5, t6, t7; \
		vmerge_epi32(R[0], R[1], &T0, &T1); \
		vmerge_epi32(R[2], R[3], &T2, &T3); \
		vmerge_epi32(R[4], R[5], &T4, &T5); \
		vmerge_epi32(R[6], R[7], &T6, &T7); \
		vmerge_epi64(T0, T2, &t0, &t1); \
		vmerge_epi64(T1, T3, &t2, &t3); \
		vmerge_epi64(T4, T6, &t4, &t5); \
		vmerge_epi64(T5, T7, &t6, &t7); \
		vmerge(t0, t4, &R[0], &R[1]); \
		vmerge(t1, t5, &R[2], &R[3]); \
		vmerge(t2, t6, &R[4], &R[5]); \
		vmerge(t3, t7, &R[6], &R[7]); \
	} while (false)

#if !__clang__
#if !__INTEL_COMPILER && !__llvm__
// This intrinsic is not always available in GCC, so define it here.
static inline int vtestz(vtype __M, vtype __V)
{
    return __builtin_ia32_ptestz256((__v4di)__M, (__v4di)__V);
}
#endif
// This is a modified SSE2 port of Algorithm 6-2 from "Hackers Delight" by
// Henry Warren, ISBN 0-201-91465-4. Returns non-zero if any double word in X
// is zero using a branchless algorithm. -- taviso.
static inline int vtestz_epi32(vtype __X)
{
    vtype M = vcmpeq_epi32(__X, __X);
    vtype Z = vsrli_epi32(M, 1);
    vtype Y = vandnot(vor(vor(vadd_epi32(vand(__X, Z), Z), __X), Z), M);
    return ! vtestz(Y, M);
}
#else
static inline int vtestz_epi32(vtype __X)
{
    uint32_t JTR_ALIGN(SIMD_COEF_32 * 4) words[4];
    vstore(words, __X);
    return !words[0] || !words[1] || !words[2] || !words[3];
}
#endif

/************************* SSE2/3/4/AVX/XOP ***************************/
#elif __SSE2__
#if __AVX__
#include <immintrin.h>
#if __XOP__
#include <x86intrin.h>
#endif
#endif
#include <emmintrin.h>

#define SIMD_COEF_32            4
#define SIMD_COEF_64            2

typedef __m128i vtype;

#define vadd_epi32              _mm_add_epi32
#define vadd_epi64              _mm_add_epi64
#define vand                    _mm_and_si128
#define vandnot                 _mm_andnot_si128
#if __XOP__
#define vcmov                   _mm_cmov_si128
#else
#define vcmov(y, z, x)          vxor(z, vand(x, vxor(y, z)))
#endif
#define vcmpeq_epi32            _mm_cmpeq_epi32
#define vcmpeq_epi8             _mm_cmpeq_epi8
#define vload(x)                _mm_load_si128((void*)x)
#define vloadu(x)               _mm_loadu_si128((void*)x)
#define vmovemask_epi8          _mm_movemask_epi8
#define vor                     _mm_or_si128
#if __XOP__
#define vroti_epi16             _mm_roti_epi16
#define vroti_epi32             _mm_roti_epi32
#define vroti_epi64             _mm_roti_epi64
#endif
#define vset1_epi32             _mm_set1_epi32
#define vset1_epi64x            _mm_set1_epi64x
#define vset_epi64x             _mm_set_epi64x
#define vsetzero                _mm_setzero_si128
#ifdef __SSSE3__
#define vshuffle_epi8           _mm_shuffle_epi8
#endif
#define vshuffle_epi32          _mm_shuffle_epi32
#define vshufflehi_epi16        _mm_shufflehi_epi16
#define vshufflelo_epi16        _mm_shufflelo_epi16
#define vslli_epi16             _mm_slli_epi16
#define vslli_epi32             _mm_slli_epi32
#define vslli_epi64             _mm_slli_epi64
#define vsrli_epi16             _mm_srli_epi16
#define vsrli_epi32             _mm_srli_epi32
#define vsrli_epi64             _mm_srli_epi64
#define vstore(x, y)            _mm_store_si128((void*)x, y)
#define vunpackhi_epi32         _mm_unpackhi_epi32
#define vunpackhi_epi64         _mm_unpackhi_epi64
#define vunpacklo_epi32         _mm_unpacklo_epi32
#define vunpacklo_epi64         _mm_unpacklo_epi64
#define vxor                    _mm_xor_si128
#define vpermute4x64_epi64      _mm_permute4x64_epi64
#define vpermute2x128           _mm_permute2x128_si128
#define vset_epi32              _mm_set_epi32

#if __SSSE3__
#define vswap32(n)	  \
	n = vshuffle_epi8(n, vset_epi32(0x0c0d0e0f, 0x08090a0b, \
	                                0x04050607, 0x00010203))
#else
#define ROT16(n) vshufflelo_epi16(vshufflehi_epi16(n, 0xb1), 0xb1))

#define vswap32(n) n = vxor(vsrli_epi16(ROT16(n), 8),	\
                            vslli_epi16(ROT16(n), 8))
#endif

#define vtranspose_epi32(R) do {	  \
		vtype T0, T1, T2, T3; \
		T0  = vunpacklo_epi32(R[0], R[1]); \
		T1  = vunpacklo_epi32(R[2], R[3]); \
		T2  = vunpackhi_epi32(R[0], R[1]); \
		T3  = vunpackhi_epi32(R[2], R[3]); \
		R[0]  = vunpacklo_epi64(T0, T1); \
		R[1]  = vunpackhi_epi64(T0, T1); \
		R[2]  = vunpacklo_epi64(T2, T3); \
		R[3]  = vunpackhi_epi64(T2, T3); \
	} while (false)

#if __SSE4_1__ && !__clang__
#if !__INTEL_COMPILER && !__llvm__
// This intrinsic is not always available in GCC, so define it here.
static inline int vtestz(vtype __M, vtype __V)
{
    return __builtin_ia32_ptestz128((__v2di)__M, (__v2di)__V);
}
#endif
// This is a modified SSE2 port of Algorithm 6-2 from "Hackers Delight" by
// Henry Warren, ISBN 0-201-91465-4. Returns non-zero if any double word in X
// is zero using a branchless algorithm. -- taviso.
static inline int vtestz_epi32(vtype __X)
{
    vtype M = vcmpeq_epi32(__X, __X);
    vtype Z = vsrli_epi32(M, 1);
    vtype Y = vandnot(vor(vor(vadd_epi32(vand(__X, Z), Z), __X), Z), M);
    return ! vtestz(Y, M);
}
#else
static inline int vtestz_epi32(vtype __X)
{
    uint32_t JTR_ALIGN(SIMD_COEF_32 * 4) words[4];
    vstore(words, __X);
    return !words[0] || !words[1] || !words[2] || !words[3];
}
#endif

/******************************** MMX *********************************/

#elif __MMX__
#include <mmintrin.h>

#define SIMD_COEF_32            2
#define SIMD_COEF_64            1

typedef __m64i vtype;

#error MMX intrinsics not implemented

#endif /* __SIMD__ elif __SIMD__ elif __SIMD__ */

/**************************** common stuff ****************************/

#define MEM_ALIGN_SIMD          (SIMD_COEF_32 * 4)

#if !__XOP__
#define vroti_epi16(x, n) ((n) > 0 ?	  \
                           vxor(vsrli_epi16(x, 16 - (n)), vslli_epi16(x, n)) : \
                           vxor(vsrli_epi16(x, -n), vslli_epi16(x, 16 + (n))))
#define vroti_epi32(x, n) ((n) == 16 ?	  \
                           vshufflelo_epi16(vshufflehi_epi16((x), 0xb1), 0xb1) : \
                           ((n) > 0 ?	  \
                            vxor(vsrli_epi32(x, 32 - (n)), vslli_epi32(x, n)) : \
                            vxor(vsrli_epi32(x, -n), vslli_epi32(x, 32 + (n)))))
#define vroti_epi64(x, n) ((n) > 0 ?	  \
                           vxor(vsrli_epi64(x, 64 - (n)), vslli_epi64(x, n)) : \
                           vxor(vsrli_epi64(x, -n), vslli_epi64(x, 64 + (n))))
#endif /* !__XOP__ */

#endif /* _SSE_PSEUDO_H */
