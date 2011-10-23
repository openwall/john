/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2010,2011 by Solar Designer
 */

#include "arch.h"

#if !DES_BS_ASM
#include "DES_bs.h"

#define vzero (*(vtype *)&DES_bs_all.zero)
#define vones (*(vtype *)&DES_bs_all.ones)

#define DES_BS_VECTOR_LOOPS 0

#if defined(__ALTIVEC__) && DES_BS_DEPTH == 128
#ifdef __linux__
#include <altivec.h>
#endif

typedef vector signed int vtype;

#define vst(dst, ofs, src) \
	vec_st((src), (ofs) * sizeof(DES_bs_vector), &(dst))

#define vxorf(a, b) \
	vec_xor((a), (b))

#define vnot(dst, a) \
	(dst) = vec_nor((a), (a))
#define vand(dst, a, b) \
	(dst) = vec_and((a), (b))
#define vor(dst, a, b) \
	(dst) = vec_or((a), (b))
#define vandn(dst, a, b) \
	(dst) = vec_andc((a), (b))
#define vsel(dst, a, b, c) \
	(dst) = vec_sel((a), (b), (c))

#elif defined(__ALTIVEC__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 192) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 160))
#ifdef __linux__
#include <altivec.h>
#endif

typedef struct {
	vector signed int f;
	ARCH_WORD g;
} vtype;

#define vst(dst, ofs, src) \
	vec_st((src).f, (ofs) * sizeof(DES_bs_vector), &((vtype *)&(dst))->f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = vec_xor((a).f, (b).f); \
	(dst).g = (a).g ^ (b).g

#define vnot(dst, a) \
	(dst).f = vec_nor((a).f, (a).f); \
	(dst).g = ~(a).g
#define vand(dst, a, b) \
	(dst).f = vec_and((a).f, (b).f); \
	(dst).g = (a).g & (b).g
#define vor(dst, a, b) \
	(dst).f = vec_or((a).f, (b).f); \
	(dst).g = (a).g | (b).g
#define vandn(dst, a, b) \
	(dst).f = vec_andc((a).f, (b).f); \
	(dst).g = (a).g & ~(b).g
#define vsel(dst, a, b, c) \
	(dst).f = vec_sel((a).f, (b).f, (c).f); \
	(dst).g = (((a).g & ~(c).g) ^ ((b).g & (c).g))

#elif defined(__ALTIVEC__) && DES_BS_DEPTH == 256
#ifdef __linux__
#include <altivec.h>
#endif

typedef struct {
	vector signed int f, g;
} vtype;

#define vst(dst, ofs, src) \
	vec_st((src).f, (ofs) * sizeof(DES_bs_vector), &((vtype *)&(dst))->f); \
	vec_st((src).g, (ofs) * sizeof(DES_bs_vector), &((vtype *)&(dst))->g)

#define vxor(dst, a, b) \
	(dst).f = vec_xor((a).f, (b).f); \
	(dst).g = vec_xor((a).g, (b).g)

#define vnot(dst, a) \
	(dst).f = vec_nor((a).f, (a).f); \
	(dst).g = vec_nor((a).g, (a).g)
#define vand(dst, a, b) \
	(dst).f = vec_and((a).f, (b).f); \
	(dst).g = vec_and((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = vec_or((a).f, (b).f); \
	(dst).g = vec_or((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = vec_andc((a).f, (b).f); \
	(dst).g = vec_andc((a).g, (b).g)
#define vsel(dst, a, b, c) \
	(dst).f = vec_sel((a).f, (b).f, (c).f); \
	(dst).g = vec_sel((a).g, (b).g, (c).g)

#elif defined(__AVX__) && DES_BS_DEPTH == 256 && !defined(DES_BS_NO_AVX256)
#include <immintrin.h>

/* Not __m256i because bitwise ops are "floating-point" with AVX */
typedef __m256 vtype;

#define vst(dst, ofs, src) \
	_mm256_store_ps((float *)((DES_bs_vector *)&(dst) + (ofs)), (src))

#define vxorf(a, b) \
	_mm256_xor_ps((a), (b))

#define vand(dst, a, b) \
	(dst) = _mm256_and_ps((a), (b))
#define vor(dst, a, b) \
	(dst) = _mm256_or_ps((a), (b))
#define vandn(dst, a, b) \
	(dst) = _mm256_andnot_ps((b), (a))

#ifdef __XOP__
/* This could be _mm256_cmov_ps(), but it does not exist (yet?) */
#define vsel(dst, a, b, c) \
	(dst) = __builtin_ia32_vpcmov_v8sf256((b), (a), (c))
#endif

#elif defined(__AVX__) && DES_BS_DEPTH == 384 && !defined(DES_BS_NO_AVX128)
#include <immintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#endif

typedef struct {
/* Not __m256i because bitwise ops are "floating-point" with AVX */
	__m256 f;
	__m128i g;
} vtype;

#define vst(dst, ofs, src) \
	_mm256_store_ps( \
	    (float *)&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g, \
	    (src).g)

#define vxor(dst, a, b) \
	(dst).f = _mm256_xor_ps((a).f, (b).f); \
	(dst).g = _mm_xor_si128((a).g, (b).g)

#define vand(dst, a, b) \
	(dst).f = _mm256_and_ps((a).f, (b).f); \
	(dst).g = _mm_and_si128((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = _mm256_or_ps((a).f, (b).f); \
	(dst).g = _mm_or_si128((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = _mm256_andnot_ps((b).f, (a).f); \
	(dst).g = _mm_andnot_si128((b).g, (a).g)

#ifdef __XOP__
/* This could be _mm256_cmov_ps(), but it does not exist (yet?) */
#define vsel(dst, a, b, c) \
	(dst).f = __builtin_ia32_vpcmov_v8sf256((b).f, (a).f, (c).f); \
	(dst).g = _mm_cmov_si128((b).g, (a).g, (c).g)
#endif

#elif defined(__AVX__) && DES_BS_DEPTH == 512
#include <immintrin.h>

typedef struct {
/* Not __m256i because bitwise ops are "floating-point" with AVX */
	__m256 f, g;
} vtype;

#define vst(dst, ofs, src) \
	_mm256_store_ps( \
	    (float *)&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	_mm256_store_ps( \
	    (float *)&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g, \
	    (src).g)

#define vxor(dst, a, b) \
	(dst).f = _mm256_xor_ps((a).f, (b).f); \
	(dst).g = _mm256_xor_ps((a).g, (b).g)

#define vand(dst, a, b) \
	(dst).f = _mm256_and_ps((a).f, (b).f); \
	(dst).g = _mm256_and_ps((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = _mm256_or_ps((a).f, (b).f); \
	(dst).g = _mm256_or_ps((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = _mm256_andnot_ps((b).f, (a).f); \
	(dst).g = _mm256_andnot_ps((b).g, (a).g)

#ifdef __XOP__
/* This could be _mm256_cmov_ps(), but it does not exist (yet?) */
#define vsel(dst, a, b, c) \
	(dst).f = __builtin_ia32_vpcmov_v8sf256((b).f, (a).f, (c).f); \
	(dst).g = __builtin_ia32_vpcmov_v8sf256((b).g, (a).g, (c).g)
#endif

#elif defined(__AVX__) && defined(__MMX__) && DES_BS_DEPTH == 320 && \
    !defined(DES_BS_NO_MMX)
#include <immintrin.h>
#include <mmintrin.h>

typedef struct {
/* Not __m256i because bitwise ops are "floating-point" with AVX */
	__m256 f;
	__m64 g;
} vtype;

#define vst(dst, ofs, src) \
	_mm256_store_ps( \
	    (float *)&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm256_xor_ps((a).f, (b).f); \
	(dst).g = _mm_xor_si64((a).g, (b).g)

#define vand(dst, a, b) \
	(dst).f = _mm256_and_ps((a).f, (b).f); \
	(dst).g = _mm_and_si64((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = _mm256_or_ps((a).f, (b).f); \
	(dst).g = _mm_or_si64((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = _mm256_andnot_ps((b).f, (a).f); \
	(dst).g = _mm_andnot_si64((b).g, (a).g)

#elif defined(__AVX__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 320) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 288))
#include <immintrin.h>
#include <mmintrin.h>

typedef struct {
/* Not __m256i because bitwise ops are "floating-point" with AVX */
	__m256 f;
	ARCH_WORD g;
} vtype;

#define vst(dst, ofs, src) \
	_mm256_store_ps( \
	    (float *)&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm256_xor_ps((a).f, (b).f); \
	(dst).g = (a).g ^ (b).g

#define vnot(dst, a) \
	(dst).f = _mm256_xor_ps((a).f, vones.f); \
	(dst).g = ~(a).g
#define vand(dst, a, b) \
	(dst).f = _mm256_and_ps((a).f, (b).f); \
	(dst).g = (a).g & (b).g
#define vor(dst, a, b) \
	(dst).f = _mm256_or_ps((a).f, (b).f); \
	(dst).g = (a).g | (b).g
#define vandn(dst, a, b) \
	(dst).f = _mm256_andnot_ps((b).f, (a).f); \
	(dst).g = (a).g & ~(b).g

#elif defined(__AVX__) && defined(__MMX__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 384) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 352))
#include <immintrin.h>
#include <mmintrin.h>

typedef struct {
/* Not __m256i because bitwise ops are "floating-point" with AVX */
	__m256 f;
	__m64 g;
	ARCH_WORD h;
} vtype;

#define vst(dst, ofs, src) \
	_mm256_store_ps( \
	    (float *)&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g; \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->h = (src).h

#define vxor(dst, a, b) \
	(dst).f = _mm256_xor_ps((a).f, (b).f); \
	(dst).g = _mm_xor_si64((a).g, (b).g); \
	(dst).h = (a).h ^ (b).h

#define vnot(dst, a) \
	(dst).f = _mm256_xor_ps((a).f, vones.f); \
	(dst).g = _mm_xor_si64((a).g, vones.g); \
	(dst).h = ~(a).h
#define vand(dst, a, b) \
	(dst).f = _mm256_and_ps((a).f, (b).f); \
	(dst).g = _mm_and_si64((a).g, (b).g); \
	(dst).h = (a).h & (b).h
#define vor(dst, a, b) \
	(dst).f = _mm256_or_ps((a).f, (b).f); \
	(dst).g = _mm_or_si64((a).g, (b).g); \
	(dst).h = (a).h | (b).h
#define vandn(dst, a, b) \
	(dst).f = _mm256_andnot_ps((b).f, (a).f); \
	(dst).g = _mm_andnot_si64((b).g, (a).g); \
	(dst).h = (a).h & ~(b).h

#elif defined(__SSE2__) && DES_BS_DEPTH == 128
#ifdef __AVX__
#include <immintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#endif
#else
#include <emmintrin.h>
#endif

typedef __m128i vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128((vtype *)((DES_bs_vector *)&(dst) + (ofs)), (src))

#define vxorf(a, b) \
	_mm_xor_si128((a), (b))

#define vand(dst, a, b) \
	(dst) = _mm_and_si128((a), (b))
#define vor(dst, a, b) \
	(dst) = _mm_or_si128((a), (b))
#define vandn(dst, a, b) \
	(dst) = _mm_andnot_si128((b), (a))

#ifdef __XOP__
#define vsel(dst, a, b, c) \
	(dst) = _mm_cmov_si128((b), (a), (c))
#else
#define vsel(dst, a, b, c) \
	(dst) = _mm_xor_si128(_mm_andnot_si128((c), (a)), \
	    _mm_and_si128((c), (b)))
#endif

#elif defined(__SSE2__) && DES_BS_DEPTH == 256 && defined(DES_BS_NO_MMX)
#ifdef __AVX__
#include <immintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#endif
#else
#include <emmintrin.h>
#endif

typedef struct {
	__m128i f, g;
} vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g, \
	    (src).g)

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si128((a).f, (b).f); \
	(dst).g = _mm_xor_si128((a).g, (b).g)

#define vand(dst, a, b) \
	(dst).f = _mm_and_si128((a).f, (b).f); \
	(dst).g = _mm_and_si128((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = _mm_or_si128((a).f, (b).f); \
	(dst).g = _mm_or_si128((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si128((b).f, (a).f); \
	(dst).g = _mm_andnot_si128((b).g, (a).g)

#ifdef __XOP__
#define vsel(dst, a, b, c) \
	(dst).f = _mm_cmov_si128((b).f, (a).f, (c).f); \
	(dst).g = _mm_cmov_si128((b).g, (a).g, (c).g)
#endif

#elif defined(__SSE2__) && defined(__MMX__) && DES_BS_DEPTH == 192 && \
    !defined(DES_BS_NO_MMX)
#include <emmintrin.h>
#include <mmintrin.h>

typedef struct {
	__m128i f;
	__m64 g;
} vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si128((a).f, (b).f); \
	(dst).g = _mm_xor_si64((a).g, (b).g)

#define vand(dst, a, b) \
	(dst).f = _mm_and_si128((a).f, (b).f); \
	(dst).g = _mm_and_si64((a).g, (b).g)
#define vor(dst, a, b) \
	(dst).f = _mm_or_si128((a).f, (b).f); \
	(dst).g = _mm_or_si64((a).g, (b).g)
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si128((b).f, (a).f); \
	(dst).g = _mm_andnot_si64((b).g, (a).g)

#elif defined(__SSE2__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 192) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 160))
#include <emmintrin.h>

typedef struct {
	__m128i f;
	ARCH_WORD g;
} vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si128((a).f, (b).f); \
	(dst).g = (a).g ^ (b).g

#define vnot(dst, a) \
	(dst).f = _mm_xor_si128((a).f, vones.f); \
	(dst).g = ~(a).g
#define vand(dst, a, b) \
	(dst).f = _mm_and_si128((a).f, (b).f); \
	(dst).g = (a).g & (b).g
#define vor(dst, a, b) \
	(dst).f = _mm_or_si128((a).f, (b).f); \
	(dst).g = (a).g | (b).g
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si128((b).f, (a).f); \
	(dst).g = (a).g & ~(b).g

#elif defined(__SSE2__) && defined(__MMX__) && \
    ((ARCH_BITS == 64 && DES_BS_DEPTH == 256) || \
    (ARCH_BITS == 32 && DES_BS_DEPTH == 224))
#include <emmintrin.h>
#include <mmintrin.h>

typedef struct {
	__m128i f;
	__m64 g;
	ARCH_WORD h;
} vtype;

#define vst(dst, ofs, src) \
	_mm_store_si128(&((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f, \
	    (src).f); \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g; \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->h = (src).h

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si128((a).f, (b).f); \
	(dst).g = _mm_xor_si64((a).g, (b).g); \
	(dst).h = (a).h ^ (b).h

#define vnot(dst, a) \
	(dst).f = _mm_xor_si128((a).f, vones.f); \
	(dst).g = _mm_xor_si64((a).g, vones.g); \
	(dst).h = ~(a).h
#define vand(dst, a, b) \
	(dst).f = _mm_and_si128((a).f, (b).f); \
	(dst).g = _mm_and_si64((a).g, (b).g); \
	(dst).h = (a).h & (b).h
#define vor(dst, a, b) \
	(dst).f = _mm_or_si128((a).f, (b).f); \
	(dst).g = _mm_or_si64((a).g, (b).g); \
	(dst).h = (a).h | (b).h
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si128((b).f, (a).f); \
	(dst).g = _mm_andnot_si64((b).g, (a).g); \
	(dst).h = (a).h & ~(b).h

#elif defined(__MMX__) && ARCH_BITS != 64 && DES_BS_DEPTH == 64
#include <mmintrin.h>

typedef __m64 vtype;

#define vxorf(a, b) \
	_mm_xor_si64((a), (b))

#define vand(dst, a, b) \
	(dst) = _mm_and_si64((a), (b))
#define vor(dst, a, b) \
	(dst) = _mm_or_si64((a), (b))
#define vandn(dst, a, b) \
	(dst) = _mm_andnot_si64((b), (a))

#elif defined(__MMX__) && ARCH_BITS == 32 && DES_BS_DEPTH == 96
#include <mmintrin.h>

typedef struct {
	__m64 f;
	ARCH_WORD g;
} vtype;

#define vst(dst, ofs, src) \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->f = (src).f; \
	((vtype *)((DES_bs_vector *)&(dst) + (ofs)))->g = (src).g

#define vxor(dst, a, b) \
	(dst).f = _mm_xor_si64((a).f, (b).f); \
	(dst).g = (a).g ^ (b).g

#define vnot(dst, a) \
	(dst).f = _mm_xor_si64((a).f, vones.f); \
	(dst).g = ~(a).g
#define vand(dst, a, b) \
	(dst).f = _mm_and_si64((a).f, (b).f); \
	(dst).g = (a).g & (b).g
#define vor(dst, a, b) \
	(dst).f = _mm_or_si64((a).f, (b).f); \
	(dst).g = (a).g | (b).g
#define vandn(dst, a, b) \
	(dst).f = _mm_andnot_si64((b).f, (a).f); \
	(dst).g = (a).g & ~(b).g

#else

#if DES_BS_VECTOR
#define DES_BS_VECTOR_LOOPS
#endif

typedef ARCH_WORD vtype;

#define vxorf(a, b) \
	((a) ^ (b))

#define vnot(dst, a) \
	(dst) = ~(a)
#define vand(dst, a, b) \
	(dst) = (a) & (b)
#define vor(dst, a, b) \
	(dst) = (a) | (b)
#define vandn(dst, a, b) \
	(dst) = (a) & ~(b)
#define vsel(dst, a, b, c) \
	(dst) = (((a) & ~(c)) ^ ((b) & (c)))

#define vshl(dst, src, shift) \
	(dst) = (src) << (shift)
#define vshr(dst, src, shift) \
	(dst) = (src) >> (shift)

/* Archs friendly to use of immediate values */
#ifdef __x86_64__
#define mask01 0x0101010101010101UL
#elif __i386__
#define mask01 0x01010101UL
#else
#undef mask01
#endif

/* Assume that 0 always fits in one load immediate instruction */
#undef vzero
#define vzero 0

#ifdef mask01
#undef vones
#define vones (~(vtype)0)
#define mask02 (mask01 << 1)
#define mask04 (mask01 << 2)
#define mask08 (mask01 << 3)
#define mask10 (mask01 << 4)
#define mask20 (mask01 << 5)
#define mask40 (mask01 << 6)
#define mask80 (mask01 << 7)
#endif

#endif

#ifndef mask01
#define mask01 (*(vtype *)&DES_bs_all.masks[0])
#define mask02 (*(vtype *)&DES_bs_all.masks[1])
#define mask04 (*(vtype *)&DES_bs_all.masks[2])
#define mask08 (*(vtype *)&DES_bs_all.masks[3])
#define mask10 (*(vtype *)&DES_bs_all.masks[4])
#define mask20 (*(vtype *)&DES_bs_all.masks[5])
#define mask40 (*(vtype *)&DES_bs_all.masks[6])
#define mask80 (*(vtype *)&DES_bs_all.masks[7])
#endif

#ifndef vst
#define vst(dst, ofs, src) \
	*((vtype *)((DES_bs_vector *)&(dst) + (ofs))) = (src)
#endif

#if !defined(vxor) && defined(vxorf)
#define vxor(dst, a, b) \
	(dst) = vxorf((a), (b))
#endif
#if !defined(vxorf) && defined(vxor)
/*
 * This requires gcc's "Statement Exprs" extension (also supported by a number
 * of other C compilers).
 */
#define vxorf(a, b) \
	({ vtype tmp; vxor(tmp, (a), (b)); tmp; })
#endif

#ifndef vnot
#define vnot(dst, a) \
	vxor((dst), (a), vones)
#endif

#ifndef vshl
#define vshl(dst, src, shift) { \
	int depth; \
	for (depth = 0; depth < DES_BS_VECTOR; depth++) \
		((unsigned ARCH_WORD *)&(dst))[depth] = \
		    ((unsigned ARCH_WORD *)&(src))[depth] << (shift); \
}
#endif
#ifndef vshr
#define vshr(dst, src, shift) { \
	int depth; \
	for (depth = 0; depth < DES_BS_VECTOR; depth++) \
		((unsigned ARCH_WORD *)&(dst))[depth] = \
		    ((unsigned ARCH_WORD *)&(src))[depth] >> (shift); \
}
#endif

#ifdef __GNUC__
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define MAYBE_INLINE __attribute__((always_inline))
#else
#define MAYBE_INLINE __inline__
#endif
#else
#define MAYBE_INLINE
#endif

/* Include the S-boxes here so that the compiler can inline them */
#if DES_BS == 3
#include "sboxes-s.c"
#elif DES_BS == 2
#include "sboxes.c"
#else
#undef andn
#include "nonstd.c"
#endif

#define b				DES_bs_all.B
#define e				DES_bs_all.E.E

#if DES_BS_VECTOR_LOOPS
#define kd				[depth]
#define bd				[depth]
#define ed				[depth]
#define DEPTH				[depth]
#define for_each_depth() \
	for (depth = 0; depth < DES_BS_VECTOR; depth++)
#else
#if DES_BS_EXPAND
#define kd
#else
#define kd				[0]
#endif
#define bd
#define ed				[0]
#define DEPTH
#define for_each_depth()
#endif

#define DES_bs_clear_block_8(i) \
	for_each_depth() { \
		vst(b[i] bd, 0, zero); \
		vst(b[i] bd, 1, zero); \
		vst(b[i] bd, 2, zero); \
		vst(b[i] bd, 3, zero); \
		vst(b[i] bd, 4, zero); \
		vst(b[i] bd, 5, zero); \
		vst(b[i] bd, 6, zero); \
		vst(b[i] bd, 7, zero); \
	}

#define DES_bs_clear_block \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56);

#define DES_bs_set_block_8(i, v0, v1, v2, v3, v4, v5, v6, v7) \
	for_each_depth() { \
		vst(b[i] bd, 0, v0); \
		vst(b[i] bd, 1, v1); \
		vst(b[i] bd, 2, v2); \
		vst(b[i] bd, 3, v3); \
		vst(b[i] bd, 4, v4); \
		vst(b[i] bd, 5, v5); \
		vst(b[i] bd, 6, v6); \
		vst(b[i] bd, 7, v7); \
	}

#define x(p) vxorf(*(vtype *)&e[p] ed, *(vtype *)&k[p] kd)
#define y(p, q) vxorf(*(vtype *)&b[p] bd, *(vtype *)&k[q] kd)
#define z(r) ((vtype *)&b[r] bd)

void DES_bs_crypt(int count)
{
#if DES_BS_EXPAND
	DES_bs_vector *k;
#else
	ARCH_WORD **k;
#endif
	int iterations, rounds_and_swapped;
#if DES_BS_VECTOR_LOOPS
	int depth;
#endif

	{
		vtype zero = vzero;
		DES_bs_clear_block
	}

#if DES_BS_EXPAND
	k = DES_bs_all.KS.v;
#else
	k = DES_bs_all.KS.p;
#endif
	rounds_and_swapped = 8;
	iterations = count;

start:
	for_each_depth()
	s1(x(0), x(1), x(2), x(3), x(4), x(5),
		z(40), z(48), z(54), z(62));
	for_each_depth()
	s2(x(6), x(7), x(8), x(9), x(10), x(11),
		z(44), z(59), z(33), z(49));
	for_each_depth()
	s3(x(12), x(13), x(14), x(15), x(16), x(17),
		z(55), z(47), z(61), z(37));
	for_each_depth()
	s4(x(18), x(19), x(20), x(21), x(22), x(23),
		z(57), z(51), z(41), z(32));
	for_each_depth()
	s5(x(24), x(25), x(26), x(27), x(28), x(29),
		z(39), z(45), z(56), z(34));
	for_each_depth()
	s6(x(30), x(31), x(32), x(33), x(34), x(35),
		z(35), z(60), z(42), z(50));
	for_each_depth()
	s7(x(36), x(37), x(38), x(39), x(40), x(41),
		z(63), z(43), z(53), z(38));
	for_each_depth()
	s8(x(42), x(43), x(44), x(45), x(46), x(47),
		z(36), z(58), z(46), z(52));

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(x(48), x(49), x(50), x(51), x(52), x(53),
		z(8), z(16), z(22), z(30));
	for_each_depth()
	s2(x(54), x(55), x(56), x(57), x(58), x(59),
		z(12), z(27), z(1), z(17));
	for_each_depth()
	s3(x(60), x(61), x(62), x(63), x(64), x(65),
		z(23), z(15), z(29), z(5));
	for_each_depth()
	s4(x(66), x(67), x(68), x(69), x(70), x(71),
		z(25), z(19), z(9), z(0));
	for_each_depth()
	s5(x(72), x(73), x(74), x(75), x(76), x(77),
		z(7), z(13), z(24), z(2));
	for_each_depth()
	s6(x(78), x(79), x(80), x(81), x(82), x(83),
		z(3), z(28), z(10), z(18));
	for_each_depth()
	s7(x(84), x(85), x(86), x(87), x(88), x(89),
		z(31), z(11), z(21), z(6));
	for_each_depth()
	s8(x(90), x(91), x(92), x(93), x(94), x(95),
		z(4), z(26), z(14), z(20));

	k += 96;

	if (--rounds_and_swapped) goto start;
	k -= (0x300 + 48);
	rounds_and_swapped = 0x108;
	if (--iterations) goto swap;
	return;

next:
	k -= (0x300 - 48);
	rounds_and_swapped = 8;
	if (--iterations) goto start;
}

void DES_bs_crypt_25(void)
{
#if DES_BS_EXPAND
	DES_bs_vector *k;
#else
	ARCH_WORD **k;
#endif
	int iterations, rounds_and_swapped;
#if DES_BS_VECTOR_LOOPS
	int depth;
#endif

	{
		vtype zero = vzero;
		DES_bs_clear_block
	}

#if DES_BS_EXPAND
	k = DES_bs_all.KS.v;
#else
	k = DES_bs_all.KS.p;
#endif
	rounds_and_swapped = 8;
	iterations = 25;

start:
	for_each_depth()
	s1(x(0), x(1), x(2), x(3), x(4), x(5),
		z(40), z(48), z(54), z(62));
	for_each_depth()
	s2(x(6), x(7), x(8), x(9), x(10), x(11),
		z(44), z(59), z(33), z(49));
	for_each_depth()
	s3(y(7, 12), y(8, 13), y(9, 14),
		y(10, 15), y(11, 16), y(12, 17),
		z(55), z(47), z(61), z(37));
	for_each_depth()
	s4(y(11, 18), y(12, 19), y(13, 20),
		y(14, 21), y(15, 22), y(16, 23),
		z(57), z(51), z(41), z(32));
	for_each_depth()
	s5(x(24), x(25), x(26), x(27), x(28), x(29),
		z(39), z(45), z(56), z(34));
	for_each_depth()
	s6(x(30), x(31), x(32), x(33), x(34), x(35),
		z(35), z(60), z(42), z(50));
	for_each_depth()
	s7(y(23, 36), y(24, 37), y(25, 38),
		y(26, 39), y(27, 40), y(28, 41),
		z(63), z(43), z(53), z(38));
	for_each_depth()
	s8(y(27, 42), y(28, 43), y(29, 44),
		y(30, 45), y(31, 46), y(0, 47),
		z(36), z(58), z(46), z(52));

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(x(48), x(49), x(50), x(51), x(52), x(53),
		z(8), z(16), z(22), z(30));
	for_each_depth()
	s2(x(54), x(55), x(56), x(57), x(58), x(59),
		z(12), z(27), z(1), z(17));
	for_each_depth()
	s3(y(39, 60), y(40, 61), y(41, 62),
		y(42, 63), y(43, 64), y(44, 65),
		z(23), z(15), z(29), z(5));
	for_each_depth()
	s4(y(43, 66), y(44, 67), y(45, 68),
		y(46, 69), y(47, 70), y(48, 71),
		z(25), z(19), z(9), z(0));
	for_each_depth()
	s5(x(72), x(73), x(74), x(75), x(76), x(77),
		z(7), z(13), z(24), z(2));
	for_each_depth()
	s6(x(78), x(79), x(80), x(81), x(82), x(83),
		z(3), z(28), z(10), z(18));
	for_each_depth()
	s7(y(55, 84), y(56, 85), y(57, 86),
		y(58, 87), y(59, 88), y(60, 89),
		z(31), z(11), z(21), z(6));
	for_each_depth()
	s8(y(59, 90), y(60, 91), y(61, 92),
		y(62, 93), y(63, 94), y(32, 95),
		z(4), z(26), z(14), z(20));

	k += 96;

	if (--rounds_and_swapped) goto start;
	k -= (0x300 + 48);
	rounds_and_swapped = 0x108;
	if (--iterations) goto swap;
	return;

next:
	k -= (0x300 - 48);
	rounds_and_swapped = 8;
	iterations--;
	goto start;
}

#ifdef __i386__
/* register-starved */
#define LOAD_V \
	vtype v0 = *(vtype *)&vp[0]; \
	vtype v4 = *(vtype *)&vp[4];
#define v1 *(vtype *)&vp[1]
#define v2 *(vtype *)&vp[2]
#define v3 *(vtype *)&vp[3]
#define v5 *(vtype *)&vp[5]
#define v6 *(vtype *)&vp[6]
#define v7 *(vtype *)&vp[7]
#else
#define LOAD_V \
	vtype v0 = *(vtype *)&vp[0]; \
	vtype v1 = *(vtype *)&vp[1]; \
	vtype v2 = *(vtype *)&vp[2]; \
	vtype v3 = *(vtype *)&vp[3]; \
	vtype v4 = *(vtype *)&vp[4]; \
	vtype v5 = *(vtype *)&vp[5]; \
	vtype v6 = *(vtype *)&vp[6]; \
	vtype v7 = *(vtype *)&vp[7];
#endif

#define vand_shl_or(dst, src, mask, shift) \
	vand(tmp, src, mask); \
	vshl(tmp, tmp, shift); \
	vor(dst, dst, tmp)

#define vand_shl(dst, src, mask, shift) \
	vand(tmp, src, mask); \
	vshl(dst, tmp, shift)

#define vand_or(dst, src, mask) \
	vand(tmp, src, mask); \
	vor(dst, dst, tmp)

#define vand_shr_or(dst, src, mask, shift) \
	vand(tmp, src, mask); \
	vshr(tmp, tmp, shift); \
	vor(dst, dst, tmp)

#define vand_shr(dst, src, mask, shift) \
	vand(tmp, src, mask); \
	vshr(dst, tmp, shift)

#define FINALIZE_NEXT_KEY_BIT_0 { \
	vtype m = mask01, va, vb, tmp; \
	vand(va, v0, m); \
	vand_shl(vb, v1, m, 1); \
	vand_shl_or(va, v2, m, 2); \
	vand_shl_or(vb, v3, m, 3); \
	vand_shl_or(va, v4, m, 4); \
	vand_shl_or(vb, v5, m, 5); \
	vand_shl_or(va, v6, m, 6); \
	vand_shl_or(vb, v7, m, 7); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_1 { \
	vtype m = mask02, va, vb, tmp; \
	vand_shr(va, v0, m, 1); \
	vand(vb, v1, m); \
	vand_shl_or(va, v2, m, 1); \
	vand_shl_or(vb, v3, m, 2); \
	vand_shl_or(va, v4, m, 3); \
	vand_shl_or(vb, v5, m, 4); \
	vand_shl_or(va, v6, m, 5); \
	vand_shl_or(vb, v7, m, 6); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_2 { \
	vtype m = mask04, va, vb, tmp; \
	vand_shr(va, v0, m, 2); \
	vand_shr(vb, v1, m, 1); \
	vand_or(va, v2, m); \
	vand_shl_or(vb, v3, m, 1); \
	vand_shl_or(va, v4, m, 2); \
	vand_shl_or(vb, v5, m, 3); \
	vand_shl_or(va, v6, m, 4); \
	vand_shl_or(vb, v7, m, 5); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_3 { \
	vtype m = mask08, va, vb, tmp; \
	vand_shr(va, v0, m, 3); \
	vand_shr(vb, v1, m, 2); \
	vand_shr_or(va, v2, m, 1); \
	vand_or(vb, v3, m); \
	vand_shl_or(va, v4, m, 1); \
	vand_shl_or(vb, v5, m, 2); \
	vand_shl_or(va, v6, m, 3); \
	vand_shl_or(vb, v7, m, 4); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_4 { \
	vtype m = mask10, va, vb, tmp; \
	vand_shr(va, v0, m, 4); \
	vand_shr(vb, v1, m, 3); \
	vand_shr_or(va, v2, m, 2); \
	vand_shr_or(vb, v3, m, 1); \
	vand_or(va, v4, m); \
	vand_shl_or(vb, v5, m, 1); \
	vand_shl_or(va, v6, m, 2); \
	vand_shl_or(vb, v7, m, 3); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_5 { \
	vtype m = mask20, va, vb, tmp; \
	vand_shr(va, v0, m, 5); \
	vand_shr(vb, v1, m, 4); \
	vand_shr_or(va, v2, m, 3); \
	vand_shr_or(vb, v3, m, 2); \
	vand_shr_or(va, v4, m, 1); \
	vand_or(vb, v5, m); \
	vand_shl_or(va, v6, m, 1); \
	vand_shl_or(vb, v7, m, 2); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_6 { \
	vtype m = mask40, va, vb, tmp; \
	vand_shr(va, v0, m, 6); \
	vand_shr(vb, v1, m, 5); \
	vand_shr_or(va, v2, m, 4); \
	vand_shr_or(vb, v3, m, 3); \
	vand_shr_or(va, v4, m, 2); \
	vand_shr_or(vb, v5, m, 1); \
	vand_or(va, v6, m); \
	vand_shl_or(vb, v7, m, 1); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_7 { \
	vtype m = mask80, va, vb, tmp; \
	vand_shr(va, v0, m, 7); \
	vand_shr(vb, v1, m, 6); \
	vand_shr_or(va, v2, m, 5); \
	vand_shr_or(vb, v3, m, 4); \
	vand_shr_or(va, v4, m, 3); \
	vand_shr_or(vb, v5, m, 2); \
	vand_shr_or(va, v6, m, 1); \
	vand_or(vb, v7, m); \
	vor(*(vtype *)kp, va, vb); \
	kp++; \
}

void DES_bs_finalize_keys(void)
{
#if DES_BS_VECTOR_LOOPS
	int depth;
#endif

	if (!DES_bs_all.keys_changed)
		return;
	DES_bs_all.keys_changed = 0;

	for_each_depth() {
		DES_bs_vector *kp = (DES_bs_vector *)&DES_bs_all.K[0] DEPTH;
		int ic;
		for (ic = 0; ic < 8; ic++) {
			DES_bs_vector *vp =
			    (DES_bs_vector *)&DES_bs_all.xkeys.v[ic][0] DEPTH;
			LOAD_V
			FINALIZE_NEXT_KEY_BIT_0
			FINALIZE_NEXT_KEY_BIT_1
			FINALIZE_NEXT_KEY_BIT_2
			FINALIZE_NEXT_KEY_BIT_3
			FINALIZE_NEXT_KEY_BIT_4
			FINALIZE_NEXT_KEY_BIT_5
			FINALIZE_NEXT_KEY_BIT_6
		}
	}

#if DES_BS_EXPAND
	{
		int index;
		for (index = 0; index < 0x300; index++)
		for_each_depth() {
#if DES_BS_VECTOR_LOOPS
			DES_bs_all.KS.v[index] DEPTH =
			    DES_bs_all.KSp[index] DEPTH;
#else
			vst(*(vtype *)&DES_bs_all.KS.v[index], 0,
			    *(vtype *)DES_bs_all.KSp[index]);
#endif
		}
	}
#endif
}

void DES_bs_finalize_keys_LM(void)
{
#if DES_BS_VECTOR_LOOPS
	int depth;
#endif

	for_each_depth() {
		DES_bs_vector *kp = (DES_bs_vector *)&DES_bs_all.K[0] DEPTH;
		int ic;
		for (ic = 0; ic < 7; ic++) {
			DES_bs_vector *vp =
			    (DES_bs_vector *)&DES_bs_all.xkeys.v[ic][0] DEPTH;
			LOAD_V
			FINALIZE_NEXT_KEY_BIT_0
			FINALIZE_NEXT_KEY_BIT_1
			FINALIZE_NEXT_KEY_BIT_2
			FINALIZE_NEXT_KEY_BIT_3
			FINALIZE_NEXT_KEY_BIT_4
			FINALIZE_NEXT_KEY_BIT_5
			FINALIZE_NEXT_KEY_BIT_6
			FINALIZE_NEXT_KEY_BIT_7
		}
	}
}

#undef v1
#undef v2
#undef v3
#undef v5
#undef v6
#undef v7

#undef x

#undef kd
#if DES_BS_VECTOR_LOOPS
#define kd				[depth]
#else
#define kd				[0]
#endif

void DES_bs_crypt_LM(void)
{
	ARCH_WORD **k;
	int rounds;
#if DES_BS_VECTOR_LOOPS
	int depth;
#endif

	{
		vtype z = vzero, o = vones;
		DES_bs_set_block_8(0, z, z, z, z, z, z, z, z);
		DES_bs_set_block_8(8, o, o, o, z, o, z, z, z);
		DES_bs_set_block_8(16, z, z, z, z, z, z, z, o);
		DES_bs_set_block_8(24, z, z, o, z, z, o, o, o);
		DES_bs_set_block_8(32, z, z, z, o, z, o, o, o);
		DES_bs_set_block_8(40, z, z, z, z, z, o, z, z);
		DES_bs_set_block_8(48, o, o, z, z, z, z, o, z);
		DES_bs_set_block_8(56, o, z, o, z, o, o, o, o);
	}

	k = DES_bs_all.KS.p;
	rounds = 8;

	do {
		for_each_depth()
		s1(y(31, 0), y(0, 1), y(1, 2),
			y(2, 3), y(3, 4), y(4, 5),
			z(40), z(48), z(54), z(62));
		for_each_depth()
		s2(y(3, 6), y(4, 7), y(5, 8),
			y(6, 9), y(7, 10), y(8, 11),
			z(44), z(59), z(33), z(49));
		for_each_depth()
		s3(y(7, 12), y(8, 13), y(9, 14),
			y(10, 15), y(11, 16), y(12, 17),
			z(55), z(47), z(61), z(37));
		for_each_depth()
		s4(y(11, 18), y(12, 19), y(13, 20),
			y(14, 21), y(15, 22), y(16, 23),
			z(57), z(51), z(41), z(32));
		for_each_depth()
		s5(y(15, 24), y(16, 25), y(17, 26),
			y(18, 27), y(19, 28), y(20, 29),
			z(39), z(45), z(56), z(34));
		for_each_depth()
		s6(y(19, 30), y(20, 31), y(21, 32),
			y(22, 33), y(23, 34), y(24, 35),
			z(35), z(60), z(42), z(50));
		for_each_depth()
		s7(y(23, 36), y(24, 37), y(25, 38),
			y(26, 39), y(27, 40), y(28, 41),
			z(63), z(43), z(53), z(38));
		for_each_depth()
		s8(y(27, 42), y(28, 43), y(29, 44),
			y(30, 45), y(31, 46), y(0, 47),
			z(36), z(58), z(46), z(52));

		for_each_depth()
		s1(y(63, 48), y(32, 49), y(33, 50),
			y(34, 51), y(35, 52), y(36, 53),
			z(8), z(16), z(22), z(30));
		for_each_depth()
		s2(y(35, 54), y(36, 55), y(37, 56),
			y(38, 57), y(39, 58), y(40, 59),
			z(12), z(27), z(1), z(17));
		for_each_depth()
		s3(y(39, 60), y(40, 61), y(41, 62),
			y(42, 63), y(43, 64), y(44, 65),
			z(23), z(15), z(29), z(5));
		for_each_depth()
		s4(y(43, 66), y(44, 67), y(45, 68),
			y(46, 69), y(47, 70), y(48, 71),
			z(25), z(19), z(9), z(0));
		for_each_depth()
		s5(y(47, 72), y(48, 73), y(49, 74),
			y(50, 75), y(51, 76), y(52, 77),
			z(7), z(13), z(24), z(2));
		for_each_depth()
		s6(y(51, 78), y(52, 79), y(53, 80),
			y(54, 81), y(55, 82), y(56, 83),
			z(3), z(28), z(10), z(18));
		for_each_depth()
		s7(y(55, 84), y(56, 85), y(57, 86),
			y(58, 87), y(59, 88), y(60, 89),
			z(31), z(11), z(21), z(6));
		for_each_depth()
		s8(y(59, 90), y(60, 91), y(61, 92),
			y(62, 93), y(63, 94), y(32, 95),
			z(4), z(26), z(14), z(20));

		k += 96;
	} while (--rounds);
}
#endif
