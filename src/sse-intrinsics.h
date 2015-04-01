/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Some modifications, Jim Fougeron, 2013.  Licensing rights listed in accompanying sse-intrinsics.c file.
 */

#if !defined (__JTR_SSE_INTRINSICS_H__)
#define __JTR_SSE_INTRINSICS_H__

#if (SIMD_COEF_32 && SIMD_COEF_32 == 2) || !SIMD_COEF_32
#undef SSE_type
#define SSE_type			"x86"
#undef SIMD_COEF_32
#endif

#include "common.h"
#include "pseudo_intrinsics.h"
#include "sse-intrinsics-load-flags.h"
#include "aligned.h"

#ifndef _EMMINTRIN_H_INCLUDED
#define __m128i void
#endif
#define vtype void

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#if __MIC__
#undef SSE_type
#define SSE_type			"MIC"
#elif __AVX512__
#undef SSE_type
#define SSE_type			"AVX512"
#elif __AVX2__
#undef SSE_type
#define SSE_type			"AVX2"
#elif defined(__XOP__)
#undef SSE_type
#define SSE_type			"XOP"
//#elif defined(__AVX__) /* We actually only use up to SSE4.1, or AVX2+ */
//#undef SSE_type
//#define SSE_type			"AVX"
#elif defined(__SSE4_1__)
#undef SSE_type
#define SSE_type			"SSE4.1"
#elif defined(__SSSE3__)
#undef SSE_type
#define SSE_type			"SSSE3"
#elif SIMD_COEF_32
#undef SSE_type
#define SSE_type			"SSE2"
#endif

#ifdef MD5_SSE_PARA
void md5cryptsse(unsigned char * buf, unsigned char * salt, char * out, int md5_type);
void SSEmd5body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define MD5_SSE_type			SSE_type
#define MD5_ALGORITHM_NAME		"128/128 " MD5_SSE_type " " MD5_N_STR
#else
#define MD5_SSE_type			"1x"
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef MD4_SSE_PARA
//void SSEmd4body(__m128i* data, unsigned int * out, int init);
void SSEmd4body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define MD4_SSE_type			SSE_type
#define MD4_ALGORITHM_NAME		"128/128 " MD4_SSE_type " " MD4_N_STR
#else
#define MD4_SSE_type			"1x"
#define MD4_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SHA1_SSE_PARA
void SSESHA1body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define SHA1_SSE_type			SSE_type
#define SHA1_ALGORITHM_NAME		"128/128 " SHA1_SSE_type " " SHA1_N_STR
#else
#define SHA1_SSE_type			"1x"
#define SHA1_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

// code for SHA256 and SHA512 (from rawSHA256_ng_fmt.c and rawSHA512_ng_fmt.c)

#if defined __XOP__
#define SIMD_TYPE                 "XOP"
#elif defined __SSE4_1__
#define SIMD_TYPE                 "SSE4.1"
#elif defined __SSSE3__
#define SIMD_TYPE                 "SSSE3"
#else
#define SIMD_TYPE                 "SSE2"
#endif

// we use the 'outter' SIMD_COEF_32 wrapper, as the flag for SHA256/SHA512.  FIX_ME!!
#if SIMD_COEF_32 > 1

#ifdef SIMD_COEF_32
#define SHA256_ALGORITHM_NAME	"128/128 " SIMD_TYPE " " STRINGIZE(SIMD_COEF_32)"x"
void SSESHA256body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define SHA256_BUF_SIZ 16
#define SIMD_PARA_SHA256 1
#endif

#ifdef SIMD_COEF_64
#define SHA512_ALGORITHM_NAME	"128/128 " SIMD_TYPE " " STRINGIZE(SIMD_COEF_64)"x"
void SSESHA512body(vtype* data, ARCH_WORD_64 *out, ARCH_WORD_64 *reload_state, unsigned SSEi_flags);
// ????  (16 long longs).
#define SHA512_BUF_SIZ 16
#define SIMD_PARA_SHA512 1
#endif

#else
#if ARCH_BITS >= 64
#define SHA256_ALGORITHM_NAME                 "64/" ARCH_BITS_STR " " SHA2_LIB
#define SHA512_ALGORITHM_NAME                 "64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define SHA256_ALGORITHM_NAME                 "32/" ARCH_BITS_STR " " SHA2_LIB
#define SHA512_ALGORITHM_NAME                 "32/" ARCH_BITS_STR " " SHA2_LIB
#endif

#endif

#endif // __JTR_SSE_INTRINSICS_H__
