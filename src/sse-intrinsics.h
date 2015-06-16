/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Some modifications, Jim Fougeron, 2013.  Licensing rights listed in accompanying sse-intrinsics.c file.
 */

#if !defined (__JTR_SSE_INTRINSICS_H__)
#define __JTR_SSE_INTRINSICS_H__

#if (SIMD_COEF_32 && SIMD_COEF_32 == 2) || !SIMD_COEF_32
#undef SIMD_TYPE
#define SIMD_TYPE			""
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
#undef SIMD_TYPE
#define SIMD_TYPE            "MIC"
#elif __AVX512__
#undef SIMD_TYPE
#define SIMD_TYPE            "AVX512"
#elif __AVX2__
#undef SIMD_TYPE
#define SIMD_TYPE            "AVX2"
#elif __XOP__
#undef SIMD_TYPE
#define SIMD_TYPE            "XOP"
#elif __AVX__
#undef SIMD_TYPE
#define SIMD_TYPE            "AVX"
#elif __SSE4_1__
#undef SIMD_TYPE
#define SIMD_TYPE            "SSE4.1"
#elif __SSSE3__
#undef SIMD_TYPE
#define SIMD_TYPE            "SSSE3"
#elif __SSE2__
#undef SIMD_TYPE
#define SIMD_TYPE            "SSE2"
#elif SIMD_COEF_32
#define SIMD_TYPE            "MMX" // not really supported
#endif

#if SIMD_COEF_32 == 16
#define BITS				"512/512"
#elif SIMD_COEF_32 == 8
#define BITS				"256/256"
#elif SIMD_COEF_32 == 4
#define BITS				"128/128"
#elif SIMD_COEF_32 == 2
#define BITS				"64/64"
#endif

#ifdef SIMD_PARA_MD5
void md5cryptsse(unsigned char *buf, unsigned char *salt, char *out, unsigned int md5_type);
void SSEmd5body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define MD5_ALGORITHM_NAME		BITS " " SIMD_TYPE " " MD5_N_STR
#else
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SIMD_PARA_MD4
//void SSEmd4body(__m128i* data, unsigned int *out, int init);
void SSEmd4body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define MD4_ALGORITHM_NAME		BITS " " SIMD_TYPE " " MD4_N_STR
#else
#define MD4_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SIMD_PARA_SHA1
void SSESHA1body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define SHA1_ALGORITHM_NAME		BITS " " SIMD_TYPE " " SHA1_N_STR
#else
#define SHA1_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

// we use the 'outter' SIMD_COEF_32 wrapper, as the flag for SHA256/SHA512.  FIX_ME!!
#if SIMD_COEF_32 > 1

#ifdef SIMD_COEF_32
#define SHA256_ALGORITHM_NAME	BITS " " SIMD_TYPE " " SHA256_N_STR
void SSESHA256body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#endif

#ifdef SIMD_COEF_64
#define SHA512_ALGORITHM_NAME	BITS " " SIMD_TYPE " " SHA512_N_STR
void SSESHA512body(vtype* data, ARCH_WORD_64 *out, ARCH_WORD_64 *reload_state, unsigned SSEi_flags);
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

#undef vtype /* void */

#endif // __JTR_SSE_INTRINSICS_H__
