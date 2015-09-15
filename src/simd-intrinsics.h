/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Some modifications, Jim Fougeron, 2013.  Licensing rights listed in accompanying simd-intrinsics.c file.
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
#include "simd-intrinsics-load-flags.h"
#include "aligned.h"

#ifndef _EMMINTRIN_H_INCLUDED
#define __m128i void
#endif
#define vtype void

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#if __ALTIVEC__
#undef SIMD_TYPE
#define SIMD_TYPE            "AltiVec"
#elif __ARM_NEON__
#undef SIMD_TYPE
#define SIMD_TYPE            "NEON"
#elif __MIC__
#undef SIMD_TYPE
#define SIMD_TYPE            "MIC"
#elif __AVX512F__
#undef SIMD_TYPE
#define SIMD_TYPE            "AVX512F"
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
void SIMDmd5body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
void md5_reverse(uint32_t *hash);
void md5_unreverse(uint32_t *hash);
#define MD5_ALGORITHM_NAME		BITS " " SIMD_TYPE " " MD5_N_STR
#else
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SIMD_PARA_MD4
//void SIMDmd4body(__m128i* data, unsigned int *out, int init);
void SIMDmd4body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
void md4_reverse(uint32_t *hash);
void md4_unreverse(uint32_t *hash);
#define MD4_ALGORITHM_NAME		BITS " " SIMD_TYPE " " MD4_N_STR
#else
#define MD4_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SIMD_PARA_SHA1
void SIMDSHA1body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
void sha1_reverse(uint32_t *hash);
void sha1_unreverse(uint32_t *hash);
#define SHA1_ALGORITHM_NAME		BITS " " SIMD_TYPE " " SHA1_N_STR
#else
#define SHA1_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

// we use the 'outter' SIMD_COEF_32 wrapper, as the flag for SHA256/SHA512.  FIX_ME!!
#if SIMD_COEF_32 > 1

#ifdef SIMD_COEF_32
#define SHA256_ALGORITHM_NAME	BITS " " SIMD_TYPE " " SHA256_N_STR
void SIMDSHA256body(vtype* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
void sha224_reverse(uint32_t *hash);
void sha224_unreverse(uint32_t *hash);
void sha256_reverse(uint32_t *hash);
void sha256_unreverse(uint32_t *hash);
#endif

#ifdef SIMD_COEF_64
#define SHA512_ALGORITHM_NAME	BITS " " SIMD_TYPE " " SHA512_N_STR
void SIMDSHA512body(vtype* data, ARCH_WORD_64 *out, ARCH_WORD_64 *reload_state, unsigned SSEi_flags);
void sha384_reverse(ARCH_WORD_64 *hash);
void sha384_unreverse(ARCH_WORD_64 *hash);
void sha512_reverse(ARCH_WORD_64 *hash);
void sha512_unreverse(ARCH_WORD_64 *hash);
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
