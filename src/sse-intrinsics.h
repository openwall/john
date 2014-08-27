/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Some modifications, Jim Fougeron, 2013.  Licensing rights listed in accompanying sse-intrinsics.c file.
 */

#if !defined (__JTR_SSE_INTRINSICS_H__)
#define __JTR_SSE_INTRINSICS_H__

#if (MMX_COEF && MMX_COEF == 2) || !MMX_COEF
#undef SSE_type
#define SSE_type			"x86"
#undef MMX_COEF
#endif

#include "common.h"
#include "sse-intrinsics-load-flags.h"
#include "aligned.h"

#ifndef _EMMINTRIN_H_INCLUDED
#define __m128i void
#endif

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#if defined(__XOP__)
#undef SSE_type
#define SSE_type			"XOP"
#elif defined(__AVX__)
#undef SSE_type
#define SSE_type			"AVX"
#elif defined(__SSE4_1__)
#undef SSE_type
#define SSE_type			"SSE4.1"
#elif defined(__SSSE3__)
#undef SSE_type
#define SSE_type			"SSSE3"
#elif MMX_COEF
#undef SSE_type
#define SSE_type			"SSE2"
#endif

#ifdef MD5_SSE_PARA
void md5cryptsse(unsigned char * buf, unsigned char * salt, char * out, int md5_type);
void SSEmd5body(__m128i* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define MD5_SSE_type			SSE_type
#define MD5_ALGORITHM_NAME		"128/128 " MD5_SSE_type " " MD5_N_STR
#else
#define MD5_SSE_type			"1x"
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef MD4_SSE_PARA
//void SSEmd4body(__m128i* data, unsigned int * out, int init);
void SSEmd4body(__m128i* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define MD4_SSE_type			SSE_type
#define MD4_ALGORITHM_NAME		"128/128 " MD4_SSE_type " " MD4_N_STR
#else
#define MD4_SSE_type			"1x"
#define MD4_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SHA1_SSE_PARA
void SSESHA1body(__m128i* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
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

// we use the 'outter' MMX_COEF wrapper, as the flag for SHA256/SHA512.  FIX_ME!!
#if MMX_COEF==4

#ifdef MMX_COEF_SHA256
#define SHA256_ALGORITHM_NAME	"128/128 " SIMD_TYPE " " STRINGIZE(MMX_COEF_SHA256)"x"
void SSESHA256body(__m128i* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags);
#define SHA256_BUF_SIZ 16
#define SHA256_SSE_PARA 1
#endif

#ifdef MMX_COEF_SHA512
#define SHA512_ALGORITHM_NAME	"128/128 " SIMD_TYPE " " STRINGIZE(MMX_COEF_SHA512)"x"
void SSESHA512body(__m128i* data, ARCH_WORD_64 *out, ARCH_WORD_64 *reload_state, unsigned SSEi_flags);
// ????  (16 long longs).
#define SHA512_BUF_SIZ 16
#define SHA512_SSE_PARA 1
#endif

#endif

#endif // __JTR_SSE_INTRINSICS_H__
