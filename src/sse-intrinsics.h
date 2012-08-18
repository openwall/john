/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */
#ifndef _EMMINTRIN_H_INCLUDED
#define __m128i void
#endif

#if defined(__XOP__)
#define SSE_type			"XOP intrinsics"
#elif defined(__AVX__)
#define SSE_type			"AVX intrinsics"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define SSE_type			"MMX"
#else
#define SSE_type			"SSE2 intrinsics"
#endif

#ifdef MD5_SSE_PARA
void md5cryptsse(unsigned char * buf, unsigned char * salt, char * out, int md5_type);
void SSEmd5body(__m128i* data, unsigned int * out, int init);
#define MD5_SSE_type			SSE_type
#define MD5_ALGORITHM_NAME		"128/128 " MD5_SSE_type " " MD5_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define MD5_SSE_type			"SSE2"
#define MD5_ALGORITHM_NAME		"128/128 " MD5_SSE_type " 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define MD5_SSE_type			"MMX"
#define MD5_ALGORITHM_NAME		"64/64 " MD5_SSE_type " 2x"
#elif defined(MMX_COEF)
#define MD5_SSE_type			"?"
#define MD5_ALGORITHM_NAME		MD5_SSE_type
#else
#define MD5_SSE_type			"1x"
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef MD4_SSE_PARA
void SSEmd4body(__m128i* data, unsigned int * out, int init);
#define MD4_SSE_type			SSE_type
#define MD4_ALGORITHM_NAME		"128/128 " MD4_SSE_type " " MD4_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define MD4_SSE_type			"SSE2"
#define MD4_ALGORITHM_NAME		"128/128 " MD4_SSE_type " 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define MD4_SSE_type			"MMX"
#define MD4_ALGORITHM_NAME		"64/64 " MD4_SSE_type " 2x"
#elif defined(MMX_COEF)
#define MD4_SSE_type			"?"
#define MD4_ALGORITHM_NAME		MD4_SSE_type
#else
#define MD4_SSE_type			"1x"
#define MD4_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#ifdef SHA1_SSE_PARA
void SSESHA1body(__m128i* data, unsigned int * out, unsigned int * reload_state, int input_layout_output); // if reload_state null, then 'normal' init performed.
#define SHA1_SSE_type			SSE_type
#define SHA1_ALGORITHM_NAME		"128/128 " SHA1_SSE_type " " SHA1_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define SHA1_SSE_type			"SSE2"
#define SHA1_ALGORITHM_NAME		"128/128 " SHA1_SSE_type " 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define SHA1_SSE_type			"MMX"
#define SHA1_ALGORITHM_NAME		"64/64 " SHA1_SSE_type " 2x"
#elif defined(MMX_COEF)
#define SHA1_SSE_type			"?"
#define SHA1_ALGORITHM_NAME		SHA1_SSE_type
#else
#define SHA1_SSE_type			"1x"
#define SHA1_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif
