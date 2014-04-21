/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * New (optional) SHA1 version by JimF 2011, using 16x4 buffer. This change, and
 * all other modifications to this file by Jim are released with the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2011 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Use of XOP intrinsics added by Solar Designer, 2012.
 *
 * SHA-2 Copyright 2013, epixoip. Redistribution and use in source and binary
 * forms, with or without modification, are permitted provided that
 * redistribution of source retains the above copyright.
 *
 * JimF, 2013:
 * Rewrote SHA-256 function code These improvements over original code found in
 * rawSHA256_ng_fmt.c (copywrite epixoip) are:
 *    SHA256 and SHA224 support.
 *    Multi block support (reload state from prior crypt)
 *    handle either flat, and SSE interleaved input buffers.
 *    Optional un-BE of results (normally not done).
 *    integration support (simply include "sse-intrinsics.h"
 *    #defines for algorithm name
 *    Output is in interleaved SSE format.
 *    OMP safe (output structure would have been a problem as implemented in
 *    raw_SHA256_ng_fmt.c) Code only requires [16] element array.  Original
 *    code required [64] elements. Optionally perform final +=.  This can be
 *    eliminated, and only done at binary load (by doing a minus equal there
 *    of the IV). It only works on 1 limb crypts.
 * Ported SHA512, added SHA384.  Code still 50% original epixoip code (from
 *    raw-SHA512_ng_fmt.c) added all setup and tear down logic, to do multi-block,
 *    sha384, flat or interleaved, OMP safe optional un-BE, optional final add of
 *    original vector (the +=).
 */

#include "arch.h"
#include <string.h>
#include <emmintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#elif defined __SSE4_1__
#include <smmintrin.h>
#elif defined __SSSE3__
#include <tmmintrin.h>
#endif

#include "memory.h"
#include "md5.h"
#include "MD5_std.h"
#include "stdint.h"
#include "johnswap.h"
#include "sse-intrinsics-load-flags.h"
#include "aligned.h"

#include "memdbg.h"

#if defined (_MSC_VER) && !defined (_M_X64)
/* These are slow, but the F'n 32 bit compiler will not build these intrinsics.
   Only the 64-bit (Win64) MSVC compiler has these as intrinsics. These slow
   ones let me debug, and develop this code, and work, but use CPU */
_inline __m128i _mm_set_epi64x (long long a, long long b)
{
	__m128i x; x.m128i_i64[0] = b; x.m128i_i64[1] = a;
	return x;
}
_inline __m128i _mm_set1_epi64x(long long a)
{
	__m128i x; x.m128i_i64[0] = x.m128i_i64[1] = a;
	return x;
}
#endif

#if defined(__GNUC__) && !defined(__INTEL_COMPILER) && !defined(__clang__) && !defined(__llvm__) && !defined (_MSC_VER)
#pragma GCC optimize 3
#endif

#ifdef __XOP__
// for non XOP, we have a 'special' 16 bit roti. So we simply define
// it back to the real roti intrinsic.
#define _mm_roti16_epi32	_mm_roti_epi32
#else
  #define _mm_slli_epi32a(a, s)		\
	((s) == 1 ?						\
		_mm_add_epi32((a), (a))		\
	:								\
		_mm_slli_epi32((a), (s)))

  #define _mm_cmov_si128(y,z,x)		\
	(_mm_xor_si128(z, _mm_and_si128(x, _mm_xor_si128 (y,z))))

  // XOP roti must handle both ROTL and ROTR. If s < 0, then ROTR. Else ROTL
  // There's a specialized rotate16, which is specialized for ssse3+
  #define _mm_roti_epi32(a, s)													\
	((s) < 0 ?																	\
		_mm_or_si128(_mm_srli_epi32((a), ~(s)+1), _mm_slli_epi32a((a),32+(s)))	\
	:																			\
		_mm_or_si128(_mm_slli_epi32a((a), (s)), _mm_srli_epi32((a), 32-(s))))

  // 64 bit roti  (both ROTL and ROTR handled)
  #define _mm_roti_epi64(a, s)													\
	((s) < 0 ?																	\
		_mm_or_si128(_mm_srli_epi64((a), ~(s)+1), _mm_slli_epi64((a),64+(s)))	\
	:																			\
		_mm_or_si128(_mm_slli_epi64((a), (s)), _mm_srli_epi64((a), 64-(s))))

  #ifdef __SSSE3__
    #define rot16_mask				\
		_mm_set_epi32(0x0d0c0f0e, 0x09080b0a, 0x05040706, 0x01000302)

    #define _mm_roti16_epi32(a,s)	\
		(_mm_shuffle_epi8((a), rot16_mask))
  #else
    #define _mm_roti16_epi32(a,s)		\
		(_mm_shufflelo_epi16(_mm_shufflehi_epi16((a), 0xb1), 0xb1))
  #endif
#endif

#ifdef __SSSE3__

#ifndef __XOP__
  #define rot16_mask				\
	_mm_set_epi32(0x0d0c0f0e, 0x09080b0a, 0x05040706, 0x01000302)

  #define _mm_roti16_epi32(a,s)	\
	(_mm_shuffle_epi8((a), rot16_mask))
#endif

  #define swap_endian_mask		\
	_mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203)
  #define swap_endian64_mask		\
	_mm_set_epi64x(0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL)

  #define SWAP_ENDIAN(n)			\
	(n = _mm_shuffle_epi8(n, swap_endian_mask))
  #define SWAP_ENDIAN64(n)		\
	(n = _mm_shuffle_epi8(n, swap_endian64_mask))
 #else
  #define SWAP_ENDIAN(n)			\
	(n = _mm_xor_si128(				\
		_mm_srli_epi16(				\
			_mm_roti16_epi32(n,16), 8),	\
			_mm_slli_epi16(_mm_roti16_epi32(n,16), 8)))
  #define SWAP_ENDIAN64(n)                                                \
  {                                                                       \
    n = _mm_shufflehi_epi16 (_mm_shufflelo_epi16 (n, 0xb1), 0xb1);        \
    n = _mm_xor_si128 (_mm_slli_epi16 (n, 8), _mm_srli_epi16 (n, 8));     \
    n = _mm_shuffle_epi32 (n, 0xb1);                                      \
  }
#endif

#ifdef __SSE4_1__
#define GATHER_4x(x, y, z)                      \
{                                               \
    x = _mm_cvtsi32_si128 (   y[z]   );         \
    x = _mm_insert_epi32  (x, y[z+(1<<6)], 1);  \
    x = _mm_insert_epi32  (x, y[z+(2<<6)], 2);  \
    x = _mm_insert_epi32  (x, y[z+(3<<6)], 3);  \
}
#define GATHER_2x(x, y, z)                      \
{                                               \
    x = _mm_cvtsi32_si128 (   y[z]   );         \
    x = _mm_insert_epi32  (x, y[z+(1<<5)], 1);  \
    x = _mm_insert_epi32  (x, y[z+(2<<5)], 2);  \
    x = _mm_insert_epi32  (x, y[z+(3<<5)], 3);  \
}
#define GATHER(x, y, z)                         \
{                                               \
    x = _mm_cvtsi32_si128 (   y[z]   );    \
    x = _mm_insert_epi32  (x, y[z+(1<<4)], 1);  \
    x = _mm_insert_epi32  (x, y[z+(2<<4)], 2);  \
    x = _mm_insert_epi32  (x, y[z+(3<<4)], 3);  \
}
#endif
#define GATHER64(x,y,z)		{x = _mm_set_epi64x (y[1][z], y[0][z]);}


#ifndef MMX_COEF
#define MMX_COEF 4
#endif

#ifdef MD5_SSE_PARA
#define MD5_SSE_NUM_KEYS	(MMX_COEF*MD5_SSE_PARA)
#define MD5_PARA_DO(x)	for((x)=0;(x)<MD5_SSE_PARA;(x)++)

#define MD5_F(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_cmov_si128((y[i]),(z[i]),(x[i]));

#define MD5_G(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_cmov_si128((x[i]),(y[i]),(z[i]));

#define MD5_H(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_xor_si128((y[i]),(z[i])); \
	MD5_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(x[i]));

#define MD5_I(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_andnot_si128((z[i]), mask); \
	MD5_PARA_DO(i) tmp[i] = _mm_or_si128((tmp[i]),(x[i])); \
	MD5_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(y[i]));

#define MD5_STEP(f, a, b, c, d, x, t, s) \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], _mm_set_epi32(t,t,t,t) ); \
	f((b),(c),(d)) \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], tmp[i] ); \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], data[i*16+x] ); \
	MD5_PARA_DO(i) a[i] = _mm_roti_epi32( a[i], (s) ); \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], b[i] );

#define MD5_STEP_r16(f, a, b, c, d, x, t, s) \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], _mm_set_epi32(t,t,t,t) ); \
	f((b),(c),(d)) \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], tmp[i] ); \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], data[i*16+x] ); \
	MD5_PARA_DO(i) a[i] = _mm_roti16_epi32( a[i], (s) ); \
	MD5_PARA_DO(i) a[i] = _mm_add_epi32( a[i], b[i] );

void SSEmd5body(__m128i* _data, unsigned int * out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags)
{
	__m128i w[16*MD5_SSE_PARA];
	__m128i a[MD5_SSE_PARA];
	__m128i b[MD5_SSE_PARA];
	__m128i c[MD5_SSE_PARA];
	__m128i d[MD5_SSE_PARA];
	__m128i tmp[MD5_SSE_PARA];
	__m128i mask;
	unsigned int i;
	__m128i *data;

	mask = _mm_set1_epi32(0Xffffffff);

	if(SSEi_flags & SSEi_FLAT_IN) {
		// Move _data to __data, mixing it MMX_COEF wise.
#ifdef __SSE4_1__
		unsigned k;
		__m128i *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32 *)_data;
		MD5_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_4x (W[i], saved_key, i); }
				saved_key += (MMX_COEF<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_2x (W[i], saved_key, i); }
				saved_key += (MMX_COEF<<5);
			} else {
				for (i=0; i < 16; ++i) { GATHER (W[i], saved_key, i); }
				saved_key += (MMX_COEF<<4);
			}
			W += 16;
		}
#else
		unsigned j, k;
		ARCH_WORD_32 *p = (ARCH_WORD_32 *)w;
		__m128i *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32 *)_data;
		MD5_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (MMX_COEF<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (MMX_COEF<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (MMX_COEF<<4);
			}
			W += 16;
		}
#endif
		// now set our data pointer to point to this 'mixed' data.
		data = w;
	} else
		data = _data;

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		MD5_PARA_DO(i)
		{
			a[i] = _mm_set1_epi32(0x67452301);
			b[i] = _mm_set1_epi32(0xefcdab89);
			c[i] = _mm_set1_epi32(0x98badcfe);
			d[i] = _mm_set1_epi32(0x10325476);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			MD5_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+12]);
			}
		}
		else
		{
			MD5_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*16+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*16+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*16+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*16+12]);
			}
		}
	}

/* Round 1 */
		MD5_STEP(MD5_F, a, b, c, d, 0, 0xd76aa478, 7)
		MD5_STEP(MD5_F, d, a, b, c, 1, 0xe8c7b756, 12)
		MD5_STEP(MD5_F, c, d, a, b, 2, 0x242070db, 17)
		MD5_STEP(MD5_F, b, c, d, a, 3, 0xc1bdceee, 22)
		MD5_STEP(MD5_F, a, b, c, d, 4, 0xf57c0faf, 7)
		MD5_STEP(MD5_F, d, a, b, c, 5, 0x4787c62a, 12)
		MD5_STEP(MD5_F, c, d, a, b, 6, 0xa8304613, 17)
		MD5_STEP(MD5_F, b, c, d, a, 7, 0xfd469501, 22)
		MD5_STEP(MD5_F, a, b, c, d, 8, 0x698098d8, 7)
		MD5_STEP(MD5_F, d, a, b, c, 9, 0x8b44f7af, 12)
		MD5_STEP(MD5_F, c, d, a, b, 10, 0xffff5bb1, 17)
		MD5_STEP(MD5_F, b, c, d, a, 11, 0x895cd7be, 22)
		MD5_STEP(MD5_F, a, b, c, d, 12, 0x6b901122, 7)
		MD5_STEP(MD5_F, d, a, b, c, 13, 0xfd987193, 12)
		MD5_STEP(MD5_F, c, d, a, b, 14, 0xa679438e, 17)
		MD5_STEP(MD5_F, b, c, d, a, 15, 0x49b40821, 22)

/* Round 2 */
		MD5_STEP(MD5_G, a, b, c, d, 1, 0xf61e2562, 5)
		MD5_STEP(MD5_G, d, a, b, c, 6, 0xc040b340, 9)
		MD5_STEP(MD5_G, c, d, a, b, 11, 0x265e5a51, 14)
		MD5_STEP(MD5_G, b, c, d, a, 0, 0xe9b6c7aa, 20)
		MD5_STEP(MD5_G, a, b, c, d, 5, 0xd62f105d, 5)
		MD5_STEP(MD5_G, d, a, b, c, 10, 0x02441453, 9)
		MD5_STEP(MD5_G, c, d, a, b, 15, 0xd8a1e681, 14)
		MD5_STEP(MD5_G, b, c, d, a, 4, 0xe7d3fbc8, 20)
		MD5_STEP(MD5_G, a, b, c, d, 9, 0x21e1cde6, 5)
		MD5_STEP(MD5_G, d, a, b, c, 14, 0xc33707d6, 9)
		MD5_STEP(MD5_G, c, d, a, b, 3, 0xf4d50d87, 14)
		MD5_STEP(MD5_G, b, c, d, a, 8, 0x455a14ed, 20)
		MD5_STEP(MD5_G, a, b, c, d, 13, 0xa9e3e905, 5)
		MD5_STEP(MD5_G, d, a, b, c, 2, 0xfcefa3f8, 9)
		MD5_STEP(MD5_G, c, d, a, b, 7, 0x676f02d9, 14)
		MD5_STEP(MD5_G, b, c, d, a, 12, 0x8d2a4c8a, 20)

/* Round 3 */
		MD5_STEP(MD5_H, a, b, c, d, 5, 0xfffa3942, 4)
		MD5_STEP(MD5_H, d, a, b, c, 8, 0x8771f681, 11)
		MD5_STEP_r16(MD5_H, c, d, a, b, 11, 0x6d9d6122, 16)
		MD5_STEP(MD5_H, b, c, d, a, 14, 0xfde5380c, 23)
		MD5_STEP(MD5_H, a, b, c, d, 1, 0xa4beea44, 4)
		MD5_STEP(MD5_H, d, a, b, c, 4, 0x4bdecfa9, 11)
		MD5_STEP_r16(MD5_H, c, d, a, b, 7, 0xf6bb4b60, 16)
		MD5_STEP(MD5_H, b, c, d, a, 10, 0xbebfbc70, 23)
		MD5_STEP(MD5_H, a, b, c, d, 13, 0x289b7ec6, 4)
		MD5_STEP(MD5_H, d, a, b, c, 0, 0xeaa127fa, 11)
		MD5_STEP_r16(MD5_H, c, d, a, b, 3, 0xd4ef3085, 16)
		MD5_STEP(MD5_H, b, c, d, a, 6, 0x04881d05, 23)
		MD5_STEP(MD5_H, a, b, c, d, 9, 0xd9d4d039, 4)
		MD5_STEP(MD5_H, d, a, b, c, 12, 0xe6db99e5, 11)
		MD5_STEP_r16(MD5_H, c, d, a, b, 15, 0x1fa27cf8, 16)
		MD5_STEP(MD5_H, b, c, d, a, 2, 0xc4ac5665, 23)

/* Round 4 */
		MD5_STEP(MD5_I, a, b, c, d, 0, 0xf4292244, 6)
		MD5_STEP(MD5_I, d, a, b, c, 7, 0x432aff97, 10)
		MD5_STEP(MD5_I, c, d, a, b, 14, 0xab9423a7, 15)
		MD5_STEP(MD5_I, b, c, d, a, 5, 0xfc93a039, 21)
		MD5_STEP(MD5_I, a, b, c, d, 12, 0x655b59c3, 6)
		MD5_STEP(MD5_I, d, a, b, c, 3, 0x8f0ccc92, 10)
		MD5_STEP(MD5_I, c, d, a, b, 10, 0xffeff47d, 15)
		MD5_STEP(MD5_I, b, c, d, a, 1, 0x85845dd1, 21)
		MD5_STEP(MD5_I, a, b, c, d, 8, 0x6fa87e4f, 6)
		MD5_STEP(MD5_I, d, a, b, c, 15, 0xfe2ce6e0, 10)
		MD5_STEP(MD5_I, c, d, a, b, 6, 0xa3014314, 15)
		MD5_STEP(MD5_I, b, c, d, a, 13, 0x4e0811a1, 21)
		MD5_STEP(MD5_I, a, b, c, d, 4, 0xf7537e82, 6)
		MD5_STEP(MD5_I, d, a, b, c, 11, 0xbd3af235, 10)
		MD5_STEP(MD5_I, c, d, a, b, 2, 0x2ad7d2bb, 15)
		MD5_STEP(MD5_I, b, c, d, a, 9, 0xeb86d391, 21)

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		MD5_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_set1_epi32(0x67452301));
			b[i] = _mm_add_epi32(b[i], _mm_set1_epi32(0xefcdab89));
			c[i] = _mm_add_epi32(c[i], _mm_set1_epi32(0x98badcfe));
			d[i] = _mm_add_epi32(d[i], _mm_set1_epi32(0x10325476));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			MD5_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+12]));
			}
		}
		else
		{
			MD5_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*16+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*16+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*16+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*16+12]));
			}
		}
	}
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		MD5_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*16*4+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+12], d[i]);
		}
	}
	else
	{
		MD5_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*16+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16+12], d[i]);
		}
	}
}

#define GETPOS(i, index)                ( (index&3)*4 + (i& (0xffffffff-3) )*MMX_COEF + ((i)&3) )

static MAYBE_INLINE void mmxput(void * buf, unsigned int index, unsigned int bid, unsigned int offset, unsigned char * src, unsigned int len)
{
	unsigned char * nbuf;
	unsigned int i;

	nbuf = ((unsigned char*)buf) + (index>>2)*64*MMX_COEF + bid*64*MD5_SSE_NUM_KEYS;
	for(i=0;i<len;i++)
		nbuf[ GETPOS((offset+i), index) ] = src[i];

}

static MAYBE_INLINE void mmxput2(void * buf, unsigned int bid, void * src)
{
	unsigned char * nbuf;
	unsigned int i;

	nbuf = ((unsigned char*)buf) + bid*64*MD5_SSE_NUM_KEYS;
	MD5_PARA_DO(i)
		memcpy( nbuf+i*64*MMX_COEF, ((unsigned char*)src)+i*64, 64);
}

static MAYBE_INLINE void mmxput3(void * buf, unsigned int bid, unsigned int * offset, int mult, int saltlen, void * src)
{
	unsigned char * nbuf;
	unsigned int noff;
	unsigned int noffd;
	unsigned int i,j;
	unsigned int dec;

	MD5_PARA_DO(j)
	{
		nbuf = ((unsigned char*)buf) + bid*64*MD5_SSE_NUM_KEYS + j*64*MMX_COEF;
		for(i=0;i<MMX_COEF;i++)
		{
			noff = offset[i+j*MMX_COEF]*mult + saltlen;
			dec = (noff&3)*8;
			if(dec)
			{
				noffd = noff & (~3);
				((unsigned int *)(nbuf+noffd*4))[i] &= (0xffffffff>>(32-dec));
				((unsigned int *)(nbuf+noffd*4))[i] |= (((unsigned int *)src)[i+j*16+0] << dec);
				((unsigned int *)(nbuf+noffd*4))[i+4] = (((unsigned int *)src)[i+j*16+4] << dec) | (((unsigned int *)src)[i+j*16+0] >> (32-dec));
				((unsigned int *)(nbuf+noffd*4))[i+8] = (((unsigned int *)src)[i+j*16+8] << dec) | (((unsigned int *)src)[i+j*16+4] >> (32-dec));
				((unsigned int *)(nbuf+noffd*4))[i+12] = (((unsigned int *)src)[i+j*16+12] << dec) | (((unsigned int *)src)[i+j*16+8] >> (32-dec));
				((unsigned int *)(nbuf+noffd*4))[i+16] &= (0xffffffff<<dec);
				((unsigned int *)(nbuf+noffd*4))[i+16] |= (((unsigned int *)src)[i+j*16+12] >> (32-dec));
			}
			else
			{
				((unsigned int *)(nbuf+noff*4))[i] = ((unsigned int *)src)[i+j*16+0];
				((unsigned int *)(nbuf+noff*4))[i+4] = ((unsigned int *)src)[i+j*16+4];
				((unsigned int *)(nbuf+noff*4))[i+8] = ((unsigned int *)src)[i+j*16+8];
				((unsigned int *)(nbuf+noff*4))[i+12] = ((unsigned int *)src)[i+j*16+12];
			}
		}
	}

}

static MAYBE_INLINE void dispatch(unsigned char buffers[8][64*MD5_SSE_NUM_KEYS], unsigned int f[4*MD5_SSE_NUM_KEYS], unsigned int length[MD5_SSE_NUM_KEYS], unsigned int saltlen)
{
	unsigned int i, j;
	unsigned int bufferid;

	i = 1000 / 42; j = 0;
	do {
		switch(j)
		{
			case 0:
				bufferid = 0;
				mmxput2(buffers, bufferid, f);
				break;
			case 21:
				bufferid = 1;
				mmxput3(buffers, bufferid, length, 1, 0, f);
				break;
			case 3:
			case 9:
			case 15:
			case 27:
			case 33:
			case 39:
				bufferid = 2;
				mmxput3(buffers, bufferid, length, 2, 0, f);
				break;
			case 6:
			case 12:
			case 18:
			case 24:
			case 30:
			case 36:
				bufferid = 3;
				mmxput2(buffers, bufferid, f);
				break;
			case 7:
			case 35:
				bufferid = 4;
				mmxput3(buffers, bufferid, length, 1, saltlen, f);
				break;
			case 14:
			case 28:
				bufferid = 5;
				mmxput2(buffers, bufferid, f);
				break;
			case 2:
			case 4:
			case 8:
			case 10:
			case 16:
			case 20:
			case 22:
			case 26:
			case 32:
			case 34:
			case 38:
			case 40:
				bufferid = 6;
				mmxput2(buffers, bufferid, f);
				break;
			default:
				bufferid = 7;
				mmxput3(buffers, bufferid, length, 2, saltlen, f);
				break;
		}
		SSEmd5body((__m128i*)&buffers[bufferid], f, NULL, SSEi_MIXED_IN);
		if (j++ < 1000 % 42 - 1)
			continue;
		if (j == 1000 % 42) {
			if (!i)
				break;
			i--;
			continue;
		}
		if (j >= 42)
			j = 0;
	} while (1);
}


void md5cryptsse(unsigned char pwd[MD5_SSE_NUM_KEYS][16], unsigned char * salt, char * out, int md5_type)
{
	unsigned int length[MD5_SSE_NUM_KEYS];
	unsigned int saltlen;
	unsigned int * bt;
	unsigned int tf[4];
	unsigned int i,j;
	MD5_CTX ctx;
	MD5_CTX tctx;
	ALIGN(16) unsigned char buffers[8][64*MD5_SSE_NUM_KEYS];
	ALIGN(16) unsigned int F[4*MD5_SSE_NUM_KEYS];

	memset(F,0,sizeof(F));
	memset(buffers, 0, sizeof(buffers));
	saltlen = strlen((char *)salt);
	for(i=0;i<MD5_SSE_NUM_KEYS;i++)
	{
		unsigned int length_i = strlen((char *)pwd[i]);
		/* cas 0 fs */
		mmxput(buffers, i, 0, 16, pwd[i], length_i);
		mmxput(buffers, i, 0, length_i+16, (unsigned char *)"\x80", 1);
		/* cas 1 sf */
		mmxput(buffers, i, 1, 0, pwd[i], length_i);
		mmxput(buffers, i, 1, length_i+16, (unsigned char *)"\x80", 1);
		/* cas 2 ssf */
		mmxput(buffers, i, 2, 0, pwd[i], length_i);
		mmxput(buffers, i, 2, length_i, pwd[i], length_i);
		mmxput(buffers, i, 2, length_i*2+16, (unsigned char *)"\x80", 1);
		/* cas 3 fss */
		mmxput(buffers, i, 3, 16, pwd[i], length_i);
		mmxput(buffers, i, 3, 16+length_i, pwd[i], length_i);
		mmxput(buffers, i, 3, length_i*2+16, (unsigned char *)"\x80", 1);
		/* cas 4 scf */
		mmxput(buffers, i, 4, 0, pwd[i], length_i);
		mmxput(buffers, i, 4, length_i, salt, saltlen);
		mmxput(buffers, i, 4, saltlen+length_i+16, (unsigned char *)"\x80", 1);
		/* cas 5 fcs */
		mmxput(buffers, i, 5, 16, salt, saltlen);
		mmxput(buffers, i, 5, 16+saltlen, pwd[i], length_i);
		mmxput(buffers, i, 5, saltlen+length_i+16, (unsigned char *)"\x80", 1);
		/* cas 6 fcss */
		mmxput(buffers, i, 6, 16, salt, saltlen);
		mmxput(buffers, i, 6, 16+saltlen, pwd[i], length_i);
		mmxput(buffers, i, 6, 16+saltlen+length_i, pwd[i], length_i);
		mmxput(buffers, i, 6, saltlen+2*length_i+16, (unsigned char *)"\x80", 1);
		/* cas 7 scsf */
		mmxput(buffers, i, 7, 0, pwd[i], length_i);
		mmxput(buffers, i, 7, length_i, salt, saltlen);
		mmxput(buffers, i, 7, length_i+saltlen, pwd[i], length_i);
		mmxput(buffers, i, 7, saltlen+2*length_i+16, (unsigned char *)"\x80", 1);

		bt = (unsigned int *) &buffers[0]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i+16)<<3;
		bt = (unsigned int *) &buffers[1]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i+16)<<3;
		bt = (unsigned int *) &buffers[2]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i*2+16)<<3;
		bt = (unsigned int *) &buffers[3]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i*2+16)<<3;
		bt = (unsigned int *) &buffers[4]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i+saltlen+16)<<3;
		bt = (unsigned int *) &buffers[5]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i+saltlen+16)<<3;
		bt = (unsigned int *) &buffers[6]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i*2+saltlen+16)<<3;
		bt = (unsigned int *) &buffers[7]; bt[14*MMX_COEF + (i&3) + (i>>2)*64] = (length_i*2+saltlen+16)<<3;

		MD5_Init(&ctx);
		MD5_Update(&ctx, pwd[i], length_i);
		if (md5_type == MD5_TYPE_STD)
			MD5_Update(&ctx, "$1$", 3);
		else if (md5_type == MD5_TYPE_APACHE)
			MD5_Update(&ctx, "$apr1$", 6);
		// else it's AIX and no prefix included
		MD5_Update(&ctx, salt, saltlen);
		MD5_Init(&tctx);
		MD5_Update(&tctx, pwd[i], length_i);
		MD5_Update(&tctx, salt, saltlen);
		MD5_Update(&tctx, pwd[i], length_i);
		MD5_Final((unsigned char *)tf, &tctx);
		MD5_Update(&ctx, tf, length_i);
		length[i] = length_i;
		for(j=length_i;j;j>>=1)
			if(j&1)
				MD5_Update(&ctx, "\0", 1);
			else
				MD5_Update(&ctx, pwd[i], 1);
		MD5_Final((unsigned char *)tf, &ctx);
		F[(i>>2)*16 + (i&3)] = tf[0];
		F[(i>>2)*16 + (i&3) + 4] = tf[1];
		F[(i>>2)*16 + (i&3) + 8] = tf[2];
		F[(i>>2)*16 + (i&3) + 12] = tf[3];
	}
	dispatch(buffers, F, length, saltlen);
	memcpy(out, F, MD5_SSE_NUM_KEYS*16);
}
#endif /* MD5_SSE_PARA */

#ifdef MD4_SSE_PARA
#define MD4_SSE_NUM_KEYS	(MMX_COEF*MD4_SSE_PARA)
#define MD4_PARA_DO(x)	for((x)=0;(x)<MD4_SSE_PARA;(x)++)

#define MD4_F(x,y,z) \
	MD4_PARA_DO(i) tmp[i] = _mm_cmov_si128((y[i]),(z[i]),(x[i]));

#define MD4_G(x,y,z) \
	MD4_PARA_DO(i) tmp[i] = _mm_or_si128((y[i]),(z[i])); \
	MD4_PARA_DO(i) tmp2[i] = _mm_and_si128((y[i]),(z[i])); \
	MD4_PARA_DO(i) tmp[i] = _mm_and_si128((tmp[i]),(x[i])); \
	MD4_PARA_DO(i) tmp[i] = _mm_or_si128((tmp[i]), (tmp2[i]) );

#define MD4_H(x,y,z) \
	MD4_PARA_DO(i) tmp[i] = _mm_xor_si128((y[i]),(z[i])); \
	MD4_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(x[i]));

#define MD4_STEP(f, a, b, c, d, x, t, s) \
	MD4_PARA_DO(i) a[i] = _mm_add_epi32( a[i], t ); \
	f((b),(c),(d)) \
	MD4_PARA_DO(i) a[i] = _mm_add_epi32( a[i], tmp[i] ); \
	MD4_PARA_DO(i) a[i] = _mm_add_epi32( a[i], data[i*16+x] ); \
	MD4_PARA_DO(i) a[i] = _mm_roti_epi32( a[i], (s) );

void SSEmd4body(__m128i* _data, unsigned int * out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags)
{
	__m128i w[16*MD4_SSE_PARA];
	__m128i a[MD4_SSE_PARA];
	__m128i b[MD4_SSE_PARA];
	__m128i c[MD4_SSE_PARA];
	__m128i d[MD4_SSE_PARA];
	__m128i tmp[MD4_SSE_PARA];
	__m128i tmp2[MD4_SSE_PARA];
	__m128i	cst;
	unsigned int i;
	__m128i *data;

if(SSEi_flags & SSEi_FLAT_IN) {
		// Move _data to __data, mixing it MMX_COEF wise.
#ifdef __SSE4_1__
		unsigned k;
		__m128i *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32 *)_data;
		MD4_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_4x (W[i], saved_key, i); }
				saved_key += (MMX_COEF<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_2x (W[i], saved_key, i); }
				saved_key += (MMX_COEF<<5);
			} else {
				for (i=0; i < 16; ++i) { GATHER (W[i], saved_key, i); }
				saved_key += (MMX_COEF<<4);
			}
			W += 16;
		}
#else
		unsigned j, k;
		ARCH_WORD_32 *p = (ARCH_WORD_32 *)w;
		__m128i *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32 *)_data;
		MD4_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (MMX_COEF<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (MMX_COEF<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (MMX_COEF<<4);
			}
			W += 16;
		}
#endif
		// now set our data pointer to point to this 'mixed' data.
		data = w;
	} else
		data = _data;

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		MD4_PARA_DO(i)
		{
			a[i] = _mm_set1_epi32(0x67452301);
			b[i] = _mm_set1_epi32(0xefcdab89);
			c[i] = _mm_set1_epi32(0x98badcfe);
			d[i] = _mm_set1_epi32(0x10325476);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			MD4_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+12]);
			}
		}
		else
		{
			MD4_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*16+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*16+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*16+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*16+12]);
			}
		}
	}


/* Round 1 */
		cst = _mm_set_epi32(0,0,0,0);
		MD4_STEP(MD4_F, a, b, c, d, 0, cst, 3)
		MD4_STEP(MD4_F, d, a, b, c, 1, cst, 7)
		MD4_STEP(MD4_F, c, d, a, b, 2, cst, 11)
		MD4_STEP(MD4_F, b, c, d, a, 3, cst, 19)
		MD4_STEP(MD4_F, a, b, c, d, 4, cst, 3)
		MD4_STEP(MD4_F, d, a, b, c, 5, cst, 7)
		MD4_STEP(MD4_F, c, d, a, b, 6, cst, 11)
		MD4_STEP(MD4_F, b, c, d, a, 7, cst, 19)
		MD4_STEP(MD4_F, a, b, c, d, 8, cst, 3)
		MD4_STEP(MD4_F, d, a, b, c, 9, cst, 7)
		MD4_STEP(MD4_F, c, d, a, b, 10, cst, 11)
		MD4_STEP(MD4_F, b, c, d, a, 11, cst, 19)
		MD4_STEP(MD4_F, a, b, c, d, 12, cst, 3)
		MD4_STEP(MD4_F, d, a, b, c, 13, cst, 7)
		MD4_STEP(MD4_F, c, d, a, b, 14, cst, 11)
		MD4_STEP(MD4_F, b, c, d, a, 15, cst, 19)

/* Round 2 */
		cst = _mm_set_epi32(0x5A827999L,0x5A827999L,0x5A827999L,0x5A827999L);
		MD4_STEP(MD4_G, a, b, c, d, 0, cst, 3)
		MD4_STEP(MD4_G, d, a, b, c, 4, cst, 5)
		MD4_STEP(MD4_G, c, d, a, b, 8, cst, 9)
		MD4_STEP(MD4_G, b, c, d, a, 12, cst, 13)
		MD4_STEP(MD4_G, a, b, c, d, 1, cst, 3)
		MD4_STEP(MD4_G, d, a, b, c, 5, cst, 5)
		MD4_STEP(MD4_G, c, d, a, b, 9, cst, 9)
		MD4_STEP(MD4_G, b, c, d, a, 13, cst, 13)
		MD4_STEP(MD4_G, a, b, c, d, 2, cst, 3)
		MD4_STEP(MD4_G, d, a, b, c, 6, cst, 5)
		MD4_STEP(MD4_G, c, d, a, b, 10, cst, 9)
		MD4_STEP(MD4_G, b, c, d, a, 14, cst, 13)
		MD4_STEP(MD4_G, a, b, c, d, 3, cst, 3)
		MD4_STEP(MD4_G, d, a, b, c, 7, cst, 5)
		MD4_STEP(MD4_G, c, d, a, b, 11, cst, 9)
		MD4_STEP(MD4_G, b, c, d, a, 15, cst, 13)

/* Round 3 */
		cst = _mm_set_epi32(0x6ED9EBA1L,0x6ED9EBA1L,0x6ED9EBA1L,0x6ED9EBA1L);
		MD4_STEP(MD4_H, a, b, c, d, 0, cst, 3)
		MD4_STEP(MD4_H, d, a, b, c, 8, cst, 9)
		MD4_STEP(MD4_H, c, d, a, b, 4, cst, 11)
		MD4_STEP(MD4_H, b, c, d, a, 12, cst, 15)
		MD4_STEP(MD4_H, a, b, c, d, 2, cst, 3)
		MD4_STEP(MD4_H, d, a, b, c, 10, cst, 9)
		MD4_STEP(MD4_H, c, d, a, b, 6, cst, 11)
		MD4_STEP(MD4_H, b, c, d, a, 14, cst, 15)
		MD4_STEP(MD4_H, a, b, c, d, 1, cst, 3)
		MD4_STEP(MD4_H, d, a, b, c, 9, cst, 9)
		MD4_STEP(MD4_H, c, d, a, b, 5, cst, 11)
		MD4_STEP(MD4_H, b, c, d, a, 13, cst, 15)
		MD4_STEP(MD4_H, a, b, c, d, 3, cst, 3)
		MD4_STEP(MD4_H, d, a, b, c, 11, cst, 9)
		MD4_STEP(MD4_H, c, d, a, b, 7, cst, 11)
		MD4_STEP(MD4_H, b, c, d, a, 15, cst, 15)


	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		MD4_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_set1_epi32(0x67452301));
			b[i] = _mm_add_epi32(b[i], _mm_set1_epi32(0xefcdab89));
			c[i] = _mm_add_epi32(c[i], _mm_set1_epi32(0x98badcfe));
			d[i] = _mm_add_epi32(d[i], _mm_set1_epi32(0x10325476));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			MD4_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+12]));
			}
		}
		else
		{
			MD4_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*16+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*16+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*16+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*16+12]));
			}
		}
	}
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		MD4_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*16*4+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+12], d[i]);
		}
	}
	else
	{
		MD4_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*16+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16+12], d[i]);
		}
	}
}

#endif /* MD4_SSE_PARA */

#ifdef SHA1_SSE_PARA
#define SHA1_SSE_NUM_KEYS	(MMX_COEF*SHA1_SSE_PARA)
#define SHA1_PARA_DO(x)		for((x)=0;(x)<SHA1_SSE_PARA;(x)++)

#define SHA1_F(x,y,z) \
	SHA1_PARA_DO(i) tmp[i] = _mm_cmov_si128((y[i]),(z[i]),(x[i]));

#define SHA1_G(x,y,z) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128((y[i]),(z[i])); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(x[i]));

#ifdef __XOP__
#define SHA1_H(x,y,z) \
	SHA1_PARA_DO(i) tmp[i] = _mm_cmov_si128((x[i]),(y[i]),(z[i])); \
	SHA1_PARA_DO(i) tmp2[i] = _mm_andnot_si128((x[i]),(y[i])); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(tmp2[i]));
#else
#define SHA1_H(x,y,z) \
	SHA1_PARA_DO(i) tmp[i] = _mm_and_si128((x[i]),(y[i])); \
	SHA1_PARA_DO(i) tmp2[i] = _mm_or_si128((x[i]),(y[i])); \
	SHA1_PARA_DO(i) tmp2[i] = _mm_and_si128((tmp2[i]),(z[i])); \
	SHA1_PARA_DO(i) tmp[i] = _mm_or_si128((tmp[i]),(tmp2[i]));
#endif

#define SHA1_I(x,y,z) SHA1_G(x,y,z)

#if SHA_BUF_SIZ == 80

// Bartavelle's original code, using 80x4 words of buffer

#define SHA1_EXPAND(t) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( data[i*80+t-3], data[i*80+t-8] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*80+t-14] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*80+t-16] ); \
	SHA1_PARA_DO(i) data[i*80+t] = _mm_roti_epi32(tmp[i], 1);

#define SHA1_ROUND(a,b,c,d,e,F,t) \
	F(b,c,d) \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_roti_epi32(a[i], 5); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], cst ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], data[i*80+t] ); \
	SHA1_PARA_DO(i) b[i] = _mm_roti_epi32(b[i], 30);

void SSESHA1body(__m128i* data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned int SSEi_flags)
{
	__m128i a[SHA1_SSE_PARA];
	__m128i b[SHA1_SSE_PARA];
	__m128i c[SHA1_SSE_PARA];
	__m128i d[SHA1_SSE_PARA];
	__m128i e[SHA1_SSE_PARA];
	__m128i tmp[SHA1_SSE_PARA];
	__m128i tmp2[SHA1_SSE_PARA];
	__m128i	cst;
	unsigned int i,j;

	for(j=16;j<80;j++)
	{
		SHA1_EXPAND(j);
	}

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_set1_epi32(0x67452301);
			b[i] = _mm_set1_epi32(0xefcdab89);
			c[i] = _mm_set1_epi32(0x98badcfe);
			d[i] = _mm_set1_epi32(0x10325476);
			e[i] = _mm_set1_epi32(0xC3D2E1F0);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*80*4+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*80*4+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*80*4+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*80*4+12]);
				e[i] = _mm_load_si128((__m128i *)&reload_state[i*80*4+16]);
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*20+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*20+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*20+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*20+12]);
				e[i] = _mm_load_si128((__m128i *)&reload_state[i*20+16]);
			}
		}
	}

	cst = _mm_set1_epi32(0x5A827999);
	SHA1_ROUND( a, b, c, d, e, SHA1_F,  0 );
	SHA1_ROUND( e, a, b, c, d, SHA1_F,  1 );
	SHA1_ROUND( d, e, a, b, c, SHA1_F,  2 );
	SHA1_ROUND( c, d, e, a, b, SHA1_F,  3 );
	SHA1_ROUND( b, c, d, e, a, SHA1_F,  4 );
	SHA1_ROUND( a, b, c, d, e, SHA1_F,  5 );
	SHA1_ROUND( e, a, b, c, d, SHA1_F,  6 );
	SHA1_ROUND( d, e, a, b, c, SHA1_F,  7 );
	SHA1_ROUND( c, d, e, a, b, SHA1_F,  8 );
	SHA1_ROUND( b, c, d, e, a, SHA1_F,  9 );
	SHA1_ROUND( a, b, c, d, e, SHA1_F, 10 );
	SHA1_ROUND( e, a, b, c, d, SHA1_F, 11 );
	SHA1_ROUND( d, e, a, b, c, SHA1_F, 12 );
	SHA1_ROUND( c, d, e, a, b, SHA1_F, 13 );
	SHA1_ROUND( b, c, d, e, a, SHA1_F, 14 );
	SHA1_ROUND( a, b, c, d, e, SHA1_F, 15 );
	SHA1_ROUND( e, a, b, c, d, SHA1_F, 16 );
	SHA1_ROUND( d, e, a, b, c, SHA1_F, 17 );
	SHA1_ROUND( c, d, e, a, b, SHA1_F, 18 );
	SHA1_ROUND( b, c, d, e, a, SHA1_F, 19 );

	cst = _mm_set1_epi32(0x6ED9EBA1);
	SHA1_ROUND( a, b, c, d, e, SHA1_G, 20 );
	SHA1_ROUND( e, a, b, c, d, SHA1_G, 21 );
	SHA1_ROUND( d, e, a, b, c, SHA1_G, 22 );
	SHA1_ROUND( c, d, e, a, b, SHA1_G, 23 );
	SHA1_ROUND( b, c, d, e, a, SHA1_G, 24 );
	SHA1_ROUND( a, b, c, d, e, SHA1_G, 25 );
	SHA1_ROUND( e, a, b, c, d, SHA1_G, 26 );
	SHA1_ROUND( d, e, a, b, c, SHA1_G, 27 );
	SHA1_ROUND( c, d, e, a, b, SHA1_G, 28 );
	SHA1_ROUND( b, c, d, e, a, SHA1_G, 29 );
	SHA1_ROUND( a, b, c, d, e, SHA1_G, 30 );
	SHA1_ROUND( e, a, b, c, d, SHA1_G, 31 );
	SHA1_ROUND( d, e, a, b, c, SHA1_G, 32 );
	SHA1_ROUND( c, d, e, a, b, SHA1_G, 33 );
	SHA1_ROUND( b, c, d, e, a, SHA1_G, 34 );
	SHA1_ROUND( a, b, c, d, e, SHA1_G, 35 );
	SHA1_ROUND( e, a, b, c, d, SHA1_G, 36 );
	SHA1_ROUND( d, e, a, b, c, SHA1_G, 37 );
	SHA1_ROUND( c, d, e, a, b, SHA1_G, 38 );
	SHA1_ROUND( b, c, d, e, a, SHA1_G, 39 );

	cst = _mm_set1_epi32(0x8F1BBCDC);
	SHA1_ROUND( a, b, c, d, e, SHA1_H, 40 );
	SHA1_ROUND( e, a, b, c, d, SHA1_H, 41 );
	SHA1_ROUND( d, e, a, b, c, SHA1_H, 42 );
	SHA1_ROUND( c, d, e, a, b, SHA1_H, 43 );
	SHA1_ROUND( b, c, d, e, a, SHA1_H, 44 );
	SHA1_ROUND( a, b, c, d, e, SHA1_H, 45 );
	SHA1_ROUND( e, a, b, c, d, SHA1_H, 46 );
	SHA1_ROUND( d, e, a, b, c, SHA1_H, 47 );
	SHA1_ROUND( c, d, e, a, b, SHA1_H, 48 );
	SHA1_ROUND( b, c, d, e, a, SHA1_H, 49 );
	SHA1_ROUND( a, b, c, d, e, SHA1_H, 50 );
	SHA1_ROUND( e, a, b, c, d, SHA1_H, 51 );
	SHA1_ROUND( d, e, a, b, c, SHA1_H, 52 );
	SHA1_ROUND( c, d, e, a, b, SHA1_H, 53 );
	SHA1_ROUND( b, c, d, e, a, SHA1_H, 54 );
	SHA1_ROUND( a, b, c, d, e, SHA1_H, 55 );
	SHA1_ROUND( e, a, b, c, d, SHA1_H, 56 );
	SHA1_ROUND( d, e, a, b, c, SHA1_H, 57 );
	SHA1_ROUND( c, d, e, a, b, SHA1_H, 58 );
	SHA1_ROUND( b, c, d, e, a, SHA1_H, 59 );

	cst = _mm_set1_epi32(0xCA62C1D6);
	SHA1_ROUND( a, b, c, d, e, SHA1_I, 60 );
	SHA1_ROUND( e, a, b, c, d, SHA1_I, 61 );
	SHA1_ROUND( d, e, a, b, c, SHA1_I, 62 );
	SHA1_ROUND( c, d, e, a, b, SHA1_I, 63 );
	SHA1_ROUND( b, c, d, e, a, SHA1_I, 64 );
	SHA1_ROUND( a, b, c, d, e, SHA1_I, 65 );
	SHA1_ROUND( e, a, b, c, d, SHA1_I, 66 );
	SHA1_ROUND( d, e, a, b, c, SHA1_I, 67 );
	SHA1_ROUND( c, d, e, a, b, SHA1_I, 68 );
	SHA1_ROUND( b, c, d, e, a, SHA1_I, 69 );
	SHA1_ROUND( a, b, c, d, e, SHA1_I, 70 );
	SHA1_ROUND( e, a, b, c, d, SHA1_I, 71 );
	SHA1_ROUND( d, e, a, b, c, SHA1_I, 72 );
	SHA1_ROUND( c, d, e, a, b, SHA1_I, 73 );
	SHA1_ROUND( b, c, d, e, a, SHA1_I, 74 );
	SHA1_ROUND( a, b, c, d, e, SHA1_I, 75 );
	SHA1_ROUND( e, a, b, c, d, SHA1_I, 76 );
	SHA1_ROUND( d, e, a, b, c, SHA1_I, 77 );
	SHA1_ROUND( c, d, e, a, b, SHA1_I, 78 );
	SHA1_ROUND( b, c, d, e, a, SHA1_I, 79 );

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_set1_epi32(0x67452301));
			b[i] = _mm_add_epi32(b[i], _mm_set1_epi32(0xefcdab89));
			c[i] = _mm_add_epi32(c[i], _mm_set1_epi32(0x98badcfe));
			d[i] = _mm_add_epi32(d[i], _mm_set1_epi32(0x10325476));
			e[i] = _mm_add_epi32(e[i], _mm_set1_epi32(0xC3D2E1F0));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*80*4+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*80*4+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*80*4+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*80*4+12]));
				e[i] = _mm_add_epi32(e[i], _mm_load_si128((__m128i *)&reload_state[i*80*4+16]));
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*20+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*20+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*20+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*20+12]));
				e[i] = _mm_add_epi32(e[i], _mm_load_si128((__m128i *)&reload_state[i*20+16]));
			}
		}
	}
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		SHA1_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*80*4+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*80*4+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*80*4+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*80*4+12], d[i]);
			_mm_store_si128((__m128i *)&out[i*80*4+16], e[i]);
		}
	}
	else
	{
		SHA1_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*20+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*20+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*20+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*20+12], d[i]);
			_mm_store_si128((__m128i *)&out[i*20+16], e[i]);
		}
	}
}
#else /* SHA_BUF_SIZ */

// JimF's code, using 16x4 words of buffer just like MD4/5

#define SHA1_EXPAND2a(t) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( data[i*16+t-3], data[i*16+t-8] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*16+t-14] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*16+t-16] ); \
	SHA1_PARA_DO(i) tmpR[i*16+((t)&0xF)] = _mm_roti_epi32(tmp[i], 1);
#define SHA1_EXPAND2b(t) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmpR[i*16+((t-3)&0xF)], data[i*16+t-8] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*16+t-14] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*16+t-16] ); \
	SHA1_PARA_DO(i) tmpR[i*16+((t)&0xF)] = _mm_roti_epi32(tmp[i], 1);
#define SHA1_EXPAND2c(t) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmpR[i*16+((t-3)&0xF)], tmpR[i*16+((t-8)&0xF)] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*16+t-14] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*16+t-16] ); \
	SHA1_PARA_DO(i) tmpR[i*16+((t)&0xF)] = _mm_roti_epi32(tmp[i], 1);
#define SHA1_EXPAND2d(t) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmpR[i*16+((t-3)&0xF)], tmpR[i*16+((t-8)&0xF)] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], tmpR[i*16+((t-14)&0xF)] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], data[i*16+t-16] ); \
	SHA1_PARA_DO(i) tmpR[i*16+((t)&0xF)] = _mm_roti_epi32(tmp[i], 1);
#define SHA1_EXPAND2(t) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmpR[i*16+((t-3)&0xF)], tmpR[i*16+((t-8)&0xF)] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], tmpR[i*16+((t-14)&0xF)] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128( tmp[i], tmpR[i*16+((t-16)&0xF)] ); \
	SHA1_PARA_DO(i) tmpR[i*16+((t)&0xF)] = _mm_roti_epi32(tmp[i], 1);

#define SHA1_ROUND2a(a,b,c,d,e,F,t) \
	SHA1_EXPAND2a(t+16) \
	F(b,c,d) \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_roti_epi32(a[i], 5); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], cst ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], data[i*16+t] ); \
	SHA1_PARA_DO(i) b[i] = _mm_roti_epi32(b[i], 30);
#define SHA1_ROUND2b(a,b,c,d,e,F,t) \
	SHA1_EXPAND2b(t+16) \
	F(b,c,d) \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_roti_epi32(a[i], 5); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], cst ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], data[i*16+t] ); \
	SHA1_PARA_DO(i) b[i] = _mm_roti_epi32(b[i], 30);
#define SHA1_ROUND2c(a,b,c,d,e,F,t) \
	SHA1_EXPAND2c(t+16) \
	F(b,c,d) \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_roti_epi32(a[i], 5); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], cst ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], data[i*16+t] ); \
	SHA1_PARA_DO(i) b[i] = _mm_roti_epi32(b[i], 30);
#define SHA1_ROUND2d(a,b,c,d,e,F,t) \
	SHA1_EXPAND2d(t+16) \
	F(b,c,d) \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_roti_epi32(a[i], 5); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], cst ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], data[i*16+t] ); \
	SHA1_PARA_DO(i) b[i] = _mm_roti_epi32(b[i], 30);
#define SHA1_ROUND2(a,b,c,d,e,F,t) \
	SHA1_PARA_DO(i) tmp3[i] = tmpR[i*16+(t&0xF)]; \
	SHA1_EXPAND2(t+16) \
	F(b,c,d) \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_roti_epi32(a[i], 5); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], cst ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp3[i] ); \
	SHA1_PARA_DO(i) b[i] = _mm_roti_epi32(b[i], 30);
#define SHA1_ROUND2x(a,b,c,d,e,F,t) \
	F(b,c,d) \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) tmp[i] = _mm_roti_epi32(a[i], 5); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmp[i] ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], cst ); \
	SHA1_PARA_DO(i) e[i] = _mm_add_epi32( e[i], tmpR[i*16+(t&0xF)] ); \
	SHA1_PARA_DO(i) b[i] = _mm_roti_epi32(b[i], 30);

void SSESHA1body(__m128i* _data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags)
{
	__m128i w[16*SHA1_SSE_PARA];
	__m128i a[SHA1_SSE_PARA];
	__m128i b[SHA1_SSE_PARA];
	__m128i c[SHA1_SSE_PARA];
	__m128i d[SHA1_SSE_PARA];
	__m128i e[SHA1_SSE_PARA];
	__m128i tmp[SHA1_SSE_PARA];
	__m128i tmp2[SHA1_SSE_PARA];
	__m128i tmp3[SHA1_SSE_PARA];
	__m128i tmpR[SHA1_SSE_PARA*16];
	__m128i	cst;
	unsigned int i;
	__m128i *data;

	if(SSEi_flags & SSEi_FLAT_IN) {
		// Move _data to __data, mixing it MMX_COEF wise.
#ifdef __SSE4_1__
		unsigned k;
		__m128i *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32 *)_data;
		SHA1_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 14; ++i) { GATHER_4x (W[i], saved_key, i); SWAP_ENDIAN (W[i]); }
				GATHER_4x (W[14], saved_key, 14);
				GATHER_4x (W[15], saved_key, 15);
				saved_key += (MMX_COEF<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 14; ++i) { GATHER_2x (W[i], saved_key, i); SWAP_ENDIAN (W[i]); }
				GATHER_2x (W[14], saved_key, 14);
				GATHER_2x (W[15], saved_key, 15);
				saved_key += (MMX_COEF<<5);
			} else {
				for (i=0; i < 14; ++i) { GATHER (W[i], saved_key, i); SWAP_ENDIAN (W[i]); }
				GATHER (W[14], saved_key, 14);
				GATHER (W[15], saved_key, 15);
				saved_key += (MMX_COEF<<4);
			}
			if ( ((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
				 ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK)) {
				SWAP_ENDIAN (W[14]);
				SWAP_ENDIAN (W[15]);
			}
			W += 16;
		}
#else
		unsigned j, k;
		ARCH_WORD_32 *p = (ARCH_WORD_32 *)w;
		__m128i *W = w;
		ARCH_WORD_32 *saved_key = (ARCH_WORD_32 *)_data;
		SHA1_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (MMX_COEF<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (MMX_COEF<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < MMX_COEF; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (MMX_COEF<<4);
			}
			for (i=0; i < 14; i++)
				SWAP_ENDIAN (W[i]);
			if ( ((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
				 ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK)) {
				SWAP_ENDIAN (W[14]);
				SWAP_ENDIAN (W[15]);
			}
			W += 16;
		}
#endif

		// now set our data pointer to point to this 'mixed' data.
		data = w;
	} else
		data = _data;

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_set1_epi32(0x67452301);
			b[i] = _mm_set1_epi32(0xefcdab89);
			c[i] = _mm_set1_epi32(0x98badcfe);
			d[i] = _mm_set1_epi32(0x10325476);
			e[i] = _mm_set1_epi32(0xC3D2E1F0);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+12]);
				e[i] = _mm_load_si128((__m128i *)&reload_state[i*16*4+16]);
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_load_si128((__m128i *)&reload_state[i*20+0]);
				b[i] = _mm_load_si128((__m128i *)&reload_state[i*20+4]);
				c[i] = _mm_load_si128((__m128i *)&reload_state[i*20+8]);
				d[i] = _mm_load_si128((__m128i *)&reload_state[i*20+12]);
				e[i] = _mm_load_si128((__m128i *)&reload_state[i*20+16]);
			}
		}
	}

	cst = _mm_set1_epi32(0x5A827999);
	SHA1_ROUND2a( a, b, c, d, e, SHA1_F,  0 );
	SHA1_ROUND2a( e, a, b, c, d, SHA1_F,  1 );
	SHA1_ROUND2a( d, e, a, b, c, SHA1_F,  2 );
	SHA1_ROUND2b( c, d, e, a, b, SHA1_F,  3 );
	SHA1_ROUND2b( b, c, d, e, a, SHA1_F,  4 );
	SHA1_ROUND2b( a, b, c, d, e, SHA1_F,  5 );
	SHA1_ROUND2b( e, a, b, c, d, SHA1_F,  6 );
	SHA1_ROUND2b( d, e, a, b, c, SHA1_F,  7 );
	SHA1_ROUND2c( c, d, e, a, b, SHA1_F,  8 );
	SHA1_ROUND2c( b, c, d, e, a, SHA1_F,  9 );
	SHA1_ROUND2c( a, b, c, d, e, SHA1_F, 10 );
	SHA1_ROUND2c( e, a, b, c, d, SHA1_F, 11 );
	SHA1_ROUND2c( d, e, a, b, c, SHA1_F, 12 );
	SHA1_ROUND2c( c, d, e, a, b, SHA1_F, 13 );
	SHA1_ROUND2d( b, c, d, e, a, SHA1_F, 14 );
	SHA1_ROUND2d( a, b, c, d, e, SHA1_F, 15 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_F, 16 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_F, 17 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_F, 18 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_F, 19 );

	cst = _mm_set1_epi32(0x6ED9EBA1);
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 20 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 21 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 22 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 23 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 24 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 25 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 26 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 27 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 28 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 29 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 30 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 31 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 32 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 33 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 34 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_G, 35 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_G, 36 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_G, 37 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_G, 38 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_G, 39 );

	cst = _mm_set1_epi32(0x8F1BBCDC);
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 40 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 41 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 42 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 43 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 44 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 45 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 46 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 47 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 48 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 49 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 50 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 51 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 52 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 53 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 54 );
	SHA1_ROUND2( a, b, c, d, e, SHA1_H, 55 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_H, 56 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_H, 57 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_H, 58 );
	SHA1_ROUND2( b, c, d, e, a, SHA1_H, 59 );

	cst = _mm_set1_epi32(0xCA62C1D6);
	SHA1_ROUND2( a, b, c, d, e, SHA1_I, 60 );
	SHA1_ROUND2( e, a, b, c, d, SHA1_I, 61 );
	SHA1_ROUND2( d, e, a, b, c, SHA1_I, 62 );
	SHA1_ROUND2( c, d, e, a, b, SHA1_I, 63 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 64 );
	SHA1_ROUND2x( a, b, c, d, e, SHA1_I, 65 );
	SHA1_ROUND2x( e, a, b, c, d, SHA1_I, 66 );
	SHA1_ROUND2x( d, e, a, b, c, SHA1_I, 67 );
	SHA1_ROUND2x( c, d, e, a, b, SHA1_I, 68 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 69 );
	SHA1_ROUND2x( a, b, c, d, e, SHA1_I, 70 );
	SHA1_ROUND2x( e, a, b, c, d, SHA1_I, 71 );
	SHA1_ROUND2x( d, e, a, b, c, SHA1_I, 72 );
	SHA1_ROUND2x( c, d, e, a, b, SHA1_I, 73 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 74 );
	SHA1_ROUND2x( a, b, c, d, e, SHA1_I, 75 );
	SHA1_ROUND2x( e, a, b, c, d, SHA1_I, 76 );
	SHA1_ROUND2x( d, e, a, b, c, SHA1_I, 77 );
	SHA1_ROUND2x( c, d, e, a, b, SHA1_I, 78 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 79 );

	if((SSEi_flags & SSEi_RELOAD)==0)
	{
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_set1_epi32(0x67452301));
			b[i] = _mm_add_epi32(b[i], _mm_set1_epi32(0xefcdab89));
			c[i] = _mm_add_epi32(c[i], _mm_set1_epi32(0x98badcfe));
			d[i] = _mm_add_epi32(d[i], _mm_set1_epi32(0x10325476));
			e[i] = _mm_add_epi32(e[i], _mm_set1_epi32(0xC3D2E1F0));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+12]));
				e[i] = _mm_add_epi32(e[i], _mm_load_si128((__m128i *)&reload_state[i*16*4+16]));
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*20+0]));
				b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*20+4]));
				c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*20+8]));
				d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*20+12]));
				e[i] = _mm_add_epi32(e[i], _mm_load_si128((__m128i *)&reload_state[i*20+16]));
			}
		}
	}
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		SHA1_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*16*4+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+12], d[i]);
			_mm_store_si128((__m128i *)&out[i*16*4+16], e[i]);
		}
	}
	else
	{
		SHA1_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*20+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*20+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*20+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*20+12], d[i]);
			_mm_store_si128((__m128i *)&out[i*20+16], e[i]);
		}
	}
}
#endif /* SHA_BUF_SIZ */
#endif /* SHA1_SSE_PARA */


#define S0(x)                           \
(                                       \
    _mm_xor_si128 (                     \
        _mm_roti_epi32 (x, -22),        \
        _mm_xor_si128 (                 \
            _mm_roti_epi32 (x,  -2),    \
            _mm_roti_epi32 (x, -13)     \
        )                               \
    )                                   \
)

#define S1(x)                           \
(                                       \
    _mm_xor_si128 (                     \
        _mm_roti_epi32 (x, -25),        \
        _mm_xor_si128 (                 \
            _mm_roti_epi32 (x,  -6),    \
            _mm_roti_epi32 (x, -11)     \
        )                               \
    )                                   \
)

#define s0(x)                           \
(                                       \
    _mm_xor_si128 (                     \
        _mm_srli_epi32 (x, 3),          \
        _mm_xor_si128 (                 \
            _mm_roti_epi32 (x,  -7),    \
            _mm_roti_epi32 (x, -18)     \
        )                               \
    )                                   \
)

#define s1(x)                           \
(                                       \
    _mm_xor_si128 (                     \
        _mm_srli_epi32 (x, 10),         \
        _mm_xor_si128 (                 \
            _mm_roti_epi32 (x, -17),    \
            _mm_roti_epi32 (x, -19)     \
        )                               \
    )                                   \
)

#define Maj(x,y,z) _mm_cmov_si128 (x, y, _mm_xor_si128 (z, y))

#define Ch(x,y,z) _mm_cmov_si128 (y, z, x)

#undef R
#define R(x,x1,x2,x3)                         \
{                                             \
    tmp1 = _mm_add_epi32 (s1(w[x1]), w[x2]);  \
    tmp1 = _mm_add_epi32 (w[x],  tmp1);       \
    w[x] = _mm_add_epi32 (s0(w[x3]), tmp1);   \
}

#define SHA256_STEP0(a,b,c,d,e,f,g,h,x,K)            \
{                                                    \
    tmp1 = _mm_add_epi32 (h,    S1(e));              \
    tmp1 = _mm_add_epi32 (tmp1, Ch(e,f,g));          \
    tmp1 = _mm_add_epi32 (tmp1, _mm_set1_epi32(K));  \
    tmp1 = _mm_add_epi32 (tmp1, w[x]);               \
    tmp2 = _mm_add_epi32 (S0(a),Maj(a,b,c));         \
    d    = _mm_add_epi32 (tmp1, d);                  \
    h    = _mm_add_epi32 (tmp1, tmp2);               \
}
#define SHA256_STEP_R(a,b,c,d,e,f,g,h, x,x1,x2,x3, K)\
{                                                    \
	R(x,x1,x2,x3);								     \
    tmp1 = _mm_add_epi32 (h,    S1(e));              \
    tmp1 = _mm_add_epi32 (tmp1, Ch(e,f,g));          \
    tmp1 = _mm_add_epi32 (tmp1, _mm_set1_epi32(K));  \
    tmp1 = _mm_add_epi32 (tmp1, w[x]);				 \
    tmp2 = _mm_add_epi32 (S0(a),Maj(a,b,c));         \
    d    = _mm_add_epi32 (tmp1, d);                  \
    h    = _mm_add_epi32 (tmp1, tmp2);               \
}

// this macro was used to create the new macros for the smaller w[16] array.
/*
#define SHA256_STEP(a,b,c,d,e,f,g,h,x,K)       \
	printf ("_SHA256_STEP(%s,%s,%s,%s,%s,%s,%s,%s, %d,%d,%2d,%2d, 0x%08x);\n", \
                        #a, #b, #c, #d, #e, #f, #g, #h, \
                        (x)%16, (x-2)>15?(x-2)%16:x-2, (x-7)>15?(x-7)%16:x-7, (x-15)>15?(x-15)%16:x-15, K);
*/

/* TODO:
 *  1. (DONE) try to get w[] array down to w[32].  (Actually, now it is ONLY [16] in size.
 *            the data[] array is only required to be 16 elements also.
 *  2. (DONE) Get sha224 working (different IV, and only copy 224 bits)
 *  3. (DONE, needs tested.) Handle the init, so we can do more than 1 block.
 *  4. (DONE) try to make this function work properly with either a 'flat' input or a more common (in JtR lingo), COEF mixed set of data
 *  5. (DONE) Redid the out, into a MMX mixed blob, and not 8 arrays
 *  6. (DONE) Separated the reload array from the out array.  Required for work like PBKDF2, where we capture first block value, then replay it over and over.
 *  6. Optimizations.  Look at intel, AMD, newest intel, newest AMD, etc performances.
 *  7. See if we can do anything better using 'DO_PARA' type methods, like we do in SHA1/MD4/5
 */
#if defined (MMX_COEF_SHA256)
void SSESHA256body(__m128i *data, ARCH_WORD_32 *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags)
{
	__m128i a, b, c, d, e, f, g, h;
	union {
		__m128i w[16];
		ARCH_WORD_32 p[16*sizeof(__m128i)/sizeof(ARCH_WORD_32)];

	}_w;
	__m128i tmp1, tmp2, *w=_w.w;
	ARCH_WORD_32 *saved_key=0;

	int i;
	if (SSEi_flags & SSEi_FLAT_IN) {

#ifdef __SSE4_1__
		saved_key = (ARCH_WORD_32 *)data;
		if (SSEi_flags & SSEi_4BUF_INPUT) {
			for (i=0; i < 14; ++i) { GATHER_4x (w[i], saved_key, i); SWAP_ENDIAN (w[i]); }
			GATHER_4x (w[14], saved_key, 14);
			GATHER_4x (w[15], saved_key, 15);
		} else if (SSEi_flags & SSEi_2BUF_INPUT) {
			for (i=0; i < 14; ++i) { GATHER_2x (w[i], saved_key, i); SWAP_ENDIAN (w[i]); }
			GATHER_2x (w[14], saved_key, 14);
			GATHER_2x (w[15], saved_key, 15);
		} else {
			for (i=0; i < 14; ++i) { GATHER (w[i], saved_key, i); SWAP_ENDIAN (w[i]); }
			GATHER (w[14], saved_key, 14);
			GATHER (w[15], saved_key, 15);
		}
		if ( ((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			 ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK)) {
			SWAP_ENDIAN (w[14]);
			SWAP_ENDIAN (w[15]);
		}
#else
		int j;
		ARCH_WORD_32 *p = _w.p;
		saved_key = (ARCH_WORD_32 *)data;
		if (SSEi_flags & SSEi_4BUF_INPUT) {
			for (j=0; j < 16; j++)
				for (i=0; i < MMX_COEF_SHA256; i++)
					*p++ = saved_key[(i<<6)+j];
		} else if (SSEi_flags & SSEi_2BUF_INPUT) {
			for (j=0; j < 16; j++)
				for (i=0; i < MMX_COEF_SHA256; i++)
					*p++ = saved_key[(i<<5)+j];
		} else {
			for (j=0; j < 16; j++)
				for (i=0; i < MMX_COEF_SHA256; i++)
					*p++ = saved_key[(i<<4)+j];
		}
		for (i=0; i < 14; i++)
			SWAP_ENDIAN (w[i]);
		if ( ((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			 ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK)) {
			SWAP_ENDIAN (w[14]);
			SWAP_ENDIAN (w[15]);
		}
#endif
	} else
		memcpy(w, data, 16*sizeof(__m128i));

//	dump_stuff_shammx(w, 64, 0);


	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			i=0; // later if we do PARA, i will be used in the PARA_FOR loop
			a = _mm_load_si128((__m128i *)&reload_state[i*16*4+0]);
			b = _mm_load_si128((__m128i *)&reload_state[i*16*4+4]);
			c = _mm_load_si128((__m128i *)&reload_state[i*16*4+8]);
			d = _mm_load_si128((__m128i *)&reload_state[i*16*4+12]);
			e = _mm_load_si128((__m128i *)&reload_state[i*16*4+16]);
			f = _mm_load_si128((__m128i *)&reload_state[i*16*4+20]);
			g = _mm_load_si128((__m128i *)&reload_state[i*16*4+24]);
			h = _mm_load_si128((__m128i *)&reload_state[i*16*4+28]);
		}
		else
		{
			i=0;
			a = _mm_load_si128((__m128i *)&reload_state[i*32+0]);
			b = _mm_load_si128((__m128i *)&reload_state[i*32+4]);
			c = _mm_load_si128((__m128i *)&reload_state[i*32+8]);
			d = _mm_load_si128((__m128i *)&reload_state[i*32+12]);
			e = _mm_load_si128((__m128i *)&reload_state[i*32+16]);
			f = _mm_load_si128((__m128i *)&reload_state[i*32+20]);
			g = _mm_load_si128((__m128i *)&reload_state[i*32+24]);
			h = _mm_load_si128((__m128i *)&reload_state[i*32+28]);
		}
	} else {
		if (SSEi_flags & SSEi_CRYPT_SHA224) {
			/* SHA-224 IV */
			a = _mm_set1_epi32 (0xc1059ed8);
			b = _mm_set1_epi32 (0x367cd507);
			c = _mm_set1_epi32 (0x3070dd17);
			d = _mm_set1_epi32 (0xf70e5939);
			e = _mm_set1_epi32 (0xffc00b31);
			f = _mm_set1_epi32 (0x68581511);
			g = _mm_set1_epi32 (0x64f98fa7);
			h = _mm_set1_epi32 (0xbefa4fa4);
		} else {
			// SHA-256 IV */
			a = _mm_set1_epi32 (0x6a09e667);
			b = _mm_set1_epi32 (0xbb67ae85);
			c = _mm_set1_epi32 (0x3c6ef372);
			d = _mm_set1_epi32 (0xa54ff53a);
			e = _mm_set1_epi32 (0x510e527f);
			f = _mm_set1_epi32 (0x9b05688c);
			g = _mm_set1_epi32 (0x1f83d9ab);
			h = _mm_set1_epi32 (0x5be0cd19);
		}
	}
	SHA256_STEP0(a, b, c, d, e, f, g, h,  0, 0x428a2f98);
	SHA256_STEP0(h, a, b, c, d, e, f, g,  1, 0x71374491);
	SHA256_STEP0(g, h, a, b, c, d, e, f,  2, 0xb5c0fbcf);
	SHA256_STEP0(f, g, h, a, b, c, d, e,  3, 0xe9b5dba5);
	SHA256_STEP0(e, f, g, h, a, b, c, d,  4, 0x3956c25b);
	SHA256_STEP0(d, e, f, g, h, a, b, c,  5, 0x59f111f1);
	SHA256_STEP0(c, d, e, f, g, h, a, b,  6, 0x923f82a4);
	SHA256_STEP0(b, c, d, e, f, g, h, a,  7, 0xab1c5ed5);
	SHA256_STEP0(a, b, c, d, e, f, g, h,  8, 0xd807aa98);
	SHA256_STEP0(h, a, b, c, d, e, f, g,  9, 0x12835b01);
	SHA256_STEP0(g, h, a, b, c, d, e, f, 10, 0x243185be);
	SHA256_STEP0(f, g, h, a, b, c, d, e, 11, 0x550c7dc3);
	SHA256_STEP0(e, f, g, h, a, b, c, d, 12, 0x72be5d74);
	SHA256_STEP0(d, e, f, g, h, a, b, c, 13, 0x80deb1fe);
	SHA256_STEP0(c, d, e, f, g, h, a, b, 14, 0x9bdc06a7);
	SHA256_STEP0(b, c, d, e, f, g, h, a, 15, 0xc19bf174);

	SHA256_STEP_R(a,b,c,d,e,f,g,h,  0,14, 9, 1, 0xe49b69c1);
	SHA256_STEP_R(h,a,b,c,d,e,f,g,  1,15,10, 2, 0xefbe4786);
	SHA256_STEP_R(g,h,a,b,c,d,e,f,  2, 0,11, 3, 0x0fc19dc6);
	SHA256_STEP_R(f,g,h,a,b,c,d,e,  3, 1,12, 4, 0x240ca1cc);
	SHA256_STEP_R(e,f,g,h,a,b,c,d,  4, 2,13, 5, 0x2de92c6f);
	SHA256_STEP_R(d,e,f,g,h,a,b,c,  5, 3,14, 6, 0x4a7484aa);
	SHA256_STEP_R(c,d,e,f,g,h,a,b,  6, 4,15, 7, 0x5cb0a9dc);
	SHA256_STEP_R(b,c,d,e,f,g,h,a,  7, 5, 0, 8, 0x76f988da);
	SHA256_STEP_R(a,b,c,d,e,f,g,h,  8, 6, 1, 9, 0x983e5152);
	SHA256_STEP_R(h,a,b,c,d,e,f,g,  9, 7, 2,10, 0xa831c66d);
	SHA256_STEP_R(g,h,a,b,c,d,e,f, 10, 8, 3,11, 0xb00327c8);
	SHA256_STEP_R(f,g,h,a,b,c,d,e, 11, 9, 4,12, 0xbf597fc7);
	SHA256_STEP_R(e,f,g,h,a,b,c,d, 12,10, 5,13, 0xc6e00bf3);
	SHA256_STEP_R(d,e,f,g,h,a,b,c, 13,11, 6,14, 0xd5a79147);
	SHA256_STEP_R(c,d,e,f,g,h,a,b, 14,12, 7,15, 0x06ca6351);
	SHA256_STEP_R(b,c,d,e,f,g,h,a, 15,13, 8, 0, 0x14292967);

	SHA256_STEP_R(a,b,c,d,e,f,g,h,  0,14, 9, 1, 0x27b70a85);
	SHA256_STEP_R(h,a,b,c,d,e,f,g,  1,15,10, 2, 0x2e1b2138);
	SHA256_STEP_R(g,h,a,b,c,d,e,f,  2, 0,11, 3, 0x4d2c6dfc);
	SHA256_STEP_R(f,g,h,a,b,c,d,e,  3, 1,12, 4, 0x53380d13);
	SHA256_STEP_R(e,f,g,h,a,b,c,d,  4, 2,13, 5, 0x650a7354);
	SHA256_STEP_R(d,e,f,g,h,a,b,c,  5, 3,14, 6, 0x766a0abb);
	SHA256_STEP_R(c,d,e,f,g,h,a,b,  6, 4,15, 7, 0x81c2c92e);
	SHA256_STEP_R(b,c,d,e,f,g,h,a,  7, 5, 0, 8, 0x92722c85);
	SHA256_STEP_R(a,b,c,d,e,f,g,h,  8, 6, 1, 9, 0xa2bfe8a1);
	SHA256_STEP_R(h,a,b,c,d,e,f,g,  9, 7, 2,10, 0xa81a664b);
	SHA256_STEP_R(g,h,a,b,c,d,e,f, 10, 8, 3,11, 0xc24b8b70);
	SHA256_STEP_R(f,g,h,a,b,c,d,e, 11, 9, 4,12, 0xc76c51a3);
	SHA256_STEP_R(e,f,g,h,a,b,c,d, 12,10, 5,13, 0xd192e819);
	SHA256_STEP_R(d,e,f,g,h,a,b,c, 13,11, 6,14, 0xd6990624);
	SHA256_STEP_R(c,d,e,f,g,h,a,b, 14,12, 7,15, 0xf40e3585);
	SHA256_STEP_R(b,c,d,e,f,g,h,a, 15,13, 8, 0, 0x106aa070);

	SHA256_STEP_R(a,b,c,d,e,f,g,h,  0,14, 9, 1, 0x19a4c116);
	SHA256_STEP_R(h,a,b,c,d,e,f,g,  1,15,10, 2, 0x1e376c08);
	SHA256_STEP_R(g,h,a,b,c,d,e,f,  2, 0,11, 3, 0x2748774c);
	SHA256_STEP_R(f,g,h,a,b,c,d,e,  3, 1,12, 4, 0x34b0bcb5);
	SHA256_STEP_R(e,f,g,h,a,b,c,d,  4, 2,13, 5, 0x391c0cb3);
	SHA256_STEP_R(d,e,f,g,h,a,b,c,  5, 3,14, 6, 0x4ed8aa4a);
	SHA256_STEP_R(c,d,e,f,g,h,a,b,  6, 4,15, 7, 0x5b9cca4f);
	SHA256_STEP_R(b,c,d,e,f,g,h,a,  7, 5, 0, 8, 0x682e6ff3);
	SHA256_STEP_R(a,b,c,d,e,f,g,h,  8, 6, 1, 9, 0x748f82ee);
	SHA256_STEP_R(h,a,b,c,d,e,f,g,  9, 7, 2,10, 0x78a5636f);
	SHA256_STEP_R(g,h,a,b,c,d,e,f, 10, 8, 3,11, 0x84c87814);
	SHA256_STEP_R(f,g,h,a,b,c,d,e, 11, 9, 4,12, 0x8cc70208);
	SHA256_STEP_R(e,f,g,h,a,b,c,d, 12,10, 5,13, 0x90befffa);
	SHA256_STEP_R(d,e,f,g,h,a,b,c, 13,11, 6,14, 0xa4506ceb);
	SHA256_STEP_R(c,d,e,f,g,h,a,b, 14,12, 7,15, 0xbef9a3f7);
	SHA256_STEP_R(b,c,d,e,f,g,h,a, 15,13, 8, 0, 0xc67178f2);

	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			i=0; // later if we do PARA, i will be used in the PARA_FOR loop
			a = _mm_add_epi32(a,_mm_load_si128((__m128i *)&reload_state[i*16*2+0]));
			b = _mm_add_epi32(b,_mm_load_si128((__m128i *)&reload_state[i*16*2+4]));
			c = _mm_add_epi32(c,_mm_load_si128((__m128i *)&reload_state[i*16*2+8]));
			d = _mm_add_epi32(d,_mm_load_si128((__m128i *)&reload_state[i*16*2+12]));
			e = _mm_add_epi32(e,_mm_load_si128((__m128i *)&reload_state[i*16*2+16]));
			f = _mm_add_epi32(f,_mm_load_si128((__m128i *)&reload_state[i*16*2+20]));
			g = _mm_add_epi32(g,_mm_load_si128((__m128i *)&reload_state[i*16*2+24]));
			h = _mm_add_epi32(h,_mm_load_si128((__m128i *)&reload_state[i*16*2+28]));
		}
		else
		{
			i=0;
			a = _mm_add_epi32(a,_mm_load_si128((__m128i *)&reload_state[i*32+0]));
			b = _mm_add_epi32(b,_mm_load_si128((__m128i *)&reload_state[i*32+4]));
			c = _mm_add_epi32(c,_mm_load_si128((__m128i *)&reload_state[i*32+8]));
			d = _mm_add_epi32(d,_mm_load_si128((__m128i *)&reload_state[i*32+12]));
			e = _mm_add_epi32(e,_mm_load_si128((__m128i *)&reload_state[i*32+16]));
			f = _mm_add_epi32(f,_mm_load_si128((__m128i *)&reload_state[i*32+20]));
			g = _mm_add_epi32(g,_mm_load_si128((__m128i *)&reload_state[i*32+24]));
			h = _mm_add_epi32(h,_mm_load_si128((__m128i *)&reload_state[i*32+28]));
		}
	} else if ((SSEi_flags & SSEi_SKIP_FINAL_ADD) == 0) {
		if (SSEi_flags & SSEi_CRYPT_SHA224) {
			/* SHA-224 IV */
			a = _mm_add_epi32 (a, _mm_set1_epi32 (0xc1059ed8));
			b = _mm_add_epi32 (b, _mm_set1_epi32 (0x367cd507));
			c = _mm_add_epi32 (c, _mm_set1_epi32 (0x3070dd17));
			d = _mm_add_epi32 (d, _mm_set1_epi32 (0xf70e5939));
			e = _mm_add_epi32 (e, _mm_set1_epi32 (0xffc00b31));
			f = _mm_add_epi32 (f, _mm_set1_epi32 (0x68581511));
			g = _mm_add_epi32 (g, _mm_set1_epi32 (0x64f98fa7));
			h = _mm_add_epi32 (h, _mm_set1_epi32 (0xbefa4fa4));
		} else {
			/* SHA-256 IV */
			a = _mm_add_epi32 (a, _mm_set1_epi32 (0x6a09e667));
			b = _mm_add_epi32 (b, _mm_set1_epi32 (0xbb67ae85));
			c = _mm_add_epi32 (c, _mm_set1_epi32 (0x3c6ef372));
			d = _mm_add_epi32 (d, _mm_set1_epi32 (0xa54ff53a));
			e = _mm_add_epi32 (e, _mm_set1_epi32 (0x510e527f));
			f = _mm_add_epi32 (f, _mm_set1_epi32 (0x9b05688c));
			g = _mm_add_epi32 (g, _mm_set1_epi32 (0x1f83d9ab));
			h = _mm_add_epi32 (h, _mm_set1_epi32 (0x5be0cd19));
		}
	}
	if (SSEi_flags & SSEi_SWAP_FINAL) {
		/* NOTE, if we swap OUT of BE into proper LE, then this can not be
		 * used in a sha256_flags&SHA256_RELOAD manner, without swapping back into BE format.
		 * NORMALLY, a format will switch binary values into BE format at start, and then
		 * just take the 'normal' non swapped output of this function (i.e. keep it in BE) */
		SWAP_ENDIAN (a);
		SWAP_ENDIAN (b);
		SWAP_ENDIAN (c);
		SWAP_ENDIAN (d);
		SWAP_ENDIAN (e);
		SWAP_ENDIAN (f);
		SWAP_ENDIAN (g);
		SWAP_ENDIAN (h);
	}
	/* We store the MMX_mixed values.  This will be in proper 'mixed' format, in BE
	 * format (i.e. correct to reload on a subsquent call), UNLESS, swapped in the prior
	 * if statement (the SHA256_SWAP_FINAL) */
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		i=0;
		//SHA512_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*16*4+0], a);
			_mm_store_si128((__m128i *)&out[i*16*4+4], b);
			_mm_store_si128((__m128i *)&out[i*16*4+8], c);
			_mm_store_si128((__m128i *)&out[i*16*4+12], d);
			_mm_store_si128((__m128i *)&out[i*16*4+16], e);
			_mm_store_si128((__m128i *)&out[i*16*4+20], f);
			_mm_store_si128((__m128i *)&out[i*16*4+24], g);
			_mm_store_si128((__m128i *)&out[i*16*4+28], h);
		}
	}
	else
	{
		i=0;
		//SHA512_PARA_DO(i)
		{
			_mm_store_si128 ((__m128i *)&(out[i*32+0]), a);
			_mm_store_si128 ((__m128i *)&(out[i*32+4]), b);
			_mm_store_si128 ((__m128i *)&(out[i*32+8]), c);
			_mm_store_si128 ((__m128i *)&(out[i*32+12]), d);
			_mm_store_si128 ((__m128i *)&(out[i*32+16]), e);
			_mm_store_si128 ((__m128i *)&(out[i*32+20]), f);
			_mm_store_si128 ((__m128i *)&(out[i*32+24]), g);
			_mm_store_si128 ((__m128i *)&(out[i*32+28]), h);
		}
	}

}
#endif

/* SHA-512 below */

#undef S0
#define S0(x)                          \
(                                      \
    _mm_xor_si128 (                    \
        _mm_roti_epi64 (x, -39),       \
        _mm_xor_si128 (                \
            _mm_roti_epi64 (x, -28),   \
            _mm_roti_epi64 (x, -34)    \
        )                              \
    )                                  \
)

#undef S1
#define S1(x)                          \
(                                      \
    _mm_xor_si128 (                    \
        _mm_roti_epi64 (x, -41),       \
        _mm_xor_si128 (                \
            _mm_roti_epi64 (x, -14),   \
            _mm_roti_epi64 (x, -18)    \
        )                              \
    )                                  \
)

#undef s0
#define s0(x)                          \
(                                      \
    _mm_xor_si128 (                    \
        _mm_srli_epi64 (x, 7),         \
        _mm_xor_si128 (                \
            _mm_roti_epi64 (x, -1),    \
            _mm_roti_epi64 (x, -8)     \
        )                              \
    )                                  \
)

#undef s1
#define s1(x)                          \
(                                      \
    _mm_xor_si128 (                    \
        _mm_srli_epi64 (x, 6),         \
        _mm_xor_si128 (                \
            _mm_roti_epi64 (x, -19),   \
            _mm_roti_epi64 (x, -61)    \
        )                              \
    )                                  \
)

#define Maj(x,y,z) _mm_cmov_si128 (x, y, _mm_xor_si128 (z, y))

#define Ch(x,y,z)  _mm_cmov_si128 (y, z, x)

#undef R
#define R(t)                                         \
{                                                    \
    tmp1 = _mm_add_epi64 (s1(w[t -  2]), w[t - 7]);  \
    tmp2 = _mm_add_epi64 (s0(w[t - 15]), w[t - 16]); \
    w[t] = _mm_add_epi64 (tmp1, tmp2);               \
}

#define SHA512_STEP(a,b,c,d,e,f,g,h,x,K)             \
{                                                    \
    tmp1 = _mm_add_epi64 (h,    w[x]);               \
    tmp2 = _mm_add_epi64 (S1(e),_mm_set1_epi64x(K)); \
    tmp1 = _mm_add_epi64 (tmp1, Ch(e,f,g));          \
    tmp1 = _mm_add_epi64 (tmp1, tmp2);               \
    tmp2 = _mm_add_epi64 (S0(a),Maj(a,b,c));         \
    d    = _mm_add_epi64 (tmp1, d);                  \
    h    = _mm_add_epi64 (tmp1, tmp2);               \
}

#if defined (MMX_COEF_SHA512)
void SSESHA512body(__m128i* data, unsigned int *out, ARCH_WORD_32 *reload_state, unsigned SSEi_flags)
{
	int i;

	__m128i a, b, c, d, e, f, g, h;
	__m128i w[80], tmp1, tmp2;

	if (SSEi_flags & SSEi_FLAT_IN) {

		if (SSEi_flags & SSEi_2BUF_INPUT) {
			ARCH_WORD_64 (*saved_key)[32] = (ARCH_WORD_64(*)[32])data;
			for (i = 0; i < 14; i += 2) {
				GATHER64 (tmp1, saved_key, i);
				GATHER64 (tmp2, saved_key, i + 1);
				SWAP_ENDIAN64 (tmp1);
				SWAP_ENDIAN64 (tmp2);
				w[i] = tmp1;
				w[i + 1] = tmp2;
			}
			GATHER64 (tmp1, saved_key, 14);
			GATHER64 (tmp2, saved_key, 15);
		} else {
			ARCH_WORD_64 (*saved_key)[16] = (ARCH_WORD_64(*)[16])data;
			for (i = 0; i < 14; i += 2) {
				GATHER64 (tmp1, saved_key, i);
				GATHER64 (tmp2, saved_key, i + 1);
				SWAP_ENDIAN64 (tmp1);
				SWAP_ENDIAN64 (tmp2);
				w[i] = tmp1;
				w[i + 1] = tmp2;
			}
			GATHER64 (tmp1, saved_key, 14);
			GATHER64 (tmp2, saved_key, 15);
		}
		if ( ((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK)) {
			SWAP_ENDIAN64 (tmp1);
			SWAP_ENDIAN64 (tmp2);
		}
		w[14] = tmp1;
		w[15] = tmp2;
	} else
		memcpy(w, data, 16*sizeof(__m128i));

	for (i = 16; i < 80; i++)
		R(i);

	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			i=0; // later if we do PARA, i will be used in the PARA_FOR loop
			a = _mm_load_si128((__m128i *)&reload_state[i*16*8+0]);
			b = _mm_load_si128((__m128i *)&reload_state[i*16*8+4]);
			c = _mm_load_si128((__m128i *)&reload_state[i*16*8+8]);
			d = _mm_load_si128((__m128i *)&reload_state[i*16*8+12]);
			e = _mm_load_si128((__m128i *)&reload_state[i*16*8+16]);
			f = _mm_load_si128((__m128i *)&reload_state[i*16*8+20]);
			g = _mm_load_si128((__m128i *)&reload_state[i*16*8+24]);
			h = _mm_load_si128((__m128i *)&reload_state[i*16*8+28]);
		}
		else
		{
			i=0;
			a = _mm_load_si128((__m128i *)&reload_state[i*32+0]);
			b = _mm_load_si128((__m128i *)&reload_state[i*32+4]);
			c = _mm_load_si128((__m128i *)&reload_state[i*32+8]);
			d = _mm_load_si128((__m128i *)&reload_state[i*32+12]);
			e = _mm_load_si128((__m128i *)&reload_state[i*32+16]);
			f = _mm_load_si128((__m128i *)&reload_state[i*32+20]);
			g = _mm_load_si128((__m128i *)&reload_state[i*32+24]);
			h = _mm_load_si128((__m128i *)&reload_state[i*32+28]);
		}
	} else {
		if (SSEi_flags & SSEi_CRYPT_SHA384) {
			/* SHA-384 IV */
			a = _mm_set1_epi64x (0xcbbb9d5dc1059ed8ULL);
			b = _mm_set1_epi64x (0x629a292a367cd507ULL);
			c = _mm_set1_epi64x (0x9159015a3070dd17ULL);
			d = _mm_set1_epi64x (0x152fecd8f70e5939ULL);
			e = _mm_set1_epi64x (0x67332667ffc00b31ULL);
			f = _mm_set1_epi64x (0x8eb44a8768581511ULL);
			g = _mm_set1_epi64x (0xdb0c2e0d64f98fa7ULL);
			h = _mm_set1_epi64x (0x47b5481dbefa4fa4ULL);
		} else {
			// SHA-512 IV */
			a = _mm_set1_epi64x (0x6a09e667f3bcc908ULL);
			b = _mm_set1_epi64x (0xbb67ae8584caa73bULL);
			c = _mm_set1_epi64x (0x3c6ef372fe94f82bULL);
			d = _mm_set1_epi64x (0xa54ff53a5f1d36f1ULL);
			e = _mm_set1_epi64x (0x510e527fade682d1ULL);
			f = _mm_set1_epi64x (0x9b05688c2b3e6c1fULL);
			g = _mm_set1_epi64x (0x1f83d9abfb41bd6bULL);
			h = _mm_set1_epi64x (0x5be0cd19137e2179ULL);
		}
	}

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

	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT)==SSEi_RELOAD_INP_FMT)
		{
			i=0; // later if we do PARA, i will be used in the PARA_FOR loop
			//SHA512_PARA_DO(i)
			{
				a = _mm_add_epi64(a,_mm_load_si128((__m128i *)&reload_state[i*16*8+0]));
				b = _mm_add_epi64(b,_mm_load_si128((__m128i *)&reload_state[i*16*8+4]));
				c = _mm_add_epi64(c,_mm_load_si128((__m128i *)&reload_state[i*16*8+8]));
				d = _mm_add_epi64(d,_mm_load_si128((__m128i *)&reload_state[i*16*8+12]));
				e = _mm_add_epi64(e,_mm_load_si128((__m128i *)&reload_state[i*16*8+16]));
				f = _mm_add_epi64(f,_mm_load_si128((__m128i *)&reload_state[i*16*8+20]));
				g = _mm_add_epi64(g,_mm_load_si128((__m128i *)&reload_state[i*16*8+24]));
				h = _mm_add_epi64(h,_mm_load_si128((__m128i *)&reload_state[i*16*8+28]));
			}
		}
		else
		{
			i=0;
			//SHA512_PARA_DO(i)
			{
				a = _mm_add_epi64(a,_mm_load_si128((__m128i *)&reload_state[i*32+0]));
				b = _mm_add_epi64(b,_mm_load_si128((__m128i *)&reload_state[i*32+4]));
				c = _mm_add_epi64(c,_mm_load_si128((__m128i *)&reload_state[i*32+8]));
				d = _mm_add_epi64(d,_mm_load_si128((__m128i *)&reload_state[i*32+12]));
				e = _mm_add_epi64(e,_mm_load_si128((__m128i *)&reload_state[i*32+16]));
				f = _mm_add_epi64(f,_mm_load_si128((__m128i *)&reload_state[i*32+20]));
				g = _mm_add_epi64(g,_mm_load_si128((__m128i *)&reload_state[i*32+24]));
				h = _mm_add_epi64(h,_mm_load_si128((__m128i *)&reload_state[i*32+28]));
				}
		}
	} else if ((SSEi_flags & SSEi_SKIP_FINAL_ADD) == 0) {
		if (SSEi_flags & SSEi_CRYPT_SHA384) {
			/* SHA-384 IV */
			a = _mm_add_epi64 (a, _mm_set1_epi64x (0xcbbb9d5dc1059ed8ULL));
			b = _mm_add_epi64 (b, _mm_set1_epi64x (0x629a292a367cd507ULL));
			c = _mm_add_epi64 (c, _mm_set1_epi64x (0x9159015a3070dd17ULL));
			d = _mm_add_epi64 (d, _mm_set1_epi64x (0x152fecd8f70e5939ULL));
			e = _mm_add_epi64 (e, _mm_set1_epi64x (0x67332667ffc00b31ULL));
			f = _mm_add_epi64 (f, _mm_set1_epi64x (0x8eb44a8768581511ULL));
			g = _mm_add_epi64 (g, _mm_set1_epi64x (0xdb0c2e0d64f98fa7ULL));
			h = _mm_add_epi64 (h, _mm_set1_epi64x (0x47b5481dbefa4fa4ULL));
		} else {
			/* SHA-512 IV */
			a = _mm_add_epi64 (a, _mm_set1_epi64x (0x6a09e667f3bcc908ULL));
			b = _mm_add_epi64 (b, _mm_set1_epi64x (0xbb67ae8584caa73bULL));
			c = _mm_add_epi64 (c, _mm_set1_epi64x (0x3c6ef372fe94f82bULL));
			d = _mm_add_epi64 (d, _mm_set1_epi64x (0xa54ff53a5f1d36f1ULL));
			e = _mm_add_epi64 (e, _mm_set1_epi64x (0x510e527fade682d1ULL));
			f = _mm_add_epi64 (f, _mm_set1_epi64x (0x9b05688c2b3e6c1fULL));
			g = _mm_add_epi64 (g, _mm_set1_epi64x (0x1f83d9abfb41bd6bULL));
			h = _mm_add_epi64 (h, _mm_set1_epi64x (0x5be0cd19137e2179ULL));
		}
	}

	if (SSEi_flags & SSEi_SWAP_FINAL) {
		/* NOTE, if we swap OUT of BE into proper LE, then this can not be
		 * used in a sha512_flags&SHA512_RELOAD manner, without swapping back into BE format.
		 * NORMALLY, a format will switch binary values into BE format at start, and then
		 * just take the 'normal' non swapped output of this function (i.e. keep it in BE) */
		SWAP_ENDIAN64(a);
		SWAP_ENDIAN64(b);
		SWAP_ENDIAN64(c);
		SWAP_ENDIAN64(d);
		SWAP_ENDIAN64(e);
		SWAP_ENDIAN64(f);
		SWAP_ENDIAN64(g);
		SWAP_ENDIAN64(h);
	}

	/* We store the MMX_mixed values.  This will be in proper 'mixed' format, in BE
	 * format (i.e. correct to reload on a subsquent call), UNLESS, swapped in the prior
	 * if statement (the SHA512_SWAP_FINAL) */
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		i=0;
		//SHA512_PARA_DO(i)
		{
			_mm_store_si128((__m128i *)&out[i*16*8+0], a);
			_mm_store_si128((__m128i *)&out[i*16*8+4], b);
			_mm_store_si128((__m128i *)&out[i*16*8+8], c);
			_mm_store_si128((__m128i *)&out[i*16*8+12], d);
			_mm_store_si128((__m128i *)&out[i*16*8+16], e);
			_mm_store_si128((__m128i *)&out[i*16*8+20], f);
			_mm_store_si128((__m128i *)&out[i*16*8+24], g);
			_mm_store_si128((__m128i *)&out[i*16*8+28], h);
		}
	}
	else
	{
		i=0;
		//SHA512_PARA_DO(i)
		{
			_mm_store_si128 ((__m128i *)&(out[i*32+0]), a);
			_mm_store_si128 ((__m128i *)&(out[i*32+4]), b);
			_mm_store_si128 ((__m128i *)&(out[i*32+8]), c);
			_mm_store_si128 ((__m128i *)&(out[i*32+12]), d);
			_mm_store_si128 ((__m128i *)&(out[i*32+16]), e);
			_mm_store_si128 ((__m128i *)&(out[i*32+20]), f);
			_mm_store_si128 ((__m128i *)&(out[i*32+24]), g);
			_mm_store_si128 ((__m128i *)&(out[i*32+28]), h);
		}
	}


}
#endif
