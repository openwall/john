/*
 * This software is
 * Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>,
 * Copyright (c) 2012,2015,2024 Solar Designer,
 * Copyright (c) 2011-2015 JimF,
 * Copyright (c) 2011-2023 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * SHA-2 Copyright 2013, epixoip. Redistribution and use in source and binary
 * forms, with or without modification, are permitted provided that
 * redistribution of source retains the above copyright.
 */

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "pseudo_intrinsics.h"
#include "memory.h"
#include "md5.h"
#include "MD5_std.h"
#include "johnswap.h"
#include "simd-intrinsics-load-flags.h"
#include "aligned.h"
#include "misc.h"

/* Shorter names for use in index calculations */
#define VS32 SIMD_COEF_32
#define VS64 SIMD_COEF_64

#if SIMD_PARA_MD5
#define MD5_SSE_NUM_KEYS	(SIMD_COEF_32*SIMD_PARA_MD5)
#define MD5_PARA_DO(x)	for ((x)=0;(x)<SIMD_PARA_MD5;(x)++)

#define MD5_F(x,y,z)                            \
    tmp[i] = vcmov((y[i]),(z[i]),(x[i]));

#define MD5_G(x,y,z)                            \
    tmp[i] = vcmov((x[i]),(y[i]),(z[i]));

#ifdef vternarylogic
#define MD5_H(x,y,z)                            \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0x96);

#define MD5_H2(x,y,z)                           \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0x96);
#elif 1
#define MD5_H(x,y,z)                            \
    tmp2[i] = vxor((x[i]),(y[i]));              \
    tmp[i] = vxor(tmp2[i], (z[i]));

#define MD5_H2(x,y,z)                           \
    tmp[i] = vxor((x[i]), tmp2[i]);
#else
#define MD5_H(x,y,z)                            \
    tmp[i] = vxor((x[i]),(y[i]));               \
    tmp[i] = vxor((tmp[i]),(z[i]));

#define MD5_H2(x,y,z)                           \
    tmp[i] = vxor((y[i]),(z[i]));               \
    tmp[i] = vxor((tmp[i]),(x[i]));
#endif

#ifdef vternarylogic
#define MD5_I(x,y,z)                            \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0x39);
#elif __ARM_NEON || __aarch64__
#define MD5_I(x,y,z)                            \
    tmp[i] = vorn((x[i]), (z[i]));              \
    tmp[i] = vxor((tmp[i]), (y[i]));
#elif !VCMOV_EMULATED
#define MD5_I(x,y,z)                            \
    tmp[i] = vcmov((x[i]), mask, (z[i]));       \
    tmp[i] = vxor((tmp[i]), (y[i]));
#else
#define MD5_I(x,y,z)                            \
    tmp[i] = vandnot((z[i]), mask);             \
    tmp[i] = vor((tmp[i]),(x[i]));              \
    tmp[i] = vxor((tmp[i]),(y[i]));
#endif

#define MD5_STEP(f, a, b, c, d, x, t, s)            \
    MD5_PARA_DO(i) {                                \
        a[i] = vadd_epi32( a[i], vset1_epi32(t) );  \
        a[i] = vadd_epi32( a[i], data[i*16+x] );    \
        f((b),(c),(d))                              \
        a[i] = vadd_epi32( a[i], tmp[i] );          \
        a[i] = vroti_epi32( a[i], (s) );            \
        a[i] = vadd_epi32( a[i], b[i] );            \
    }

#define MD5_STEP_r16(f, a, b, c, d, x, t, s)        \
    MD5_PARA_DO(i) {                                \
        a[i] = vadd_epi32( a[i], vset1_epi32(t) );  \
        a[i] = vadd_epi32( a[i], data[i*16+x] );    \
        f((b),(c),(d))                              \
        a[i] = vadd_epi32( a[i], tmp[i] );          \
        a[i] = vroti16_epi32( a[i], (s) );          \
        a[i] = vadd_epi32( a[i], b[i] );            \
    }

void SIMDmd5body(vtype* _data, unsigned int *out,
                uint32_t *reload_state, unsigned SSEi_flags)
{
	union {
		vtype vec[16*SIMD_PARA_MD5];
		uint32_t u32[1];
	} uw;
	vtype *w = uw.vec;
	vtype a[SIMD_PARA_MD5];
	vtype b[SIMD_PARA_MD5];
	vtype c[SIMD_PARA_MD5];
	vtype d[SIMD_PARA_MD5];
	vtype tmp[SIMD_PARA_MD5];
#ifndef vternarylogic
	vtype tmp2[SIMD_PARA_MD5];
#endif
	unsigned int i;
	vtype *data;

#if !defined(vternarylogic) && !__ARM_NEON && !__aarch64__
	vtype mask;
	mask = vset1_epi32(0xffffffff);
#endif

	if (SSEi_flags & SSEi_FLAT_IN) {
		// Move _data to __data, mixing it SIMD_COEF_32 wise.
#if __SSE4_1__ || __MIC__
		unsigned k;
		vtype *W = w;
		uint32_t *saved_key = (uint32_t*)_data;
		MD5_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_4x(W[i], saved_key, i); }
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_2x(W[i], saved_key, i); }
				saved_key += (VS32<<5);
			} else {
				for (i=0; i < 16; ++i) { GATHER(W[i], saved_key, i); }
				saved_key += (VS32<<4);
			}
			W += 16;
		}
#else
		unsigned j, k;
		uint32_t *p = uw.u32;
#if !ARCH_LITTLE_ENDIAN
		vtype *W = w;
#endif
		uint32_t *saved_key = (uint32_t*)_data;
		MD5_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (VS32<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (VS32<<4);
			}
#if !ARCH_LITTLE_ENDIAN
			for (i=0; i < 14; i++)
				W[i] = vswap32(W[i]);
			if (((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			    ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) /* ||
			    (SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST) */) {
				W[14] = vswap32(W[14]);
				W[15] = vswap32(W[15]);
			}
			W += 16;
#endif
		}
#endif
		// now set our data pointer to point to this 'mixed' data.
		data = w;
	} else
		data = _data;

	if (!(SSEi_flags & SSEi_RELOAD))
	{
		MD5_PARA_DO(i)
		{
			a[i] = vset1_epi32(0x67452301);
			b[i] = vset1_epi32(0xefcdab89);
			c[i] = vset1_epi32(0x98badcfe);
			d[i] = vset1_epi32(0x10325476);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			MD5_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*16*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*16*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*16*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*16*VS32+3*VS32]);
			}
		}
		else
		{
			MD5_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*4*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*4*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*4*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*4*VS32+3*VS32]);
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
	MD5_STEP(MD5_H2, d, a, b, c, 8, 0x8771f681, 11)
	MD5_STEP_r16(MD5_H, c, d, a, b, 11, 0x6d9d6122, 16)
	MD5_STEP(MD5_H2, b, c, d, a, 14, 0xfde5380c, 23)
	MD5_STEP(MD5_H, a, b, c, d, 1, 0xa4beea44, 4)
	MD5_STEP(MD5_H2, d, a, b, c, 4, 0x4bdecfa9, 11)
	MD5_STEP_r16(MD5_H, c, d, a, b, 7, 0xf6bb4b60, 16)
	MD5_STEP(MD5_H2, b, c, d, a, 10, 0xbebfbc70, 23)
	MD5_STEP(MD5_H, a, b, c, d, 13, 0x289b7ec6, 4)
	MD5_STEP(MD5_H2, d, a, b, c, 0, 0xeaa127fa, 11)
	MD5_STEP_r16(MD5_H, c, d, a, b, 3, 0xd4ef3085, 16)
	MD5_STEP(MD5_H2, b, c, d, a, 6, 0x04881d05, 23)
	MD5_STEP(MD5_H, a, b, c, d, 9, 0xd9d4d039, 4)
	MD5_STEP(MD5_H2, d, a, b, c, 12, 0xe6db99e5, 11)
	MD5_STEP_r16(MD5_H, c, d, a, b, 15, 0x1fa27cf8, 16)
	MD5_STEP(MD5_H2, b, c, d, a, 2, 0xc4ac5665, 23)

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

	if (SSEi_flags & SSEi_REVERSE_STEPS)
	{
		MD5_PARA_DO(i)
		{
			vstore((vtype*)&out[i*4*VS32+0*VS32], a[i]);
		}
		return;
	}

	MD5_STEP(MD5_I, d, a, b, c, 11, 0xbd3af235, 10)
	MD5_STEP(MD5_I, c, d, a, b, 2, 0x2ad7d2bb, 15)
	MD5_STEP(MD5_I, b, c, d, a, 9, 0xeb86d391, 21)

	if (!(SSEi_flags & SSEi_RELOAD))
	{
		MD5_PARA_DO(i)
		{
			a[i] = vadd_epi32(a[i], vset1_epi32(0x67452301));
			b[i] = vadd_epi32(b[i], vset1_epi32(0xefcdab89));
			c[i] = vadd_epi32(c[i], vset1_epi32(0x98badcfe));
			d[i] = vadd_epi32(d[i], vset1_epi32(0x10325476));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			MD5_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*16*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*16*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*16*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*16*VS32+3*VS32]));
			}
		}
		else
		{
			MD5_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*4*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*4*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*4*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*4*VS32+3*VS32]));
			}
		}
	}

#if USE_EXPERIMENTAL
/*
 * This is currently not used for MD5, and was observed to result
 * in a significant performance regression (at least on XOP) just by sitting
 * here. http://www.openwall.com/lists/john-dev/2015/09/05/5
 * NOTE the regression might be gone now anyway since we went from -O3 to -O2.
 */
	if (SSEi_flags & SSEi_FLAT_OUT) {
		MD5_PARA_DO(i)
		{
			uint32_t *o = (uint32_t*)&out[i*4*VS32];
#if __AVX512F__ || __MIC__
			vtype idxs = vset_epi32(15*4,14*4,13*4,12*4,
			                        11*4,10*4, 9*4, 8*4,
			                         7*4, 6*4, 5*4, 4*4,
			                         3*4, 2*4, 1*4, 0*4);

			vscatter_epi32(o + 0, idxs, a[i], 4);
			vscatter_epi32(o + 1, idxs, b[i], 4);
			vscatter_epi32(o + 2, idxs, c[i], 4);
			vscatter_epi32(o + 3, idxs, d[i], 4);
#else
			uint32_t j, k;
			union {
				vtype v[4];
				uint32_t s[4 * VS32];
			} tmp;

			tmp.v[0] = a[i];
			tmp.v[1] = b[i];
			tmp.v[2] = c[i];
			tmp.v[3] = d[i];

			for (j = 0; j < VS32; j++)
				for (k = 0; k < 4; k++)
					o[j*4+k] = tmp.s[k*VS32+j];
#endif
		}
	}
	else
#endif

#if SIMD_PARA_MD5 > 1
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		if ((SSEi_flags & SSEi_OUTPUT_AS_2BUF_INP_FMT) == SSEi_OUTPUT_AS_2BUF_INP_FMT) {
			MD5_PARA_DO(i)
			{
				vstore((vtype*)&out[i*32*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*32*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*32*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*32*VS32+3*VS32], d[i]);
			}
		} else {
			MD5_PARA_DO(i)
			{
				vstore((vtype*)&out[i*16*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*16*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*16*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*16*VS32+3*VS32], d[i]);
			}
		}
	}
	else
#endif
	{
		MD5_PARA_DO(i)
		{
			vstore((vtype*)&out[i*4*VS32+0*VS32], a[i]);
			vstore((vtype*)&out[i*4*VS32+1*VS32], b[i]);
			vstore((vtype*)&out[i*4*VS32+2*VS32], c[i]);
			vstore((vtype*)&out[i*4*VS32+3*VS32], d[i]);
		}
	}
}

#if ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)    ( (index&(VS32-1))*4 + (i& (0xffffffff-3) )*VS32 + ((i)&3) )
#else
#define GETPOS(i, index)    ( (index&(VS32-1))*4 + (i& (0xffffffff-3) )*VS32 + (3-((i)&3)) )
#endif

static MAYBE_INLINE void mmxput(void *buf, unsigned int index, unsigned int bid,
                                unsigned int offset, unsigned char *src,
                                unsigned int len)
{
	unsigned char *nbuf;
	unsigned int i;

	nbuf = ((unsigned char*)buf) + index/VS32*64*VS32 + bid*64*MD5_SSE_NUM_KEYS;
	for (i=0;i<len;i++)
		nbuf[ GETPOS((offset+i), index) ] = src[i];

}
#undef GETPOS

static MAYBE_INLINE void mmxput2(void *buf, unsigned int bid, void *src)
{
	unsigned char *nbuf;
	unsigned int i;

	nbuf = ((unsigned char*)buf) + bid*64*MD5_SSE_NUM_KEYS;
	MD5_PARA_DO(i)
		memcpy( nbuf+i*64*VS32, ((unsigned char*)src)+i*16*VS32, 16*VS32);
}

#if (ARCH_SIZE >= 8) || defined(__i386__) || defined(__ARM_NEON)
#define BITALIGN(hi, lo, s) ((((uint64_t)(hi) << 32) | (lo)) >> (s))
#else
#define BITALIGN(hi, lo, s) (((hi) << (32 - (s))) | ((lo) >> (s)))
#endif

static MAYBE_INLINE void mmxput3(void *buf, unsigned int bid,
                                 unsigned int *offset, unsigned int mult,
                                 unsigned int saltlen, void *src)
{
	unsigned int j;

	MD5_PARA_DO(j) {
		unsigned int i;
		unsigned int jm = j * VS32 * 4;
		unsigned char *nbuf = ((unsigned char *)buf) + bid * (64 * MD5_SSE_NUM_KEYS) + jm * 16;
		unsigned int *s = (unsigned int *)src + jm;
		for (i = 0; i < VS32; i++, s++) {
			unsigned int n = offset[i + jm / 4] * mult + saltlen;
			unsigned int *d = (unsigned int *)(nbuf + (n & ~3U) * VS32) + i;

			switch (n &= 3) {
			case 0:
				d[0] = s[0];
				d[1 * VS32] = s[1 * VS32];
				d[2 * VS32] = s[2 * VS32];
				d[3 * VS32] = s[3 * VS32];
				break;
#if 0
			default:
				n <<= 3;
				{
					unsigned int m = 32 - n;
					d[0] = (d[0] & (0xffffffffU >> m)) | (s[0] << n);
					d[1 * VS32] = BITALIGN(s[1 * VS32], s[0], m);
					d[2 * VS32] = BITALIGN(s[2 * VS32], s[1 * VS32], m);
					d[3 * VS32] = BITALIGN(s[3 * VS32], s[2 * VS32], m);
					d[4 * VS32] = (d[4 * VS32] & (0xffffffffU << n)) | (s[3 * VS32] >> m);
				}
#else
			case 1:
				d[0] = (d[0] & 0xffU) | (s[0] << 8);
				d[1 * VS32] = BITALIGN(s[1 * VS32], s[0], 24);
				d[2 * VS32] = BITALIGN(s[2 * VS32], s[1 * VS32], 24);
				d[3 * VS32] = BITALIGN(s[3 * VS32], s[2 * VS32], 24);
				d[4 * VS32] = (d[4 * VS32] & 0xffffff00U) | (s[3 * VS32] >> 24);
				break;
			case 2:
				d[0] = (d[0] & 0xffffU) | (s[0] << 16);
				d[1 * VS32] = BITALIGN(s[1 * VS32], s[0], 16);
				d[2 * VS32] = BITALIGN(s[2 * VS32], s[1 * VS32], 16);
				d[3 * VS32] = BITALIGN(s[3 * VS32], s[2 * VS32], 16);
				d[4 * VS32] = (d[4 * VS32] & 0xffff0000U) | (s[3 * VS32] >> 16);
				break;
			case 3:
				d[0] = (d[0] & 0xffffffU) | (s[0] << 24);
				d[1 * VS32] = BITALIGN(s[1 * VS32], s[0], 8);
				d[2 * VS32] = BITALIGN(s[2 * VS32], s[1 * VS32], 8);
				d[3 * VS32] = BITALIGN(s[3 * VS32], s[2 * VS32], 8);
				d[4 * VS32] = (d[4 * VS32] & 0xff000000U) | (s[3 * VS32] >> 8);
#endif
			}
		}
	}
}

static MAYBE_INLINE void dispatch(unsigned char buffers[8][64*MD5_SSE_NUM_KEYS],
                                  unsigned int f[4*MD5_SSE_NUM_KEYS],
                                  unsigned int length[MD5_SSE_NUM_KEYS],
                                  unsigned int saltlen)
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
		SIMDmd5body((vtype*)&buffers[bufferid], f, NULL, SSEi_MIXED_IN);
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


void md5cryptsse(unsigned char pwd[MD5_SSE_NUM_KEYS][16], unsigned char *salt,
                 char *out, unsigned int md5_type)
{
	unsigned int length[MD5_SSE_NUM_KEYS];
	unsigned int saltlen;
	unsigned int i,j;
	MD5_CTX ctx;
	MD5_CTX tctx;
	JTR_ALIGN(MEM_ALIGN_SIMD)
		unsigned char buffers[8][64*MD5_SSE_NUM_KEYS] = { { 0 } };
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned int F[4*MD5_SSE_NUM_KEYS];

	saltlen = strlen((char*)salt);
	for (i=0;i<MD5_SSE_NUM_KEYS;i++)
	{
		unsigned int length_i = strlen((char*)pwd[i]);
		unsigned int *bt;
		unsigned int tf[4];

		/* cas 0 fs */
		mmxput(buffers, i, 0, 16, pwd[i], length_i);
		mmxput(buffers, i, 0, length_i+16, (unsigned char*)"\x80", 1);
		/* cas 1 sf */
		mmxput(buffers, i, 1, 0, pwd[i], length_i);
		mmxput(buffers, i, 1, length_i+16, (unsigned char*)"\x80", 1);
		/* cas 2 ssf */
		mmxput(buffers, i, 2, 0, pwd[i], length_i);
		mmxput(buffers, i, 2, length_i, pwd[i], length_i);
		mmxput(buffers, i, 2, length_i*2+16, (unsigned char*)"\x80", 1);
		/* cas 3 fss */
		mmxput(buffers, i, 3, 16, pwd[i], length_i);
		mmxput(buffers, i, 3, 16+length_i, pwd[i], length_i);
		mmxput(buffers, i, 3, length_i*2+16, (unsigned char*)"\x80", 1);
		/* cas 4 scf */
		mmxput(buffers, i, 4, 0, pwd[i], length_i);
		mmxput(buffers, i, 4, length_i, salt, saltlen);
		mmxput(buffers, i, 4, saltlen+length_i+16, (unsigned char*)"\x80", 1);
		/* cas 5 fcs */
		mmxput(buffers, i, 5, 16, salt, saltlen);
		mmxput(buffers, i, 5, 16+saltlen, pwd[i], length_i);
		mmxput(buffers, i, 5, saltlen+length_i+16, (unsigned char*)"\x80", 1);
		/* cas 6 fcss */
		mmxput(buffers, i, 6, 16, salt, saltlen);
		mmxput(buffers, i, 6, 16+saltlen, pwd[i], length_i);
		mmxput(buffers, i, 6, 16+saltlen+length_i, pwd[i], length_i);
		mmxput(buffers, i, 6, saltlen+2*length_i+16, (unsigned char*)"\x80", 1);
		/* cas 7 scsf */
		mmxput(buffers, i, 7, 0, pwd[i], length_i);
		mmxput(buffers, i, 7, length_i, salt, saltlen);
		mmxput(buffers, i, 7, length_i+saltlen, pwd[i], length_i);
		mmxput(buffers, i, 7, saltlen+2*length_i+16, (unsigned char*)"\x80", 1);

		bt = (unsigned int*)&buffers[0];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i+16)<<3;
		bt = (unsigned int*)&buffers[1];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i+16)<<3;
		bt = (unsigned int*)&buffers[2];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i*2+16)<<3;
		bt = (unsigned int*)&buffers[3];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i*2+16)<<3;
		bt = (unsigned int*)&buffers[4];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i+saltlen+16)<<3;
		bt = (unsigned int*)&buffers[5];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i+saltlen+16)<<3;
		bt = (unsigned int*)&buffers[6];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i*2+saltlen+16)<<3;
		bt = (unsigned int*)&buffers[7];
		bt[14*VS32 + (i&(VS32-1)) + i/VS32*16*VS32] = (length_i*2+saltlen+16)<<3;

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
		MD5_Final((unsigned char*)tf, &tctx);
		MD5_Update(&ctx, tf, length_i);
		length[i] = length_i;
		for (j=length_i;j;j>>=1)
			if (j&1)
				MD5_Update(&ctx, "\0", 1);
			else
				MD5_Update(&ctx, pwd[i], 1);
		MD5_Final((unsigned char*)tf, &ctx);
#if ARCH_LITTLE_ENDIAN
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 0*VS32] = tf[0];
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 1*VS32] = tf[1];
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 2*VS32] = tf[2];
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 3*VS32] = tf[3];
#else
		// TODO:  find a better swapper if possible!
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 0*VS32] = JOHNSWAP(tf[0]);
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 1*VS32] = JOHNSWAP(tf[1]);
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 2*VS32] = JOHNSWAP(tf[2]);
		F[i/VS32*4*VS32 + (i&(VS32-1)) + 3*VS32] = JOHNSWAP(tf[3]);
#endif
	}
	dispatch(buffers, F, length, saltlen);
	memcpy(out, F, MD5_SSE_NUM_KEYS*16);
}
#endif /* SIMD_PARA_MD5 */


#if SIMD_PARA_MD4
#define MD4_PARA_DO(x)	for ((x)=0;(x)<SIMD_PARA_MD4;(x)++)

#define MD4_F(x,y,z)                            \
    tmp[i] = vcmov((y[i]),(z[i]),(x[i]));

#ifdef vternarylogic
#define MD4_G(x,y,z)                            \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0xE8);
#elif !VCMOV_EMULATED
#define MD4_G(x,y,z)                            \
    tmp[i] = vxor((y[i]), (z[i]));              \
    tmp[i] = vcmov((x[i]), (z[i]), (tmp[i]));
#elif 0 /* Wei Dai's trick, but we let the compiler cache/reuse or not */
#define MD4_G(x,y,z)                            \
    tmp[i] = vxor((y[i]), vand(vxor((x[i]), (y[i])), vxor((y[i]), z[i])));
#else
#define MD4_G(x,y,z)                            \
    tmp[i] = vor((y[i]),(z[i]));                \
    tmp2[i] = vand((y[i]),(z[i]));              \
    tmp[i] = vand((tmp[i]),(x[i]));             \
    tmp[i] = vor((tmp[i]), (tmp2[i]) );
#define MD4_TMP2_NEEDED	1
#endif

#ifdef vternarylogic
#define MD4_H(x,y,z)                            \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0x96);

#define MD4_H2(x,y,z)                           \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0x96);
#elif SIMD_PARA_MD4 < 3
#define MD4_H(x,y,z)                            \
    tmp2[i] = vxor((x[i]),(y[i]));              \
    tmp[i] = vxor(tmp2[i], (z[i]));

#define MD4_H2(x,y,z)                           \
    tmp[i] = vxor((x[i]), tmp2[i]);
#define MD4_TMP2_NEEDED	1
#else
#define MD4_H(x,y,z)                            \
    tmp[i] = vxor((x[i]),(y[i]));               \
    tmp[i] = vxor((tmp[i]),(z[i]));

#define MD4_H2(x,y,z)                           \
    tmp[i] = vxor((y[i]),(z[i]));               \
    tmp[i] = vxor((tmp[i]),(x[i]));
#endif

#define MD4_STEP(f, a, b, c, d, x, t, s)            \
    MD4_PARA_DO(i) {                                \
        a[i] = vadd_epi32( a[i], t );               \
        f((b),(c),(d))                              \
        a[i] = vadd_epi32( a[i], tmp[i] );          \
        a[i] = vadd_epi32( a[i], data[i*16+x] );    \
        a[i] = vroti_epi32( a[i], (s) );            \
    }

#define MD4_REV_STEP(f, a, b, c, d, x, t, s)        \
    MD4_PARA_DO(i) {                                \
        f((b),(c),(d))                              \
        a[i] = vadd_epi32( a[i], tmp[i] );          \
        a[i] = vadd_epi32( a[i], data[i*16+x] );    \
    }

void SIMDmd4body(vtype* _data, unsigned int *out, uint32_t *reload_state,
                unsigned SSEi_flags)
{
	union {
		vtype vec[16*SIMD_PARA_MD4];
		uint32_t u32[1];
	} uw;
	vtype *w = uw.vec;
	vtype a[SIMD_PARA_MD4];
	vtype b[SIMD_PARA_MD4];
	vtype c[SIMD_PARA_MD4];
	vtype d[SIMD_PARA_MD4];
	vtype tmp[SIMD_PARA_MD4];
#if MD4_TMP2_NEEDED
	vtype tmp2[SIMD_PARA_MD4];
#endif
	vtype cst;
	unsigned int i;
	vtype *data;

	if (SSEi_flags & SSEi_FLAT_IN) {
		// Move _data to __data, mixing it SIMD_COEF_32 wise.
#if __SSE4_1__ || __MIC__
		unsigned k;
		vtype *W = w;
		uint32_t *saved_key = (uint32_t*)_data;
		MD4_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_4x(W[i], saved_key, i); }
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 16; ++i) { GATHER_2x(W[i], saved_key, i); }
				saved_key += (VS32<<5);
			} else {
				for (i=0; i < 16; ++i) { GATHER(W[i], saved_key, i); }
				saved_key += (VS32<<4);
			}
			W += 16;
		}
#else
		unsigned j, k;
		uint32_t *p = uw.u32;
#if !ARCH_LITTLE_ENDIAN
		vtype *W = w;
#endif
		uint32_t *saved_key = (uint32_t*)_data;
		MD4_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (VS32<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (VS32<<4);
			}
#if !ARCH_LITTLE_ENDIAN
			for (i=0; i < 14; i++)
				W[i] = vswap32(W[i]);
			if (((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			    ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) /* ||
			    (SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST) */) {
				W[14] = vswap32(W[14]);
				W[15] = vswap32(W[15]);
			}
			W += 16;
#endif
		}
#endif
		// now set our data pointer to point to this 'mixed' data.
		data = w;
	} else
		data = _data;

	if (!(SSEi_flags & SSEi_RELOAD))
	{
		MD4_PARA_DO(i)
		{
			a[i] = vset1_epi32(0x67452301);
			b[i] = vset1_epi32(0xefcdab89);
			c[i] = vset1_epi32(0x98badcfe);
			d[i] = vset1_epi32(0x10325476);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			MD4_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*16*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*16*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*16*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*16*VS32+3*VS32]);
			}
		}
		else
		{
			MD4_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*4*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*4*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*4*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*4*VS32+3*VS32]);
			}
		}
	}


/* Round 1 */
	cst = vsetzero();
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
	cst = vset1_epi32(0x5A827999L);
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
	cst = vset1_epi32(0x6ED9EBA1L);
	MD4_STEP(MD4_H, a, b, c, d, 0, cst, 3)
	MD4_STEP(MD4_H2, d, a, b, c, 8, cst, 9)
	MD4_STEP(MD4_H, c, d, a, b, 4, cst, 11)
	MD4_STEP(MD4_H2, b, c, d, a, 12, cst, 15)
	MD4_STEP(MD4_H, a, b, c, d, 2, cst, 3)
	MD4_STEP(MD4_H2, d, a, b, c, 10, cst, 9)
	MD4_STEP(MD4_H, c, d, a, b, 6, cst, 11)
	MD4_STEP(MD4_H2, b, c, d, a, 14, cst, 15)
	MD4_STEP(MD4_H, a, b, c, d, 1, cst, 3)
	MD4_STEP(MD4_H2, d, a, b, c, 9, cst, 9)
	MD4_STEP(MD4_H, c, d, a, b, 5, cst, 11)

	if (SSEi_flags & SSEi_REVERSE_STEPS)
	{
		MD4_REV_STEP(MD4_H2, b, c, d, a, 13, cst, 15)
		MD4_PARA_DO(i)
		{
			vstore((vtype*)&out[i*4*VS32+1*VS32], b[i]);
		}
		return;
	}

	MD4_STEP(MD4_H2, b, c, d, a, 13, cst, 15)
	MD4_STEP(MD4_H, a, b, c, d, 3, cst, 3)
	MD4_STEP(MD4_H2, d, a, b, c, 11, cst, 9)
	MD4_STEP(MD4_H, c, d, a, b, 7, cst, 11)
	MD4_STEP(MD4_H2, b, c, d, a, 15, cst, 15)

	if (!(SSEi_flags & SSEi_RELOAD))
	{
		MD4_PARA_DO(i)
		{
			a[i] = vadd_epi32(a[i], vset1_epi32(0x67452301));
			b[i] = vadd_epi32(b[i], vset1_epi32(0xefcdab89));
			c[i] = vadd_epi32(c[i], vset1_epi32(0x98badcfe));
			d[i] = vadd_epi32(d[i], vset1_epi32(0x10325476));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			MD4_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*16*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*16*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*16*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*16*VS32+3*VS32]));
			}
		}
		else
		{
			MD4_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*4*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*4*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*4*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*4*VS32+3*VS32]));
			}
		}
	}

#if USE_EXPERIMENTAL
/*
 * This is currently not used for MD4, and was observed to result
 * in a significant performance regression (at least on XOP) just by sitting
 * here. http://www.openwall.com/lists/john-dev/2015/09/05/5
 * NOTE the regression might be gone now anyway since we went from -O3 to -O2.
 */
	if (SSEi_flags & SSEi_FLAT_OUT) {
		MD4_PARA_DO(i)
		{
			uint32_t *o = (uint32_t*)&out[i*4*VS32];
#if __AVX512F__ || __MIC__
			vtype idxs = vset_epi32(15*4,14*4,13*4,12*4,
			                        11*4,10*4, 9*4, 8*4,
			                         7*4, 6*4, 5*4, 4*4,
			                         3*4, 2*4, 1*4, 0*4);

			vscatter_epi32(o + 0, idxs, a[i], 4);
			vscatter_epi32(o + 1, idxs, b[i], 4);
			vscatter_epi32(o + 2, idxs, c[i], 4);
			vscatter_epi32(o + 3, idxs, d[i], 4);
#else
			uint32_t j, k;
			union {
				vtype v[4];
				uint32_t s[4 * VS32];
			} tmp;

			tmp.v[0] = a[i];
			tmp.v[1] = b[i];
			tmp.v[2] = c[i];
			tmp.v[3] = d[i];

			for (j = 0; j < VS32; j++)
				for (k = 0; k < 4; k++)
					o[j*4+k] = tmp.s[k*VS32+j];
#endif
		}
	}
	else
#endif

#if SIMD_PARA_MD4 > 1
	if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		if ((SSEi_flags & SSEi_OUTPUT_AS_2BUF_INP_FMT) == SSEi_OUTPUT_AS_2BUF_INP_FMT) {
			MD4_PARA_DO(i)
			{
				vstore((vtype*)&out[i*32*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*32*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*32*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*32*VS32+3*VS32], d[i]);
			}
		} else {
			MD4_PARA_DO(i)
			{
				vstore((vtype*)&out[i*16*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*16*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*16*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*16*VS32+3*VS32], d[i]);
			}
		}
	}
	else
#endif
	{
		MD4_PARA_DO(i)
		{
			vstore((vtype*)&out[i*4*VS32+0*VS32], a[i]);
			vstore((vtype*)&out[i*4*VS32+1*VS32], b[i]);
			vstore((vtype*)&out[i*4*VS32+2*VS32], c[i]);
			vstore((vtype*)&out[i*4*VS32+3*VS32], d[i]);
		}
	}
}

#endif /* SIMD_PARA_MD4 */


#if SIMD_PARA_SHA1
#define SHA1_PARA_DO(x)		for ((x)=0;(x)<SIMD_PARA_SHA1;(x)++)

#define SHA1_F(x,y,z)                           \
    tmp[i] = vcmov((y[i]),(z[i]),(x[i]));

#ifdef vternarylogic
#define SHA1_G(x,y,z)                           \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0x96);
#else
#define SHA1_G(x,y,z)                           \
    tmp[i] = vxor((y[i]),(z[i]));               \
    tmp[i] = vxor((tmp[i]),(x[i]));
#endif

#ifdef vternarylogic
#define SHA1_H(x,y,z)                           \
    tmp[i] = vternarylogic(x[i], y[i], z[i], 0xE8);
#elif !VCMOV_EMULATED
#define SHA1_H(x,y,z)                           \
    tmp[i] = vxor((z[i]), (y[i]));              \
    tmp[i] = vcmov((x[i]), (y[i]), tmp[i]);
#elif 0 /* Wei Dai's trick, but we let the compiler cache/reuse or not */
#define SHA1_H(x,y,z)                           \
    tmp[i] = vxor((y[i]), vand(vxor((x[i]), (y[i])), vxor((y[i]), z[i])));
#else
#define SHA1_H(x,y,z)                                       \
    tmp[i] = vand((x[i]),(y[i]));                           \
    tmp[i] = vor((tmp[i]),vand(vor((x[i]),(y[i])),(z[i])));
#endif

#define SHA1_I(x,y,z) SHA1_G(x,y,z)

/*
 * non-ternary: load, load, xor, load, xor, load, xor, rotate, store
 * ternary:     load, load, load, xor3, load, xor, rotate, store
 *
 * 5% boost seen w/ Xeon Silver 4110 and gcc 5.4.0
 *
 * Also tried changing order to:
 *              load, load, xor, load, load, xor3, rotate, store
 * but that was slightly slower.
 */
#ifdef vternarylogic

#define SHA1_EXPAND2a(t)                                    \
    tmp[i] = vternarylogic(data[i*16+t-3], data[i*16+t-8],  \
                           data[i*16+t-14], 0x96);          \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );               \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2b(t)                                        \
    tmp[i] = vternarylogic(w[i*16+((t-3)&0xF)], data[i*16+t-8], \
                           data[i*16+t-14], 0x96);              \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );                   \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2c(t)                                                \
    tmp[i] = vternarylogic(w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)],    \
                           data[i*16+t-14], 0x96);                      \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );                           \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2d(t)                                                \
    tmp[i] = vternarylogic(w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)],    \
                           w[i*16+((t-14)&0xF)], 0x96);                 \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );                           \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2(t)                                                 \
    tmp[i] = vternarylogic(w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)],    \
                           w[i*16+((t-14)&0xF)], 0x96);                 \
    tmp[i] = vxor( tmp[i], w[i*16+((t-16)&0xF)] );                      \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#else

#define SHA1_EXPAND2a(t)                                \
    tmp[i] = vxor( data[i*16+t-3], data[i*16+t-8] );    \
    tmp[i] = vxor( tmp[i], data[i*16+t-14] );           \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );           \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2b(t)                                    \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], data[i*16+t-8] );   \
    tmp[i] = vxor( tmp[i], data[i*16+t-14] );               \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );               \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2c(t)                                        \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)] );  \
    tmp[i] = vxor( tmp[i], data[i*16+t-14] );                   \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );                   \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2d(t)                                        \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)] );  \
    tmp[i] = vxor( tmp[i], w[i*16+((t-14)&0xF)] );              \
    tmp[i] = vxor( tmp[i], data[i*16+t-16] );                   \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);

#define SHA1_EXPAND2(t)                                         \
    tmp[i] = vxor( w[i*16+((t-3)&0xF)], w[i*16+((t-8)&0xF)] );  \
    tmp[i] = vxor( tmp[i], w[i*16+((t-14)&0xF)] );              \
    tmp[i] = vxor( tmp[i], w[i*16+((t-16)&0xF)] );              \
    w[i*16+((t)&0xF)] = vroti_epi32(tmp[i], 1);
#endif

#define SHA1_ROUND2a(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2a(t+16)                         \
    }

#define SHA1_ROUND2b(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2b(t+16)                         \
    }

#define SHA1_ROUND2c(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2c(t+16)                         \
    }

#define SHA1_ROUND2d(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], data[i*16+t] );    \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2d(t+16)                         \
    }

#define SHA1_ROUND2(a,b,c,d,e,F,t)                  \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], w[i*16+(t&0xF)] ); \
        b[i] = vroti_epi32(b[i], 30);               \
        SHA1_EXPAND2(t+16)                          \
    }

#define SHA1_ROUND2x(a,b,c,d,e,F,t)                 \
    SHA1_PARA_DO(i) {                               \
        F(b,c,d)                                    \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        tmp[i] = vroti_epi32(a[i], 5);              \
        e[i] = vadd_epi32( e[i], tmp[i] );          \
        e[i] = vadd_epi32( e[i], cst );             \
        e[i] = vadd_epi32( e[i], w[i*16+(t&0xF)] ); \
        b[i] = vroti_epi32(b[i], 30);               \
    }

void SIMDSHA1body(vtype* _data, uint32_t *out, uint32_t *reload_state,
                 unsigned SSEi_flags)
{
	union {
		vtype vec[16*SIMD_PARA_SHA1];
		uint32_t u32[1];
	} uw;
	vtype *w = uw.vec;
	vtype a[SIMD_PARA_SHA1];
	vtype b[SIMD_PARA_SHA1];
	vtype c[SIMD_PARA_SHA1];
	vtype d[SIMD_PARA_SHA1];
	vtype e[SIMD_PARA_SHA1];
	vtype tmp[SIMD_PARA_SHA1];
	vtype cst;
	unsigned int i;
	vtype *data;

	if (SSEi_flags & SSEi_FLAT_IN) {
		// Move _data to __data, mixing it SIMD_COEF_32 wise.
#if __SSE4_1__ || __MIC__
		unsigned k;
		vtype *W = w;
		uint32_t *saved_key = (uint32_t*)_data;
		SHA1_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 14; ++i) {
					GATHER_4x(W[i], saved_key, i);
					W[i] = vswap32(W[i]);
				}
				GATHER_4x(W[14], saved_key, 14);
				GATHER_4x(W[15], saved_key, 15);
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 14; ++i) {
					GATHER_2x(W[i], saved_key, i);
					W[i] = vswap32(W[i]);
				}
				GATHER_2x(W[14], saved_key, 14);
				GATHER_2x(W[15], saved_key, 15);
				saved_key += (VS32<<5);
			} else {
				for (i=0; i < 14; ++i) {
					GATHER(W[i], saved_key, i);
					W[i] = vswap32(W[i]);
				}
				GATHER(W[14], saved_key, 14);
				GATHER(W[15], saved_key, 15);
				saved_key += (VS32<<4);
			}
			if (((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			    ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) /* ||
			    (SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST) */) {
				W[14] = vswap32(W[14]);
				W[15] = vswap32(W[15]);
			}
			W += 16;
		}
#else
		unsigned j, k;
		uint32_t *p = uw.u32;
		vtype *W = w;
		uint32_t *saved_key = (uint32_t*)_data;
		SHA1_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (VS32<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (VS32<<4);
			}
#if ARCH_LITTLE_ENDIAN
			for (i=0; i < 14; i++)
				W[i] = vswap32(W[i]);
			if (((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			    ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) /* ||
			    (SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST) */) {
				W[14] = vswap32(W[14]);
				W[15] = vswap32(W[15]);
			}
#endif
			W += 16;
		}
#endif

		// now set our data pointer to point to this 'mixed' data.
		data = w;
	} else
		data = _data;

	if (!(SSEi_flags & SSEi_RELOAD))
	{
		SHA1_PARA_DO(i)
		{
			a[i] = vset1_epi32(0x67452301);
			b[i] = vset1_epi32(0xefcdab89);
			c[i] = vset1_epi32(0x98badcfe);
			d[i] = vset1_epi32(0x10325476);
			e[i] = vset1_epi32(0xC3D2E1F0);
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*16*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*16*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*16*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*16*VS32+3*VS32]);
				e[i] = vload((vtype*)&reload_state[i*16*VS32+4*VS32]);
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*5*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*5*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*5*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*5*VS32+3*VS32]);
				e[i] = vload((vtype*)&reload_state[i*5*VS32+4*VS32]);
			}
		}
	}

	cst = vset1_epi32(0x5A827999);
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

	cst = vset1_epi32(0x6ED9EBA1);
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

	cst = vset1_epi32(0x8F1BBCDC);
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

	cst = vset1_epi32(0xCA62C1D6);
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

	if (SSEi_flags & SSEi_REVERSE_STEPS)
	{
		SHA1_PARA_DO(i)
		{
			vstore((vtype*)&out[i*5*VS32+4*VS32], e[i]);
		}
		return;
	}

	SHA1_ROUND2x( e, a, b, c, d, SHA1_I, 76 );

	if (SSEi_flags & SSEi_REVERSE_3STEPS)
	{
		SHA1_PARA_DO(i)
		{
			vstore((vtype*)&out[i*5*VS32+3*VS32], d[i]);
		}
		return;
	}

	SHA1_ROUND2x( d, e, a, b, c, SHA1_I, 77 );
	SHA1_ROUND2x( c, d, e, a, b, SHA1_I, 78 );
	SHA1_ROUND2x( b, c, d, e, a, SHA1_I, 79 );

	if (!(SSEi_flags & SSEi_RELOAD))
	{
		SHA1_PARA_DO(i)
		{
			a[i] = vadd_epi32(a[i], vset1_epi32(0x67452301));
			b[i] = vadd_epi32(b[i], vset1_epi32(0xefcdab89));
			c[i] = vadd_epi32(c[i], vset1_epi32(0x98badcfe));
			d[i] = vadd_epi32(d[i], vset1_epi32(0x10325476));
			e[i] = vadd_epi32(e[i], vset1_epi32(0xC3D2E1F0));
		}
	}
	else
	{
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*16*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*16*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*16*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*16*VS32+3*VS32]));
				e[i] = vadd_epi32(e[i], vload((vtype*)&reload_state[i*16*VS32+4*VS32]));
			}
		}
		else
		{
			SHA1_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i], vload((vtype*)&reload_state[i*5*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i], vload((vtype*)&reload_state[i*5*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i], vload((vtype*)&reload_state[i*5*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i], vload((vtype*)&reload_state[i*5*VS32+3*VS32]));
				e[i] = vadd_epi32(e[i], vload((vtype*)&reload_state[i*5*VS32+4*VS32]));
			}
		}
	}

	if (SSEi_flags & SSEi_FLAT_OUT) {
		SHA1_PARA_DO(i)
		{
			uint32_t *o = (uint32_t*)&out[i*5*VS32];
#if __AVX512F__ || __MIC__
			vtype idxs = vset_epi32(15*5,14*5,13*5,12*5,
			                        11*5,10*5, 9*5, 8*5,
			                         7*5, 6*5, 5*5, 4*5,
			                         3*5, 2*5, 1*5, 0*5);

			vscatter_epi32(o + 0, idxs, vswap32(a[i]), 4);
			vscatter_epi32(o + 1, idxs, vswap32(b[i]), 4);
			vscatter_epi32(o + 2, idxs, vswap32(c[i]), 4);
			vscatter_epi32(o + 3, idxs, vswap32(d[i]), 4);
			vscatter_epi32(o + 4, idxs, vswap32(e[i]), 4);
#else
			uint32_t j, k;
			union {
				vtype v[5];
				uint32_t s[5 * VS32];
			} tmp;

#if ARCH_LITTLE_ENDIAN
			tmp.v[0] = vswap32(a[i]);
			tmp.v[1] = vswap32(b[i]);
			tmp.v[2] = vswap32(c[i]);
			tmp.v[3] = vswap32(d[i]);
			tmp.v[4] = vswap32(e[i]);
#else
			tmp.v[0] = a[i];
			tmp.v[1] = b[i];
			tmp.v[2] = c[i];
			tmp.v[3] = d[i];
			tmp.v[4] = e[i];
#endif

			for (j = 0; j < VS32; j++)
				for (k = 0; k < 5; k++)
					o[j*5+k] = tmp.s[k*VS32+j];
#endif
		}
	}
#if SIMD_PARA_SHA1 > 1
	else if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		if ((SSEi_flags & SSEi_OUTPUT_AS_2BUF_INP_FMT) == SSEi_OUTPUT_AS_2BUF_INP_FMT) {
			SHA1_PARA_DO(i)
			{
				vstore((vtype*)&out[i*32*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*32*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*32*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*32*VS32+3*VS32], d[i]);
				vstore((vtype*)&out[i*32*VS32+4*VS32], e[i]);
			}
		} else {
			SHA1_PARA_DO(i)
			{
				vstore((vtype*)&out[i*16*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*16*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*16*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*16*VS32+3*VS32], d[i]);
				vstore((vtype*)&out[i*16*VS32+4*VS32], e[i]);
			}
		}
	}
#endif
	else
	{
		SHA1_PARA_DO(i)
		{
			vstore((vtype*)&out[i*5*VS32+0*VS32], a[i]);
			vstore((vtype*)&out[i*5*VS32+1*VS32], b[i]);
			vstore((vtype*)&out[i*5*VS32+2*VS32], c[i]);
			vstore((vtype*)&out[i*5*VS32+3*VS32], d[i]);
			vstore((vtype*)&out[i*5*VS32+4*VS32], e[i]);
		}
	}
}
#endif /* SIMD_PARA_SHA1 */


#if SIMD_PARA_SHA256

#ifdef vternarylogic
/*
 * Two xor's in one shot. 10% boost for AVX-512
 */
#define S0(x) vternarylogic(vroti_epi32(x, -22),    \
                            vroti_epi32(x,  -2),    \
                            vroti_epi32(x, -13),    \
                            0x96)

#define S1(x) vternarylogic(vroti_epi32(x, -25),    \
                            vroti_epi32(x,  -6),    \
                            vroti_epi32(x, -11),    \
                            0x96)

#elif 0
/*
 * These Sigma alternatives are from "Fast SHA-256 Implementations on Intel
 * Architecture Processors" whitepaper by Intel. They were intended for use
 * with destructive rotate (minimizing register copies) but might be better
 * or worse on different hardware for other reasons.
 */
#define S0(x) vroti_epi32(vxor(vroti_epi32(vxor(vroti_epi32(x, -9), x), -11), x), -2)
#define S1(x) vroti_epi32(vxor(vroti_epi32(vxor(vroti_epi32(x, -14), x), -5), x), -6)

#else

/* Original SHA-2 function */
#define S0(x)                                   \
(                                               \
    vxor(                                       \
        vroti_epi32(x, -22),                    \
        vxor(                                   \
            vroti_epi32(x,  -2),                \
            vroti_epi32(x, -13)                 \
        )                                       \
    )                                           \
)

#define S1(x)                                   \
(                                               \
    vxor(                                       \
        vroti_epi32(x, -25),                    \
        vxor(                                   \
            vroti_epi32(x,  -6),                \
            vroti_epi32(x, -11)                 \
        )                                       \
    )                                           \
)
#endif

#ifdef vternarylogic
/*
 * Two xor's in one shot. 10% boost for AVX-512
 */
#define s0(x) vternarylogic(vsrli_epi32(x, 3),      \
                            vroti_epi32(x, -7),     \
                            vroti_epi32(x, -18),    \
                            0x96)

#define s1(x) vternarylogic(vsrli_epi32(x, 10),     \
                            vroti_epi32(x, -17),    \
                            vroti_epi32(x, -19),    \
                            0x96)

#elif VROTI_EMULATED
/*
 * These sigma alternatives are derived from "Fast SHA-512 Implementations
 * on Intel Architecture Processors" whitepaper by Intel (rewritten here
 * for SHA-256 by magnum). They were intended for use with destructive shifts
 * (minimizing register copies) but might be better or worse on different
 * hardware for other reasons. They will likely always be a regression when
 * we have hardware rotate instructions.
 */
#define s0(x)  (vxor(vsrli_epi32(vxor(vsrli_epi32(vxor(              \
                     vsrli_epi32(x, 11), x), 4), x), 3),             \
                     vslli_epi32(vxor(vslli_epi32(x, 11), x), 14)))

#define s1(x)  (vxor(vsrli_epi32(vxor(vsrli_epi32(vxor(              \
                     vsrli_epi32(x, 2), x), 7), x), 10),             \
                     vslli_epi32(vxor(vslli_epi32(x, 2), x), 13)))
#else

/* Original SHA-2 function */
#define s0(x)                                   \
(                                               \
    vxor(                                       \
        vsrli_epi32(x, 3),                      \
        vxor(                                   \
            vroti_epi32(x,  -7),                \
            vroti_epi32(x, -18)                 \
        )                                       \
    )                                           \
)

#define s1(x)                                   \
(                                               \
    vxor(                                       \
        vsrli_epi32(x, 10),                     \
        vxor(                                   \
            vroti_epi32(x, -17),                \
            vroti_epi32(x, -19)                 \
        )                                       \
    )                                           \
)
#endif

#ifdef vternarylogic
#define Maj(x,y,z) vternarylogic(x, y, z, 0xE8)
#elif !VCMOV_EMULATED
#define Maj(x,y,z) vcmov(x, y, vxor(z, y))
#elif 0 /* Wei Dai's trick, but we let the compiler cache/reuse or not */
#define Maj(x,y,z) vxor(y, vand(vxor(x, y), vxor(y, z)))
#else
#define Maj(x,y,z) vor(vand(x, y), vand(vor(x, y), z))
#endif

#define Ch(x,y,z) vcmov(y, z, x)

#undef R
#define R(t)                                                \
{                                                           \
    tmp1[i] = vadd_epi32(s1(w[(t-2)&0xf]), w[(t-7)&0xf]);   \
    tmp2[i] = vadd_epi32(s0(w[(t-15)&0xf]), w[(t-16)&0xf]); \
    w[(t)&0xf] = vadd_epi32(tmp1[i], tmp2[i]);              \
}

#define SHA256_PARA_DO(x) for (x = 0; x < SIMD_PARA_SHA256; ++x)

#define SHA256_STEP(a,b,c,d,e,f,g,h,x,K)                    \
{                                                           \
    SHA256_PARA_DO(i)                                       \
    {                                                       \
        w = _w[i].w;                                        \
        tmp1[i] = vadd_epi32(h[i],    S1(e[i]));            \
        tmp1[i] = vadd_epi32(tmp1[i], Ch(e[i],f[i],g[i]));  \
        tmp1[i] = vadd_epi32(tmp1[i], vset1_epi32(K));      \
        tmp1[i] = vadd_epi32(tmp1[i], w[(x)&0xf]);          \
        tmp2[i] = vadd_epi32(S0(a[i]),Maj(a[i],b[i],c[i])); \
        d[i]    = vadd_epi32(tmp1[i], d[i]);                \
        h[i]    = vadd_epi32(tmp1[i], tmp2[i]);             \
        if (x < 48) R(x);                                   \
    }                                                       \
}

void SIMDSHA256body(vtype *data, uint32_t *out, uint32_t *reload_state, unsigned SSEi_flags)
{
	vtype a[SIMD_PARA_SHA256],
		  b[SIMD_PARA_SHA256],
		  c[SIMD_PARA_SHA256],
		  d[SIMD_PARA_SHA256],
		  e[SIMD_PARA_SHA256],
		  f[SIMD_PARA_SHA256],
		  g[SIMD_PARA_SHA256],
		  h[SIMD_PARA_SHA256];
	union {
		vtype w[16];
		uint32_t p[16*sizeof(vtype)/sizeof(uint32_t)];
	}_w[SIMD_PARA_SHA256];
	vtype tmp1[SIMD_PARA_SHA256], tmp2[SIMD_PARA_SHA256], *w = NULL;
	uint32_t *saved_key=0;

	unsigned int i, k;
	if (SSEi_flags & SSEi_FLAT_IN) {

#if __SSE4_1__ || __MIC__
		saved_key = (uint32_t*)data;
		SHA256_PARA_DO(k)
		{
			w = _w[k].w;
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (i=0; i < 14; ++i) {
					GATHER_4x(w[i], saved_key, i);
					w[i] = vswap32(w[i]);
				}
				GATHER_4x(w[14], saved_key, 14);
				GATHER_4x(w[15], saved_key, 15);
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (i=0; i < 14; ++i) {
					GATHER_2x(w[i], saved_key, i);
					w[i] = vswap32(w[i]);
				}
				GATHER_2x(w[14], saved_key, 14);
				GATHER_2x(w[15], saved_key, 15);
				saved_key += (VS32<<5);
			} else {
				for (i=0; i < 14; ++i) {
					GATHER(w[i], saved_key, i);
					w[i] = vswap32(w[i]);
				}
				GATHER(w[14], saved_key, 14);
				GATHER(w[15], saved_key, 15);
				saved_key += (VS32<<4);
			}
			if (((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			    ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) ||
			    (SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST)) {
				w[14] = vswap32(w[14]);
				w[15] = vswap32(w[15]);
			}
		}
#else
		unsigned int j;
		saved_key = (uint32_t*)data;
		SHA256_PARA_DO(k)
		{
			uint32_t *p = _w[k].p;
			w = _w[k].w;
			if (SSEi_flags & SSEi_4BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<6)+j];
				saved_key += (VS32<<6);
			} else if (SSEi_flags & SSEi_2BUF_INPUT) {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<5)+j];
				saved_key += (VS32<<5);
			} else {
				for (j=0; j < 16; j++)
					for (i=0; i < VS32; i++)
						*p++ = saved_key[(i<<4)+j];
				saved_key += (VS32<<4);
			}
#if ARCH_LITTLE_ENDIAN
			for (i=0; i < 14; i++)
				w[i] = vswap32(w[i]);
			if (((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) ||
			    ((SSEi_flags & SSEi_4BUF_INPUT_FIRST_BLK) == SSEi_4BUF_INPUT_FIRST_BLK) ||
			    (SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST)) {
				w[14] = vswap32(w[14]);
				w[15] = vswap32(w[15]);
			}
#endif
		}
#endif
	} else
		memcpy(_w, data, 16*sizeof(vtype)*SIMD_PARA_SHA256);

//	dump_stuff_shammx(w, 64, 0);


	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			SHA256_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*16*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*16*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*16*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*16*VS32+3*VS32]);
				e[i] = vload((vtype*)&reload_state[i*16*VS32+4*VS32]);
				f[i] = vload((vtype*)&reload_state[i*16*VS32+5*VS32]);
				g[i] = vload((vtype*)&reload_state[i*16*VS32+6*VS32]);
				h[i] = vload((vtype*)&reload_state[i*16*VS32+7*VS32]);
			}
		}
		else
		{
			SHA256_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*8*VS32+0*VS32]);
				b[i] = vload((vtype*)&reload_state[i*8*VS32+1*VS32]);
				c[i] = vload((vtype*)&reload_state[i*8*VS32+2*VS32]);
				d[i] = vload((vtype*)&reload_state[i*8*VS32+3*VS32]);
				e[i] = vload((vtype*)&reload_state[i*8*VS32+4*VS32]);
				f[i] = vload((vtype*)&reload_state[i*8*VS32+5*VS32]);
				g[i] = vload((vtype*)&reload_state[i*8*VS32+6*VS32]);
				h[i] = vload((vtype*)&reload_state[i*8*VS32+7*VS32]);
			}
		}
	} else {
		if (SSEi_flags & SSEi_CRYPT_SHA224) {
			SHA256_PARA_DO(i)
			{
				/* SHA-224 IV */
				a[i] = vset1_epi32(0xc1059ed8);
				b[i] = vset1_epi32(0x367cd507);
				c[i] = vset1_epi32(0x3070dd17);
				d[i] = vset1_epi32(0xf70e5939);
				e[i] = vset1_epi32(0xffc00b31);
				f[i] = vset1_epi32(0x68581511);
				g[i] = vset1_epi32(0x64f98fa7);
				h[i] = vset1_epi32(0xbefa4fa4);
			}
		} else {
			SHA256_PARA_DO(i)
			{
				// SHA-256 IV */
				a[i] = vset1_epi32(0x6a09e667);
				b[i] = vset1_epi32(0xbb67ae85);
				c[i] = vset1_epi32(0x3c6ef372);
				d[i] = vset1_epi32(0xa54ff53a);
				e[i] = vset1_epi32(0x510e527f);
				f[i] = vset1_epi32(0x9b05688c);
				g[i] = vset1_epi32(0x1f83d9ab);
				h[i] = vset1_epi32(0x5be0cd19);
			}
		}
	}

	SHA256_STEP(a, b, c, d, e, f, g, h,  0, 0x428a2f98);
	SHA256_STEP(h, a, b, c, d, e, f, g,  1, 0x71374491);
	SHA256_STEP(g, h, a, b, c, d, e, f,  2, 0xb5c0fbcf);
	SHA256_STEP(f, g, h, a, b, c, d, e,  3, 0xe9b5dba5);
	SHA256_STEP(e, f, g, h, a, b, c, d,  4, 0x3956c25b);
	SHA256_STEP(d, e, f, g, h, a, b, c,  5, 0x59f111f1);
	SHA256_STEP(c, d, e, f, g, h, a, b,  6, 0x923f82a4);
	SHA256_STEP(b, c, d, e, f, g, h, a,  7, 0xab1c5ed5);
	SHA256_STEP(a, b, c, d, e, f, g, h,  8, 0xd807aa98);
	SHA256_STEP(h, a, b, c, d, e, f, g,  9, 0x12835b01);
	SHA256_STEP(g, h, a, b, c, d, e, f, 10, 0x243185be);
	SHA256_STEP(f, g, h, a, b, c, d, e, 11, 0x550c7dc3);
	SHA256_STEP(e, f, g, h, a, b, c, d, 12, 0x72be5d74);
	SHA256_STEP(d, e, f, g, h, a, b, c, 13, 0x80deb1fe);
	SHA256_STEP(c, d, e, f, g, h, a, b, 14, 0x9bdc06a7);
	SHA256_STEP(b, c, d, e, f, g, h, a, 15, 0xc19bf174);

	SHA256_STEP(a, b, c, d, e, f, g, h, 16, 0xe49b69c1);
	SHA256_STEP(h, a, b, c, d, e, f, g, 17, 0xefbe4786);
	SHA256_STEP(g, h, a, b, c, d, e, f, 18, 0x0fc19dc6);
	SHA256_STEP(f, g, h, a, b, c, d, e, 19, 0x240ca1cc);
	SHA256_STEP(e, f, g, h, a, b, c, d, 20, 0x2de92c6f);
	SHA256_STEP(d, e, f, g, h, a, b, c, 21, 0x4a7484aa);
	SHA256_STEP(c, d, e, f, g, h, a, b, 22, 0x5cb0a9dc);
	SHA256_STEP(b, c, d, e, f, g, h, a, 23, 0x76f988da);
	SHA256_STEP(a, b, c, d, e, f, g, h, 24, 0x983e5152);
	SHA256_STEP(h, a, b, c, d, e, f, g, 25, 0xa831c66d);
	SHA256_STEP(g, h, a, b, c, d, e, f, 26, 0xb00327c8);
	SHA256_STEP(f, g, h, a, b, c, d, e, 27, 0xbf597fc7);
	SHA256_STEP(e, f, g, h, a, b, c, d, 28, 0xc6e00bf3);
	SHA256_STEP(d, e, f, g, h, a, b, c, 29, 0xd5a79147);
	SHA256_STEP(c, d, e, f, g, h, a, b, 30, 0x06ca6351);
	SHA256_STEP(b, c, d, e, f, g, h, a, 31, 0x14292967);

	SHA256_STEP(a, b, c, d, e, f, g, h, 32, 0x27b70a85);
	SHA256_STEP(h, a, b, c, d, e, f, g, 33, 0x2e1b2138);
	SHA256_STEP(g, h, a, b, c, d, e, f, 34, 0x4d2c6dfc);
	SHA256_STEP(f, g, h, a, b, c, d, e, 35, 0x53380d13);
	SHA256_STEP(e, f, g, h, a, b, c, d, 36, 0x650a7354);
	SHA256_STEP(d, e, f, g, h, a, b, c, 37, 0x766a0abb);
	SHA256_STEP(c, d, e, f, g, h, a, b, 38, 0x81c2c92e);
	SHA256_STEP(b, c, d, e, f, g, h, a, 39, 0x92722c85);
	SHA256_STEP(a, b, c, d, e, f, g, h, 40, 0xa2bfe8a1);
	SHA256_STEP(h, a, b, c, d, e, f, g, 41, 0xa81a664b);
	SHA256_STEP(g, h, a, b, c, d, e, f, 42, 0xc24b8b70);
	SHA256_STEP(f, g, h, a, b, c, d, e, 43, 0xc76c51a3);
	SHA256_STEP(e, f, g, h, a, b, c, d, 44, 0xd192e819);
	SHA256_STEP(d, e, f, g, h, a, b, c, 45, 0xd6990624);
	SHA256_STEP(c, d, e, f, g, h, a, b, 46, 0xf40e3585);
	SHA256_STEP(b, c, d, e, f, g, h, a, 47, 0x106aa070);

	SHA256_STEP(a, b, c, d, e, f, g, h, 48, 0x19a4c116);
	SHA256_STEP(h, a, b, c, d, e, f, g, 49, 0x1e376c08);
	SHA256_STEP(g, h, a, b, c, d, e, f, 50, 0x2748774c);
	SHA256_STEP(f, g, h, a, b, c, d, e, 51, 0x34b0bcb5);
	SHA256_STEP(e, f, g, h, a, b, c, d, 52, 0x391c0cb3);
	SHA256_STEP(d, e, f, g, h, a, b, c, 53, 0x4ed8aa4a);
	SHA256_STEP(c, d, e, f, g, h, a, b, 54, 0x5b9cca4f);
	SHA256_STEP(b, c, d, e, f, g, h, a, 55, 0x682e6ff3);
	SHA256_STEP(a, b, c, d, e, f, g, h, 56, 0x748f82ee);

	if (SSEi_flags & SSEi_REVERSE_STEPS && !(SSEi_flags & SSEi_CRYPT_SHA224))
	{
		SHA256_PARA_DO(i)
		{
			vstore((vtype*)&(out[i*8*VS32+0*VS32]), h[i]);
		}
		return;
	}

	SHA256_STEP(h, a, b, c, d, e, f, g, 57, 0x78a5636f);
	SHA256_STEP(g, h, a, b, c, d, e, f, 58, 0x84c87814);
	SHA256_STEP(f, g, h, a, b, c, d, e, 59, 0x8cc70208);
	SHA256_STEP(e, f, g, h, a, b, c, d, 60, 0x90befffa);

	if (SSEi_flags & SSEi_REVERSE_STEPS)
	{
		SHA256_PARA_DO(i)
		{
			vstore((vtype*)&(out[i*8*VS32+3*VS32]), d[i]);
		}
		return;
	}

	SHA256_STEP(d, e, f, g, h, a, b, c, 61, 0xa4506ceb);
	SHA256_STEP(c, d, e, f, g, h, a, b, 62, 0xbef9a3f7);
	SHA256_STEP(b, c, d, e, f, g, h, a, 63, 0xc67178f2);

	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			SHA256_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i],vload((vtype*)&reload_state[i*16*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i],vload((vtype*)&reload_state[i*16*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i],vload((vtype*)&reload_state[i*16*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i],vload((vtype*)&reload_state[i*16*VS32+3*VS32]));
				e[i] = vadd_epi32(e[i],vload((vtype*)&reload_state[i*16*VS32+4*VS32]));
				f[i] = vadd_epi32(f[i],vload((vtype*)&reload_state[i*16*VS32+5*VS32]));
				g[i] = vadd_epi32(g[i],vload((vtype*)&reload_state[i*16*VS32+6*VS32]));
				h[i] = vadd_epi32(h[i],vload((vtype*)&reload_state[i*16*VS32+7*VS32]));
			}
		}
		else
		{
			SHA256_PARA_DO(i)
			{
				a[i] = vadd_epi32(a[i],vload((vtype*)&reload_state[i*8*VS32+0*VS32]));
				b[i] = vadd_epi32(b[i],vload((vtype*)&reload_state[i*8*VS32+1*VS32]));
				c[i] = vadd_epi32(c[i],vload((vtype*)&reload_state[i*8*VS32+2*VS32]));
				d[i] = vadd_epi32(d[i],vload((vtype*)&reload_state[i*8*VS32+3*VS32]));
				e[i] = vadd_epi32(e[i],vload((vtype*)&reload_state[i*8*VS32+4*VS32]));
				f[i] = vadd_epi32(f[i],vload((vtype*)&reload_state[i*8*VS32+5*VS32]));
				g[i] = vadd_epi32(g[i],vload((vtype*)&reload_state[i*8*VS32+6*VS32]));
				h[i] = vadd_epi32(h[i],vload((vtype*)&reload_state[i*8*VS32+7*VS32]));
			}
		}
	} else {
		if (SSEi_flags & SSEi_CRYPT_SHA224) {
			SHA256_PARA_DO(i)
			{
				/* SHA-224 IV */
				a[i] = vadd_epi32(a[i], vset1_epi32(0xc1059ed8));
				b[i] = vadd_epi32(b[i], vset1_epi32(0x367cd507));
				c[i] = vadd_epi32(c[i], vset1_epi32(0x3070dd17));
				d[i] = vadd_epi32(d[i], vset1_epi32(0xf70e5939));
				e[i] = vadd_epi32(e[i], vset1_epi32(0xffc00b31));
				f[i] = vadd_epi32(f[i], vset1_epi32(0x68581511));
				g[i] = vadd_epi32(g[i], vset1_epi32(0x64f98fa7));
				h[i] = vadd_epi32(h[i], vset1_epi32(0xbefa4fa4));
			}
		} else {
			SHA256_PARA_DO(i)
			{
				/* SHA-256 IV */
				a[i] = vadd_epi32(a[i], vset1_epi32(0x6a09e667));
				b[i] = vadd_epi32(b[i], vset1_epi32(0xbb67ae85));
				c[i] = vadd_epi32(c[i], vset1_epi32(0x3c6ef372));
				d[i] = vadd_epi32(d[i], vset1_epi32(0xa54ff53a));
				e[i] = vadd_epi32(e[i], vset1_epi32(0x510e527f));
				f[i] = vadd_epi32(f[i], vset1_epi32(0x9b05688c));
				g[i] = vadd_epi32(g[i], vset1_epi32(0x1f83d9ab));
				h[i] = vadd_epi32(h[i], vset1_epi32(0x5be0cd19));
			}
		}
	}

	if (SSEi_flags & SSEi_FLAT_OUT) {
		SHA256_PARA_DO(i)
		{
			uint32_t *o = (uint32_t*)&out[i*8*VS32];
#if __AVX512F__ || __MIC__
			vtype idxs = vset_epi32(15<<3,14<<3,13<<3,12<<3,
			                        11<<3,10<<3, 9<<3, 8<<3,
			                         7<<3, 6<<3, 5<<3, 4<<3,
			                         3<<3, 2<<3, 1<<3, 0<<3);

			vscatter_epi32(o + 0, idxs, vswap32(a[i]), 4);
			vscatter_epi32(o + 1, idxs, vswap32(b[i]), 4);
			vscatter_epi32(o + 2, idxs, vswap32(c[i]), 4);
			vscatter_epi32(o + 3, idxs, vswap32(d[i]), 4);
			vscatter_epi32(o + 4, idxs, vswap32(e[i]), 4);
			vscatter_epi32(o + 5, idxs, vswap32(f[i]), 4);
			vscatter_epi32(o + 6, idxs, vswap32(g[i]), 4);
			vscatter_epi32(o + 7, idxs, vswap32(h[i]), 4);
#else
			uint32_t j, k;
			union {
				vtype v[8];
				uint32_t s[8 * VS32];
			} tmp;

#if ARCH_LITTLE_ENDIAN
			tmp.v[0] = vswap32(a[i]);
			tmp.v[1] = vswap32(b[i]);
			tmp.v[2] = vswap32(c[i]);
			tmp.v[3] = vswap32(d[i]);
			tmp.v[4] = vswap32(e[i]);
			tmp.v[5] = vswap32(f[i]);
			tmp.v[6] = vswap32(g[i]);
			tmp.v[7] = vswap32(h[i]);
#else
			tmp.v[0] = a[i];
			tmp.v[1] = b[i];
			tmp.v[2] = c[i];
			tmp.v[3] = d[i];
			tmp.v[4] = e[i];
			tmp.v[5] = f[i];
			tmp.v[6] = g[i];
			tmp.v[7] = h[i];
#endif

			for (j = 0; j < VS32; j++)
				for (k = 0; k < 8; k++)
					o[j*8+k] = tmp.s[k*VS32+j];
#endif
		}
	}
#if SIMD_PARA_SHA256 > 1
	else if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT) {
		if ((SSEi_flags & SSEi_OUTPUT_AS_2BUF_INP_FMT) == SSEi_OUTPUT_AS_2BUF_INP_FMT) {
			SHA256_PARA_DO(i)
			{
				vstore((vtype*)&out[i*32*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*32*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*32*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*32*VS32+3*VS32], d[i]);
				vstore((vtype*)&out[i*32*VS32+4*VS32], e[i]);
				vstore((vtype*)&out[i*32*VS32+5*VS32], f[i]);
				vstore((vtype*)&out[i*32*VS32+6*VS32], g[i]);
				vstore((vtype*)&out[i*32*VS32+7*VS32], h[i]);
			}
		} else {
			SHA256_PARA_DO(i)
			{
				vstore((vtype*)&out[i*16*VS32+0*VS32], a[i]);
				vstore((vtype*)&out[i*16*VS32+1*VS32], b[i]);
				vstore((vtype*)&out[i*16*VS32+2*VS32], c[i]);
				vstore((vtype*)&out[i*16*VS32+3*VS32], d[i]);
				vstore((vtype*)&out[i*16*VS32+4*VS32], e[i]);
				vstore((vtype*)&out[i*16*VS32+5*VS32], f[i]);
				vstore((vtype*)&out[i*16*VS32+6*VS32], g[i]);
				vstore((vtype*)&out[i*16*VS32+7*VS32], h[i]);
			}
		}
	}
#endif
	else
	{
		SHA256_PARA_DO(i)
		{
			vstore((vtype*)&(out[i*8*VS32+0*VS32]), a[i]);
			vstore((vtype*)&(out[i*8*VS32+1*VS32]), b[i]);
			vstore((vtype*)&(out[i*8*VS32+2*VS32]), c[i]);
			vstore((vtype*)&(out[i*8*VS32+3*VS32]), d[i]);
			vstore((vtype*)&(out[i*8*VS32+4*VS32]), e[i]);
			vstore((vtype*)&(out[i*8*VS32+5*VS32]), f[i]);
			vstore((vtype*)&(out[i*8*VS32+6*VS32]), g[i]);
			vstore((vtype*)&(out[i*8*VS32+7*VS32]), h[i]);
		}
	}

}
#endif /* SIMD_PARA_SHA256 */

#if SIMD_PARA_SHA512

#undef S0
#undef S1
#undef s0
#undef s1

#ifdef vternarylogic
/*
 * Two xor's in one shot. 10% boost for AVX-512
 */
#define S0(x) vternarylogic(vroti_epi64(x, -39),    \
                            vroti_epi64(x, -28),    \
                            vroti_epi64(x, -34),    \
                            0x96)

#define S1(x) vternarylogic(vroti_epi64(x, -41),    \
                            vroti_epi64(x, -14),    \
                            vroti_epi64(x, -18),    \
                            0x96)

#elif 0
/*
 * These Sigma alternatives are derived from "Fast SHA-256 Implementations
 * on Intel Architecture Processors" whitepaper by Intel (rewritten here
 * for SHA-512 by magnum). They were intended for use with destructive rotate
 * (minimizing register copies) but might be better or worse on different
 * hardware for other reasons.
 */
#define S0(x) vroti_epi64(vxor(vroti_epi64(vxor(vroti_epi64(x, -5), x), -6), x), -28)
#define S1(x) vroti_epi64(vxor(vroti_epi64(vxor(vroti_epi64(x, -23), x), -4), x), -14)

#else

/* Original SHA-2 function */
#define S0(x)                                   \
(                                               \
    vxor(                                       \
        vroti_epi64(x, -39),                    \
        vxor(                                   \
            vroti_epi64(x, -28),                \
            vroti_epi64(x, -34)                 \
        )                                       \
    )                                           \
)

#define S1(x)                                   \
(                                               \
    vxor(                                       \
        vroti_epi64(x, -41),                    \
        vxor(                                   \
            vroti_epi64(x, -14),                \
            vroti_epi64(x, -18)                 \
        )                                       \
    )                                           \
)
#endif

#ifdef vternarylogic
/*
 * Two xor's in one shot. 10% boost for AVX-512
 */
#define s0(x) vternarylogic(vsrli_epi64(x, 7),  \
                            vroti_epi64(x, -1), \
                            vroti_epi64(x, -8), \
                            0x96)

#define s1(x) vternarylogic(vsrli_epi64(x, 6),      \
                            vroti_epi64(x, -19),    \
                            vroti_epi64(x, -61),    \
                            0x96)

#elif VROTI_EMULATED
/*
 * These sigma alternatives are from "Fast SHA-512 Implementations on Intel
 * Architecture Processors" whitepaper by Intel. They were intended for use
 * with destructive shifts (minimizing register copies) but might be better
 * or worse on different hardware for other reasons. They will likely always
 * be a regression when we have 64-bit hardware rotate instructions.
 */
#define s0(x)  (vxor(vsrli_epi64(vxor(vsrli_epi64(vxor(             \
                     vsrli_epi64(x, 1), x), 6), x), 1),             \
                     vslli_epi64(vxor(vslli_epi64(x, 7), x), 56)))

#define s1(x)  (vxor(vsrli_epi64(vxor(vsrli_epi64(vxor(             \
                     vsrli_epi64(x, 42), x), 13), x), 6),           \
                     vslli_epi64(vxor(vslli_epi64(x, 42), x), 3)))
#else

/* Original SHA-2 function */
#define s0(x)                                   \
(                                               \
    vxor(                                       \
        vsrli_epi64(x, 7),                      \
        vxor(                                   \
            vroti_epi64(x, -1),                 \
            vroti_epi64(x, -8)                  \
        )                                       \
    )                                           \
)

#define s1(x)                                   \
(                                               \
    vxor(                                       \
        vsrli_epi64(x, 6),                      \
        vxor(                                   \
            vroti_epi64(x, -19),                \
            vroti_epi64(x, -61)                 \
        )                                       \
    )                                           \
)
#endif

#define SHA512_PARA_DO(x) for (x = 0; x < SIMD_PARA_SHA512; ++x)

#undef R
#define R(t)                                                        \
{                                                                   \
    tmp1[i] = vadd_epi64(s1(w[i][(t-2)&0xf]), w[i][(t-7)&0xf]);     \
    tmp2[i] = vadd_epi64(s0(w[i][(t-15)&0xf]), w[i][(t-16)&0xf]);   \
    w[i][(t)&0xf] = vadd_epi64(tmp1[i], tmp2[i]);                   \
}

#define SHA512_STEP(a,b,c,d,e,f,g,h,x,K)                    \
{                                                           \
    SHA512_PARA_DO(i)                                       \
    {                                                       \
        tmp1[i] = vadd_epi64(h[i],    w[i][(x)&0xf]);       \
        tmp2[i] = vadd_epi64(S1(e[i]),vset1_epi64(K));      \
        tmp1[i] = vadd_epi64(tmp1[i], Ch(e[i],f[i],g[i]));  \
        tmp1[i] = vadd_epi64(tmp1[i], tmp2[i]);             \
        tmp2[i] = vadd_epi64(S0(a[i]),Maj(a[i],b[i],c[i])); \
        d[i]    = vadd_epi64(tmp1[i], d[i]);                \
        h[i]    = vadd_epi64(tmp1[i], tmp2[i]);             \
        if (x < 64) R(x);                                   \
    }                                                       \
}

#define SHA512_MANUAL_OPT 0

#if SHA512_MANUAL_OPT
#undef R0
#define R0(t)                                                       \
    w[i][t] = vadd_epi64(s0(w[i][(t-15)&0xf]), w[i][(t-16)&0xf]);

#undef R1
#define R1(t)                                                       \
{                                                                   \
    tmp1[i] = s1(w[i][(t-2)&0xf]);                                  \
    tmp2[i] = vadd_epi64(s0(w[i][(t-15)&0xf]), w[i][(t-16)&0xf]);   \
    w[i][t] = vadd_epi64(tmp1[i], tmp2[i]);                         \
}

#undef R2
#define R2(t)                                                       \
{                                                                   \
    tmp1[i] = vadd_epi64(s1(w[i][t-2]), w[i][t-7]);                 \
    w[i][t] = vadd_epi64(tmp1[i], w[i][(t-16)&0xf]);                \
}

#undef R3
#define R3(t)                                                       \
    w[i][t] = vadd_epi64(s1(w[i][t-2]), w[i][t-7]);

#undef R4
#define R4(t)                                                       \
{                                                                   \
    tmp1[i] = vadd_epi64(s1(w[i][t-2]), w[i][t-7]);                 \
    tmp2[i] = s0(w[i][(t-15)&0xf]);                                 \
    w[i][t] = vadd_epi64(tmp1[i], tmp2[i]);                         \
}

#define SHA512_STEP0(a,b,c,d,e,f,g,h,x,K)                   \
{                                                           \
    SHA512_PARA_DO(i)                                       \
    {                                                       \
        tmp1[i] = (x > 8 && x < 15) ? h[i] : vadd_epi64(h[i], w[i][(x)&0xf]); \
        tmp2[i] = vadd_epi64(S1(e[i]),vset1_epi64(K));      \
        tmp1[i] = vadd_epi64(tmp1[i], Ch(e[i],f[i],g[i]));  \
        tmp1[i] = vadd_epi64(tmp1[i], tmp2[i]);             \
        tmp2[i] = vadd_epi64(S0(a[i]),Maj(a[i],b[i],c[i])); \
        d[i]    = vadd_epi64(tmp1[i], d[i]);                \
        h[i]    = vadd_epi64(tmp1[i], tmp2[i]);             \
        if (x == 0) R0(x) else                              \
        if (x < 6) R1(x) else                               \
        if (x == 8) R2(x) else                              \
        if (x > 8 && x < 14) R3(x) else                     \
        if (x == 14) R4(x) else                             \
        if (x < 64) R(x);                                   \
    }                                                       \
}
#endif

#define INIT_D 0x152fecd8f70e5939ULL

void sha384_reverse(uint64_t *hash)
{
	hash[3] -= INIT_D;
}

void sha384_unreverse(uint64_t *hash)
{
	hash[3] += INIT_D;
}

#undef INIT_D

static MAYBE_INLINE void SIMDSHA512univ(vtype* data, uint64_t *out, uint64_t *reload_state, unsigned SSEi_flags)
{
	unsigned int i, k;

	vtype a[SIMD_PARA_SHA512],
	      b[SIMD_PARA_SHA512],
	      c[SIMD_PARA_SHA512],
	      d[SIMD_PARA_SHA512],
	      e[SIMD_PARA_SHA512],
	      f[SIMD_PARA_SHA512],
	      g[SIMD_PARA_SHA512],
	      h[SIMD_PARA_SHA512];
	vtype w[SIMD_PARA_SHA512][16];
	vtype tmp1[SIMD_PARA_SHA512], tmp2[SIMD_PARA_SHA512];

	if (SSEi_flags & SSEi_FLAT_IN) {
		SSEi_flags &= ~(SSEi_HALF_IN|SSEi_LOOP);

		uint64_t *_data = (uint64_t*)data;
		SHA512_PARA_DO(k)
		{
			if (SSEi_flags & SSEi_2BUF_INPUT) {
				uint64_t (*saved_key)[32] = (uint64_t(*)[32])_data;
				for (i = 0; i < 14; i += 2) {
					GATHER64(tmp1[k], saved_key, i);
					GATHER64(tmp2[k], saved_key, i + 1);
#if ARCH_LITTLE_ENDIAN
					w[k][i] = vswap64(tmp1[k]);
					w[k][i + 1] = vswap64(tmp2[k]);
#else
					w[k][i] = tmp1[k];
					w[k][i + 1] = tmp2[k];
#endif
				}
				GATHER64(tmp1[k], saved_key, 14);
				GATHER64(tmp2[k], saved_key, 15);
				_data += (VS64<<5);
			} else {
				uint64_t (*saved_key)[16] = (uint64_t(*)[16])_data;
				for (i = 0; i < 14; i += 2) {
					GATHER64(tmp1[k], saved_key, i);
					GATHER64(tmp2[k], saved_key, i + 1);
#if ARCH_LITTLE_ENDIAN
					w[k][i] = vswap64(tmp1[k]);
					w[k][i + 1] = vswap64(tmp2[k]);
#else
					w[k][i] = tmp1[k];
					w[k][i + 1] = tmp2[k];
#endif
				}
				GATHER64(tmp1[k], saved_key, 14);
				GATHER64(tmp2[k], saved_key, 15);
				_data += (VS64<<4);
			}
#if ARCH_LITTLE_ENDIAN
			if (((SSEi_flags & SSEi_2BUF_INPUT_FIRST_BLK) == SSEi_2BUF_INPUT_FIRST_BLK) /* ||
			    (SSEi_flags & SSEi_FLAT_RELOAD_SWAPLAST) */) {
				tmp1[k] = vswap64(tmp1[k]);
				tmp2[k] = vswap64(tmp2[k]);
			}
#endif
			w[k][14] = tmp1[k];
			w[k][15] = tmp2[k];
		}
	} else if (SSEi_flags & SSEi_HALF_IN) {
		SSEi_flags &= ~(SSEi_FLAT_IN|SSEi_RELOAD|SSEi_REVERSE_STEPS|SSEi_CRYPT_SHA384|SSEi_OUTPUT_AS_INP_FMT);

		vtype *_data = data;
		SHA512_PARA_DO(k)
		{
			w[k][0] = _data[0];
			w[k][1] = _data[1];
			w[k][2] = _data[2];
			w[k][3] = _data[3];
			w[k][4] = _data[4];
			w[k][5] = _data[5];
			w[k][6] = _data[6];
			w[k][7] = _data[7];
			w[k][8] = vset1_epi64(0x8000000000000000ULL);
#if !SHA512_MANUAL_OPT
			w[k][9] =
			w[k][10] =
			w[k][11] =
			w[k][12] =
			w[k][13] =
			w[k][14] = vset1_epi64(0);
#endif
			w[k][15] = vset1_epi64(64 << 3);
			_data += 8;
		}
next_half:
		SHA512_PARA_DO(k)
		{
			w[k][8] = vset1_epi64(0x8000000000000000ULL);
#if !SHA512_MANUAL_OPT
			w[k][9] =
			w[k][10] =
			w[k][11] =
			w[k][12] =
			w[k][13] =
			w[k][14] = vset1_epi64(0);
#endif
			w[k][15] = vset1_epi64(64 << 3);
		}
	} else if (SSEi_flags & SSEi_LOOP) {
		SSEi_flags &= ~(SSEi_HALF_IN|SSEi_FLAT_IN|SSEi_RELOAD|SSEi_REVERSE_STEPS|SSEi_CRYPT_SHA384);

		vtype *_data = data;
		SHA512_PARA_DO(k)
		{
			w[k][0] = _data[0];
			w[k][1] = _data[1];
			w[k][2] = _data[2];
			w[k][3] = _data[3];
			w[k][4] = _data[4];
			w[k][5] = _data[5];
			w[k][6] = _data[6];
			w[k][7] = _data[7];
			w[k][8] = _data[8];
			w[k][9] = _data[9];
			w[k][10] = _data[10];
			w[k][11] = _data[11];
			w[k][12] = _data[12];
			w[k][13] = _data[13];
			w[k][14] = _data[14];
			w[k][15] = _data[15];
			_data += 16;
		}
next_full:
		_data = data;
		SHA512_PARA_DO(k)
		{
			w[k][8] = _data[8];
			w[k][9] = _data[9];
			w[k][10] = _data[10];
			w[k][11] = _data[11];
			w[k][12] = _data[12];
			w[k][13] = _data[13];
			w[k][14] = _data[14];
			w[k][15] = _data[15];
			_data += 16;
		}
	} else
		memcpy(w, data, 16 * sizeof(vtype) * SIMD_PARA_SHA512);

	//dump_stuff_shammx64_msg("\nindex 2", w, 128, 2);

	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			SHA512_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*16*VS64+0*VS64]);
				b[i] = vload((vtype*)&reload_state[i*16*VS64+1*VS64]);
				c[i] = vload((vtype*)&reload_state[i*16*VS64+2*VS64]);
				d[i] = vload((vtype*)&reload_state[i*16*VS64+3*VS64]);
				e[i] = vload((vtype*)&reload_state[i*16*VS64+4*VS64]);
				f[i] = vload((vtype*)&reload_state[i*16*VS64+5*VS64]);
				g[i] = vload((vtype*)&reload_state[i*16*VS64+6*VS64]);
				h[i] = vload((vtype*)&reload_state[i*16*VS64+7*VS64]);
			}
		}
		else
		{
			SHA512_PARA_DO(i)
			{
				a[i] = vload((vtype*)&reload_state[i*8*VS64+0*VS64]);
				b[i] = vload((vtype*)&reload_state[i*8*VS64+1*VS64]);
				c[i] = vload((vtype*)&reload_state[i*8*VS64+2*VS64]);
				d[i] = vload((vtype*)&reload_state[i*8*VS64+3*VS64]);
				e[i] = vload((vtype*)&reload_state[i*8*VS64+4*VS64]);
				f[i] = vload((vtype*)&reload_state[i*8*VS64+5*VS64]);
				g[i] = vload((vtype*)&reload_state[i*8*VS64+6*VS64]);
				h[i] = vload((vtype*)&reload_state[i*8*VS64+7*VS64]);
			}
		}
	} else {
		if (SSEi_flags & SSEi_CRYPT_SHA384) {
			SHA512_PARA_DO(i)
			{
				/* SHA-384 IV */
				a[i] = vset1_epi64(0xcbbb9d5dc1059ed8ULL);
				b[i] = vset1_epi64(0x629a292a367cd507ULL);
				c[i] = vset1_epi64(0x9159015a3070dd17ULL);
				d[i] = vset1_epi64(0x152fecd8f70e5939ULL);
				e[i] = vset1_epi64(0x67332667ffc00b31ULL);
				f[i] = vset1_epi64(0x8eb44a8768581511ULL);
				g[i] = vset1_epi64(0xdb0c2e0d64f98fa7ULL);
				h[i] = vset1_epi64(0x47b5481dbefa4fa4ULL);
			}
		} else {
			SHA512_PARA_DO(i)
			{
				/* SHA-512 IV */
				a[i] = vset1_epi64(0x6a09e667f3bcc908ULL);
				b[i] = vset1_epi64(0xbb67ae8584caa73bULL);
				c[i] = vset1_epi64(0x3c6ef372fe94f82bULL);
				d[i] = vset1_epi64(0xa54ff53a5f1d36f1ULL);
				e[i] = vset1_epi64(0x510e527fade682d1ULL);
				f[i] = vset1_epi64(0x9b05688c2b3e6c1fULL);
				g[i] = vset1_epi64(0x1f83d9abfb41bd6bULL);
				h[i] = vset1_epi64(0x5be0cd19137e2179ULL);
			}
		}
	}

#if SHA512_MANUAL_OPT
	if (SSEi_flags & SSEi_HALF_IN) {
		SHA512_STEP0(a, b, c, d, e, f, g, h,  0, 0x428a2f98d728ae22ULL);
		SHA512_STEP0(h, a, b, c, d, e, f, g,  1, 0x7137449123ef65cdULL);
		SHA512_STEP0(g, h, a, b, c, d, e, f,  2, 0xb5c0fbcfec4d3b2fULL);
		SHA512_STEP0(f, g, h, a, b, c, d, e,  3, 0xe9b5dba58189dbbcULL);
		SHA512_STEP0(e, f, g, h, a, b, c, d,  4, 0x3956c25bf348b538ULL);
		SHA512_STEP0(d, e, f, g, h, a, b, c,  5, 0x59f111f1b605d019ULL);
		SHA512_STEP(c, d, e, f, g, h, a, b,  6, 0x923f82a4af194f9bULL);
		SHA512_STEP(b, c, d, e, f, g, h, a,  7, 0xab1c5ed5da6d8118ULL);
		SHA512_STEP0(a, b, c, d, e, f, g, h,  8, 0xd807aa98a3030242ULL);
		SHA512_STEP0(h, a, b, c, d, e, f, g,  9, 0x12835b0145706fbeULL);
		SHA512_STEP0(g, h, a, b, c, d, e, f, 10, 0x243185be4ee4b28cULL);
		SHA512_STEP0(f, g, h, a, b, c, d, e, 11, 0x550c7dc3d5ffb4e2ULL);
		SHA512_STEP0(e, f, g, h, a, b, c, d, 12, 0x72be5d74f27b896fULL);
		SHA512_STEP0(d, e, f, g, h, a, b, c, 13, 0x80deb1fe3b1696b1ULL);
		SHA512_STEP0(c, d, e, f, g, h, a, b, 14, 0x9bdc06a725c71235ULL);
	} else {
#endif
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
#if SHA512_MANUAL_OPT
	}
#endif
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

	if (SSEi_flags & SSEi_REVERSE_STEPS && !(SSEi_flags & SSEi_CRYPT_SHA384))
	{
		SHA512_PARA_DO(i)
		{
			vstore((vtype*)&(out[i*8*VS64+0*VS64]), h[i]);
		}
		return;
	}

	SHA512_STEP(h, a, b, c, d, e, f, g, 73, 0x32caab7b40c72493ULL);
	SHA512_STEP(g, h, a, b, c, d, e, f, 74, 0x3c9ebe0a15c9bebcULL);
	SHA512_STEP(f, g, h, a, b, c, d, e, 75, 0x431d67c49c100d4cULL);
	SHA512_STEP(e, f, g, h, a, b, c, d, 76, 0x4cc5d4becb3e42b6ULL);

	if (SSEi_flags & SSEi_REVERSE_STEPS)
	{
		SHA512_PARA_DO(i)
		{
			vstore((vtype*)&(out[i*8*VS64+3*VS64]), d[i]);
		}
		return;
	}

	SHA512_STEP(d, e, f, g, h, a, b, c, 77, 0x597f299cfc657e2aULL);
	SHA512_STEP(c, d, e, f, g, h, a, b, 78, 0x5fcb6fab3ad6faecULL);
	SHA512_STEP(b, c, d, e, f, g, h, a, 79, 0x6c44198c4a475817ULL);

	if (SSEi_flags & SSEi_RELOAD) {
		if ((SSEi_flags & SSEi_RELOAD_INP_FMT) == SSEi_RELOAD_INP_FMT)
		{
			SHA512_PARA_DO(i)
			{
				a[i] = vadd_epi64(a[i],vload((vtype*)&reload_state[i*16*VS64+0*VS64]));
				b[i] = vadd_epi64(b[i],vload((vtype*)&reload_state[i*16*VS64+1*VS64]));
				c[i] = vadd_epi64(c[i],vload((vtype*)&reload_state[i*16*VS64+2*VS64]));
				d[i] = vadd_epi64(d[i],vload((vtype*)&reload_state[i*16*VS64+3*VS64]));
				e[i] = vadd_epi64(e[i],vload((vtype*)&reload_state[i*16*VS64+4*VS64]));
				f[i] = vadd_epi64(f[i],vload((vtype*)&reload_state[i*16*VS64+5*VS64]));
				g[i] = vadd_epi64(g[i],vload((vtype*)&reload_state[i*16*VS64+6*VS64]));
				h[i] = vadd_epi64(h[i],vload((vtype*)&reload_state[i*16*VS64+7*VS64]));
			}
		}
		else
		{
			SHA512_PARA_DO(i)
			{
				a[i] = vadd_epi64(a[i],vload((vtype*)&reload_state[i*8*VS64+0*VS64]));
				b[i] = vadd_epi64(b[i],vload((vtype*)&reload_state[i*8*VS64+1*VS64]));
				c[i] = vadd_epi64(c[i],vload((vtype*)&reload_state[i*8*VS64+2*VS64]));
				d[i] = vadd_epi64(d[i],vload((vtype*)&reload_state[i*8*VS64+3*VS64]));
				e[i] = vadd_epi64(e[i],vload((vtype*)&reload_state[i*8*VS64+4*VS64]));
				f[i] = vadd_epi64(f[i],vload((vtype*)&reload_state[i*8*VS64+5*VS64]));
				g[i] = vadd_epi64(g[i],vload((vtype*)&reload_state[i*8*VS64+6*VS64]));
				h[i] = vadd_epi64(h[i],vload((vtype*)&reload_state[i*8*VS64+7*VS64]));
			}
		}
	} else {
		if (SSEi_flags & SSEi_CRYPT_SHA384) {
			SHA512_PARA_DO(i)
			{
				/* SHA-384 IV */
				a[i] = vadd_epi64(a[i], vset1_epi64(0xcbbb9d5dc1059ed8ULL));
				b[i] = vadd_epi64(b[i], vset1_epi64(0x629a292a367cd507ULL));
				c[i] = vadd_epi64(c[i], vset1_epi64(0x9159015a3070dd17ULL));
				d[i] = vadd_epi64(d[i], vset1_epi64(0x152fecd8f70e5939ULL));
				e[i] = vadd_epi64(e[i], vset1_epi64(0x67332667ffc00b31ULL));
				f[i] = vadd_epi64(f[i], vset1_epi64(0x8eb44a8768581511ULL));
				g[i] = vadd_epi64(g[i], vset1_epi64(0xdb0c2e0d64f98fa7ULL));
				h[i] = vadd_epi64(h[i], vset1_epi64(0x47b5481dbefa4fa4ULL));
			}
		} else {
			SHA512_PARA_DO(i)
			{
				/* SHA-512 IV */
				a[i] = vadd_epi64(a[i], vset1_epi64(0x6a09e667f3bcc908ULL));
				b[i] = vadd_epi64(b[i], vset1_epi64(0xbb67ae8584caa73bULL));
				c[i] = vadd_epi64(c[i], vset1_epi64(0x3c6ef372fe94f82bULL));
				d[i] = vadd_epi64(d[i], vset1_epi64(0xa54ff53a5f1d36f1ULL));
				e[i] = vadd_epi64(e[i], vset1_epi64(0x510e527fade682d1ULL));
				f[i] = vadd_epi64(f[i], vset1_epi64(0x9b05688c2b3e6c1fULL));
				g[i] = vadd_epi64(g[i], vset1_epi64(0x1f83d9abfb41bd6bULL));
				h[i] = vadd_epi64(h[i], vset1_epi64(0x5be0cd19137e2179ULL));
			}
		}
	}

	if (SSEi_flags & SSEi_LOOP) {
		SHA512_PARA_DO(i)
		{
			w[i][0] = a[i];
			w[i][1] = b[i];
			w[i][2] = c[i];
			w[i][3] = d[i];
			w[i][4] = e[i];
			w[i][5] = f[i];
			w[i][6] = g[i];
			w[i][7] = h[i];
		}

		if ((SSEi_flags & (SSEi_HALF_IN | SSEi_FLAT_OUT)) == (SSEi_HALF_IN | SSEi_FLAT_OUT)) {
			SHA512_PARA_DO(i)
			{
#if __AVX512F__ || __MIC__
				vtype idxs = vset_epi64(7<<3, 6<<3, 5<<3, 4<<3, 3<<3, 2<<3, 1<<3, 0<<3);

				vscatter_epi64(out + 0, idxs, a[i], 8);
				vscatter_epi64(out + 1, idxs, b[i], 8);
				vscatter_epi64(out + 2, idxs, c[i], 8);
				vscatter_epi64(out + 3, idxs, d[i], 8);
				vscatter_epi64(out + 4, idxs, e[i], 8);
				vscatter_epi64(out + 5, idxs, f[i], 8);
				vscatter_epi64(out + 6, idxs, g[i], 8);
				vscatter_epi64(out + 7, idxs, h[i], 8);
				out += 64;
#else
				uint64_t j;
				union {
					vtype v[8];
					uint64_t s[8 * VS64];
				} tmp;

/* We could make tmp a pointer to w instead, but this causes strict aliasing
 * warnings with old gcc, and it could prevent the compiler from keeping w[]
 * in registers. */
				tmp.v[0] = a[i];
				tmp.v[1] = b[i];
				tmp.v[2] = c[i];
				tmp.v[3] = d[i];
				tmp.v[4] = e[i];
				tmp.v[5] = f[i];
				tmp.v[6] = g[i];
				tmp.v[7] = h[i];
				for (j = 0; j < VS64; j++) {
					out[0] = tmp.s[0*VS64+j];
					out[1] = tmp.s[1*VS64+j];
					out[2] = tmp.s[2*VS64+j];
					out[3] = tmp.s[3*VS64+j];
					out[4] = tmp.s[4*VS64+j];
					out[5] = tmp.s[5*VS64+j];
					out[6] = tmp.s[6*VS64+j];
					out[7] = tmp.s[7*VS64+j];
					out += 8;
				}
#endif
			}
			if (out < reload_state)
				goto next_half;
			out = (uint64_t *)data;
		} else if (SSEi_flags & SSEi_HALF_IN) {
			if (--*reload_state)
				goto next_half;
		} else {
			if (--*reload_state)
				goto next_full;
			goto out_full;
		}
		goto out_half;
	} else
	if (SSEi_flags & SSEi_FLAT_OUT) {
		SHA512_PARA_DO(i)
		{
#if __AVX512F__ || __MIC__
			vtype idxs = vset_epi64(7<<3, 6<<3, 5<<3, 4<<3, 3<<3, 2<<3, 1<<3, 0<<3);

			vscatter_epi64(out + 0, idxs, vswap64(a[i]), 8);
			vscatter_epi64(out + 1, idxs, vswap64(b[i]), 8);
			vscatter_epi64(out + 2, idxs, vswap64(c[i]), 8);
			vscatter_epi64(out + 3, idxs, vswap64(d[i]), 8);
			vscatter_epi64(out + 4, idxs, vswap64(e[i]), 8);
			vscatter_epi64(out + 5, idxs, vswap64(f[i]), 8);
			vscatter_epi64(out + 6, idxs, vswap64(g[i]), 8);
			vscatter_epi64(out + 7, idxs, vswap64(h[i]), 8);
			out += 64;
#else
			uint64_t j;
			union {
				vtype v[8];
				uint64_t s[8 * VS64];
			} tmp;

#if ARCH_LITTLE_ENDIAN
			tmp.v[0] = vswap64(a[i]);
			tmp.v[1] = vswap64(b[i]);
			tmp.v[2] = vswap64(c[i]);
			tmp.v[3] = vswap64(d[i]);
			tmp.v[4] = vswap64(e[i]);
			tmp.v[5] = vswap64(f[i]);
			tmp.v[6] = vswap64(g[i]);
			tmp.v[7] = vswap64(h[i]);
#else
			tmp.v[0] = a[i];
			tmp.v[1] = b[i];
			tmp.v[2] = c[i];
			tmp.v[3] = d[i];
			tmp.v[4] = e[i];
			tmp.v[5] = f[i];
			tmp.v[6] = g[i];
			tmp.v[7] = h[i];
#endif
			for (j = 0; j < VS64; j++) {
				out[0] = tmp.s[0*VS64+j];
				out[1] = tmp.s[1*VS64+j];
				out[2] = tmp.s[2*VS64+j];
				out[3] = tmp.s[3*VS64+j];
				out[4] = tmp.s[4*VS64+j];
				out[5] = tmp.s[5*VS64+j];
				out[6] = tmp.s[6*VS64+j];
				out[7] = tmp.s[7*VS64+j];
				out += 8;
			}
#endif
		}
	}
#if SIMD_PARA_SHA512 > 1
	else if (SSEi_flags & SSEi_OUTPUT_AS_INP_FMT)
	{
		if ((SSEi_flags & SSEi_OUTPUT_AS_2BUF_INP_FMT) == SSEi_OUTPUT_AS_2BUF_INP_FMT) {
			SHA512_PARA_DO(i)
			{
				vstore((vtype*)&out[i*32*VS64+0*VS64], a[i]);
				vstore((vtype*)&out[i*32*VS64+1*VS64], b[i]);
				vstore((vtype*)&out[i*32*VS64+2*VS64], c[i]);
				vstore((vtype*)&out[i*32*VS64+3*VS64], d[i]);
				vstore((vtype*)&out[i*32*VS64+4*VS64], e[i]);
				vstore((vtype*)&out[i*32*VS64+5*VS64], f[i]);
				vstore((vtype*)&out[i*32*VS64+6*VS64], g[i]);
				vstore((vtype*)&out[i*32*VS64+7*VS64], h[i]);
			}
		} else {
out_full:
			SHA512_PARA_DO(i)
			{
				vstore((vtype*)&out[i*16*VS64+0*VS64], a[i]);
				vstore((vtype*)&out[i*16*VS64+1*VS64], b[i]);
				vstore((vtype*)&out[i*16*VS64+2*VS64], c[i]);
				vstore((vtype*)&out[i*16*VS64+3*VS64], d[i]);
				vstore((vtype*)&out[i*16*VS64+4*VS64], e[i]);
				vstore((vtype*)&out[i*16*VS64+5*VS64], f[i]);
				vstore((vtype*)&out[i*16*VS64+6*VS64], g[i]);
				vstore((vtype*)&out[i*16*VS64+7*VS64], h[i]);
			}
		}
	}
#endif
	else
	{
out_half:
#if SIMD_PARA_SHA512 == 1
out_full:
#endif
		SHA512_PARA_DO(i)
		{
			vstore((vtype*)&(out[i*8*VS64+0*VS64]), a[i]);
			vstore((vtype*)&(out[i*8*VS64+1*VS64]), b[i]);
			vstore((vtype*)&(out[i*8*VS64+2*VS64]), c[i]);
			vstore((vtype*)&(out[i*8*VS64+3*VS64]), d[i]);
			vstore((vtype*)&(out[i*8*VS64+4*VS64]), e[i]);
			vstore((vtype*)&(out[i*8*VS64+5*VS64]), f[i]);
			vstore((vtype*)&(out[i*8*VS64+6*VS64]), g[i]);
			vstore((vtype*)&(out[i*8*VS64+7*VS64]), h[i]);
		}
	}
}

void SIMDSHA512halfloop(vtype* data, uint64_t *out, uint64_t *count)
{
	SIMDSHA512univ(data, out, count, SSEi_HALF_IN|SSEi_LOOP);
}

void SIMDSHA512halfloopflat(vtype* data, uint64_t *out, uint64_t *end)
{
	SIMDSHA512univ(data, out, end, SSEi_HALF_IN|SSEi_LOOP|SSEi_FLAT_OUT);
}

void SIMDSHA512halfinout(vtype* data, uint64_t *out)
{
	SIMDSHA512univ(data, out, NULL, SSEi_HALF_IN);
}

void SIMDSHA512half(vtype* data, uint64_t *out, uint64_t *reload_state, unsigned SSEi_flags)
{
	SIMDSHA512univ(data, out, reload_state, (SSEi_flags & ~SSEi_LOOP) | SSEi_HALF_IN);
}

void SIMDSHA512flatin2buf(vtype* data, uint64_t *out, uint64_t *reload_state, unsigned SSEi_flags)
{
	SIMDSHA512univ(data, out, reload_state, SSEi_FLAT_IN|SSEi_2BUF_INPUT_FIRST_BLK | (SSEi_flags & SSEi_RELOAD));
}

void SIMDSHA512fullloop(vtype* data, uint64_t *out, uint64_t *count)
{
	SIMDSHA512univ(data, out, count, SSEi_MIXED_IN|SSEi_LOOP);
}

void SIMDSHA512full(vtype* data, uint64_t *out, uint64_t *reload_state, unsigned SSEi_flags)
{
	SIMDSHA512univ(data, out, reload_state, SSEi_flags & ~(SSEi_HALF_IN|SSEi_LOOP));
}

#endif /* SIMD_PARA_SHA512 */
