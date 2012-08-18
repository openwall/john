/*
 * This software is Copyright (c) 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * New (optional) SHA1 version by JimF 2011, using 16x4 buffer.
 * Use of XOP intrinsics added by Solar Designer, 2012.
 */

#include "arch.h"
#include <string.h>
#include <emmintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#endif
#include "memory.h"
#include "md5.h"
#include "MD5_std.h"

#ifndef __XOP__
#define _mm_slli_epi32a(a, s) \
	((s) == 1 ? _mm_add_epi32((a), (a)) : _mm_slli_epi32((a), (s)))
#ifdef __SSSE3__
#include <tmmintrin.h>
#define rot16_mask _mm_set_epi32(0x0d0c0f0e, 0x09080b0a, 0x05040706, 0x01000302)
#define _mm_roti_epi32(a, s) \
	((s) == 16 ? _mm_shuffle_epi8((a), rot16_mask) : \
	_mm_or_si128(_mm_slli_epi32a((a), (s)), _mm_srli_epi32((a), 32-(s))))
#else
#define _mm_roti_epi32(a, s) \
	((s) == 16 ? \
	_mm_shufflelo_epi16(_mm_shufflehi_epi16((a), 0xb1), 0xb1) : \
	_mm_or_si128(_mm_slli_epi32a((a), (s)), _mm_srli_epi32((a), 32-(s))))
#endif
#endif

#ifndef MMX_COEF
#define MMX_COEF 4
#endif

#ifdef MD5_SSE_PARA
#define MD5_SSE_NUM_KEYS	(MMX_COEF*MD5_SSE_PARA)
#define MD5_PARA_DO(x)	for((x)=0;(x)<MD5_SSE_PARA;(x)++)

#ifdef __XOP__
#define MD5_F(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_cmov_si128((y[i]),(z[i]),(x[i]));
#else
#define MD5_F(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_xor_si128((y[i]),(z[i])); \
	MD5_PARA_DO(i) tmp[i] = _mm_and_si128((tmp[i]),(x[i])); \
	MD5_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(z[i]));
#endif

#ifdef __XOP__
#define MD5_G(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_cmov_si128((x[i]),(y[i]),(z[i]));
#else
#define MD5_G(x,y,z) \
	MD5_PARA_DO(i) tmp[i] = _mm_xor_si128((y[i]),(x[i])); \
	MD5_PARA_DO(i) tmp[i] = _mm_and_si128((tmp[i]),(z[i])); \
	MD5_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]), (y[i]) );
#endif

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

unsigned int debug = 0;

void sse_debug(void)
{
	debug = 1;
}

void SSEmd5body(__m128i* data, unsigned int * out, int init)
{
	__m128i a[MD5_SSE_PARA];
	__m128i b[MD5_SSE_PARA];
	__m128i c[MD5_SSE_PARA];
	__m128i d[MD5_SSE_PARA];
	__m128i tmp[MD5_SSE_PARA];
	__m128i mask;
	unsigned int i;

	mask = _mm_set1_epi32(0Xffffffff);

	if(init)
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
		MD5_PARA_DO(i)
		{
			a[i] = _mm_load_si128((__m128i *)&out[i*16+0]);
			b[i] = _mm_load_si128((__m128i *)&out[i*16+4]);
			c[i] = _mm_load_si128((__m128i *)&out[i*16+8]);
			d[i] = _mm_load_si128((__m128i *)&out[i*16+12]);
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
		MD5_STEP(MD5_H, c, d, a, b, 11, 0x6d9d6122, 16)
		MD5_STEP(MD5_H, b, c, d, a, 14, 0xfde5380c, 23)
		MD5_STEP(MD5_H, a, b, c, d, 1, 0xa4beea44, 4)
		MD5_STEP(MD5_H, d, a, b, c, 4, 0x4bdecfa9, 11)
		MD5_STEP(MD5_H, c, d, a, b, 7, 0xf6bb4b60, 16)
		MD5_STEP(MD5_H, b, c, d, a, 10, 0xbebfbc70, 23)
		MD5_STEP(MD5_H, a, b, c, d, 13, 0x289b7ec6, 4)
		MD5_STEP(MD5_H, d, a, b, c, 0, 0xeaa127fa, 11)
		MD5_STEP(MD5_H, c, d, a, b, 3, 0xd4ef3085, 16)
		MD5_STEP(MD5_H, b, c, d, a, 6, 0x04881d05, 23)
		MD5_STEP(MD5_H, a, b, c, d, 9, 0xd9d4d039, 4)
		MD5_STEP(MD5_H, d, a, b, c, 12, 0xe6db99e5, 11)
		MD5_STEP(MD5_H, c, d, a, b, 15, 0x1fa27cf8, 16)
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

	if (init) {
		MD5_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_set1_epi32(0x67452301));
			b[i] = _mm_add_epi32(b[i], _mm_set1_epi32(0xefcdab89));
			c[i] = _mm_add_epi32(c[i], _mm_set1_epi32(0x98badcfe));
			d[i] = _mm_add_epi32(d[i], _mm_set1_epi32(0x10325476));
			_mm_store_si128((__m128i *)&out[i*16+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16+12], d[i]);
		}
	} else {
		MD5_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&out[i*16+0]));
			b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&out[i*16+4]));
			c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&out[i*16+8]));
			d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&out[i*16+12]));
			_mm_store_si128((__m128i *)&out[i*16+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16+12], d[i]);
		}
	}
}

#define GETPOS(i, index)                ( (index&3)*4 + (i& (0xffffffff-3) )*MMX_COEF + ((i)&3) )

void mmxput(void * buf, unsigned int index, unsigned int bid, unsigned int offset, unsigned char * src, unsigned int len)
{
	unsigned char * nbuf;
	unsigned int i;

	nbuf = ((unsigned char*)buf) + (index>>2)*64*MMX_COEF + bid*64*MD5_SSE_NUM_KEYS;
	for(i=0;i<len;i++)
		nbuf[ GETPOS((offset+i), index) ] = src[i];

}

void mmxput2(void * buf, unsigned int bid, void * src)
{
	unsigned char * nbuf;
	unsigned int i;

	nbuf = ((unsigned char*)buf) + bid*64*MD5_SSE_NUM_KEYS;
	MD5_PARA_DO(i)
		memcpy( nbuf+i*64*MMX_COEF, ((unsigned char*)src)+i*64, 64);
}

void mmxput3(void * buf, unsigned int bid, unsigned int * offset, int mult, int saltlen, void * src)
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

void dispatch(unsigned char buffers[8][64*MD5_SSE_NUM_KEYS], unsigned int f[4*MD5_SSE_NUM_KEYS], unsigned int length[MD5_SSE_NUM_KEYS], unsigned int saltlen)
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
		SSEmd5body((__m128i*)&buffers[bufferid], f, 1);
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
#ifdef _MSC_VER
	__declspec(align(16)) unsigned char buffers[8][64*MD5_SSE_NUM_KEYS];
	__declspec(align(16)) unsigned int F[4*MD5_SSE_NUM_KEYS];
#else
	unsigned char buffers[8][64*MD5_SSE_NUM_KEYS] __attribute__ ((aligned(16)));
	unsigned int F[4*MD5_SSE_NUM_KEYS] __attribute__ ((aligned(16)));
#endif

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
		if(md5_type == MD5_TYPE_APACHE)
			MD5_Update(&ctx, "$apr1$", 6);
		else
			MD5_Update(&ctx, "$1$", 3);
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

#ifdef __XOP__
#define MD4_F(x,y,z) \
	MD4_PARA_DO(i) tmp[i] = _mm_cmov_si128((y[i]),(z[i]),(x[i]));
#else
#define MD4_F(x,y,z) \
	MD4_PARA_DO(i) tmp[i] = _mm_xor_si128((y[i]),(z[i])); \
	MD4_PARA_DO(i) tmp[i] = _mm_and_si128((tmp[i]),(x[i])); \
	MD4_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(z[i]));
#endif

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

void SSEmd4body(__m128i* data, unsigned int * out, int init)
{
	__m128i a[MD4_SSE_PARA];
	__m128i b[MD4_SSE_PARA];
	__m128i c[MD4_SSE_PARA];
	__m128i d[MD4_SSE_PARA];
	__m128i tmp[MD4_SSE_PARA];
	__m128i tmp2[MD4_SSE_PARA];
	__m128i	cst;
	unsigned int i;

	if(init)
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
		MD4_PARA_DO(i)
		{
			a[i] = _mm_load_si128((__m128i *)&out[i*16+0]);
			b[i] = _mm_load_si128((__m128i *)&out[i*16+4]);
			c[i] = _mm_load_si128((__m128i *)&out[i*16+8]);
			d[i] = _mm_load_si128((__m128i *)&out[i*16+12]);
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

	if (init) {
		MD4_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_set1_epi32(0x67452301));
			b[i] = _mm_add_epi32(b[i], _mm_set1_epi32(0xefcdab89));
			c[i] = _mm_add_epi32(c[i], _mm_set1_epi32(0x98badcfe));
			d[i] = _mm_add_epi32(d[i], _mm_set1_epi32(0x10325476));
			_mm_store_si128((__m128i *)&out[i*16+0], a[i]);
			_mm_store_si128((__m128i *)&out[i*16+4], b[i]);
			_mm_store_si128((__m128i *)&out[i*16+8], c[i]);
			_mm_store_si128((__m128i *)&out[i*16+12], d[i]);
		}
	} else {
		MD4_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&out[i*16+0]));
			b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&out[i*16+4]));
			c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&out[i*16+8]));
			d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&out[i*16+12]));
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

#ifdef __XOP__
#define SHA1_F(x,y,z) \
	SHA1_PARA_DO(i) tmp[i] = _mm_cmov_si128((y[i]),(z[i]),(x[i]));
#else
#define SHA1_F(x,y,z) \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128((y[i]),(z[i])); \
	SHA1_PARA_DO(i) tmp[i] = _mm_and_si128((tmp[i]),(x[i])); \
	SHA1_PARA_DO(i) tmp[i] = _mm_xor_si128((tmp[i]),(z[i]));
#endif

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

void SSESHA1body(__m128i* data, unsigned int * out, unsigned int * reload_state, int input_layout_output)
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

	if(!reload_state)
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
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_load_si128((__m128i *)&reload_state[i*20+0]);
			b[i] = _mm_load_si128((__m128i *)&reload_state[i*20+4]);
			c[i] = _mm_load_si128((__m128i *)&reload_state[i*20+8]);
			d[i] = _mm_load_si128((__m128i *)&reload_state[i*20+12]);
			e[i] = _mm_load_si128((__m128i *)&reload_state[i*20+16]);
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

	if(!reload_state)
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
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*20+0]));
			b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*20+4]));
			c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*20+8]));
			d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*20+12]));
			e[i] = _mm_add_epi32(e[i], _mm_load_si128((__m128i *)&reload_state[i*20+16]));
		}
	}
	if (input_layout_output)
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

void SSESHA1body(__m128i* data, unsigned int * out, unsigned int * reload_state, int input_layout_output)
{
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
	unsigned int i; // ,j;

	if(!reload_state)
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
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_load_si128((__m128i *)&reload_state[i*20+0]);
			b[i] = _mm_load_si128((__m128i *)&reload_state[i*20+4]);
			c[i] = _mm_load_si128((__m128i *)&reload_state[i*20+8]);
			d[i] = _mm_load_si128((__m128i *)&reload_state[i*20+12]);
			e[i] = _mm_load_si128((__m128i *)&reload_state[i*20+16]);
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

	if(!reload_state)
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
		SHA1_PARA_DO(i)
		{
			a[i] = _mm_add_epi32(a[i], _mm_load_si128((__m128i *)&reload_state[i*20+0]));
			b[i] = _mm_add_epi32(b[i], _mm_load_si128((__m128i *)&reload_state[i*20+4]));
			c[i] = _mm_add_epi32(c[i], _mm_load_si128((__m128i *)&reload_state[i*20+8]));
			d[i] = _mm_add_epi32(d[i], _mm_load_si128((__m128i *)&reload_state[i*20+12]));
			e[i] = _mm_add_epi32(e[i], _mm_load_si128((__m128i *)&reload_state[i*20+16]));
		}
	}
	if (input_layout_output)
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
