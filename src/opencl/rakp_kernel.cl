/*
 * Code largely based on OpenCL SHA1 kernel by Samuele Giovanni Tonon (C) 2011,
 * magnum (C) 2012
 *
 * OpenCL RAKP kernel (C) 2013 by Harrison Neal
 * Vectorizing, packed key buffer and other optimizations (c) magnum 2013
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor
 * implied. See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include "opencl_device_info.h"

#define CONCAT(TYPE,WIDTH)	TYPE ## WIDTH
#define VECTOR(x, y)		CONCAT(x, y)

/* host code may pass -DV_WIDTH=2 or some other width */
#if defined(V_WIDTH) && V_WIDTH > 1
#define MAYBE_VECTOR_UINT	VECTOR(uint, V_WIDTH)
#else
#define MAYBE_VECTOR_UINT	uint
#define SCALAR
#endif

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#if gpu_nvidia(DEVICE_INFO) || amd_gcn(DEVICE_INFO)
inline uint SWAP32(uint x)
{
	x = rotate(x, 16U);
	return ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
}
#else
#define SWAP32(a)	(as_uint(as_uchar4(a).wzyx))
#endif

/* Macros for reading/writing chars from int32's */
#define LASTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & (0xffffff00U << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))

#if V_WIDTH > 1 || no_byte_addressable(DEVICE_INFO)
/* 32-bit stores */
#define PUTCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << ((((index) & 3) ^ 3) << 3))) + ((val) << ((((index) & 3) ^ 3) << 3))
#else
/* Byte-adressed stores */
#define PUTCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] = (val)
#endif

#define INIT_A			0x67452301
#define INIT_B			0xefcdab89
#define INIT_C			0x98badcfe
#define INIT_D			0x10325476
#define INIT_E			0xc3d2e1f0

#define SQRT_2			0x5a827999
#define SQRT_3			0x6ed9eba1

#define K1			0x5a827999
#define K2			0x6ed9eba1
#define K3			0x8f1bbcdc
#define K4			0xca62c1d6

#ifdef USE_BITSELECT
#define F1(x, y, z)	bitselect(z, y, x)
#else
#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#endif

#define F2(x, y, z)		(x ^ y ^ z)

#ifdef USE_BITSELECT
#define F3(x, y, z)	(bitselect(x, y, z) ^ bitselect(x, 0U, y))
#else
#define F3(x, y, z)	((x & y) | (z & (x | y)))
#endif

#define F4(x, y, z)		(x ^ y ^ z)

#if 1 // Significantly faster, at least on nvidia
#define S(x, n)	rotate((x), (uint)(n))
#else
#define S(x, n)	((x << n) | ((x) >> (32 - n)))
#endif

#define R(t)	  \
	( \
		temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( W[t & 0x0F] = S(temp, 1) ) \
		)

#define R2(t)	  \
	( \
		S((W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		   W[(t - 14) & 0x0F] ^ W[ t      & 0x0F]), 1) \
		)

#define P1(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F1(b, c, d) + K1 + x; b = S(b, 30); \
	}

#define P2(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F2(b, c, d) + K2 + x; b = S(b, 30); \
	}

#define P3(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F3(b, c, d) + K3 + x; b = S(b, 30); \
	}

#define P4(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F4(b, c, d) + K4 + x; b = S(b, 30); \
	}

#define PZ(a, b, c, d, e)	  \
	{ \
		e += S(a, 5) + F1(b, c, d) + K1 ; b = S(b, 30); \
	}

#define SHA1(A, B, C, D, E, W)	  \
	P1(A, B, C, D, E, W[0] ); \
	P1(E, A, B, C, D, W[1] ); \
	P1(D, E, A, B, C, W[2] ); \
	P1(C, D, E, A, B, W[3] ); \
	P1(B, C, D, E, A, W[4] ); \
	P1(A, B, C, D, E, W[5] ); \
	P1(E, A, B, C, D, W[6] ); \
	P1(D, E, A, B, C, W[7] ); \
	P1(C, D, E, A, B, W[8] ); \
	P1(B, C, D, E, A, W[9] ); \
	P1(A, B, C, D, E, W[10]); \
	P1(E, A, B, C, D, W[11]); \
	P1(D, E, A, B, C, W[12]); \
	P1(C, D, E, A, B, W[13]); \
	P1(B, C, D, E, A, W[14]); \
	P1(A, B, C, D, E, W[15]); \
	P1(E, A, B, C, D, R(16)); \
	P1(D, E, A, B, C, R(17)); \
	P1(C, D, E, A, B, R(18)); \
	P1(B, C, D, E, A, R(19)); \
	P2(A, B, C, D, E, R(20)); \
	P2(E, A, B, C, D, R(21)); \
	P2(D, E, A, B, C, R(22)); \
	P2(C, D, E, A, B, R(23)); \
	P2(B, C, D, E, A, R(24)); \
	P2(A, B, C, D, E, R(25)); \
	P2(E, A, B, C, D, R(26)); \
	P2(D, E, A, B, C, R(27)); \
	P2(C, D, E, A, B, R(28)); \
	P2(B, C, D, E, A, R(29)); \
	P2(A, B, C, D, E, R(30)); \
	P2(E, A, B, C, D, R(31)); \
	P2(D, E, A, B, C, R(32)); \
	P2(C, D, E, A, B, R(33)); \
	P2(B, C, D, E, A, R(34)); \
	P2(A, B, C, D, E, R(35)); \
	P2(E, A, B, C, D, R(36)); \
	P2(D, E, A, B, C, R(37)); \
	P2(C, D, E, A, B, R(38)); \
	P2(B, C, D, E, A, R(39)); \
	P3(A, B, C, D, E, R(40)); \
	P3(E, A, B, C, D, R(41)); \
	P3(D, E, A, B, C, R(42)); \
	P3(C, D, E, A, B, R(43)); \
	P3(B, C, D, E, A, R(44)); \
	P3(A, B, C, D, E, R(45)); \
	P3(E, A, B, C, D, R(46)); \
	P3(D, E, A, B, C, R(47)); \
	P3(C, D, E, A, B, R(48)); \
	P3(B, C, D, E, A, R(49)); \
	P3(A, B, C, D, E, R(50)); \
	P3(E, A, B, C, D, R(51)); \
	P3(D, E, A, B, C, R(52)); \
	P3(C, D, E, A, B, R(53)); \
	P3(B, C, D, E, A, R(54)); \
	P3(A, B, C, D, E, R(55)); \
	P3(E, A, B, C, D, R(56)); \
	P3(D, E, A, B, C, R(57)); \
	P3(C, D, E, A, B, R(58)); \
	P3(B, C, D, E, A, R(59)); \
	P4(A, B, C, D, E, R(60)); \
	P4(E, A, B, C, D, R(61)); \
	P4(D, E, A, B, C, R(62)); \
	P4(C, D, E, A, B, R(63)); \
	P4(B, C, D, E, A, R(64)); \
	P4(A, B, C, D, E, R(65)); \
	P4(E, A, B, C, D, R(66)); \
	P4(D, E, A, B, C, R(67)); \
	P4(C, D, E, A, B, R(68)); \
	P4(B, C, D, E, A, R(69)); \
	P4(A, B, C, D, E, R(70)); \
	P4(E, A, B, C, D, R(71)); \
	P4(D, E, A, B, C, R(72)); \
	P4(C, D, E, A, B, R(73)); \
	P4(B, C, D, E, A, R(74)); \
	P4(A, B, C, D, E, R(75)); \
	P4(E, A, B, C, D, R(76)); \
	P4(D, E, A, B, C, R(77)); \
	P4(C, D, E, A, B, R(78)); \
	P4(B, C, D, E, A, R(79));

#define sha1_init(o) {	  \
		o[0] = INIT_A; \
		o[1] = INIT_B; \
		o[2] = INIT_C; \
		o[3] = INIT_D; \
		o[4] = INIT_E; \
	}

/* The extra a-e variables are a workaround for an AMD bug in Cat 14.6b */
#define sha1_block(block, o) {	\
		MAYBE_VECTOR_UINT a, b, c, d, e; \
		a = A = o[0]; \
		b = B = o[1]; \
		c = C = o[2]; \
		d = D = o[3]; \
		e = E = o[4]; \
		SHA1(A, B, C, D, E, block); \
		o[0] = a + A; \
		o[1] = b + B; \
		o[2] = c + C; \
		o[3] = d + D; \
		o[4] = e + E; \
	}

#define dump_stuff_msg(msg, x, size) {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (size)/4; ii++) \
			printf("%08x ", x[ii]); \
		printf("\n"); \
	}

#define VEC_IN(NUM)	  \
	base = index[gid * V_WIDTH + 0x##NUM]; \
	len = ((base & 63) + 3) / 4; \
	keys = key_array + (base >> 6); \
	for (i = 0; i < len; i++) \
		K[i].s##NUM = SWAP32(keys[i])

#define VEC_OUT(NUM)	  \
	digest[i * gws * V_WIDTH + gid * V_WIDTH + 0x##NUM] = stage2[i].s##NUM

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void rakp_kernel(
	__constant      uint* salt,
	__global const  uint* key_array,
	__global const  uint* index,
	__global        uint* digest
) {
	MAYBE_VECTOR_UINT W[16], K[16] = { 0 }, stage1[5], stage2[5];
	MAYBE_VECTOR_UINT temp, A, B, C, D, E;
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint i;
	uint base = index[gid * V_WIDTH];
	uint len = ((base & 63) + 3) / 4;
	__global const uint *keys = key_array + (base >> 6);

#ifdef SCALAR
	for (i = 0; i < len; i++)
		K[i] = SWAP32(keys[i]);
#else
	for (i = 0; i < len; i++)
		K[i].s0 = SWAP32(keys[i]);

	VEC_IN(1);
#if V_WIDTH > 2
	VEC_IN(2);
#if V_WIDTH > 3
	VEC_IN(3);
#if V_WIDTH > 4
	VEC_IN(4);
	VEC_IN(5);
	VEC_IN(6);
	VEC_IN(7);
#if V_WIDTH > 8
	VEC_IN(8);
	VEC_IN(9);
	VEC_IN(a);
	VEC_IN(b);
	VEC_IN(c);
	VEC_IN(d);
	VEC_IN(e);
	VEC_IN(f);
#endif
#endif
#endif
#endif
#endif
	sha1_init(stage1);

	for (i = 0; i < 16; i++)
		W[i] = K[i] ^ 0x36363636U;
	sha1_block(W, stage1);

	for (i = 0; i < 16; i++)
		W[i] = *salt++;
	sha1_block(W, stage1);

	for (i = 0; i < 16; i++)
		W[i] = *salt++;
	sha1_block(W, stage1);

	sha1_init(stage2);

	for (i = 0; i < 16; i++)
		W[i] = K[i] ^ 0x5C5C5C5CU;
	sha1_block(W, stage2);

	for (i = 0; i < 5; i++)
		W[i] = stage1[i];
	W[5] = 0x80000000;
	for (i = 6; i < 15; i++)
		W[i] = 0;
	W[15] = 672; // (64 + 20) * 8
	sha1_block(W, stage2);

	for (i = 0; i < 5; i++)
#ifdef SCALAR
		digest[i * gws + gid] = stage2[i];
#else
	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}
