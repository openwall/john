/*
   This code was largely inspired by
   pyrit opencl kernel sha1 routines, royger's sha1 sample,
   and md5_opencl_kernel.cl inside jtr.
   Copyright 2011 by Samuele Giovanni Tonon
   samu at linuxasylum dot net
   and Copyright (c) 2012, magnum
   This program comes with ABSOLUTELY NO WARRANTY; express or
   implied .
   This is free software, and you are welcome to redistribute it
   under certain conditions; as expressed here
   http://www.gnu.org/licenses/gpl-2.0.html
*/

/*
 * Modifications (c) 2014 Harrison Neal.
 * Licensed GPLv2
 */

#include "opencl_device_info.h"

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

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
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

#define sha1_block(b, o) {	\
		A = o[0]; \
		B = o[1]; \
		C = o[2]; \
		D = o[3]; \
		E = o[4]; \
		SHA1(A, B, C, D, E, b); \
		o[0] += A; \
		o[1] += B; \
		o[2] += C; \
		o[3] += D; \
		o[4] += E; \
	}

#define dump_stuff_msg(msg, x, size) {	  \
		uint ii; \
		printf("%s : ", msg); \
		for (ii = 0; ii < (size)/4; ii++) \
			printf("%08x ", x[ii]); \
		printf("\n"); \
	}

__kernel void o5logon_kernel(__global uint* keys, __constant uint* salt, __global const uint *index, __global uint* digest)
{
	uint W[16] = { 0 }, salt_s[3], output[5];
	uint temp, A, B, C, D, E;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = base & 63;
	uint i;
	uint shift = len % 4;
	uint sr = 8 * shift;
	uint sl = 32 - sr;
	uint sra = (0xffffffff - (1 << sr)) + 1;
	uint sla = 0xffffffff - sra;

	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = SWAP32(*keys++);

	// Do the typical byte swapping...
	salt_s[0] = SWAP32(*salt++);
	salt_s[1] = SWAP32(*salt++);
	salt_s[2] = SWAP32(*salt);

	// Shift the salt bytes into place after the given key.
	W[len/4] |= (salt_s[0] & sra) >> sr;
	W[len/4+1] = ((salt_s[0] & sla) << sl) | ((salt_s[1] & sra) >> sr);
	W[len/4+2] = ((salt_s[1] & sla) << sl) | ((salt_s[2] & sra) >> sr);
	W[len/4+3] = (salt_s[2] & sla) << sl;

	// The 0x80 ending character is added to the salt before we receive it

	W[15] = (len+10) << 3;

	sha1_init(output);
	sha1_block(W, output);

	// Because the receiving program will need the entire hash immediately
	// (as opposed to receiving part of it, and only receiving the rest if
	// the first part appears to be a match), arranging the output like so
	// prevents the receiving program from having to jump around to get the
	// entire hash (one memcpy as opposed to five).
	digest[gid * 5] = SWAP32(output[0]);
	digest[gid * 5 + 1] = SWAP32(output[1]);
	digest[gid * 5 + 2] = SWAP32(output[2]);
	digest[gid * 5 + 3] = SWAP32(output[3]);
	digest[gid * 5 + 4] = SWAP32(output[4]);
}
