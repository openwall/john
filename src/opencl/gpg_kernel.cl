/*
 *  FIPS-180-1 compliant SHA-1 implementation
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  The SHA-1 standard was published by NIST in 1993.
 *
 *  http://www.itl.nist.gov/fipspubs/fip180-1.htm
 */

#include "opencl_device_info.h"

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#define  uint8_t		uchar
#define uint16_t		ushort
#define uint32_t		uint

/*
 * 32-bit integer manipulation macros (big endian)
 */

#ifndef GET_UINT_BE
#define GET_UINT_BE(n,b,i)	  \
	{ \
		(n) = ( (uint32_t) (b)[(i)    ] << 24 ) \
			| ( (uint32_t) (b)[(i) + 1] << 16 ) \
			| ( (uint32_t) (b)[(i) + 2] <<  8 ) \
			| ( (uint32_t) (b)[(i) + 3]       ); \
	}
#endif

#ifndef PUT_UINT_BE
#define PUT_UINT_BE(n,b,i)	  \
	{ \
		(b)[(i)    ] = (uchar) ( (n) >> 24 ); \
		(b)[(i) + 1] = (uchar) ( (n) >> 16 ); \
		(b)[(i) + 2] = (uchar) ( (n) >>  8 ); \
		(b)[(i) + 3] = (uchar) ( (n)       ); \
	}
#endif

inline void* _memcpy(void* dest, __global const uchar *src, int count)
{
	char* dst8 = (char*)dest;
	__global uchar* src8 = (__global uchar*)src;

	while (count--) {
		*dst8++ = *src8++;
	}
	return dest;
}

inline void* _memcpy_(void* dest, const uchar *src, int count)
{
	char* dst8 = (char*)dest;
	uchar* src8 = (uchar*)src;

	while (count--) {
		*dst8++ = *src8++;
	}
	return dest;
}

typedef struct {
        uint32_t length;
        uint8_t v[PLAINTEXT_LENGTH];
} gpg_password;

typedef struct {
	uint8_t v[16];
} gpg_hash;

typedef struct {
        uint32_t length;
	uint32_t count;
        uint8_t salt[8];
} gpg_salt;

/*
 * SHA-1 context setup
 */

typedef struct
{
	uint32_t total;        /*!< number of bytes processed  */
	uint32_t state[5];     /*!< intermediate digest state  */
	uint8_t buffer[64];    /*!< data block being processed */
}
	sha1_context;

inline void sha1_init( sha1_context *ctx )
{
	ctx->total = 0;

	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
}

inline void sha1_process( sha1_context *ctx, const uchar data[64] )
{
	uint32_t temp, W[16], A, B, C, D, E;

	GET_UINT_BE( W[ 0], data,  0 );
	GET_UINT_BE( W[ 1], data,  4 );
	GET_UINT_BE( W[ 2], data,  8 );
	GET_UINT_BE( W[ 3], data, 12 );
	GET_UINT_BE( W[ 4], data, 16 );
	GET_UINT_BE( W[ 5], data, 20 );
	GET_UINT_BE( W[ 6], data, 24 );
	GET_UINT_BE( W[ 7], data, 28 );
	GET_UINT_BE( W[ 8], data, 32 );
	GET_UINT_BE( W[ 9], data, 36 );
	GET_UINT_BE( W[10], data, 40 );
	GET_UINT_BE( W[11], data, 44 );
	GET_UINT_BE( W[12], data, 48 );
	GET_UINT_BE( W[13], data, 52 );
	GET_UINT_BE( W[14], data, 56 );
	GET_UINT_BE( W[15], data, 60 );

#if gpu(DEVICE_INFO)
#define S(x,n) (rotate(x, (uint)n))
#else
#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))
#endif

#define R(t)	  \
	( \
	 temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
	 W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
	 ( W[t & 0x0F] = S(temp,1) ) \
	                                                        )

#define P(a,b,c,d,e,x)	  \
	{ \
		e += S(a,5) + F(b,c,d) + K + x; b = S(b,30); \
	}

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];

#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect(z, y, x)
#else
#define F(x, y, z)	(z ^ (x & (y ^ z)))
#endif
#define K 0x5A827999

	P( A, B, C, D, E, W[0]  );
	P( E, A, B, C, D, W[1]  );
	P( D, E, A, B, C, W[2]  );
	P( C, D, E, A, B, W[3]  );
	P( B, C, D, E, A, W[4]  );
	P( A, B, C, D, E, W[5]  );
	P( E, A, B, C, D, W[6]  );
	P( D, E, A, B, C, W[7]  );
	P( C, D, E, A, B, W[8]  );
	P( B, C, D, E, A, W[9]  );
	P( A, B, C, D, E, W[10] );
	P( E, A, B, C, D, W[11] );
	P( D, E, A, B, C, W[12] );
	P( C, D, E, A, B, W[13] );
	P( B, C, D, E, A, W[14] );
	P( A, B, C, D, E, W[15] );
	P( E, A, B, C, D, R(16) );
	P( D, E, A, B, C, R(17) );
	P( C, D, E, A, B, R(18) );
	P( B, C, D, E, A, R(19) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P( A, B, C, D, E, R(20) );
	P( E, A, B, C, D, R(21) );
	P( D, E, A, B, C, R(22) );
	P( C, D, E, A, B, R(23) );
	P( B, C, D, E, A, R(24) );
	P( A, B, C, D, E, R(25) );
	P( E, A, B, C, D, R(26) );
	P( D, E, A, B, C, R(27) );
	P( C, D, E, A, B, R(28) );
	P( B, C, D, E, A, R(29) );
	P( A, B, C, D, E, R(30) );
	P( E, A, B, C, D, R(31) );
	P( D, E, A, B, C, R(32) );
	P( C, D, E, A, B, R(33) );
	P( B, C, D, E, A, R(34) );
	P( A, B, C, D, E, R(35) );
	P( E, A, B, C, D, R(36) );
	P( D, E, A, B, C, R(37) );
	P( C, D, E, A, B, R(38) );
	P( B, C, D, E, A, R(39) );

#undef K
#undef F

#ifdef USE_BITSELECT
#define F(x, y, z)	(bitselect(x, y, z) ^ bitselect(x, 0U, y))
#else
#define F(x, y, z)	((x & y) | (z & (x | y)))
#endif
#define K 0x8F1BBCDC

	P( A, B, C, D, E, R(40) );
	P( E, A, B, C, D, R(41) );
	P( D, E, A, B, C, R(42) );
	P( C, D, E, A, B, R(43) );
	P( B, C, D, E, A, R(44) );
	P( A, B, C, D, E, R(45) );
	P( E, A, B, C, D, R(46) );
	P( D, E, A, B, C, R(47) );
	P( C, D, E, A, B, R(48) );
	P( B, C, D, E, A, R(49) );
	P( A, B, C, D, E, R(50) );
	P( E, A, B, C, D, R(51) );
	P( D, E, A, B, C, R(52) );
	P( C, D, E, A, B, R(53) );
	P( B, C, D, E, A, R(54) );
	P( A, B, C, D, E, R(55) );
	P( E, A, B, C, D, R(56) );
	P( D, E, A, B, C, R(57) );
	P( C, D, E, A, B, R(58) );
	P( B, C, D, E, A, R(59) );

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P( A, B, C, D, E, R(60) );
	P( E, A, B, C, D, R(61) );
	P( D, E, A, B, C, R(62) );
	P( C, D, E, A, B, R(63) );
	P( B, C, D, E, A, R(64) );
	P( A, B, C, D, E, R(65) );
	P( E, A, B, C, D, R(66) );
	P( D, E, A, B, C, R(67) );
	P( C, D, E, A, B, R(68) );
	P( B, C, D, E, A, R(69) );
	P( A, B, C, D, E, R(70) );
	P( E, A, B, C, D, R(71) );
	P( D, E, A, B, C, R(72) );
	P( C, D, E, A, B, R(73) );
	P( B, C, D, E, A, R(74) );
	P( A, B, C, D, E, R(75) );
	P( E, A, B, C, D, R(76) );
	P( D, E, A, B, C, R(77) );
	P( C, D, E, A, B, R(78) );
	P( B, C, D, E, A, R(79) );

#undef K
#undef F

	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}

/*
 * SHA-1 process buffer
 */
inline void sha1_update( sha1_context *ctx, const uchar *input, int ilen )
{
	int fill;
	uint32_t left;

	if( ilen <= 0 )
		return;

	left = ctx->total & 0x3F;
	fill = 64 - left;

	ctx->total += (uint32_t) ilen;

	if( left && ilen >= fill )
	{
		_memcpy_( (void *) (ctx->buffer + left),
		          input, fill );
		sha1_process( ctx, ctx->buffer );
		input += fill;
		ilen  -= fill;
		left = 0;
	}

	while( ilen >= 64 )
	{
		sha1_process( ctx, input );
		input += 64;
		ilen  -= 64;
	}

	if( ilen > 0 )
	{
		_memcpy_( (void *) (ctx->buffer + left),
		          input, ilen );
	}
}

/*
 * SHA-1 final digest
 */
inline void sha1_final( sha1_context *ctx, uchar output[20] )
{
	uint32_t last, padn;
	uint32_t bits;
	uchar msglen[8];
	uchar sha1_padding[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	bits  = ctx->total <<  3;

	PUT_UINT_BE( 0, msglen, 0 );
	PUT_UINT_BE( bits,  msglen, 4 );

	last = ctx->total & 0x3F;
	padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

	sha1_update( ctx, sha1_padding, padn );
	sha1_update( ctx, msglen, 8 );

	PUT_UINT_BE( ctx->state[0], output,  0 );
	PUT_UINT_BE( ctx->state[1], output,  4 );
	PUT_UINT_BE( ctx->state[2], output,  8 );
	PUT_UINT_BE( ctx->state[3], output, 12 );
	PUT_UINT_BE( ctx->state[4], output, 16 );
}

#define KEYBUFFER_LENGTH (64 * (PLAINTEXT_LENGTH + 8))
#define SHA_DIGEST_LENGTH 20

inline void S2KItSaltedSHA1Generator(__global const uchar *password, int password_length, __global const uchar *salt, int count, __global uchar *key, int length)
{
	uchar keybuf[KEYBUFFER_LENGTH];
	sha1_context ctx;
	uchar *bptr;
#if PLAINTEXT_LENGTH > 20
	int i;
	int numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	const uchar pad[(PLAINTEXT_LENGTH + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH] = { 0 };
#endif
	uchar lkey[20];
	int outlen = 0;

	_memcpy(keybuf, salt, 8);
	_memcpy(keybuf + 8, password, password_length);

	// TODO: This is not very efficient with multiple hashes
#if PLAINTEXT_LENGTH > 20
	for (i = 0; i < numHashes; i++)
#endif
	{
		int tl;
		int mul;
		int bs;
		int n;

		sha1_init(&ctx);

#if PLAINTEXT_LENGTH > 20
		if (i)
			sha1_update(&ctx, pad, i);
#endif
		// Find multiplicator
		tl = password_length + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		while (n-- > 1) {
			_memcpy_(bptr, keybuf, tl);
			bptr += tl;
		}
		n = count / bs;
		while (n-- > 0) {
			sha1_update(&ctx, keybuf, bs);
		}
		sha1_update(&ctx, keybuf, count % bs);
		sha1_final(&ctx, lkey);

		for(n = 0; n < length && outlen < length; n++)
			key[outlen++] = lkey[n];
	}
}

__kernel void gpg(__global const gpg_password * inbuffer,
                  __global gpg_hash * outbuffer, __global const gpg_salt * salt)
{
	uint32_t idx = get_global_id(0);

	S2KItSaltedSHA1Generator(inbuffer[idx].v, inbuffer[idx].length,
	                         salt->salt, salt->count, outbuffer[idx].v, 16);
}
