/*
 * This software is
 * Copyright (c) 2011, 2012 Lukas Odzioba <ukasz at openwall.net>
 * Copyright (c) 2012, 2013 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : disable
#endif

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))
#else
#define PUTCHAR(buf, index, val) ((uchar*)(buf))[index] = (val)
#endif

#define ROTATE_LEFT(x, s) rotate(x, (uint)s)

#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#define G(x, y, z)	bitselect((y), (x), (z))
#else
#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)	((y) ^ ((z) & ((x) ^ (y))))
#endif

#define H(x, y, z)	(x ^ y ^ z)
#define I(x, y, z)	(y ^ (x | ~z))

#define FF(v, w, x, y, z, s, ac) {	  \
		v += F(w, x, y) + z + ac; \
		v = ROTATE_LEFT(v, s) + w; \
	}

#define GG(v, w, x, y, z, s, ac) {	  \
		v += G(w, x, y) + z + ac; \
		v = ROTATE_LEFT(v, s) + w; \
	}

#define HH(v, w, x, y, z, s, ac) {	  \
		v += H(w, x, y) + z + ac; \
		v = ROTATE_LEFT(v, s) + w; \
	}

#define II(v, w, x, y, z, s, ac) {	  \
		v += I(w, x, y) + z + ac; \
		v = ROTATE_LEFT(v, s) + w; \
	}

#define S11 		7
#define S12 		12
#define S13 		17
#define S14 		22
#define S21 		5
#define S22 		9
#define S23 		14
#define S24 		20
#define S31 		4
#define S32 		11
#define S33 		16
#define S34 		23
#define S41 		6
#define S42 		10
#define S43 		15
#define S44 		21

#define AC1				0xd76aa477
#define AC2pCd				0xf8fa0bcc
#define AC3pCc				0xbcdb4dd9
#define AC4pCb				0xb18b7a77
#define MASK1				0x77777777


typedef struct {
	uint saltlen;
	uchar salt[8];
	uchar prefix;		/** 'a' when $apr1$ or '1' when $1$ **/
} crypt_md5_salt;

typedef struct {
	uint length;
	uchar v[15];
} crypt_md5_password;

typedef struct {
	uint v[4];		/** 128 bits **/
} crypt_md5_hash;

typedef struct {
	uint buffer[16];
} md5_ctx;

__constant uchar cl_md5_salt_prefix[] = "$1$";
__constant uchar cl_apr1_salt_prefix[] = "$apr1$";

inline void ctx_update(md5_ctx *ctx, uchar *string, uint len, uint *ctx_buflen)
{
	uint i;

	for (i = 0; i < len; i++)
		PUTCHAR(ctx->buffer, *ctx_buflen + i, string[i]);

	*ctx_buflen += len;
}

inline void ctx_update_prefix(md5_ctx *ctx, uchar prefix, uint *ctx_buflen)
{
	uint i;

	if (prefix == '1') {
		for (i = 0; i < 3; i++)
			PUTCHAR(ctx->buffer, *ctx_buflen + i, cl_md5_salt_prefix[i]);
		*ctx_buflen += 3;
	} else {
		for (i = 0; i < 6; i++)
			PUTCHAR(ctx->buffer, *ctx_buflen + i, cl_apr1_salt_prefix[i]);
		*ctx_buflen += 6;
	}
}

inline void init_ctx(md5_ctx *ctx, uint *ctx_buflen)
{
	uint i;
	uint *buf = (uint*)ctx->buffer;

	for (i = 0; i < 16; i++)
		*buf++ = 0;
	*ctx_buflen = 0;
}

inline void md5_digest(md5_ctx *ctx, uint *result, uint *ctx_buflen)
{
	uint len = *ctx_buflen;
	uint x[16];
	uint a;
	uint b = 0xefcdab89;
	uint c = 0x98badcfe;
	uint d = 0x10325476;

	PUTCHAR(ctx->buffer, len, 0x80);

	for (a = 0; a < 16; a++)
		x[a] = ctx->buffer[a];

	len <<= 3;

	{
		a = ROTATE_LEFT(AC1 + x[0], S11);
		a += b;		/* 1 */
		d = ROTATE_LEFT((c ^ (a & MASK1)) + x[1] + AC2pCd, S12);
		d += a;		/* 2 */
		c = ROTATE_LEFT(F(d, a, b) + x[2] + AC3pCc, S13);
		c += d;		/* 3 */
		b = ROTATE_LEFT(F(c, d, a) + x[3] + AC4pCb, S14);
		b += c;		/* 4 */
		FF(a, b, c, d, x[4], S11, 0xf57c0faf);	/* 5 */
		FF(d, a, b, c, x[5], S12, 0x4787c62a);	/* 6 */
		FF(c, d, a, b, x[6], S13, 0xa8304613);	/* 7 */
		FF(b, c, d, a, x[7], S14, 0xfd469501);	/* 8 */
		FF(a, b, c, d, x[8], S11, 0x698098d8);	/* 9 */
		FF(d, a, b, c, x[9], S12, 0x8b44f7af);	/* 10 */
		FF(c, d, a, b, x[10], S13, 0xffff5bb1);	/* 11 */
		FF(b, c, d, a, x[11], S14, 0x895cd7be);	/* 12 */
		FF(a, b, c, d, x[12], S11, 0x6b901122);	/* 13 */
		FF(d, a, b, c, x[13], S12, 0xfd987193);	/* 14 */
		FF(c, d, a, b, len, S13, 0xa679438e);	/* 15 */
		FF(b, c, d, a, 0, S14, 0x49b40821);	/* 16 */
	}
	{
		GG(a, b, c, d, x[1], S21, 0xf61e2562);	/* 17 */
		GG(d, a, b, c, x[6], S22, 0xc040b340);	/* 18 */
		GG(c, d, a, b, x[11], S23, 0x265e5a51);	/* 19 */
		GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);	/* 20 */
		GG(a, b, c, d, x[5], S21, 0xd62f105d);	/* 21 */
		GG(d, a, b, c, x[10], S22, 0x2441453);	/* 22 */
		GG(c, d, a, b, 0, S23, 0xd8a1e681);	/* 23 */
		GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);	/* 24 */
		GG(a, b, c, d, x[9], S21, 0x21e1cde6);	/* 25 */
		GG(d, a, b, c, len, S22, 0xc33707d6);	/* 26 */
		GG(c, d, a, b, x[3], S23, 0xf4d50d87);	/* 27 */
		GG(b, c, d, a, x[8], S24, 0x455a14ed);	/* 28 */
		GG(a, b, c, d, x[13], S21, 0xa9e3e905);	/* 29 */
		GG(d, a, b, c, x[2], S22, 0xfcefa3f8);	/* 30 */
		GG(c, d, a, b, x[7], S23, 0x676f02d9);	/* 31 */
		GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);	/* 32 */
	}
	{
		HH(a, b, c, d, x[5], S31, 0xfffa3942);	/* 33 */
		HH(d, a, b, c, x[8], S32, 0x8771f681);	/* 34 */
		HH(c, d, a, b, x[11], S33, 0x6d9d6122);	/* 35 */
		HH(b, c, d, a, len, S34, 0xfde5380c);	/* 36 */
		HH(a, b, c, d, x[1], S31, 0xa4beea44);	/* 37 */
		HH(d, a, b, c, x[4], S32, 0x4bdecfa9);	/* 38 */
		HH(c, d, a, b, x[7], S33, 0xf6bb4b60);	/* 39 */
		HH(b, c, d, a, x[10], S34, 0xbebfbc70);	/* 40 */
		HH(a, b, c, d, x[13], S31, 0x289b7ec6);	/* 41 */
		HH(d, a, b, c, x[0], S32, 0xeaa127fa);	/* 42 */
		HH(c, d, a, b, x[3], S33, 0xd4ef3085);	/* 43 */
		HH(b, c, d, a, x[6], S34, 0x4881d05);	/* 44 */
		HH(a, b, c, d, x[9], S31, 0xd9d4d039);	/* 45 */
		HH(d, a, b, c, x[12], S32, 0xe6db99e5);	/* 46 */
		HH(c, d, a, b, 0, S33, 0x1fa27cf8);	/* 47 */
		HH(b, c, d, a, x[2], S34, 0xc4ac5665);	/* 48 */
	}
	{
		II(a, b, c, d, x[0], S41, 0xf4292244);	/* 49 */
		II(d, a, b, c, x[7], S42, 0x432aff97);	/* 50 */
		II(c, d, a, b, len, S43, 0xab9423a7);	/* 51 */
		II(b, c, d, a, x[5], S44, 0xfc93a039);	/* 52 */
		II(a, b, c, d, x[12], S41, 0x655b59c3);	/* 53 */
		II(d, a, b, c, x[3], S42, 0x8f0ccc92);	/* 54 */
		II(c, d, a, b, x[10], S43, 0xffeff47d);	/* 55 */
		II(b, c, d, a, x[1], S44, 0x85845dd1);	/* 56 */
		II(a, b, c, d, x[8], S41, 0x6fa87e4f);	/* 57 */
		II(d, a, b, c, 0, S42, 0xfe2ce6e0);	/* 58 */
		II(c, d, a, b, x[6], S43, 0xa3014314);	/* 59 */
		II(b, c, d, a, x[13], S44, 0x4e0811a1);	/* 60 */
		II(a, b, c, d, x[4], S41, 0xf7537e82);	/* 61 */
		II(d, a, b, c, x[11], S42, 0xbd3af235);	/* 62 */
		II(c, d, a, b, x[2], S43, 0x2ad7d2bb);	/* 63 */
		II(b, c, d, a, x[9], S44, 0xeb86d391);	/* 64 */
	}
	result[0] = a + 0x67452301;
	result[1] = b + 0xefcdab89;
	result[2] = c + 0x98badcfe;
	result[3] = d + 0x10325476;
}

__kernel void cryptmd5(__global const crypt_md5_password *inbuffer,
                       __global crypt_md5_hash *outbuffer,
                       __global const crypt_md5_salt *hsalt)
{
	uint idx = get_global_id(0);
	uint pass_len = inbuffer[idx].length;
	uint salt_len = hsalt->saltlen;
	uint alt_result[4];
	md5_ctx ctx;
	uint ctx_buflen;
	union {
		uint w[4];
		uchar c[15];
	} pass;
	union {
		uint w[2];
		uchar c[8];
	} salt;
	uint i;

	for (i = 0; i < 4; i++)
		pass.w[i] = ((__global uint*)&inbuffer[idx].v)[i];

	for (i = 0; i < 2; i++)
		salt.w[i] = ((__global uint*)&hsalt->salt)[i];

	init_ctx(&ctx, &ctx_buflen);
	ctx_update(&ctx, pass.c, pass_len, &ctx_buflen);
	ctx_update(&ctx, salt.c, salt_len, &ctx_buflen);
	ctx_update(&ctx, pass.c, pass_len, &ctx_buflen);
	md5_digest(&ctx, alt_result, &ctx_buflen);

	init_ctx(&ctx, &ctx_buflen);
	ctx_update(&ctx, pass.c, pass_len, &ctx_buflen);
	ctx_update_prefix(&ctx, hsalt->prefix, &ctx_buflen);
	ctx_update(&ctx, salt.c, salt_len, &ctx_buflen);
#if 0
	for (i = pass_len; i > 16; i -= 16)
		ctx_update(&ctx, (uchar*)alt_result, 16, &ctx_buflen);
	ctx_update(&ctx, (uchar*)alt_result, i, &ctx_buflen);
#else
	ctx_update(&ctx, (uchar*)alt_result, pass_len, &ctx_buflen);
#endif
	*alt_result = 0;
	for (i = pass_len; i > 0; i >>= 1)
		if (i & 1)
			ctx_update(&ctx, (uchar*)alt_result, 1, &ctx_buflen);
		else
			ctx_update(&ctx, pass.c, 1, &ctx_buflen);
	md5_digest(&ctx, alt_result, &ctx_buflen);

	for (i = 0; i < 1000; i++) {
		init_ctx(&ctx, &ctx_buflen);

		if ((i & 1) != 0)
			ctx_update(&ctx, pass.c, pass_len, &ctx_buflen);
		else
			ctx_update(&ctx, (uchar*)alt_result, 16, &ctx_buflen);

		if (i % 3 != 0)
			ctx_update(&ctx, salt.c, salt_len, &ctx_buflen);

		if (i % 7 != 0)
			ctx_update(&ctx, pass.c, pass_len, &ctx_buflen);

		if ((i & 1) != 0)
			ctx_update(&ctx, (uchar*)alt_result, 16, &ctx_buflen);
		else
			ctx_update(&ctx, pass.c, pass_len, &ctx_buflen);

		md5_digest(&ctx, alt_result, &ctx_buflen);
	}

	outbuffer[idx].v[0]=alt_result[0];
	outbuffer[idx].v[1]=alt_result[1];
	outbuffer[idx].v[2]=alt_result[2];
	outbuffer[idx].v[3]=alt_result[3];
}
