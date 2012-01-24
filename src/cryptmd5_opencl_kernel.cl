/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#define uint32_t	unsigned int
#define uint8_t		unsigned char

#define ROTATE_LEFT(x, s) ((x << s) | (x >> (32 - s)))

#define F(x, y, z) (x&y | ~x&z)
#define G(x, y, z) (x&z | y&~z)

#define H(x, y, z) (x^y^z)
#define I(x, y, z) (y^(x|~z))

#define FF(v, w, x, y, z, s, ac) { \
 v += F(w, x, y) + z + ac; \
 v = ROTATE_LEFT(v, s) + w; \
 }
#define GG(v, w, x, y, z, s, ac) { \
 v += G(w, x, y) + z + ac; \
 v = ROTATE_LEFT(v, s) + w; \
 }
#define HH(v, w, x, y, z, s, ac) { \
 v += H(w, x, y) + z + ac; \
 v = ROTATE_LEFT(v, s) + w; \
 }
#define II(v, w, x, y, z, s, ac) { \
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

typedef struct {
	uint8_t saltlen;
	uint8_t salt[8];
	uint8_t prefix;		/** 'a' when $apr1$ or '1' when $1$ **/
} crypt_md5_salt;

typedef struct {
	uint8_t length;
	uint8_t v[15];
} crypt_md5_password;

typedef struct {
	uint32_t v[4];		/** 128 bits **/
} crypt_md5_hash;

typedef struct {
#define ctx_buffsize 64
	uint8_t buffer[ctx_buffsize];
	uint32_t buflen;
	uint32_t len;
	uint32_t A, B, C, D;
} md5_ctx;


__constant uint8_t cl_md5_salt_prefix[] = "$1$";
__constant uint8_t cl_apr1_salt_prefix[] = "$apr1$";

void ctx_update_global(__private md5_ctx * ctx, __global uint8_t * string,
    size_t len)
{
	uint8_t *dest = &ctx->buffer[ctx->buflen];
	__global uint8_t *src = string;
	ctx->buflen += len;
	int i = len;
	for (i = 0; i < len; i++)
		dest[i] = src[i];
}

void ctx_update_private(__private md5_ctx * ctx, __private uint8_t * string,
    size_t len)
{
	uint8_t *dest = &ctx->buffer[ctx->buflen];
	__private uint8_t *src = string;
	ctx->buflen += len;
	int i = len;
	for (i = 0; i < len; i++)
		dest[i] = src[i];
}

void ctx_update_prefix(__private md5_ctx * ctx, uint8_t prefix)
{
	uint8_t i, *dest = &ctx->buffer[ctx->buflen];
	if (prefix == '1') {
		ctx->buflen += 3;
		for (i = 0; i < 3; i++)
			dest[i] = cl_md5_salt_prefix[i];
	} else {
		ctx->buflen += 6;
		for (i = 0; i < 6; i++)
			dest[i] = cl_apr1_salt_prefix[i];
	}
}


void init_ctx(__private md5_ctx * ctx)
{
	int i = ctx_buffsize / sizeof(uint32_t);
	uint32_t *buf = (uint32_t *) ctx->buffer;
	while (i--)
		*buf++ = 0;
	ctx->buflen = 0;
	ctx->len = 0;
}

void md5_block(__private md5_ctx * ctx, uint32_t blocks, size_t len)
{
	uint32_t a = 0x67452301;
	uint32_t b = 0xefcdab89;
	uint32_t c = 0x98badcfe;
	uint32_t d = 0x10325476;

	ctx->len += len;
	len <<= 3;
	__private uint32_t *x = (uint32_t *) & ctx->buffer[0];

	{
		FF(a, b, c, d, x[0], S11, 0xd76aa478);	/* 1 */
		FF(d, a, b, c, x[1], S12, 0xe8c7b756);	/* 2 */
		FF(c, d, a, b, x[2], S13, 0x242070db);	/* 3 */
		FF(b, c, d, a, x[3], S14, 0xc1bdceee);	/* 4 */
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
	ctx->A = a + 0x67452301;
	ctx->B = b + 0xefcdab89;
	ctx->C = c + 0x98badcfe;
	ctx->D = d + 0x10325476;
}


void md5_digest(__private md5_ctx * ctx, __private uint32_t * result)
{
	uint32_t len = ctx->buflen, blocks = 1;
	uint32_t *x = (uint32_t *) ctx->buffer;
	uint32_t i = len % 64;
	x[i / 4] |= (((uint32_t) 0x80) << ((i & 0x3) << 3));

	md5_block(ctx, blocks, len);

	result[0] = ctx->A;
	result[1] = ctx->B;
	result[2] = ctx->C;
	result[3] = ctx->D;
}

__kernel void cryptmd5
    (__global const crypt_md5_password * inbuffer,
    __global crypt_md5_hash * outbuffer,
    __global const crypt_md5_salt * hsalt) {
	uint32_t idx = get_global_id(0);
	uint32_t i;
	__global const uint8_t *pass = inbuffer[idx].v;
	__global uint32_t *tresult = outbuffer[idx].v;

	__private uint32_t alt_result[4];
	uint8_t pass_len = inbuffer[idx].length;
	uint8_t salt_len = hsalt->saltlen;
	const __global uint8_t *salt = hsalt->salt;

	__private md5_ctx ctx, alt_ctx;
	init_ctx(&ctx);
	init_ctx(&alt_ctx);

	ctx_update_global(&ctx, (__global uint8_t *) pass, pass_len);
	ctx_update_prefix(&ctx, hsalt->prefix);
	ctx_update_global(&ctx, (__global uint8_t *) salt, salt_len);

	ctx_update_global(&alt_ctx, (__global uint8_t *) pass, pass_len);
	ctx_update_global(&alt_ctx, (__global uint8_t *) salt, salt_len);
	ctx_update_global(&alt_ctx, (__global uint8_t *) pass, pass_len);
	md5_digest(&alt_ctx, alt_result);

	for (i = pass_len; i > 16; i -= 16)
		ctx_update_private(&ctx, (uint8_t *) alt_result, 16);
	ctx_update_private(&ctx, (uint8_t *) alt_result, i);


	*alt_result = 0;

	for (i = pass_len; i > 0; i >>= 1)
		if ((i & 1) != 0)
			ctx.buffer[ctx.buflen++] = ((char *) alt_result)[0];
		else
			ctx.buffer[ctx.buflen++] = pass[0];

	md5_digest(&ctx, alt_result);



	for (i = 0; i < 1000; i++) {
		init_ctx(&ctx);

		if ((i & 1) != 0)
			ctx_update_global(&ctx, (__global uint8_t *) pass,
			    pass_len);
		else
			ctx_update_private(&ctx, (uint8_t *) alt_result, 16);

		if (i % 3 != 0)
			ctx_update_global(&ctx, (__global uint8_t *) salt,
			    salt_len);

		if (i % 7 != 0)
			ctx_update_global(&ctx, (__global uint8_t *) pass,
			    pass_len);

		if ((i & 1) != 0)
			ctx_update_private(&ctx, (uint8_t *) alt_result, 16);
		else
			ctx_update_global(&ctx, (__global uint8_t *) pass,
			    pass_len);
		md5_digest(&ctx, alt_result);

	}
	tresult[0] = ctx.A;
	tresult[1] = ctx.B;
	tresult[2] = ctx.C;
	tresult[3] = ctx.D;
}
