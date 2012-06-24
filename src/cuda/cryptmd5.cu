/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../cuda_cryptmd5.h"
#include "cuda_common.cuh"

extern "C" void md5_crypt_gpu(crypt_md5_password *, uint32_t *,
    crypt_md5_salt *);

__device__ __constant__ char md5_salt_prefix_cu[] = "$1$";
__device__ __constant__ char apr1_salt_prefix_cu[] = "$apr1$";
__device__ __constant__ crypt_md5_salt cuda_salt[1];

__device__ void md5_process_block_cu(const void *, size_t, md5_ctx *);
__device__ void md5_process_bytes_cu(const void *, size_t, md5_ctx *);

__device__ void ctx_init(md5_ctx * ctx, uint8_t * ctx_buflen)
{
	uint32_t *buf = (uint32_t *) ctx->buffer;
	int i = 14;
	while (i--)
		*buf++ = 0;
	*ctx_buflen = 0;
}

__device__ void ctx_update(md5_ctx * ctx, const char *string, uint8_t len,
    uint8_t * ctx_buflen)
{
	uint8_t *dest = &ctx->buffer[*ctx_buflen];
	uint8_t *src = (uint8_t *) string;
	*ctx_buflen += len;
	memcpy(dest, src, len);
}

__device__ void md5_digest(md5_ctx * ctx, uint32_t * result,
    uint8_t * ctx_buflen)
{
	uint32_t len = *ctx_buflen;
	uint32_t *x = (uint32_t *) ctx->buffer;
	x[len / 4] |= (((uint32_t) 0x80) << ((len & 0x3) << 3));
	len <<= 3;

	uint32_t b = 0xefcdab89;
	uint32_t c = 0x98badcfe;
	uint32_t d = 0x10325476;
	uint32_t a = ROTATE_LEFT(AC1 + x[0], S11);
	a += b;			/* 1 */
	d = ROTATE_LEFT((c ^ (a & MASK1)) + x[1] + AC2pCd, S12);
	d += a;			/* 2 */
	c = ROTATE_LEFT(F(d, a, b) + x[2] + AC3pCc, S13);
	c += d;			/* 3 */
	b = ROTATE_LEFT(F(c, d, a) + x[3] + AC4pCb, S14);
	b += c;			/* 4 */
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
	FF2(b, c, d, a, S14, 0x49b40821);	/* 16 */


	GG(a, b, c, d, x[1], S21, 0xf61e2562);	/* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340);	/* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51);	/* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);	/* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d);	/* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453);	/* 22 */
	GG2(c, d, a, b, S23, 0xd8a1e681);	/* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);	/* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6);	/* 25 */
	GG(d, a, b, c, len, S22, 0xc33707d6);	/* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87);	/* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed);	/* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905);	/* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8);	/* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9);	/* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);	/* 32 */


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
	HH2(c, d, a, b, S33, 0x1fa27cf8);	/* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665);	/* 48 */


	II(a, b, c, d, x[0], S41, 0xf4292244);	/* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97);	/* 50 */
	II(c, d, a, b, len, S43, 0xab9423a7);	/* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039);	/* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3);	/* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92);	/* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d);	/* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1);	/* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f);	/* 57 */
	II2(d, a, b, c, S42, 0xfe2ce6e0);	/* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314);	/* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1);	/* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82);	/* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235);	/* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb);	/* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391);	/* 64 */

	result[0] = a + 0x67452301;
	result[1] = b + 0xefcdab89;
	result[2] = c + 0x98badcfe;
	result[3] = d + 0x10325476;
}


__device__ void md5crypt(const char *gpass, size_t keysize, char *result)
{

	uint32_t i;
	__shared__ uint32_t alt_result[THREADS][4 + 1];
	__shared__ char spass[THREADS][16 + 4];

	uint8_t ctx_buflen;
	char *pass = spass[threadIdx.x];
	memcpy(pass, gpass, 15);
	uint8_t pass_len = keysize;
	uint8_t salt_len = cuda_salt[0].length;
	char *salt = cuda_salt[0].salt;
	md5_ctx ctx;
	ctx_init(&ctx, &ctx_buflen);

	ctx_update(&ctx, pass, pass_len, &ctx_buflen);
	ctx_update(&ctx, salt, salt_len, &ctx_buflen);
	ctx_update(&ctx, pass, pass_len, &ctx_buflen);
	md5_digest(&ctx, alt_result[threadIdx.x], &ctx_buflen);

	ctx_init(&ctx, &ctx_buflen);


	ctx_update(&ctx, pass, pass_len, &ctx_buflen);
	if (cuda_salt[0].prefix == '1') {
		ctx_update(&ctx, md5_salt_prefix_cu, 3, &ctx_buflen);
	} else
		ctx_update(&ctx, apr1_salt_prefix_cu, 6, &ctx_buflen);

	ctx_update(&ctx, salt, salt_len, &ctx_buflen);


	ctx_update(&ctx, (const char *) alt_result[threadIdx.x], pass_len,
	    &ctx_buflen);

	*alt_result[threadIdx.x] = 0;

	for (i = pass_len; i > 0; i >>= 1)
		if ((i & 1) != 0)
			ctx.buffer[ctx_buflen++] =
			    ((const char *) alt_result[threadIdx.x])[0];
		else
			ctx.buffer[ctx_buflen++] = pass[0];

	md5_digest(&ctx, alt_result[threadIdx.x], &ctx_buflen);

	for (i = 0; i < 1000; i++) {
		ctx_init(&ctx, &ctx_buflen);

		if ((i & 1) != 0)
			ctx_update(&ctx, pass, pass_len, &ctx_buflen);
		else
			ctx_update(&ctx,
			    (const char *) alt_result[threadIdx.x], 16,
			    &ctx_buflen);

		if (i % 3 != 0)
			ctx_update(&ctx, salt, salt_len, &ctx_buflen);

		if (i % 7 != 0)
			ctx_update(&ctx, pass, pass_len, &ctx_buflen);

		if ((i & 1) != 0)
			ctx_update(&ctx,
			    (const char *) alt_result[threadIdx.x], 16,
			    &ctx_buflen);
		else
			ctx_update(&ctx, pass, pass_len, &ctx_buflen);
		md5_digest(&ctx, alt_result[threadIdx.x], &ctx_buflen);
	}
	char cracked = 1;
	cracked &= (alt_result[threadIdx.x][0] == cuda_salt[0].hash[0]);
	cracked &= (alt_result[threadIdx.x][1] == cuda_salt[0].hash[1]);
	cracked &= (alt_result[threadIdx.x][2] == cuda_salt[0].hash[2]);
	cracked &= (alt_result[threadIdx.x][3] == cuda_salt[0].hash[3]);
	*result = cracked;
}


__global__ void kernel_crypt_r(crypt_md5_password * inbuffer,
    crypt_md5_crack * outbuffer)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	md5crypt((char *) inbuffer[idx].v, inbuffer[idx].length,
	    &outbuffer[idx].cracked);
}

__host__ void md5_crypt_gpu(crypt_md5_password * inbuffer,
    uint32_t * outbuffer, crypt_md5_salt * host_salt)
{
	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt,
		sizeof(crypt_md5_salt)));
	crypt_md5_password *cuda_inbuffer;
	crypt_md5_crack *cuda_outbuffer;

	size_t insize = sizeof(crypt_md5_password) * KEYS_PER_CRYPT;
	size_t outsize = sizeof(crypt_md5_crack) * KEYS_PER_CRYPT;

	HANDLE_ERROR(cudaMalloc(&cuda_inbuffer, insize));
	HANDLE_ERROR(cudaMalloc(&cuda_outbuffer, outsize));


	HANDLE_ERROR(cudaMemcpy(cuda_inbuffer, inbuffer, insize,
		cudaMemcpyHostToDevice));

	kernel_crypt_r <<< BLOCKS, THREADS >>> (cuda_inbuffer, cuda_outbuffer);

	HANDLE_ERROR(cudaMemcpy(outbuffer, cuda_outbuffer, outsize,
		cudaMemcpyDeviceToHost));

	HANDLE_ERROR(cudaFree(cuda_inbuffer));
	HANDLE_ERROR(cudaFree(cuda_outbuffer));
}
