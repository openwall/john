/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../cuda_phpass.h"
#include "cuda_common.cuh"

const uint DATA_IN_SIZE = KEYS_PER_CRYPT * sizeof(phpass_password);
const uint DATA_OUT_SIZE = KEYS_PER_CRYPT * sizeof(phpass_crack);

__device__ __constant__ phpass_salt cuda_salt[1];

__global__ void kernel_phpass(unsigned char *, phpass_crack *);

extern "C" void gpu_phpass(uint8_t * host_data, phpass_salt * salt,
    phpass_crack * host_data_out)
{
	uint8_t *cuda_data;
	phpass_crack *cuda_data_out;
	HANDLE_ERROR(cudaMalloc(&cuda_data, DATA_IN_SIZE));
	HANDLE_ERROR(cudaMalloc(&cuda_data_out, DATA_OUT_SIZE));

	HANDLE_ERROR(cudaMemcpy(cuda_data, host_data, DATA_IN_SIZE,
		cudaMemcpyHostToDevice));
	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, salt, SALT_SIZE));

	kernel_phpass <<< BLOCKS, THREADS >>> (cuda_data, cuda_data_out);

	HANDLE_ERROR(cudaThreadSynchronize());
	HANDLE_ERROR(cudaMemcpy(host_data_out, cuda_data_out, DATA_OUT_SIZE,
		cudaMemcpyDeviceToHost));
	HANDLE_ERROR(cudaFree(cuda_data));
	HANDLE_ERROR(cudaFree(cuda_data_out));
}

__device__ void cuda_md5(char len, uint32_t * internal_ret, uint32_t * x)
{
	x[len / 4] |= (((uint32_t) 0x80) << ((len & 0x3) << 3));
	uint32_t x14 = len << 3;

	uint32_t a = 0x67452301;
	uint32_t b = 0xefcdab89;
	uint32_t c = 0x98badcfe;
	uint32_t d = 0x10325476;

	a = AC1 + x[0];
	a = ROTATE_LEFT(a, S11);
	a += b;			/* 1 */
	d = (c ^ (a & MASK1)) + x[1] + AC2pCd;
	d = ROTATE_LEFT(d, S12);
	d += a;			/* 2 */
	c = F(d, a, b) + x[2] + AC3pCc;
	c = ROTATE_LEFT(c, S13);
	c += d;			/* 3 */
	b = F(c, d, a) + x[3] + AC4pCb;
	b = ROTATE_LEFT(b, S14);
	b += c;
	FF(a, b, c, d, x[4], S11, 0xf57c0faf);
	FF(d, a, b, c, x[5], S12, 0x4787c62a);
	FF(c, d, a, b, x[6], S13, 0xa8304613);
	FF(b, c, d, a, x[7], S14, 0xfd469501);
	FF(a, b, c, d, 0, S11, 0x698098d8);
	FF(d, a, b, c, 0, S12, 0x8b44f7af);
	FF(c, d, a, b, 0, S13, 0xffff5bb1);
	FF(b, c, d, a, 0, S14, 0x895cd7be);
	FF(a, b, c, d, 0, S11, 0x6b901122);
	FF(d, a, b, c, 0, S12, 0xfd987193);
	FF(c, d, a, b, x14, S13, 0xa679438e);
	FF(b, c, d, a, 0, S14, 0x49b40821);

	GG(a, b, c, d, x[1], S21, 0xf61e2562);
	GG(d, a, b, c, x[6], S22, 0xc040b340);
	GG(c, d, a, b, 0, S23, 0x265e5a51);
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
	GG(a, b, c, d, x[5], S21, 0xd62f105d);
	GG(d, a, b, c, 0, S22, 0x2441453);
	GG(c, d, a, b, 0, S23, 0xd8a1e681);
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
	GG(a, b, c, d, 0, S21, 0x21e1cde6);
	GG(d, a, b, c, x14, S22, 0xc33707d6);
	GG(c, d, a, b, x[3], S23, 0xf4d50d87);
	GG(b, c, d, a, 0, S24, 0x455a14ed);
	GG(a, b, c, d, 0, S21, 0xa9e3e905);
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
	GG(c, d, a, b, x[7], S23, 0x676f02d9);
	GG(b, c, d, a, 0, S24, 0x8d2a4c8a);

	HH(a, b, c, d, x[5], S31, 0xfffa3942);
	HH(d, a, b, c, 0, S32, 0x8771f681);
	HH(c, d, a, b, 0, S33, 0x6d9d6122);
	HH(b, c, d, a, x14, S34, 0xfde5380c);
	HH(a, b, c, d, x[1], S31, 0xa4beea44);
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
	HH(b, c, d, a, 0, S34, 0xbebfbc70);
	HH(a, b, c, d, 0, S31, 0x289b7ec6);
	HH(d, a, b, c, x[0], S32, 0xeaa127fa);
	HH(c, d, a, b, x[3], S33, 0xd4ef3085);
	HH(b, c, d, a, x[6], S34, 0x4881d05);
	HH(a, b, c, d, 0, S31, 0xd9d4d039);
	HH(d, a, b, c, 0, S32, 0xe6db99e5);
	HH(c, d, a, b, 0, S33, 0x1fa27cf8);
	HH(b, c, d, a, x[2], S34, 0xc4ac5665);

	II(a, b, c, d, x[0], S41, 0xf4292244);
	II(d, a, b, c, x[7], S42, 0x432aff97);
	II(c, d, a, b, x14, S43, 0xab9423a7);
	II(b, c, d, a, x[5], S44, 0xfc93a039);
	II(a, b, c, d, 0, S41, 0x655b59c3);
	II(d, a, b, c, x[3], S42, 0x8f0ccc92);
	II(c, d, a, b, 0, S43, 0xffeff47d);
	II(b, c, d, a, x[1], S44, 0x85845dd1);
	II(a, b, c, d, 0, S41, 0x6fa87e4f);
	II(d, a, b, c, 0, S42, 0xfe2ce6e0);
	II(c, d, a, b, x[6], S43, 0xa3014314);
	II(b, c, d, a, 0, S44, 0x4e0811a1);
	II(a, b, c, d, x[4], S41, 0xf7537e82);
	II(d, a, b, c, 0, S42, 0xbd3af235);
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
	II(b, c, d, a, 0, S44, 0xeb86d391);

	internal_ret[0] = a + 0x67452301;
	internal_ret[1] = b + 0xefcdab89;
	internal_ret[2] = c + 0x98badcfe;
	internal_ret[3] = d + 0x10325476;
}

__device__ void clear_ctx(uint32_t * x)
{
	int i;
#pragma unroll 8
	for (i = 0; i < 8; i++)
		*x++ = 0;
}

__global__ void kernel_phpass(unsigned char *password, phpass_crack * data_out)
{
	uint32_t x[8];
	clear_ctx(x);

	int length, count, i;
	unsigned char *buff = (unsigned char *) x;
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	length = password[address(15, idx)];

#pragma unroll 8
	for (i = 0; i < 8; i++)
		buff[i] = cuda_salt[0].salt[i];

	for (i = 8; i < 8 + length; i++) {
		buff[i] = password[address(i - 8, idx)];
	}

	cuda_md5(8 + length, x, x);
	count = cuda_salt[0].rounds;
	for (i = 16; i < 16 + length; i++)
		buff[i] = password[address(i - 16, idx)];

	uint32_t a, b, c, d, x0, x1, x2, x3, x4, x5, x6, x7;
	uint32_t len = 16 + length;
	uint32_t x14 = len << 3;

	x[len / 4] |= ((0x80) << ((len & 0x3) << 3));
	x0 = x[0];
	x1 = x[1];
	x2 = x[2];
	x3 = x[3];
	x4 = x[4];
	x5 = x[5];
	x6 = x[6];
	x7 = x[7];
	do {

		b = 0xefcdab89;
		c = 0x98badcfe;
		d = 0x10325476;

		a = AC1 + x0;
		a = ROTATE_LEFT(a, S11);
		a += b;		/* 1 */
		d = (c ^ (a & MASK1)) + x1 + AC2pCd;
		d = ROTATE_LEFT(d, S12);
		d += a;		/* 2 */
		c = F(d, a, b) + x2 + AC3pCc;
		c = ROTATE_LEFT(c, S13);
		c += d;		/* 3 */
		b = F(c, d, a) + x3 + AC4pCb;
		b = ROTATE_LEFT(b, S14);
		b += c;
		FF(a, b, c, d, x4, S11, 0xf57c0faf);
		FF(d, a, b, c, x5, S12, 0x4787c62a);
		FF(c, d, a, b, x6, S13, 0xa8304613);
		FF(b, c, d, a, x7, S14, 0xfd469501);
		FF(a, b, c, d, 0, S11, 0x698098d8);
		FF(d, a, b, c, 0, S12, 0x8b44f7af);
		FF(c, d, a, b, 0, S13, 0xffff5bb1);
		FF(b, c, d, a, 0, S14, 0x895cd7be);
		FF(a, b, c, d, 0, S11, 0x6b901122);
		FF(d, a, b, c, 0, S12, 0xfd987193);
		FF(c, d, a, b, x14, S13, 0xa679438e);
		FF(b, c, d, a, 0, S14, 0x49b40821);

		GG(a, b, c, d, x1, S21, 0xf61e2562);
		GG(d, a, b, c, x6, S22, 0xc040b340);
		GG(c, d, a, b, 0, S23, 0x265e5a51);
		GG(b, c, d, a, x0, S24, 0xe9b6c7aa);
		GG(a, b, c, d, x5, S21, 0xd62f105d);
		GG(d, a, b, c, 0, S22, 0x2441453);
		GG(c, d, a, b, 0, S23, 0xd8a1e681);
		GG(b, c, d, a, x4, S24, 0xe7d3fbc8);
		GG(a, b, c, d, 0, S21, 0x21e1cde6);
		GG(d, a, b, c, x14, S22, 0xc33707d6);
		GG(c, d, a, b, x3, S23, 0xf4d50d87);
		GG(b, c, d, a, 0, S24, 0x455a14ed);
		GG(a, b, c, d, 0, S21, 0xa9e3e905);
		GG(d, a, b, c, x2, S22, 0xfcefa3f8);
		GG(c, d, a, b, x7, S23, 0x676f02d9);
		GG(b, c, d, a, 0, S24, 0x8d2a4c8a);

		HH(a, b, c, d, x5, S31, 0xfffa3942);
		HH(d, a, b, c, 0, S32, 0x8771f681);
		HH(c, d, a, b, 0, S33, 0x6d9d6122);
		HH(b, c, d, a, x14, S34, 0xfde5380c);
		HH(a, b, c, d, x1, S31, 0xa4beea44);
		HH(d, a, b, c, x4, S32, 0x4bdecfa9);
		HH(c, d, a, b, x7, S33, 0xf6bb4b60);
		HH(b, c, d, a, 0, S34, 0xbebfbc70);
		HH(a, b, c, d, 0, S31, 0x289b7ec6);
		HH(d, a, b, c, x0, S32, 0xeaa127fa);
		HH(c, d, a, b, x3, S33, 0xd4ef3085);
		HH(b, c, d, a, x6, S34, 0x4881d05);
		HH(a, b, c, d, 0, S31, 0xd9d4d039);
		HH(d, a, b, c, 0, S32, 0xe6db99e5);
		HH(c, d, a, b, 0, S33, 0x1fa27cf8);
		HH(b, c, d, a, x2, S34, 0xc4ac5665);

		II(a, b, c, d, x0, S41, 0xf4292244);
		II(d, a, b, c, x7, S42, 0x432aff97);
		II(c, d, a, b, x14, S43, 0xab9423a7);
		II(b, c, d, a, x5, S44, 0xfc93a039);
		II(a, b, c, d, 0, S41, 0x655b59c3);
		II(d, a, b, c, x3, S42, 0x8f0ccc92);
		II(c, d, a, b, 0, S43, 0xffeff47d);
		II(b, c, d, a, x1, S44, 0x85845dd1);
		II(a, b, c, d, 0, S41, 0x6fa87e4f);
		II(d, a, b, c, 0, S42, 0xfe2ce6e0);
		II(c, d, a, b, x6, S43, 0xa3014314);
		II(b, c, d, a, 0, S44, 0x4e0811a1);
		II(a, b, c, d, x4, S41, 0xf7537e82);
		II(d, a, b, c, 0, S42, 0xbd3af235);
		II(c, d, a, b, x2, S43, 0x2ad7d2bb);
		II(b, c, d, a, 0, S44, 0xeb86d391);

		x0 = a + 0x67452301;
		x1 = b + 0xefcdab89;
		x2 = c + 0x98badcfe;
		x3 = d + 0x10325476;

	} while (--count);

	char cracked = 1;
	cracked &= (x0 == cuda_salt[0].hash[0]);
	cracked &= (x1 == cuda_salt[0].hash[1]);
	cracked &= (x2 == cuda_salt[0].hash[2]);
	cracked &= (x3 == cuda_salt[0].hash[3]);
	data_out[idx].cracked = cracked;
}
