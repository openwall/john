/*
* This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* This file is shared by raw-sha224-cuda and raw-sha256-cuda formats,
* SHA256 definition is used to distinguish between them.
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "cuda_common.cuh"
#include "../cuda_rawsha256.h"

static void cuda_rawsha256(sha256_password *, void *, int);

#ifdef SHA256
#define SHA_HASH sha256_hash
__constant__ const uint32_t H[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
	    0x1f83d9ab, 0x5be0cd19
};

extern "C" void gpu_rawsha256(sha256_password * i, SHA_HASH * o, int lap)
{
	cuda_rawsha256(i, o, lap);
}
#endif
#ifdef SHA224
#define SHA_HASH sha224_hash
__constant__ const uint32_t H[] = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511,
	    0x64f98fa7, 0xbefa4fa4
};

extern "C" void gpu_rawsha224(sha256_password * i, SHA_HASH * o, int lap)
{
	cuda_rawsha256(i, o, lap);
}
#endif

const uint32_t DATA_IN_SIZE = KEYS_PER_CRYPT * sizeof(sha256_password);
const uint32_t DATA_OUT_SIZE = KEYS_PER_CRYPT * sizeof(SHA_HASH);

static sha256_password *cuda_data = NULL;	///candidates
static SHA_HASH *cuda_data_out = NULL;		///sha256(candidate) or sha224(candidate)

static cudaStream_t stream0, stream1, stream2;	///streams for async cuda calls

static sha256_password *cuda_data0 = NULL;	///candidates
static sha256_password *cuda_data1 = NULL;	///candidates
static sha256_password *cuda_data2 = NULL;	///candidates

static SHA_HASH *cuda_data_out0 = NULL;	///sha256(candidates)
static SHA_HASH *cuda_data_out1 = NULL;	///sha256(candidates)
static SHA_HASH *cuda_data_out2 = NULL;	///sha256(candidates)

__global__ void kernel_sha256(sha256_password * data, SHA_HASH * data_out);
static void cuda_rawsha256(sha256_password * host_in, void *out, int overlap)
{
	if (overlap) {
		HANDLE_ERROR(cudaMalloc(&cuda_data0, DATA_IN_SIZE / 3));
		HANDLE_ERROR(cudaMalloc(&cuda_data1, DATA_IN_SIZE / 3));
		HANDLE_ERROR(cudaMalloc(&cuda_data2, DATA_IN_SIZE / 3));
		HANDLE_ERROR(cudaMalloc(&cuda_data_out0, DATA_OUT_SIZE / 3));
		HANDLE_ERROR(cudaMalloc(&cuda_data_out1, DATA_OUT_SIZE / 3));
		HANDLE_ERROR(cudaMalloc(&cuda_data_out2, DATA_OUT_SIZE / 3));

		HANDLE_ERROR(cudaStreamCreate(&stream0));
		HANDLE_ERROR(cudaStreamCreate(&stream1));
		HANDLE_ERROR(cudaStreamCreate(&stream2));

		dim3 dimGrid(BLOCKS / 3);
		dim3 dimBlock(THREADS);

		HANDLE_ERROR(cudaMemcpyAsync(cuda_data0, host_in,
			DATA_IN_SIZE / 3, cudaMemcpyHostToDevice, stream0));
		kernel_sha256 <<< dimGrid, dimBlock, 0,
		    stream0 >>> (cuda_data0, cuda_data_out0);

		HANDLE_ERROR(cudaMemcpyAsync(cuda_data1,
			host_in + KEYS_PER_CRYPT / 3, DATA_IN_SIZE / 3,
			cudaMemcpyHostToDevice, stream1));
		kernel_sha256 <<< dimGrid, dimBlock, 0,
		    stream1 >>> (cuda_data1, cuda_data_out1);

		cudaMemcpyAsync(cuda_data2, host_in + 2 * KEYS_PER_CRYPT / 3,
		    DATA_IN_SIZE / 3, cudaMemcpyHostToDevice, stream2);
		kernel_sha256 <<< dimGrid, dimBlock, 0,
		    stream2 >>> (cuda_data2, cuda_data_out2);

		HANDLE_ERROR(cudaMemcpyAsync((SHA_HASH *) out, cuda_data_out0,
			DATA_OUT_SIZE / 3, cudaMemcpyDeviceToHost, stream0));
		HANDLE_ERROR(cudaMemcpyAsync((SHA_HASH *) out +
			KEYS_PER_CRYPT / 3, cuda_data_out1, DATA_OUT_SIZE / 3,
			cudaMemcpyDeviceToHost, stream1));
		HANDLE_ERROR(cudaMemcpyAsync((SHA_HASH *) out +
			2 * KEYS_PER_CRYPT / 3, cuda_data_out2,
			DATA_OUT_SIZE / 3, cudaMemcpyDeviceToHost, stream2));

		HANDLE_ERROR(cudaStreamSynchronize(stream0));
		HANDLE_ERROR(cudaStreamSynchronize(stream1));
		HANDLE_ERROR(cudaStreamSynchronize(stream2));

		cudaStreamDestroy(stream0);
		cudaStreamDestroy(stream1);
		cudaStreamDestroy(stream2);
		cudaFree(cuda_data0);
		cudaFree(cuda_data1);
		cudaFree(cuda_data2);
		cudaFree(cuda_data_out0);
		cudaFree(cuda_data_out1);
		cudaFree(cuda_data_out2);

	} else {
		SHA_HASH *host_out = (SHA_HASH *) out;
		cudaMalloc(&cuda_data, DATA_IN_SIZE);
		cudaMalloc(&cuda_data_out, DATA_OUT_SIZE);
		cudaMemcpy(cuda_data, host_in, DATA_IN_SIZE,
		    cudaMemcpyHostToDevice);

		kernel_sha256 <<< BLOCKS, THREADS >>> (cuda_data,
		    cuda_data_out);
		cudaThreadSynchronize();

		cudaMemcpy(host_out, cuda_data_out, DATA_OUT_SIZE,
		    cudaMemcpyDeviceToHost);
		cudaFree(cuda_data);
		cudaFree(cuda_data_out);
	}
}

__constant__ uint32_t k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	    0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
	    0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
	    0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	    0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
	    0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
	    0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	    0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
	    0xbef9a3f7, 0xc67178f2
};

   /* highly unoptimal kernel */
__global__ void kernel_sha256(sha256_password * data, SHA_HASH * data_out)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	uint32_t w[64];//this should be limited do 16 uints
	SHA_HASH *out = &data_out[idx];
	sha256_password *in = &data[idx];
	char dl = in->length;
	unsigned char *key = in->v;
	int j;
	for (j = 0; j < 15; j++)
		w[j] = 0;
	for (j = 0; j < dl; j++) {
		uint32_t tmp = 0;
		tmp |= (((uint32_t) key[j]) << ((3 - (j & 0x3)) << 3));
		w[j / 4] |= tmp;
	}
	w[dl / 4] |= (((uint32_t) 0x80) << ((3 - (dl & 0x3)) << 3));
	w[15] = 0x00000000 | (dl * 8);


	w[16] = sigma0(w[1]) + w[0];
	w[17] = sigma1(w[15]) + sigma0(w[2]) + w[1];
	w[18] = sigma1(w[16]) + sigma0(w[3]) + w[2];
	w[19] = sigma1(w[17]) + sigma0(w[4]) + w[3];
	w[20] = sigma1(w[18]) + sigma0(w[5]) + w[4];
	w[21] = sigma1(w[19]) + w[5];
	w[22] = sigma1(w[20]) + w[15];
	w[23] = sigma1(w[21]) + w[16];
	w[24] = sigma1(w[22]) + w[17];
	w[25] = sigma1(w[23]) + w[18];
	w[26] = sigma1(w[24]) + w[19];
	w[27] = sigma1(w[25]) + w[20];
	w[28] = sigma1(w[26]) + w[21];
	w[29] = sigma1(w[27]) + w[22];
	w[30] = sigma1(w[28]) + w[23] + sigma0(w[15]);
	w[31] = sigma1(w[29]) + w[24] + sigma0(w[16]) + w[15];

#pragma unroll 32
	for (uint32_t j = 32; j < 64; j++) {
		w[j] =
		    sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j -
		    16];
	}

	uint32_t a = H[0];
	uint32_t b = H[1];
	uint32_t c = H[2];
	uint32_t d = H[3];
	uint32_t e = H[4];
	uint32_t f = H[5];
	uint32_t g = H[6];
	uint32_t h = H[7];
#pragma unroll 64
	for (uint32_t j = 0; j < 64; j++) {
		uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k[j] + w[j];
		uint32_t t2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	out->v[0] = a + H[0];
	out->v[1] = b + H[1];
	out->v[2] = c + H[2];
	out->v[3] = d + H[3];
	out->v[4] = e + H[4];
	out->v[5] = f + H[5];
	out->v[6] = g + H[6];
#ifdef SHA256
	out->v[7] = h + H[7];
#endif
}
