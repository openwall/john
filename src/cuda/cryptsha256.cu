/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../cuda_cryptsha256.h"
#include "cuda_common.cuh"

extern "C" void sha256_crypt_gpu(crypt_sha256_password * inbuffer,
    crypt_sha256_hash * outbuffer, crypt_sha256_salt * host_salt);

__constant__ crypt_sha256_salt cuda_salt[1];
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



__device__ void init_ctx(sha256_ctx * ctx)
{
	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;
	ctx->total = 0;
	ctx->buflen = 0;
}

__device__ void insert_to_buffer(sha256_ctx * ctx, const uint8_t * string,
    uint8_t len)
{
	int i = len;
	uint8_t *d = &ctx->buffer[ctx->buflen];
	while (i--)
		*d++ = *string++;
	ctx->buflen += len;
}

__device__ void sha256_block(sha256_ctx * ctx)
{
	int i;
	uint32_t a = ctx->H[0];
	uint32_t b = ctx->H[1];
	uint32_t c = ctx->H[2];
	uint32_t d = ctx->H[3];
	uint32_t e = ctx->H[4];
	uint32_t f = ctx->H[5];
	uint32_t g = ctx->H[6];
	uint32_t h = ctx->H[7];
	uint32_t w[16];
	uint32_t *data = (uint32_t *) ctx->buffer;

    #pragma unroll 16
	  for (i = 0; i < 16; i++)
		w[i] = SWAP(data[i]);
	
	uint32_t t1, t2;
	for (i = 0; i < 16; i++) {
		t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	for (i = 16; i < 64; i++) {

		w[i & 15] =
		    sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i -
			16) & 15] + w[(i - 7) & 15];
		t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);
		t2 = Maj(a, b, c) + Sigma0(a);

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->H[0] += a;
	ctx->H[1] += b;
	ctx->H[2] += c;
	ctx->H[3] += d;
	ctx->H[4] += e;
	ctx->H[5] += f;
	ctx->H[6] += g;
	ctx->H[7] += h;

}

__device__ void ctx_update(sha256_ctx * ctx, const char *string, uint8_t len)
{
	ctx->total += len;
	uint8_t startpos = ctx->buflen;
	uint8_t partsize;
	if (startpos + len <= 64) {
		partsize = len;
	} else
		partsize = 64 - startpos;

	insert_to_buffer(ctx, (const uint8_t *) string, partsize);
	if (ctx->buflen == 64) {
		uint8_t offset = 64 - startpos;
		sha256_block(ctx);
		ctx->buflen = 0;
		insert_to_buffer(ctx, (const uint8_t *) (string + offset),
		    len - offset);
	}
}

/**
  Add 0x80 byte to ctx->buffer and clean the rest of it
**/
__device__ void ctx_append_1(sha256_ctx * ctx)
{
	int i = 63 - ctx->buflen;
	uint8_t *d = &ctx->buffer[ctx->buflen];
	*d++ = 0x80;	
	while (i--)
	{
	  *d++ = 0;
	}

}

/**
  Add ctx->bufflen at the end of ctx->buffer
**/
__device__ void ctx_add_length(sha256_ctx * ctx)
{
	uint32_t *blocks = (uint32_t *) ctx->buffer;
	blocks[15] = SWAP(ctx->total * 8);
}

__device__ void finish_ctx(sha256_ctx * ctx)
{
	ctx_append_1(ctx);
	ctx_add_length(ctx);
	ctx->buflen = 0;
}

__device__ void clear_ctx_buffer(sha256_ctx * ctx)
{
	uint32_t *w = (uint32_t *) ctx->buffer;
#pragma unroll 16
	for (int i = 0; i < 16; i++)
		w[i] = 0;
	ctx->buflen = 0;

}

__device__ void sha256_digest(sha256_ctx * ctx, uint32_t * result)
{
	uint8_t i;
	if (ctx->buflen <= 55) {	//data+0x80+datasize fits in one 512bit block
		finish_ctx(ctx);
		sha256_block(ctx);
	} else {
		uint8_t moved = 1;
		if (ctx->buflen < 64) {	//data and 0x80 fits in one block
			ctx_append_1(ctx);
			moved = 0;
		}
		sha256_block(ctx);
		clear_ctx_buffer(ctx);
		if (moved)
			ctx->buffer[0] = 0x80;	//append 1,the rest is already clean
		ctx_add_length(ctx);
		sha256_block(ctx);
	}
#pragma unroll 8
	for (i = 0; i < 8; i++)
		result[i] = SWAP(ctx->H[i]);
}

__device__ void sha256crypt(const char *pass, uint8_t passlength,
    uint32_t * tresult, uint32_t idx, uint32_t rounds)
{

	uint32_t i, alt_result[8], temp_result[8];

	sha256_ctx ctx, alt_ctx;
	init_ctx(&ctx);
	init_ctx(&alt_ctx);

	ctx_update(&ctx, pass, passlength);
	ctx_update(&ctx, cuda_salt[0].salt, cuda_salt[0].saltlen);

	ctx_update(&alt_ctx, pass, passlength);
	ctx_update(&alt_ctx, cuda_salt[0].salt, cuda_salt[0].saltlen);
	ctx_update(&alt_ctx, pass, passlength);

	sha256_digest(&alt_ctx, alt_result);

	ctx_update(&ctx, (const char *) alt_result, passlength);


	for (i = passlength; i > 0; i >>= 1) {
		if ((i & 1) != 0)
			ctx_update(&ctx, (const char *) alt_result, 32);
		else
			ctx_update(&ctx, pass, passlength);
	}
	sha256_digest(&ctx, alt_result);

	init_ctx(&alt_ctx);
	for (i = 0; i < passlength; i++)
		ctx_update(&alt_ctx, pass, passlength);

	sha256_digest(&alt_ctx, temp_result);

	__shared__ char sp_sequence[THREADS][16+4];
	char *p_sequence=sp_sequence[threadIdx.x];
	memcpy(p_sequence, temp_result, passlength);

	init_ctx(&alt_ctx);
	for (i = 0; i < 16 + ((unsigned char *) alt_result)[0]; i++)
		ctx_update(&alt_ctx, cuda_salt[0].salt, cuda_salt[0].saltlen);

	sha256_digest(&alt_ctx, temp_result);

	uint8_t saltlength = cuda_salt[0].saltlen;

	__shared__ char ss_sequence[THREADS][16+4];
	char *s_sequence=ss_sequence[threadIdx.x];
	memcpy(s_sequence, temp_result, saltlength);

	for (i = 0; i < rounds; i++) {
		init_ctx(&ctx);

		if ((i & 1) != 0)
			ctx_update(&ctx, p_sequence, passlength);
		else
			ctx_update(&ctx, (const char *) alt_result, 32);

		if ((i % 3) != 0)
			ctx_update(&ctx, s_sequence, saltlength);

		if ((i % 7) != 0)
			ctx_update(&ctx, p_sequence, passlength);

		if ((i & 1) != 0)
			ctx_update(&ctx, (const char *) alt_result, 32);
		else
			ctx_update(&ctx, p_sequence, passlength);


		sha256_digest(&ctx, alt_result);
	}
	__syncthreads();
#pragma unroll 8
	for (i = 0; i < 8; i++)
		tresult[hash_addr(i, idx)] = alt_result[i];
}

__global__ void kernel_crypt_r(crypt_sha256_password * inbuffer,
    uint32_t * outbuffer)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	sha256crypt((const char *) inbuffer[idx].v, inbuffer[idx].length,
	    outbuffer, idx, cuda_salt[0].rounds);

}


void sha256_crypt_gpu(crypt_sha256_password * inbuffer,
    crypt_sha256_hash * outbuffer, crypt_sha256_salt * host_salt)
{

	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt,
		sizeof(crypt_sha256_salt)));

	crypt_sha256_password *cuda_inbuffer;
	uint32_t *cuda_outbuffer;
	size_t insize = sizeof(crypt_sha256_password) * KEYS_PER_CRYPT;
	size_t outsize = sizeof(crypt_sha256_hash) * KEYS_PER_CRYPT;
	HANDLE_ERROR(cudaMalloc(&cuda_inbuffer, insize));
	HANDLE_ERROR(cudaMalloc(&cuda_outbuffer, outsize));

	HANDLE_ERROR(cudaMemcpy(cuda_inbuffer, inbuffer, insize,
		cudaMemcpyHostToDevice));
	dim3 dimGrid(BLOCKS);
	dim3 dimBlock(THREADS);
	kernel_crypt_r <<< dimGrid, dimBlock >>> (cuda_inbuffer,
	    cuda_outbuffer);
	cudaThreadSynchronize();
	HANDLE_ERROR(cudaGetLastError());
	HANDLE_ERROR(cudaMemcpy(outbuffer, cuda_outbuffer, outsize,
		cudaMemcpyDeviceToHost));

	HANDLE_ERROR(cudaFree(cuda_inbuffer));
	HANDLE_ERROR(cudaFree(cuda_outbuffer));
}
