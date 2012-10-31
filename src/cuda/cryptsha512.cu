/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <stdio.h>
#include "../cuda_cryptsha512.h"
#include "cuda_common.cuh"

__constant__ uint64_t k[] = {
	0x428a2f98d728ae22LL, 0x7137449123ef65cdLL, 0xb5c0fbcfec4d3b2fLL,
	    0xe9b5dba58189dbbcLL,
	0x3956c25bf348b538LL, 0x59f111f1b605d019LL, 0x923f82a4af194f9bLL,
	    0xab1c5ed5da6d8118LL,
	0xd807aa98a3030242LL, 0x12835b0145706fbeLL, 0x243185be4ee4b28cLL,
	    0x550c7dc3d5ffb4e2LL,
	0x72be5d74f27b896fLL, 0x80deb1fe3b1696b1LL, 0x9bdc06a725c71235LL,
	    0xc19bf174cf692694LL,
	0xe49b69c19ef14ad2LL, 0xefbe4786384f25e3LL, 0x0fc19dc68b8cd5b5LL,
	    0x240ca1cc77ac9c65LL,
	0x2de92c6f592b0275LL, 0x4a7484aa6ea6e483LL, 0x5cb0a9dcbd41fbd4LL,
	    0x76f988da831153b5LL,
	0x983e5152ee66dfabLL, 0xa831c66d2db43210LL, 0xb00327c898fb213fLL,
	    0xbf597fc7beef0ee4LL,
	0xc6e00bf33da88fc2LL, 0xd5a79147930aa725LL, 0x06ca6351e003826fLL,
	    0x142929670a0e6e70LL,
	0x27b70a8546d22ffcLL, 0x2e1b21385c26c926LL, 0x4d2c6dfc5ac42aedLL,
	    0x53380d139d95b3dfLL,
	0x650a73548baf63deLL, 0x766a0abb3c77b2a8LL, 0x81c2c92e47edaee6LL,
	    0x92722c851482353bLL,
	0xa2bfe8a14cf10364LL, 0xa81a664bbc423001LL, 0xc24b8b70d0f89791LL,
	    0xc76c51a30654be30LL,
	0xd192e819d6ef5218LL, 0xd69906245565a910LL, 0xf40e35855771202aLL,
	    0x106aa07032bbd1b8LL,
	0x19a4c116b8d2d0c8LL, 0x1e376c085141ab53LL, 0x2748774cdf8eeb99LL,
	    0x34b0bcb5e19b48a8LL,
	0x391c0cb3c5c95a63LL, 0x4ed8aa4ae3418acbLL, 0x5b9cca4f7763e373LL,
	    0x682e6ff3d6b2b8a3LL,
	0x748f82ee5defb2fcLL, 0x78a5636f43172f60LL, 0x84c87814a1f0ab72LL,
	    0x8cc702081a6439ecLL,
	0x90befffa23631e28LL, 0xa4506cebde82bde9LL, 0xbef9a3f7b2c67915LL,
	    0xc67178f2e372532bLL,
	0xca273eceea26619cLL, 0xd186b8c721c0c207LL, 0xeada7dd6cde0eb1eLL,
	    0xf57d4f7fee6ed178LL,
	0x06f067aa72176fbaLL, 0x0a637dc5a2c898a6LL, 0x113f9804bef90daeLL,
	    0x1b710b35131c471bLL,
	0x28db77f523047d84LL, 0x32caab7b40c72493LL, 0x3c9ebe0a15c9bebcLL,
	    0x431d67c49c100d4cLL,
	0x4cc5d4becb3e42b6LL, 0x597f299cfc657e2aLL, 0x5fcb6fab3ad6faecLL,
	    0x6c44198c4a475817LL,
};

__constant__ crypt_sha512_salt cuda_salt[1];

extern "C" void sha512_crypt_gpu(crypt_sha512_password * inbuffer,
    crypt_sha512_hash * outbuffer, crypt_sha512_salt * salt);


__device__ void init_ctx(sha512_ctx * ctx)
{
	ctx->H[0] = 0x6a09e667f3bcc908LL;
	ctx->H[1] = 0xbb67ae8584caa73bLL;
	ctx->H[2] = 0x3c6ef372fe94f82bLL;
	ctx->H[3] = 0xa54ff53a5f1d36f1LL;
	ctx->H[4] = 0x510e527fade682d1LL;
	ctx->H[5] = 0x9b05688c2b3e6c1fLL;
	ctx->H[6] = 0x1f83d9abfb41bd6bLL;
	ctx->H[7] = 0x5be0cd19137e2179LL;
	ctx->total = 0;
	ctx->buflen = 0;
}


__device__ void insert_to_buffer(sha512_ctx * ctx, const uint8_t * string,
    uint8_t len)
{
	uint8_t *d = &ctx->buffer[ctx->buflen];
	memcpy(d,string,len);
	ctx->buflen += len;
}


__device__ void sha512_block(sha512_ctx * ctx)
{
	int i;
	uint64_t a = ctx->H[0];
	uint64_t b = ctx->H[1];
	uint64_t c = ctx->H[2];
	uint64_t d = ctx->H[3];
	uint64_t e = ctx->H[4];
	uint64_t f = ctx->H[5];
	uint64_t g = ctx->H[6];
	uint64_t h = ctx->H[7];


	uint64_t w[16];

	uint64_t *data = (uint64_t *) ctx->buffer;
//#pragma unroll 16
	for (i = 0; i < 16; i++)
		w[i] = SWAP64(data[i]);

	uint64_t t1, t2;
//#pragma unroll 16
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


	for (i = 16; i < 80; i++) {


		w[i & 15] =sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i -16) & 15] + w[(i - 7) & 15];
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


__device__ void ctx_append_1(sha512_ctx * ctx)
{
	uint32_t length=ctx->buflen;
	int i = 127 - length;
	uint32_t *x = (uint32_t *) ctx->buffer;
	uint8_t *d = &ctx->buffer[length];
	*d++ = 0x80;
	while(++length%4!=0)
	{  *d++=0;
	i--;
	}
	x=(uint32_t*)d;
	while(i>0)
	{  i-=4;
	    *x++=0;
	}
}

__device__ void ctx_add_length(sha512_ctx * ctx)
{
	uint64_t *blocks = (uint64_t *) ctx->buffer;
	blocks[15] = SWAP64((uint64_t) ctx->total * 8);
}

__device__ void finish_ctx(sha512_ctx * ctx)
{
	ctx_append_1(ctx);
	ctx_add_length(ctx);
	ctx->buflen = 0;
}


__device__ void ctx_update(sha512_ctx * ctx, const char *string, uint8_t len)
{
	ctx->total += len;
	uint8_t startpos = ctx->buflen;
	uint8_t partsize;
	if (startpos + len <= 128) {
		partsize = len;
	} else
		partsize = 128 - startpos;

	insert_to_buffer(ctx, (const uint8_t *) string, partsize);
	if (ctx->buflen == 128) {
		uint8_t offset = 128 - startpos;
		sha512_block(ctx);
		ctx->buflen = 0;
		insert_to_buffer(ctx, (const uint8_t *) (string + offset),
		    len - offset);
	}
}

__device__ void clear_ctx_buffer(sha512_ctx * ctx)
{
	uint32_t *w = (uint32_t *) ctx->buffer;
//#pragma unroll 30
	for (int i = 0; i < 30; i++)
		w[i] = 0;
	  
	  ctx->buflen = 0;
}

__device__ void sha512_digest(sha512_ctx * ctx, uint64_t * result)
{
	uint8_t i;
	if (ctx->buflen <= 111) {	//data+0x80+datasize fits in one 1024bit block
		finish_ctx(ctx);
		sha512_block(ctx);
	} else {
		uint8_t moved = 1;
		if (ctx->buflen < 128) {	//data and 0x80 fits in one block
			ctx_append_1(ctx);
			moved = 0;
		}
		sha512_block(ctx);
		clear_ctx_buffer(ctx);
		if (moved)
			ctx->buffer[0] = 0x80;	//append 1,the rest is already clean
		ctx_add_length(ctx);
		sha512_block(ctx);
	}
//#pragma unroll 8
	for (i = 0; i < 8; i++)
		result[i] = SWAP64(ctx->H[i]);
}


__device__ void sha512crypt(const char *pass, uint8_t passlength,
    uint64_t * tresult, uint32_t idx, uint32_t rounds)
{

	uint64_t  alt_result[8], temp_result[8];
	int i;
	sha512_ctx ctx;
	init_ctx(&ctx);

	ctx_update(&ctx, pass, passlength);
	ctx_update(&ctx, cuda_salt[0].salt, cuda_salt[0].saltlen);
	ctx_update(&ctx, pass, passlength);

	sha512_digest(&ctx, alt_result);
	init_ctx(&ctx);
	
	ctx_update(&ctx, pass, passlength);
	ctx_update(&ctx, cuda_salt[0].salt, cuda_salt[0].saltlen);
	ctx_update(&ctx, (const char *) alt_result, passlength);


	for (i = passlength; i > 0; i >>= 1) {
		if ((i & 1) != 0)
			ctx_update(&ctx, (const char *) alt_result, 64);
		else
			ctx_update(&ctx, pass, passlength);
	}
	sha512_digest(&ctx, alt_result);


	init_ctx(&ctx);
	for (i = 0; i < passlength; i++)
		ctx_update(&ctx, pass, passlength);

	sha512_digest(&ctx, temp_result);

	__shared__ char sp_sequence[THREADS][16+4];
	char *p_sequence=sp_sequence[threadIdx.x];
	memcpy(p_sequence, temp_result, passlength);

	init_ctx(&ctx);
	for (i = 0; i < 16 + ((unsigned char *) alt_result)[0]; i++)
		ctx_update(&ctx, cuda_salt[0].salt, cuda_salt[0].saltlen);

	sha512_digest(&ctx, temp_result);

	uint8_t saltlength = cuda_salt[0].saltlen;

	__shared__ char ss_sequence[THREADS][16+4];
	char *s_sequence=ss_sequence[threadIdx.x];
	memcpy(s_sequence, temp_result, saltlength);

	for (i = 0; i < rounds; i++) {
		init_ctx(&ctx);

		if ((i & 1) != 0)
			ctx_update(&ctx, p_sequence, passlength);
		else
			ctx_update(&ctx, (const char *) alt_result, 64);

		if ((i % 3) != 0)
			ctx_update(&ctx, s_sequence, saltlength);

		if ((i % 7) != 0)
			ctx_update(&ctx, p_sequence, passlength);

		if ((i & 1) != 0)
			ctx_update(&ctx, (const char *) alt_result, 64);
		else
			ctx_update(&ctx, p_sequence, passlength);


		sha512_digest(&ctx, alt_result);
	}
//#pragma unroll 8
	for (i = 0; i < 8; i++)
		tresult[i] = alt_result[i];
}



__global__ void kernel_crypt_r(crypt_sha512_password * inbuffer,
    crypt_sha512_hash * outbuffer)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	sha512crypt((const char *) inbuffer[idx].v, inbuffer[idx].length,
	    outbuffer[idx].v, idx, cuda_salt[0].rounds);
}

void sha512_crypt_gpu(crypt_sha512_password * inbuffer,
    crypt_sha512_hash * outbuffer, crypt_sha512_salt * host_salt)
{

	crypt_sha512_password *cuda_inbuffer;
	crypt_sha512_hash *cuda_outbuffer;
	size_t insize = sizeof(crypt_sha512_password) * KEYS_PER_CRYPT;
	size_t outsize = sizeof(crypt_sha512_hash) * KEYS_PER_CRYPT;

	HANDLE_ERROR(cudaMalloc(&cuda_inbuffer, insize));
	HANDLE_ERROR(cudaMalloc(&cuda_outbuffer, outsize));

	HANDLE_ERROR(cudaMemcpy(cuda_inbuffer, inbuffer, insize,
		cudaMemcpyHostToDevice));
	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt,
		sizeof(crypt_sha512_salt)));

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
