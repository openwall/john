/*
 * This software is Copyright (c) 2011 Myrice <qqlddg at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Thanks to Lukas Odzioba <lukas dot odzioba at gmail dot com>, his code helps me a lot
*/
#include "../cuda_xsha512.h"
#include "cuda_common.cuh"

extern "C" void cuda_xsha512(xsha512_key *host_password, xsha512_salt *host_salt, xsha512_hash* host_hash);
extern "C" void cuda_xsha512_init();
extern "C" int cuda_cmp_all(void *binary, int count);
extern "C" void cuda_xsha512_cpy_hash(xsha512_hash* host_hash);

static xsha512_key *cuda_password;
static xsha512_hash *cuda_hash;
static size_t password_size;
static size_t hash_size;

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

__constant__ xsha512_salt cuda_salt[1];
__constant__ uint64_t cuda_b0[1];

__device__ void xsha512_init(xsha512_ctx *ctx)
{
    ctx->H[0] = 0x6a09e667f3bcc908LL;
	ctx->H[1] = 0xbb67ae8584caa73bLL;
	ctx->H[2] = 0x3c6ef372fe94f82bLL;
	ctx->H[3] = 0xa54ff53a5f1d36f1LL;
	ctx->H[4] = 0x510e527fade682d1LL;
	ctx->H[5] = 0x9b05688c2b3e6c1fLL;
	ctx->H[6] = 0x1f83d9abfb41bd6bLL;
	ctx->H[7] = 0x5be0cd19137e2179LL;
	ctx->buflen = 0;
}


__device__ void xsha512_update(xsha512_ctx *ctx, const char *string, uint8_t length)
{
    uint8_t *off = &ctx->buffer[ctx->buflen];
    memcpy(off, string, length);
    ctx->buflen += length;
}

// The function below is from Lukas' crypt512-cuda
__device__ void sha512_block(xsha512_ctx * ctx)
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
    #pragma unroll 16
	for (i = 0; i < 16; i++)
		w[i] = SWAP64(data[i]);

	uint64_t t1, t2;
    #pragma unroll 16
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
    #pragma unroll 64
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
#if 0
	ctx->H[1] += b;
	ctx->H[2] += c;
	ctx->H[3] += d;
	ctx->H[4] += e;
	ctx->H[5] += f;
	ctx->H[6] += g;
	ctx->H[7] += h;
#endif
}

__device__ void xsha512_final(xsha512_ctx *ctx)
{
    //append 1 to ctx buffer
    uint32_t length = ctx->buflen;
    uint8_t *buffer8 = &ctx->buffer[length];

    *buffer8++ = 0x80;

    while(++length % 4 != 0)  {
        *buffer8++ = 0;
    }

    uint32_t *buffer32 = (uint32_t*)buffer8;
    for(uint32_t i = length; i < 128; i+=4) {// append 0 to 128
        *buffer32++=0;
    }

    //append length to ctx buffer
    uint64_t *buffer64 = (uint64_t *)ctx->buffer;
    buffer64[15] = SWAP64((uint64_t) ctx->buflen * 8); 

    sha512_block(ctx);
}

__device__ void xsha512(const char* password, uint8_t pass_len, uint64_t *hash, uint32_t offset)
{
    xsha512_ctx ctx;
    xsha512_init(&ctx);
    xsha512_update(&ctx, (const char*)cuda_salt[0].v, SALT_SIZE);
    xsha512_update(&ctx, password, pass_len);
    xsha512_final(&ctx);

#if 0
	#pragma unroll 8
	for(uint32_t i = 0; i < 8; ++i) {
		hash[hash_addr(i, idx)] = SWAP64(ctx.H[i]);
	}
#else
	hash[hash_addr(0, offset)] = SWAP64(ctx.H[0]);
#endif
}

__global__ void kernel_xsha512(xsha512_key *cuda_password, xsha512_hash *cuda_hash)
{

    uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	for(uint32_t it = 0; it < (MAX_KEYS_PER_CRYPT/KEYS_PER_CRYPT); ++it) {		
		uint32_t offset = idx+it*KEYS_PER_CRYPT;
    	xsha512((const char*)cuda_password[offset].v, cuda_password[offset].length, (uint64_t*)cuda_hash, offset);
	}
}

void cuda_xsha512_init()
{
    password_size = sizeof(xsha512_key) * MAX_KEYS_PER_CRYPT;
    hash_size = sizeof(xsha512_hash) * MAX_KEYS_PER_CRYPT;
	HANDLE_ERROR(cudaMalloc(&cuda_password, password_size));
    HANDLE_ERROR(cudaMalloc(&cuda_hash, hash_size));
}

void cuda_xsha512_cpy_hash(xsha512_hash* host_hash)
{
	HANDLE_ERROR(cudaMemcpy(host_hash, cuda_hash, hash_size, cudaMemcpyDeviceToHost));
}

void cuda_xsha512(xsha512_key *host_password, xsha512_salt *host_salt, xsha512_hash* host_hash) 
{
	if(xsha512_key_changed) {
	    HANDLE_ERROR(cudaMemcpy(cuda_password, host_password, password_size, cudaMemcpyHostToDevice));
	}
    HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt, sizeof(xsha512_salt)));

    dim3 dimGrid(BLOCKS);
    dim3 dimBlock(THREADS);
    kernel_xsha512 <<< dimGrid, dimBlock >>> (cuda_password, cuda_hash);
}

__global__ void kernel_cmp_all(int count, uint64_t* hash, uint8_t *result)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	if(idx == 0)
		*result = 0;
	__syncthreads();
	for(uint32_t it = 0; it < (MAX_KEYS_PER_CRYPT/KEYS_PER_CRYPT); ++it) {		
		uint32_t offset = idx+it*KEYS_PER_CRYPT;
		if(offset < count){
			if (cuda_b0[0] == hash[hash_addr(0, offset)])
				*result = 1;
		}
	}
}

int cuda_cmp_all(void *binary, int count)
{
	uint64_t b0 = *(uint64_t *)binary;
	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_b0, &b0, sizeof(uint64_t)));
	uint8_t result = 0;
	uint8_t *cuda_result;
	HANDLE_ERROR(cudaMalloc(&cuda_result, sizeof(uint8_t)));
    dim3 dimGrid(BLOCKS);
    dim3 dimBlock(THREADS);
	kernel_cmp_all <<< dimGrid, dimBlock >>> (count, (uint64_t*)cuda_hash, cuda_result);
	HANDLE_ERROR(cudaMemcpy(&result, cuda_result, sizeof(uint8_t), cudaMemcpyDeviceToHost));
	return result;
}
