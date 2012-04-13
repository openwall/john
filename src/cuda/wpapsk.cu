/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

#include <stdio.h>
#include "../cuda_wpapsk.h"
#include "cuda_common.cuh"
extern "C" void wpapsk_gpu(wpapsk_password *, wpapsk_hash *, wpapsk_salt *);

__constant__ wpapsk_salt cuda_salt[1];

__device__ static void preproc(const uint8_t * key, uint32_t keylen,
    uint32_t * state, uint8_t var1, uint32_t var4)
{
	int i;
	uint32_t W[16], temp;
	uint8_t ipad[16];

	for (i = 0; i < keylen; i++)
		ipad[i] = var1 ^ key[i];
	for (i = keylen; i < 16; i++)
		ipad[i] = var1;

	for (i = 0; i < 4; i++)
		GET_WORD_32_BE(W[i], ipad, i * 4);

	for (i = 4; i < 16; i++)
		W[i] = var4;

	uint32_t A = INIT_A;
	uint32_t B = INIT_B;
	uint32_t C = INIT_C;
	uint32_t D = INIT_D;
	uint32_t E = INIT_E;

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;

}

__device__ static void hmac_sha1(uint32_t * output,
    uint32_t * ipad_state, uint32_t * opad_state, const uint8_t * salt,
    int saltlen, uint8_t add)
{
	int i;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;
	uint8_t buf[64];
	uint32_t *src = (uint32_t *) buf;
	i = 64 / 4;
	while (i--)
		*src++ = 0;
	memcpy(buf, salt, saltlen);
	buf[saltlen + 4] = 0x80;
	buf[saltlen + 3] = add;
	PUT_WORD_32_BE((64 + saltlen + 4) << 3, buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += ipad_state[0];
	B += ipad_state[1];
	C += ipad_state[2];
	D += ipad_state[3];
	E += ipad_state[4];

	PUT_WORD_32_BE(A, buf, 0);
	PUT_WORD_32_BE(B, buf, 4);
	PUT_WORD_32_BE(C, buf, 8);
	PUT_WORD_32_BE(D, buf, 12);
	PUT_WORD_32_BE(E, buf, 16);

	buf[20] = 0x80;
	PUT_WORD_32_BE(0x2A0, buf, 60);

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
}



__device__ static void big_hmac_sha1(uint32_t * input, uint32_t inputlen,
    uint32_t * ipad_state, uint32_t * opad_state, uint32_t * tmp_out)
{
	int i, lo;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;

	for (i = 0; i < 5; i++)
		W[i] = input[i];

	for (lo = 1; lo < ITERATIONS; lo++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];

		W[5] = 0x80000000;
		W[15] = 0x2A0;

		SHA2(A, B, C, D, E, W);

		A += ipad_state[0];
		B += ipad_state[1];
		C += ipad_state[2];
		D += ipad_state[3];
		E += ipad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = 0x80000000;
		W[15] = 0x2A0;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];

		SHA2(A, B, C, D, E, W);

		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
	}

#pragma unroll 5
	for (i = 0; i < 5; i++)
		tmp_out[i] = SWAP(tmp_out[i]);
}

__device__ void pbkdf2(const uint8_t * pass, int passlen, const uint8_t * salt,
    int saltlen, uint8_t * out)
{
	uint32_t ipad_state[5];
	uint32_t opad_state[5];
	uint32_t tmp_out[5];

	preproc(pass, passlen, ipad_state, 0x36, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c, 0x5c5c5c5c);

	hmac_sha1(tmp_out, ipad_state, opad_state, salt, saltlen, 0x01);

	big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH, ipad_state, opad_state,
	    tmp_out);

	memcpy(out, tmp_out, 20);

	hmac_sha1(tmp_out, ipad_state, opad_state, salt, saltlen, 0x02);

	big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH, ipad_state, opad_state,
	    tmp_out);

	memcpy(out + 20, tmp_out, 12);
}



__global__ void wpapsk_pbkdf2_kernel(wpapsk_password * inbuffer,
    wpapsk_hash * outbuffer)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	pbkdf2((uint8_t *) inbuffer[idx].v, inbuffer[idx].length,
	    cuda_salt[0].salt, cuda_salt[0].length,
	    (uint8_t *) outbuffer[idx].v);
}

__host__ void wpapsk_gpu(wpapsk_password * inbuffer, wpapsk_hash * outbuffer,
    wpapsk_salt * host_salt)
{
	wpapsk_password *cuda_inbuffer;
	wpapsk_hash *cuda_outbuffer;
	size_t insize = sizeof(wpapsk_password) * KEYS_PER_CRYPT;
	size_t outsize = sizeof(wpapsk_hash) * KEYS_PER_CRYPT;

	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt,
		sizeof(wpapsk_salt)));

	HANDLE_ERROR(cudaMalloc(&cuda_inbuffer, insize));
	HANDLE_ERROR(cudaMalloc(&cuda_outbuffer, outsize));

	HANDLE_ERROR(cudaMemcpy(cuda_inbuffer, inbuffer, insize,
		cudaMemcpyHostToDevice));

	wpapsk_pbkdf2_kernel <<< BLOCKS, THREADS >>> (cuda_inbuffer,
	    cuda_outbuffer);

	HANDLE_ERROR(cudaMemcpy(outbuffer, cuda_outbuffer, outsize,
		cudaMemcpyDeviceToHost));

	HANDLE_ERROR(cudaFree(cuda_inbuffer));
	HANDLE_ERROR(cudaFree(cuda_outbuffer));

}
