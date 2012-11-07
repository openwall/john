/*
* This software is Copyright (c) 2011 Lukas Odzioba
* <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on Alain Espinosa implementation http://openwall.info/wiki/john/MSCash
*/

#include <stdio.h>
#include "../cuda_mscash.h"
#include "cuda_common.cuh"

extern "C" void cuda_mscash(mscash_password *, mscash_hash *, mscash_salt *);

__constant__ mscash_salt cuda_salt[1];

__device__ static void md4_crypt(uint32_t * output, uint32_t * nt_buffer)
{
	unsigned int a = INIT_A;
	unsigned int b = INIT_B;
	unsigned int c = INIT_C;
	unsigned int d = INIT_D;

	/* Round 1 */
	a += (d ^ (b & (c ^ d))) + nt_buffer[0];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[1];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[2];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[3];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[4];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[5];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[6];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[7];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[8];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[9];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[10];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[11];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[12];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[13];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[14];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[15];
	b = (b << 19) | (b >> 13);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2;
	b = (b << 13) | (b >> 19);

	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3;
	b = (b << 15) | (b >> 17);

	output[0] = a + INIT_A;
	output[1] = b + INIT_B;
	output[2] = c + INIT_C;
	output[3] = d + INIT_D;
}

__device__ void prepare_key(uint8_t * key, int length, uint32_t * nt_buffer)
{
	int i = 0;
	for (i = 0; i < 16; i++)
		nt_buffer[i] = 0;
	for (i = 0; i < length / 2; i++)
		nt_buffer[i] = key[2 * i] | (key[2 * i + 1] << 16);
	if (length % 2 == 1)
		nt_buffer[i] = key[length - 1] | 0x800000;
	else
		nt_buffer[i] = 0x80;
	nt_buffer[14] = length << 4;
}

__device__ void prepare_login(uint8_t * login, int length,
    uint32_t * login_buffer)
{
	int i = 0;
	for (i = 0; i < 12; i++)
		login_buffer[i] = 0;
	for (i = 0; i < length / 2; i++)
		login_buffer[i] = login[2 * i] | (login[2 * i + 1] << 16);
	if (length % 2 == 1)
		login_buffer[i] = login[length - 1] | 0x800000;
	else
		login_buffer[i] = 0x80;
	login_buffer[10] = (length << 4) + 128;
}


__global__ void mscash_kernel(mscash_password * inbuffer,
    mscash_hash * outbuffer)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint8_t *login =(uint8_t*) cuda_salt[0].salt;
	uint8_t loginlength = cuda_salt[0].length;

	uint8_t *password = inbuffer[idx].v;
	uint8_t passwordlength = inbuffer[idx].length;

	int i;
	uint32_t nt_buffer[16];
	uint32_t login_buffer[12];
	uint32_t output[4];

	prepare_key(password, passwordlength, nt_buffer);
	md4_crypt(output, nt_buffer);
	memcpy(nt_buffer, output, 4 * 4);

	prepare_login(login, loginlength, login_buffer);
	memcpy(nt_buffer + 4, login_buffer, 12 * 4);
	md4_crypt(output, nt_buffer);

	for (i = 0; i < 4; i++)
		outbuffer[idx].v[i] = output[i];

}

__host__ void cuda_mscash(mscash_password * inbuffer, mscash_hash * outbuffer,
    mscash_salt * host_salt)
{

	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt,
		sizeof(mscash_salt)));
	mscash_password *cuda_inbuffer;
	mscash_hash *cuda_outbuffer;

	size_t insize = sizeof(mscash_password) * KEYS_PER_CRYPT;
	size_t outsize = sizeof(mscash_hash) * KEYS_PER_CRYPT;

	HANDLE_ERROR(cudaMalloc(&cuda_inbuffer, insize));
	HANDLE_ERROR(cudaMalloc(&cuda_outbuffer, outsize));

	HANDLE_ERROR(cudaMemcpy(cuda_inbuffer, inbuffer, insize,
		cudaMemcpyHostToDevice));

	mscash_kernel <<< BLOCKS, THREADS >>> (cuda_inbuffer, cuda_outbuffer);
	HANDLE_ERROR(cudaGetLastError());

	HANDLE_ERROR(cudaMemcpy(outbuffer, cuda_outbuffer, outsize,
		cudaMemcpyDeviceToHost));

	HANDLE_ERROR(cudaFree(cuda_inbuffer));
	HANDLE_ERROR(cudaFree(cuda_outbuffer));

}
