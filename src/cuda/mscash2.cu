/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/

#include <stdio.h>
#include "../cuda_mscash2.h"
#include "cuda_common.cuh"
extern "C" void mscash2_gpu(mscash2_password *, mscash2_hash *, mscash2_salt *);

__constant__ mscash2_salt cuda_salt[1];

__host__ void md4_crypt(uint32_t * buffer, uint32_t * hash)
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;

	a = 0xFFFFFFFF + buffer[0];
	a = (a << 3) | (a >> 29);
	d = INIT_D + (INIT_C ^ (a & 0x77777777)) + buffer[1];
	d = (d << 7) | (d >> 25);
	c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B))) + buffer[2];
	c = (c << 11) | (c >> 21);
	b = INIT_B + (a ^ (c & (d ^ a))) + buffer[3];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + buffer[4];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + buffer[5];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + buffer[6];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + buffer[7];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + buffer[8];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + buffer[9];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + buffer[10];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + buffer[11];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + buffer[12];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + buffer[13];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + buffer[14];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + buffer[15];
	b = (b << 19) | (b >> 13);

	a += ((b & (c | d)) | (c & d)) + buffer[0] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[4] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[8] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[12] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + buffer[1] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[5] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[9] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[13] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + buffer[2] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[6] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[10] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[14] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + buffer[3] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + buffer[7] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + buffer[11] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + buffer[15] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += (d ^ c ^ b) + buffer[0] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + buffer[8] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[4] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[12] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + buffer[2] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + buffer[10] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[6] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[14] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + buffer[1] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + buffer[9] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[5] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[13] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + buffer[3] + SQRT_3;
	a = (a << 3) | (a >> 29);

	d += (c ^ b ^ a) + buffer[11] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + buffer[7] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + buffer[15] + SQRT_3;
	b = (b << 15) | (b >> 17);

	hash[0] = a + INIT_A;
	hash[1] = b + INIT_B;
	hash[2] = c + INIT_C;
	hash[3] = d + INIT_D;
}

__device__ __host__ void preproc(const uint8_t * key,
    uint32_t * state, uint8_t var)
{
	int i;
	uint32_t W[16], temp;
	uint8_t ipad[64];

	for (i = 0; i < 64; i++)
		ipad[i] = var;

	for (i = 0; i < 16; i++)
		ipad[i] = ipad[i] ^ key[i];

#pragma unroll 16
	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], ipad, i * 4);
	
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

__device__ void hmac_sha1(const uint8_t * key, uint32_t keylen,
    const uint8_t * input, uint32_t inputlen, uint32_t * output,
    uint32_t * ipad_state, uint32_t * opad_state)
{
	int i;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;
	uint32_t state_A,state_B,state_C,state_D,state_E;
	uint8_t buf[64];
	uint32_t *src=(uint32_t*)buf;
	i=64/4;
	while(i--)
	  *src++=0;

	memcpy(buf, input, inputlen);
	buf[inputlen] = 0x80;
	PUT_WORD_32_BE((64 + inputlen) << 3, buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	
	state_A=A;
	state_B=B;
	state_C=C;
	state_D=D;
	state_E=E;

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += state_A;
	B += state_B;
	C += state_C;
	D += state_D;
	E += state_E;

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
	
	state_A=A;
	state_B=B;
	state_C=C;
	state_D=D;
	state_E=E;

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += state_A;
	B += state_B;
	C += state_C;
	D += state_D;
	E += state_E;

	output[0]=SWAP(A);
	output[1]=SWAP(B);
	output[2]=SWAP(C);
	output[3]=SWAP(D);
	output[4]=SWAP(E);
}


__device__ void big_hmac_sha1(
    uint32_t * input, uint32_t inputlen,
    uint32_t * ipad_state, uint32_t * opad_state,uint32_t *tmp_out)
{
	int i,lo;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;
#pragma unroll 5
	for(i=0;i<5;i++)
	  W[i]=SWAP(input[i]);
#pragma unroll 4
	for(i=0;i<4;i++)
	tmp_out[i]=SWAP(tmp_out[i]);
	
	for(lo=1; lo<ITERATIONS; lo++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];

		W[5]=0x80000000;
		W[15]=0x2A0;
		
		#pragma unroll 9
		for (i = 6; i < 15; i++) W[i]=0;

		SHA1(A, B, C, D, E, W);

		A += ipad_state[0];
		B += ipad_state[1];
		C += ipad_state[2];
		D += ipad_state[3];
		E += ipad_state[4];

		W[0]=A;
		W[1]=B;
		W[2]=C;
		W[3]=D;
		W[4]=E;
		W[5]=0x80000000;
		W[15]=0x2A0;
		
		#pragma unroll 9
		for(i=6;i<15;i++) W[i]=0;
		
  
		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];

		SHA1(A, B, C, D, E, W);

		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];

		W[0]=A;
		W[1]=B;
		W[2]=C;
		W[3]=D;
		W[4]=E;
	
		tmp_out[0]^=A;
		tmp_out[1]^=B;
		tmp_out[2]^=C;
		tmp_out[3]^=D;
	}

#pragma unroll 4
for(i=0;i<4;i++)
	tmp_out[i]=SWAP(tmp_out[i]);
}


__device__ void pbkdf2(const uint8_t * pass, const uint8_t * salt,
            int saltlen, uint8_t * out)
{
	uint8_t buf[48];
	uint32_t ipad_state[5];
	uint32_t opad_state[5];
	uint32_t tmp_out[5];
	int i=48/4;
	uint32_t *src=(uint32_t*)buf;
	while(i--)
		*src++=0;

	memcpy(buf, salt, saltlen);
	buf[saltlen + 3] = 0x01;

	preproc(pass, ipad_state, 0x36);
	preproc(pass, opad_state, 0x5c);

	hmac_sha1(pass, 16, buf, saltlen + 4, tmp_out, ipad_state, opad_state);

	big_hmac_sha1( tmp_out, SHA1_DIGEST_LENGTH, ipad_state,opad_state,tmp_out);

	memcpy(out, tmp_out, 16);
}



__global__ void pbkdf2_kernel(mscash2_password * inbuffer,
    mscash2_hash * outbuffer)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;

	uint32_t username_len = (uint32_t) cuda_salt[0].length;

	pbkdf2((uint8_t *) inbuffer[idx].dcc_hash,
	    cuda_salt[0].unicode_salt, username_len << 1,
	    (uint8_t *) outbuffer[idx].v);

}

__host__ void mscash_cpu(mscash2_password * inbuffer, mscash2_hash * outbuffer,
    mscash2_salt * host_salt)
    {
      
      int i,idx = 0;
	uint32_t buffer[16];
	uint32_t nt_hash[16];
	uint8_t salt[64];
	memset(salt,0,64);
	uint8_t *username = host_salt->salt;
	uint32_t username_len = (uint32_t) host_salt->length;
	//printf("username len=%d\n",username_len<<1);
	int r=0;
	if(username_len%2==1)
	    r=1;
	for (i = 0; i < (username_len >> 1) + r; i++)
		((uint32_t *) salt)[i] =
		    username[2 * i] | (username[2 * i + 1] << 16);
	memcpy(host_salt->unicode_salt, salt, 64);

	for (idx = 0; idx < KEYS_PER_CRYPT; idx++) {

		uint8_t *password = inbuffer[idx].v;
		uint32_t password_len = inbuffer[idx].length;
		memset(nt_hash, 0, 64);
		memset(buffer, 0, 64);

		for (i = 0; i < password_len >> 1; i++)
			buffer[i] =
			    password[2 * i] | (password[2 * i + 1] << 16);

		if (password_len % 2 == 1)
			buffer[i] = password[password_len - 1] | 0x800000;
		else
			buffer[i] = 0x80;

		buffer[14] = password_len << 4;
	//	printf("buffer[14]= %d\n",buffer[14]);
		md4_crypt(buffer, nt_hash);
       //printf("buffer = %08x \n",((unsigned int *)buffer)[0]);

		memcpy((uint8_t *) nt_hash + 16, salt, username_len << 1);

		i = username_len + 8;

		if (username_len % 2 == 1)
			nt_hash[i >> 1] =
			    username[username_len - 1] | 0x800000;
		else
			nt_hash[i >> 1] = 0x80;

		nt_hash[14] = i << 4;

		md4_crypt(nt_hash, inbuffer[idx].dcc_hash);

	}
    }

__host__ void mscash2_gpu(mscash2_password * inbuffer, mscash2_hash * outbuffer,
    mscash2_salt * host_salt)
{
	
	mscash_cpu(inbuffer,outbuffer,host_salt);
	mscash2_password *cuda_inbuffer;
	mscash2_hash *cuda_outbuffer;
	size_t insize = sizeof(mscash2_password) * KEYS_PER_CRYPT;
	size_t outsize = sizeof(mscash2_hash) * KEYS_PER_CRYPT;
	
	HANDLE_ERROR(cudaMemcpyToSymbol(cuda_salt, host_salt,
		sizeof(mscash2_salt)));
	
	HANDLE_ERROR(cudaMalloc(&cuda_inbuffer, insize));
	HANDLE_ERROR(cudaMalloc(&cuda_outbuffer, outsize));

	HANDLE_ERROR(cudaMemcpy(cuda_inbuffer, inbuffer, insize,
		cudaMemcpyHostToDevice));

	//int i;
	//printf("usename len=%d dcc:\n",host_salt[0].length << 1);
	//for(i=0;i<4;i++)
	// printf("%08x ",inbuffer[0].dcc_hash[i]);
	//puts("");
	//for(i=0;i<64;i++)
	//  printf("%d ",host_salt[0].unicode_salt[i]);

	pbkdf2_kernel <<< BLOCKS, THREADS >>> (cuda_inbuffer, cuda_outbuffer);

	HANDLE_ERROR(cudaMemcpy(outbuffer, cuda_outbuffer, outsize,
		cudaMemcpyDeviceToHost));

	HANDLE_ERROR(cudaFree(cuda_inbuffer));
	HANDLE_ERROR(cudaFree(cuda_outbuffer));

}
