/*
* This software is Copyright (c) 2012-2013
* Lukas Odzioba <ukasz at openwall.net> and Brian Wallace <brian.wallace9809 at gmail.com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "../cuda_pwsafe.h"
#include "cuda_common.cuh"

#define PWSAFE_IN_SIZE (KEYS_PER_GPU * sizeof(pwsafe_pass))
#define PWSAFE_OUT_SIZE (KEYS_PER_GPU * sizeof(pwsafe_hash))
#define PWSAFE_SALT_SIZE (sizeof(pwsafe_salt))

__global__ void kernel_pwsafe(pwsafe_pass * in, pwsafe_salt * salt,
    pwsafe_hash * out)
{
	uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint32_t pl = in[idx].length, i;

	uint32_t a = 0x6a09e667;
	uint32_t b = 0xbb67ae85;
	uint32_t c = 0x3c6ef372;
	uint32_t d = 0xa54ff53a;
	uint32_t e = 0x510e527f;
	uint32_t f = 0x9b05688c;
	uint32_t g = 0x1f83d9ab;
	uint32_t h = 0x5be0cd19;

	uint32_t w[16];
	for(i = 0; i < 16; i++) w[i] = 0;
	for(i = 0; i < pl; i++){
		uint32_t tmp;
		tmp = (((uint32_t) in[idx].v[i]) << ((3 - (i & 0x3)) << 3));
		w[i / 4] |= tmp;
	}
	for (; i < 32 + pl; i++) {
		uint32_t tmp;
		tmp = (((uint32_t) salt->salt[i - pl]) << ((3 - (i & 0x3)) << 3));
		w[i / 4] |= tmp;
	}
	w[i / 4] |= (((uint32_t) 0x80) << ((3 - (i & 0x3)) << 3));
	w[15] = 0x00000000 | (i * 8);

	R1(a, b, c, d, e, f, g, h, 0x428a2f98 + w[0]);
	R1(h, a, b, c, d, e, f, g, 0x71374491 + w[1]);
	R1(g, h, a, b, c, d, e, f, 0xb5c0fbcf + w[2]);
	R1(f, g, h, a, b, c, d, e, 0xe9b5dba5 + w[3]);
	R1(e, f, g, h, a, b, c, d, 0x3956c25b + w[4]);
	R1(d, e, f, g, h, a, b, c, 0x59f111f1 + w[5]);
	R1(c, d, e, f, g, h, a, b, 0x923f82a4 + w[6]);
	R1(b, c, d, e, f, g, h, a, 0xab1c5ed5 + w[7]);
	R1(a, b, c, d, e, f, g, h, 0xd807aa98 + w[8]);
	R1(h, a, b, c, d, e, f, g, 0x12835b01 + w[9]);
	R1(g, h, a, b, c, d, e, f, 0x243185be + w[10]);
	R1(f, g, h, a, b, c, d, e, 0x550c7dc3 + w[11]);
	R1(e, f, g, h, a, b, c, d, 0x72be5d74 + w[12]);
	R1(d, e, f, g, h, a, b, c, 0x80deb1fe + w[13]);
	R1(c, d, e, f, g, h, a, b, 0x9bdc06a7 + w[14]);
	R1(b, c, d, e, f, g, h, a, 0xc19bf174 + w[15]);

	w[0] += sigma1(w[14]) + w[9] + sigma0(w[1]);
	w[1] += sigma1(w[15]) + w[10] + sigma0(w[2]);
	w[2] += sigma1(w[0]) + w[11] + sigma0(w[3]);
	w[3] += sigma1(w[1]) + w[12] + sigma0(w[4]);
	w[4] += sigma1(w[2]) + w[13] + sigma0(w[5]);
	w[5] += sigma1(w[3]) + w[14] + sigma0(w[6]);
	w[6] += sigma1(w[4]) + w[15] + sigma0(w[7]);
	w[7] += sigma1(w[5]) + w[0] + sigma0(w[8]);
	w[8] += sigma1(w[6]) + w[1] + sigma0(w[9]);
	w[9] += sigma1(w[7]) + w[2] + sigma0(w[10]);
	w[10] += sigma1(w[8]) + w[3] + sigma0(w[11]);
	w[11] += sigma1(w[9]) + w[4] + sigma0(w[12]);
	w[12] += sigma1(w[10]) + w[5] + sigma0(w[13]);
	w[13] += sigma1(w[11]) + w[6] + sigma0(w[14]);
	w[14] += sigma1(w[12]) + w[7] + sigma0(w[15]);
	w[15] += sigma1(w[13]) + w[8] + sigma0(w[0]);

	R1(a, b, c, d, e, f, g, h, 0xe49b69c1 + w[0]);
	R1(h, a, b, c, d, e, f, g, 0xefbe4786 + w[1]);
	R1(g, h, a, b, c, d, e, f, 0x0fc19dc6 + w[2]);
	R1(f, g, h, a, b, c, d, e, 0x240ca1cc + w[3]);
	R1(e, f, g, h, a, b, c, d, 0x2de92c6f + w[4]);
	R1(d, e, f, g, h, a, b, c, 0x4a7484aa + w[5]);
	R1(c, d, e, f, g, h, a, b, 0x5cb0a9dc + w[6]);
	R1(b, c, d, e, f, g, h, a, 0x76f988da + w[7]);
	R1(a, b, c, d, e, f, g, h, 0x983e5152 + w[8]);
	R1(h, a, b, c, d, e, f, g, 0xa831c66d + w[9]);
	R1(g, h, a, b, c, d, e, f, 0xb00327c8 + w[10]);
	R1(f, g, h, a, b, c, d, e, 0xbf597fc7 + w[11]);
	R1(e, f, g, h, a, b, c, d, 0xc6e00bf3 + w[12]);
	R1(d, e, f, g, h, a, b, c, 0xd5a79147 + w[13]);
	R1(c, d, e, f, g, h, a, b, 0x06ca6351 + w[14]);
	R1(b, c, d, e, f, g, h, a, 0x14292967 + w[15]);

	w[0] += sigma1(w[14]) + w[9] + sigma0(w[1]);
	w[1] += sigma1(w[15]) + w[10] + sigma0(w[2]);
	w[2] += sigma1(w[0]) + w[11] + sigma0(w[3]);
	w[3] += sigma1(w[1]) + w[12] + sigma0(w[4]);
	w[4] += sigma1(w[2]) + w[13] + sigma0(w[5]);
	w[5] += sigma1(w[3]) + w[14] + sigma0(w[6]);
	w[6] += sigma1(w[4]) + w[15] + sigma0(w[7]);
	w[7] += sigma1(w[5]) + w[0] + sigma0(w[8]);
	w[8] += sigma1(w[6]) + w[1] + sigma0(w[9]);
	w[9] += sigma1(w[7]) + w[2] + sigma0(w[10]);
	w[10] += sigma1(w[8]) + w[3] + sigma0(w[11]);
	w[11] += sigma1(w[9]) + w[4] + sigma0(w[12]);
	w[12] += sigma1(w[10]) + w[5] + sigma0(w[13]);
	w[13] += sigma1(w[11]) + w[6] + sigma0(w[14]);
	w[14] += sigma1(w[12]) + w[7] + sigma0(w[15]);
	w[15] += sigma1(w[13]) + w[8] + sigma0(w[0]);

	R1(a, b, c, d, e, f, g, h, 0x27b70a85 + w[0]);
	R1(h, a, b, c, d, e, f, g, 0x2e1b2138 + w[1]);
	R1(g, h, a, b, c, d, e, f, 0x4d2c6dfc + w[2]);
	R1(f, g, h, a, b, c, d, e, 0x53380d13 + w[3]);
	R1(e, f, g, h, a, b, c, d, 0x650a7354 + w[4]);
	R1(d, e, f, g, h, a, b, c, 0x766a0abb + w[5]);
	R1(c, d, e, f, g, h, a, b, 0x81c2c92e + w[6]);
	R1(b, c, d, e, f, g, h, a, 0x92722c85 + w[7]);
	R1(a, b, c, d, e, f, g, h, 0xa2bfe8a1 + w[8]);
	R1(h, a, b, c, d, e, f, g, 0xa81a664b + w[9]);
	R1(g, h, a, b, c, d, e, f, 0xc24b8b70 + w[10]);
	R1(f, g, h, a, b, c, d, e, 0xc76c51a3 + w[11]);
	R1(e, f, g, h, a, b, c, d, 0xd192e819 + w[12]);
	R1(d, e, f, g, h, a, b, c, 0xd6990624 + w[13]);
	R1(c, d, e, f, g, h, a, b, 0xf40e3585 + w[14]);
	R1(b, c, d, e, f, g, h, a, 0x106aa070 + w[15]);

	w[0] += sigma1(w[14]) + w[9] + sigma0(w[1]);
	w[1] += sigma1(w[15]) + w[10] + sigma0(w[2]);
	w[2] += sigma1(w[0]) + w[11] + sigma0(w[3]);
	w[3] += sigma1(w[1]) + w[12] + sigma0(w[4]);
	w[4] += sigma1(w[2]) + w[13] + sigma0(w[5]);
	w[5] += sigma1(w[3]) + w[14] + sigma0(w[6]);
	w[6] += sigma1(w[4]) + w[15] + sigma0(w[7]);
	w[7] += sigma1(w[5]) + w[0] + sigma0(w[8]);
	w[8] += sigma1(w[6]) + w[1] + sigma0(w[9]);
	w[9] += sigma1(w[7]) + w[2] + sigma0(w[10]);
	w[10] += sigma1(w[8]) + w[3] + sigma0(w[11]);
	w[11] += sigma1(w[9]) + w[4] + sigma0(w[12]);
	w[12] += sigma1(w[10]) + w[5] + sigma0(w[13]);
	w[13] += sigma1(w[11]) + w[6] + sigma0(w[14]);
	w[14] += sigma1(w[12]) + w[7] + sigma0(w[15]);
	w[15] += sigma1(w[13]) + w[8] + sigma0(w[0]);

	R1(a, b, c, d, e, f, g, h, 0x19a4c116 + w[0]);
	R1(h, a, b, c, d, e, f, g, 0x1e376c08 + w[1]);
	R1(g, h, a, b, c, d, e, f, 0x2748774c + w[2]);
	R1(f, g, h, a, b, c, d, e, 0x34b0bcb5 + w[3]);
	R1(e, f, g, h, a, b, c, d, 0x391c0cb3 + w[4]);
	R1(d, e, f, g, h, a, b, c, 0x4ed8aa4a + w[5]);
	R1(c, d, e, f, g, h, a, b, 0x5b9cca4f + w[6]);
	R1(b, c, d, e, f, g, h, a, 0x682e6ff3 + w[7]);
	R1(a, b, c, d, e, f, g, h, 0x748f82ee + w[8]);
	R1(h, a, b, c, d, e, f, g, 0x78a5636f + w[9]);
	R1(g, h, a, b, c, d, e, f, 0x84c87814 + w[10]);
	R1(f, g, h, a, b, c, d, e, 0x8cc70208 + w[11]);
	R1(e, f, g, h, a, b, c, d, 0x90befffa + w[12]);
	R1(d, e, f, g, h, a, b, c, 0xa4506ceb + w[13]);
	R1(c, d, e, f, g, h, a, b, 0xbef9a3f7 + w[14]);
	R1(b, c, d, e, f, g, h, a, 0xc67178f2 + w[15]);

	w[0] = a + 0x6a09e667;
	w[1] = b + 0xbb67ae85;
	w[2] = c + 0x3c6ef372;
	w[3] = d + 0xa54ff53a;
	w[4] = e + 0x510e527f;
	w[5] = f + 0x9b05688c;
	w[6] = g + 0x1f83d9ab;
	w[7] = h + 0x5be0cd19;
	for (i = 0; i <= salt->iterations; i++) {
		a = 0x6a09e667;
		b = 0xbb67ae85;
		c = 0x3c6ef372;
		d = 0xa54ff53a;
		e = 0x510e527f;
		f = 0x9b05688c;
		g = 0x1f83d9ab;
		h = 0x5be0cd19;

		R1(a, b, c, d, e, f, g, h, 0x428a2f98 + w[0]);
		R1(h, a, b, c, d, e, f, g, 0x71374491 + w[1]);
		R1(g, h, a, b, c, d, e, f, 0xb5c0fbcf + w[2]);
		R1(f, g, h, a, b, c, d, e, 0xe9b5dba5 + w[3]);
		R1(e, f, g, h, a, b, c, d, 0x3956c25b + w[4]);
		R1(d, e, f, g, h, a, b, c, 0x59f111f1 + w[5]);
		R1(c, d, e, f, g, h, a, b, 0x923f82a4 + w[6]);
		R1(b, c, d, e, f, g, h, a, 0xab1c5ed5 + w[7]);
		R1(a, b, c, d, e, f, g, h, 0x5807aa98);
		R1(h, a, b, c, d, e, f, g, 0x12835b01);
		R1(g, h, a, b, c, d, e, f, 0x243185be);
		R1(f, g, h, a, b, c, d, e, 0x550c7dc3);
		R1(e, f, g, h, a, b, c, d, 0x72be5d74);
		R1(d, e, f, g, h, a, b, c, 0x80deb1fe);
		R1(c, d, e, f, g, h, a, b, 0x9bdc06a7);
		R1(b, c, d, e, f, g, h, a, 0xc19bf274);


		w[0] += sigma0( w[1] );
		R1(a, b, c, d, e, f, g, h, 0xe49b69c1 + w[0]);
		w[1] += 0x00a00000 + sigma0( w[2] );
		R1(h, a, b, c, d, e, f, g, 0xefbe4786 + w[1]);
		w[2] += sigma1(w[0]) + sigma0(w[3]);
		R1(g, h, a, b, c, d, e, f, 0x0fc19dc6 + w[2]);
		w[3] += sigma1(w[1]) + sigma0(w[4]);
		R1(f, g, h, a, b, c, d, e, 0x240ca1cc + w[3]);
		w[4] += sigma1( w[2] ) + sigma0( w[5] );
		R1(e, f, g, h, a, b, c, d, 0x2de92c6f + w[4]);
		w[5] += sigma1( w[3] ) + sigma0( w[6] );
		R1(d, e, f, g, h, a, b, c, 0x4a7484aa + w[5]);
		w[6] += sigma1( w[4] ) + 256 + sigma0( w[7] );
		R1(c, d, e, f, g, h, a, b, 0x5cb0a9dc + w[6]);
		w[7] += sigma1( w[5] ) + w[0] + 0x11002000;
		R1(b, c, d, e, f, g, h, a, 0x76f988da + w[7]);
		w[8] = 0x80000000 + sigma1(w[6]) + w[1];
		R1(a, b, c, d, e, f, g, h, 0x983e5152 + w[8]);
		w[9] = sigma1( w[7] ) + w[2];
		R1(h, a, b, c, d, e, f, g, 0xa831c66d + w[9]);
		w[10] = sigma1( w[8] ) + w[3];
		R1(g, h, a, b, c, d, e, f, 0xb00327c8 + w[10]);
		w[11] = sigma1( w[9] ) + w[4];
		R1(f, g, h, a, b, c, d, e, 0xbf597fc7 + w[11]);
		w[12] = sigma1( w[10] ) + w[5];
		R1(e, f, g, h, a, b, c, d, 0xc6e00bf3 + w[12]);
		w[13] = sigma1( w[11] ) + w[6];
		R1(d, e, f, g, h, a, b, c, 0xd5a79147 + w[13]);
		w[14] = sigma1( w[12] ) + w[7] + 0x00400022;
		R1(c, d, e, f, g, h, a, b, 0x06ca6351 + w[14]);
		w[15] = 256 + sigma1( w[13] ) + w[8] + sigma0( w[0] );
		R1(b, c, d, e, f, g, h, a, 0x14292967 + w[15]);

		w[0] += sigma1(w[14]) + w[9] + sigma0(w[1]);
		w[1] += sigma1(w[15]) + w[10] + sigma0(w[2]);
		w[2] += sigma1(w[0]) + w[11] + sigma0(w[3]);
		w[3] += sigma1(w[1]) + w[12] + sigma0(w[4]);
		w[4] += sigma1(w[2]) + w[13] + sigma0(w[5]);
		w[5] += sigma1(w[3]) + w[14] + sigma0(w[6]);
		w[6] += sigma1(w[4]) + w[15] + sigma0(w[7]);
		w[7] += sigma1(w[5]) + w[0] + sigma0(w[8]);
		w[8] += sigma1(w[6]) + w[1] + sigma0(w[9]);
		w[9] += sigma1(w[7]) + w[2] + sigma0(w[10]);
		w[10] += sigma1(w[8]) + w[3] + sigma0(w[11]);
		w[11] += sigma1(w[9]) + w[4] + sigma0(w[12]);
		w[12] += sigma1(w[10]) + w[5] + sigma0(w[13]);
		w[13] += sigma1(w[11]) + w[6] + sigma0(w[14]);
		w[14] += sigma1(w[12]) + w[7] + sigma0(w[15]);
		w[15] += sigma1(w[13]) + w[8] + sigma0(w[0]);

		R1(a, b, c, d, e, f, g, h, 0x27b70a85 + w[0]);
		R1(h, a, b, c, d, e, f, g, 0x2e1b2138 + w[1]);
		R1(g, h, a, b, c, d, e, f, 0x4d2c6dfc + w[2]);
		R1(f, g, h, a, b, c, d, e, 0x53380d13 + w[3]);
		R1(e, f, g, h, a, b, c, d, 0x650a7354 + w[4]);
		R1(d, e, f, g, h, a, b, c, 0x766a0abb + w[5]);
		R1(c, d, e, f, g, h, a, b, 0x81c2c92e + w[6]);
		R1(b, c, d, e, f, g, h, a, 0x92722c85 + w[7]);
		R1(a, b, c, d, e, f, g, h, 0xa2bfe8a1 + w[8]);
		R1(h, a, b, c, d, e, f, g, 0xa81a664b + w[9]);
		R1(g, h, a, b, c, d, e, f, 0xc24b8b70 + w[10]);
		R1(f, g, h, a, b, c, d, e, 0xc76c51a3 + w[11]);
		R1(e, f, g, h, a, b, c, d, 0xd192e819 + w[12]);
		R1(d, e, f, g, h, a, b, c, 0xd6990624 + w[13]);
		R1(c, d, e, f, g, h, a, b, 0xf40e3585 + w[14]);
		R1(b, c, d, e, f, g, h, a, 0x106aa070 + w[15]);

		w[0] += sigma1(w[14]) + w[9] + sigma0(w[1]);
		w[1] += sigma1(w[15]) + w[10] + sigma0(w[2]);
		w[2] += sigma1(w[0]) + w[11] + sigma0(w[3]);
		w[3] += sigma1(w[1]) + w[12] + sigma0(w[4]);
		w[4] += sigma1(w[2]) + w[13] + sigma0(w[5]);
		w[5] += sigma1(w[3]) + w[14] + sigma0(w[6]);
		w[6] += sigma1(w[4]) + w[15] + sigma0(w[7]);
		w[7] += sigma1(w[5]) + w[0] + sigma0(w[8]);
		w[8] += sigma1(w[6]) + w[1] + sigma0(w[9]);
		w[9] += sigma1(w[7]) + w[2] + sigma0(w[10]);
		w[10] += sigma1(w[8]) + w[3] + sigma0(w[11]);
		w[11] += sigma1(w[9]) + w[4] + sigma0(w[12]);
		w[12] += sigma1(w[10]) + w[5] + sigma0(w[13]);
		w[13] += sigma1(w[11]) + w[6] + sigma0(w[14]);
		w[14] += sigma1(w[12]) + w[7] + sigma0(w[15]);
		w[15] += sigma1(w[13]) + w[8] + sigma0(w[0]);

		R1(a, b, c, d, e, f, g, h, 0x19a4c116 + w[0]);
		R1(h, a, b, c, d, e, f, g, 0x1e376c08 + w[1]);
		R1(g, h, a, b, c, d, e, f, 0x2748774c + w[2]);
		R1(f, g, h, a, b, c, d, e, 0x34b0bcb5 + w[3]);
		R1(e, f, g, h, a, b, c, d, 0x391c0cb3 + w[4]);
		R1(d, e, f, g, h, a, b, c, 0x4ed8aa4a + w[5]);
		R1(c, d, e, f, g, h, a, b, 0x5b9cca4f + w[6]);
		R1(b, c, d, e, f, g, h, a, 0x682e6ff3 + w[7]);
		R1(a, b, c, d, e, f, g, h, 0x748f82ee + w[8]);
		R1(h, a, b, c, d, e, f, g, 0x78a5636f + w[9]);
		R1(g, h, a, b, c, d, e, f, 0x84c87814 + w[10]);
		R1(f, g, h, a, b, c, d, e, 0x8cc70208 + w[11]);
		R1(e, f, g, h, a, b, c, d, 0x90befffa + w[12]);
		R1(d, e, f, g, h, a, b, c, 0xa4506ceb + w[13]);
		R1(c, d, e, f, g, h, a, b, 0xbef9a3f7 + w[14]);
		R1(b, c, d, e, f, g, h, a, 0xc67178f2 + w[15]);

		w[0] = 0x6a09e667 + a;
		w[1] = 0xbb67ae85 + b;
		w[2] = 0x3c6ef372 + c;
		w[3] = 0xa54ff53a + d;
		w[4] = 0x510e527f + e;
		w[5] = 0x9b05688c + f;
		w[6] = 0x1f83d9ab + g;
		w[7] = 0x5be0cd19 + h;
	}

	uint32_t cmp = 0;
	uint32_t *v = (uint32_t *) salt->hash;
	if (*v++ == w[0]) {
		uint32_t diff;
		diff = *v++ ^ (w[1]);
		diff |= *v++ ^ (w[2]);
		diff |= *v++ ^ (w[3]);
		diff |= *v++ ^ (w[4]);
		diff |= *v++ ^ (w[5]);
		diff |= *v++ ^ (w[6]);
		diff |= *v++ ^ (w[7]);
		cmp = !diff;
	}
	out[idx].cracked = cmp;
}

extern "C" void gpu_pwpass(pwsafe_pass * host_in, pwsafe_salt * host_salt,
                           pwsafe_hash * host_out, int count)
{
#if GPUS == 1
	pwsafe_pass *cuda_pass = NULL;  ///passwords
	pwsafe_salt *cuda_salt = NULL;  ///salt
	pwsafe_hash *cuda_hash = NULL;  ///hashes
	int blocks = (count + THREADS * GPUS - 1) / (THREADS * GPUS);

        ///Aloc memory and copy data to gpu
        cudaMalloc(&cuda_pass, PWSAFE_IN_SIZE);
        cudaMalloc(&cuda_salt, PWSAFE_SALT_SIZE);
        cudaMalloc(&cuda_hash, PWSAFE_OUT_SIZE);
	///Somehow this memset, which is not required, speeds things up a bit
	cudaMemset(cuda_hash, 0, PWSAFE_OUT_SIZE);
        cudaMemcpy(cuda_pass, host_in, PWSAFE_IN_SIZE, cudaMemcpyHostToDevice);
        cudaMemcpy(cuda_salt, host_salt, PWSAFE_SALT_SIZE,
            cudaMemcpyHostToDevice);

        ///Run kernel and wait for execution end
        kernel_pwsafe <<< blocks, THREADS >>> (cuda_pass, cuda_salt,
            cuda_hash);
        cudaThreadSynchronize();
	HANDLE_ERROR(cudaGetLastError());

        ///Free memory and copy results back
        cudaMemcpy(host_out, cuda_hash, PWSAFE_OUT_SIZE,
            cudaMemcpyDeviceToHost);
        cudaFree(cuda_pass);
        cudaFree(cuda_salt);
        cudaFree(cuda_hash);
#else
	unsigned int gpu = 0;
	int blocks = (count + THREADS * GPUS - 1) / (THREADS * GPUS);
	//int runtimeVersion=0;
	//cudaRuntimeGetVersion(&runtimeVersion);
	//printf("Cuda runtime: %d.%d\n",runtimeVersion/1000,(runtimeVersion%100)/10);


	//unsigned int TB=THREADS*BLOCKS;
        pwsafe_pass *cuda_pass[GPUS];  ///passwords
        pwsafe_salt *cuda_salt[GPUS];  ///salt
        pwsafe_hash *cuda_hash[GPUS];  ///hashes

        //puts("stage 0");
        ///Aloc memory and copy data to gpus
	for(gpu=0;gpu<GPUS;gpu++){
		HANDLE_ERROR(cudaSetDevice(gpu));
		HANDLE_ERROR(cudaMalloc(&cuda_pass[gpu], PWSAFE_IN_SIZE));
		HANDLE_ERROR(cudaMalloc(&cuda_salt[gpu], PWSAFE_SALT_SIZE));
		HANDLE_ERROR(cudaMalloc(&cuda_hash[gpu], PWSAFE_OUT_SIZE));

		///Somehow this memset, which is not required, speeds things up a bit
		HANDLE_ERROR(cudaMemset(cuda_hash[gpu], 0, PWSAFE_OUT_SIZE));
		HANDLE_ERROR(cudaMemcpy(cuda_pass[gpu], host_in+gpu*KEYS_PER_GPU, PWSAFE_IN_SIZE, cudaMemcpyHostToDevice));
		HANDLE_ERROR(cudaMemcpy(cuda_salt[gpu], host_salt, PWSAFE_SALT_SIZE,
			cudaMemcpyHostToDevice));
	}
	//puts("stage 1");
	for(gpu=0;gpu<GPUS;gpu++){
		HANDLE_ERROR(cudaSetDevice(gpu));
		//printf("gpu=%d\n",gpu);
		///Run kernel and wait for execution end
		pwsafe_pass *current_pass=cuda_pass[gpu];
		pwsafe_salt *current_salt=cuda_salt[gpu];
		pwsafe_hash *current_hash=cuda_hash[gpu];

		kernel_pwsafe <<< blocks, THREADS >>> (current_pass, current_salt,
			current_hash);

		//cudaThreadSynchronize();
		HANDLE_ERROR(cudaGetLastError());
	}
	//puts("stage 2");
	for(gpu=0;gpu<GPUS;gpu++){
		HANDLE_ERROR(cudaSetDevice(gpu));
		///Free memory and copy results back
		HANDLE_ERROR(cudaMemcpy(host_out+KEYS_PER_GPU*gpu, cuda_hash[gpu], 				PWSAFE_OUT_SIZE,cudaMemcpyDeviceToHost));
		HANDLE_ERROR(cudaFree(cuda_pass[gpu]));
		HANDLE_ERROR(cudaFree(cuda_salt[gpu]));
		HANDLE_ERROR(cudaFree(cuda_hash[gpu]));
	}
	//puts("stage 3");
#endif
}
