/*
* This software is Copyright (c) 2012-2013
* Lukas Odzioba <ukasz at openwall.net> and Brian Wallace <brian.wallace9809 at gmail.com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include "opencl_device_info.h"
#include "opencl_misc.h"

#if HAVE_LUT3
#define Ch(x, y, z) lut3(x, y, z, 0xca)
#define Maj(x, y, z) lut3(x, y, z, 0xe8)
#elif USE_BITSELECT
#define Ch(x,y,z) bitselect(z, y, x)
#define Maj(x, y, z) bitselect(x, y, z ^ x)
#else
#if HAVE_ANDNOT
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#endif
#if 0 /* Wei Dai's trick, but we let the compiler cache/reuse or not */
#define Maj(x, y, z) (y ^ ((x ^ y) & (y ^ z)))
#elif 0
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#else
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#endif
#endif

#define ror(x,n) rotate(x, 32U-n)

#define Sigma0(x) ((ror(x, 2))  ^ (ror(x, 13)) ^ (ror(x, 22)))
#define Sigma1(x) ((ror(x, 6))  ^ (ror(x, 11)) ^ (ror(x, 25)))
#define sigma0(x) ((ror(x, 7))  ^ (ror(x, 18)) ^ (x >> 3))
#define sigma1(x) ((ror(x, 17)) ^ (ror(x, 19)) ^ (x >> 10))

#define R1(a, b, c, d, e, f, g, h, ac) \
		h += Sigma1(e) + Ch(e,f,g) + ac; \
		d += h;\
		h += Sigma0(a) + Maj(a,b,c);

#define R2() \
	w[0] += sigma1(w[14]) + w[9] + sigma0(w[1]); \
        w[1] += sigma1(w[15]) + w[10] + sigma0(w[2]); \
        w[2] += sigma1(w[0]) + w[11] + sigma0(w[3]); \
        w[3] += sigma1(w[1]) + w[12] + sigma0(w[4]); \
        w[4] += sigma1(w[2]) + w[13] + sigma0(w[5]); \
        w[5] += sigma1(w[3]) + w[14] + sigma0(w[6]); \
        w[6] += sigma1(w[4]) + w[15] + sigma0(w[7]); \
        w[7] += sigma1(w[5]) + w[0] + sigma0(w[8]); \
        w[8] += sigma1(w[6]) + w[1] + sigma0(w[9]); \
        w[9] += sigma1(w[7]) + w[2] + sigma0(w[10]); \
        w[10] += sigma1(w[8]) + w[3] + sigma0(w[11]); \
        w[11] += sigma1(w[9]) + w[4] + sigma0(w[12]); \
        w[12] += sigma1(w[10]) + w[5] + sigma0(w[13]); \
        w[13] += sigma1(w[11]) + w[6] + sigma0(w[14]); \
        w[14] += sigma1(w[12]) + w[7] + sigma0(w[15]); \
        w[15] += sigma1(w[13]) + w[8] + sigma0(w[0]);


typedef struct {
	uint32_t length;
	uint8_t v[87];
} pwsafe_pass;

typedef struct {
	uint32_t v[8];
	uint32_t iterations;
} pwsafe_state;

typedef struct {
	uint32_t cracked;
} pwsafe_hash;

typedef struct {
	int version;
	uint32_t iterations;
	uint8_t hash[32];
	uint8_t salt[32];
} pwsafe_salt;

inline void sha256_transform(uint32_t *w, uint32_t *state)
{
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];
	uint32_t e = state[4];
	uint32_t f = state[5];
	uint32_t g = state[6];
	uint32_t h = state[7];

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

	R2();

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

	R2();

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

	R2();

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

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

__kernel void pwsafe_init(__global const pwsafe_pass *in,
                          __global pwsafe_state *state,
                          __constant pwsafe_salt *salt)
{
	uint32_t idx = get_global_id(0);
	uint32_t pl = in[idx].length, i;
	uint32_t w[32] = {0};
	uint32_t tstate[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	if (pl < 24)
	{
		for (i = 0; i < pl; i++)
		{
			w[i / 4] |= (((uint32_t) in[idx].v[i]) << ((3 - (i & 0x3)) << 3));
		}
		for (; i < 32 + pl; i++)
		{
			w[i / 4] |= (((uint32_t) salt->salt[i - pl]) << ((3 - (i & 0x3)) << 3));
		}
		w[i / 4] |= (((uint32_t) 0x80) << ((3 - (i & 0x3)) << 3));
		w[15] = i * 8;
		sha256_transform(w, tstate);
	}
	else
	{
		for (i = 0; i < pl; i++)
		{
			w[i / 4] |= (((uint32_t) in[idx].v[i]) << ((3 - (i & 0x3)) << 3));
		}
		for (; i < 32 + pl; i++)
		{
			w[i / 4] |= (((uint32_t) salt->salt[i - pl]) << ((3 - (i & 0x3)) << 3));
		}
		w[i / 4] |= (((uint32_t) 0x80) << ((3 - (i & 0x3)) << 3));
		w[31] = i * 8;
		sha256_transform(w, tstate);
		sha256_transform(&w[16], tstate);
	}

	state[idx].v[0] = tstate[0];
	state[idx].v[1] = tstate[1];
	state[idx].v[2] = tstate[2];
	state[idx].v[3] = tstate[3];
	state[idx].v[4] = tstate[4];
	state[idx].v[5] = tstate[5];
	state[idx].v[6] = tstate[6];
	state[idx].v[7] = tstate[7];
	state[idx].iterations = salt->iterations + 1;
}

__kernel void pwsafe_iter(__global pwsafe_state *state)
{
	uint32_t idx = get_global_id(0);
	uint32_t i = MIN(state[idx].iterations, 258);
	state[idx].iterations -= i;
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t w[16];

	w[0] = state[idx].v[0];
	w[1] = state[idx].v[1];
	w[2] = state[idx].v[2];
	w[3] = state[idx].v[3];
	w[4] = state[idx].v[4];
	w[5] = state[idx].v[5];
	w[6] = state[idx].v[6];
	w[7] = state[idx].v[7];

	while (i > 0) {
		i--;
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

		R2();

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

		R2();

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

	state[idx].v[0] = w[0];
	state[idx].v[1] = w[1];
	state[idx].v[2] = w[2];
	state[idx].v[3] = w[3];
	state[idx].v[4] = w[4];
	state[idx].v[5] = w[5];
	state[idx].v[6] = w[6];
	state[idx].v[7] = w[7];
}

__kernel void pwsafe_check(__global pwsafe_state *state, __global pwsafe_hash *out,
                           __constant pwsafe_salt *salt)
{
	uint32_t idx = get_global_id(0);
	__global uint32_t *w = (__global uint32_t *)state[idx].v;
	uint32_t cmp = 0;
	__constant uint32_t *v = (__constant uint32_t *) salt->hash;

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
