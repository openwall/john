/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"

typedef struct {
	uchar length;
	uchar v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint hash[8]; /** 256 bits **/
} crack_t;

typedef struct {
	uchar length;
	uchar salt[115];
	uint rounds;
} salt_t;

typedef struct {
	uint ipad[8];
	uint opad[8];
	uint hash[8];
	uint W[8];
	uint rounds;
} state_t;

inline void preproc(__global const uchar * key, uint keylen,
                    uint * state, uint padding)
{
	uint j, t;
	uint W[16];
	uint A = h[0];
	uint B = h[1];
	uint C = h[2];
	uint D = h[3];
	uint E = h[4];
	uint F = h[5];
	uint G = h[6];
	uint H = h[7];

	for (j = 0; j < 16; j++)
		W[j] = padding;

	for (j = 0; j < keylen; j++)
		XORCHAR_BE(W, j, key[j]);

	SHA256(A, B, C, D, E, F, G, H);

	state[0] = A + h[0];
	state[1] = B + h[1];
	state[2] = C + h[2];
	state[3] = D + h[3];
	state[4] = E + h[4];
	state[5] = F + h[5];
	state[6] = G + h[6];
	state[7] = H + h[7];
}


inline void hmac_sha256(uint * output, uint * ipad_state,
                        uint * opad_state, __global const uchar * salt,
                        uint saltlen)
{
	uint i, t;
	uint W[16];
	uint A, B, C, D, E, F, G, H;

// Not sure if either 'method' (i.e. a buf[128]={0} or simply dropping right into W[] array)
// is better than the other, so both have been left in the kernel for now.  Once we know
// one is better, or easier to follow, then we can drop the other.
//
//	uchar buf[128] = { 0 };
//
//	for (i = 0; i < saltlen; i++)
//		buf[i] = salt[i];
//
//	buf[saltlen + 3] = 0x1;
//	buf[saltlen + 4] = 0x80;
//
//	A = ipad_state[0];
//	B = ipad_state[1];
//	C = ipad_state[2];
//	D = ipad_state[3];
//	E = ipad_state[4];
//	F = ipad_state[5];
//	G = ipad_state[6];
//	H = ipad_state[7];
//
//	for (i = 0; i < 15; i++)
//		GET_UINT32BE(W[i], buf, i * 4);
//	if (saltlen < 52) {
//		PUT_UINT32BE((uint) ((64 + saltlen + 4) << 3), buf, 60);
//		GET_UINT32BE(W[15], buf, 60);
//		SHA256(A, B, C, D, E, F, G, H);
//		W[0] = A + ipad_state[0];
//		W[1] = B + ipad_state[1];
//		W[2] = C + ipad_state[2];
//		W[3] = D + ipad_state[3];
//		W[4] = E + ipad_state[4];
//		W[5] = F + ipad_state[5];
//		W[6] = G + ipad_state[6];
//		W[7] = H + ipad_state[7];
//	} else {
//		uint a, b, c, d, e, f, g, h;
//		GET_UINT32BE(W[15], buf, 60);
//		SHA256(A, B, C, D, E, F, G, H);
//		PUT_UINT32BE((uint) ((64 + saltlen + 4) << 3), buf, 60+64);
//		for (i = 0; i < 16; i++)
//			GET_UINT32BE(W[i], buf, 64 + i * 4);
//		a = (A += ipad_state[0]);
//		b = (B += ipad_state[1]);
//		c = (C += ipad_state[2]);
//		d = (D += ipad_state[3]);
//		e = (E += ipad_state[4]);
//		f = (F += ipad_state[5]);
//		g = (G += ipad_state[6]);
//		h = (H += ipad_state[7]);
//		SHA256(A, B, C, D, E, F, G, H);
//		W[0] = A + a;
//		W[1] = B + b;
//		W[2] = C + c;
//		W[3] = D + d;
//		W[4] = E + e;
//		W[5] = F + f;
//		W[6] = G + g;
//		W[7] = H + h;
//	}

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	for (i = 0; i < 15; i++)
		W[i] = 0;
	if (saltlen < 52) {
		// only needs 1 limb
		for (i = 0; i < saltlen; i++)
			PUTCHAR_BE(W, i, salt[i]);
		PUTCHAR_BE(W, saltlen + 3, 1);
		PUTCHAR_BE(W, saltlen + 4, 0x80);
		W[15] = (64 + saltlen + 4) << 3;
		SHA256(A, B, C, D, E, F, G, H);
		W[0] = A + ipad_state[0];
		W[1] = B + ipad_state[1];
		W[2] = C + ipad_state[2];
		W[3] = D + ipad_state[3];
		W[4] = E + ipad_state[4];
		W[5] = F + ipad_state[5];
		W[6] = G + ipad_state[6];
		W[7] = H + ipad_state[7];
	} else {
		// handles 2 limbs of salt and loop-count (up to 115 byte salt)
		uint a, b, c, d, e, f, g; // we use i for h
		W[15] = 0;	// first buffer will NOT get length, so zero it out also.
		for (i = 0; i < saltlen && i < 64; i++)
			PUTCHAR_BE(W, i, salt[i]);
		// i MUST be preserved.  It if our count of # of salt bytes consumed.
		a = i;
		if (saltlen < 61)
			PUTCHAR_BE(W, saltlen + 3, 1);
		if (saltlen < 60)
			PUTCHAR_BE(W, saltlen + 4, 0x80);
		SHA256(A, B, C, D, E, F, G, H);

		// now build and process 2nd limb
		for (i = 0; i < 15; i++)  // do not fuk with i!
			W[i] = 0;
		for (i = a; i < saltlen; i++)
			PUTCHAR_BE(W, i - 64, salt[i]);
		if (saltlen >= 61)
			PUTCHAR_BE(W, saltlen + 3 - 64, 1);
		if (saltlen >= 60)
			PUTCHAR_BE(W, saltlen + 4 - 64, 0x80);
		W[15] = (64 + saltlen + 4) << 3;
		{
			a = (A += ipad_state[0]);
			b = (B += ipad_state[1]);
			c = (C += ipad_state[2]);
			d = (D += ipad_state[3]);
			e = (E += ipad_state[4]);
			f = (F += ipad_state[5]);
			g = (G += ipad_state[6]);
			i = (H += ipad_state[7]);
			SHA256(A, B, C, D, E, F, G, H);
			W[0] = A + a;
			W[1] = B + b;
			W[2] = C + c;
			W[3] = D + d;
			W[4] = E + e;
			W[5] = F + f;
			W[6] = G + g;
			W[7] = H + i;
		}
	}

	W[8] = 0x80000000;
	W[15] = 0x300;

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];
	F = opad_state[5];
	G = opad_state[6];
	H = opad_state[7];

	SHA256_ZEROS(A, B, C, D, E, F, G, H);

	output[0] = A + opad_state[0];
	output[1] = B + opad_state[1];
	output[2] = C + opad_state[2];
	output[3] = D + opad_state[3];
	output[4] = E + opad_state[4];
	output[5] = F + opad_state[5];
	output[6] = G + opad_state[6];
	output[7] = H + opad_state[7];
}

__kernel void pbkdf2_sha256_loop(__global state_t *state,
                                 __global crack_t *out)
{
	uint idx = get_global_id(0);
	uint i, round, rounds = state[idx].rounds;
	uint W[16];
	uint ipad_state[8];
	uint opad_state[8];
	uint tmp_out[8];

	for (i = 0; i < 8; i++) {
		W[i] = state[idx].W[i];
		ipad_state[i] = state[idx].ipad[i];
		opad_state[i] = state[idx].opad[i];
		tmp_out[i] = state[idx].hash[i];
	}

	for (round = 0; round < MIN(rounds,HASH_LOOPS); round++) {
		uint A, B, C, D, E, F, G, H, t;

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];
		F = ipad_state[5];
		G = ipad_state[6];
		H = ipad_state[7];

		W[8] = 0x80000000;
		W[15] = 0x300;

		SHA256_ZEROS(A, B, C, D, E, F, G, H);

		W[0] = A + ipad_state[0];
		W[1] = B + ipad_state[1];
		W[2] = C + ipad_state[2];
		W[3] = D + ipad_state[3];
		W[4] = E + ipad_state[4];
		W[5] = F + ipad_state[5];
		W[6] = G + ipad_state[6];
		W[7] = H + ipad_state[7];
		W[8] = 0x80000000;
		W[15] = 0x300;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];
		F = opad_state[5];
		G = opad_state[6];
		H = opad_state[7];

		SHA256_ZEROS(A, B, C, D, E, F, G, H);

		W[0] = A += opad_state[0];
		W[1] = B += opad_state[1];
		W[2] = C += opad_state[2];
		W[3] = D += opad_state[3];
		W[4] = E += opad_state[4];
		W[5] = F += opad_state[5];
		W[6] = G += opad_state[6];
		W[7] = H += opad_state[7];

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
		tmp_out[5] ^= F;
		tmp_out[6] ^= G;
		tmp_out[7] ^= H;
	}

	if (rounds >= HASH_LOOPS) { // there is still work to do
		state[idx].rounds = rounds - HASH_LOOPS;
		for (i = 0; i < 8; i++) {
			state[idx].hash[i] = tmp_out[i];
			state[idx].W[i] = W[i];
		}
	}
	else { // rounds == 0 - we're done
		for (i = 0; i < 8; i++)
			out[idx].hash[i] = SWAP32(tmp_out[i]);
	}
}

__kernel void pbkdf2_sha256_kernel(__global const pass_t * inbuffer,
                                   __global const salt_t * gsalt,
                                   __global state_t * state)
{

	uint ipad_state[8];
	uint opad_state[8];
	uint tmp_out[8];
	uint i, idx = get_global_id(0);

	__global const uchar *pass = inbuffer[idx].v;
	__global const uchar *salt = gsalt->salt;
	uint passlen = inbuffer[idx].length;
	uint saltlen = gsalt->length;

	state[idx].rounds = gsalt->rounds - 1;

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	hmac_sha256(tmp_out, ipad_state, opad_state, salt, saltlen);

	for(i = 0; i < 8; i++) {
		state[idx].ipad[i] = ipad_state[i];
		state[idx].opad[i] = opad_state[i];
		state[idx].hash[i] = tmp_out[i];
		state[idx].W[i] = tmp_out[i];
	}
}
