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
	uchar salt[64];
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
	uchar buf[64] = { 0 };

	for (i = 0; i < saltlen; i++)
		buf[i] = salt[i];

	buf[saltlen + 3] = 0x1;
	buf[saltlen + 4] = 0x80;

	PUT_UINT32BE((uint) ((64 + saltlen + 4) << 3), buf, 60);

	for (i = 0; i < 16; i++)
		GET_UINT32BE(W[i], buf, i * 4);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	SHA256(A, B, C, D, E, F, G, H);

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

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];
	F += opad_state[5];
	G += opad_state[6];
	H += opad_state[7];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
	output[5] = F;
	output[6] = G;
	output[7] = H;
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
