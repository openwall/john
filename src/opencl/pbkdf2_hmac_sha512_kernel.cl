/*
 * This software is
 * Copyright (c) 2012, 2013 Lukas Odzioba <ukasz at openwall dot net>
 * copyright 2014, JimF
 * and Copyright 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"

typedef struct {
	ulong v[(PLAINTEXT_LENGTH + 7) / 8];
	ulong length;
} pass_t;

typedef struct {
	ulong hash[8];
} crack_t;

typedef struct {
	ulong salt[(107 + 1 + 4 + 7) / 8];
	uint length;
	uint rounds;
} salt_t;

typedef struct {
	ulong ipad[8];
	ulong opad[8];
	ulong hash[8];
	ulong W[8];
	uint rounds;
} state_t;

inline void _phs512_preproc(__global const ulong *key, uint keylen,
                            ulong *state, ulong mask)
{
	uint i, j;
	ulong W[16];
	ulong A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	j = ((keylen+7)/8);
	for (i = 0; i < j; i++)
		W[i] = mask ^ SWAP64(key[i]);

	for (; i < 16; i++)
		W[i] = mask;

	SHA512(A, B, C, D, E, F, G, H, W);

	state[0] = A + SHA2_INIT_A;
	state[1] = B + SHA2_INIT_B;
	state[2] = C + SHA2_INIT_C;
	state[3] = D + SHA2_INIT_D;
	state[4] = E + SHA2_INIT_E;
	state[5] = F + SHA2_INIT_F;
	state[6] = G + SHA2_INIT_G;
	state[7] = H + SHA2_INIT_H;
}

inline void _phs512_hmac(ulong *output, ulong *ipad_state, ulong *opad_state,
                         __constant ulong *salt, uint saltlen)
{
	uint i, j;
	ulong W[16] = { 0 };
	ulong A, B, C, D, E, F, G, H, t;

	j = ((saltlen + 7) / 8);
	for (i = 0; i < j; i++)
		W[i] = SWAP64(salt[i]);

	// saltlen contains the \0\0\0\1 and 0x80 byte.  The 0001 are part
	// of the salt length. the 0x80 is not, but is the end of hash
	// marker.  So we set legth to be 127+saltlen and not 128+saltlen.
	// 127+saltlen is correct, it just looks funny.
	W[15] = ((127 + saltlen) << 3);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	SHA512(A, B, C, D, E, F, G, H, W);

	W[0] = A + ipad_state[0];
	W[1] = B + ipad_state[1];
	W[2] = C + ipad_state[2];
	W[3] = D + ipad_state[3];
	W[4] = E + ipad_state[4];
	W[5] = F + ipad_state[5];
	W[6] = G + ipad_state[6];
	W[7] = H + ipad_state[7];
	W[8] = 0x8000000000000000UL;
	W[15] = 0x600;
	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];
	F = opad_state[5];
	G = opad_state[6];
	H = opad_state[7];

	SHA512_ZEROS(A, B, C, D, E, F, G, H, W);

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

__kernel void pbkdf2_sha512_loop(__global state_t *state,
                                 __global crack_t *out)
{
	uint idx = get_global_id(0);
	uint i, rounds = state[idx].rounds;
	uint r = MIN(rounds, HASH_LOOPS);
	ulong W[16];
	ulong ipad_state[8];
	ulong opad_state[8];
	ulong tmp_out[8];

	for (i = 0; i < 8; i++) {
		W[i] = state[idx].W[i];
		ipad_state[i] = state[idx].ipad[i];
		opad_state[i] = state[idx].opad[i];
		tmp_out[i] = state[idx].hash[i];
	}

	for (i = 0; i < r; i++) {
		ulong A, B, C, D, E, F, G, H, t;

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];
		F = ipad_state[5];
		G = ipad_state[6];
		H = ipad_state[7];

		W[8] = 0x8000000000000000UL;
		W[15] = 0x600;

		SHA512_ZEROS(A, B, C, D, E, F, G, H, W);

		W[0] = A + ipad_state[0];
		W[1] = B + ipad_state[1];
		W[2] = C + ipad_state[2];
		W[3] = D + ipad_state[3];
		W[4] = E + ipad_state[4];
		W[5] = F + ipad_state[5];
		W[6] = G + ipad_state[6];
		W[7] = H + ipad_state[7];
		W[8] = 0x8000000000000000UL;
		W[15] = 0x600;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];
		F = opad_state[5];
		G = opad_state[6];
		H = opad_state[7];

		SHA512_ZEROS(A, B, C, D, E, F, G, H, W);

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
			out[idx].hash[i] = tmp_out[i];
	}
}

__kernel void pbkdf2_sha512_kernel(__global const pass_t *inbuffer,
                                   __constant salt_t *gsalt,
                                   __global state_t *state)
{
	ulong ipad_state[8];
	ulong opad_state[8];
	ulong tmp_out[8];
	uint  i;
	uint idx = get_global_id(0);
	__global const ulong *pass = inbuffer[idx].v;
	__constant ulong *salt = gsalt->salt;
	uint passlen = inbuffer[idx].length;
	uint saltlen = gsalt->length;

	state[idx].rounds = gsalt->rounds - 1;

	_phs512_preproc(pass, passlen, ipad_state, 0x3636363636363636UL);
	_phs512_preproc(pass, passlen, opad_state, 0x5c5c5c5c5c5c5c5cUL);

	_phs512_hmac(tmp_out, ipad_state, opad_state, salt, saltlen);

	for (i = 0; i < 8; i++) {
		state[idx].ipad[i] = ipad_state[i];
		state[idx].opad[i] = opad_state[i];
		state[idx].hash[i] = tmp_out[i];
		state[idx].W[i] = tmp_out[i];
	}
}
