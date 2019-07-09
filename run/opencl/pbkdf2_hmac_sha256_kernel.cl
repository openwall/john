/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright 2014 - 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Now unlimited salt length. (Dec 2017, JimF)
 *
 * skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 32). So to calculate only
 * byte 33-64 (second chunk) you can say "outlen=32 skip_bytes=32"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 32 as opposed to 64.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"
#include "opencl_pbkdf2_hmac_sha256.h"

#ifdef GLOBAL_SALT_NO_INIT
#define SALT_TYPE __global const
#else
#define SALT_TYPE MAYBE_CONSTANT
#endif

inline void _phsk_preproc(__global const uchar *key, uint keylen,
                          __global uint *state, uint padding)
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

	SHA256(A, B, C, D, E, F, G, H, W);

	state[0] = A + h[0];
	state[1] = B + h[1];
	state[2] = C + h[2];
	state[3] = D + h[3];
	state[4] = E + h[4];
	state[5] = F + h[5];
	state[6] = G + h[6];
	state[7] = H + h[7];
}


inline void _phsk_hmac_sha256(__global uint *output, __global uint *ipad_state,
                              __global uint *opad_state, SALT_TYPE uchar *salt,
                              uint saltlen, uchar add)
{
	uint i, j, last;
	uint W[16], ctx[8];

	// Code now handles ANY length salt!
	// switched to use sha256_block ctx model
	for (j = 0; j < 8; j++)
		ctx[j] = ipad_state[j];

	i = 0;
	last = saltlen;	// this the count of bytes of salt put into the final buffer.
	while (i+64 <= saltlen) {
		// no need to clean. We are using the entire 64 bytes with this block of salt
		for (j = 0; j < 64; ++j, ++i)
			PUTCHAR_BE(W, j, salt[i]);
		last -= 64;
		sha256_block(W, ctx);
	}
	//
	// ok, either this is the last limb, OR we have this one, and have to make 1 more.
	//
	// Fully blank out the buffer (dont skip element 15 len 61-63 wont clean buffer)
	for (j = 0; j < 16; j++)
		W[j] = 0;

	// assertion [i <= saltlen < (i+64)], so all remaining salt (if any) fits in this block
	for (j = 0; i < saltlen; ++j, ++i)
		PUTCHAR_BE(W, j, salt[i]);

	if (last <= 51) {
		// this is last limb, everything fits
		PUTCHAR_BE(W, last + 3, add);
		PUTCHAR_BE(W, last + 4, 0x80);
		W[15] = (64 + saltlen + 4) << 3;
	} else {
		// do the last limb with salt data, then 1 more buffer, since this one
		// the salt + add number did NOT fit into this buffer.
		if (last < 61)
			PUTCHAR_BE(W, last + 3, 1);	// should be add to allow more than 32 bytes to be returned!
		if (last < 60)
			PUTCHAR_BE(W, last + 4, 0x80);
		sha256_block(W, ctx);
		// Final limb (no salt data put into this one)
		for (j = 0; j < 15; j++)
			W[j] = 0;
		if (last >= 61)
			PUTCHAR_BE(W, last + 3 - 64, 1);	// should be add to allow more than 32 bytes to be returned!
		if (last >= 60)
			PUTCHAR_BE(W, last + 4 - 64, 0x80);
		W[15] = (64 + saltlen + 4) << 3;
	}
	// this is sha256_final for our salt.add-word.
	sha256_block(W, ctx);
	for (j = 0; j < 8; j++)
		W[j] = ctx[j];
	W[8] = 0x80000000;
	W[15] = 0x300;

	for (j = 0; j < 8; j++)
		ctx[j] = opad_state[j];
	sha256_block_zeros(W, ctx);

	for (j = 0; j < 8; j++)
		output[j] = ctx[j];
}

__kernel void pbkdf2_sha256_loop(__global state_t *state)
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

		SHA256_ZEROS(A, B, C, D, E, F, G, H, W);

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

		SHA256_ZEROS(A, B, C, D, E, F, G, H, W);

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

	state[idx].rounds = rounds - HASH_LOOPS;
	for (i = 0; i < 8; i++) {
		state[idx].hash[i] = tmp_out[i];
		state[idx].W[i] = W[i];
	}
}

#ifndef GLOBAL_SALT_NO_INIT
__kernel void pbkdf2_sha256_init(__global const pass_t *inbuffer,
                                 MAYBE_CONSTANT salt_t *salt,
                                 __global state_t *state)
{
	uint i, idx = get_global_id(0);
	uint pass = salt->skip_bytes / 32;

	state[idx].rounds = salt->rounds - 1;

	_phsk_preproc(inbuffer[idx].v, inbuffer[idx].length,
	              state[idx].ipad, 0x36363636);
	_phsk_preproc(inbuffer[idx].v, inbuffer[idx].length,
	              state[idx].opad, 0x5c5c5c5c);

	_phsk_hmac_sha256(state[idx].hash, state[idx].ipad, state[idx].opad,
	                  salt->salt, salt->length, pass + 1);

	for (i = 0; i < 8; i++)
		state[idx].W[i] = state[idx].hash[i];

	state[idx].pass = pass;
}
#endif

__kernel void pbkdf2_sha256_final(__global crack_t *out,
                                  MAYBE_CONSTANT salt_t *salt,
                                  __global state_t *state)
{
	uint idx = get_global_id(0);

#ifdef RAR5
	out[idx].hash[0] = SWAP32(state[idx].hash[0]);
	out[idx].hash[1] = SWAP32(state[idx].hash[1]);
	out[idx].hash[0] ^= SWAP32(state[idx].hash[2]);
	out[idx].hash[1] ^= SWAP32(state[idx].hash[3]);
	out[idx].hash[0] ^= SWAP32(state[idx].hash[4]);
	out[idx].hash[1] ^= SWAP32(state[idx].hash[5]);
	out[idx].hash[0] ^= SWAP32(state[idx].hash[6]);
	out[idx].hash[1] ^= SWAP32(state[idx].hash[7]);
#else
	uint i;
	uint base = (state[idx].pass - salt->skip_bytes / 32) * 8;

	// First/next 32 bytes of output
	for (i = 0; i < 8; i++)
		out[idx].hash[base + i] = SWAP32(state[idx].hash[i]);

#ifndef GLOBAL_SALT_NO_INIT
	uint pass = ++state[idx].pass;

	/* Was this the last pass? If not, prepare for next one */
	if (4 * base + 32 < OUTLEN) {
		_phsk_hmac_sha256(state[idx].hash, state[idx].ipad, state[idx].opad,
		                  salt->salt, salt->length, pass + 1);

		for (i = 0; i < 8; i++)
			state[idx].W[i] = state[idx].hash[i];

		state[idx].rounds = salt->rounds - 1;
	}
#endif /* GLOBAL_SALT_NO_INIT */
#endif /* RAR5 */
}
