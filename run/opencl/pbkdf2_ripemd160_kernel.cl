/*
 * RIPEMD-160 implementation. Copyright (c) 2015, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * KEYLEN  should be PLAINTEXT_LENGTH for passwords or 20 for hash
 * OUTLEN  should be sizeof(outbuffer->v)
 * SALTLEN should be sizeof(currentsalt.salt)
 */

#include "opencl_misc.h"
#include "opencl_ripemd.h"
#define AES_SRC_TYPE __constant
#define AES_DST_TYPE __global
#include "opencl_aes.h"

#define ITERATIONS 2000

typedef struct {
	uint length;
	uchar v[KEYLEN];
} pbkdf2_password;

typedef struct {
	uint v[16 / 4];
} tc_hash;

typedef struct {
	uint salt[SALTLEN / 4];
	uint bin[(512 - 64) / 4];
} tc_salt;

#define RIPEMD160_DIGEST_LENGTH 20

inline void preproc(__global const uchar *key, uint keylen, uint *state,
                    uint padding)
{
	uint i;
	uint W[16];

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR(W, i, key[i]);

	state[0] = INIT_A;
	state[1] = INIT_B;
	state[2] = INIT_C;
	state[3] = INIT_D;
	state[4] = INIT_E;

	ripemd160(W, state);
}

inline void hmac_ripemd160(uint *output, uint *ipad_state, uint *opad_state,
                           __constant uint *salt, uchar add)
{
	uint i;
	uint W[16] = { 0 };

	for (i = 0; i < 5; i++)
		output[i] = ipad_state[i];

	for (i = 0; i < 16; i++)
		W[i] = salt[i];

	ripemd160(W, output);

	W[0] = add << 24;
	W[1] = 0x80;
	for (i = 2; i < 14; i++)
		W[i] = 0;
	W[14] = (64 + SALTLEN + 4) << 3;
	W[15] = 0;

	ripemd160(W, output);

	for (i = 0; i < 5; i++)
		W[i] = output[i];

	for (i = 0; i < 5; i++)
		output[i] = opad_state[i];

	ripemd160_160Z(W, output);
}

inline void big_hmac_ripemd160(uint *input, uint inputlen, uint *ipad_state,
                               uint *opad_state, uint *tmp_out)
{
	uint i;
	uint W[5];

	for (i = 0; i < 5; i++)
		W[i] = input[i];

	for (i = 1; i < ITERATIONS; i++) {
		uint ctx[5];
		uint j;

		for (j = 0; j < 5; j++)
			ctx[j] = ipad_state[j];

		ripemd160_160Z(W, ctx);

		for (j = 0; j < 5; j++)
			W[j] = ctx[j];

		for (j = 0; j < 5; j++)
			ctx[j] = opad_state[j];

		ripemd160_160Z(W, ctx);

		for (j = 0; j < 5; j++)
			W[j] = ctx[j];

		for (j = 0; j < 5; j++)
			tmp_out[j] ^= ctx[j];
	}
}

inline void pbkdf2(__global const uchar *pass, uint passlen,
                   __constant uint *salt, uint *out)
{
	uint ipad_state[5];
	uint opad_state[5];
	uint r, t = 0;

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	for (r = 1; r <= (OUTLEN + 19) / 20; r++) {
		uint tmp_out[5];
		uint i;

		hmac_ripemd160(tmp_out, ipad_state, opad_state, salt, r);

		big_hmac_ripemd160(tmp_out, RIPEMD160_DIGEST_LENGTH,
		                   ipad_state, opad_state,
		                   tmp_out);

		for (i = 0; i < 20 && t < (OUTLEN + 3) / 4 * 4; i++, t++)
			PUTCHAR(out, t, ((uchar*)tmp_out)[i]);
	}
}

__kernel void tc_ripemd_aesxts(__global const pbkdf2_password *inbuffer,
                               __global tc_hash *outbuffer,
                               __constant tc_salt *salt)
{
	uint idx = get_global_id(0);
	uint key[64 / 4];

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length, salt->salt, key);

	AES_256_XTS_first_sector(salt->bin, outbuffer[idx].v, (uchar*)key);
}
