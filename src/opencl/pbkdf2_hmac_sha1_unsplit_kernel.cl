/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and Copyright (c) 2012 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Pass this kernel -DKEYLEN=x -DOUTLEN=y -DSALTLEN=z for generic use.
 *
 * KEYLEN  should be PLAINTEXT_LENGTH for passwords or 20 for hash
 * OUTLEN  should be sizeof(outbuffer->v)
 * SALTLEN should be sizeof(currentsalt.salt)
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

#define SHA1_DIGEST_LENGTH     20

typedef struct {
	uint length;
	uchar v[KEYLEN];
} pbkdf2_password;

typedef struct {
	uint v[(OUTLEN+3)/4];
} pbkdf2_hash;

typedef struct {
	uchar length;
	uchar salt[SALTLEN];
	uint iterations;
	uint outlen;
} pbkdf2_salt;

inline void preproc(__global const uchar * key, uint keylen,
    __private uint * state, uint padding)
{
	uint i;
	uint W[16], temp;

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);

	uint A = INIT_A;
	uint B = INIT_B;
	uint C = INIT_C;
	uint D = INIT_D;
	uint E = INIT_E;

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;
}

inline void hmac_sha1(__private uint * output,
    __private uint * ipad_state,
    __private uint * opad_state,
    __global const uchar * salt, int saltlen, uchar add)
{
	int i;
	uint temp, W[16];
	uint A, B, C, D, E;
	uchar buf[64];
	uint *src = (uint *) buf;
	i = 64 / 4;
	while (i--)
		*src++ = 0;
	//_memcpy(buf, salt, saltlen);
	for (i = 0; i < saltlen; i++)
		buf[i] = salt[i];

	buf[saltlen + 4] = 0x80;
	buf[saltlen + 3] = add;
	PUT_UINT32BE((64 + saltlen + 4) << 3, buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < 16; i++)
		GET_UINT32BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += ipad_state[0];
	B += ipad_state[1];
	C += ipad_state[2];
	D += ipad_state[3];
	E += ipad_state[4];

	PUT_UINT32BE(A, buf, 0);
	PUT_UINT32BE(B, buf, 4);
	PUT_UINT32BE(C, buf, 8);
	PUT_UINT32BE(D, buf, 12);
	PUT_UINT32BE(E, buf, 16);
	PUT_UINT32BE(0, buf, 20);
	PUT_UINT32BE(0, buf, 24);

	buf[20] = 0x80;
	PUT_UINT32BE(0x2A0, buf, 60);

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];

	for (i = 0; i < 16; i++)
		GET_UINT32BE(W[i], buf, i * 4);

	SHA1_160Z(A, B, C, D, E, W);

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

inline void big_hmac_sha1(__private uint * input, uint inputlen,
    __private uint * ipad_state,
    __private uint * opad_state, __private uint * tmp_out, uint iterations)
{
	uint i;
	uint W[16];

	for (i = 0; i < 5; i++)
		W[i] = input[i];

	for (i = 1; i < iterations; i++) {
		uint A, B, C, D, E, temp;

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];

		W[5] = 0x80000000;
		W[15] = 0x2A0;

		SHA1_160Z(A, B, C, D, E, W);

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

		SHA1_160Z(A, B, C, D, E, W);

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
}

inline void pbkdf2(__global const uchar * pass, uint passlen,
                   __global const uchar * salt, uint saltlen, uint iterations,
                   __global uint * out, uint outlen)
{
	uint ipad_state[5];
	uint opad_state[5];
	uint r, t = 0;

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	for (r = 1; r <= (outlen + 19) / 20; r++) {
		uint tmp_out[5];
		int i;

		hmac_sha1(tmp_out, ipad_state, opad_state, salt, saltlen, r);

		big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH,
		              ipad_state, opad_state,
		              tmp_out, iterations);

		for (i = 0; i < 20 && t < (outlen + 3) / 4 * 4; i++, t++)
			PUTCHAR_BE_G(out, t, ((uchar*)tmp_out)[i]);
	}
}

__kernel void derive_key(__global const pbkdf2_password *inbuffer,
    __global pbkdf2_hash *outbuffer, __global const pbkdf2_salt *salt)
{
	uint idx = get_global_id(0);

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->salt, salt->length,
	       salt->iterations, outbuffer[idx].v, salt->outlen);
}
