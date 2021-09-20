/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and Copyright (c) 2012-2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Pass this kernel -DKEYLEN=x -DOUTLEN=y -DSALTLEN=z for generic use.
 *
 * KEYLEN  should be PLAINTEXT_LENGTH for passwords or 20 for hash
 * OUTLEN  should be sizeof(outbuffer->v)
 * SALTLEN should be sizeof(currentsalt.salt)
 *
 * salt->skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 20). So to calculate only
 * byte 21-40 (second chunk) you can say "salt->outlen=20 salt->skip_bytes=20"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 20 as opposed to 40.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

/* avoid name clashes */
#define preproc   u_preproc
#define hmac_sha1 u_hmac_sha1
#define big_hmac_sha1 u_big_hmac_sha1

typedef struct {
	uint  length;
	uchar v[KEYLEN];
} pbkdf2_password;

typedef struct {
	uint  v[(OUTLEN+3)/4]; /* output of PBKDF2 */
} pbkdf2_hash;

typedef struct {
	uint  iterations;
	uint  outlen;
	uint  skip_bytes;
	uchar length;
	uchar salt[SALTLEN];
} pbkdf2_salt;

inline void preproc(__global const uchar *key, uint keylen,
    uint *state, uint padding)
{
	uint i;
	uint W[16];
	uint A, B, C, D, E, temp, r[16];

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);

	A = INIT_A;
	B = INIT_B;
	C = INIT_C;
	D = INIT_D;
	E = INIT_E;

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;
}

inline void hmac_sha1(uint *output,
    uint *ipad_state,
    uint *opad_state,
    __constant uchar *salt, int saltlen, uchar add)
{
	int i;
	uint W[16];
	uint A, B, C, D, E, temp, r[16];
	union {
		uchar c[64];
		uint w[64/4];
	} buf;

	for (i = 0; i < 16; i++)
		buf.w[i] = 0;
	memcpy_cp(buf.c, salt, saltlen);

	buf.c[saltlen + 4] = 0x80;
	buf.c[saltlen + 3] = add;
	PUT_UINT32BE((64 + saltlen + 4) << 3, buf.c, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < 16; i++)
		W[i] = SWAP32(buf.w[i]);

	SHA1(A, B, C, D, E, W);

	W[0] = A + ipad_state[0];
	W[1] = B + ipad_state[1];
	W[2] = C + ipad_state[2];
	W[3] = D + ipad_state[3];
	W[4] = E + ipad_state[4];
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

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
}

inline void big_hmac_sha1(uint *input, uint inputlen,
    uint *ipad_state,
    uint *opad_state, uint *tmp_out, uint iterations)
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

		W[0] = A + ipad_state[0];
		W[1] = B + ipad_state[1];
		W[2] = C + ipad_state[2];
		W[3] = D + ipad_state[3];
		W[4] = E + ipad_state[4];
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

inline void pbkdf2(__global const uchar *pass, uint passlen,
                   __constant uchar *salt, uint saltlen, uint iterations,
                   __global uint *out, uint outlen, uint skip_bytes)
{
	uint ipad_state[5];
	uint opad_state[5];
	uint accum = 0;
	uint loop, loops;

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	loops = (skip_bytes + outlen + (SHA1_DIGEST_LENGTH-1)) / SHA1_DIGEST_LENGTH;
	loop = skip_bytes / SHA1_DIGEST_LENGTH + 1;
	skip_bytes %= SHA1_DIGEST_LENGTH;

	while (loop <= loops) {
		uint tmp_out[5];
		int i;

		hmac_sha1(tmp_out, ipad_state, opad_state, salt, saltlen, loop);

		big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH,
		              ipad_state, opad_state,
		              tmp_out, iterations);

		for (i = skip_bytes; i < SHA1_DIGEST_LENGTH && accum < (outlen + 3) / 4 * 4; i++, accum++) {
			PUTCHAR_BE_G(out, accum, ((uchar*)tmp_out)[i]);
		}

		loop++;
		skip_bytes = 0;
	}
}

#undef preproc
#undef hmac_sha1
#undef big_hmac_sha1

__kernel void derive_key(__global const pbkdf2_password *inbuffer,
                         __global pbkdf2_hash *outbuffer,
                         __constant pbkdf2_salt *salt)
{
	uint idx = get_global_id(0);

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	       salt->salt, salt->length, salt->iterations,
	       outbuffer[idx].v, salt->outlen, salt->skip_bytes);
}
