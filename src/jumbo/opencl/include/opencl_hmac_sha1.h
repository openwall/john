/*
 * This software is Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_sha1.h"

inline void preproc(const uchar *key, uint keylen,
                    __private uint *state, uint padding)
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

#if __OS_X__ && gpu_intel(DEVICE_INFO)
/*
 * Ridiculous workaround for Apple w/ Intel HD Graphics. I tried to
 * replace this with a barrier but that did not do the trick.
 *
 * Yosemite, HD Graphics 4000, 1.2(Jul 29 2015 02:40:37)
 */
	if (get_global_id(0) == 0x7fffffff) printf(".");
#endif
}

#define ANOTHER_SHA1(A, B, C, D, E, W) {	\
	uint a, b, c, d, e; \
	a = A; \
	b = B; \
	c = C; \
	d = D; \
	e = E; \
	SHA1(A, B, C, D, E, W); \
	A += a; \
	B += b; \
	C += c; \
	D += d; \
	E += e; \
	}

inline void hmac_sha1(__global uint *output,
                      __constant uint *message, int messagelen,
                      const uint *key, uint keylen)
{
	int i;
	uint W[16];
	uchar *w = (uchar*)W;
	uint A, B, C, D, E, temp, r[16];
	uint ipad_state[5];
	uint opad_state[5];

	preproc((uchar*)key, keylen, ipad_state, 0x36363636);
	preproc((uchar*)key, keylen, opad_state, 0x5c5c5c5c);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < messagelen / 4; i++) {
		W[(i & 15)] = SWAP32(message[i]);
		if ((i & 15) == 15)
			ANOTHER_SHA1(A, B, C, D, E, W);
	}
	for (i *= 4; i < messagelen; i++) {
		w[(i & 63) ^ 3] = ((__constant uchar*)message)[i];
		if ((i & 63) == 63)
			ANOTHER_SHA1(A, B, C, D, E, W);
	}

	for (i = messagelen & 63; i < 64; i++)
		w[i ^ 3] = 0;
	w[(messagelen & 63) ^ 3] = 0x80;
	if ((messagelen & 63) > 55) {
		ANOTHER_SHA1(A, B, C, D, E, W);
		for (i = 0; i < 15; i++)
			W[i] = 0;
	}
	W[15] = (64 + messagelen) << 3;
	ANOTHER_SHA1(A, B, C, D, E, W);

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

	output[0] = SWAP32(A);
	output[1] = SWAP32(B);
	output[2] = SWAP32(C);
	output[3] = SWAP32(D);
	output[4] = SWAP32(E);
}
