/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>,
 * Copyright (c) 2012 Milen Rangelov and Copyright (c) 2012-2013 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_md5.h"
#include "opencl_sha1.h"

typedef struct {
	uint keymic[16 / 4];
} mic_t;

typedef struct {
	uint  length;
	uint  eapol[(256 + 64) / 4];
	uint  eapol_size;
	uint  data[(64 + 12) / 4]; // pre-processed mac and nonce
	uchar salt[36]; // essid
} wpapsk_salt;

typedef struct {
	MAYBE_VECTOR_UINT W[5];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT out[5];
	MAYBE_VECTOR_UINT partial[5];
} wpapsk_state;

inline void hmac_sha1(__global MAYBE_VECTOR_UINT *state,
                      __global MAYBE_VECTOR_UINT *ipad,
                      __global MAYBE_VECTOR_UINT *opad,
                      MAYBE_CONSTANT uchar *salt, uint saltlen, uchar add)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];

	for (i = 0; i < 5; i++)
		output[i] = ipad[i];

	for (i = 0; i < 15; i++)
		W[i] = 0;

	for (i = 0; i < saltlen; i++)
		PUTCHAR_BE(W, i, salt[i]);
	PUTCHAR_BE(W, saltlen + 3, add);
	PUTCHAR_BE(W, saltlen + 4, 0x80);
	W[15] = (64 + saltlen + 4) << 3;
	sha1_block(MAYBE_VECTOR_UINT, W, output);

	for (i = 0; i < 5; i++)
		W[i] = output[i];
	W[5] = 0x80000000;

	for (i = 0; i < 5; i++)
		output[i] = opad[i];
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, output);
	for (i = 0; i < 5; i++)
		state[i] = output[i];
}

inline void preproc(__global const MAYBE_VECTOR_UINT *key,
                    __global MAYBE_VECTOR_UINT *state, uint padding)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[5];

	for (i = 0; i < 16; i++)
		W[i] = key[i] ^ padding;

	sha1_single(MAYBE_VECTOR_UINT, W, output);

	for (i = 0; i < 5; i++)
		state[i] = output[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_init(__global const MAYBE_VECTOR_UINT *inbuffer,
                 MAYBE_CONSTANT wpapsk_salt *salt,
                 __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	preproc(&inbuffer[gid * 16], state[gid].ipad, 0x36363636);
	preproc(&inbuffer[gid * 16], state[gid].opad, 0x5c5c5c5c);

	hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad,
	          salt->salt, salt->length, 0x01);

	for (i = 0; i < 5; i++)
		state[gid].W[i] = state[gid].out[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_loop(__global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i, j;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT output[5];
	MAYBE_VECTOR_UINT state_out[5];

	for (i = 0; i < 5; i++)
		W[i] = state[gid].W[i];
	for (i = 0; i < 5; i++)
		ipad[i] = state[gid].ipad[i];
	for (i = 0; i < 5; i++)
		opad[i] = state[gid].opad[i];
	for (i = 0; i < 5; i++)
		state_out[i] = state[gid].out[i];

	for (j = 0; j < HASH_LOOPS; j++) {
		for (i = 0; i < 5; i++)
			output[i] = ipad[i];
		W[5] = 0x80000000;
		W[15] = (64 + 20) << 3;
		sha1_block_160Z(MAYBE_VECTOR_UINT, W, output);
		for (i = 0; i < 5; i++)
			W[i] = output[i];
		W[5] = 0x80000000;
		for (i = 0; i < 5; i++)
			output[i] = opad[i];
		W[15] = (64 + 20) << 3;
		sha1_block_160Z(MAYBE_VECTOR_UINT, W, output);
		for (i = 0; i < 5; i++)
			W[i] = output[i];

		for (i = 0; i < 5; i++)
			state_out[i] ^= output[i];
	}

	for (i = 0; i < 5; i++)
		state[gid].W[i] = W[i];
	for (i = 0; i < 5; i++)
		state[gid].out[i] = state_out[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_pass2(MAYBE_CONSTANT wpapsk_salt *salt,
                  __global wpapsk_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	for (i = 0; i < 5; i++)
		state[gid].partial[i] = state[gid].out[i];
	for (i = 0; i < 5; i++)
		state[gid].out[i] = VSWAP32(state[gid].out[i]);

	hmac_sha1(state[gid].out, state[gid].ipad, state[gid].opad, salt->salt, salt->length, 0x02);

	for (i = 0; i < 5; i++)
		state[gid].W[i] = state[gid].out[i];
}

//__constant uchar *text = "Pairwise key expansion\0";
//__constant uint text[6] = { 0x72696150, 0x65736977, 0x79656b20, 0x70786520, 0x69736e61, 0x00006e6f };
__constant uint text[6] = { 0x50616972, 0x77697365, 0x206b6579, 0x20657870, 0x616e7369, 0x6f6e0000 };

inline void prf_512(const MAYBE_VECTOR_UINT *key,
                    MAYBE_CONSTANT uint *data,
                    MAYBE_VECTOR_UINT *ret)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];

	// HMAC(EVP_sha1(), key, 32, (text.data), 100, ret, NULL);

	/* ipad */
	for (i = 0; i < 8; i++)
		W[i] = 0x36363636 ^ key[i]; // key is already swapped
	for (i = 8; i < 16; i++)
		W[i] = 0x36363636;
	sha1_single(MAYBE_VECTOR_UINT, W, ipad); // update(ipad)

	/* 64 first bytes */
	for (i = 0; i < 6; i++)
		W[i] = text[i];
	for (i = 5; i < 15; i++) {
		W[i] = (W[i] & 0xffffff00) | *data >> 24;
		W[i + 1] = *data++ << 8;
	}
	W[15] |= *data >> 24;
	sha1_block(MAYBE_VECTOR_UINT, W, ipad); // update(data)

	/* 36 remaining bytes */
	W[0] = *data++ << 8;
	for (i = 0; i < 8; i++) {
		W[i] = (W[i] & 0xffffff00) | *data >> 24;
		W[i + 1] = *data++ << 8;
	}
	W[9] = 0x80000000;
	for (i = 10; i < 15; i++)
		W[i] = 0;
	W[15] = (64 + 100) << 3;
	sha1_block(MAYBE_VECTOR_UINT, W, ipad); // update(data) + final

	/* opad */
	for (i = 0; i < 8; i++)
		W[i] = 0x5c5c5c5c ^ key[i];
	for (i = 8; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	sha1_single(MAYBE_VECTOR_UINT, W, opad); // update(opad)

	for (i = 0; i < 5; i++)
		W[i] = ipad[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, opad);
	/* Only 16 bits used */
	for (i = 0; i < 4; i++)
		ret[i] = opad[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_final_md5(__global wpapsk_state *state,
                      MAYBE_CONSTANT wpapsk_salt *salt,
                      __global mic_t *mic)
{
	uint gid = get_global_id(0);
	MAYBE_VECTOR_UINT outbuffer[8];
	MAYBE_VECTOR_UINT prf[4];
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[4], opad[4];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(EVP_md5(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size blocks, already prepared with 0x80 and len)
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ VSWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;
	md5_init(ipad);
	md5_block(MAYBE_VECTOR_UINT, W, ipad); /* md5_update(ipad, 64) */

	/* eapol_blocks (of MD5),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = salt->eapol_size;

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;
		md5_block(MAYBE_VECTOR_UINT, W, ipad); /* md5_update(), md5_final() */
	}

	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ VSWAP32(prf[i]);
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;
	md5_init(opad);
	md5_block(MAYBE_VECTOR_UINT, W, opad); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		W[i] = ipad[i];
	W[4] = 0x80;
	for (i = 5; i < 14; i++)
		W[i] = 0;
	W[14] = (64 + 16) << 3;
	W[15] = 0;
	md5_block(MAYBE_VECTOR_UINT, W, opad); /* md5_update(ipad, 16), md5_final() */

	for (i = 0; i < 4; i++)
#ifdef SCALAR
		mic[gid].keymic[i] = opad[i];
#else

#define VEC_OUT(NUM)	  \
		mic[gid * V_WIDTH + 0x##NUM].keymic[i] = opad[i].s##NUM

	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void wpapsk_final_sha1(__global wpapsk_state *state,
                       MAYBE_CONSTANT wpapsk_salt *salt,
                       __global mic_t *mic)
{
	MAYBE_VECTOR_UINT outbuffer[8];
	MAYBE_VECTOR_UINT prf[4];
	uint gid = get_global_id(0);
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	uint i, eapol_blocks;
	MAYBE_CONSTANT uint *cp = salt->eapol;

	for (i = 0; i < 5; i++)
		outbuffer[i] = state[gid].partial[i];

	for (i = 0; i < 3; i++)
		outbuffer[5 + i] = state[gid].out[i];

	prf_512(outbuffer, salt->data, prf);

	// HMAC(EVP_sha1(), prf, 16, hccap.eapol, hccap.eapol_size, mic[gid].keymic, NULL);
	// prf is the key (16 bytes)
	// eapol is the message (eapol_size bytes)
	for (i = 0; i < 4; i++)
		W[i] = 0x36363636 ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x36363636;
	sha1_single(MAYBE_VECTOR_UINT, W, ipad);

	/* eapol_blocks (of SHA1),
	 * eapol data + 0x80, null padded and len set in set_salt() */
	eapol_blocks = salt->eapol_size;

	/* At least this will not diverge */
	while (eapol_blocks--) {
		for (i = 0; i < 16; i++)
			W[i] = *cp++;

		sha1_block(MAYBE_VECTOR_UINT, W, ipad);
	}

	for (i = 0; i < 4; i++)
		W[i] = 0x5c5c5c5c ^ prf[i];
	for (i = 4; i < 16; i++)
		W[i] = 0x5c5c5c5c;

	sha1_single(MAYBE_VECTOR_UINT, W, opad);

	for (i = 0; i < 5; i++)
		W[i] = ipad[i];
	W[5] = 0x80000000;
	W[15] = (64 + 20) << 3;
	sha1_block_160Z(MAYBE_VECTOR_UINT, W, opad);
	/* We only use 16 bytes */
	for (i = 0; i < 4; i++)
#ifdef SCALAR
		mic[gid].keymic[i] = SWAP32(opad[i]);
#else

#undef VEC_OUT
#define VEC_OUT(NUM)	  \
	mic[gid * V_WIDTH + 0x##NUM].keymic[i] = SWAP32(opad[i].s##NUM)

	{
		VEC_OUT(0);
		VEC_OUT(1);
#if V_WIDTH > 2
		VEC_OUT(2);
#if V_WIDTH > 3
		VEC_OUT(3);
#if V_WIDTH > 4
		VEC_OUT(4);
		VEC_OUT(5);
		VEC_OUT(6);
		VEC_OUT(7);
#if V_WIDTH > 8
		VEC_OUT(8);
		VEC_OUT(9);
		VEC_OUT(a);
		VEC_OUT(b);
		VEC_OUT(c);
		VEC_OUT(d);
		VEC_OUT(e);
		VEC_OUT(f);
#endif
#endif
#endif
#endif
	}
#endif
}
