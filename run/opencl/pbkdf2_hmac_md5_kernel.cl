/*
 * This software is Copyright (c) 2015 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * increased salt_len from 52 (which was a bug), to 115.  salts [52-115] bytes
 * require 2 md5 limbs to handle.  Salts [0-51] bytes in length are handled by
 * 1 md5 limb.  (Feb. 2/16, JimF)
 * increased salt again.  Now unlimited salt length. (Dec 2017, JimF)
 *
 * This is a generic pbkdf2-hmac-md5
 *
 * Build-time (at run-time for host code) defines:
 * -DHASH_LOOPS is number of rounds (of 2 x MD5) per call to loop kernel.
 *
 * For a fixed iterations count, define ITERATIONS. Otherwise salt->iterations
 * will be used (slower).
 *
 * For a fixed output length, define OUTLEN. Otherwise salt->outlen will be
 * used.
 *
 * Example for 4096 iterations and output length 16:
 * -DITERATIONS=4095
 * -DHASH_LOOPS=105 (made by factors of 4095)
 * -DOUTLEN=16
 * pbkdf2_init()
 * for (ITERATIONS / HASH_LOOPS)
 *     pbkdf2_loop()
 * pbkdf2_final()
 *
 *
 * Example for variable iterations count and length:
 * -DHASH_LOOPS=100
 * pbkdf2_init()
 * for ((salt.iterations - 1) / HASH_LOOPS)
 *     pbkdf2_loop()
 * pbkdf2_final() // first 16 bytes of output
 * for ((salt.iterations - 1) / HASH_LOOPS)
 *     pbkdf2_loop()
 * pbkdf2_final() // next 16 bytes of output
 * ...
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_md5.h"

#ifdef ITERATIONS
#if ITERATIONS % HASH_LOOPS
#error HASH_LOOPS must be a divisor of ITERATIONS
#endif
#endif

#define CONCAT(TYPE,WIDTH)	TYPE ## WIDTH
#define VECTOR(x, y)		CONCAT(x, y)

/* MAYBE_VECTOR_UINT need to be defined before this header */
#include "opencl_pbkdf2_hmac_md5.h"

inline void hmac_md5(__global MAYBE_VECTOR_UINT *state,
                     __global MAYBE_VECTOR_UINT *ipad,
                     __global MAYBE_VECTOR_UINT *opad,
                     MAYBE_CONSTANT uchar *salt, uint saltlen, uchar add)
{
	uint i, j, last;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[4];

	for (i = 0; i < 4; i++)
		output[i] = ipad[i];

	// Code now handles ANY length salt!
	i = 0;
	last = saltlen;	// this the count of bytes of salt put into the final buffer.
	while (i+64 <= saltlen) {
		// no need to clean. We are using the entire 64 bytes with this block of salt
		for (j = 0; j < 64; ++j, ++i)
			PUTCHAR(W, j, salt[i]);
		last -= 64;
		md5_block(MAYBE_VECTOR_UINT, W, output);
	}
	//
	// ok, either this is the last limb, OR we have this one, and have to make 1 more.
	//
	// Fully blank out the buffer (dont skip element 15 len 61-63 wont clean buffer)
	for (j = 0; j < 16; j++)
		W[j] = 0;

	// assertion [i <= saltlen < (i+64)], so all remaining salt (if any) fits in this block
	for (j = 0; i < saltlen; ++j, ++i)
		PUTCHAR(W, j, salt[i]);

	if (last <= 51) {
		// this is last limb, everything fits
		PUTCHAR(W, last + 3, add);
		PUTCHAR(W, last + 4, 0x80);
		W[14] = (64 + saltlen + 4) << 3;
	} else {
		// do the last limb with salt data, then 1 more buffer, since this one
		// the salt + add number did NOT fit into this buffer.
		if (last < 61)
			PUTCHAR(W, last + 3, add);
		if (last < 60)
			PUTCHAR(W, last + 4, 0x80);
		md5_block(MAYBE_VECTOR_UINT, W, output);
		// Final limb (no salt data put into this one)
		for (j = 0; j < 14; j++)
			W[j] = 0;
		if (last >= 61)
			PUTCHAR(W, last + 3 - 64, add);
		if (last >= 60)
			PUTCHAR(W, last + 4 - 64, 0x80);
		W[14] = (64 + saltlen + 4) << 3;
		W[15] = 0;
	}
	// this is sha1_final for our salt.add-word.
	md5_block(MAYBE_VECTOR_UINT, W, output);

	for (i = 0; i < 4; i++)
		W[i] = output[i];
	W[4] = 0x80;
	for (i = 5; i < 14; i++)
		W[i] = 0;
	W[14] = (64 + 16) << 3;
	W[15] = 0;

	for (i = 0; i < 4; i++)
		output[i] = opad[i];
	md5_block(MAYBE_VECTOR_UINT, W, output);

	for (i = 0; i < 4; i++)
		state[i] = output[i];
}

inline void preproc(__global const MAYBE_VECTOR_UINT *key,
                    __global MAYBE_VECTOR_UINT *state, uint padding)
{
	uint i;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT output[4];

	for (i = 0; i < 16; i++)
		W[i] = key[i] ^ padding;

	md5_single(MAYBE_VECTOR_UINT, W, output);

	for (i = 0; i < 4; i++)
		state[i] = output[i];
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void pbkdf2_init(__global const MAYBE_VECTOR_UINT *inbuffer,
                 MAYBE_CONSTANT pbkdf2_salt *salt,
                 __global pbkdf2_state *state)
{
	uint gid = get_global_id(0);
	uint i;

	preproc(&inbuffer[gid * 16], state[gid].ipad, 0x36363636);
	preproc(&inbuffer[gid * 16], state[gid].opad, 0x5c5c5c5c);

	hmac_md5(state[gid].out, state[gid].ipad, state[gid].opad,
	         salt->salt, salt->length, 0x01);

	for (i = 0; i < 4; i++)
		state[gid].W[i] = state[gid].out[i];

#ifndef ITERATIONS
	state[gid].iter_cnt = salt->iterations - 1;
#endif
	state[gid].pass = 0;
}

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void pbkdf2_loop(__global pbkdf2_state *state)
{
	uint gid = get_global_id(0);
	uint i, j;
	MAYBE_VECTOR_UINT W[16];
	MAYBE_VECTOR_UINT ipad[4];
	MAYBE_VECTOR_UINT opad[4];
	MAYBE_VECTOR_UINT output[4];
	MAYBE_VECTOR_UINT state_out[4];
#if defined ITERATIONS
#define iterations HASH_LOOPS
#else
	uint iterations = state[gid].iter_cnt > HASH_LOOPS ?
		HASH_LOOPS : state[gid].iter_cnt;
#endif
	for (i = 0; i < 4; i++)
		W[i] = state[gid].W[i];
	for (i = 0; i < 4; i++)
		ipad[i] = state[gid].ipad[i];
	for (i = 0; i < 4; i++)
		opad[i] = state[gid].opad[i];
	for (i = 0; i < 4; i++)
		state_out[i] = state[gid].out[i];

	for (j = 0; j < iterations; j++) {
		for (i = 0; i < 4; i++)
			output[i] = ipad[i];
		W[4] = 0x80;
		for (i = 5; i < 14; i++)
			W[i] = 0;
		W[14] = (64 + 16) << 3;
		W[15] = 0;
		md5_block(MAYBE_VECTOR_UINT, W, output);

		for (i = 0; i < 4; i++)
			W[i] = output[i];
		W[4] = 0x80;
		for (i = 5; i < 14; i++)
			W[i] = 0;
		W[14] = (64 + 16) << 3;
		W[15] = 0;
		for (i = 0; i < 4; i++)
			output[i] = opad[i];
		md5_block(MAYBE_VECTOR_UINT, W, output);

		for (i = 0; i < 4; i++)
			W[i] = output[i];

		for (i = 0; i < 4; i++)
			state_out[i] ^= output[i];
	}

	for (i = 0; i < 4; i++)
		state[gid].W[i] = W[i];
	for (i = 0; i < 4; i++)
		state[gid].out[i] = state_out[i];

#ifndef ITERATIONS
	state[gid].iter_cnt -= iterations;
#endif
}

#ifndef OUTLEN
#define OUTLEN salt->outlen
#endif

__kernel
__attribute__((vec_type_hint(MAYBE_VECTOR_UINT)))
void pbkdf2_final(MAYBE_CONSTANT pbkdf2_salt *salt,
                  __global pbkdf2_out *out,
                  __global pbkdf2_state *state)
{
	uint gid = get_global_id(0);
	uint i, pass, base;

	base = state[gid].pass++ * 4;
	pass = state[gid].pass;

	// First/next 16 bytes of output
	for (i = 0; i < 4; i++)
#ifdef SCALAR
		out[gid].dk[base + i] = state[gid].out[i];
#else

#define VEC_OUT(NUM)	  \
	out[gid * V_WIDTH + 0x##NUM].dk[base + i] = state[gid].out[i].s##NUM

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

	/* Was this the last pass? If not, prepare for next one */
	if (4 * base + 16 < OUTLEN) {
		hmac_md5(state[gid].out, state[gid].ipad, state[gid].opad,
		         salt->salt, salt->length, 1 + pass);

		for (i = 0; i < 4; i++)
			state[gid].W[i] = state[gid].out[i];

#ifndef ITERATIONS
		state[gid].iter_cnt = salt->iterations - 1;
#endif
	}
}
