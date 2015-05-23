/* MD4 OpenCL kernel based on Solar Designer's MD4 algorithm implementation at:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 * This code is in public domain.
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Useful References:
 * 1  nt_opencl_kernel.c (written by Alain Espinosa <alainesp at gmail.com>)
 * 2. http://tools.ietf.org/html/rfc1320
 * 3. http://en.wikipedia.org/wiki/MD4  */

#include "opencl_device_info.h"
#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_mask.h"

/* The basic MD4 functions */
#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#else
#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#endif
#define G(x, y, z)	(((x) & ((y) | (z))) | ((y) & (z)))

#define H(x, y, z)	(((x) ^ (y)) ^ (z))
#define H2(x, y, z)	((x) ^ ((y) ^ (z)))

/* The MD4 transformation for all three rounds. */
#define STEP(f, a, b, c, d, x, s)	  \
	(a) += f((b), (c), (d)) + (x); \
	(a) = rotate((a), (uint)(s))

inline void md4_encrypt(__private uint *hash, __private uint *W, uint len)
{

	PUTCHAR(W, len, 0x80);
	W[14] = len << 3;

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;

	/* Round 1 */
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[0], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[1], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[2], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[3], 19);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[4], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[5], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[6], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[7], 19);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[8], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[9], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[10], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[11], 19);
	STEP(F, hash[0], hash[1], hash[2], hash[3], W[12], 3);
	STEP(F, hash[3], hash[0], hash[1], hash[2], W[13], 7);
	STEP(F, hash[2], hash[3], hash[0], hash[1], W[14], 11);
	STEP(F, hash[1], hash[2], hash[3], hash[0], W[15], 19);

	/* Round 2 */
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[0] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[4] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[8] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[12] + 0x5a827999, 13);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[1] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[5] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[9] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[13] + 0x5a827999, 13);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[2] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[6] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[10] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[14] + 0x5a827999, 13);
	STEP(G, hash[0], hash[1], hash[2], hash[3], W[3] + 0x5a827999, 3);
	STEP(G, hash[3], hash[0], hash[1], hash[2], W[7] + 0x5a827999, 5);
	STEP(G, hash[2], hash[3], hash[0], hash[1], W[11] + 0x5a827999, 9);
	STEP(G, hash[1], hash[2], hash[3], hash[0], W[15] + 0x5a827999, 13);

	/* Round 3 */
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[0] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[8] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[4] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[12] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[2] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[10] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[6] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[14] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[1] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[9] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[5] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[13] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[3] + 0x6ed9eba1, 3);
	STEP(H2, hash[3], hash[0], hash[1], hash[2], W[11] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[7] + 0x6ed9eba1, 11);
	STEP(H2, hash[1], hash[2], hash[3], hash[0], W[15] + 0x6ed9eba1, 15);
}

inline void cmp(uint gid,
		uint iter,
		uint num_hashes,
		volatile __global uint *output,
		__global const uint *loaded_hashes,
		__private uint *hash,
		volatile __global uint *bitmap) {
	uint t, j;

	hash[0] += 0x67452301;
	hash[1] += 0xefcdab89;
	hash[2] += 0x98badcfe;
	hash[3] += 0x10325476;

	for (j = 0; j < num_hashes; j++) {
		t = 0;

		t = (loaded_hashes[4 * j] == hash[0]) && (loaded_hashes[4 * j + 1] == hash[1]) &&
			(loaded_hashes[4 * j + 2] == hash[2]) && (loaded_hashes[4 * j + 3] == hash[3]);
		if(t) {
/* Prevent duplicate keys from cracking same hash */
			if (!(atomic_or(&bitmap[j/32], (1U << (j % 32))) & (1U << (j % 32)))) {
				t = atomic_inc(&output[0]);
				output[1 + 3 * t] = gid;
				output[2 + 3 * t] = iter;
				output[3 + 3 * t] = j;
			}

		}
	}
}

/* some constants used below are passed with -D */
//#define KEY_LENGTH (MD4_PLAINTEXT_LENGTH + 1)

/* OpenCL kernel entry point. Copy key to be hashed from
 * global to local (thread) memory. Break the key into 16 32-bit (uint)
 * words. MD4 hash of a key is 128 bit (uint4). */
__kernel void md4(__global uint *keys,
		  __global uint *index,
		  __global uint *int_key_loc,
		  __global uint *int_keys,
		  __global uint *loaded_hashes,
		  volatile __global uint *out_hash,
		  volatile __global uint *bitmap)
{
	uint gid = get_global_id(0);
	uint W[16] = { 0 };
	uint i;

	uint base = index[gid];
	uint len = base & 63;
	uint ikl = int_key_loc[gid];
	uint hash[4];

	if (!gid) {
		out_hash[0] = 0;
		for (i = 0; i < (NUM_LOADED_HASHES - 1)/32 + 1; i++)
			bitmap[i] = 0;
	}

	barrier(CLK_GLOBAL_MEM_FENCE);

	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = *keys++;

	for (i = 0; i < NUM_INT_KEYS; i++) {

		if (NUM_INT_KEYS > 1) {
			PUTCHAR(W, (ikl & 0xff), (int_keys[i] & 0xff));
			if ((1 < MASK_FMT_INT_PLHDR) && (ikl & 0xff00) != 0x8000)
				PUTCHAR(W, ((ikl & 0xff00) >> 8), ((int_keys[i] & 0xff00) >> 8));
			if ((2 < MASK_FMT_INT_PLHDR) && (ikl & 0xff0000) != 0x800000)
				PUTCHAR(W, ((ikl & 0xff0000) >> 16), ((int_keys[i] & 0xff0000) >> 16));
			if ((3 < MASK_FMT_INT_PLHDR) && (ikl & 0xff000000) != 0x80000000)
				PUTCHAR(W, ((ikl & 0xff000000) >> 24), ((int_keys[i] & 0xff000000) >> 24));
		}

		md4_encrypt(hash, W, len);
		cmp(gid, i, NUM_LOADED_HASHES, out_hash, loaded_hashes, hash, bitmap);
	}
}
