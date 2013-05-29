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

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

/* The basic MD4 functions */
#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#else
#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#endif
#define G(x, y, z)	(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)	((x) ^ (y) ^ (z))

/* The MD4 transformation for all three rounds. */
#define STEP(f, a, b, c, d, x, s)	  \
	(a) += f((b), (c), (d)) + (x); \
	(a) = rotate((a), (uint)(s))

/* some constants used below are passed with -D */
//#define KEY_LENGTH (MD4_PLAINTEXT_LENGTH + 1)

/* OpenCL kernel entry point. Copy KEY_LENGTH bytes key to be hashed from
 * global to local memory. Break the key into 16 32-bit (uint) words.
 * MD4 hash of a key is 128 bit (uint4). */
__kernel void md4(__global const uint * keys, __global uint * hashes)
{
	int id = get_global_id(0);
	uint W[16] = { 0 };
	uint i;
	uint num_keys = get_global_size(0);
	int base = id * (KEY_LENGTH / 4);
	char *p;
	uint a, b, c, d;

	for (i = 0; i != (KEY_LENGTH / 4) && keys[base + i]; i++)
		W[i] = keys[base + i];

	// Find actual length
	p = (char *) W;
	for (i = i ? (i - 1) * 4 : 0; p[i]; i++);

	PUTCHAR(W, i, 0x80);
	W[14] = i << 3;

	a = 0x67452301;
	b = 0xefcdab89;
	c = 0x98badcfe;
	d = 0x10325476;

	/* Round 1 */
	STEP(F, a, b, c, d, W[0], 3);
	STEP(F, d, a, b, c, W[1], 7);
	STEP(F, c, d, a, b, W[2], 11);
	STEP(F, b, c, d, a, W[3], 19);
	STEP(F, a, b, c, d, W[4], 3);
	STEP(F, d, a, b, c, W[5], 7);
	STEP(F, c, d, a, b, W[6], 11);
	STEP(F, b, c, d, a, W[7], 19);
	STEP(F, a, b, c, d, W[8], 3);
	STEP(F, d, a, b, c, W[9], 7);
	STEP(F, c, d, a, b, W[10], 11);
	STEP(F, b, c, d, a, W[11], 19);
	STEP(F, a, b, c, d, W[12], 3);
	STEP(F, d, a, b, c, W[13], 7);
	STEP(F, c, d, a, b, W[14], 11);
	STEP(F, b, c, d, a, W[15], 19);

	/* Round 2 */
	STEP(G, a, b, c, d, W[0] + 0x5a827999, 3);
	STEP(G, d, a, b, c, W[4] + 0x5a827999, 5);
	STEP(G, c, d, a, b, W[8] + 0x5a827999, 9);
	STEP(G, b, c, d, a, W[12] + 0x5a827999, 13);
	STEP(G, a, b, c, d, W[1] + 0x5a827999, 3);
	STEP(G, d, a, b, c, W[5] + 0x5a827999, 5);
	STEP(G, c, d, a, b, W[9] + 0x5a827999, 9);
	STEP(G, b, c, d, a, W[13] + 0x5a827999, 13);
	STEP(G, a, b, c, d, W[2] + 0x5a827999, 3);
	STEP(G, d, a, b, c, W[6] + 0x5a827999, 5);
	STEP(G, c, d, a, b, W[10] + 0x5a827999, 9);
	STEP(G, b, c, d, a, W[14] + 0x5a827999, 13);
	STEP(G, a, b, c, d, W[3] + 0x5a827999, 3);
	STEP(G, d, a, b, c, W[7] + 0x5a827999, 5);
	STEP(G, c, d, a, b, W[11] + 0x5a827999, 9);
	STEP(G, b, c, d, a, W[15] + 0x5a827999, 13);

	/* Round 3 */
	STEP(H, a, b, c, d, W[0] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, W[8] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, W[4] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, W[12] + 0x6ed9eba1, 15);
	STEP(H, a, b, c, d, W[2] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, W[10] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, W[6] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, W[14] + 0x6ed9eba1, 15);
	STEP(H, a, b, c, d, W[1] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, W[9] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, W[5] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, W[13] + 0x6ed9eba1, 15);
	STEP(H, a, b, c, d, W[3] + 0x6ed9eba1, 3);
	STEP(H, d, a, b, c, W[11] + 0x6ed9eba1, 9);
	STEP(H, c, d, a, b, W[7] + 0x6ed9eba1, 11);
	STEP(H, b, c, d, a, W[15] + 0x6ed9eba1, 15);

	hashes[id] = a + 0x67452301;
	hashes[1 * num_keys + id] = b + 0xefcdab89;
	hashes[2 * num_keys + id] = c + 0x98badcfe;
	hashes[3 * num_keys + id] = d + 0x10325476;
}
