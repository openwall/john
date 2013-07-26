/* MD4 OpenCL kernel based on Solar Designer's MD4 algorithm implementation at:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 * This code is in public domain.
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2012, magnum
 * and Copyright (c) 2013, Sayantan Datta <std2048 at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Useful References:
 * 1  nt_opencl_kernel.c (written by Alain Espinosa <alainesp at gmail.com>)
 * 2. http://tools.ietf.org/html/rfc1320
 * 3. http://en.wikipedia.org/wiki/MD4  */

#include "opencl_device_info.h"
#include "opencl_rawmd4_fmt.h"

#define BITMAP_HASH_0 	    (BITMAP_SIZE_0 - 1)
#define BITMAP_HASH_1	    (BITMAP_SIZE_1 - 1)

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

/* OpenCL kernel entry point. Copy key to be hashed from
 * global to local (thread) memory. Break the key into 16 32-bit (uint)
 * words. MD4 hash of a key is 128 bit (uint4). */

void md4_encrypt(__private uint *hash, __private uint *W, uint len) {

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

	/* Rounhash[3] 2 */
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

	/* Rounhash[3] 3 */
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[0] + 0x6ed9eba1, 3);
	STEP(H, hash[3], hash[0], hash[1], hash[2], W[8] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[4] + 0x6ed9eba1, 11);
	STEP(H, hash[1], hash[2], hash[3], hash[0], W[12] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[2] + 0x6ed9eba1, 3);
	STEP(H, hash[3], hash[0], hash[1], hash[2], W[10] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[6] + 0x6ed9eba1, 11);
	STEP(H, hash[1], hash[2], hash[3], hash[0], W[14] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[1] + 0x6ed9eba1, 3);
	STEP(H, hash[3], hash[0], hash[1], hash[2], W[9] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[5] + 0x6ed9eba1, 11);
	STEP(H, hash[1], hash[2], hash[3], hash[0], W[13] + 0x6ed9eba1, 15);
	STEP(H, hash[0], hash[1], hash[2], hash[3], W[3] + 0x6ed9eba1, 3);
	STEP(H, hash[3], hash[0], hash[1], hash[2], W[11] + 0x6ed9eba1, 9);
	STEP(H, hash[2], hash[3], hash[0], hash[1], W[7] + 0x6ed9eba1, 11);
	STEP(H, hash[1], hash[2], hash[3], hash[0], W[15] + 0x6ed9eba1, 15);

}

void cmp(__global uint *hashes,
	  __global uint *loaded_hashes,
	  __local uint *bitmap0,
	  __local uint *bitmap1,
	  __private uint *hash,
	  __global uint *outKeyIdx,
	  uint gid,
	  uint num_loaded_hashes) {

	uint loaded_hash, i, tmp;

	hash[0] += 0x67452301;
	hash[1] += 0xefcdab89;
	hash[2] += 0x98badcfe;
	hash[3] += 0x10325476;

	for(i = 0; i < num_loaded_hashes; i++) {

		loaded_hash = hash[0] & BITMAP_HASH_1;
		tmp = (bitmap0[loaded_hash >> 5] >> (loaded_hash & 31)) & 1U ;
		if(tmp) {

			loaded_hash = hash[1] & BITMAP_HASH_1;
			tmp &= (bitmap1[loaded_hash >> 5] >> (loaded_hash & 31)) & 1U;
			if(tmp) {

				loaded_hash = loaded_hashes[i * 4 + 3];
				if(hash[2] == loaded_hash) {

					loaded_hash = loaded_hashes[i * 4 + 4];
					if(hash[3] == loaded_hash) {

						hashes[i] = hash[0];
						hashes[1 * num_loaded_hashes + i] = hash[1];
						hashes[2 * num_loaded_hashes + i] = hash[2];
						hashes[3 * num_loaded_hashes + i] = hash[3];
						outKeyIdx[i] = gid ;
					}
				}
			}
		}
	}
 }

__kernel void md4_self_test(__global const uint *keys, __global const uint *index, __global uint *hashes)
{
	uint gid = get_global_id(0);
	uint W[16] = { 0 };
	uint i;
	uint num_keys = get_global_size(0);
	uint base = index[gid];
	uint len = base & 63;
	uint hash[4];

	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = *keys++;

	md4_encrypt(hash, W, len);

	hashes[gid] = hash[0] + 0x67452301;
	hashes[1 * num_keys + gid] = hash[1] + 0xefcdab89;
	hashes[2 * num_keys + gid] = hash[2] + 0x98badcfe;
	hashes[3 * num_keys + gid] = hash[3] + 0x10325476;
}

__kernel void md4(__global const uint *keys, __global const uint *index, __global uint *hashes,__global uint *loaded_hashes, __global uint *outKeyIdx, __global struct bitmap_ctx *bitmap)
{
	uint gid = get_global_id(0), lid = get_local_id(0);
	uint W[16] = { 0 };
	uint i;
	uint num_keys = get_global_size(0);
	uint base = index[gid];
	uint len = base & 63;
	uint hash[4];
	uint num_loaded_hashes = loaded_hashes[0];

	__local uint sbitmap0[BITMAP_SIZE_1 >> 5];
	__local uint sbitmap1[BITMAP_SIZE_1 >> 5];

	if(!gid)
		for (i = 0; i < num_loaded_hashes; i++)
			outKeyIdx[i] = outKeyIdx[i + num_loaded_hashes] = 0;

	for(i = 0; i < ((BITMAP_SIZE_1 >> 5) / LWS); i++)
		sbitmap0[i*LWS + lid] = bitmap[0].bitmap0[i*LWS + lid];

	for(i = 0; i < ((BITMAP_SIZE_1 >> 5)/ LWS); i++)
		sbitmap1[i*LWS + lid] = bitmap[0].bitmap1[i*LWS + lid];

	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = *keys++;

	barrier(CLK_LOCAL_MEM_FENCE);

	md4_encrypt(hash, W, len);
	cmp(hashes, loaded_hashes, sbitmap0, sbitmap1, hash, outKeyIdx, gid, num_loaded_hashes);

}
