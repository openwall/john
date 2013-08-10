/* MD5 OpenCL kernel based on Solar Designer's MD5 algorithm implementation at:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>
 * ,Copyright (c) 2012, magnum
 * and Copyright (c) 2013, Sayantan Datta <std2048 at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Useful References:
 * 1. CUDA MD5 Hashing Experiments, http://majuric.org/software/cudamd5/
 * 2. oclcrack, http://sghctoma.extra.hu/index.php?p=entry&id=11
 * 3. http://people.eku.edu/styere/Encrypt/JS-MD5.html
 * 4. http://en.wikipedia.org/wiki/MD5#Algorithm */

#include "opencl_device_info.h"

#if gpu_amd(DEVICE_INFO)
#define USE_BITSELECT
#endif

#define LDS_CACHE_SIZE		64
/* Macros for reading/writing chars from int32's (from rar_kernel.cl) */
#define GETCHAR(buf, index) (((uchar*)(buf))[(index)])
#define PUTCHAR(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2] & ~(0xffU << (((index) & 3) << 3))) + ((val) << (((index) & 3) << 3))

/* The basic MD5 functions */
#ifdef USE_BITSELECT
#define F(x, y, z)	bitselect((z), (y), (x))
#define G(x, y, z)	bitselect((y), (x), (z))
#else
#define F(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)	((y) ^ ((z) & ((x) ^ (y))))
#endif
#define H(x, y, z)	((x) ^ (y) ^ (z))
#define I(x, y, z)	((y) ^ ((x) | ~(z)))

/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s)	  \
	(a) += f((b), (c), (d)) + (x) + (t); \
	    (a) = rotate((a), (uint)(s)); \
	    (a) += (b)

/* some constants used below are passed with -D */
//#define KEY_LENGTH (MD4_PLAINTEXT_LENGTH + 1)

struct return_key {
	uint key[15];
	uint length;
};

/* OpenCL kernel entry point. Copy key to be hashed from
 * global to local (thread) memory. Break the key into 16 32-bit (uint)
 * words. MD5 hash of a key is 128 bit (uint4). */

void raw_md5_encrypt(__global const uint *keys, __private uint4 *hash, int len) {

	uint W[16] = { 0 };
	uint i;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = *keys++;

	PUTCHAR(W, len, 0x80);
	W[14] = len << 3;

	hash[0].s0 = 0x67452301;
	hash[0].s1 = 0xefcdab89;
	hash[0].s2 = 0x98badcfe;
	hash[0].s3 = 0x10325476;

	/* Round 1 */
	STEP(F, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[0], 0xd76aa478, 7);
	STEP(F, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[1], 0xe8c7b756, 12);
	STEP(F, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[2], 0x242070db, 17);
	STEP(F, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[3], 0xc1bdceee, 22);
	STEP(F, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[4], 0xf57c0faf, 7);
	STEP(F, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[5], 0x4787c62a, 12);
	STEP(F, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[6], 0xa8304613, 17);
	STEP(F, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[7], 0xfd469501, 22);
	STEP(F, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[8], 0x698098d8, 7);
	STEP(F, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[9], 0x8b44f7af, 12);
	STEP(F, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[10], 0xffff5bb1, 17);
	STEP(F, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[11], 0x895cd7be, 22);
	STEP(F, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[12], 0x6b901122, 7);
	STEP(F, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[13], 0xfd987193, 12);
	STEP(F, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[14], 0xa679438e, 17);
	STEP(F, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[15], 0x49b40821, 22);

	/* Round 2 */
	STEP(G, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[1], 0xf61e2562, 5);
	STEP(G, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[6], 0xc040b340, 9);
	STEP(G, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[11], 0x265e5a51, 14);
	STEP(G, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[0], 0xe9b6c7aa, 20);
	STEP(G, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[5], 0xd62f105d, 5);
	STEP(G, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[10], 0x02441453, 9);
	STEP(G, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[15], 0xd8a1e681, 14);
	STEP(G, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[4], 0xe7d3fbc8, 20);
	STEP(G, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[9], 0x21e1cde6, 5);
	STEP(G, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[14], 0xc33707d6, 9);
	STEP(G, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[3], 0xf4d50d87, 14);
	STEP(G, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[8], 0x455a14ed, 20);
	STEP(G, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[13], 0xa9e3e905, 5);
	STEP(G, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[2], 0xfcefa3f8, 9);
	STEP(G, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[7], 0x676f02d9, 14);
	STEP(G, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[12], 0x8d2a4c8a, 20);

	/* Round 3 */
	STEP(H, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[5], 0xfffa3942, 4);
	STEP(H, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[8], 0x8771f681, 11);
	STEP(H, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[11], 0x6d9d6122, 16);
	STEP(H, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[14], 0xfde5380c, 23);
	STEP(H, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[1], 0xa4beea44, 4);
	STEP(H, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[4], 0x4bdecfa9, 11);
	STEP(H, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[7], 0xf6bb4b60, 16);
	STEP(H, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[10], 0xbebfbc70, 23);
	STEP(H, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[13], 0x289b7ec6, 4);
	STEP(H, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[0], 0xeaa127fa, 11);
	STEP(H, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[3], 0xd4ef3085, 16);
	STEP(H, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[6], 0x04881d05, 23);
	STEP(H, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[9], 0xd9d4d039, 4);
	STEP(H, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[12], 0xe6db99e5, 11);
	STEP(H, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[15], 0x1fa27cf8, 16);
	STEP(H, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[2], 0xc4ac5665, 23);

	/* Round 4 */
	STEP(I, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[0], 0xf4292244, 6);
	STEP(I, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[7], 0x432aff97, 10);
	STEP(I, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[14], 0xab9423a7, 15);
	STEP(I, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[5], 0xfc93a039, 21);
	STEP(I, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[12], 0x655b59c3, 6);
	STEP(I, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[3], 0x8f0ccc92, 10);
	STEP(I, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[10], 0xffeff47d, 15);
	STEP(I, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[1], 0x85845dd1, 21);
	STEP(I, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[8], 0x6fa87e4f, 6);
	STEP(I, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[15], 0xfe2ce6e0, 10);
	STEP(I, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[6], 0xa3014314, 15);
	STEP(I, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[13], 0x4e0811a1, 21);
	STEP(I, hash[0].s0, hash[0].s1, hash[0].s2, hash[0].s3, W[4], 0xf7537e82, 6);
	STEP(I, hash[0].s3, hash[0].s0, hash[0].s1, hash[0].s2, W[11], 0xbd3af235, 10);
	STEP(I, hash[0].s2, hash[0].s3, hash[0].s0, hash[0].s1, W[2], 0x2ad7d2bb, 15);
	STEP(I, hash[0].s1, hash[0].s2, hash[0].s3, hash[0].s0, W[9], 0xeb86d391, 21);

 }

 void cmp(__global uint *hashes,
	  __global const uint *loaded_hashes,
	  __private uint4 *hash,
	  __local uint *lds_cache,
	  __global uint * cmp_out,
	  __global const uint *keys,
	  uint len,
	  __global struct return_key *return_keys) {

	uint i, j, loaded_hash, cache_offset, tmp, k;
	uint num_loaded_hashes = loaded_hashes[0];
	uint num_keys = get_global_size(0);

	hash[0].s0 += 0x67452301;
	cache_offset = 0;
	for(i = 0 , k = 0; i < num_loaded_hashes; i++, k++) {
		// Cache loaded_hashes into local memory
		if(i == cache_offset) {
			tmp = ((cache_offset + LDS_CACHE_SIZE) > num_loaded_hashes) ? (num_loaded_hashes - cache_offset) : LDS_CACHE_SIZE;
			if(!get_local_id(0)) {
				for(j = 0; j < tmp; j++)
					lds_cache[j] = loaded_hashes[cache_offset + j + 1];
			}
			barrier(CLK_LOCAL_MEM_FENCE);
			cache_offset += LDS_CACHE_SIZE;
			k = 0;
		}

		loaded_hash = lds_cache[k];

		if(hash[0].s0 == loaded_hash) {
			hashes[i] = hash[0].s0;
			hashes[1 * num_loaded_hashes + i] = hash[0].s1 + 0xefcdab89;
			hashes[2 * num_loaded_hashes + i] = hash[0].s2 + 0x98badcfe;
			hashes[3 * num_loaded_hashes + i] = hash[0].s3 + 0x10325476;

			for (j = 0; j < (len+3)/4; j++)
			    return_keys[i].key[j] = *keys++;
			return_keys[i].length = len;

			cmp_out[i] = 0xffffffff;
		}
	}
 }

__kernel void md5_self_test(__global const uint *keys, __global const uint *index, __global uint *hashes)
{
	uint4 hash;
	uint num_keys = get_global_size(0);
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = base & 63;

	keys += base >> 6;

	raw_md5_encrypt(keys, &hash, len);

	hashes[gid] = hash.s0 + 0x67452301;
	hashes[1 * num_keys + gid] = hash.s1 + 0xefcdab89;
	hashes[2 * num_keys + gid] = hash.s2 + 0x98badcfe;
	hashes[3 * num_keys + gid] = hash.s3 + 0x10325476;
}

__kernel void md5(__global const uint *keys, __global const uint *index, __global uint *hashes, __global const uint* loaded_hashes, __global uint *cmp_out, __global struct return_key *return_keys)
{
	uint4 hash;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = base & 63;

	int i;

	__local uint lds_cache[LDS_CACHE_SIZE];

	if(!gid)
		for (i = 0; i < loaded_hashes[0]; i++)
			cmp_out[i] = 0;

	keys += base >> 6;
	raw_md5_encrypt(keys, &hash, len);
	cmp(hashes, loaded_hashes, &hash, lds_cache, cmp_out, keys, len, return_keys);
}
