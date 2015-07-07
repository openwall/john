/*
 * This software is Copyright (c) 2015, Sayantan Datta <sdatta@openwall.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#include "opencl_device_info.h"
#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_mask.h"

#define INIT_A			0x67452301
#define INIT_B			0xefcdab89
#define INIT_C			0x98badcfe
#define INIT_D			0x10325476

#define SQRT_2			0x5a827999
#define SQRT_3			0x6ed9eba1

inline void md4_crypt_a(__private uint *hash, __private uint *nt_buffer)
{
	unsigned int a = INIT_A;
	unsigned int b = INIT_B;
	unsigned int c = INIT_C;
	unsigned int d = INIT_D;

	/* Round 1 */
	a += (d ^ (b & (c ^ d))) + nt_buffer[0];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[1];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[2];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[3];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[4];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[5];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[6];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[7];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[8];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[9];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[10];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[11];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + nt_buffer[12];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + nt_buffer[13];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + nt_buffer[14];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + nt_buffer[15];
	b = (b << 19) | (b >> 13);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2;
	b = (b << 13) | (b >> 19);

	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3;
	b = (b << 15) | (b >> 17);

	hash[0] = a + INIT_A;
	hash[1] = b + INIT_B;
	hash[2] = c + INIT_C;
	hash[3] = d + INIT_D;
}

inline void md4_crypt_b(__private uint *hash, constant uint *salt)
{
	unsigned int a = INIT_A;
	unsigned int b = INIT_B;
	unsigned int c = INIT_C;
	unsigned int d = INIT_D;

	/* Round 1 */
	a += (d ^ (b & (c ^ d))) + hash[0];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + hash[1];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + hash[2];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + hash[3];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + salt[0];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + salt[1];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + salt[2];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + salt[3];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + salt[4];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + salt[5];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + salt[6];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + salt[7];
	b = (b << 19) | (b >> 13);

	a += (d ^ (b & (c ^ d))) + salt[8];
	a = (a << 3) | (a >> 29);
	d += (c ^ (a & (b ^ c))) + salt[9];
	d = (d << 7) | (d >> 25);
	c += (b ^ (d & (a ^ b))) + salt[10];
	c = (c << 11) | (c >> 21);
	b += (a ^ (c & (d ^ a))) + salt[11];
	b = (b << 19) | (b >> 13);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + hash[0] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + salt[0] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + salt[4] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + salt[8] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + hash[1] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + salt[1] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + salt[5] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + salt[9] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + hash[2] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + salt[2] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + salt[6] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + salt[10] + SQRT_2;
	b = (b << 13) | (b >> 19);

	a += ((b & (c | d)) | (c & d)) + hash[3] + SQRT_2;
	a = (a << 3) | (a >> 29);
	d += ((a & (b | c)) | (b & c)) + salt[3] + SQRT_2;
	d = (d << 5) | (d >> 27);
	c += ((d & (a | b)) | (a & b)) + salt[7] + SQRT_2;
	c = (c << 9) | (c >> 23);
	b += ((c & (d | a)) | (d & a)) + salt[11] + SQRT_2;
	b = (b << 13) | (b >> 19);

	/* Round 3 */
	a += (d ^ c ^ b) + hash[0] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + salt[4] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + salt[0] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + salt[8] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + hash[2] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + salt[6] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + salt[2] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + salt[10] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + hash[1] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + salt[5] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + salt[1] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + salt[9] + SQRT_3;
	b = (b << 15) | (b >> 17);

	a += (d ^ c ^ b) + hash[3] + SQRT_3;
	a = (a << 3) | (a >> 29);
	d += (c ^ b ^ a) + salt[7] + SQRT_3;
	d = (d << 9) | (d >> 23);
	c += (b ^ a ^ d) + salt[3] + SQRT_3;
	c = (c << 11) | (c >> 21);
	b += (a ^ d ^ c) + salt[11] + SQRT_3;
	b = (b << 15) | (b >> 17);

	hash[0] = a + INIT_A;
	hash[1] = b + INIT_B;
	hash[2] = c + INIT_C;
	hash[3] = d + INIT_D;
}

inline void prepare_key(__global uint * key, uint length, uint * nt_buffer)
{
	uint i = 0, nt_index, keychars;
	nt_index = 0;
	for (i = 0; i < (length + 3)/ 4; i++) {
		keychars = key[i];
		nt_buffer[nt_index++] = (keychars & 0xFF) | (((keychars >> 8) & 0xFF) << 16);
		nt_buffer[nt_index++] = ((keychars >> 16) & 0xFF) | ((keychars >> 24) << 16);
	}
	nt_index = length >> 1;
	nt_buffer[nt_index] = (nt_buffer[nt_index] & 0xFF) | (0x80 << ((length & 1) << 4));
	nt_buffer[nt_index + 1] = 0;
	nt_buffer[14] = length << 4;
}

inline void cmp_final(uint gid,
		uint iter,
		__private uint *hash,
		__global uint *offset_table,
		__global uint *hash_table,
		constant uint *salt,
		__global uint *return_hashes,
		volatile __global uint *output,
		volatile __global uint *bitmap_dupe) {

	uint t, offset_table_index, hash_table_index;
	unsigned long LO, HI;
	unsigned long p;

	HI = ((unsigned long)hash[3] << 32) | (unsigned long)hash[2];
	LO = ((unsigned long)hash[1] << 32) | (unsigned long)hash[0];

	p = (HI % salt[13]) * salt[15];
	p += LO % salt[13];
	p %= salt[13];
	offset_table_index = (unsigned int)p;

	//error: chances of overflow is extremely low.
	LO += (unsigned long)offset_table[offset_table_index];

	p = (HI % salt[14]) * salt[16];
	p += LO % salt[14];
	p %= salt[14];
	hash_table_index = (unsigned int)p;

	if (hash_table[hash_table_index] == hash[0])
	if (hash_table[salt[14] + hash_table_index] == hash[1])
	{
/*
 * Prevent duplicate keys from cracking same hash
 */
		if (!(atomic_or(&bitmap_dupe[hash_table_index/32], (1U << (hash_table_index % 32))) & (1U << (hash_table_index % 32)))) {
			t = atomic_inc(&output[0]);
			output[1 + 3 * t] = gid;
			output[2 + 3 * t] = iter;
			output[3 + 3 * t] = hash_table_index;
			return_hashes[2 * t] = hash[2];
			return_hashes[2 * t + 1] = hash[3];
		}
	}
}

inline void cmp(uint gid,
		uint iter,
		__private uint *hash,
		__global uint *bitmaps,
		uint bitmap_sz_bits,
		__global uint *offset_table,
		__global uint *hash_table,
		constant uint *salt,
		__global uint *return_hashes,
		volatile __global uint *output,
		volatile __global uint *bitmap_dupe) {
	uint bitmap_index, tmp = 1;

	bitmap_index = hash[3] & salt[12];
	tmp &= (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[2] & salt[12];
	tmp &= (bitmaps[(bitmap_sz_bits >> 5) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;

	if (tmp)
		cmp_final(gid, iter, hash, offset_table, hash_table, salt, return_hashes, output, bitmap_dupe);
}

#define USE_CONST_CACHE \
	(CONST_CACHE_SIZE >= ((NUM_INT_KEYS + 17) * 4))
/* some constants used below are passed with -D */
//#define KEY_LENGTH (MD4_PLAINTEXT_LENGTH + 1)

/* OpenCL kernel entry point. Copy key to be hashed from
 * global to local (thread) memory. Break the key into 16 32-bit (uint)
 * words. MD4 hash of a key is 128 bit (uint4). */
__kernel void mscash(__global uint *keys,
		  __global uint *index,
		  constant uint *salt
#if gpu_amd(DEVICE_INFO)
		__attribute__((max_constant_size(17 * sizeof(uint))))
#endif
		  , __global uint *int_key_loc,
#if USE_CONST_CACHE
		  constant
#else
		  __global
#endif
		  uint *int_keys
#if USE_CONST_CACHE && gpu_amd(DEVICE_INFO)
		__attribute__((max_constant_size (NUM_INT_KEYS * 4)))
#endif
		 , __global uint *bitmaps,
		  __global uint *offset_table,
		  __global uint *hash_table,
		  __global uint *return_hashes,
		  volatile __global uint *out_hash_ids,
		  volatile __global uint *bitmap_dupe)
{
	uint i;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint nt_buffer[16] = { 0 };
	uint len = base & 63;
	uint hash[4] = {0};
	uint bitmap_sz_bits = salt[12] + 1;

#if __OPENCL_VERSION__ < 120 || (__OS_X__ && gpu_nvidia(DEVICE_INFO))
	if (!gid) {
		out_hash_ids[0] = 0;
		for (i = 0; i < salt[14]/32 + 1; i++)
			bitmap_dupe[i] = 0;
	}
	barrier(CLK_GLOBAL_MEM_FENCE);
#endif

#if NUM_INT_KEYS > 1 && !IS_STATIC_GPU_MASK
	uint ikl = int_key_loc[gid];
	uint loc0 = ikl & 0xff;
#if 1 < MASK_FMT_INT_PLHDR
#if LOC_1 >= 0
	uint loc1 = (ikl & 0xff00) >> 8;
#endif
#endif
#if 2 < MASK_FMT_INT_PLHDR
#if LOC_2 >= 0
	uint loc2 = (ikl & 0xff0000) >> 16;
#endif
#endif
#if 3 < MASK_FMT_INT_PLHDR
#if LOC_3 >= 0
	uint loc3 = (ikl & 0xff000000) >> 24;
#endif
#endif
#endif

#if !IS_STATIC_GPU_MASK
#define GPU_LOC_0 loc0
#define GPU_LOC_1 loc1
#define GPU_LOC_2 loc2
#define GPU_LOC_3 loc3
#else
#define GPU_LOC_0 LOC_0
#define GPU_LOC_1 LOC_1
#define GPU_LOC_2 LOC_2
#define GPU_LOC_3 LOC_3
#endif

	keys += base >> 6;
	prepare_key(keys, len, nt_buffer);

	for (i = 0; i < NUM_INT_KEYS; i++) {
#if NUM_INT_KEYS > 1
		PUTSHORT(nt_buffer, GPU_LOC_0, (int_keys[i] & 0xff));
#if 1 < MASK_FMT_INT_PLHDR
#if LOC_1 >= 0
		PUTSHORT(nt_buffer, GPU_LOC_1, ((int_keys[i] & 0xff00) >> 8));
#endif
#endif
#if 2 < MASK_FMT_INT_PLHDR
#if LOC_2 >= 0
		PUTSHORT(nt_buffer, GPU_LOC_2, ((int_keys[i] & 0xff0000) >> 16));
#endif
#endif
#if 3 < MASK_FMT_INT_PLHDR
#if LOC_3 >= 0
		PUTSHORT(nt_buffer, GPU_LOC_3, ((int_keys[i] & 0xff000000) >> 24));
#endif
#endif
#endif
		md4_crypt_a(hash, nt_buffer);
		md4_crypt_b(hash, salt);

		cmp(gid, i, hash, bitmaps, bitmap_sz_bits, offset_table, hash_table,
		    salt, return_hashes, out_hash_ids, bitmap_dupe);

	}
}
