/*
   This code was largely inspired by
   pyrit opencl kernel sha1 routines, royger's sha1 sample,
   and md5_opencl_kernel.cl inside jtr.
   Copyright 2011 by Samuele Giovanni Tonon
   samu at linuxasylum dot net
   Copyright (c) 2012, magnum
   and Copyright (c) 2015, Sayantan Datta <sdatta@openwall.com>
   This program comes with ABSOLUTELY NO WARRANTY; express or
   implied .
   This is free software, and you are welcome to redistribute it
   under certain conditions; as expressed here
   http://www.gnu.org/licenses/gpl-2.0.html
*/

#include "opencl_device_info.h"
#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_mask.h"

#define INIT_A			0x67452301
#define INIT_B			0xefcdab89
#define INIT_C			0x98badcfe
#define INIT_D			0x10325476
#define INIT_E			0xc3d2e1f0

#define SQRT_2			0x5a827999
#define SQRT_3			0x6ed9eba1

#define K1			0x5a827999
#define K2			0x6ed9eba1
#define K3			0x8f1bbcdc
#define K4			0xca62c1d6

#ifdef USE_BITSELECT
#define F1(x, y, z)	bitselect(z, y, x)
#else
#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#endif

#define F2(x, y, z)		(x ^ y ^ z)

#ifdef USE_BITSELECT
#define F3(x, y, z)	(bitselect(x, y, z) ^ bitselect(x, 0U, y))
#else
#define F3(x, y, z)	((x & y) | (z & (x | y)))
#endif

#define F4(x, y, z)		(x ^ y ^ z)

#if 1 // Significantly faster, at least on nvidia
#define S(x, n)	rotate((x), (uint)(n))
#else
#define S(x, n)	((x << n) | ((x) >> (32 - n)))
#endif

#if BITMAP_SIZE_BITS_LESS_ONE < 0xffffffff
#define BITMAP_SIZE_BITS (BITMAP_SIZE_BITS_LESS_ONE + 1)
#else
/*undefined, cause error.*/
#endif

#define R(t)	  \
	( \
		temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = S(temp, 1) ) \
		)

#define Ro1(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = S(temp, 1) ) \
		)
#define Ro2(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ r[(t - 8) & 0x0F] ^ \
		W[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = S(temp, 1) ) \
		)

#define Ro3(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ r[(t - 8) & 0x0F] ^ \
		r[(t - 14) & 0x0F] ^ W[ t      & 0x0F], \
		( r[t & 0x0F] = S(temp, 1) ) \
		)

#define Rr(t)	  \
	( \
		temp = r[(t -  3) & 0x0F] ^ r[(t - 8) & 0x0F] ^ \
		r[(t - 14) & 0x0F] ^ r[ t      & 0x0F], \
		( r[t & 0x0F] = S(temp, 1) ) \
		)



#define R2(t)	  \
	( \
		S((W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ \
		   W[(t - 14) & 0x0F] ^ W[ t      & 0x0F]), 1) \
		)

#define P1(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F1(b, c, d) + K1 + x; b = S(b, 30); \
	}

#define P2(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F2(b, c, d) + K2 + x; b = S(b, 30); \
	}

#define P3(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F3(b, c, d) + K3 + x; b = S(b, 30); \
	}

#define P4(a, b, c, d, e, x)	  \
	{ \
		e += S(a, 5) + F4(b, c, d) + K4 + x; b = S(b, 30); \
	}

#define PZ(a, b, c, d, e)	  \
	{ \
		e += S(a, 5) + F1(b, c, d) + K1 ; b = S(b, 30); \
	}

#define SHA1(A, B, C, D, E, W)	  \
	P1(A, B, C, D, E, W[0] ); \
	P1(E, A, B, C, D, W[1] ); \
	P1(D, E, A, B, C, W[2] ); \
	P1(C, D, E, A, B, W[3] ); \
	P1(B, C, D, E, A, W[4] ); \
	P1(A, B, C, D, E, W[5] ); \
	P1(E, A, B, C, D, W[6] ); \
	P1(D, E, A, B, C, W[7] ); \
	P1(C, D, E, A, B, W[8] ); \
	P1(B, C, D, E, A, W[9] ); \
	P1(A, B, C, D, E, W[10]); \
	P1(E, A, B, C, D, W[11]); \
	P1(D, E, A, B, C, W[12]); \
	P1(C, D, E, A, B, W[13]); \
	P1(B, C, D, E, A, W[14]); \
	P1(A, B, C, D, E, W[15]); \
	P1(E, A, B, C, D, R(16)); \
	P1(D, E, A, B, C, R(17)); \
	P1(C, D, E, A, B, R(18)); \
	P1(B, C, D, E, A, Ro1(19)); \
	P2(A, B, C, D, E, Ro1(20)); \
	P2(E, A, B, C, D, Ro1(21)); \
	P2(D, E, A, B, C, Ro1(22)); \
	P2(C, D, E, A, B, Ro1(23)); \
	P2(B, C, D, E, A, Ro2(24)); \
	P2(A, B, C, D, E, Ro2(25)); \
	P2(E, A, B, C, D, Ro2(26)); \
	P2(D, E, A, B, C, Ro2(27)); \
	P2(C, D, E, A, B, Ro2(28)); \
	P2(B, C, D, E, A, Ro2(29)); \
	P2(A, B, C, D, E, Ro3(30)); \
	P2(E, A, B, C, D, Ro3(31)); \
	P2(D, E, A, B, C, Rr(32)); \
	P2(C, D, E, A, B, Rr(33)); \
	P2(B, C, D, E, A, Rr(34)); \
	P2(A, B, C, D, E, Rr(35)); \
	P2(E, A, B, C, D, Rr(36)); \
	P2(D, E, A, B, C, Rr(37)); \
	P2(C, D, E, A, B, Rr(38)); \
	P2(B, C, D, E, A, Rr(39)); \
	P3(A, B, C, D, E, Rr(40)); \
	P3(E, A, B, C, D, Rr(41)); \
	P3(D, E, A, B, C, Rr(42)); \
	P3(C, D, E, A, B, Rr(43)); \
	P3(B, C, D, E, A, Rr(44)); \
	P3(A, B, C, D, E, Rr(45)); \
	P3(E, A, B, C, D, Rr(46)); \
	P3(D, E, A, B, C, Rr(47)); \
	P3(C, D, E, A, B, Rr(48)); \
	P3(B, C, D, E, A, Rr(49)); \
	P3(A, B, C, D, E, Rr(50)); \
	P3(E, A, B, C, D, Rr(51)); \
	P3(D, E, A, B, C, Rr(52)); \
	P3(C, D, E, A, B, Rr(53)); \
	P3(B, C, D, E, A, Rr(54)); \
	P3(A, B, C, D, E, Rr(55)); \
	P3(E, A, B, C, D, Rr(56)); \
	P3(D, E, A, B, C, Rr(57)); \
	P3(C, D, E, A, B, Rr(58)); \
	P3(B, C, D, E, A, Rr(59)); \
	P4(A, B, C, D, E, Rr(60)); \
	P4(E, A, B, C, D, Rr(61)); \
	P4(D, E, A, B, C, Rr(62)); \
	P4(C, D, E, A, B, Rr(63)); \
	P4(B, C, D, E, A, Rr(64)); \
	P4(A, B, C, D, E, Rr(65)); \
	P4(E, A, B, C, D, Rr(66)); \
	P4(D, E, A, B, C, Rr(67)); \
	P4(C, D, E, A, B, Rr(68)); \
	P4(B, C, D, E, A, Rr(69)); \
	P4(A, B, C, D, E, Rr(70)); \
	P4(E, A, B, C, D, Rr(71)); \
	P4(D, E, A, B, C, Rr(72)); \
	P4(C, D, E, A, B, Rr(73)); \
	P4(B, C, D, E, A, Rr(74)); \
	P4(A, B, C, D, E, Rr(75)); \
	P4(E, A, B, C, D, Rr(76)); \
	P4(D, E, A, B, C, Rr(77)); \
	P4(C, D, E, A, B, Rr(78)); \
	P4(B, C, D, E, A, Rr(79));

#define sha1_init(o) {	  \
		o[0] = INIT_A; \
		o[1] = INIT_B; \
		o[2] = INIT_C; \
		o[3] = INIT_D; \
		o[4] = INIT_E; \
	}

#define sha1_block(b, o) {	\
		A = o[0]; \
		B = o[1]; \
		C = o[2]; \
		D = o[3]; \
		E = o[4]; \
		SHA1(A, B, C, D, E, b); \
		o[0] += A; \
		o[1] += B; \
		o[2] += C; \
		o[3] += D; \
		o[4] += E; \
	}


inline void cmp_final(uint gid,
		uint iter,
		__private uint *hash,
		__global uint *offset_table,
		__global uint *hash_table,
		__global uint *return_hashes,
		volatile __global uint *output,
		volatile __global uint *bitmap_dupe) {

	uint t, offset_table_index, hash_table_index;
	unsigned long LO, MI, HI;
	unsigned long p;

	HI = (unsigned long)hash[4];
	MI = ((unsigned long)hash[3] << 32) | (unsigned long)hash[2];
	LO = ((unsigned long)hash[1] << 32) | (unsigned long)hash[0];

	p = (HI % OFFSET_TABLE_SIZE) * SHIFT128_OT_SZ;
	p += (MI % OFFSET_TABLE_SIZE) * SHIFT64_OT_SZ;
	p += LO % OFFSET_TABLE_SIZE;
	p %= OFFSET_TABLE_SIZE;
	offset_table_index = (unsigned int)p;

	//error: chances of overflow is extremely low.
	LO += (unsigned long)offset_table[offset_table_index];

	p = (HI % HASH_TABLE_SIZE) * SHIFT128_HT_SZ;
	p += (MI % HASH_TABLE_SIZE) * SHIFT64_HT_SZ;
	p += LO % HASH_TABLE_SIZE;
	p %= HASH_TABLE_SIZE;
	hash_table_index = (unsigned int)p;

	if (hash_table[hash_table_index] == hash[0])
	if (hash_table[HASH_TABLE_SIZE + hash_table_index] == hash[1])
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
#if USE_LOCAL_BITMAPS
		__local
#else
		__global
#endif
		uint *bitmaps,
		__global uint *offset_table,
		__global uint *hash_table,
		__global uint *return_hashes,
		volatile __global uint *output,
		volatile __global uint *bitmap_dupe) {
	uint bitmap_index, tmp = 1;

	hash[0] = SWAP32(hash[0]);
	hash[1] = SWAP32(hash[1]);
	hash[2] = SWAP32(hash[2]);
	hash[3] = SWAP32(hash[3]);
	hash[4] = SWAP32(hash[4]);

#if SELECT_CMP_STEPS > 4
	bitmap_index = hash[0] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[0] >> 16) & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[1] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 4) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[1] >> 16) & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) * 3 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[2] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 3) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[2] >> 16) & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) * 5 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[3] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) * 6 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[3] >> 16) & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) * 7 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#elif SELECT_CMP_STEPS > 2
	bitmap_index = hash[3] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[2] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[1] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 4) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[0] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) * 3 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#elif SELECT_CMP_STEPS > 1
	bitmap_index = hash[3] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[2] & (BITMAP_SIZE_BITS - 1);
	tmp &= (bitmaps[(BITMAP_SIZE_BITS >> 5) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#else
	bitmap_index = hash[3] & BITMAP_SIZE_BITS_LESS_ONE;
	tmp &= (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
#endif

	if (tmp)
		cmp_final(gid, iter, hash, offset_table, hash_table, return_hashes, output, bitmap_dupe);
}

#define USE_CONST_CACHE \
	((CONST_CACHE_SIZE >= (NUM_INT_KEYS * 4)) && (!IS_STATIC_GPU_MASK))

__kernel void sha1(__global uint *keys,
		  __global uint *index,
		  __global uint *int_key_loc,
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
	uint lid = get_local_id(0);
	uint lws = get_local_size(0);
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint W[16] = { 0 };
	uint temp, A, B, C, D, E;
	uint len = base & 63;
	uint hash[5];
	uint r[16] = {0};

#if __OPENCL_VERSION__ < 120 || (APPLE && gpu_nvidia(DEVICE_INFO))
	if (!gid) {
		out_hash_ids[0] = 0;
		for (i = 0; i < HASH_TABLE_SIZE/32 + 1; i++)
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

#if USE_LOCAL_BITMAPS
	uint __local s_bitmaps[(BITMAP_SIZE_BITS >> 5) * SELECT_CMP_STEPS];

	for(i = 0; i < (((BITMAP_SIZE_BITS >> 5) * SELECT_CMP_STEPS) / lws); i++)
		s_bitmaps[i*lws + lid] = bitmaps[i*lws + lid];

	barrier(CLK_LOCAL_MEM_FENCE);
#endif

	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = SWAP32(*keys++);

	PUTCHAR_BE(W, len, 0x80);
	W[15] = len << 3;

	for (i = 0; i < NUM_INT_KEYS; i++) {
#if NUM_INT_KEYS > 1
		PUTCHAR_BE(W, GPU_LOC_0, (int_keys[i] & 0xff));

#if 1 < MASK_FMT_INT_PLHDR
#if LOC_1 >= 0
		PUTCHAR_BE(W, GPU_LOC_1, ((int_keys[i] & 0xff00) >> 8));
#endif
#endif
#if 2 < MASK_FMT_INT_PLHDR
#if LOC_2 >= 0
		PUTCHAR_BE(W, GPU_LOC_2, ((int_keys[i] & 0xff0000) >> 16));
#endif
#endif
#if 3 < MASK_FMT_INT_PLHDR
#if LOC_3 >= 0
		PUTCHAR_BE(W, GPU_LOC_3, ((int_keys[i] & 0xff000000) >> 24));
#endif
#endif
#endif
		sha1_init(hash);
		sha1_block(W, hash);

		cmp(gid, i, hash,
#if USE_LOCAL_BITMAPS
		    s_bitmaps
#else
		    bitmaps
#endif
		    , offset_table, hash_table, return_hashes, out_hash_ids, bitmap_dupe);
	}
}
