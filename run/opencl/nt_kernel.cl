/* NTLM kernel (OpenCL 1.2 conformant)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2010 and modified by
 * Samuele Giovanni Tonon in 2011. No copyright is claimed, and
 * the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2010 Alain Espinosa
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * Copyright (c) 2015 Sayantan Datta <sdatta at openwall.com>
 * Copyright (c) 2015 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_md4.h"
#include "opencl_unicode.h"
#include "opencl_mask.h"

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#if BITMAP_SIZE_BITS_LESS_ONE < 0xffffffff
#define BITMAP_SIZE_BITS (BITMAP_SIZE_BITS_LESS_ONE + 1)
#else
#error BITMAP_SIZE_BITS_LESS_ONE too large
#endif

inline void nt_crypt(__private uint *hash, __private uint *nt_buffer, uint md4_size) {
	uint tmp;

	/* Round 1 */
	hash[0] = 0xFFFFFFFF + nt_buffer[0]; hash[0]=rotate(hash[0], 3u);
	hash[3] = INIT_D + (INIT_C ^ (hash[0] & 0x77777777)) + nt_buffer[1]; hash[3]=rotate(hash[3], 7u);
	hash[2] = INIT_C + MD4_F(hash[3], hash[0], INIT_B)   + nt_buffer[2]; hash[2]=rotate(hash[2], 11u);
	hash[1] = INIT_B + MD4_F(hash[2], hash[3], hash[0])  + nt_buffer[3]; hash[1]=rotate(hash[1], 19u);

	hash[0] += MD4_F(hash[1], hash[2], hash[3])  +  nt_buffer[4] ; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_F(hash[0], hash[1], hash[2])  +  nt_buffer[5] ; hash[3] = rotate(hash[3] , 7u );
	hash[2] += MD4_F(hash[3], hash[0], hash[1])  +  nt_buffer[6] ; hash[2] = rotate(hash[2] , 11u);
	hash[1] += MD4_F(hash[2], hash[3], hash[0])  +  nt_buffer[7] ; hash[1] = rotate(hash[1] , 19u);

	hash[0] += MD4_F(hash[1], hash[2], hash[3])  +  nt_buffer[8] ; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_F(hash[0], hash[1], hash[2])  +  nt_buffer[9] ; hash[3] = rotate(hash[3] , 7u );
	hash[2] += MD4_F(hash[3], hash[0], hash[1])  +  nt_buffer[10]; hash[2] = rotate(hash[2] , 11u);
	hash[1] += MD4_F(hash[2], hash[3], hash[0])  +  nt_buffer[11]; hash[1] = rotate(hash[1] , 19u);

	hash[0] += MD4_F(hash[1], hash[2], hash[3])  +  nt_buffer[12]; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_F(hash[0], hash[1], hash[2])  +  nt_buffer[13]; hash[3] = rotate(hash[3] , 7u );
	hash[2] += MD4_F(hash[3], hash[0], hash[1])  +    md4_size   ; hash[2] = rotate(hash[2] , 11u);
	hash[1] += MD4_F(hash[2], hash[3], hash[0])                  ; hash[1] = rotate(hash[1] , 19u);

	/* Round 2 */

	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[0] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[4] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[8] + SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[12]+ SQRT_2; hash[1] = rotate(hash[1] , 13u);

	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[1] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[5] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[9] + SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[13]+ SQRT_2; hash[1] = rotate(hash[1] , 13u);

	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[2] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[6] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[10]+ SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) +   md4_size   + SQRT_2; hash[1] = rotate(hash[1] , 13u);

	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[3] + SQRT_2; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[7] + SQRT_2; hash[3] = rotate(hash[3] , 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[11]+ SQRT_2; hash[2] = rotate(hash[2] , 9u );
	hash[1] += MD4_G(hash[2], hash[3], hash[0])                + SQRT_2; hash[1] = rotate(hash[1] , 13u);

	/* Round 3 */
	hash[0] += MD4_H(hash[1], hash[2], hash[3]) + nt_buffer[0]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[8]  + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += MD4_H(hash[3], hash[0], hash[1]) + nt_buffer[4]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);
	hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[12] + SQRT_3; hash[1] = rotate(hash[1] , 15u);

	hash[0] += MD4_H(hash[1], hash[2], hash[3]) + nt_buffer[2]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[10] + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += MD4_H(hash[3], hash[0], hash[1]) + nt_buffer[6]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);
	hash[1] += MD4_H2(hash[2], hash[3], hash[0]) +   md4_size    + SQRT_3; hash[1] = rotate(hash[1] , 15u);

	hash[0] += MD4_H(hash[1], hash[2], hash[3]) + nt_buffer[1]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[9]  + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += MD4_H(hash[3], hash[0], hash[1]) + nt_buffer[5]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);
	//It is better to calculate this remining steps that access global memory
	hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[13];
	tmp = hash[1];
	tmp += SQRT_3; tmp = rotate(tmp , 15u);

	hash[0] += MD4_H(hash[3], hash[2], tmp) + nt_buffer[3]  + SQRT_3; hash[0] = rotate(hash[0] , 3u );
	hash[3] += MD4_H2(hash[2], tmp, hash[0]) + nt_buffer[11] + SQRT_3; hash[3] = rotate(hash[3] , 9u );
	hash[2] += MD4_H(tmp, hash[0], hash[3]) + nt_buffer[7]  + SQRT_3; hash[2] = rotate(hash[2] , 11u);
}

#if __OS_X__ && (cpu(DEVICE_INFO) || gpu_nvidia(DEVICE_INFO))
/* This is a workaround for driver/runtime bugs */
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
#endif

#if UTF_8

inline uint prepare_key(__global uint *key, uint length,
                        MAYBE_VOLATILE uint *nt_buffer)
{
	const __global UTF8 *source = (const __global UTF8*)key;
	const __global UTF8 *sourceEnd = &source[length];
	MAYBE_VOLATILE UTF16 *target = (UTF16*)nt_buffer;
	MAYBE_VOLATILE const UTF16 *targetEnd = &target[PLAINTEXT_LENGTH];
	UTF32 ch;
	uint extraBytesToRead;

	/* Input buffer is UTF-8 without zero-termination */
	while (source < sourceEnd) {
		if (*source < 0xC0) {
			*target++ = (UTF16)*source++;
			if (target >= targetEnd)
				break;
			continue;
		}
		ch = *source;
		// This point must not be reached with *source < 0xC0
		extraBytesToRead =
			opt_trailingBytesUTF8[ch & 0x3f];
		if (source + extraBytesToRead >= sourceEnd) {
			break;
		}
		switch (extraBytesToRead) {
		case 3:
			ch <<= 6;
			ch += *++source;
		case 2:
			ch <<= 6;
			ch += *++source;
		case 1:
			ch <<= 6;
			ch += *++source;
			++source;
			break;
		default:
			*target = UNI_REPLACEMENT_CHAR;
			break; // from switch
		}
		if (*target == UNI_REPLACEMENT_CHAR)
			break; // from while
		ch -= offsetsFromUTF8[extraBytesToRead];
#ifdef UCS_2
		/* UCS-2 only */
		*target++ = (UTF16)ch;
#else
		/* full UTF-16 with surrogate pairs */
		if (ch <= UNI_MAX_BMP) {  /* Target is a character <= 0xFFFF */
			*target++ = (UTF16)ch;
		} else {  /* target is a character in range 0xFFFF - 0x10FFFF. */
			if (target + 1 >= targetEnd)
				break;
			ch -= halfBase;
			*target++ = (UTF16)((ch >> halfShift) + UNI_SUR_HIGH_START);
			*target++ = (UTF16)((ch & halfMask) + UNI_SUR_LOW_START);
		}
#endif
		if (target >= targetEnd)
			break;
	}
	*target = 0x80;	// Terminate

	return (uint)(target - (UTF16*)nt_buffer);
}

#else

inline uint prepare_key(__global uint *key, uint length, uint *nt_buffer)
{
	uint i, nt_index, keychars;

	nt_index = 0;
	for (i = 0; i < (length + 3)/ 4; i++) {
		keychars = key[i];
		nt_buffer[nt_index++] = CP_LUT(keychars & 0x000000FF) | (CP_LUT((keychars & 0x0000FF00) >> 8) << 16);
		nt_buffer[nt_index++] = CP_LUT((keychars & 0x00FF0000) >> 16) | (CP_LUT(keychars >> 24) << 16);
	}
	nt_index = length >> 1;
	nt_buffer[nt_index] = (nt_buffer[nt_index] & 0xFFFF) | (0x80 << ((length & 1) << 4));

	return length;
}

#endif /* UTF_8 */

inline void cmp_final(uint gid,
		uint iter,
		__private uint *hash,
		__global uint *offset_table,
		__global uint *hash_table,
		__global uint *return_hashes,
		volatile __global uint *output,
		volatile __global uint *bitmap_dupe) {

	uint t, offset_table_index, hash_table_index;
	unsigned long LO, HI;
	unsigned long p;

	HI = ((unsigned long)hash[3] << 32) | (unsigned long)hash[2];
	LO = ((unsigned long)hash[1] << 32) | (unsigned long)hash[0];

	p = (HI % OFFSET_TABLE_SIZE) * SHIFT64_OT_SZ;
	p += LO % OFFSET_TABLE_SIZE;
	p %= OFFSET_TABLE_SIZE;
	offset_table_index = (unsigned int)p;

	//error: chances of overflow is extremely low.
	LO += (unsigned long)offset_table[offset_table_index];

	p = (HI % HASH_TABLE_SIZE) * SHIFT64_HT_SZ;
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

/*	hash[0] += 0x67452301;
	hash[1] += 0xefcdab89;
	hash[2] += 0x98badcfe;
	hash[3] += 0x10325476;*/

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
	(CONST_CACHE_SIZE >= (NUM_INT_KEYS * 4))

/* OpenCL kernel entry point. Copy key to be hashed from
 * global to local (thread) memory. Break the key into 16 32-bit (uint)
 * words. MD4 hash of a key is 128 bit (uint4). */
__kernel void nt(__global uint *keys,
		  __global uint *index,
		  __global uint *int_key_loc,
#if USE_CONST_CACHE
		  constant
#else
		  __global
#endif
		  uint *int_keys
#if !defined(__OS_X__) && USE_CONST_CACHE && gpu_amd(DEVICE_INFO)
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
	uint nt_buffer[14] = { 0 };
	uint md4_size = base & 127;
	uint hash[4];

#if NUM_INT_KEYS > 1 && !IS_STATIC_GPU_MASK
	uint ikl = int_key_loc[gid];
	uint loc0 = ikl & 0xff;
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
	uint loc1 = (ikl & 0xff00) >> 8;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
	uint loc2 = (ikl & 0xff0000) >> 16;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
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
	uint lid = get_local_id(0);
	uint lws = get_local_size(0);
	uint __local s_bitmaps[(BITMAP_SIZE_BITS >> 5) * SELECT_CMP_STEPS];

	for (i = 0; i < (((BITMAP_SIZE_BITS >> 5) * SELECT_CMP_STEPS) / lws); i++)
		s_bitmaps[i*lws + lid] = bitmaps[i*lws + lid];

	barrier(CLK_LOCAL_MEM_FENCE);
#endif

	keys += base >> 7;
	md4_size = prepare_key(keys, md4_size, nt_buffer);
	md4_size = md4_size << 4;

	for (i = 0; i < NUM_INT_KEYS; i++) {
#if NUM_INT_KEYS > 1
		PUTSHORT(nt_buffer, GPU_LOC_0, CP_LUT(int_keys[i] & 0xff));
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
		PUTSHORT(nt_buffer, GPU_LOC_1, CP_LUT((int_keys[i] & 0xff00) >> 8));
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
		PUTSHORT(nt_buffer, GPU_LOC_2, CP_LUT((int_keys[i] & 0xff0000) >> 16));
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
		PUTSHORT(nt_buffer, GPU_LOC_3, CP_LUT((int_keys[i] & 0xff000000) >> 24));
#endif
#endif
#endif
		nt_crypt(hash, nt_buffer, md4_size);
		cmp(gid, i, hash,
#if USE_LOCAL_BITMAPS
		    s_bitmaps
#else
		    bitmaps
#endif
		    , offset_table, hash_table, return_hashes, out_hash_ids, bitmap_dupe);
	}
}
