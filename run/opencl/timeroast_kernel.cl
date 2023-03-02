/*
 * This software is Copyright (c) 2023, magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_md4.h"
#include "opencl_md5.h"
#include "opencl_unicode.h"
#include "opencl_mask.h"

inline void md4_crypt(uint *hash, uint *nt_buffer)
{
	md4_single(uint, nt_buffer, hash);
}

inline void md5_crypt(uint *hash, __constant uint *salt)
{
	uint W[16];

	memcpy_macro(W, hash, 4);
	memcpy_macro(W + 4, salt, 12);
	md5_single(uint, W, hash);

	W[0] = 0x80;
	for (uint i = 1; i < 14; i++)
		W[i] = 0;
	W[14] = 64 << 3;
	W[15] = 0;
	md5_block(uint, W, hash);
}

#if __OS_X__ && (cpu(DEVICE_INFO) || gpu_nvidia(DEVICE_INFO))
/* This is a workaround for driver/runtime bugs */
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
#endif

#if UTF_8

inline void prepare_key(__global uint *key, uint length,
                        MAYBE_VOLATILE uint *nt_buffer)
{
	const __global UTF8 *source = (const __global uchar*)key;
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

	nt_buffer[14] = (uint)(target - (UTF16*)nt_buffer) << 4;
}

#else

inline void prepare_key(__global uint *key, uint length, uint *nt_buffer)
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
	nt_buffer[nt_index + 1] = 0;
	nt_buffer[14] = length << 4;
}

#endif /* UTF_8 */

inline void cmp_final(uint gid,
		uint iter,
		uint *hash,
		__global uint *offset_table,
		__global uint *hash_table,
		__constant uint *salt,
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
		uint *hash,
		__global uint *bitmaps,
		uint bitmap_sz_bits,
		__global uint *offset_table,
		__global uint *hash_table,
		__constant uint *salt,
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
__kernel void timeroast(__global uint *keys,
                        __global uint *index,
                        __constant uint *salt
                        , __global uint *int_key_loc,
#if USE_CONST_CACHE
                        __constant
#else
                        __global
#endif
                        uint *int_keys
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
	uint len = base & 127;
	uint hash[4] = {0};
	uint bitmap_sz_bits = salt[12] + 1;

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

	keys += base >> 7;
	prepare_key(keys, len, nt_buffer);

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
		md4_crypt(hash, nt_buffer);
		md5_crypt(hash, salt);

		cmp(gid, i, hash, bitmaps, bitmap_sz_bits, offset_table, hash_table,
		    salt, return_hashes, out_hash_ids, bitmap_dupe);

	}
}
