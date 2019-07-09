/*
 * NTLMv2
 * MD4 + 2 x HMAC-MD5, with Unicode conversion on GPU
 * Now also featuring GPU-side mask and compare
 *
 * Copyright (c) 2012-2016, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"
#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_md4.h"
#include "opencl_md5.h"
#include "opencl_unicode.h"
#include "opencl_mask.h"

#if __OS_X__ && (cpu(DEVICE_INFO) || gpu_nvidia(DEVICE_INFO))
/* This is a workaround for driver/runtime bugs */
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
#endif

#ifdef UTF_8

inline
void prepare_key(const __global uint *key, uint length,
                 MAYBE_VOLATILE uint *nt_buffer)
{
	const __global UTF8 *source = (const __global uchar*)key;
	const __global UTF8 *sourceEnd = &source[length];
	UTF16 *target = (UTF16*)nt_buffer;
	const UTF16 *targetEnd = &target[PLAINTEXT_LENGTH];
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

inline
void prepare_key(const __global uint *key, uint length, uint *nt_buffer)
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

#endif /* encodings */

inline
void ntlmv2_final(uint *nthash, MAYBE_CONSTANT uint *challenge, uint *output)
{
	uint block[16];
	uint hash[4];
	uint challenge_size;
	uint i;

	/* 1st HMAC */
	md5_init(output);

	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ nthash[i];
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(uint, block, output); /* md5_update(ipad, 64) */

	/* challenge == identity[32].len,server_chal.client_chal[len] */
	/* Salt buffer is prepared with 0x80, zero-padding and length,
	 * it can be one or two blocks */
	for (i = 0; i < 16; i++)
		block[i] = *challenge++;
	md5_block(uint, block, output); /* md5_update(salt, saltlen), md5_final() */

	if (challenge[14]) { /* salt longer than 27 characters */
		for (i = 0; i < 16; i++)
			block[i] = *challenge++;
		md5_block(uint, block, output); /* alternate final */
	} else
		challenge += 16;

	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ nthash[i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(uint, block, output); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(uint, block, output); /* md5_update(hash, 16), md5_final() */

	/* 2nd HMAC */
	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ output[i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(uint, block, output); /* md5_update(ipad, 64) */

	/* Challenge:  blocks (of MD5),
	 * Server Challenge + Client Challenge (Blob) +
	 * 0x80, null padded and len set in get_salt() */
	challenge_size = *challenge++;

	/* At least this will not diverge */
	while (challenge_size--) {
		for (i = 0; i < 16; i++)
			block[i] = *challenge++;
		md5_block(uint, block, output); /* md5_update(challenge, len), md5_final() */
	}

	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ hash[i];
	for (i = 0; i < 4; i++)
		hash[i] = output[i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(uint, block, output); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(uint, block, output); /* md5_update(hash, 16), md5_final() */
}

inline
void cmp_final(uint gid,
               uint iter,
               __private uint *hash,
               __global uint *offset_table,
               __global uint *hash_table,
               MAYBE_CONSTANT uint *salt,
               __global uint *return_hashes,
               volatile __global uint *output,
               volatile __global uint *bitmap_dupe)
{
	uint t, offset_table_index, hash_table_index;
	unsigned long LO, HI;
	unsigned long p;

	HI = ((unsigned long)hash[3] << 32) | (unsigned long)hash[2];
	LO = ((unsigned long)hash[1] << 32) | (unsigned long)hash[0];

	p = (HI % salt[SALT_PARAM_BASE + 1]) * salt[SALT_PARAM_BASE + 3];
	p += LO % salt[SALT_PARAM_BASE + 1];
	p %= salt[SALT_PARAM_BASE + 1];
	offset_table_index = (unsigned int)p;

	//error: chances of overflow is extremely low.
	LO += (unsigned long)offset_table[offset_table_index];

	p = (HI % salt[SALT_PARAM_BASE + 2]) * salt[SALT_PARAM_BASE + 4];
	p += LO % salt[SALT_PARAM_BASE + 2];
	p %= salt[SALT_PARAM_BASE + 2];
	hash_table_index = (unsigned int)p;

	if (hash_table[hash_table_index] == hash[0])
	if (hash_table[salt[SALT_PARAM_BASE + 2] + hash_table_index] == hash[1])
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

inline
void cmp(uint gid,
         uint iter,
         __private uint *hash,
         __global uint *bitmaps,
         uint bitmap_sz_bits,
         __global uint *offset_table,
         __global uint *hash_table,
         MAYBE_CONSTANT uint *salt,
         __global uint *return_hashes,
         volatile __global uint *output,
         volatile __global uint *bitmap_dupe)
{
	uint bitmap_index, tmp = 1;

	bitmap_index = hash[3] & salt[SALT_PARAM_BASE];
	tmp &= (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
	bitmap_index = hash[2] & salt[SALT_PARAM_BASE];
	tmp &= (bitmaps[(bitmap_sz_bits >> 5) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;

	if (tmp)
		cmp_final(gid, iter, hash, offset_table, hash_table, salt, return_hashes, output, bitmap_dupe);
}

__kernel void
ntlmv2(const __global uint *keys,
       __global const uint *index,
       MAYBE_CONSTANT uint *challenge,
       __global uint *int_key_loc,
#if USE_CONST_CACHE
       __constant
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
	uint nt_buffer[16] = { 0 };
	uint nthash[4];
	uint hash[4];
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = base & 127;
	uint i;
	uint bitmap_sz_bits = challenge[SALT_PARAM_BASE] + 1;
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

	/* Parse keys input buffer and re-encode to UTF-16LE */
	keys += base >> 7;
	prepare_key(keys, len, nt_buffer);

	/* Apply GPU-side mask */
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

		/* Initial NT hash of password */
		md4_init(nthash);
		md4_block(uint, nt_buffer, nthash);

		/* Final hashing */
		ntlmv2_final(nthash, challenge, hash);

		/* GPU-side compare */
		cmp(gid, i, hash, bitmaps, bitmap_sz_bits, offset_table, hash_table,
		    challenge, return_hashes, out_hash_ids, bitmap_dupe);
	}
}
