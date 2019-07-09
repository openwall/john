/*
 * Kerberos 5 AS_REQ Pre-Auth etype 23
 * MD4 + HMAC-MD5 + RC4, with Unicode conversion on GPU
 *
 * Copyright (c) 2013, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"
#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_unicode.h"
#define RC4_IN_PLACE
#include "opencl_rc4.h"
#include "opencl_md4.h"
#include "opencl_md5.h"
#include "opencl_mask.h"

#if __OS_X__ && (cpu(DEVICE_INFO) || gpu_nvidia(DEVICE_INFO))
/* This is a workaround for driver/runtime bugs */
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
#endif

#ifdef UTF_8

inline
void prepare(const __global uint *key, uint length,
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

inline
void prepare(const __global uint *key, uint length, uint *nt_buffer)
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
void krb5pa_md5_final(const uint *K,
                      MAYBE_CONSTANT uint *salts,
#ifdef RC4_USE_LOCAL
                      __local uint *state_l,
#endif
                      uint *K2)
{
	uint i;
	uint block[16];
	uint plain[36/4];
	uchar *cleartext = (uchar*)plain;
	uint K1[4], K3[4], ihash[4];

	/*
	 * K = MD4(UTF-16LE(password)), ordinary 16-byte NTLM hash
	 * 1st HMAC K1 = HMAC-MD5(K, 1LE)
	 */
	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ K[i];
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_single(uint, block, ihash); /* md5_update(ipad, 64) */

	block[0] = 0x01;    /* little endian "one", 4 bytes */
	block[1] = 0x80;
	for (i = 2; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 4) << 3;
	block[15] = 0;
	md5_block(uint, block, ihash); /* md5_update(one, 4), md5_final() */

	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ K[i];
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_single(uint, block, K1); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = ihash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(uint, block, K1); /* md5_update(ihash, 16), md5_final() */


	/*
	 * 2nd HMAC K3 = HMAC-MD5(K1, CHECKSUM)
	 */
	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ K1[i];
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_single(uint, block, ihash); /* md5_update(ipad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = *salts++; /* checksum, 16 bytes */
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(uint, block, ihash); /* md5_update(cs, 16), md5_final() */

	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ K1[i];
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_single(uint, block, K3); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = ihash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(uint, block, K3); /* md5_update(ihash, 16), md5_final() */

	/* Salts now point to encrypted timestamp. */
	for (i = 0; i < 4; i++)
		plain[i] = salts[i];

	/* K3 is our RC4 key. First decrypt just one block for early rejection */
#ifdef RC4_USE_LOCAL
	rc4(state_l, K3, plain, 16);
#else
	rc4(K3, plain, 16);
#endif

	/* Known-plain UTC timestamp */
	if (cleartext[14] == '2' && cleartext[15] == '0') {
		for (i = 0; i < 9; i++)
			plain[i] = salts[i];

#ifdef RC4_USE_LOCAL
		rc4(state_l, K3, plain, 36);
#else
		rc4(K3, plain, 36);
#endif
		if (cleartext[28] == 'Z') {
			/*
			 * 3rd HMAC K2 = HMAC-MD5(K1, plaintext)
			 */
			for (i = 0; i < 4; i++)
				block[i] = 0x36363636 ^ K1[i];
			for (i = 4; i < 16; i++)
				block[i] = 0x36363636;
			md5_single(uint, block, ihash); /* md5_update(ipad, 64) */

			for (i = 0; i < 9; i++)
				block[i] = plain[i]; /* plaintext, 36 bytes */
			block[9] = 0x80;
			for (i = 10; i < 14; i++)
				block[i] = 0;
			block[14] = (64 + 36) << 3;
			block[15] = 0;
			md5_block(uint, block, ihash); /* md5_update(cs, 16), md5_final() */

			for (i = 0; i < 4; i++)
				block[i] = 0x5c5c5c5c ^ K1[i];
			for (i = 4; i < 16; i++)
				block[i] = 0x5c5c5c5c;
			md5_single(uint, block, K2); /* md5_update(opad, 64) */

			for (i = 0; i < 4; i++)
				block[i] = ihash[i];
			block[4] = 0x80;
			for (i = 5; i < 14; i++)
				block[i] = 0;
			block[14] = (64 + 16) << 3;
			block[15] = 0;
			md5_block(uint, block, K2); /* md5_update(ihash, 16), md5_final() */
		}
		else {
			K2[0] = 0;
		}
	}
	else {
		K2[0] = 0;
	}
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

#ifdef RC4_USE_LOCAL
__attribute__((work_group_size_hint(64,1,1)))
#endif
__kernel
void krb5pa_md5(__global const uint *keys,
                __global const uint *index,
                MAYBE_CONSTANT uint *salts,
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
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = base & 127;
	uint nt_buffer[16] = { 0 };
	uint nt_hash[4];
	uint final_hash[4];
	uint i;
#ifdef RC4_USE_LOCAL
	/*
	 * The "+ 1" extra element (actually never touched) give a huge boost
	 * on Maxwell and GCN due to access patterns or whatever.
	 */
	__local uint state_l[64][256/4 + 1];
#endif
	uint bitmap_sz_bits = salts[SALT_PARAM_BASE] + 1;
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

	/* Parse keys input buffer and re-encode to UTF-16LE */
	prepare(keys, len, nt_buffer);

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
		/* Initial hash of password */
		md4_single(uint, nt_buffer, nt_hash);

		/* Final krb5pa-md5 hash */
		krb5pa_md5_final(nt_hash, salts,
#ifdef RC4_USE_LOCAL
		                 state_l[get_local_id(0)],
#endif
		                 final_hash);

		/* GPU-side compare */
		cmp(gid, i, final_hash, bitmaps, bitmap_sz_bits, offset_table,
		    hash_table, salts, return_hashes, out_hash_ids, bitmap_dupe);
	}
}
