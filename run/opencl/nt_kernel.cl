/*
 * NTLM kernel (OpenCL 1.2 conformant)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2010 and modified by
 * Samuele Giovanni Tonon in 2011. No copyright is claimed, and
 * the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2010 Alain Espinosa
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * Copyright (c) 2015 Sayantan Datta <sdatta at openwall.com>
 * Copyright (c) 2015-2023 magnum
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

/*
 * If enabled, will check bitmap after calculating just the
 * first 32 bits of 'b' (does not apply to nt-long-opencl).
 */
#define EARLY_REJECT	1

#if USE_LOCAL_BITMAPS
#define BITMAPS_TYPE	__local
#else
#define BITMAPS_TYPE	__global
#endif

#define USE_CONST_CACHE \
	(CONST_CACHE_SIZE >= (NUM_INT_KEYS * 4))

#if USE_CONST_CACHE
#define CACHE_TYPE	__constant
#else
#define CACHE_TYPE	__global
#endif

/* This handles an input of 0xffffffffU correctly */
#define BITMAP_SHIFT ((BITMAP_MASK >> 5) + 1)

inline int nt_crypt(uint *hash, uint *nt_buffer, uint md4_size, BITMAPS_TYPE uint *bitmaps)
{
	MD4_G_VARS

	/* Round 1 */
	hash[0] = 0xFFFFFFFF + nt_buffer[0] ; hash[0] = rotate(hash[0], 3u);
	hash[3] = INIT_D + (INIT_C ^ (hash[0] & 0x77777777)) + nt_buffer[1] ; hash[3] = rotate(hash[3], 7u );
	hash[2] = INIT_C + MD4_F(hash[3], hash[0], INIT_B)   + nt_buffer[2] ; hash[2] = rotate(hash[2], 11u);
	hash[1] = INIT_B + MD4_F(hash[2], hash[3], hash[0])  + nt_buffer[3] ; hash[1] = rotate(hash[1], 19u);

	hash[0] += MD4_F(hash[1], hash[2], hash[3]) + nt_buffer[4]  ; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_F(hash[0], hash[1], hash[2]) + nt_buffer[5]  ; hash[3] = rotate(hash[3], 7u );
	hash[2] += MD4_F(hash[3], hash[0], hash[1]) + nt_buffer[6]  ; hash[2] = rotate(hash[2], 11u);
	hash[1] += MD4_F(hash[2], hash[3], hash[0]) + nt_buffer[7]  ; hash[1] = rotate(hash[1], 19u);

	hash[0] += MD4_F(hash[1], hash[2], hash[3]) + nt_buffer[8]  ; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_F(hash[0], hash[1], hash[2]) + nt_buffer[9]  ; hash[3] = rotate(hash[3], 7u );
	hash[2] += MD4_F(hash[3], hash[0], hash[1]) + nt_buffer[10] ; hash[2] = rotate(hash[2], 11u);
	hash[1] += MD4_F(hash[2], hash[3], hash[0]) + nt_buffer[11] ; hash[1] = rotate(hash[1], 19u);

	hash[0] += MD4_F(hash[1], hash[2], hash[3]) + nt_buffer[12] ; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_F(hash[0], hash[1], hash[2]) + nt_buffer[13] ; hash[3] = rotate(hash[3], 7u );
#if PLAINTEXT_LENGTH > 27
	hash[2] += MD4_F(hash[3], hash[0], hash[1]) + nt_buffer[14] ; hash[2] = rotate(hash[2], 11u);
	hash[1] += MD4_F(hash[2], hash[3], hash[0]) + nt_buffer[15] ; hash[1] = rotate(hash[1], 19u);
#else
	hash[2] += MD4_F(hash[3], hash[0], hash[1]) + md4_size      ; hash[2] = rotate(hash[2], 11u);
	hash[1] += MD4_F(hash[2], hash[3], hash[0])                 ; hash[1] = rotate(hash[1], 19u);
#endif

	MD4_G_CACHE_NT

	/* Round 2 */
	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[0]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[4]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[8]  + SQRT_2; hash[2] = rotate(hash[2], 9u );
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[12] + SQRT_2; hash[1] = rotate(hash[1], 13u);

	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[1]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[5]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[9]  + SQRT_2; hash[2] = rotate(hash[2], 9u );
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[13] + SQRT_2; hash[1] = rotate(hash[1], 13u);

	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[2]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[6]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[10] + SQRT_2; hash[2] = rotate(hash[2], 9u );
#if PLAINTEXT_LENGTH > 27
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[14] + SQRT_2; hash[1] = rotate(hash[1], 13u);
#else
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) + md4_size      + SQRT_2; hash[1] = rotate(hash[1], 13u);
#endif
	hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[3]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[7]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
	hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[11] + SQRT_2; hash[2] = rotate(hash[2], 9u );
#if PLAINTEXT_LENGTH > 27
	hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[15] + SQRT_2; hash[1] = rotate(hash[1], 13u);
#else
	hash[1] += MD4_G(hash[2], hash[3], hash[0])                 + SQRT_2; hash[1] = rotate(hash[1], 13u);
#endif

	/* Round 3 */
	hash[0] += MD4_H (hash[1], hash[2], hash[3]) + nt_buffer[0]  + SQRT_3; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[8]  + SQRT_3; hash[3] = rotate(hash[3], 9u );
	hash[2] += MD4_H (hash[3], hash[0], hash[1]) + nt_buffer[4]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
	hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[12] + SQRT_3; hash[1] = rotate(hash[1], 15u);

	hash[0] += MD4_H (hash[1], hash[2], hash[3]) + nt_buffer[2]  + SQRT_3; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[10] + SQRT_3; hash[3] = rotate(hash[3], 9u );
	hash[2] += MD4_H (hash[3], hash[0], hash[1]) + nt_buffer[6]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
#if PLAINTEXT_LENGTH > 27
	hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[14] + SQRT_3; hash[1] = rotate(hash[1], 15u);
#else
	hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + md4_size      + SQRT_3; hash[1] = rotate(hash[1], 15u);
#endif
	hash[0] += MD4_H (hash[1], hash[2], hash[3]) + nt_buffer[1]  + SQRT_3; hash[0] = rotate(hash[0], 3u );
	hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[9]  + SQRT_3; hash[3] = rotate(hash[3], 9u );
	hash[2] += MD4_H (hash[3], hash[0], hash[1]) + nt_buffer[5]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
	hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[13];

#if EARLY_REJECT && PLAINTEXT_LENGTH <= 27
	uint bitmap_index = hash[1] & BITMAP_MASK;
	uint tmp = (bitmaps[BITMAP_SHIFT * 0 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#if SELECT_CMP_STEPS == 8
	bitmap_index = (hash[1] >> 8) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 1 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[1] >> 16) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 2 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[1] >> 24) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 3 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#elif SELECT_CMP_STEPS == 4
	bitmap_index = (hash[1] >> 16) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 1 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#endif	/* SELECT_CMP_STEPS == 8 */
	if (likely(!tmp))
		return 0;
#endif	/* EARLY_REJECT && PLAINTEXT_LENGTH <= 27 */

	uint hash1 = hash[1] + SQRT_3; hash1 = rotate(hash1, 15u);

	hash[0] += MD4_H (hash[3], hash[2], hash1  ) + nt_buffer[3]  + SQRT_3; hash[0] = rotate(hash[0], 3u );

#if PLAINTEXT_LENGTH > 27
	if (likely(md4_size <= (27 << 4)))
		return 1;

	/*
	 * Complete the first of a multi-block MD4 (reversing steps not possible).
	 */
	hash[3] +=        MD4_H2(hash[2], hash1,   hash[0]) + nt_buffer[11] + SQRT_3; hash[3] = rotate(hash[3], 9u );
	hash[2] +=        MD4_H (hash1,   hash[0], hash[3]) + nt_buffer[7]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
	hash[1] = hash1 + MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[15] + SQRT_3; hash[1] = rotate(hash[1], 15u);
	hash[0] += INIT_A;
	hash[1] += INIT_B;
	hash[2] += INIT_C;
	hash[3] += INIT_D;

#if PLAINTEXT_LENGTH > 59
	uint blocks = ((md4_size >> 4) + 5 + 31) / 32;
	while (--blocks)
#endif
	{
		nt_buffer += 16;

		uint a = hash[0];
		uint b = hash[1];
		uint c = hash[2];
		uint d = hash[3];

		hash[0] += MD4_F(hash[1], hash[2], hash[3]) + nt_buffer[0]  ; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_F(hash[0], hash[1], hash[2]) + nt_buffer[1]  ; hash[3] = rotate(hash[3], 7u );
		hash[2] += MD4_F(hash[3], hash[0], hash[1]) + nt_buffer[2]  ; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_F(hash[2], hash[3], hash[0]) + nt_buffer[3]  ; hash[1] = rotate(hash[1], 19u);

		hash[0] += MD4_F(hash[1], hash[2], hash[3]) + nt_buffer[4]  ; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_F(hash[0], hash[1], hash[2]) + nt_buffer[5]  ; hash[3] = rotate(hash[3], 7u );
		hash[2] += MD4_F(hash[3], hash[0], hash[1]) + nt_buffer[6]  ; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_F(hash[2], hash[3], hash[0]) + nt_buffer[7]  ; hash[1] = rotate(hash[1], 19u);

		hash[0] += MD4_F(hash[1], hash[2], hash[3]) + nt_buffer[8]  ; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_F(hash[0], hash[1], hash[2]) + nt_buffer[9]  ; hash[3] = rotate(hash[3], 7u );
		hash[2] += MD4_F(hash[3], hash[0], hash[1]) + nt_buffer[10] ; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_F(hash[2], hash[3], hash[0]) + nt_buffer[11] ; hash[1] = rotate(hash[1], 19u);

		hash[0] += MD4_F(hash[1], hash[2], hash[3]) + nt_buffer[12] ; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_F(hash[0], hash[1], hash[2]) + nt_buffer[13] ; hash[3] = rotate(hash[3], 7u );
		hash[2] += MD4_F(hash[3], hash[0], hash[1]) + nt_buffer[14] ; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_F(hash[2], hash[3], hash[0]) + nt_buffer[15] ; hash[1] = rotate(hash[1], 19u);

		MD4_G_CACHE_NT

		/* Round 2 */
		hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[0]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[4]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
		hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[8]  + SQRT_2; hash[2] = rotate(hash[2], 9u );
		hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[12] + SQRT_2; hash[1] = rotate(hash[1], 13u);

		hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[1]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[5]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
		hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[9]  + SQRT_2; hash[2] = rotate(hash[2], 9u );
		hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[13] + SQRT_2; hash[1] = rotate(hash[1], 13u);

		hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[2]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[6]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
		hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[10] + SQRT_2; hash[2] = rotate(hash[2], 9u );
		hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[14] + SQRT_2; hash[1] = rotate(hash[1], 13u);

		hash[0] += MD4_G(hash[1], hash[2], hash[3]) + nt_buffer[3]  + SQRT_2; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_G(hash[0], hash[1], hash[2]) + nt_buffer[7]  + SQRT_2; hash[3] = rotate(hash[3], 5u );
		hash[2] += MD4_G(hash[3], hash[0], hash[1]) + nt_buffer[11] + SQRT_2; hash[2] = rotate(hash[2], 9u );
		hash[1] += MD4_G(hash[2], hash[3], hash[0]) + nt_buffer[15] + SQRT_2; hash[1] = rotate(hash[1], 13u);

		/* Round 3 */
		hash[0] += MD4_H (hash[1], hash[2], hash[3]) + nt_buffer[0]  + SQRT_3; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[8]  + SQRT_3; hash[3] = rotate(hash[3], 9u );
		hash[2] += MD4_H (hash[3], hash[0], hash[1]) + nt_buffer[4]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[12] + SQRT_3; hash[1] = rotate(hash[1], 15u);

		hash[0] += MD4_H (hash[1], hash[2], hash[3]) + nt_buffer[2]  + SQRT_3; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[10] + SQRT_3; hash[3] = rotate(hash[3], 9u );
		hash[2] += MD4_H (hash[3], hash[0], hash[1]) + nt_buffer[6]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[14] + SQRT_3; hash[1] = rotate(hash[1], 15u);

		hash[0] += MD4_H (hash[1], hash[2], hash[3]) + nt_buffer[1]  + SQRT_3; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_H2(hash[0], hash[1], hash[2]) + nt_buffer[9]  + SQRT_3; hash[3] = rotate(hash[3], 9u );
		hash[2] += MD4_H (hash[3], hash[0], hash[1]) + nt_buffer[5]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[13] + SQRT_3; hash[1] = rotate(hash[1], 15u);

		hash[0] += MD4_H (hash[3], hash[2], hash[1]) + nt_buffer[3]  + SQRT_3; hash[0] = rotate(hash[0], 3u );
		hash[3] += MD4_H2(hash[2], hash[1], hash[0]) + nt_buffer[11] + SQRT_3; hash[3] = rotate(hash[3], 9u );
		hash[2] += MD4_H (hash[1], hash[0], hash[3]) + nt_buffer[7]  + SQRT_3; hash[2] = rotate(hash[2], 11u);
		hash[1] += MD4_H2(hash[2], hash[3], hash[0]) + nt_buffer[15] + SQRT_3; hash[1] = rotate(hash[1], 15u);

		hash[0] += a;
		hash[1] += b;
		hash[2] += c;
		hash[3] += d;
	}

	/*
	 * This bogus reverse adds a little work to long crypts instead
	 * of losing the real reverse for single block crypts.
	 */
	hash[3] -= INIT_D;
	hash[2] -= INIT_C;
	hash[1] -= INIT_B;
	hash[0] -= INIT_A;
	hash[1]  = (hash[1] >> 15) | (hash[1] << 17);
	hash[1] -= SQRT_3 + MD4_H2(hash[2], hash[3], hash[0]);
	hash[1]  = rotate(hash[1], -15u);
	hash[1] -= SQRT_3;
#endif
	return 1;
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
                      uint *hash,
                      __global uint *offset_table,
                      __global uint *hash_table,
                      volatile __global uint *output,
                      volatile __global uint *bitmap_dupe)
{
	uint t, hash_table_index;
	ulong hash64;

	hash64 = ((ulong)hash[1] << 32) | (ulong)hash[0];
	hash64 += (ulong)offset_table[hash64 % OFFSET_TABLE_SIZE];
	hash_table_index = hash64 % HASH_TABLE_SIZE;

	if (hash_table[hash_table_index] == hash[0] &&
	    hash_table[hash_table_index + HASH_TABLE_SIZE] == hash[1]) {
		/*
		 * Prevent duplicate keys from cracking same hash
		 */
		if (!(atomic_or(&bitmap_dupe[hash_table_index / 32],
		                (1U << (hash_table_index % 32))) & (1U << (hash_table_index % 32)))) {
			t = atomic_inc(&output[0]);
			output[3 * t + 1] = gid;
			output[3 * t + 2] = iter;
			output[3 * t + 3] = hash_table_index;
		}
	}
}

inline void cmp(uint gid,
                uint iter,
                uint *hash,
                BITMAPS_TYPE uint *bitmaps,
                __global uint *offset_table,
                __global uint *hash_table,
                volatile __global uint *output,
                volatile __global uint *bitmap_dupe)
{
	uint bitmap_index, tmp = 1;

#if SELECT_CMP_STEPS == 8
#if !EARLY_REJECT || PLAINTEXT_LENGTH > 27
	bitmap_index = hash[1] & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 0 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[1] >> 8) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 1 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[1] >> 16) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 2 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[1] >> 24) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 3 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#endif
	bitmap_index = hash[0] & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 4 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[0] >> 8) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 5 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[0] >> 16) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 6 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[0] >> 24) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 7 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;

#elif SELECT_CMP_STEPS == 4
#if !EARLY_REJECT || PLAINTEXT_LENGTH > 27
	bitmap_index = hash[1] & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 0 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[1] >> 16) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 1 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#endif
	bitmap_index = hash[0] & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 2 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
	bitmap_index = (hash[0] >> 16) & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 3 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;

#elif SELECT_CMP_STEPS == 2
#if !EARLY_REJECT || PLAINTEXT_LENGTH > 27
	bitmap_index = hash[1] & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 0 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#endif
	bitmap_index = hash[0] & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 1 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;

#elif !EARLY_REJECT || PLAINTEXT_LENGTH > 27 /* SELECT_CMP_STEPS == 1 */
	bitmap_index = hash[1] & BITMAP_MASK;
	tmp &= (bitmaps[BITMAP_SHIFT * 0 + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;

#endif	/* SELECT_CMP_STEPS == 8 */

	if (tmp)
		cmp_final(gid, iter, hash, offset_table, hash_table, output, bitmap_dupe);
}

/*
 * OpenCL kernel entry point. Break the key into 16 32-bit (uint)
 * words. MD4 hash of a key is 128 bits but we only do 64 bits here, and
 * reverse steps where possible.
 */
__kernel void nt(__global uint *keys,
                 __global uint *index,
                 __global uint *int_key_loc,
                 CACHE_TYPE uint *int_keys,
                 __global uint *bitmaps,
                 __global uint *offset_table,
                 __global uint *hash_table,
                 volatile __global uint *out_hash_ids,
                 volatile __global uint *bitmap_dupe)
{
	uint i;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint nt_buffer[(PLAINTEXT_LENGTH + 5 + 31) / 32 * 16] = { 0 };
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
	__local uint s_bitmaps[BITMAP_SHIFT * SELECT_CMP_STEPS];

	for (i = lid; i < BITMAP_SHIFT * SELECT_CMP_STEPS; i+= lws)
		s_bitmaps[i] = bitmaps[i];

	barrier(CLK_LOCAL_MEM_FENCE);

#define BITMAPS	s_bitmaps
#else
#define BITMAPS	bitmaps
#endif

	keys += base >> 7;
	md4_size = prepare_key(keys, md4_size, nt_buffer);

	/* Put the length word in the correct place in buffer, outside the loop */
	uint size_idx = ((md4_size + 5 + 31) / 32 - 1) * 16 + 14;
	md4_size <<= 4;
	nt_buffer[size_idx] = md4_size;

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
		if (nt_crypt(hash, nt_buffer, md4_size, BITMAPS))
			cmp(gid, i, hash, BITMAPS, offset_table, hash_table, out_hash_ids, bitmap_dupe);
	}
}
