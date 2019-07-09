/*
 * Office 97-2003
 * MD5 + RC4, with Unicode conversion on GPU
 *
 * Copyright (c) 2014, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_unicode.h"
#if DEV_VER_MAJOR < 1912
#define AMD_PUTCHAR_NOCAST /* AMD bug workaround */
#endif
#include "opencl_misc.h"
#define RC4_IN_PLACE
#include "opencl_rc4.h"
#include "opencl_md5.h"
#include "opencl_sha1.h"
#include "opencl_mask.h"

typedef struct {
	dyna_salt dsalt;
	int type;
	uint salt[16/4];
	uint verifier[16/4]; /* or encryptedVerifier */
	uint verifierHash[20/4];  /* or encryptedVerifierHash */
	volatile uint has_mitm;
	volatile uint cracked;
	uint mitm[8/4]; /* Meet-in-the-middle hint, if we have one */
} salt_t;

typedef struct {
	uint len;
	ushort password[PLAINTEXT_LENGTH + 1];
} nt_buffer_t;

#ifdef UTF_8

inline
void oldoffice_utf16(__global const uchar *source,
                     __global const uint *index,
                     nt_buffer_t *nt_buffer)
{
	uint gid = get_global_id(0);
	uint base = index[gid];
	__global const UTF8 *sourceEnd;
	UTF16 *target = nt_buffer->password;
	UTF16 *targetStart = target;
	const UTF16 *targetEnd = &target[PLAINTEXT_LENGTH];
	UTF32 ch;
	uint extraBytesToRead;

	sourceEnd = source + index[gid + 1];
	source += base;

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

	*target = 0;
	nt_buffer->len = (uint)(target - targetStart);
}

#else

inline
void oldoffice_utf16(__global const uchar *password,
                     __global const uint *index,
                     nt_buffer_t *nt_buffer)
{
	uint i;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	/* Input buffer is in a 'codepage' encoding, without zero-termination */
	for (i = 0; i < len; i++)
		nt_buffer->password[i] = CP_LUT(password[i]);

	nt_buffer->password[i] = 0;
	nt_buffer->len = len;
}

#endif /* encodings */

#if __OS_X__ && gpu_amd(DEVICE_INFO)
/* This is a workaround for driver/runtime bugs */
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
#endif

inline
void oldoffice_md5(const nt_buffer_t *nt_buffer,
                   __global salt_t *cs,
                   __global uint *result,
#ifdef RC4_USE_LOCAL
                   __local uint *state_l,
#endif
                   __global uint *benchmark)
{
	uint i;
	uint W[64/4];
	uint verifier[32/4];
	uint md5[16/4];
	uint key[16/4];
	uint len = nt_buffer->len;
	uint salt[16/4];
	const ushort *p = nt_buffer->password;

	/* Initial hash of password */
#if PLAINTEXT_LENGTH > 27
	md5_init(md5);
#endif
#if PLAINTEXT_LENGTH > 31
	if (len > 31) {
		for (i = 0; i < 32; i += 2) {
			W[i >> 1] = (uint)*p++;
			W[i >> 1] |= (*p++ << 16U);
		}
		md5_block(uint, W, md5);
		for (i = 0; i < len - 32; i += 2) {
			W[i >> 1] = (uint)*p++;
			W[i >> 1] |= (*p++ << 16U);
		}
		PUTSHORT(W, i, 0x80);
		i++;
		for (; i < 28; i++)
			PUTSHORT(W, i, 0);
		W[14] = len << 4;
		W[15] = 0;
		md5_block(uint, W, md5);
	} else
#endif
#if PLAINTEXT_LENGTH > 27
	if (len > 27) {
		for (i = 0; i < len; i += 2) {
			W[i >> 1] = (uint)*p++;
			W[i >> 1] |= (*p++ << 16U);
		}
		PUTSHORT(W, i, 0x80);
		for (i = len + 1; i < 32; i++)
			PUTSHORT(W, i, 0);
		md5_block(uint, W, md5);
		for (i = 0; i < 14; i++)
			W[i] = 0;
		W[14] = len << 4;
		W[15] = 0;
		md5_block(uint, W, md5);
	} else
#endif
	{
		for (i = 0; i < len; i += 2) {
			W[i >> 1] = (uint)*p++;
			W[i >> 1] |= (*p++ << 16U);
		}
		PUTSHORT(W, len, 0x80);
		for (i = len + 1; i < 28; i++)
			PUTSHORT(W, i, 0);
		W[14] = len << 4;
		W[15] = 0;
#if PLAINTEXT_LENGTH > 27
		md5_block(uint, W, md5);
#else
		md5_single(uint, W, md5);
#endif
	}

	for (i = 0; i < 4; i++)
		salt[i] = cs->salt[i];

	W[0] = md5[0];
	PUTCHAR(W, 4, GETCHAR(md5, 4));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 5, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 21, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 26, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 42, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 47, GETCHAR(salt, i));
	PUTCHAR(W, 63, GETCHAR(md5, 0));
	md5_single(uint, W, key);
	for (i = 1; i < 5; i++)
		PUTCHAR(W, i - 1, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 4, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 20, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 25, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 41, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 46, GETCHAR(salt, i));
	PUTCHAR(W, 62, GETCHAR(md5, 0));
	PUTCHAR(W, 63, GETCHAR(md5, 1));
	md5_block(uint, W, key);
	for (i = 2; i < 5; i++)
		PUTCHAR(W, i - 2, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 3, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 19, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 24, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 40, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 45, GETCHAR(salt, i));
	PUTCHAR(W, 61, GETCHAR(md5, 0));
	PUTCHAR(W, 62, GETCHAR(md5, 1));
	PUTCHAR(W, 63, GETCHAR(md5, 2));
	md5_block(uint, W, key);
	for (i = 3; i < 5; i++)
		PUTCHAR(W, i - 3, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 2, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 18, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 23, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 39, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 44, GETCHAR(salt, i));
	PUTCHAR(W, 60, GETCHAR(md5, 0));
	PUTCHAR(W, 61, GETCHAR(md5, 1));
	PUTCHAR(W, 62, GETCHAR(md5, 2));
	PUTCHAR(W, 63, GETCHAR(md5, 3));
	md5_block(uint, W, key);
	PUTCHAR(W, 0, GETCHAR(md5, 4));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 1, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 17, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 22, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 38, GETCHAR(md5, i));
	for (i = 0; i < 16; i++)
		PUTCHAR(W, i + 43, GETCHAR(salt, i));
	for (i = 0; i < 5; i++)
		PUTCHAR(W, i + 59, GETCHAR(md5, i));
	md5_block(uint, W, key);
	for (i = 0; i < 4; i++)
		W[i] = cs->salt[i];
	W[4] = 0x80;
	for (i = 5; i < 14; i++)
		W[i] = 0;
	W[14] = (16 * (5 + 16)) << 3;
	W[15] = 0;
	md5_block(MAYBE_VOLATILE uint, W, key);

	key[1] &= 0xff;

	if (cs->has_mitm) {
		*result = (key[0] == cs->mitm[0] && key[1] == cs->mitm[1]);
		if (*result)
			atomic_xchg(&cs->cracked, 1);
	} else {
		W[0] = key[0];
		W[1] = key[1];
		W[2] = 0x8000;
		for (i = 3; i < 14; i++)
			W[i] = 0;
		W[14] = 9 << 3;
		W[15] = 0;
		md5_single(MAYBE_VOLATILE uint, W, md5);

		for (i = 0; i < 32/4; i++)
			verifier[i] = cs->verifier[i];
#ifdef RC4_USE_LOCAL
		rc4(state_l, md5, verifier, 32);
#else
		rc4(md5, verifier, 32);
#endif

		for (i = 0; i < 4; i++)
			W[i] = verifier[i];
		W[4] = 0x80;
		for (i = 5; i < 14; i++)
			W[i] = 0;
		W[14] = 16 << 3;
		W[15] = 0;
		md5_single(MAYBE_VOLATILE uint, W, verifier);

		if (verifier[0] == verifier[4] &&
		    verifier[1] == verifier[5] &&
		    verifier[2] == verifier[6] &&
		    verifier[3] == verifier[7]) {
			*result = 1;
			if (!atomic_xchg(&cs->cracked, 1) &&
			    !*benchmark && !atomic_xchg(&cs->has_mitm, 1)) {
				cs->mitm[0] = key[0];
				cs->mitm[1] = key[1];
			}
		} else {
			*result = 0;
		}
	}
}

inline
void oldoffice_sha1(const nt_buffer_t *nt_buffer,
                    __global salt_t *cs,
                    __global uint *result,
#ifdef RC4_USE_LOCAL
                    __local uint *state_l,
#endif
                    __global uint *benchmark)
{
	uint i;
	uint W[64/4];
	uint verifier[32/4];
	uint sha1[20/4];
	uint key[20/4];
	uint len = nt_buffer->len + 8;
	const ushort *p = nt_buffer->password;

	/* Initial hash of salt.password */
#if PLAINTEXT_LENGTH > (27 - 8)
	sha1_init(key);
#endif
	for (i = 0; i < 4; i++)
		W[i] = SWAP32(cs->salt[i]);
#if PLAINTEXT_LENGTH > (31 - 8)
	if (len > 31) {
		for (i = 8; i < 32; i += 2) {
			uint u = *p++;
			u |= (*p++ << 16U);
			W[i >> 1] = SWAP32(u);
		}
		sha1_block(uint, W, key);
		for (i = 0; i < len - 32; i += 2) {
			uint u = *p++;
			u |= (*p++ << 16U);
			W[i >> 1] = SWAP32(u);
		}
		PUTSHORT_BE(W, len - 32, 0x8000);
		for (i = len - 32 + 1; i < 30; i++)
			PUTSHORT_BE(W, i, 0);
		W[15] = len << 4;
		sha1_block(uint, W, key);
	} else
#endif
#if PLAINTEXT_LENGTH > (27 - 8)
	if (len > 27) {
		for (i = 8; i < len; i += 2) {
			uint u = *p++;
			u |= (*p++ << 16U);
			W[i >> 1] = SWAP32(u);
		}
		PUTSHORT_BE(W, len, 0x8000);
		for (i = len + 1; i < 32; i++)
			PUTSHORT_BE(W, i, 0);
		sha1_block(uint, W, key);
		for (i = 0; i < 15; i++)
			W[i] = 0;
		W[15] = len << 4;
		sha1_block(uint, W, key);
	} else
#endif
	{
		for (i = 8; i < len; i += 2) {
			uint u = *p++;
			u |= (*p++ << 16U);
			W[i >> 1] = SWAP32(u);
		}
		PUTSHORT_BE(W, len, 0x8000);
		for (i = len + 1; i < 30; i++)
			PUTSHORT_BE(W, i, 0);
		W[15] = len << 4;
#if PLAINTEXT_LENGTH > (27 - 8)
		sha1_block(uint, W, key);
#else
		sha1_single(uint, W, key);
#endif
	}

	for (i = 0; i < 5; i++)
		W[i] = key[i];
	W[5] = 0;
	W[6] = 0x80000000;
	for (i = 7; i < 15; i++)
		W[i] = 0;
	W[15] = 24 << 3;
	sha1_single(uint, W, sha1);

	sha1[0] = SWAP32(sha1[0]);
	sha1[1] = SWAP32(sha1[1]);

	if (cs->type == 3 && cs->has_mitm) {
		*result = (sha1[0] == cs->mitm[0] && (sha1[1] & 0xff) == cs->mitm[1]);
		if (*result)
			atomic_xchg(&cs->cracked, 1);
	} else {
		key[0] = sha1[0];
		if (cs->type == 3) {
			key[1] = sha1[1] & 0xff;
			key[2] = 0;
			key[3] = 0;
		} else {
			key[1] = sha1[1];
			key[2] = SWAP32(sha1[2]);
			key[3] = SWAP32(sha1[3]);
		}

		for (i = 0; i < 32/4; i++)
			verifier[i] = cs->verifier[i];
#ifdef RC4_USE_LOCAL
		rc4(state_l, key, verifier, 32);
#else
		rc4(key, verifier, 32);
#endif

		for (i = 0; i < 4; i++)
			W[i] = SWAP32(verifier[i]);
		W[4] = 0x80000000;
		for (i = 5; i < 15; i++)
			W[i] = 0;
		W[15] = 16 << 3;
		sha1_single(uint, W, key);

		verifier[0] = SWAP32(key[0]);
		verifier[1] = SWAP32(key[1]);
		verifier[2] = SWAP32(key[2]);
		verifier[3] = SWAP32(key[3]);

		if (verifier[0] == verifier[4] &&
		    verifier[1] == verifier[5] &&
		    verifier[2] == verifier[6] &&
		    verifier[3] == verifier[7]) {
			*result = 1;
			if (!atomic_xchg(&cs->cracked, 1) &&
			    !*benchmark && cs->type == 3 &&
			    !atomic_xchg(&cs->has_mitm, 1)) {
				cs->mitm[0] = sha1[0];
				cs->mitm[1] = sha1[1];
			}
		} else {
			*result = 0;
		}
	}
}

#ifdef RC4_USE_LOCAL
__attribute__((work_group_size_hint(64,1,1)))
#endif
__kernel
void oldoffice(__global const uchar *password,
               __global const uint *index,
               __global salt_t *cs,
               __global uint *result,
               __global uint *benchmark,
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
               )
{
#ifdef RC4_USE_LOCAL
	/*
	 * The "+ 1" extra element (actually never touched) give a huge boost
	 * on Maxwell and GCN due to access patterns or whatever.
	 */
	__local uint state_l[64][256/4 + 1];
#endif
	nt_buffer_t nt_buffer;
	uint i;
	uint gid = get_global_id(0);
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

	/* Prepare base word */
	oldoffice_utf16(password, index, &nt_buffer);

	/* Apply GPU-side mask */
	for (i = 0; i < NUM_INT_KEYS; i++) {
#if NUM_INT_KEYS > 1
		nt_buffer.password[GPU_LOC_0] = CP_LUT(int_keys[i] & 0xff);
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
		nt_buffer.password[GPU_LOC_1] = CP_LUT((int_keys[i] & 0xff00) >> 8);
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
		nt_buffer.password[GPU_LOC_2] = CP_LUT((int_keys[i] & 0xff0000) >> 16);
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
		nt_buffer.password[GPU_LOC_3] = CP_LUT((int_keys[i] & 0xff000000) >> 24);
#endif
#endif
#endif

		if (cs->type < 3)
			oldoffice_md5(&nt_buffer, cs, &result[gid * NUM_INT_KEYS + i],
#ifdef RC4_USE_LOCAL
			              state_l[get_local_id(0)],
#endif
			              benchmark);
		else
			oldoffice_sha1(&nt_buffer, cs, &result[gid * NUM_INT_KEYS + i],
#ifdef RC4_USE_LOCAL
			               state_l[get_local_id(0)],
#endif
			               benchmark);
	}
}
