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
#include "opencl_misc.h"
#define RC4_BUFLEN 32
#define RC4_IN_PLACE
#include "opencl_rc4.h"
#include "opencl_md5.h"
#include "opencl_sha1.h"

typedef struct {
	int type;
	uint salt[16/4];
	uint verifier[16/4]; /* or encryptedVerifier */
	uint verifierHash[20/4];  /* or encryptedVerifierHash */
	uint has_mitm;
	uint mitm[8/4]; /* Meet-in-the-middle hint, if we have one */
	int benchmark; /* Disable mitm, during benchmarking */
} salt_t;

typedef struct {
	uint len;
	ushort password[PLAINTEXT_LENGTH + 1];
} mid_t;

#ifdef UTF_8

__kernel void oldoffice_utf16(__global const uchar *source,
                              __global const uint *index,
                              __global mid_t *mid)
{
	uint gid = get_global_id(0);
	uint base = index[gid];
	__global const UTF8 *sourceEnd;
	__global UTF16 *target = mid[gid].password;
	__global UTF16 *targetStart = target;
	__global const UTF16 *targetEnd = &target[PLAINTEXT_LENGTH];
	UTF32 ch;
	uint extraBytesToRead;

	sourceEnd = source + index[gid + 1];
	source += base;

	/* Input buffer is UTF-8 without zero-termination */
	while (source < sourceEnd) {
		if (*source < 0xC0) {
			*target++ = (UTF16)*source++;
			if (source >= sourceEnd || target >= targetEnd) {
				break;
			}
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
			*target = 0x80;
			break; // from switch
		}
		if (*target == 0x80)
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
		if (source >= sourceEnd || target >= targetEnd)
			break;
	}

	*target = 0;
	mid[gid].len = (uint)(target - targetStart);
}

#elif !defined(ISO_8859_1) && !defined(ASCII)

__kernel void oldoffice_utf16(__global const uchar *password,
                              __global const uint *index,
                              __global mid_t *mid)
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
		mid[gid].password[i] = (password[i] < 0x80) ?
			password[i] : cp[password[i] & 0x7f];

	mid[gid].password[i] = 0;
	mid[gid].len = len;
}

#else

__kernel void oldoffice_utf16(__global const uchar *password,
                              __global const uint *index,
                              __global mid_t *mid)
{
	uint i;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	/* Input buffer is in ISO-8859-1 encoding, without zero-termination.
	   we just type-cast it to UTF16 */
	for (i = 0; i < len; i++)
		mid[gid].password[i] = password[i];

	mid[gid].password[i] = 0;
	mid[gid].len = len;
}

#endif /* encodings */

#ifdef RC4_USE_LOCAL
__attribute__((work_group_size_hint(64,1,1)))
#endif
__kernel void oldoffice_md5(__global const mid_t *mid,
                            __global salt_t *cs,
                            __global uint *result)
{
	uint i;
	uint a, b, c, d;
	uint gid = get_global_id(0);
	uint W[64/4];
	uint verifier[32/4];
	uint md5[16/4];
	uint key[16/4];
	uint len = mid[gid].len;
	uint salt[16/4];
	__global const ushort *p = mid[gid].password;
#ifdef RC4_USE_LOCAL
	__local uint state_l[64][256/4];
#endif

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
		md5_block(W, md5);
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
		md5_block(W, md5);
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
		md5_block(W, md5);
		for (i = 0; i < 14; i++)
			W[i] = 0;
		W[14] = len << 4;
		W[15] = 0;
		md5_block(W, md5);
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
		md5_block(W, md5);
#else
		md5_single(W, md5);
#endif
	}

	for (i = 0; i < 4; i++)
		salt[i] = cs->salt[i];

#if __OS_X__ && gpu_intel(DEVICE_INFO)
/*
 * Ridiculous workaround for Apple w/ Intel HD Graphics. Un-comment
 * the below, and kernel starts working for LWS=1 GWS=1. Still segfaults
 * with higher work sizes though. This is a driver bug.
 *
 * Yosemite, HD Graphics 4000, 1.2(Jul 29 2015 02:40:37)
 */
	//dump_stuff_msg("\n", md5, 16);
#endif

	md5_init(key);
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
	md5_block(W, key);
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
	md5_block(W, key);
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
	md5_block(W, key);
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
	md5_block(W, key);
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
	md5_block(W, key);
	for (i = 0; i < 4; i++)
		W[i] = cs->salt[i];
	W[4] = 0x80;
	for (i = 5; i < 14; i++)
		W[i] = 0;
	W[14] = (16 * (5 + 16)) << 3;
	W[15] = 0;
	md5_block(W, key);

	key[1] &= 0xff;

	if (cs->has_mitm) {
		result[gid] = (key[0] == cs->mitm[0] &&
		               key[1] == cs->mitm[1]);
	} else {
		W[0] = key[0];
		W[1] = key[1];
		W[2] = 0x8000;
		for (i = 3; i < 14; i++)
			W[i] = 0;
		W[14] = 9 << 3;
		W[15] = 0;
		md5_init(md5);
		md5_block(W, md5);

		for (i = 0; i < 32/4; i++)
			verifier[i] = cs->verifier[i];
#ifdef RC4_USE_LOCAL
		rc4(state_l[get_local_id(0)], md5, verifier);
#else
		rc4(md5, verifier);
#endif

		for (i = 0; i < 4; i++)
			W[i] = verifier[i];
		W[4] = 0x80;
		for (i = 5; i < 14; i++)
			W[i] = 0;
		W[14] = 16 << 3;
		W[15] = 0;
		md5_init(verifier);
		md5_block(W, verifier);

		if (verifier[0] == verifier[4] &&
		    verifier[1] == verifier[5] &&
		    verifier[2] == verifier[6] &&
		    verifier[3] == verifier[7]) {
			result[gid] = 1;
			if (!cs->benchmark && !atomic_xchg(&cs->has_mitm, 1)) {
				cs->mitm[0] = key[0];
				cs->mitm[1] = key[1];
			}
		} else {
			result[gid] = 0;
		}
	}
}

#ifdef RC4_USE_LOCAL
__attribute__((work_group_size_hint(64,1,1)))
#endif
__kernel void oldoffice_sha1(__global const mid_t *mid,
                             __global salt_t *cs,
                             __global uint *result)
{
	uint i;
	uint gid = get_global_id(0);
	uint A, B, C, D, E, temp;
#if PLAINTEXT_LENGTH > 27
	/* Silly AMD bug workaround */
	uint a, b, c, d, e;
#endif
	uint W[64/4];
	uint verifier[32/4];
	uint sha1[20/4];
	uint key[20/4];
	uint len = mid[gid].len + 8;
	__global const ushort *p = mid[gid].password;
#ifdef RC4_USE_LOCAL
	__local uint state_l[64][256/4];
#endif

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
		sha1_block(W, key);
		for (i = 0; i < len - 32; i += 2) {
			uint u = *p++;
			u |= (*p++ << 16U);
			W[i >> 1] = SWAP32(u);
		}
		PUTSHORT_BE(W, len - 32, 0x8000);
		for (i = len - 32 + 1; i < 30; i++)
			PUTSHORT_BE(W, i, 0);
		W[15] = len << 4;
		sha1_block(W, key);
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
		sha1_block(W, key);
		for (i = 0; i < 15; i++)
			W[i] = 0;
		W[15] = len << 4;
		sha1_block(W, key);
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
		sha1_block(W, key);
#else
		sha1_single(W, key);
#endif
	}

	for (i = 0; i < 5; i++)
		W[i] = key[i];
	W[5] = 0;
	W[6] = 0x80000000;
	for (i = 7; i < 15; i++)
		W[i] = 0;
	W[15] = 24 << 3;
	sha1_single(W, sha1);

	sha1[0] = SWAP32(sha1[0]);
	sha1[1] = SWAP32(sha1[1]);

	if (cs->type == 3 && cs->has_mitm) {
		result[gid] = (sha1[0] == cs->mitm[0] &&
		               (sha1[1] & 0xff) == cs->mitm[1]);
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
		rc4(state_l[get_local_id(0)], key, verifier);
#else
		rc4(key, verifier);
#endif

		for (i = 0; i < 4; i++)
			W[i] = SWAP32(verifier[i]);
		W[4] = 0x80000000;
		for (i = 5; i < 15; i++)
			W[i] = 0;
		W[15] = 16 << 3;
		sha1_single(W, key);

		verifier[0] = SWAP32(key[0]);
		verifier[1] = SWAP32(key[1]);
		verifier[2] = SWAP32(key[2]);
		verifier[3] = SWAP32(key[3]);

		if (verifier[0] == verifier[4] &&
		    verifier[1] == verifier[5] &&
		    verifier[2] == verifier[6] &&
		    verifier[3] == verifier[7]) {
			result[gid] = 1;
			if (!cs->benchmark && cs->type == 3 &&
			    !atomic_xchg(&cs->has_mitm, 1)) {
				cs->mitm[0] = sha1[0];
				cs->mitm[1] = sha1[1];
			}
		} else {
			result[gid] = 0;
		}
	}
}
