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
#include "opencl_unicode.h"
#include "opencl_misc.h"
#define RC4_BUFLEN 16
#include "opencl_rc4.h"
#include "opencl_md4.h"
#include "opencl_md5.h"

#ifdef UTF_8

__kernel void krb5pa_md5_nthash(const __global uchar *source,
                                __global const uint *index,
                                __global uint *nthash)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16] = { 0 };
	uint a, b, c, d;
	uint output[4];
	uint base = index[gid];
	const __global UTF8 *sourceEnd;
	UTF16 *target = (UTF16*)block;
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
	*target = 0x80;	// Terminate

	block[14] = (uint)(target - targetStart) << 4;

	/* Initial hash of password */
	md4_init(output);
	md4_block(block, output);

	for (i = 0; i < 4; i++)
		nthash[gid * 4 + i] = output[i];
}

#elif !defined(ISO_8859_1) && !defined(ASCII)

__kernel void krb5pa_md5_nthash(const __global uchar *password,
                                __global const uint *index,
                                __global uint *nthash)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16] = { 0 };
	uint a, b, c, d;
	uint output[4];
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	/* Input buffer is in a 'codepage' encoding, without zero-termination */
	for (i = 0; i < len; i++)
		PUTSHORT(block, i, (password[i] < 0x80) ?
		        password[i] : cp[password[i] & 0x7f]);
	PUTCHAR(block, 2 * i, 0x80);
	block[14] = i << 4;

	/* Initial hash of password */
	md4_init(output);
	md4_block(block, output);

	for (i = 0; i < 4; i++)
		nthash[gid * 4 + i] = output[i];
}

#else

__kernel void krb5pa_md5_nthash(const __global uchar *password,
                            __global const uint *index,
                            __global uint *nthash)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16] = { 0 };
	uint a, b, c, d;
	uint output[4];
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	/* Input buffer is in ISO-8859-1 encoding, without zero-termination.
	   we can just type-cast this to UTF16 */
	for (i = 0; i < len; i++)
		PUTCHAR(block, 2 * i, password[i]);
	PUTCHAR(block, 2 * i, 0x80);
	block[14] = i << 4;

	/* Initial hash of password */
	md4_init(output);
	md4_block(block, output);

	for (i = 0; i < 4; i++)
		nthash[gid * 4 + i] = output[i];
}

#endif /* encodings */

#ifdef RC4_USE_LOCAL
__attribute__((work_group_size_hint(64,1,1)))
#endif
__kernel void krb5pa_md5_final(const __global uint *nthash,
                               MAYBE_CONSTANT uint *salts,
                               __global uint *result)
{
	uint i;
	uint gid = get_global_id(0);
	uint block[16];
	uint output[4], hash[4];
	uint a, b, c, d;
#ifdef RC4_USE_LOCAL
	__local uint state_l[64][256/4];
#endif

	/* 1st HMAC */
	md5_init(output);

	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ nthash[gid * 4 + i];
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	block[0] = 0x01;    /* little endian "one", 4 bytes */
	block[1] = 0x80;
	for (i = 2; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 4) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(one, 4), md5_final() */

	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ nthash[gid * 4 + i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(block, output); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(hash, 16), md5_final() */

	/* 2nd HMAC */
	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ output[i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = *salts++; /* checksum, 16 bytes */
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(cs, 16), md5_final() */

	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ hash[i];
	for (i = 0; i < 4; i++)
		hash[i] = output[i];

	md5_init(output);
	for (i = 4; i < 16; i++)
		block[i] = 0x5c5c5c5c;
	md5_block(block, output); /* md5_update(opad, 64) */

	for (i = 0; i < 4; i++)
		block[i] = hash[i];
	block[4] = 0x80;
	for (i = 5; i < 14; i++)
		block[i] = 0;
	block[14] = (64 + 16) << 3;
	block[15] = 0;
	md5_block(block, output); /* md5_update(hash, 16), md5_final() */

	/* output is our RC4 key. salts now point to encrypted timestamp. */
#ifdef RC4_USE_LOCAL
	rc4(state_l[get_local_id(0)], output, salts, &result[gid * 4]);
#else
	rc4(output, salts, &result[gid * 4]);
#endif
}
