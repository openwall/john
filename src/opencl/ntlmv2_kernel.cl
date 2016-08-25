/*
 * NTLMv2
 * MD4 + 2 x HMAC-MD5, with Unicode conversion on GPU
 *
 * Copyright (c) 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_unicode.h"
#include "opencl_misc.h"
#include "opencl_md4.h"
#include "opencl_md5.h"

#ifdef UTF_8

inline void prepare_keys(const __global uchar *source,
                         __global const uint *index,
                         uint *block)
{
	uint i;
	uint gid = get_global_id(0);
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
		if (source >= sourceEnd || target >= targetEnd)
			break;
	}
	*target = 0x80;	// Terminate

#if __OS_X__ && gpu_nvidia(DEVICE_INFO)
	/*
	 * Driver bug workaround. Halves the performance :-(
	 * Bug seen with GT 650M version 10.6.47 310.42.05f01
	 */
	barrier(CLK_GLOBAL_MEM_FENCE);
#endif

	block[14] = (uint)(target - targetStart) << 4;
}

#else

inline void prepare_keys(const __global uchar *password,
                         __global const uint *index,
                         uint *block)
{
	uint i;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

#if defined(ISO_8859_1) || defined(ASCII)
	/* Input buffer is in ISO-8859-1 encoding, without zero-termination.
	   we can just type-cast this to UTF16 */
	for (i = 0; i < len; i++)
		PUTCHAR(block, 2 * i, password[i]);
#else
	/* Input buffer is in a 'codepage' encoding, without zero-termination */
	for (i = 0; i < len; i++)
		PUTSHORT(block, i, (password[i] < 0x80) ?
		        password[i] : cp[password[i] & 0x7f]);
#endif

	PUTCHAR(block, 2 * i, 0x80);
	block[14] = i << 4;
}

#endif /* encodings */

inline void ntlmv2(uint *nthash,
                   MAYBE_CONSTANT uint *challenge,
                   uint *output)
{
	uint block[16];
	uint hash[4];
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint challenge_size;
	uint a, b, c, d;
	uint i;

	/* 1st HMAC */
	md5_init(output);

	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ nthash[i];
	for (i = 4; i < 16; i++)
		block[i] = 0x36363636;
	md5_block(block, output); /* md5_update(ipad, 64) */

	/* challenge == identity[32].len,server_chal.client_chal[len] */
	/* Salt buffer is prepared with 0x80, zero-padding and length,
	 * it can be one or two blocks */
	for (i = 0; i < 16; i++)
		block[i] = *challenge++;
	md5_block(block, output); /* md5_update(salt, saltlen), md5_final() */

	if (challenge[14]) { /* salt longer than 27 characters */
		for (i = 0; i < 16; i++)
			block[i] = *challenge++;
		md5_block(block, output); /* alternate final */
	} else
		challenge += 16;

	for (i = 0; i < 4; i++)
		hash[i] = output[i];
	for (i = 0; i < 4; i++)
		block[i] = 0x5c5c5c5c ^ nthash[i];

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

	/* Challenge:  blocks (of MD5),
	 * Server Challenge + Client Challenge (Blob) +
	 * 0x80, null padded and len set in get_salt() */
	challenge_size = *challenge++;

	/* At least this will not diverge */
	while (challenge_size--) {
		for (i = 0; i < 16; i++)
			block[i] = *challenge++;
		md5_block(block, output); /* md5_update(challenge, len), md5_final() */
	}

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
}

__kernel void ntlmv2_nthash(const __global uchar *source,
                            __global const uint *index,
                            MAYBE_CONSTANT uint *challenge,
                            __global uint *result)
{
	uint block[16] = { 0 };
	uint nthash[4];
	uint output[4];
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint a, b, c, d;
	uint i;

	/* Parse keys input buffer and re-encode to UTF-16LE */
	prepare_keys(source, index, block);

	/* Initial NT hash of password */
	md4_init(nthash);
	md4_block(block, nthash);

	/* Final hashing */
	ntlmv2(nthash, challenge, output);

	for (i = 0; i < 4; i++)
		result[i * gws + gid] = output[i];
}
