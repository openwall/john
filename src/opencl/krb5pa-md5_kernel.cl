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

inline
void prepare(__global const uchar *source, const uint len, uint *nt_buffer)
{
	__global const UTF8 *sourceEnd = source + len;
	UTF16 *target = (UTF16*)nt_buffer;
	UTF16 *targetStart = target;
	const UTF16 *targetEnd = &target[PLAINTEXT_LENGTH];
	UTF32 ch;
	uint extraBytesToRead;

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

	nt_buffer[14] = (uint)(target - targetStart) << 4;
}

#else

inline
void prepare(__global const uchar *password, const uint len, uint *nt_buffer)
{
	uint i;

	/* Input buffer is in a 'codepage' encoding, without zero-termination */
	for (i = 0; i < len; i++)
		PUTSHORT(nt_buffer, i, CP_LUT(password[i]));
	PUTCHAR(nt_buffer, 2 * i, 0x80);
	nt_buffer[14] = len << 4;
}

#endif /* encodings */

inline
void krb5pa_md5_final(const uint *nt_hash,
                      MAYBE_CONSTANT uint *salts,
#ifdef RC4_USE_LOCAL
                      __local uint *state_l,
#endif
                      __global uint *result)
{
	uint i;
	uint block[16];
	uint output[4], hash[4];
	uint a, b, c, d;

	/* 1st HMAC */
	md5_init(output);

	for (i = 0; i < 4; i++)
		block[i] = 0x36363636 ^ nt_hash[i];
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
		block[i] = 0x5c5c5c5c ^ nt_hash[i];

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
	rc4(state_l, output, salts, result);
#else
	rc4(output, salts, result);
#endif
}

#ifdef RC4_USE_LOCAL
__attribute__((work_group_size_hint(64,1,1)))
#endif
__kernel void krb5pa_md5(__global const uchar *source,
                         __global const uint *index,
                         MAYBE_CONSTANT uint *salts,
                         __global uint *result)
{
	uint gid = get_global_id(0);
	uint nt_buffer[16] = { 0 };
	uint nt_hash[4];
	uint a, b, c, d;
	__global const uchar *password = &source[index[gid]];
	uint len = index[gid + 1] - index[gid];
#ifdef RC4_USE_LOCAL
	/*
	 * The "+ 1" extra element (actually never touched) give a huge boost
	 * on Maxwell and GCN due to access patterns or whatever.
	 */
	__local uint state_l[64][256/4 + 1];
#endif

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	prepare(password, len, nt_buffer);

	/* Initial hash of password */
	md4_init(nt_hash);
	md4_block(nt_buffer, nt_hash);

	krb5pa_md5_final(nt_hash, salts,
#ifdef RC4_USE_LOCAL
	                 state_l[get_local_id(0)],
#endif
	                 &result[4 * gid]);
}
