/*
 * Kerberos 5 TGS-REP etype 23
 * MD4 + HMAC-MD5 + RC4, with Unicode conversion and mask acceleration.
 *
 * Copyright (c) 2023, magnum
 * This software is hereby released to the general public under the following
 * terms: Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define AMD_PUTCHAR_NOCAST
#include "opencl_misc.h"
#include "opencl_unicode.h"
#define RC4_IN_TYPE	__constant
#include "opencl_rc4.h"
#include "opencl_md4.h"
#include "opencl_md5.h"
#include "opencl_hmac_md5.h"
#include "opencl_mask.h"

typedef struct {
	dyna_salt dsalt;
	uint32_t edata1[16/4];
	uint32_t edata2len;
	uint32_t edata2[1];
} krb5tgs_salt;

typedef struct {
	uint32_t saved_K1[16/4];
} krb5tgs_state;

typedef struct {
	uint32_t orig_index;
} krb5tgs_out;

typedef struct {
	uint len;
	ushort password[PLAINTEXT_LENGTH];
} nt_buffer_t;

#ifdef UTF_8

inline
void prepare_utf16(__global const uchar *source,
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
void prepare_utf16(__global const uchar *password,
                   __global const uint *index,
                   nt_buffer_t *nt_buffer)
{
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	password += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	/* Input buffer is in a 'codepage' encoding, without zero-termination */
	for (uint i = 0; i < len; i++)
		nt_buffer->password[i] = CP_LUT(password[i]);

	nt_buffer->password[len] = 0;
	nt_buffer->len = len;
}

#endif /* encodings */

__kernel void krb5tgs_init(__global const uchar *password,
                           __global const uint *index,
                           __global krb5tgs_state *out,
                           __global uint *int_key_loc,
#if USE_CONST_CACHE
                           __constant
#else
                           __global
#endif
                           uint *int_keys)
{
	nt_buffer_t nt_buffer;
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
	prepare_utf16(password, index, &nt_buffer);

	for (uint mask_idx = 0; mask_idx < NUM_INT_KEYS; mask_idx++) {
#if NUM_INT_KEYS > 1
		nt_buffer.password[GPU_LOC_0] = CP_LUT(int_keys[mask_idx] & 0xff);
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
		nt_buffer.password[GPU_LOC_1] = CP_LUT((int_keys[mask_idx] & 0xff00) >> 8);
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
		nt_buffer.password[GPU_LOC_2] = CP_LUT((int_keys[mask_idx] & 0xff0000) >> 16);
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
		nt_buffer.password[GPU_LOC_3] = CP_LUT((int_keys[mask_idx] & 0xff000000) >> 24);
#endif
#endif
#endif
		uint W[64/4];
		uint K[16/4], K1[16/4];
		uint len = nt_buffer.len;
		const ushort *p = nt_buffer.password;
		uint i;

		/*
		 * K = MD4(UTF-16LE(password)), ordinary 16-byte NTLM hash
		 */
		for (i = 0; i < len; i++) {
			W[i] = (uint)*p++;
			W[i] |= (*p++ << 16U);
		}
		PUTSHORT(W, len, 0x80);
		for (i = len + 1; i < 28; i++)
			PUTSHORT(W, i, 0);
		W[14] = len << 4;
		W[15] = 0;

		md4_single(uint, W, K);

		uint inner[16/4];
		/*
		 * 1st HMAC K1 = HMAC-MD5(K, 2LE)
		 */
		for (i = 0; i < 4; i++)
			W[i] = 0x36363636 ^ K[i];
		for (i = 4; i < 16; i++)
			W[i] = 0x36363636;
		md5_single(uint, W, inner); /* md5_update(ipad, 64) */

		W[0] = 0x02;    /* little endian "two", 4 bytes */
		W[1] = 0x80;
		for (i = 2; i < 14; i++)
			W[i] = 0;
		W[14] = (64 + 4) << 3;
		W[15] = 0;
		md5_block(uint, W, inner); /* md5_update(two, 4), md5_final() */

		for (i = 0; i < 4; i++)
			W[i] = 0x5c5c5c5c ^ K[i];
		for (i = 4; i < 16; i++)
			W[i] = 0x5c5c5c5c;
		md5_single(uint, W, K1); /* md5_update(opad, 64) */

		for (i = 0; i < 4; i++)
			W[i] = inner[i];
		W[4] = 0x80;
		for (i = 5; i < 14; i++)
			W[i] = 0;
		W[14] = (64 + 16) << 3;
		W[15] = 0;
		md5_block(uint, W, K1); /* md5_update(inner, 16), md5_final() */

		memcpy_macro(out[gid * NUM_INT_KEYS + mask_idx].saved_K1, K1, 16/4);
	}
}

#ifdef RC4_USE_LOCAL
__attribute__((work_group_size_hint(32,1,1)))
#endif
__kernel void krb5tgs_crypt(__constant krb5tgs_salt *salt,
                            __global krb5tgs_state *state,
                            volatile __global uint *crack_count,
                            __global krb5tgs_out *out)
{
#ifdef RC4_USE_LOCAL
	__local RC4_CTX rc4_ctx[32];
#define rc4_ctx	rc4_ctx[get_local_id(0)]
#else
	RC4_CTX rc4_ctx;
#endif

	for (uint mask_idx = 0; mask_idx < NUM_INT_KEYS; mask_idx++) {
		uint gidx = get_global_id(0) * NUM_INT_KEYS + mask_idx;
		uint i;

		uint K1[16/4];
		memcpy_macro(K1, state[gidx].saved_K1, 16/4);

		uint W[64/4];
		uint inner[16/4];
		uint K3[16/4];
		/*
		 * 2nd HMAC K3 = HMAC-MD5(K1, edata1)
		 */
		for (i = 0; i < 4; i++)
			W[i] = 0x36363636 ^ K1[i];
		for (i = 4; i < 16; i++)
			W[i] = 0x36363636;
		md5_single(uint, W, inner); /* md5_update(ipad, 64) */

		for (i = 0; i < 4; i++)
			W[i] = salt->edata1[i];
		W[4] = 0x80;
		for (i = 5; i < 14; i++)
			W[i] = 0;
		W[14] = (64 + 16) << 3;
		W[15] = 0;
		md5_block(uint, W, inner); /* md5_update(edata1, 16), md5_final() */

		for (i = 0; i < 4; i++)
			W[i] = 0x5c5c5c5c ^ K1[i];
		for (i = 4; i < 16; i++)
			W[i] = 0x5c5c5c5c;
		md5_single(uint, W, K3); /* md5_update(opad, 64) */

		for (i = 0; i < 4; i++)
			W[i] = inner[i];
		W[4] = 0x80;
		for (i = 5; i < 14; i++)
			W[i] = 0;
		W[14] = (64 + 16) << 3;
		W[15] = 0;
		md5_block(uint, W, K3); /* md5_update(inner, 16), md5_final() */

		rc4_set_key(&rc4_ctx, K3);

		uint ddata[(DATA_LEN + 3) / 4];
		rc4(&rc4_ctx, salt->edata2, ddata, 20);

		uchar *edata2 = (uchar*)ddata;
		if (((!memcmp_pc(edata2 + 8, "\x63\x82", 2)) && (!memcmp_pc(edata2 + 16, "\xA0\x07\x03\x05", 4)))
		    ||
		    ((!memcmp_pc(edata2 + 8, "\x63\x81", 2)) && (!memcmp_pc(edata2 + 16, "\x03\x05\x00", 3)))) {

			/* Decrypt rest of data (eg. around 1 KB) */
			rc4(&rc4_ctx, salt->edata2 + 20/4, ddata + 20/4, salt->edata2len - 20);

			/*
			 * 3rd HMAC checksum = HMAC-MD5(K1, edata2).
			 */
			uint checksum[16/4];
			hmac_md5(K1, 16, ddata, salt->edata2len, checksum, 16);

			if (!memcmp_pc(checksum, salt->edata1, 16)) {
				const uint out_idx = atomic_inc(crack_count);
				out[out_idx].orig_index = gidx;
			}
		}
	}
}
