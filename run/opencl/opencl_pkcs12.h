/*
 * This software is Copyright (c) 2017 Dhiru Kholia <kholia at kth dot se>,
 * Copyright (c) 2017-2019 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_misc.h"
#include "opencl_unicode.h"
#include "opencl_sha1_ctx.h"
#include "opencl_sha2_ctx.h"
#include "opencl_sha1.h"
#include "opencl_sha2.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

#define UCS_2

#if __OS_X__ && !__CPU__
/* This is a workaround for driver/runtime bugs */
#define OPTIMIZE 0
#else
#define OPTIMIZE 1
#endif

#ifdef UTF_8

inline uint enc2utf16be(const UTF8 *pwd, uint length, UTF16 *unipwd)
{
	const UTF8 *source = pwd;
	const UTF8 *sourceEnd = &source[length];
	UTF16 *target = unipwd;
	UTF32 ch;
	uint extraBytesToRead;

	/* Input buffer is UTF-8 possibly without zero-termination */
	while (*source && source < sourceEnd) {
		if (*source < 0xC0) {
			*target++ = SWAP16((UTF16)(*source++));
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
		*target++ = SWAP16((UTF16)ch);
#else
		/* full UTF-16 with surrogate pairs */
		if (ch <= UNI_MAX_BMP) {  /* Target is a character <= 0xFFFF */
			*target++ = SWAP16((UTF16)ch);
		} else {  /* target is a character in range 0xFFFF - 0x10FFFF. */
			ch -= halfBase;
			*target++ = SWAP16((UTF16)((ch >> halfShift) + UNI_SUR_HIGH_START));
			*target++ = SWAP16((UTF16)((ch & halfMask) + UNI_SUR_LOW_START));
		}
#endif
	}

	*target = 0;	// Terminate

	return (target - unipwd);
}

#else

inline uint enc2utf16be(const UTF8 *pwd, uint length, UTF16 *unipwd)
{
	uint l = length;

	while (l--) {
		UTF8 c = *pwd++;
		*unipwd++ = SWAP16(CP_LUT(c));
	}
	*unipwd = 0;

	return length;
}

#endif /* encodings */

inline void pkcs12_fill_buffer(uint *data, uint data_len,
                               const uint *filler, uint fill_len)
{
	if ((fill_len & 0x03) == 0) {
		while (data_len > 0) {
			uint use_len = (data_len > fill_len) ? fill_len : data_len;

			memcpy_macro(data, filler, use_len / 4);
			data += use_len / 4;
			data_len -= use_len;
		}
	} else {
		uchar *p = (uchar*)data;

		while (data_len > 0) {
			uint use_len = (data_len > fill_len) ? fill_len : data_len;

			memcpy_pp(p, filler, use_len);
			p += use_len;
			data_len -= use_len;
		}
	}
}

/* SHA-1 */
inline void pkcs12_pbe_derive_key(uint iterations, int id,
                                  const uint *pwd, uint pwdlen,
                                  const uint *salt,
                                  uint saltlen, uint *key, uint keylen)
{
	uint i, j;
	union {
		ushort s[PLAINTEXT_LENGTH + 1];
		uint w[1];
	} unipwd;
#if !OPTIMIZE
	uint diversifier[64 / 4];
	uint salt_block[64 / 4], pwd_block[128 / 4];
#else
	uint big_block[(64 + 64 + 128) / 4];
	uint *diversifier = big_block;
	uint *salt_block = &big_block[64 / 4];
	uint *pwd_block = &big_block[(64 + 64) / 4];
#endif
	uint hash_block[64 / 4], hash_output[32 / 4];
	uint *p;
	uchar c;
	uint hlen, use_len, v, v2, datalen;
	SHA_CTX md_ctx;
	const uint idw = id | (id << 8) | (id << 16) | (id << 24);

	// Proper conversion to UTF-16BE
	pwdlen = enc2utf16be((uchar*)pwd, pwdlen, unipwd.s);
	pwdlen = (pwdlen + 1) << 1;

	pwd = unipwd.w;

	hlen = 20;	// for SHA1
	v = 64;
	v2 = ((pwdlen+64-1)/64)*64;

	// memset(diversifier, (uchar)id, v);
	for (j = 0; j < v / 4; j++)
		diversifier[j] = idw;

	pkcs12_fill_buffer(salt_block, v, salt, saltlen);
	pkcs12_fill_buffer(pwd_block,  v2, pwd,  pwdlen);

	p = key; // data
	datalen = keylen;
	while (datalen > 0) {
		// Calculate hash(diversifier || salt_block || pwd_block)
		SHA1_Init(&md_ctx);
#if !OPTIMIZE
		SHA1_Update(&md_ctx, (uchar*)diversifier, v);
		SHA1_Update(&md_ctx, (uchar*)salt_block, v);
		SHA1_Update(&md_ctx, (uchar*)pwd_block, v2);
#else
		SHA1_Update(&md_ctx, (uchar*)big_block, v + v + v2);
#endif
		SHA1_Final((uchar*)hash_output, &md_ctx);

		hash_output[0] = SWAP32(hash_output[0]);
		hash_output[1] = SWAP32(hash_output[1]);
		hash_output[2] = SWAP32(hash_output[2]);
		hash_output[3] = SWAP32(hash_output[3]);
		hash_output[4] = SWAP32(hash_output[4]);

		// Perform remaining (iterations - 1) recursive hash calculations
		for (i = 1; i < iterations; i++) {
			uint W[16];

			W[0] = hash_output[0];
			W[1] = hash_output[1];
			W[2] = hash_output[2];
			W[3] = hash_output[3];
			W[4] = hash_output[4];
			W[5] = 0x80000000;
			W[15] = 20 << 3;
			sha1_single_160Z(uint, W, hash_output);
		}
		hash_output[0] = SWAP32(hash_output[0]);
		hash_output[1] = SWAP32(hash_output[1]);
		hash_output[2] = SWAP32(hash_output[2]);
		hash_output[3] = SWAP32(hash_output[3]);
		hash_output[4] = SWAP32(hash_output[4]);

		use_len = (datalen > hlen) ? hlen : datalen;

		memcpy_macro(p, hash_output, use_len / 4);

		datalen -= use_len;

		if (datalen == 0)
			break;

		p += use_len / 4;

		// Concatenating copies of hash_output into hash_block (B)
		pkcs12_fill_buffer(hash_block, v, hash_output, hlen);

		// B += 1
		for (i = v; i > 0; i--)
			if (++((uchar*)hash_block)[i - 1] != 0)
				break;

		// salt_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)salt_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)salt_block)[i - 1] = j & 0xFF;
		}

		// pwd_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)pwd_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)pwd_block)[i - 1] = j & 0xFF;
		}
	}
}

/* SHA-256 */
inline void pkcs12_pbe_derive_key_sha256(uint iterations, int id,
                                         const uint *pwd, uint pwdlen,
                                         const uint *salt,
                                         uint saltlen, uint *key, uint keylen)
{
	uint i, j;
	union {
		ushort s[PLAINTEXT_LENGTH + 1];
		uint w[1];
	} unipwd;
#if !OPTIMIZE
	uint diversifier[64 / 4];
	uint salt_block[64 / 4], pwd_block[128 / 4];
#else
	uint big_block[(64 + 64 + 128) / 4];
	uint *diversifier = big_block;
	uint *salt_block = &big_block[64 / 4];
	uint *pwd_block = &big_block[(64 + 64) / 4];
#endif
	uint hash_block[64 / 4], hash_output[32 / 4];
	uint *p;
	uchar c;
	uint hlen, use_len, v, v2, datalen;
	SHA256_CTX md_ctx;
	const uint idw = id | (id << 8) | (id << 16) | (id << 24);

	// Proper conversion to UTF-16BE
	pwdlen = enc2utf16be((uchar*)pwd, pwdlen, unipwd.s);
	pwdlen = (pwdlen + 1) << 1;

	pwd = unipwd.w;

	hlen = 32;	// for SHA-256
	v = 64;
	v2 = ((pwdlen+64-1)/64)*64;

	// memset(diversifier, (uchar)id, v);
	for (i = 0; i < v / 4; i++)
		diversifier[i] = idw;

	pkcs12_fill_buffer(salt_block, v, salt, saltlen);
	pkcs12_fill_buffer(pwd_block,  v2, pwd,  pwdlen);

	p = key; // data
	datalen = keylen;
	while (datalen > 0) {
		// Calculate hash(diversifier || salt_block || pwd_block)
		SHA256_Init(&md_ctx);
#if !OPTIMIZE
		SHA256_Update(&md_ctx, (uchar*)diversifier, v);
		SHA256_Update(&md_ctx, (uchar*)salt_block, v);
		SHA256_Update(&md_ctx, (uchar*)pwd_block, v2);
#else
		SHA256_Update(&md_ctx, (uchar*)big_block, v + v + v2);
#endif
		SHA256_Final((uchar*)hash_output, &md_ctx);

		hash_output[0] = SWAP32(hash_output[0]);
		hash_output[1] = SWAP32(hash_output[1]);
		hash_output[2] = SWAP32(hash_output[2]);
		hash_output[3] = SWAP32(hash_output[3]);
		hash_output[4] = SWAP32(hash_output[4]);
		hash_output[5] = SWAP32(hash_output[5]);
		hash_output[6] = SWAP32(hash_output[6]);
		hash_output[7] = SWAP32(hash_output[7]);

		// Perform remaining (iterations - 1) recursive hash calculations
		for (i = 1; i < iterations; i++) {
			uint W[16];

			W[0] = hash_output[0];
			W[1] = hash_output[1];
			W[2] = hash_output[2];
			W[3] = hash_output[3];
			W[4] = hash_output[4];
			W[5] = hash_output[5];
			W[6] = hash_output[6];
			W[7] = hash_output[7];
			W[8] = 0x80000000;
			W[15] = 32 << 3;
			sha256_single_zeros(W, hash_output);
		}
		hash_output[0] = SWAP32(hash_output[0]);
		hash_output[1] = SWAP32(hash_output[1]);
		hash_output[2] = SWAP32(hash_output[2]);
		hash_output[3] = SWAP32(hash_output[3]);
		hash_output[4] = SWAP32(hash_output[4]);
		hash_output[5] = SWAP32(hash_output[5]);
		hash_output[6] = SWAP32(hash_output[6]);
		hash_output[7] = SWAP32(hash_output[7]);

		use_len = (datalen > hlen) ? hlen : datalen;
		for (i = 0; i < use_len / 4; i++)
			p[i] = hash_output[i];

		datalen -= use_len;

		if (datalen == 0)
			break;

		p += use_len / 4;

		// Concatenating copies of hash_output into hash_block (B)
		pkcs12_fill_buffer(hash_block, v, hash_output, hlen);

		// B += 1
		for (i = v; i > 0; i--)
			if (++((uchar*)hash_block)[i - 1] != 0)
				break;

		// salt_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)salt_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)salt_block)[i - 1] = j & 0xFF;
		}

		// pwd_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)pwd_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)pwd_block)[i - 1] = j & 0xFF;
		}
	}
}


/* SHA-512 */
inline void pkcs12_pbe_derive_key_sha512(uint iterations, int id,
                                         const uint *pwd, uint pwdlen,
                                         const uint *salt,
                                         uint saltlen, uint *key, uint keylen)
{
	uint i, j;
	union {
		ushort s[PLAINTEXT_LENGTH + 1];
		uint w[1];
	} unipwd;
#if !OPTIMIZE
	uint diversifier[128 / 4];
	uint salt_block[128 / 4], pwd_block[128 / 4];
#else
	uint big_block[(128 + 128 + 128) / 4];
	uint *diversifier = big_block;
	uint *salt_block = &big_block[128 / 4];
	uint *pwd_block = &big_block[(128 + 128) / 4];
#endif
	uint hash_block[128 / 4];
	union {
		ulong u64[64 / 8];
		uint u32[64 / 4];
	} hash_output;
	uint *p;
	uchar c;
	uint hlen, use_len, v, v2, datalen;
	SHA512_CTX md_ctx;
	const uint idw = id | (id << 8) | (id << 16) | (id << 24);

	// Proper conversion to UTF-16BE
	pwdlen = enc2utf16be((uchar*)pwd, pwdlen, unipwd.s);
	pwdlen = (pwdlen + 1) << 1;

	pwd = unipwd.w;

	hlen = 64;	// for SHA-512
	v = 128;
	v2 = ((pwdlen+128-1)/128)*128;

	// memset(diversifier, (uchar)id, v);
	for (i = 0; i < v / 4; i++)
		diversifier[i] = idw;

	pkcs12_fill_buffer(salt_block, v, salt, saltlen);
	pkcs12_fill_buffer(pwd_block,  v2, pwd,  pwdlen);

	p = key; // data
	datalen = keylen;
	while (datalen > 0) {
		// Calculate hash(diversifier || salt_block || pwd_block)
		SHA512_Init(&md_ctx);
#if !OPTIMIZE
		SHA512_Update(&md_ctx, (uchar*)diversifier, v);
		SHA512_Update(&md_ctx, (uchar*)salt_block, v);
		SHA512_Update(&md_ctx, (uchar*)pwd_block, v2);
#else
		SHA512_Update(&md_ctx, (uchar*)big_block, v + v + v2);
#endif
		SHA512_Final((uchar*)hash_output.u64, &md_ctx);

		hash_output.u64[0] = SWAP64(hash_output.u64[0]);
		hash_output.u64[1] = SWAP64(hash_output.u64[1]);
		hash_output.u64[2] = SWAP64(hash_output.u64[2]);
		hash_output.u64[3] = SWAP64(hash_output.u64[3]);
		hash_output.u64[4] = SWAP64(hash_output.u64[4]);
		hash_output.u64[5] = SWAP64(hash_output.u64[5]);
		hash_output.u64[6] = SWAP64(hash_output.u64[6]);
		hash_output.u64[7] = SWAP64(hash_output.u64[7]);

		// Perform remaining (iterations - 1) recursive hash calculations
		for (i = 1; i < iterations; i++) {
			ulong W[16];

			W[0] = hash_output.u64[0];
			W[1] = hash_output.u64[1];
			W[2] = hash_output.u64[2];
			W[3] = hash_output.u64[3];
			W[4] = hash_output.u64[4];
			W[5] = hash_output.u64[5];
			W[6] = hash_output.u64[6];
			W[7] = hash_output.u64[7];
			W[8] = 0x8000000000000000UL;
			W[15] = 64 << 3;
			sha512_single_zeros(W, hash_output.u64);
		}
		hash_output.u64[0] = SWAP64(hash_output.u64[0]);
		hash_output.u64[1] = SWAP64(hash_output.u64[1]);
		hash_output.u64[2] = SWAP64(hash_output.u64[2]);
		hash_output.u64[3] = SWAP64(hash_output.u64[3]);
		hash_output.u64[4] = SWAP64(hash_output.u64[4]);
		hash_output.u64[5] = SWAP64(hash_output.u64[5]);
		hash_output.u64[6] = SWAP64(hash_output.u64[6]);
		hash_output.u64[7] = SWAP64(hash_output.u64[7]);

		use_len = (datalen > hlen) ? hlen : datalen;
		memcpy_pp(p, hash_output.u32, use_len);

		datalen -= use_len;

		if (datalen == 0)
			break;

		p += use_len / 4;

		// Concatenating copies of hash_output into hash_block (B)
		pkcs12_fill_buffer(hash_block, v, hash_output.u32, hlen);

		// B += 1
		for (i = v; i > 0; i--)
			if (++((uchar*)hash_block)[i - 1] != 0)
				break;

		// salt_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)salt_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)salt_block)[i - 1] = j & 0xFF;
		}

		// pwd_block += B
		c = 0;
		for (i = v; i > 0; i--) {
			j = ((uchar*)pwd_block)[i - 1] + ((uchar*)hash_block)[i - 1] + c;
			c = (uchar)(j >> 8);
			((uchar*)pwd_block)[i - 1] = j & 0xFF;
		}
	}
}
