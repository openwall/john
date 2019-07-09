/*
 *  Modified in May of 2012 by Dhiru Kholia for JtR.
 *
 *  FIPS-180-2 compliant SHA-256 implementation
 *
 *  Copyright (C) 2001-2003  Christophe Devine
 *
 *  sha256.c - Implementation of the Secure Hash Algorithm-256 (SHA-256).

 *  Copyright (C) 2002  Southern Storm Software, Pty Ltd.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha2.h"
#include "opencl_md5_ctx.h"
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct {
	uint length;
	uchar v[PLAINTEXT_LENGTH];
} keyring_password;

typedef struct {
	uint cracked;
} keyring_hash;

typedef struct {
	uint length;
	uint iterations;
	uchar salt[SALTLEN];
	uint32_t crypto_size;
	uchar ct[LINE_BUFFER_SIZE / 2]; /* after hex conversion */
} keyring_salt;

inline int verify_decrypted_buffer(uchar *buffer, int len)
{
	uchar digest[16];
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, buffer + 16, len - 16);
	MD5_Final(digest, &ctx);

	return !memcmp_pp(buffer, digest, 16);
}

__kernel void keyring(__global const keyring_password *inbuffer,
                      __global keyring_hash *outbuffer,
                      __constant keyring_salt *salt)
{
	uint gid = get_global_id(0);
	uint W[64/4] = { 0 };
	uint o[32/4];
	uint i;
	uint len = inbuffer[gid].length;
	uint iterations = salt->iterations;
	AES_KEY akey;
	uchar buffer[LINE_BUFFER_SIZE / 2];
	union {
		uchar c[16];
		uint w[4];
	} iv;
	union {
		uchar c[16];
		uint w[4];
	} key;

	for (i = 0; i < len; i++)
		PUTCHAR_BE(W, i, inbuffer[gid].v[i]);
	for (i = 0; i < SALTLEN; i++)
		PUTCHAR_BE(W, len + i, salt->salt[i]);
	len += SALTLEN;
	PUTCHAR_BE(W, len, 0x80);
	W[15] = len << 3;

	sha256_init(o);
	sha256_block(W, o);

	for (i = 1; i < iterations; i++) {
		int j;

		for (j = 0; j < 8; j++)
			W[j] = o[j];
		W[8] = 0x80000000;
		for (j = 9; j < 15; j++)
			W[j] = 0;
		W[15] = 32 << 3;
		sha256_init(o);
		sha256_block(W, o);
	}

	for (i = 0; i < 4; i++)
		key.w[i] = SWAP32(o[i]);
	for (i = 0; i < 4; i++)
		iv.w[i] = SWAP32(o[4 + i]);

	AES_set_decrypt_key(key.c, 128, &akey);
	AES_cbc_decrypt(salt->ct, buffer, salt->crypto_size, &akey, iv.c);
	outbuffer[gid].cracked =
		verify_decrypted_buffer(buffer, salt->crypto_size);
}
