/*
   Unix SMB/CIFS implementation.
   HMAC MD5 code for use in NTLMv2
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Tridgell 1992-2000

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* taken direct from rfc2104 implementation and modified for suitable use
 * for ntlmv2.
 *
 * minor performance hacks by magnum, 2011
 */

#include "arch.h"
#include "common.h"
#include <string.h>

#include "md5.h"
#include "hmacmd5.h"

#ifdef _MSC_VER
#define inline _inline
#endif
#include "memdbg.h"

/***********************************************************************
 the rfc 2104 version of hmac_md5 initialisation.
***********************************************************************/

void hmac_md5_init_rfc2104(const unsigned char *key, int key_len, HMACMD5Context *ctx)
{
	unsigned char tk[16];
	int i;

	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {
		MD5_CTX tctx;

		MD5_Init(&tctx);
		MD5_Update(&tctx, (void *)key, key_len);
		MD5_Final(tk, &tctx);

		key = tk;
		key_len = 16;
	}

	memset(ctx->k_ipad, 0x36, sizeof(ctx->k_ipad));
	memset(ctx->k_opad, 0x5c, sizeof(ctx->k_opad));
	for (i = 0; i < key_len; i++) {
		ctx->k_ipad[i] ^= key[i];
		ctx->k_opad[i] ^= key[i];
	}

	MD5_Init(&ctx->ctx);
	MD5_Update(&ctx->ctx, ctx->k_ipad, 64);
}

/***********************************************************************
 the microsoft version of hmac_md5 initialisation.
***********************************************************************/
void hmac_md5_init_limK_to_64(const unsigned char* key, int key_len,
			HMACMD5Context *ctx)
{
	int i;

	/* if key is longer than 64 bytes truncate it */
	if (key_len > 64)
		key_len = 64;

	memset(ctx->k_ipad, 0x36, sizeof(ctx->k_ipad));
	memset(ctx->k_opad, 0x5c, sizeof(ctx->k_opad));
	for (i = 0; i < key_len; i++) {
		ctx->k_ipad[i] ^= key[i];
		ctx->k_opad[i] ^= key[i];
	}

	MD5_Init(&ctx->ctx);
	MD5_Update(&ctx->ctx, ctx->k_ipad, 64);
}

/***********************************************************************
 Optimised version for fixed key length of 16
***********************************************************************/
inline void hmac_md5_init_K16(const unsigned char* key, HMACMD5Context *ctx)
{
	int i;

	memset(ctx->k_ipad, 0x36, sizeof(ctx->k_ipad));
	memset(ctx->k_opad, 0x5c, sizeof(ctx->k_opad));

#if defined(_MSC_VER) || defined(__GNUC__)
#if (ARCH_SIZE == 8)
//#warning INFO: Using 64-bit xor
	for (i = 0; i < 2; i++) {
		((unsigned long long *)ctx->k_ipad)[i] ^= ((unsigned long long *)key)[i];
		((unsigned long long *)ctx->k_opad)[i] ^= ((unsigned long long *)key)[i];
	}
#else
//#warning INFO: Using 32-bit xor
	for (i = 0; i < 4; i++) {
		((ARCH_WORD_32 *)ctx->k_ipad)[i] ^= ((ARCH_WORD_32 *)key)[i];
		((ARCH_WORD_32 *)ctx->k_opad)[i] ^= ((ARCH_WORD_32 *)key)[i];
	}
#endif
#else
//#warning INFO: Using 8-bit xor (always safe)
	for (i = 0; i < 16; i++) {
		ctx->k_ipad[i] ^= key[i];
		ctx->k_opad[i] ^= key[i];
	}
#endif

	MD5_Init(&ctx->ctx);
	MD5_Update(&ctx->ctx, ctx->k_ipad, 64);
}

/***********************************************************************
 update hmac_md5 "inner" buffer
***********************************************************************/

inline void hmac_md5_update(const unsigned char *text, int text_len, HMACMD5Context *ctx)
{
        MD5_Update(&ctx->ctx, (void *)text, text_len); /* then text of datagram */
}

/***********************************************************************
 finish off hmac_md5 "inner" buffer and generate outer one.
***********************************************************************/
inline void hmac_md5_final(unsigned char *digest, HMACMD5Context *ctx)
{
	MD5_Final(digest, &ctx->ctx);

	MD5_Init(&ctx->ctx);
	MD5_Update(&ctx->ctx, ctx->k_opad, 64);
	MD5_Update(&ctx->ctx, digest, 16);
	MD5_Final(digest, &ctx->ctx);
}

/***********************************************************
 single function to calculate an HMAC MD5 digest from data
 using optimised hmacmd5 init method because the key is 16 bytes.
************************************************************/
void hmac_md5(const unsigned char *key, const unsigned char *data,
              int data_len, unsigned char *digest)
{
	HMACMD5Context ctx;

	hmac_md5_init_K16(key, &ctx);
	if (data_len != 0)
		hmac_md5_update(data, data_len, &ctx);
	hmac_md5_final(digest, &ctx);
}

#ifndef min
#define min( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif

#define _MD5_DIGEST_LENGTH_ 16

void pkcs5_pbkdf2_md5(unsigned char *password, size_t plen,
    unsigned char *salt, size_t slen,
    unsigned long iteration_count, unsigned long key_length,
    unsigned char *output)
{
	unsigned char d1[_MD5_DIGEST_LENGTH_];
	unsigned char work[_MD5_DIGEST_LENGTH_];
	unsigned long counter = 1;
	unsigned long generated_key_length = 0;
	unsigned long bytes_to_write = 0;
	unsigned char c[4];
	unsigned long ic = 1;

	HMACMD5Context ctx;

	while (generated_key_length < key_length) {
		c[0] = (counter >> 24) & 0xff;
		c[1] = (counter >> 16) & 0xff;
		c[2] = (counter >> 8) & 0xff;
		c[3] = (counter >> 0) & 0xff;

		hmac_md5_init_rfc2104(password, plen, &ctx);
		hmac_md5_update(salt, slen, &ctx);
		hmac_md5_update(c, 4, &ctx);
		hmac_md5_final(d1, &ctx);
		memcpy(work, d1, _MD5_DIGEST_LENGTH_);

		for (ic = 1; ic < iteration_count; ic++) {
			unsigned long i = 0;
			hmac_md5_init_rfc2104(password, plen, &ctx);
			hmac_md5_update(d1, _MD5_DIGEST_LENGTH_, &ctx);
			hmac_md5_final(d1, &ctx);
			for (i = 0; i < _MD5_DIGEST_LENGTH_; i++)
				work[i] ^= d1[i];
		}

		bytes_to_write = min((key_length - generated_key_length), _MD5_DIGEST_LENGTH_);
		memcpy(output + generated_key_length, work, bytes_to_write);
		generated_key_length += bytes_to_write;
		++counter;
	}
}
