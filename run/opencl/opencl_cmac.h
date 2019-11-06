/*
 * This code implements the CMAC (Cipher-based Message Authentication)
 * algorithm described in FIPS SP800-38B using the AES-128 cipher.
 *
 * Copyright (c) 2017, magnum.
 * Copyright (c) 2008 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _OPENCL_CMAC_H_
#define _OPENCL_CMAC_H_

#include "opencl_aes.h"

#define AES_CMAC_KEY_LENGTH	16
#define AES_CMAC_DIGEST_LENGTH	16

typedef struct _AES_CMAC_CTX {
	AES_KEY aesctx;
	uint8_t X[16];
	uint8_t M_last[16];
	uint    M_n;
} AES_CMAC_CTX;

#define LSHIFT(v, r) do {					\
	uint i;							\
	for (i = 0; i < 15; i++)				\
		(r)[i] = (v)[i] << 1 | (v)[i + 1] >> 7;		\
	(r)[15] = (v)[15] << 1;					\
} while (0)

#define XOR(v, r) do {						\
	uint i;							\
	for (i = 0; i < 16; i++)				\
		(r)[i] ^= (v)[i];				\
} while (0)

inline void
AES_CMAC_Init(AES_CMAC_CTX *ctx)
{
	uint i;

	for (i = 0; i < 16; i++)
		ctx->X[i] = 0;
	ctx->M_n = 0;
}

inline void
AES_CMAC_SetKey(AES_CMAC_CTX *ctx, const uint8_t *key)
{
	AES_set_encrypt_key(key, 128, &ctx->aesctx);
}

inline void
AES_CMAC_Update(AES_CMAC_CTX *ctx, MAYBE_CONSTANT uint8_t *data, uint len)
{
	uint i;

#if 0 /* Only needed if we ever call Update() several times */
	if (ctx->M_n > 0) {
		uint mlen = MIN(16 - ctx->M_n, len);

		for (i = 0; i < mlen; i++)
			ctx->M_last[ctx->M_n + i] = data[i];
		ctx->M_n += mlen;
		if (ctx->M_n < 16 || len == mlen)
			return;
		XOR(ctx->M_last, ctx->X);
		AES_encrypt(ctx->X, ctx->X, &ctx->aesctx);
		data += mlen;
		len -= mlen;
	}
#endif
	while (len > 16) {	/* not last block */
		XOR(data, ctx->X);
		AES_encrypt(ctx->X, ctx->X, &ctx->aesctx);
		data += 16;
		len -= 16;
	}
	/* potential last block, save it */
	for (i = 0; i < len; i++)
		ctx->M_last[i] = data[i];
	ctx->M_n = len;
}

inline void
AES_CMAC_Final(uint8_t *digest, AES_CMAC_CTX *ctx)
{
	uint8_t K[16] = { 0 };

	/* generate subkey K1 */
	AES_encrypt(K, K, &ctx->aesctx);

	if (K[0] & 0x80) {
		LSHIFT(K, K);
		K[15] ^= 0x87;
	} else
		LSHIFT(K, K);

	if (ctx->M_n == 16) {
		/* last block was a complete block */
		XOR(K, ctx->M_last);
	} else {
		/* generate subkey K2 */
		if (K[0] & 0x80) {
			LSHIFT(K, K);
			K[15] ^= 0x87;
		} else
			LSHIFT(K, K);

		/* padding(M_last) */
		ctx->M_last[ctx->M_n] = 0x80;
		while (++ctx->M_n < 16)
			ctx->M_last[ctx->M_n] = 0;

		XOR(K, ctx->M_last);
	}
	XOR(ctx->M_last, ctx->X);
	AES_encrypt(ctx->X, digest, &ctx->aesctx);
}

#endif /* _OPENCL_CMAC_H_ */
