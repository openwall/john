/*
 * This code written by JimF, is release under the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2014 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * This is generic PBKDF2-HMAC-RipeMD160. To use this simple interface,
 * simply include this header file, and then call the pbkdf2_ripemd160()
 * function, filling in all params.  This format is same as the EVPdigest
 * ripemd160 algorithm within OpenSSL.
 *
 * skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 20). So to calculate only
 * byte 21-40 (second chunk) you can say "outlen=20 skip_bytes=20"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 20 as opposed to 40.
 */

#ifndef JOHN_PBKDF2_HMAC_RIPEMD160_H
#define JOHN_PBKDF2_HMAC_RIPEMD160_H

#include <string.h>
#include "sph_ripemd.h"

#if (AC_BUILT && HAVE_RIPEMD160) && 0
// actually, built in sph_ripemd160 may be faster than oSSL build :(
#include <openssl/ripemd.h>
#define sph_ripemd160_context     RIPEMD160_CTX
#define sph_ripemd160_init(a)	  RIPEMD160_Init(a)
#define sph_ripemd160(a,b,c)	  RIPEMD160_Update(a,b,c)
#define sph_ripemd160_close(b,a)  RIPEMD160_Final(a,b)
#else
#define RIPEMD160_DIGEST_LENGTH 20
#define RIPEMD160_CBLOCK 64
#endif

static void _pbkdf2_ripemd160_load_hmac(const unsigned char *K, int KL, sph_ripemd160_context *pIpad, sph_ripemd160_context *pOpad) {
	unsigned char ipad[RIPEMD160_CBLOCK], opad[RIPEMD160_CBLOCK], k0[RIPEMD160_DIGEST_LENGTH];
	int i;

	memset(ipad, 0x36, RIPEMD160_CBLOCK);
	memset(opad, 0x5C, RIPEMD160_CBLOCK);

	if (KL > RIPEMD160_CBLOCK) {
		sph_ripemd160_context ctx;
		sph_ripemd160_init(&ctx);
		sph_ripemd160(&ctx, K, KL);
		sph_ripemd160_close(&ctx, k0);
		KL = RIPEMD160_DIGEST_LENGTH;
		K = k0;
	}
	for (i = 0; i < KL; i++) {
		ipad[i] ^= K[i];
		opad[i] ^= K[i];
	}
	// save off the first 1/2 of the ipad/opad hashes.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/2 the RIPEMD160's
	sph_ripemd160_init(pIpad);
	sph_ripemd160(pIpad, ipad, RIPEMD160_CBLOCK);
	sph_ripemd160_init(pOpad);
	sph_ripemd160(pOpad, opad, RIPEMD160_CBLOCK);
}

static void _pbkdf2_ripemd160(const unsigned char *S, int SL, int R, uint32_t *out,
	                     unsigned char loop, const sph_ripemd160_context *pIpad, const sph_ripemd160_context *pOpad) {
	sph_ripemd160_context ctx;
	unsigned char tmp_hash[RIPEMD160_DIGEST_LENGTH];
	int i, j;

	memcpy(&ctx, pIpad, sizeof(sph_ripemd160_context));
	sph_ripemd160(&ctx, S, SL);
	// this 4 byte BE 'loop' appended to the salt
	sph_ripemd160(&ctx, "\x0\x0\x0", 3);
	sph_ripemd160(&ctx, &loop, 1);
	sph_ripemd160_close(&ctx, tmp_hash);

	memcpy(&ctx, pOpad, sizeof(sph_ripemd160_context));
	sph_ripemd160(&ctx, tmp_hash, RIPEMD160_DIGEST_LENGTH);
	sph_ripemd160_close(&ctx, tmp_hash);

	memcpy(out, tmp_hash, RIPEMD160_DIGEST_LENGTH);

	for (i = 1; i < R; i++) {
		memcpy(&ctx, pIpad, sizeof(sph_ripemd160_context));
		sph_ripemd160(&ctx, tmp_hash, RIPEMD160_DIGEST_LENGTH);
		sph_ripemd160_close(&ctx, tmp_hash);

		memcpy(&ctx, pOpad, sizeof(sph_ripemd160_context));
		sph_ripemd160(&ctx, tmp_hash, RIPEMD160_DIGEST_LENGTH);
		sph_ripemd160_close(&ctx, tmp_hash);
		for (j = 0; j < RIPEMD160_DIGEST_LENGTH/sizeof(uint32_t); j++) {
			out[j] ^= ((uint32_t*)tmp_hash)[j];
		}
	}
}
static void pbkdf2_ripemd160(const unsigned char *K, int KL, const unsigned char *S, int SL, int R, unsigned char *out, int outlen, int skip_bytes)
{
	union {
		uint32_t x32[RIPEMD160_DIGEST_LENGTH/sizeof(uint32_t)];
		unsigned char out[RIPEMD160_DIGEST_LENGTH];
	} tmp;
	int loop, loops, i, accum=0;
	sph_ripemd160_context ipad, opad;

	_pbkdf2_ripemd160_load_hmac(K, KL, &ipad, &opad);

	loops = (skip_bytes + outlen + (RIPEMD160_DIGEST_LENGTH-1)) / RIPEMD160_DIGEST_LENGTH;
	loop = skip_bytes / RIPEMD160_DIGEST_LENGTH + 1;
	skip_bytes %= RIPEMD160_DIGEST_LENGTH;

	while (loop <= loops) {
		_pbkdf2_ripemd160(S,SL,R,tmp.x32,loop,&ipad,&opad);
		for (i = skip_bytes; i < RIPEMD160_DIGEST_LENGTH && accum < outlen; i++) {
			out[accum++] = ((uint8_t*)tmp.out)[i];
		}
		loop++;
		skip_bytes = 0;
	}
}

#endif
