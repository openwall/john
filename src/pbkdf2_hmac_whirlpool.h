/*
 * This code written by JimF, is release under the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2014 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * This is generic PBKDF2-HMAC-Whirlpool. To use this simple interface,
 * simply include this header file, and then call the pbkdf2_whirlpool()
 * function, filling in all params.  This format is same as the EVP
 * whirlpool algorithm within OpenSSL.  It uses a 64 byte opad/ipad even
 * though the hash base width is 128 bytes. This is unlike the other
 * PBKDF2 hashes I am familiar with (sha1, sha256, sha512 and now ripemd160).
 * each of those use i/opad the same length as the hash internal buffer
 * state. While the way done here in whirlpool sounds inferior, it actually
 * fixes one huge 'bug' there is in the PBKDF2 algorithm, namely that due to
 * ipad/opad being one crypt limb width, that there are ways to reduce each
 * iteration from 4 crypt limbs down to 2 crypt limbs.  For this whirlpool
 * variant, we do 4 crypt limbs for each iteration.  The 2nd crypt limb for
 * each half of the HMAC is KNOWN data. It simply is the 0x80 and the length
 * of bits (at the end of the buffer). Yes it is known, but there is only a
 * little speed up due to this knowledge (the known ZEROS algorithm), but
 * we do not use this
 *
 * skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 64). So to calculate only
 * byte 65-127 (second chunk) you can say "outlen=64 skip_bytes=64"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 64 as opposed to 128.
 */

#ifndef JOHN_PBKDF2_HMAC_WHIRLPOOL_H
#define JOHN_PBKDF2_HMAC_WHIRLPOOL_H

#include <string.h>
#include "sph_whirlpool.h"
#if (AC_BUILT && HAVE_WHIRLPOOL) ||	\
   (!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x10000000 && !HAVE_NO_SSL_WHIRLPOOL)
#include <openssl/whrlpool.h>
#else
// on my 32 bit cygwin builds, this code is about 4x slower than the oSSL code.
#define WHIRLPOOL_CTX             sph_whirlpool_context
#define WHIRLPOOL_Init(a)         sph_whirlpool_init(a)
#define WHIRLPOOL_Update(a,b,c)   sph_whirlpool(a,b,c)
#define WHIRLPOOL_Final(a,b)      sph_whirlpool_close(b,a)
#define WHIRLPOOL_DIGEST_LENGTH   (512/8)
#endif

// should be 128, but this is how oSSL does it in EVP digest-whirlpool
#define WHIRLPOOL_CBLOCK 64

static void _pbkdf2_whirlpool_load_hmac(const unsigned char *K, int KL, WHIRLPOOL_CTX *pIpad, WHIRLPOOL_CTX *pOpad) {
	unsigned char ipad[WHIRLPOOL_CBLOCK], opad[WHIRLPOOL_CBLOCK], k0[WHIRLPOOL_DIGEST_LENGTH];
	int i;

	memset(ipad, 0x36, WHIRLPOOL_CBLOCK);
	memset(opad, 0x5C, WHIRLPOOL_CBLOCK);

	if (KL > WHIRLPOOL_CBLOCK) {
		WHIRLPOOL_CTX ctx;
		WHIRLPOOL_Init( &ctx );
		WHIRLPOOL_Update( &ctx, K, KL);
		WHIRLPOOL_Final( k0, &ctx);
		KL = WHIRLPOOL_DIGEST_LENGTH;
		K = k0;
	}
	for (i = 0; i < KL; i++) {
		ipad[i] ^= K[i];
		opad[i] ^= K[i];
	}
	// save off the first the loaded ipad/opad contexts.  We will NEVER recompute them
	// again, during the rounds, but reuse them.  We do not save any Whirlpool calls
	// however, SINCE the CBLOCK was only 64 bytes long.  The data was just put into
	// the ipad/opad and moved into the CTX.  But no crypt was called yet.
	WHIRLPOOL_Init(pIpad);
	WHIRLPOOL_Update(pIpad, ipad, WHIRLPOOL_CBLOCK);
	WHIRLPOOL_Init(pOpad);
	WHIRLPOOL_Update(pOpad, opad, WHIRLPOOL_CBLOCK);
}

static void _pbkdf2_whirlpool(const unsigned char *S, int SL, int R, uint32_t *out,
	                     unsigned char loop, const WHIRLPOOL_CTX *pIpad, const WHIRLPOOL_CTX *pOpad) {
	WHIRLPOOL_CTX ctx;
	unsigned char tmp_hash[WHIRLPOOL_DIGEST_LENGTH];
	int i, j;

	memcpy(&ctx, pIpad, sizeof(WHIRLPOOL_CTX));
	WHIRLPOOL_Update(&ctx, S, SL);
	// this 4 byte BE 'loop' appended to the salt
	WHIRLPOOL_Update(&ctx, "\x0\x0\x0", 3);
	WHIRLPOOL_Update(&ctx, &loop, 1);
	WHIRLPOOL_Final(tmp_hash, &ctx);

	memcpy(&ctx, pOpad, sizeof(WHIRLPOOL_CTX));
	WHIRLPOOL_Update(&ctx, tmp_hash, WHIRLPOOL_DIGEST_LENGTH);
	WHIRLPOOL_Final(tmp_hash, &ctx);

	memcpy(out, tmp_hash, WHIRLPOOL_DIGEST_LENGTH);

	for (i = 1; i < R; i++) {
		memcpy(&ctx, pIpad, sizeof(WHIRLPOOL_CTX));
		WHIRLPOOL_Update(&ctx, tmp_hash, WHIRLPOOL_DIGEST_LENGTH);
		WHIRLPOOL_Final(tmp_hash, &ctx);

		memcpy(&ctx, pOpad, sizeof(WHIRLPOOL_CTX));
		WHIRLPOOL_Update(&ctx, tmp_hash, WHIRLPOOL_DIGEST_LENGTH);
		WHIRLPOOL_Final(tmp_hash, &ctx);
		for (j = 0; j < WHIRLPOOL_DIGEST_LENGTH/sizeof(uint32_t); j++) {
			out[j] ^= ((uint32_t*)tmp_hash)[j];
		}
	}
}
static void pbkdf2_whirlpool(const unsigned char *K, int KL, const unsigned char *S, int SL, int R, unsigned char *out, int outlen, int skip_bytes)
{
	union {
		uint32_t x32[WHIRLPOOL_DIGEST_LENGTH/sizeof(uint32_t)];
		unsigned char out[WHIRLPOOL_DIGEST_LENGTH];
	} tmp;
	int loop, loops, i, accum=0;
	WHIRLPOOL_CTX ipad, opad;

	_pbkdf2_whirlpool_load_hmac(K, KL, &ipad, &opad);

	loops = (skip_bytes + outlen + (WHIRLPOOL_DIGEST_LENGTH-1)) / WHIRLPOOL_DIGEST_LENGTH;
	loop = skip_bytes / WHIRLPOOL_DIGEST_LENGTH + 1;
	skip_bytes %= WHIRLPOOL_DIGEST_LENGTH;

	while (loop <= loops) {
		_pbkdf2_whirlpool(S,SL,R,tmp.x32,loop,&ipad,&opad);
		for (i = skip_bytes; i < WHIRLPOOL_DIGEST_LENGTH && accum < outlen; i++) {
			out[accum++] = ((uint8_t*)tmp.out)[i];
		}
		loop++;
		skip_bytes = 0;
	}
}

#endif
