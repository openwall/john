/* July, 2012, the oSSL PKCS5_PBKDF2_HMAC function was replaced with a much faster
 * function pbkdf2() designed by JimF.  Originally this function was designed for
 * the mscash2 (DCC2).  The same pbkdf2 function, is used, and simply required small
 * changes to use SHA256.
 *
 * This new code is 3x to 4x FASTER than the original oSSL code. Even though it is
 * only using oSSL functions.  A lot of the high level stuff in oSSL sux for speed.
 *
 * SSE2 intrinsic code, May, 2013, Jim Fougeron.
 *
 * This code release under the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2012-2013 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */


#include <string.h>

#include "arch.h"
#include "sha2.h"
#include "sse-intrinsics.h"

#ifndef SHA256_CBLOCK
#define SHA256_CBLOCK 64
#endif
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef MMX_COEF_SHA256

static void pbkdf2_sha256(unsigned char *K, int KL, unsigned char *S, int SL, int R, ARCH_WORD_32 *dgst)
{
	SHA256_CTX ctx, tmp_ctx1, tmp_ctx2;
	unsigned char ipad[SHA256_CBLOCK], opad[SHA256_CBLOCK], tmp_hash[SHA256_DIGEST_LENGTH];
	unsigned i, j;

	memset(ipad, 0x36, SHA256_CBLOCK);
	memset(opad, 0x5C, SHA256_CBLOCK);

	for(i = 0; i < KL; i++) {
		ipad[i] ^= K[i];
		opad[i] ^= K[i];
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ipad, SHA256_CBLOCK);
	// save off the first 1/2 of the ipad hash.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/4 the SHA256's
	memcpy(&tmp_ctx1, &ctx, sizeof(SHA256_CTX));
	SHA256_Update(&ctx, S, SL);
	// this BE 1 appended to the salt, allows us to do passwords up
	// to and including 64 bytes long.  If we wanted longer passwords,
	// then we would have to call the HMAC multiple times (with the
	// rounds between, but each chunk of password we would use a larger
	// BE number appended to the salt. The first roung (64 byte pw), and
	// we simply append the first number (0001 in BE)
	SHA256_Update(&ctx, "\x0\x0\x0\x1", 4);
	SHA256_Final(tmp_hash, &ctx);

	SHA256_Init(&ctx);
 	SHA256_Update(&ctx, opad, SHA256_CBLOCK);
	// save off the first 1/2 of the opad hash.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/4 the SHA256's
 	memcpy(&tmp_ctx2, &ctx, sizeof(SHA256_CTX));
 	SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
	SHA256_Final(tmp_hash, &ctx);

	memcpy(dgst, tmp_hash, SHA256_DIGEST_LENGTH);

	for(i = 1; i < R; i++) {
		memcpy(&ctx, &tmp_ctx1, sizeof(SHA256_CTX));
		SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
		SHA256_Final(tmp_hash, &ctx);

		memcpy(&ctx, &tmp_ctx2, sizeof(SHA256_CTX));
		SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
		SHA256_Final(tmp_hash, &ctx);

		for(j = 0; j < SHA256_DIGEST_LENGTH/sizeof(ARCH_WORD_32); j++)
			dgst[j] ^= ((ARCH_WORD_32*)tmp_hash)[j];
	}
}

#else

#ifndef __JTR_SHA2___H_
// we MUST call our sha2.c functions, to know the layout.  Since it is possible that apple's CommonCrypto lib could
// be used, vs just jts's sha2.c or oSSL, and CommonCrypt is NOT binary compatible, then we MUST use jtr's code here.
// To do that, I have the struture defined here (if the header was not included), and the 'real' functions declared here also.
typedef struct
{
	ARCH_WORD_32 h[8];          // SHA256 state
	ARCH_WORD_32 Nl,Nh;         // UNUSED but here to be compatible with oSSL
	unsigned char buffer[64];   // current/building data 'block'. It IS in alignment
	unsigned int num,md_len;    // UNUSED but here to be compatible with oSSL
	unsigned int total;         // number of bytes processed
	int bIs256;                 // if 1 SHA256, else SHA224
} sha256_ctx;
extern void sha256_init   (sha256_ctx *ctx, int bIs256);
extern void sha256_update (sha256_ctx *ctx, const void *input, int len);
extern void sha256_final  (void *output, sha256_ctx *ctx);
#endif

// NOTE, code for SHA256_PARA > 1 has been commented out, with //J If we later need it, we can uncomment and switch it.

static void pbkdf2_sha256_sse(unsigned char *K[MMX_COEF_SHA256], int KL[MMX_COEF_SHA256], unsigned char *S, int SL, int R, ARCH_WORD_32 *dgst[MMX_COEF_SHA256])
{
	sha256_ctx ctx1, ctx2;
	unsigned char ipad[SHA256_CBLOCK], opad[SHA256_CBLOCK], tmp_hash[SHA256_DIGEST_LENGTH];
	ARCH_WORD_32 i, j, *t_sse_crypt1, *t_sse_crypt2, *t_sse_hash1, *i1, *i2, *o1, *ptmp;

#ifdef _MSC_VER
	// sse_hash1 would need to be 'adjusted' for SHA256_PARA
	__declspec(align(16)) unsigned char sse_hash1[SHA256_BUF_SIZ*4*MMX_COEF_SHA256];
	__declspec(align(16)) unsigned char sse_crypt1[32*MMX_COEF_SHA256];
	__declspec(align(16)) unsigned char sse_crypt2[32*MMX_COEF_SHA256];
#else
	unsigned char sse_hash1[SHA256_BUF_SIZ*4*MMX_COEF_SHA256] __attribute__ ((aligned (16)));
	unsigned char sse_crypt1[32*MMX_COEF_SHA256] __attribute__ ((aligned (16)));
	unsigned char sse_crypt2[32*MMX_COEF_SHA256] __attribute__ ((aligned (16)));
#endif
	t_sse_crypt1 = (ARCH_WORD_32 *)sse_crypt1;
	t_sse_crypt2 = (ARCH_WORD_32 *)sse_crypt2;
	t_sse_hash1 = (ARCH_WORD_32 *)sse_hash1;
	i1 = (ARCH_WORD_32*)t_sse_crypt1;
	i2 = (ARCH_WORD_32*)t_sse_crypt2;
	o1 = (ARCH_WORD_32*)t_sse_hash1;

	// we need to set ONE time, the upper half of the data buffer.  We put the 0x80 byte (in BE format), at offset 32,
	// then zero out the rest of the buffer, putting 0x300 (#bits), into the proper location in the buffer.  Once this
	// part of the buffer is setup, we never touch it again, for the rest of the crypt.  We simply overwrite the first
	// half of this buffer, over and over again, with BE results of the prior hash.
	for (i = 0; i < MMX_COEF_SHA256; ++i)
		o1[ 8*MMX_COEF_SHA256 + (i&(MMX_COEF_SHA256-1))] = 0x80000000;
	for (i = 9*MMX_COEF_SHA256; i < 15*MMX_COEF_SHA256; ++i)
		o1[i] = 0;
	for (i = 0; i < MMX_COEF_SHA256; ++i)
		o1[15*MMX_COEF_SHA256 + (i&(MMX_COEF_SHA256-1))] = (96<<3); // all encrypts are 64+32 bytes.

	// Load up the IPAD and OPAD values, saving off the first half of the crypt.  We then push the ipad/opad all
	// the way to the end, and that ends up being the first iteration of the pbkdf2.  From that point on, we use
	// the 2 first halves, to load the sha256 2nd part of each crypt, in each loop.
	for (j = 0; j < MMX_COEF_SHA256; ++j) {
		for(i = 0; i < KL[j]; i++) {
			ipad[i] = K[j][i] ^ 0x36;
			opad[i] = K[j][i] ^ 0x5C;
		}
		for(; i < 64; i++) {
			ipad[i] = 0x36;
			opad[i] = 0x5C;
		}

		// These functions come from sha2.c (JTR's implentation).  We control what the CTX looks like so can access interal elements.
		sha256_init(&ctx1,1);
		sha256_init(&ctx2,1);

		sha256_update(&ctx1, ipad, SHA256_CBLOCK);
		sha256_update(&ctx2, opad, SHA256_CBLOCK);

		// we memcopy from flat into MMX_COEF_SHA256 output buffer's (our 'temp' ctx buffer).
		// This data will NOT need to be BE swapped (it already IS BE swapped).

		//J		ptmp = &i1[(j/MMX_COEF_SHA256)*MMX_COEF_SHA256*SHA_BUF_SIZ+(j&(MMX_COEF_SHA256-1))];
		ptmp = &i1[(j&(MMX_COEF_SHA256-1))];
		for (i = 0; i < 8; ++i) {
			*ptmp = ctx1.h[i];
			ptmp += MMX_COEF_SHA256;
		}

//J		ptmp = &i2[(j/MMX_COEF_SHA256)*MMX_COEF_SHA256*SHA_BUF_SIZ+(j&(MMX_COEF_SHA256-1))];
		ptmp = &i2[(j&(MMX_COEF_SHA256-1))];
		for (i = 0; i < 8; ++i) {
			*ptmp = ctx2.h[i];
			ptmp += MMX_COEF_SHA256;
		}

		sha256_update(&ctx1, S, SL);
		// this BE 1 appended to the salt, allows us to do passwords up
		// to and including 64 bytes long.  If we wanted longer passwords,
		// then we would have to call the HMAC multiple times (with the
		// rounds between, but each chunk of password we would use a larger
		// BE number appended to the salt. The first roung (64 byte pw), and
		// we simply append the first number (0001 in BE)
		sha256_update(&ctx1, "\x0\x0\x0\x1", 4);
		sha256_final(tmp_hash, &ctx1);

		sha256_update(&ctx2, tmp_hash, SHA256_DIGEST_LENGTH);
		sha256_final(tmp_hash, &ctx2);

		// now convert this from flat into MMX_COEF buffers.
		// Also, perform the 'first' ^= into the crypt buffer.  NOTE, we are doing that in BE format
		// so we will need to 'undo' that in the end.
//J		ptmp = &o1[(j/MMX_COEF_SHA256)*MMX_COEF_SHA256*8+(j&(MMX_COEF_SHA256-1))];
		ptmp = &o1[(j&(MMX_COEF_SHA256-1))];
		for (i = 0; i < 8; ++i) {
			*ptmp = dgst[j][i] = ctx2.h[i];
			ptmp += MMX_COEF_SHA256;
		}
	}

	// Here is the inner loop.  We loop from 1 to count.  iteration 0 was done in the ipad/opad computation.
	for(i = 1; i < R; i++) {
		int k;
		SSESHA256body((unsigned int*)t_sse_hash1, (unsigned int*)t_sse_hash1, (unsigned int*)t_sse_crypt1, SHA256_MIXED_IN|SHA256_RELOAD);
		SSESHA256body((unsigned int*)t_sse_hash1, (unsigned int*)t_sse_hash1, (unsigned int*)t_sse_crypt2, SHA256_MIXED_IN|SHA256_RELOAD);
		for (k = 0; k < MMX_COEF_SHA256; k++) {
//J			unsigned *p = &((unsigned int*)t_sse_hash1)[(((k>>2)*SHA256_BUF_SIZ)<<2) + (k&(MMX_COEF_SHA256-1))];
			unsigned *p = &((unsigned int*)t_sse_hash1)[k&(MMX_COEF_SHA256-1)];
			for(j = 0; j < 8; j++) {
				// repack back into a 'flat' output buffer array
				dgst[k][j] ^= p[(j<<(MMX_COEF_SHA256>>1))];

			}
		}
	}

	// we must fixup final results.  We have been working in BE (NOT switching out of, just to switch back into it at every loop).
	// for the 'very' end of the crypt, we remove BE logic, so the calling function can view it in native format.
	alter_endianity(dgst[0], 32*MMX_COEF_SHA256);
}

#endif
