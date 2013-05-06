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
#include "stdint.h"
#include "sse-intrinsics.h"

#ifndef SHA256_CBLOCK
#define SHA256_CBLOCK 64
#endif
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#ifndef MMX_COEF_SHA256

static void _pbkdf2_sha256_load_hmac(const unsigned char *K, int KL, SHA256_CTX *pIpad, SHA256_CTX *pOpad) {
	unsigned char ipad[SHA256_CBLOCK], opad[SHA256_CBLOCK];
	unsigned i;

	memset(ipad, 0x36, SHA256_CBLOCK);
	memset(opad, 0x5C, SHA256_CBLOCK);

	for(i = 0; i < KL; i++) {
		ipad[i] ^= K[i];
		opad[i] ^= K[i];
	}
	// save off the first 1/2 of the ipad/opad hashes.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/4 the SHA1's
	SHA256_Init(pIpad);
	SHA256_Update(pIpad, ipad, SHA256_CBLOCK);
	SHA256_Init(pOpad);
	SHA256_Update(pOpad, opad, SHA256_CBLOCK);
}

static void _pbkdf2_sha256(const unsigned char *S, int SL, int R, ARCH_WORD_32 *out,
	                     unsigned char loop, const SHA256_CTX *pIpad, const SHA256_CTX *pOpad) {
	SHA256_CTX ctx;
	unsigned char tmp_hash[SHA256_DIGEST_LENGTH];
	unsigned i, j;

	memcpy(&ctx, pIpad, sizeof(SHA256_CTX));
	SHA256_Update(&ctx, S, SL);
	// this 4 byte BE 'loop' appended to the salt
	SHA256_Update(&ctx, "\x0\x0\x0", 3);
	SHA256_Update(&ctx, &loop, 1);
	SHA256_Final(tmp_hash, &ctx);

	memcpy(&ctx, pOpad, sizeof(SHA256_CTX));
	SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
	SHA256_Final(tmp_hash, &ctx);

	memcpy(out, tmp_hash, SHA256_DIGEST_LENGTH);

	for(i = 1; i < R; i++) {
		memcpy(&ctx, pIpad, sizeof(SHA256_CTX));
		SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
		SHA256_Final(tmp_hash, &ctx);

		memcpy(&ctx, pOpad, sizeof(SHA256_CTX));
		SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
		SHA256_Final(tmp_hash, &ctx);
		for(j = 0; j < SHA256_DIGEST_LENGTH/sizeof(ARCH_WORD_32); j++)
			out[j] ^= ((ARCH_WORD_32*)tmp_hash)[j];
	}
}

static void pbkdf2_sha256(unsigned char *K, int KL, unsigned char *S, int SL, int R, unsigned char *out, int outlen, int skip_bytes)
{
	union {
		ARCH_WORD_32 x32[8];
		unsigned char out[32];
	} tmp;
	int loop, loops, i, accum=0;
	SHA256_CTX ipad, opad;

	_pbkdf2_sha256_load_hmac(K, KL, &ipad, &opad);

	loops = (skip_bytes + outlen + 31) / 32;
	loop = skip_bytes / 32 + 1;
	while (loop <= loops) {
		_pbkdf2_sha256(S,SL,R,tmp.x32,loop,&ipad,&opad);
		for (i = skip_bytes%32; i < 32 && accum < outlen; i++) {
#if ARCH_LITTLE_ENDIAN
			out[accum++] = ((uint8_t*)tmp.out)[i];
#else
			out[accum++] = ((uint8_t*)tmp.out)[i^3];
#endif
		}
		loop++;
		skip_bytes = 0;
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


#if SHA256_SSE_PARA
#define SSE_GROUP_SZ_256 (MMX_COEF_SHA256*SHA256_SSE_PARA)
#else
#define SSE_GROUP_SZ MMX_COEF_SHA256
#endif

static void _pbkdf2_sha256_sse_load_hmac(const unsigned char *K[SSE_GROUP_SZ_256], int KL[SSE_GROUP_SZ_256], SHA256_CTX pIpad[SSE_GROUP_SZ_256], SHA256_CTX pOpad[SSE_GROUP_SZ_256])
{
	unsigned char ipad[SHA256_CBLOCK], opad[SHA256_CBLOCK];
	int i, j;

	for (j = 0; j < SSE_GROUP_SZ_256; ++j) {
		memset(ipad, 0x36, SHA256_CBLOCK);
		memset(opad, 0x5C, SHA256_CBLOCK);

		for(i = 0; i < KL[j]; i++) {
			ipad[i] ^= K[j][i];
			opad[i] ^= K[j][i];
		}
		// save off the first 1/2 of the ipad/opad hashes.  We will NEVER recompute this
		// again, during the rounds, but reuse it. Saves 1/4 the SHA256's
		SHA256_Init(&(pIpad[j]));
		SHA256_Update(&(pIpad[j]), ipad, SHA256_CBLOCK);
		SHA256_Init(&(pOpad[j]));
		SHA256_Update(&(pOpad[j]), opad, SHA256_CBLOCK);
	}
}

static void pbkdf2_sha256_sse(const unsigned char *K[MMX_COEF_SHA256], int KL[MMX_COEF_SHA256], unsigned char *S, int SL, int R, unsigned char *out[MMX_COEF_SHA256], int outlen, int skip_bytes)
{
	unsigned char tmp_hash[SHA256_DIGEST_LENGTH];
	ARCH_WORD_32 *i1, *i2, *o1, *ptmp;
	int i,j;
	ARCH_WORD_32 dgst[SSE_GROUP_SZ_256][8];
	int loops, accum=0;
	unsigned char loop;
	SHA256_CTX ipad[SSE_GROUP_SZ_256], opad[SSE_GROUP_SZ_256], ctx;

#ifdef _MSC_VER
	// sse_hash1 would need to be 'adjusted' for SHA256_PARA
	__declspec(align(16)) unsigned char sse_hash1[SHA256_BUF_SIZ*4*SSE_GROUP_SZ_256];
	__declspec(align(16)) unsigned char sse_crypt1[32*SSE_GROUP_SZ_256];
	__declspec(align(16)) unsigned char sse_crypt2[32*SSE_GROUP_SZ_256];
#else
	unsigned char sse_hash1[SHA256_BUF_SIZ*4*SSE_GROUP_SZ_256] __attribute__ ((aligned (16)));
	unsigned char sse_crypt1[32*SSE_GROUP_SZ_256] __attribute__ ((aligned (16)));
	unsigned char sse_crypt2[32*SSE_GROUP_SZ_256] __attribute__ ((aligned (16)));
#endif
	i1 = (ARCH_WORD_32*)sse_crypt1;
	i2 = (ARCH_WORD_32*)sse_crypt2;
	o1 = (ARCH_WORD_32*)sse_hash1;

	// we need to set ONE time, the upper half of the data buffer.  We put the 0x80 byte (in BE format), at offset 32,
	// then zero out the rest of the buffer, putting 0x300 (#bits), into the proper location in the buffer.  Once this
	// part of the buffer is setup, we never touch it again, for the rest of the crypt.  We simply overwrite the first
	// half of this buffer, over and over again, with BE results of the prior hash.
	for (j = 0; j < SSE_GROUP_SZ_256/MMX_COEF_SHA256; ++j) {
		ptmp = &o1[j*MMX_COEF_SHA256*SHA256_BUF_SIZ];
		for (i = 0; i < MMX_COEF_SHA256; ++i)
			ptmp[ 8*MMX_COEF_SHA256 + (i&(MMX_COEF_SHA256-1))] = 0x80000000;
		for (i = 9*MMX_COEF_SHA256; i < 15*MMX_COEF_SHA256; ++i)
			ptmp[i] = 0;
		for (i = 0; i < MMX_COEF_SHA256; ++i)
			ptmp[15*MMX_COEF_SHA256 + (i&(MMX_COEF_SHA256-1))] = ((64+32)<<3); // all encrypts are 64+32 bytes.
	}

	// Load up the IPAD and OPAD values, saving off the first half of the crypt.  We then push the ipad/opad all
	// the way to the end, and that ends up being the first iteration of the pbkdf2.  From that point on, we use
	// the 2 first halves, to load the sha256 2nd part of each crypt, in each loop.
	_pbkdf2_sha256_sse_load_hmac(K, KL, ipad, opad);
	for (j = 0; j < SSE_GROUP_SZ_256; ++j) {
		ptmp = &i1[(j/MMX_COEF_SHA256)*MMX_COEF_SHA256*8+(j&(MMX_COEF_SHA256-1))];
		for (i = 0; i < 8; ++i) {
			*ptmp = ipad[j].h[i];
			ptmp += MMX_COEF_SHA256;
		}
		ptmp = &i2[(j/MMX_COEF_SHA256)*MMX_COEF_SHA256*8+(j&(MMX_COEF_SHA256-1))];
		for (i = 0; i < 8; ++i) {
			*ptmp = opad[j].h[i];
			ptmp += MMX_COEF_SHA256;
		}
	}

	loops = (skip_bytes + outlen + 31) / 32;
	loop = skip_bytes / 32 + 1;
	while (loop <= loops) {
		for (j = 0; j < SSE_GROUP_SZ_256; ++j) {
			memcpy(&ctx, &ipad[j], sizeof(ctx));
			SHA256_Update(&ctx, S, SL);
			// this BE 1 appended to the salt, allows us to do passwords up
			// to and including 64 bytes long.  If we wanted longer passwords,
			// then we would have to call the HMAC multiple times (with the
			// rounds between, but each chunk of password we would use a larger
			// BE number appended to the salt. The first roung (64 byte pw), and
			// we simply append the first number (0001 in BE)
			SHA256_Update(&ctx, "\x0\x0\x0", 3);
			SHA256_Update(&ctx, &loop, 1);
			SHA256_Final(tmp_hash, &ctx);

			memcpy(&ctx, &opad[j], sizeof(ctx));
			SHA256_Update(&ctx, tmp_hash, SHA256_DIGEST_LENGTH);
			SHA256_Final(tmp_hash, &ctx);

			// now convert this from flat into MMX_COEF_SHA256 buffers.
			// Also, perform the 'first' ^= into the crypt buffer.  NOTE, we are doing that in BE format
			// so we will need to 'undo' that in the end.
			ptmp = &o1[(j/MMX_COEF_SHA256)*MMX_COEF_SHA256*SHA256_BUF_SIZ+(j&(MMX_COEF_SHA256-1))];
			for (i = 0; i < 8; ++i) {
				*ptmp = dgst[j][i] = ctx.h[i];
				ptmp += MMX_COEF_SHA256;
			}
		}

		// Here is the inner loop.  We loop from 1 to count.  iteration 0 was done in the ipad/opad computation.
		for(i = 1; i < R; i++) {
			int k;
			SSESHA256body(o1,o1,i1, SHA256_RELOAD);
			SSESHA256body(o1,o1,i2, SHA256_RELOAD);
			// only xor first 16 bytes, since that is ALL this format uses
			for (k = 0; k < SSE_GROUP_SZ_256; k++) {
				unsigned *p = &o1[(k/MMX_COEF_SHA256)*MMX_COEF_SHA256*SHA256_BUF_SIZ + (k&(MMX_COEF_SHA256-1))];
				for(j = 0; j < 8; j++)
					dgst[k][j] ^= p[(j<<(MMX_COEF_SHA256>>1))];
			}
		}

		// we must fixup final results.  We have been working in BE (NOT switching out of, just to switch back into it at every loop).
		// for the 'very' end of the crypt, we remove BE logic, so the calling function can view it in native format.
		alter_endianity(dgst, sizeof(dgst));
		for (i = skip_bytes%32; i < 32 && accum < outlen; ++i) {
			for (j = 0; j < SSE_GROUP_SZ_256; ++j) {
#if ARCH_LITTLE_ENDIAN
				out[j][accum] = ((unsigned char*)(dgst[j]))[i];
#else
				out[j][accum] = ((unsigned char*)(dgst[j]))[i^3];
#endif
			}
			++accum;
		}
		++loop;
		skip_bytes = 0;
	}
}

#endif
