/*
 * This code written by JimF, is release under the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2013 JimF
 * and it is hereby released to the general public under the following
 * terms: This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * original code by Lukas Odzioba (including copywrite message), included at
 * the bottom of this file, commented out.   New code is as fast or faster
 * than original code.  New code simply uses oSSL functions, or SSE2, is much
 * simpler, AND contains an option to skip bytes, and only call the hashing
 * function where needed (significant speedup for zip format).  Also, new code
 * does not have size restrictions on PLAINTEXT_LENGTH.
 *
 * change made in Aug, 2014 (JimF) to also handle PBKDF1-HMAC-SHA1 logic. Pretty
 * simple change.  We do not append iteration count. Also we do not xor accum
 * the results of the output of each iteration. PBKDF1 only uses final
 * iterations output buffer.
 *
 * skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 20). So to calculate only
 * byte 21-40 (second chunk) you can say "outlen=20 skip_bytes=20"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 20 as opposed to 40.
 */
#ifndef JOHN_PBKDF2_HMAC_SHA1_H
#define JOHN_PBKDF2_HMAC_SHA1_H

#if 1

#include <string.h>
#include <stdint.h>

#include "sha.h"
#include "simd-intrinsics.h"

#ifdef PBKDF1_LOGIC
#define pbkdf2_sha1 pbkdf1_sha1
#define pbkdf2_sha1_sse pbkdf1_sha1_sse
#endif

#if !defined(SIMD_COEF_32) || defined(PBKDF2_HMAC_SHA1_ALSO_INCLUDE_CTX) || defined(OPENCL_FORMAT)

static void _pbkdf2_sha1_load_hmac(const unsigned char *K, int KL, SHA_CTX *pIpad, SHA_CTX *pOpad) {
	unsigned char ipad[SHA_CBLOCK], opad[SHA_CBLOCK], k0[SHA_DIGEST_LENGTH];
	int i;

	memset(ipad, 0x36, SHA_CBLOCK);
	memset(opad, 0x5C, SHA_CBLOCK);

	if (KL > SHA_CBLOCK) {
		SHA_CTX ctx;
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, K, KL);
		SHA1_Final( k0, &ctx);
		KL = SHA_DIGEST_LENGTH;
		K = k0;
	}
	for (i = 0; i < KL; i++) {
		ipad[i] ^= K[i];
		opad[i] ^= K[i];
	}
	// save off the first 1/2 of the ipad/opad hashes.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/2 the SHA1's
	SHA1_Init(pIpad);
	SHA1_Update(pIpad, ipad, SHA_CBLOCK);
	SHA1_Init(pOpad);
	SHA1_Update(pOpad, opad, SHA_CBLOCK);
}

static void _pbkdf2_sha1(const unsigned char *S, int SL, int R, uint32_t *out,
	                     unsigned char loop, const SHA_CTX *pIpad, const SHA_CTX *pOpad) {
	SHA_CTX ctx;
	unsigned char tmp_hash[SHA_DIGEST_LENGTH];
	int i, j;

	memcpy(&ctx, pIpad, sizeof(SHA_CTX));
	SHA1_Update(&ctx, S, SL);
#if !defined (PBKDF1_LOGIC)
	// this 4 byte BE 'loop' appended to the salt
	SHA1_Update(&ctx, "\x0\x0\x0", 3);
	SHA1_Update(&ctx, &loop, 1);
#endif
	SHA1_Final(tmp_hash, &ctx);

	memcpy(&ctx, pOpad, sizeof(SHA_CTX));
	SHA1_Update(&ctx, tmp_hash, SHA_DIGEST_LENGTH);
	SHA1_Final(tmp_hash, &ctx);
#if !defined (PBKDF1_LOGIC)
	memcpy(out, tmp_hash, SHA_DIGEST_LENGTH);
#endif
	for (i = 1; i < R; i++) {
		memcpy(&ctx, pIpad, sizeof(SHA_CTX));
		SHA1_Update(&ctx, tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final(tmp_hash, &ctx);

		memcpy(&ctx, pOpad, sizeof(SHA_CTX));
		SHA1_Update(&ctx, tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final(tmp_hash, &ctx);
#if !defined (PBKDF1_LOGIC)
#ifdef __MIC__
#pragma novector
#endif
		for (j = 0; j < SHA_DIGEST_LENGTH/sizeof(uint32_t); j++) {
			out[j] ^= ((uint32_t*)tmp_hash)[j];
#if defined (DPAPI_CRAP_LOGIC)
			((uint32_t*)tmp_hash)[j] = out[j];
#endif
		}
#endif
	}
#if defined (PBKDF1_LOGIC)
	// PBKDF1 simply uses end result of all of the HMAC iterations
	for (j = 0; j < SHA_DIGEST_LENGTH/sizeof(uint32_t); j++)
			out[j] = ((uint32_t*)tmp_hash)[j];
#endif
}
static void pbkdf2_sha1(const unsigned char *K, int KL, const unsigned char *S, int SL, int R, unsigned char *out, int outlen, int skip_bytes)
{
	union {
		uint32_t x32[SHA_DIGEST_LENGTH/sizeof(uint32_t)];
		unsigned char out[SHA_DIGEST_LENGTH];
	} tmp;
	int loop, loops, i, accum=0;
	SHA_CTX ipad, opad;

	_pbkdf2_sha1_load_hmac(K, KL, &ipad, &opad);

	loops = (skip_bytes + outlen + (SHA_DIGEST_LENGTH-1)) / SHA_DIGEST_LENGTH;
	loop = skip_bytes / SHA_DIGEST_LENGTH + 1;
	skip_bytes %= SHA_DIGEST_LENGTH;

	while (loop <= loops) {
		_pbkdf2_sha1(S,SL,R,tmp.x32,loop,&ipad,&opad);
		for (i = skip_bytes; i < SHA_DIGEST_LENGTH && accum < outlen; i++) {
			out[accum++] = ((uint8_t*)tmp.out)[i];
		}
		loop++;
		skip_bytes = 0;
	}
}

#endif

#if defined(SIMD_COEF_32) && !defined(OPENCL_FORMAT)

#define SSE_GROUP_SZ_SHA1 (SIMD_COEF_32*SIMD_PARA_SHA1)


static void _pbkdf2_sha1_sse_load_hmac(const unsigned char *K[SSE_GROUP_SZ_SHA1], int KL[SSE_GROUP_SZ_SHA1], SHA_CTX pIpad[SSE_GROUP_SZ_SHA1], SHA_CTX pOpad[SSE_GROUP_SZ_SHA1])
{
	unsigned char ipad[SHA_CBLOCK], opad[SHA_CBLOCK], k0[SHA_DIGEST_LENGTH];
	int i, j;

	for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		memset(ipad, 0x36, SHA_CBLOCK);
		memset(opad, 0x5C, SHA_CBLOCK);

		if (KL[j] > SHA_CBLOCK) {
			SHA_CTX ctx;
			SHA1_Init( &ctx );
			SHA1_Update( &ctx, K[j], KL[j]);
			SHA1_Final( k0, &ctx);
			for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
				ipad[i] ^= k0[i];
				opad[i] ^= k0[i];
			}
		} else
		for (i = 0; i < KL[j]; i++) {
			ipad[i] ^= K[j][i];
			opad[i] ^= K[j][i];
		}
		// save off the first 1/2 of the ipad/opad hashes.  We will NEVER recompute this
		// again, during the rounds, but reuse it. Saves 1/4 the SHA1's
		SHA1_Init(&(pIpad[j]));
		SHA1_Update(&(pIpad[j]), ipad, SHA_CBLOCK);
		SHA1_Init(&(pOpad[j]));
		SHA1_Update(&(pOpad[j]), opad, SHA_CBLOCK);
	}
}

static void pbkdf2_sha1_sse(const unsigned char *K[SSE_GROUP_SZ_SHA1], int KL[SSE_GROUP_SZ_SHA1], const unsigned char *S, int SL, int R, unsigned char *out[SSE_GROUP_SZ_SHA1], int outlen, int skip_bytes)
{
	unsigned char tmp_hash[SHA_DIGEST_LENGTH];
	uint32_t *i1, *i2, *o1, *ptmp;
	unsigned int i, j;
	uint32_t dgst[SSE_GROUP_SZ_SHA1][SHA_DIGEST_LENGTH/sizeof(uint32_t)];
	int loops, accum=0;
	unsigned char loop;
	SHA_CTX ipad[SSE_GROUP_SZ_SHA1], opad[SSE_GROUP_SZ_SHA1], ctx;

	// sse_hash1 would need to be 'adjusted' for SHA1_PARA
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_hash1[SHA_BUF_SIZ*sizeof(uint32_t)*SSE_GROUP_SZ_SHA1];
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_crypt1[SHA_DIGEST_LENGTH*SSE_GROUP_SZ_SHA1];
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_crypt2[SHA_DIGEST_LENGTH*SSE_GROUP_SZ_SHA1];
	i1 = (uint32_t*)sse_crypt1;
	i2 = (uint32_t*)sse_crypt2;
	o1 = (uint32_t*)sse_hash1;

	// we need to set ONE time, the upper half of the data buffer.  We put the 0x80 byte (in BE format), at offset 20,
	// then zero out the rest of the buffer, putting 0x2A0 (#bits), into the proper location in the buffer.  Once this
	// part of the buffer is setup, we never touch it again, for the rest of the crypt.  We simply overwrite the first
	// half of this buffer, over and over again, with BE results of the prior hash.
	for (j = 0; j < SSE_GROUP_SZ_SHA1/SIMD_COEF_32; ++j) {
		ptmp = &o1[j*SIMD_COEF_32*SHA_BUF_SIZ];
		for (i = 0; i < SIMD_COEF_32; ++i)
			ptmp[ (SHA_DIGEST_LENGTH/sizeof(uint32_t))*SIMD_COEF_32 + (i&(SIMD_COEF_32-1))] = 0x80000000;
		for (i = (SHA_DIGEST_LENGTH/sizeof(uint32_t)+1)*SIMD_COEF_32; i < 15*SIMD_COEF_32; ++i)
			ptmp[i] = 0;
		for (i = 0; i < SIMD_COEF_32; ++i)
			ptmp[15*SIMD_COEF_32 + (i&(SIMD_COEF_32-1))] = ((64+SHA_DIGEST_LENGTH)<<3); // all encrypts are 64+20 bytes.
	}

	// Load up the IPAD and OPAD values, saving off the first half of the crypt.  We then push the ipad/opad all
	// the way to the end, and that ends up being the first iteration of the pbkdf2.  From that point on, we use
	// the 2 first halves, to load the sha256 2nd part of each crypt, in each loop.
	_pbkdf2_sha1_sse_load_hmac(K, KL, ipad, opad);
	for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		ptmp = &i1[(j/SIMD_COEF_32)*SIMD_COEF_32*(SHA_DIGEST_LENGTH/sizeof(uint32_t))+(j&(SIMD_COEF_32-1))];
		ptmp[0]          = ipad[j].SHA_H0;
		ptmp[SIMD_COEF_32]   = ipad[j].SHA_H1;
		ptmp[SIMD_COEF_32*2] = ipad[j].SHA_H2;
		ptmp[SIMD_COEF_32*3] = ipad[j].SHA_H3;
		ptmp[SIMD_COEF_32*4] = ipad[j].SHA_H4;

		ptmp = &i2[(j/SIMD_COEF_32)*SIMD_COEF_32*(SHA_DIGEST_LENGTH/sizeof(uint32_t))+(j&(SIMD_COEF_32-1))];
		ptmp[0]          = opad[j].SHA_H0;
		ptmp[SIMD_COEF_32]   = opad[j].SHA_H1;
		ptmp[SIMD_COEF_32*2] = opad[j].SHA_H2;
		ptmp[SIMD_COEF_32*3] = opad[j].SHA_H3;
		ptmp[SIMD_COEF_32*4] = opad[j].SHA_H4;
	}

	loops = (skip_bytes + outlen + (SHA_DIGEST_LENGTH-1)) / SHA_DIGEST_LENGTH;
	loop = skip_bytes / SHA_DIGEST_LENGTH + 1;
	skip_bytes %= SHA_DIGEST_LENGTH;

	while (loop <= loops) {
		unsigned int k;
		for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
			memcpy(&ctx, &ipad[j], sizeof(ctx));
			SHA1_Update(&ctx, S, SL);
			// this BE 1 appended to the salt, allows us to do passwords up
			// to and including 64 bytes long.  If we wanted longer passwords,
			// then we would have to call the HMAC multiple times (with the
			// rounds between, but each chunk of password we would use a larger
			// BE number appended to the salt. The first roung (64 byte pw), and
			// we simply append the first number (0001 in BE)
#if !defined (PBKDF1_LOGIC)
			SHA1_Update(&ctx, "\x0\x0\x0", 3);
			SHA1_Update(&ctx, &loop, 1);
#endif
			SHA1_Final(tmp_hash, &ctx);

			memcpy(&ctx, &opad[j], sizeof(ctx));
			SHA1_Update(&ctx, tmp_hash, SHA_DIGEST_LENGTH);
			SHA1_Final(tmp_hash, &ctx);

			// now convert this from flat into SIMD_COEF_32 buffers.
			// Also, perform the 'first' ^= into the crypt buffer.  NOTE, we are doing that in BE format
			// so we will need to 'undo' that in the end.
			ptmp = &o1[(j/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ+(j&(SIMD_COEF_32-1))];
			ptmp[0]           = dgst[j][0] = ctx.SHA_H0;
			ptmp[SIMD_COEF_32]    = dgst[j][1] = ctx.SHA_H1;
			ptmp[SIMD_COEF_32*2]  = dgst[j][2] = ctx.SHA_H2;
			ptmp[SIMD_COEF_32*3]  = dgst[j][3] = ctx.SHA_H3;
			ptmp[SIMD_COEF_32*4]  = dgst[j][4] = ctx.SHA_H4;
		}

		// Here is the inner loop.  We loop from 1 to count.  iteration 0 was done in the ipad/opad computation.
		for (i = 1; i < (unsigned)R; i++) {
			SIMDSHA1body((unsigned char*)o1,o1,i1, SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
			SIMDSHA1body((unsigned char*)o1,o1,i2, SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
#if !defined (PBKDF1_LOGIC)
			for (k = 0; k < SSE_GROUP_SZ_SHA1; k++) {
				unsigned *p = &o1[(k/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ + (k&(SIMD_COEF_32-1))];
				for (j = 0; j < (SHA_DIGEST_LENGTH/sizeof(uint32_t)); j++) {
					dgst[k][j] ^= p[(j*SIMD_COEF_32)];
#if defined (DPAPI_CRAP_LOGIC)
					p[(j*SIMD_COEF_32)] = dgst[k][j];
#endif
				}
			}
#endif
		}
#if defined (PBKDF1_LOGIC)
		// PBKDF1 simply uses the end 'result' of all of the HMAC iterations.
		for (k = 0; k < SSE_GROUP_SZ_SHA1; k++) {
			unsigned *p = &o1[(k/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ + (k&(SIMD_COEF_32-1))];
			for (j = 0; j < (SHA_DIGEST_LENGTH/sizeof(uint32_t)); j++)
				dgst[k][j] = p[(j*SIMD_COEF_32)];
		}
#endif

		// we must fixup final results.  We have been working in BE (NOT switching out of, just to switch back into it at every loop).
		// for the 'very' end of the crypt, we remove BE logic, so the calling function can view it in native format.
		alter_endianity(dgst, sizeof(dgst));
		for (i = skip_bytes; i < SHA_DIGEST_LENGTH && accum < outlen; ++i) {
			for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
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

#else
/* This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#include <stdint.h>

/* You can't bump this without changing preproc() */
#ifdef PLAINTEXT_LENGTH
#if PLAINTEXT_LENGTH > 64
#error pbkdf2_hmac_sha1.h can not use a PLAINTEXT_LENGTH larger than 64
#endif
#else
#define PLAINTEXT_LENGTH	64
#endif

 #define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define INIT_A			0x67452301
#define INIT_B			0xefcdab89
#define INIT_C			0x98badcfe
#define INIT_D			0x10325476
#define INIT_E			0xc3d2e1f0

#define SQRT_2			0x5a827999
#define SQRT_3			0x6ed9eba1

#define SHA1_DIGEST_LENGTH	20

#define K1			0x5a827999
#define K2			0x6ed9eba1
#define K3			0x8f1bbcdc
#define K4			0xca62c1d6

#define F1(x,y,z)		(z ^ (x & (y ^ z)))
#define F2(x,y,z)		(x ^ y ^ z)
#define F3(x,y,z)		((x & y) | (z & (x | y)))
#define F4(x,y,z)		(x ^ y ^ z)

#if ARCH_LITTLE_ENDIAN
#define XORCHAR_BE(buf, index, val)	  \
	((uint8_t*)(buf))[(index) ^ 3] ^= (val)
#else
#define XORCHAR_BE(buf, index, val)	  \
	((uint8_t*)(buf))[(index)] ^= (val)
#endif

#ifndef GET_WORD_32_BE
#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )        \
        | ( (uint32_t) (b)[(i) + 1] << 16 )        \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )        \
        | ( (uint32_t) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = (uint8_t) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uint8_t) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uint8_t) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uint8_t) ( (n)       );       \
}
#endif

#define S(x,n) ((x << n) | ((x) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define R2(t)                                            \
(                                                       \
    S((W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
     W[(t - 14) & 0x0F] ^ W[ t      & 0x0F]),1)          \
)

#define P1(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F1(b,c,d) + K1 + x; b = S(b,30);        \
}

#define P2(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F2(b,c,d) + K2 + x; b = S(b,30);        \
}

#define P3(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F3(b,c,d) + K3 + x; b = S(b,30);        \
}

#define P4(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F4(b,c,d) + K4 + x; b = S(b,30);        \
}

#define PZ(a,b,c,d,e)                                  \
{                                                       \
    e += S(a,5) + F1(b,c,d) + K1 ; b = S(b,30);        \
}

#define SHA1(A,B,C,D,E,W) \
    P1(A, B, C, D, E, W[0] );\
    P1(E, A, B, C, D, W[1] );\
    P1(D, E, A, B, C, W[2] );\
    P1(C, D, E, A, B, W[3] );\
    P1(B, C, D, E, A, W[4] );\
    P1(A, B, C, D, E, W[5] );\
    P1(E, A, B, C, D, W[6] );\
    P1(D, E, A, B, C, W[7] );\
    P1(C, D, E, A, B, W[8] );\
    P1(B, C, D, E, A, W[9] );\
    P1(A, B, C, D, E, W[10]);\
    P1(E, A, B, C, D, W[11]);\
    P1(D, E, A, B, C, W[12]);\
    P1(C, D, E, A, B, W[13]);\
    P1(B, C, D, E, A, W[14]);\
    P1(A, B, C, D, E, W[15]);\
    P1(E, A, B, C, D, R(16));\
    P1(D, E, A, B, C, R(17));\
    P1(C, D, E, A, B, R(18));\
    P1(B, C, D, E, A, R(19));\
    P2(A, B, C, D, E, R(20));\
    P2(E, A, B, C, D, R(21));\
    P2(D, E, A, B, C, R(22));\
    P2(C, D, E, A, B, R(23));\
    P2(B, C, D, E, A, R(24));\
    P2(A, B, C, D, E, R(25));\
    P2(E, A, B, C, D, R(26));\
    P2(D, E, A, B, C, R(27));\
    P2(C, D, E, A, B, R(28));\
    P2(B, C, D, E, A, R(29));\
    P2(A, B, C, D, E, R(30));\
    P2(E, A, B, C, D, R(31));\
    P2(D, E, A, B, C, R(32));\
    P2(C, D, E, A, B, R(33));\
    P2(B, C, D, E, A, R(34));\
    P2(A, B, C, D, E, R(35));\
    P2(E, A, B, C, D, R(36));\
    P2(D, E, A, B, C, R(37));\
    P2(C, D, E, A, B, R(38));\
    P2(B, C, D, E, A, R(39));\
    P3(A, B, C, D, E, R(40));\
    P3(E, A, B, C, D, R(41));\
    P3(D, E, A, B, C, R(42));\
    P3(C, D, E, A, B, R(43));\
    P3(B, C, D, E, A, R(44));\
    P3(A, B, C, D, E, R(45));\
    P3(E, A, B, C, D, R(46));\
    P3(D, E, A, B, C, R(47));\
    P3(C, D, E, A, B, R(48));\
    P3(B, C, D, E, A, R(49));\
    P3(A, B, C, D, E, R(50));\
    P3(E, A, B, C, D, R(51));\
    P3(D, E, A, B, C, R(52));\
    P3(C, D, E, A, B, R(53));\
    P3(B, C, D, E, A, R(54));\
    P3(A, B, C, D, E, R(55));\
    P3(E, A, B, C, D, R(56));\
    P3(D, E, A, B, C, R(57));\
    P3(C, D, E, A, B, R(58));\
    P3(B, C, D, E, A, R(59));\
    P4(A, B, C, D, E, R(60));\
    P4(E, A, B, C, D, R(61));\
    P4(D, E, A, B, C, R(62));\
    P4(C, D, E, A, B, R(63));\
    P4(B, C, D, E, A, R(64));\
    P4(A, B, C, D, E, R(65));\
    P4(E, A, B, C, D, R(66));\
    P4(D, E, A, B, C, R(67));\
    P4(C, D, E, A, B, R(68));\
    P4(B, C, D, E, A, R(69));\
    P4(A, B, C, D, E, R(70));\
    P4(E, A, B, C, D, R(71));\
    P4(D, E, A, B, C, R(72));\
    P4(C, D, E, A, B, R(73));\
    P4(B, C, D, E, A, R(74));\
    P4(A, B, C, D, E, R(75));\
    P4(E, A, B, C, D, R(76));\
    P4(D, E, A, B, C, R(77));\
    P4(C, D, E, A, B, R(78));\
    P4(B, C, D, E, A, R(79));

#define SHA1shortBEG(A,B,C,D,E,W) \
    P1(A, B, C, D, E, W[0]);\
    P1(E, A, B, C, D, W[1]);\
    P1(D, E, A, B, C, W[2]);\
    P1(C, D, E, A, B, W[3]);\
    P1(B, C, D, E, A, W[4]);\
    P1(A, B, C, D, E, W[5]);\
    PZ(E, A, B, C, D);\
    PZ(D, E, A, B, C);\
    PZ(C, D, E, A, B);\
    PZ(B, C, D, E, A);\
    PZ(A, B, C, D, E);\
    PZ(E, A, B, C, D);\
    PZ(D, E, A, B, C);\
    PZ(C, D, E, A, B);\
    PZ(B, C, D, E, A);\
    P1(A, B, C, D, E, W[15]);\

#define Q16 (W[0] = S((W[2] ^ W[0]),1))
#define Q17 (W[1] = S((W[3] ^ W[1]),1))
#define Q18 (W[2] = S((W[15] ^ W[4] ^ W[2]),1))
#define Q19 (W[3] = S((W[0]  ^ W[5] ^ W[3]),1))
#define Q20 (W[4] = S((W[1]  ^ W[4]),1))
#define Q21 (W[5] = S((W[2] ^ W[5]),1))
#define Q22 (W[6] = S(W[3],1))
#define Q23 (W[7] = S((W[4] ^ W[15]),1))
#define Q24 (W[8] = S((W[5] ^ W[0]),1))
#define Q25 (W[9] = S((W[6] ^ W[1]),1))
#define Q26 (W[10] = S((W[7] ^ W[2]),1))
#define Q27 (W[11] = S((W[8] ^ W[3]),1))
#define Q28 (W[12] = S((W[9] ^ W[4]),1))
#define Q29 (W[13] = S((W[10] ^ W[5] ^ W[15]),1))
#define Q30 (W[14] = S((W[11] ^ W[6] ^ W[0]),1))
#define SHA1shortEND(A,B,C,D,E,W)\
    P1(E, A, B, C, D, Q16);\
    P1(D, E, A, B, C, Q17);\
    P1(C, D, E, A, B, Q18);\
    P1(B, C, D, E, A, Q19);\
    P2(A, B, C, D, E, Q20);\
    P2(E, A, B, C, D, Q21);\
    P2(D, E, A, B, C, Q22);\
    P2(C, D, E, A, B, Q23);\
    P2(B, C, D, E, A, Q24);\
    P2(A, B, C, D, E, Q25);\
    P2(E, A, B, C, D, Q26);\
    P2(D, E, A, B, C, Q27);\
    P2(C, D, E, A, B, Q28);\
    P2(B, C, D, E, A, Q29);\
    P2(A, B, C, D, E, Q30);\
    P2(E, A, B, C, D, R(31));\
    P2(D, E, A, B, C, R(32));\
    P2(C, D, E, A, B, R(33));\
    P2(B, C, D, E, A, R(34));\
    P2(A, B, C, D, E, R(35));\
    P2(E, A, B, C, D, R(36));\
    P2(D, E, A, B, C, R(37));\
    P2(C, D, E, A, B, R(38));\
    P2(B, C, D, E, A, R(39));\
    P3(A, B, C, D, E, R(40));\
    P3(E, A, B, C, D, R(41));\
    P3(D, E, A, B, C, R(42));\
    P3(C, D, E, A, B, R(43));\
    P3(B, C, D, E, A, R(44));\
    P3(A, B, C, D, E, R(45));\
    P3(E, A, B, C, D, R(46));\
    P3(D, E, A, B, C, R(47));\
    P3(C, D, E, A, B, R(48));\
    P3(B, C, D, E, A, R(49));\
    P3(A, B, C, D, E, R(50));\
    P3(E, A, B, C, D, R(51));\
    P3(D, E, A, B, C, R(52));\
    P3(C, D, E, A, B, R(53));\
    P3(B, C, D, E, A, R(54));\
    P3(A, B, C, D, E, R(55));\
    P3(E, A, B, C, D, R(56));\
    P3(D, E, A, B, C, R(57));\
    P3(C, D, E, A, B, R(58));\
    P3(B, C, D, E, A, R(59));\
    P4(A, B, C, D, E, R(60));\
    P4(E, A, B, C, D, R(61));\
    P4(D, E, A, B, C, R(62));\
    P4(C, D, E, A, B, R(63));\
    P4(B, C, D, E, A, R(64));\
    P4(A, B, C, D, E, R(65));\
    P4(E, A, B, C, D, R(66));\
    P4(D, E, A, B, C, R(67));\
    P4(C, D, E, A, B, R(68));\
    P4(B, C, D, E, A, R(69));\
    P4(A, B, C, D, E, R(70));\
    P4(E, A, B, C, D, R(71));\
    P4(D, E, A, B, C, R(72));\
    P4(C, D, E, A, B, R(73));\
    P4(B, C, D, E, A, R(74));\
    P4(A, B, C, D, E, R(75));\
    P4(E, A, B, C, D, R(76));\
    P4(D, E, A, B, C, R2(77));\
    P4(C, D, E, A, B, R2(78));\
    P4(B, C, D, E, A, R2(79));

#define  SHA1short(A,B,C,D,E,W) \
	SHA1shortBEG(A,B,C,D,E,W) SHA1shortEND(A,B,C,D,E,W)

static void preproc(const uint8_t * key, uint32_t keylen,
    uint32_t * state, uint32_t padding)
{
	int i;
	uint32_t W[16], temp;
	uint32_t A = INIT_A;
	uint32_t B = INIT_B;
	uint32_t C = INIT_C;
	uint32_t D = INIT_D;
	uint32_t E = INIT_E;

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;

}

static void hmac_sha1_(uint32_t * output,
    uint32_t * ipad_state,
    uint32_t * opad_state,
    const uint8_t * salt, int saltlen, uint8_t add)
{
	int i;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;
	uint8_t buf[64];
	uint32_t *src = (uint32_t *) buf;

	i = 64 / 4;
	while (i--)
		*src++ = 0;
	for (i = 0; i < saltlen; i++)
		buf[i] = salt[i];

	buf[saltlen+4] = 0x80;
	buf[saltlen + 3] = add;
	PUT_WORD_32_BE((64 + saltlen + 4) << 3, buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += ipad_state[0];
	B += ipad_state[1];
	C += ipad_state[2];
	D += ipad_state[3];
	E += ipad_state[4];

	PUT_WORD_32_BE(A, buf, 0);
	PUT_WORD_32_BE(B, buf, 4);
	PUT_WORD_32_BE(C, buf, 8);
	PUT_WORD_32_BE(D, buf, 12);
	PUT_WORD_32_BE(E, buf, 16);
	PUT_WORD_32_BE(0, buf, 20);
	PUT_WORD_32_BE(0, buf, 24);


	buf[20] = 0x80;
	PUT_WORD_32_BE(0x2A0, buf, 60);

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1short(A, B, C, D, E, W);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
}



static void big_hmac_sha1(uint32_t * input, uint32_t inputlen,
    uint32_t * ipad_state,
    uint32_t * opad_state, uint32_t * tmp_out, int iterations)
{
	int i, lo;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;

	for (i = 0; i < 5; i++)
		W[i] = input[i];

	for (lo = 1; lo < iterations; lo++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];

		W[5] = 0x80000000;
		W[15] = 0x2A0;

		SHA1short(A, B, C, D, E, W);

		A += ipad_state[0];
		B += ipad_state[1];
		C += ipad_state[2];
		D += ipad_state[3];
		E += ipad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = 0x80000000;
		W[15] = 0x2A0;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];

		SHA1short(A, B, C, D, E, W);

		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
	}

	for (i = 0; i < 5; i++)
		tmp_out[i] = SWAP(tmp_out[i]);
}

static void pbkdf2(const uint8_t *pass, int passlen, const uint8_t *salt,
                   int saltlen, int n, uint8_t *out, int outlen)
{
	uint32_t ipad_state[5];
	uint32_t opad_state[5];
	uint32_t tmp_out[5];
	uint32_t i, r, t = 0;

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	for (r = 1; r <= (outlen + 19) / 20; r++) {
		hmac_sha1_(tmp_out, ipad_state, opad_state, salt, saltlen, r);

		big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH, ipad_state, opad_state,
		              tmp_out, n);

		for (i = 0; i < 20 && t < outlen; i++)
#if ARCH_LITTLE_ENDIAN
			out[t++] = ((uint8_t*)tmp_out)[i];
#else
			out[t++] = ((uint8_t*)tmp_out)[i^3];
#endif
	}
}
#endif
#endif /* JOHN_PBKDF2_HMAC_SHA1_H */
