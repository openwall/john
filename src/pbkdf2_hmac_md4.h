/*
 * This software is Copyright (c) 2015 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * salt->skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 16). So to calculate only
 * byte 17-32 (second chunk) you can say "salt->outlen=16 salt->skip_bytes=16"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 16 as opposed to 32.
 */
#ifndef JOHN_PBKDF2_HMAC_MD4_H
#define JOHN_PBKDF2_HMAC_MD4_H

#include <string.h>
#include <stdint.h>

#include "md4.h"
#include "simd-intrinsics.h"

#ifndef MD4_DIGEST_LENGTH
#define MD4_DIGEST_LENGTH 16
#endif

#ifndef MD4_CBLOCK
#define MD4_CBLOCK 64
#endif

#define MD4_BUF_SIZ 16

#ifdef PBKDF1_LOGIC
#define pbkdf2_md4 pbkdf1_md4
#define pbkdf2_md4_sse pbkdf1_md4_sse
#endif

#if !defined(SIMD_COEF_32) || defined (PBKDF2_HMAC_MD4_ALSO_INCLUDE_CTX)

static void _pbkdf2_md4_load_hmac(const unsigned char *K, int KL, MD4_CTX *pIpad, MD4_CTX *pOpad) {
	unsigned char ipad[MD4_CBLOCK], opad[MD4_CBLOCK], k0[MD4_DIGEST_LENGTH];
	int i;

	memset(ipad, 0x36, MD4_CBLOCK);
	memset(opad, 0x5C, MD4_CBLOCK);

	if (KL > MD4_CBLOCK) {
		MD4_CTX ctx;
		MD4_Init( &ctx );
		MD4_Update( &ctx, K, KL);
		MD4_Final( k0, &ctx);
		KL = MD4_DIGEST_LENGTH;
		K = k0;
	}
	for (i = 0; i < KL; i++) {
		ipad[i] ^= K[i];
		opad[i] ^= K[i];
	}
	// save off the first 1/2 of the ipad/opad hashes.  We will NEVER recompute this
	// again, during the rounds, but reuse it. Saves 1/2 the MD4's
	MD4_Init(pIpad);
	MD4_Update(pIpad, ipad, MD4_CBLOCK);
	MD4_Init(pOpad);
	MD4_Update(pOpad, opad, MD4_CBLOCK);
}

static void _pbkdf2_md4(const unsigned char *S, int SL, int R, uint32_t *out,
	                     unsigned char loop, const MD4_CTX *pIpad, const MD4_CTX *pOpad) {
	MD4_CTX ctx;
	unsigned char tmp_hash[MD4_DIGEST_LENGTH];
	int i, j;

	memcpy(&ctx, pIpad, sizeof(MD4_CTX));
	MD4_Update(&ctx, S, SL);
#if !defined (PBKDF1_LOGIC)
	// this 4 byte 'loop' appended to the salt
	MD4_Update(&ctx, "\x0\x0\x0", 3);
	MD4_Update(&ctx, &loop, 1);
#endif
	MD4_Final(tmp_hash, &ctx);

	memcpy(&ctx, pOpad, sizeof(MD4_CTX));
	MD4_Update(&ctx, tmp_hash, MD4_DIGEST_LENGTH);
	MD4_Final(tmp_hash, &ctx);
#if !defined (PBKDF1_LOGIC)
	memcpy(out, tmp_hash, MD4_DIGEST_LENGTH);
#endif
	for (i = 1; i < R; i++) {
		memcpy(&ctx, pIpad, sizeof(MD4_CTX));
		MD4_Update(&ctx, tmp_hash, MD4_DIGEST_LENGTH);
		MD4_Final(tmp_hash, &ctx);

		memcpy(&ctx, pOpad, sizeof(MD4_CTX));
		MD4_Update(&ctx, tmp_hash, MD4_DIGEST_LENGTH);
		MD4_Final(tmp_hash, &ctx);
#if !defined (PBKDF1_LOGIC)
		for (j = 0; j < MD4_DIGEST_LENGTH/sizeof(uint32_t); j++) {
			out[j] ^= ((uint32_t*)tmp_hash)[j];
#if defined (DPAPI_CRAP_LOGIC)
			((uint32_t*)tmp_hash)[j] = out[j];
#endif
		}
#endif
	}
#if defined (PBKDF1_LOGIC)
	// PBKDF1 simply uses end result of all of the HMAC iterations
	for (j = 0; j < MD4_DIGEST_LENGTH/sizeof(uint32_t); j++)
			out[j] = ((uint32_t*)tmp_hash)[j];
#endif
}
static void pbkdf2_md4(const unsigned char *K, int KL, const unsigned char *S, int SL, int R, unsigned char *out, int outlen, int skip_bytes)
{
	union {
		uint32_t x32[MD4_DIGEST_LENGTH/sizeof(uint32_t)];
		unsigned char out[MD4_DIGEST_LENGTH];
	} tmp;
	int loop, loops, i, accum=0;
	MD4_CTX ipad, opad;

	_pbkdf2_md4_load_hmac(K, KL, &ipad, &opad);

	loops = (skip_bytes + outlen + (MD4_DIGEST_LENGTH-1)) / MD4_DIGEST_LENGTH;
	loop = skip_bytes / MD4_DIGEST_LENGTH + 1;
	skip_bytes %= MD4_DIGEST_LENGTH;

	while (loop <= loops) {
		_pbkdf2_md4(S,SL,R,tmp.x32,loop,&ipad,&opad);
		for (i = skip_bytes; i < MD4_DIGEST_LENGTH && accum < outlen; i++) {
			out[accum++] = ((uint8_t*)tmp.out)[i];
		}
		loop++;
		skip_bytes = 0;
	}
}

#endif

#if defined(SIMD_COEF_32) && !defined(OPENCL_FORMAT)

#define SSE_GROUP_SZ_MD4 (SIMD_COEF_32*SIMD_PARA_MD4)


static void _pbkdf2_md4_sse_load_hmac(const unsigned char *K[SSE_GROUP_SZ_MD4], int KL[SSE_GROUP_SZ_MD4], MD4_CTX pIpad[SSE_GROUP_SZ_MD4], MD4_CTX pOpad[SSE_GROUP_SZ_MD4])
{
	unsigned char ipad[MD4_CBLOCK], opad[MD4_CBLOCK], k0[MD4_DIGEST_LENGTH];
	int i, j;

	for (j = 0; j < SSE_GROUP_SZ_MD4; ++j) {
		memset(ipad, 0x36, MD4_CBLOCK);
		memset(opad, 0x5C, MD4_CBLOCK);

		if (KL[j] > MD4_CBLOCK) {
			MD4_CTX ctx;
			MD4_Init( &ctx );
			MD4_Update( &ctx, K[j], KL[j]);
			MD4_Final( k0, &ctx);
			KL[j] = MD4_DIGEST_LENGTH;
			K[j] = k0;
		}
		for (i = 0; i < KL[j]; i++) {
			ipad[i] ^= K[j][i];
			opad[i] ^= K[j][i];
		}
		// save off the first 1/2 of the ipad/opad hashes.  We will NEVER recompute this
		// again, during the rounds, but reuse it. Saves 1/4 the MD4's
		MD4_Init(&(pIpad[j]));
		MD4_Update(&(pIpad[j]), ipad, MD4_CBLOCK);
		MD4_Init(&(pOpad[j]));
		MD4_Update(&(pOpad[j]), opad, MD4_CBLOCK);
	}
}

static void pbkdf2_md4_sse(const unsigned char *K[SSE_GROUP_SZ_MD4], int KL[SSE_GROUP_SZ_MD4], const unsigned char *S, int SL, int R, unsigned char *out[SSE_GROUP_SZ_MD4], int outlen, int skip_bytes)
{
	unsigned char tmp_hash[MD4_DIGEST_LENGTH];
	uint32_t *i1, *i2, *o1, *ptmp;
	unsigned int i, j;
	uint32_t dgst[SSE_GROUP_SZ_MD4][MD4_DIGEST_LENGTH/sizeof(uint32_t)];
	int loops, accum=0;
	unsigned char loop;
	MD4_CTX ipad[SSE_GROUP_SZ_MD4], opad[SSE_GROUP_SZ_MD4], ctx;

	// sse_hash1 would need to be 'adjusted' for MD4_PARA
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_hash1[MD4_BUF_SIZ*sizeof(uint32_t)*SSE_GROUP_SZ_MD4];
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_crypt1[MD4_DIGEST_LENGTH*SSE_GROUP_SZ_MD4];
	JTR_ALIGN(MEM_ALIGN_SIMD) unsigned char sse_crypt2[MD4_DIGEST_LENGTH*SSE_GROUP_SZ_MD4];
	i1 = (uint32_t*)sse_crypt1;
	i2 = (uint32_t*)sse_crypt2;
	o1 = (uint32_t*)sse_hash1;

	// we need to set ONE time, the upper half of the data buffer.  We put the 0x80 byte at offset 16,
	// then zero out the rest of the buffer, putting 0x2A0 (#bits), into the proper location in the buffer.  Once this
	// part of the buffer is setup, we never touch it again, for the rest of the crypt.  We simply overwrite the first
	// half of this buffer, over and over again, with results of the prior hash.
	for (j = 0; j < SSE_GROUP_SZ_MD4/SIMD_COEF_32; ++j) {
		ptmp = &o1[j*SIMD_COEF_32*MD4_BUF_SIZ];
		for (i = 0; i < SIMD_COEF_32; ++i)
			ptmp[ (MD4_DIGEST_LENGTH/sizeof(uint32_t))*SIMD_COEF_32 + (i&(SIMD_COEF_32-1))] = 0x80;
		for (i = (MD4_DIGEST_LENGTH/sizeof(uint32_t)+1)*SIMD_COEF_32; i < 14*SIMD_COEF_32; ++i)
			ptmp[i] = 0;
		for (i = 0; i < SIMD_COEF_32; ++i) {
			ptmp[14*SIMD_COEF_32 + i] = ((64+MD4_DIGEST_LENGTH)<<3); // all encrypts are 64+16 bytes.
			ptmp[15*SIMD_COEF_32 + i] = 0;
		}
	}

	// Load up the IPAD and OPAD values, saving off the first half of the crypt.  We then push the ipad/opad all
	// the way to the end, and that ends up being the first iteration of the pbkdf2.  From that point on, we use
	// the 2 first halves, to load the md4256 2nd part of each crypt, in each loop.
	_pbkdf2_md4_sse_load_hmac(K, KL, ipad, opad);
	for (j = 0; j < SSE_GROUP_SZ_MD4; ++j) {
		ptmp = &i1[(j/SIMD_COEF_32)*SIMD_COEF_32*(MD4_DIGEST_LENGTH/sizeof(uint32_t))+(j&(SIMD_COEF_32-1))];
		ptmp[0]          = ipad[j].A;
		ptmp[SIMD_COEF_32]   = ipad[j].B;
		ptmp[SIMD_COEF_32*2] = ipad[j].C;
		ptmp[SIMD_COEF_32*3] = ipad[j].D;
		ptmp = &i2[(j/SIMD_COEF_32)*SIMD_COEF_32*(MD4_DIGEST_LENGTH/sizeof(uint32_t))+(j&(SIMD_COEF_32-1))];
		ptmp[0]          = opad[j].A;
		ptmp[SIMD_COEF_32]   = opad[j].B;
		ptmp[SIMD_COEF_32*2] = opad[j].C;
		ptmp[SIMD_COEF_32*3] = opad[j].D;
	}

	loops = (skip_bytes + outlen + (MD4_DIGEST_LENGTH-1)) / MD4_DIGEST_LENGTH;
	loop = skip_bytes / MD4_DIGEST_LENGTH + 1;
	skip_bytes %= MD4_DIGEST_LENGTH;

	while (loop <= loops) {
		unsigned int k;
		for (j = 0; j < SSE_GROUP_SZ_MD4; ++j) {
			memcpy(&ctx, &ipad[j], sizeof(ctx));
			MD4_Update(&ctx, S, SL);
			// this 1 appended to the salt, allows us to do passwords up
			// to and including 64 bytes long.  If we wanted longer passwords,
			// then we would have to call the HMAC multiple times (with the
			// rounds between, but each chunk of password we would use a larger
			// number appended to the salt. The first roung (64 byte pw), and
			// we simply append the first number (0001)
#if !defined (PBKDF1_LOGIC)
			MD4_Update(&ctx, "\x0\x0\x0", 3);
			MD4_Update(&ctx, &loop, 1);
#endif
			MD4_Final(tmp_hash, &ctx);

			memcpy(&ctx, &opad[j], sizeof(ctx));
			MD4_Update(&ctx, tmp_hash, MD4_DIGEST_LENGTH);
			MD4_Final(tmp_hash, &ctx);

			// now convert this from flat into SIMD_COEF_32 buffers.
			// Also, perform the 'first' ^= into the crypt buffer.
			ptmp = &o1[(j/SIMD_COEF_32)*SIMD_COEF_32*MD4_BUF_SIZ+(j&(SIMD_COEF_32-1))];
			ptmp[0]           = dgst[j][0] = ctx.A;
			ptmp[SIMD_COEF_32]    = dgst[j][1] = ctx.B;
			ptmp[SIMD_COEF_32*2]  = dgst[j][2] = ctx.C;
			ptmp[SIMD_COEF_32*3]  = dgst[j][3] = ctx.D;
		}

		// Here is the inner loop.  We loop from 1 to count.  iteration 0 was done in the ipad/opad computation.
		for (i = 1; i < R; i++) {
			SIMDmd4body((unsigned char*)o1,o1,i1, SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
			SIMDmd4body((unsigned char*)o1,o1,i2, SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
#if !defined (PBKDF1_LOGIC)
			for (k = 0; k < SSE_GROUP_SZ_MD4; k++) {
				unsigned *p = &o1[(k/SIMD_COEF_32)*SIMD_COEF_32*MD4_BUF_SIZ + (k&(SIMD_COEF_32-1))];
				for (j = 0; j < (MD4_DIGEST_LENGTH/sizeof(uint32_t)); j++) {
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
		for (k = 0; k < SSE_GROUP_SZ_MD4; k++) {
			unsigned *p = &o1[(k/SIMD_COEF_32)*SIMD_COEF_32*MD4_BUF_SIZ + (k&(SIMD_COEF_32-1))];
			for (j = 0; j < (MD4_DIGEST_LENGTH/sizeof(uint32_t)); j++)
				dgst[k][j] = p[(j*SIMD_COEF_32)];
		}
#endif

		for (i = skip_bytes; i < MD4_DIGEST_LENGTH && accum < outlen; ++i) {
			for (j = 0; j < SSE_GROUP_SZ_MD4; ++j) {
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

#endif /* JOHN_PBKDF2_HMAC_MD4_H */
