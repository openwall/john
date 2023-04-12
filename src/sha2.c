/*
 * This software is
 * Copyright (c) 2012 JimF,
 * Copyright (c) 2012-2023 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 *  FIPS-180-2 compliant SHA-256 implementation
 *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

#include <stdio.h>
#include "arch.h"
#define FORCE_GENERIC_SHA2 1
#include "sha2.h"

#include "params.h"
#include "common.h"
#include "johnswap.h"

static const unsigned char padding[128] = { 0x80, 0 /* 0,0,0,0.... */ };

// I wish C++ had a good 'known' ror command :( Hopefully the compilers will be nice with this one.
// GCC seems to do a good job of converting into roll, which is 'good' enough.  The rotates are the
// 'wrong' direction (rol(x,32-y) vs ror(x,y)), but that's not is a problem, same cycle count.
#define ROR32(x,n) ((x>>n)|(x<<(32-n)))
#define ROR64(x,n) ((x>>n)|(x<<(64-n)))

// SHA round macros
#define S0(x)     (ROR32(x, 2) ^ ROR32(x,13) ^ ROR32(x,22))
#define S1(x)     (ROR32(x, 6) ^ ROR32(x,11) ^ ROR32(x,25))
#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))
// Only used in the 'rotation' mixing macros, in rounds 17 to 64.
#define R0(x)     (ROR32(x, 7) ^ ROR32(x,18) ^ (x>>3))
#define R1(x)     (ROR32(x,17) ^ ROR32(x,19) ^ (x>>10))
// the feedback Mixing macro.
#define M(t) (W[t&0xF] += (R1(W[(t-2)&0xF]) + W[(t-7)&0xF] + R0(W[(t-15)&0xF])))

// Here is the macro for each 'round' of sha256.
#define R(a,b,c,d,e,f,g,h,x,K) do{	  \
		tmp = h + S1(e) + F1(e,f,g) + K + x; \
		h = S0(a) + F0(a,b,c) + tmp; \
		d += tmp; \
	}while(0)

/*********************************************************************/
/*********************************************************************/
/*** Here is code for SHA224 and SHA256                            ***/
/*********************************************************************/
/*********************************************************************/

void jtr_sha256_hash_block(jtr_sha256_ctx *ctx, const unsigned char data[64], int perform_endian_swap)
{
	uint32_t A, B, C, D, E, F, G, H, tmp, W[16];
#if ARCH_LITTLE_ENDIAN
	int i;
	if (perform_endian_swap) {
		for (i = 0; i < 16; ++i)
			W[i] = JOHNSWAP(*((uint32_t*)&(data[i<<2])));
	} else
#endif
		memcpy(W, data, 16*sizeof(uint32_t));

	// Load state from all prior blocks (or init state)
	A = ctx->h[0];
	B = ctx->h[1];
	C = ctx->h[2];
	D = ctx->h[3];
	E = ctx->h[4];
	F = ctx->h[5];
	G = ctx->h[6];
	H = ctx->h[7];

	R(A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98);
	R(H, A, B, C, D, E, F, G, W[ 1], 0x71374491);
	R(G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF);
	R(F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5);
	R(E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B);
	R(D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1);
	R(C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4);
	R(B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5);
	R(A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98);
	R(H, A, B, C, D, E, F, G, W[ 9], 0x12835B01);
	R(G, H, A, B, C, D, E, F, W[10], 0x243185BE);
	R(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3);
	R(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74);
	R(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE);
	R(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7);
	R(B, C, D, E, F, G, H, A, W[15], 0xC19BF174);
	R(A, B, C, D, E, F, G, H, M(16), 0xE49B69C1);
	R(H, A, B, C, D, E, F, G, M(17), 0xEFBE4786);
	R(G, H, A, B, C, D, E, F, M(18), 0x0FC19DC6);
	R(F, G, H, A, B, C, D, E, M(19), 0x240CA1CC);
	R(E, F, G, H, A, B, C, D, M(20), 0x2DE92C6F);
	R(D, E, F, G, H, A, B, C, M(21), 0x4A7484AA);
	R(C, D, E, F, G, H, A, B, M(22), 0x5CB0A9DC);
	R(B, C, D, E, F, G, H, A, M(23), 0x76F988DA);
	R(A, B, C, D, E, F, G, H, M(24), 0x983E5152);
	R(H, A, B, C, D, E, F, G, M(25), 0xA831C66D);
	R(G, H, A, B, C, D, E, F, M(26), 0xB00327C8);
	R(F, G, H, A, B, C, D, E, M(27), 0xBF597FC7);
	R(E, F, G, H, A, B, C, D, M(28), 0xC6E00BF3);
	R(D, E, F, G, H, A, B, C, M(29), 0xD5A79147);
	R(C, D, E, F, G, H, A, B, M(30), 0x06CA6351);
	R(B, C, D, E, F, G, H, A, M(31), 0x14292967);
	R(A, B, C, D, E, F, G, H, M(32), 0x27B70A85);
	R(H, A, B, C, D, E, F, G, M(33), 0x2E1B2138);
	R(G, H, A, B, C, D, E, F, M(34), 0x4D2C6DFC);
	R(F, G, H, A, B, C, D, E, M(35), 0x53380D13);
	R(E, F, G, H, A, B, C, D, M(36), 0x650A7354);
	R(D, E, F, G, H, A, B, C, M(37), 0x766A0ABB);
	R(C, D, E, F, G, H, A, B, M(38), 0x81C2C92E);
	R(B, C, D, E, F, G, H, A, M(39), 0x92722C85);
	R(A, B, C, D, E, F, G, H, M(40), 0xA2BFE8A1);
	R(H, A, B, C, D, E, F, G, M(41), 0xA81A664B);
	R(G, H, A, B, C, D, E, F, M(42), 0xC24B8B70);
	R(F, G, H, A, B, C, D, E, M(43), 0xC76C51A3);
	R(E, F, G, H, A, B, C, D, M(44), 0xD192E819);
	R(D, E, F, G, H, A, B, C, M(45), 0xD6990624);
	R(C, D, E, F, G, H, A, B, M(46), 0xF40E3585);
	R(B, C, D, E, F, G, H, A, M(47), 0x106AA070);
	R(A, B, C, D, E, F, G, H, M(48), 0x19A4C116);
	R(H, A, B, C, D, E, F, G, M(49), 0x1E376C08);
	R(G, H, A, B, C, D, E, F, M(50), 0x2748774C);
	R(F, G, H, A, B, C, D, E, M(51), 0x34B0BCB5);
	R(E, F, G, H, A, B, C, D, M(52), 0x391C0CB3);
	R(D, E, F, G, H, A, B, C, M(53), 0x4ED8AA4A);
	R(C, D, E, F, G, H, A, B, M(54), 0x5B9CCA4F);
	R(B, C, D, E, F, G, H, A, M(55), 0x682E6FF3);
	R(A, B, C, D, E, F, G, H, M(56), 0x748F82EE);
	R(H, A, B, C, D, E, F, G, M(57), 0x78A5636F);
	R(G, H, A, B, C, D, E, F, M(58), 0x84C87814);
	R(F, G, H, A, B, C, D, E, M(59), 0x8CC70208);
	R(E, F, G, H, A, B, C, D, M(60), 0x90BEFFFA);
	R(D, E, F, G, H, A, B, C, M(61), 0xA4506CEB);
	R(C, D, E, F, G, H, A, B, M(62), 0xBEF9A3F7);
	R(B, C, D, E, F, G, H, A, M(63), 0xC67178F2);

	// save state for usage in next block (or result if this was last block)
	ctx->h[0] += A;
	ctx->h[1] += B;
	ctx->h[2] += C;
	ctx->h[3] += D;
	ctx->h[4] += E;
	ctx->h[5] += F;
	ctx->h[6] += G;
	ctx->h[7] += H;
}

void jtr_sha256_init(jtr_sha256_ctx *ctx, int bIs256) {
	ctx->total = 0;
	if ((ctx->bIs256 = bIs256)) {
		// SHA-256 IV
		ctx->h[0] = 0x6A09E667;
		ctx->h[1] = 0xBB67AE85;
		ctx->h[2] = 0x3C6EF372;
		ctx->h[3] = 0xA54FF53A;
		ctx->h[4] = 0x510E527F;
		ctx->h[5] = 0x9B05688C;
		ctx->h[6] = 0x1F83D9AB;
		ctx->h[7] = 0x5BE0CD19;
	} else {
		// SHA-224 IV
		ctx->h[0] = 0xC1059ED8;
		ctx->h[1] = 0x367CD507;
		ctx->h[2] = 0x3070DD17;
		ctx->h[3] = 0xF70E5939;
		ctx->h[4] = 0xFFC00B31;
		ctx->h[5] = 0x68581511;
		ctx->h[6] = 0x64F98FA7;
		ctx->h[7] = 0xBEFA4FA4;
	}
}

void jtr_sha256_update(jtr_sha256_ctx *ctx, const void *_input, int ilenlft)
{
	int left, fill;
	const unsigned char *input;

	if (ilenlft <= 0)
		return;

	input = (const unsigned char*)_input;
	left = ctx->total & 0x3F;
	fill = 0x40 - left;

	ctx->total += ilenlft;

	if (left && ilenlft >= fill)
	{
		memcpy(ctx->buffer + left, input, fill);
		jtr_sha256_hash_block(ctx, ctx->buffer, 1);
		input += fill;
		ilenlft  -= fill;
		left = 0;
	}

	while(ilenlft >= 0x40)
	{
		jtr_sha256_hash_block(ctx, input, 1);
		input += 0x40;
		ilenlft  -= 0x40;
	}

	if (ilenlft > 0)
		memcpy(ctx->buffer + left, input, ilenlft);
}

void jtr_sha256_final(void *_output, jtr_sha256_ctx *ctx)
{
	uint32_t last, padcnt;
	uint32_t bits;
	union {
		uint32_t wlen[2];
		unsigned char mlen[8];  // need aligned on sparc
	} m;
	unsigned char *output = (unsigned char*)_output;

	bits = (ctx->total <<  3);
	m.wlen[0] = 0;
#if ARCH_LITTLE_ENDIAN
	m.wlen[1] = JOHNSWAP(bits);
#else
	m.wlen[1] = bits;
#endif

	last = ctx->total & 0x3F;
	padcnt = (last < 56) ? (56 - last) : (120 - last);

	jtr_sha256_update(ctx, (unsigned char *) padding, padcnt);
	jtr_sha256_update(ctx, m.mlen, 8);

	// the SHA2_GENERIC_DO_NOT_BUILD_ALIGNED == 1 is to force build on
	// required aligned systems without doing the alignment checking.
	// it IS faster (about 2.5%), and once the data is properly aligned
	// in the formats, the alignment checking is nore needed any more.
#if ARCH_ALLOWS_UNALIGNED == 1 || SHA2_GENERIC_DO_NOT_BUILD_ALIGNED == 1
	OUTBE32(ctx->h[0], output,  0);
	OUTBE32(ctx->h[1], output,  4);
	OUTBE32(ctx->h[2], output,  8);
	OUTBE32(ctx->h[3], output, 12);
	OUTBE32(ctx->h[4], output, 16);
	OUTBE32(ctx->h[5], output, 20);
	OUTBE32(ctx->h[6], output, 24);
	if (ctx->bIs256)
		OUTBE32(ctx->h[7], output, 28);
#else
	if (is_aligned(output,sizeof(uint32_t))) {
		OUTBE32(ctx->h[0], output,  0);
		OUTBE32(ctx->h[1], output,  4);
		OUTBE32(ctx->h[2], output,  8);
		OUTBE32(ctx->h[3], output, 12);
		OUTBE32(ctx->h[4], output, 16);
		OUTBE32(ctx->h[5], output, 20);
		OUTBE32(ctx->h[6], output, 24);
		if (ctx->bIs256)
			OUTBE32(ctx->h[7], output, 28);
	} else {
		union {
			uint32_t x[8];
			unsigned char c[64];
		} m;
		unsigned char *tmp = m.c;
		OUTBE32(ctx->h[0], tmp,  0);
		OUTBE32(ctx->h[1], tmp,  4);
		OUTBE32(ctx->h[2], tmp,  8);
		OUTBE32(ctx->h[3], tmp, 12);
		OUTBE32(ctx->h[4], tmp, 16);
		OUTBE32(ctx->h[5], tmp, 20);
		OUTBE32(ctx->h[6], tmp, 24);
		if (ctx->bIs256) {
			OUTBE32(ctx->h[7], tmp, 28);
			memcpy(output, tmp, 32);
		} else
			memcpy(output, tmp, 28);
	}
#endif
}

#define INIT_D 0xf70e5939

void sha224_reverse(uint32_t *hash)
{
	hash[3] -= INIT_D;
}

void sha224_unreverse(uint32_t *hash)
{
	hash[3] += INIT_D;
}

#undef INIT_D

#define INIT_A 0x6a09e667
#define INIT_B 0xbb67ae85
#define INIT_C 0x3c6ef372
#define INIT_D 0xa54ff53a
#define INIT_E 0x510e527f
#define INIT_F 0x9b05688c
#define INIT_G 0x1f83d9ab
#define INIT_H 0x5be0cd19

#define ror(x, n)       ((x >> n) | (x << (32 - n)))

void sha256_reverse(uint32_t *hash)
{
	uint32_t a, b, c, d, e, f, g, h, s0, maj, tmp;

	a = hash[0] - INIT_A;
	b = hash[1] - INIT_B;
	c = hash[2] - INIT_C;
	d = hash[3] - INIT_D;
	e = hash[4] - INIT_E;
	f = hash[5] - INIT_F;
	g = hash[6] - INIT_G;
	h = hash[7] - INIT_H;

	s0 = ror(b, 2) ^ ror(b, 13) ^ ror(b, 22);
	maj = (b & c) ^ (b & d) ^ (c & d);
	tmp = d;
	d = e - (a - (s0 + maj));
	e = f;
	f = g;
	g = h;
	a = b;
	b = c;
	c = tmp;

	s0 = ror(b, 2) ^ ror(b, 13) ^ ror(b, 22);
	maj = (b & c) ^ (b & d) ^ (c & d);
	tmp = d;
	d = e - (a - (s0 + maj));
	e = f;
	f = g;
	a = b;
	b = c;
	c = tmp;

	s0 = ror(b, 2) ^ ror(b, 13) ^ ror(b, 22);
	maj = (b & c) ^ (b & d) ^ (c & d);
	tmp = d;
	d = e - (a - (s0 + maj));
	e = f;
	a = b;
	b = c;
	c = tmp;

	s0 = ror(b, 2) ^ ror(b, 13) ^ ror(b, 22);
	maj = (b & c) ^ (b & d) ^ (c & d);

	hash[0] = e - (a - (s0 + maj));
}

#undef ror
#undef INIT_H
#undef INIT_G
#undef INIT_F
#undef INIT_E
#undef INIT_D
#undef INIT_C
#undef INIT_B
#undef INIT_A
#undef S0
#undef S1
#undef R0
#undef R1
#undef F0
#undef F1
#undef R

/*********************************************************************/
/*********************************************************************/
/*** Here is code for SHA386 and SHA512                            ***/
/*********************************************************************/
/*********************************************************************/

#define INIT_A 0x6a09e667f3bcc908ULL
#define INIT_B 0xbb67ae8584caa73bULL
#define INIT_C 0x3c6ef372fe94f82bULL
#define INIT_D 0xa54ff53a5f1d36f1ULL
#define INIT_E 0x510e527fade682d1ULL
#define INIT_F 0x9b05688c2b3e6c1fULL
#define INIT_G 0x1f83d9abfb41bd6bULL
#define INIT_H 0x5be0cd19137e2179ULL

#define S0(x) (ROR64(x,28) ^ ROR64(x,34) ^ ROR64(x,39))
#define S1(x) (ROR64(x,14) ^ ROR64(x,18) ^ ROR64(x,41))
#define R0(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ (x>>7))
#define R1(x) (ROR64(x,19) ^ ROR64(x,61) ^ (x>>6))

#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))

#define R(n,a,b,c,d,e,f,g,h) do{	  \
		tmp = h + S1(e) + F1(e,f,g) + K[n] + W[n]; \
		h = S0(a) + F0(a,b,c) + tmp; \
		d += tmp; \
	} while(0)

static const uint64_t K[80] =
{
	0x428A2F98D728AE22ULL,  0x7137449123EF65CDULL,
	0xB5C0FBCFEC4D3B2FULL,  0xE9B5DBA58189DBBCULL,
	0x3956C25BF348B538ULL,  0x59F111F1B605D019ULL,
	0x923F82A4AF194F9BULL,  0xAB1C5ED5DA6D8118ULL,
	0xD807AA98A3030242ULL,  0x12835B0145706FBEULL,
	0x243185BE4EE4B28CULL,  0x550C7DC3D5FFB4E2ULL,
	0x72BE5D74F27B896FULL,  0x80DEB1FE3B1696B1ULL,
	0x9BDC06A725C71235ULL,  0xC19BF174CF692694ULL,
	0xE49B69C19EF14AD2ULL,  0xEFBE4786384F25E3ULL,
	0x0FC19DC68B8CD5B5ULL,  0x240CA1CC77AC9C65ULL,
	0x2DE92C6F592B0275ULL,  0x4A7484AA6EA6E483ULL,
	0x5CB0A9DCBD41FBD4ULL,  0x76F988DA831153B5ULL,
	0x983E5152EE66DFABULL,  0xA831C66D2DB43210ULL,
	0xB00327C898FB213FULL,  0xBF597FC7BEEF0EE4ULL,
	0xC6E00BF33DA88FC2ULL,  0xD5A79147930AA725ULL,
	0x06CA6351E003826FULL,  0x142929670A0E6E70ULL,
	0x27B70A8546D22FFCULL,  0x2E1B21385C26C926ULL,
	0x4D2C6DFC5AC42AEDULL,  0x53380D139D95B3DFULL,
	0x650A73548BAF63DEULL,  0x766A0ABB3C77B2A8ULL,
	0x81C2C92E47EDAEE6ULL,  0x92722C851482353BULL,
	0xA2BFE8A14CF10364ULL,  0xA81A664BBC423001ULL,
	0xC24B8B70D0F89791ULL,  0xC76C51A30654BE30ULL,
	0xD192E819D6EF5218ULL,  0xD69906245565A910ULL,
	0xF40E35855771202AULL,  0x106AA07032BBD1B8ULL,
	0x19A4C116B8D2D0C8ULL,  0x1E376C085141AB53ULL,
	0x2748774CDF8EEB99ULL,  0x34B0BCB5E19B48A8ULL,
	0x391C0CB3C5C95A63ULL,  0x4ED8AA4AE3418ACBULL,
	0x5B9CCA4F7763E373ULL,  0x682E6FF3D6B2B8A3ULL,
	0x748F82EE5DEFB2FCULL,  0x78A5636F43172F60ULL,
	0x84C87814A1F0AB72ULL,  0x8CC702081A6439ECULL,
	0x90BEFFFA23631E28ULL,  0xA4506CEBDE82BDE9ULL,
	0xBEF9A3F7B2C67915ULL,  0xC67178F2E372532BULL,
	0xCA273ECEEA26619CULL,  0xD186B8C721C0C207ULL,
	0xEADA7DD6CDE0EB1EULL,  0xF57D4F7FEE6ED178ULL,
	0x06F067AA72176FBAULL,  0x0A637DC5A2C898A6ULL,
	0x113F9804BEF90DAEULL,  0x1B710B35131C471BULL,
	0x28DB77F523047D84ULL,  0x32CAAB7B40C72493ULL,
	0x3C9EBE0A15C9BEBCULL,  0x431D67C49C100D4CULL,
	0x4CC5D4BECB3E42B6ULL,  0x597F299CFC657E2AULL,
	0x5FCB6FAB3AD6FAECULL,  0x6C44198C4A475817ULL
};

void jtr_sha512_hash_block(jtr_sha512_ctx *ctx, const unsigned char data[128], int perform_endian_swap)
{
	uint64_t A, B, C, D, E, F, G, H, tmp, W[80];
	int i;

#if ARCH_LITTLE_ENDIAN
	if (perform_endian_swap) {
		for (i = 0; i < 16; i++) {
			W[i] = JOHNSWAP64(*((uint64_t *)&(data[i<<3])));
		}
	} else
#endif
	{
		i = 16;
		memcpy(W, data, 128);
	}

	for (; i < 80; i++)
		W[i] = R1(W[i - 2]) + W[i - 7] + R0(W[i - 15]) + W[i - 16];

	A = ctx->h[0];
	B = ctx->h[1];
	C = ctx->h[2];
	D = ctx->h[3];
	E = ctx->h[4];
	F = ctx->h[5];
	G = ctx->h[6];
	H = ctx->h[7];

	R( 0, A, B, C, D, E, F, G, H);
	R( 1, H, A, B, C, D, E, F, G);
	R( 2, G, H, A, B, C, D, E, F);
	R( 3, F, G, H, A, B, C, D, E);
	R( 4, E, F, G, H, A, B, C, D);
	R( 5, D, E, F, G, H, A, B, C);
	R( 6, C, D, E, F, G, H, A, B);
	R( 7, B, C, D, E, F, G, H, A);
	R( 8, A, B, C, D, E, F, G, H);
	R( 9, H, A, B, C, D, E, F, G);
	R(10, G, H, A, B, C, D, E, F);
	R(11, F, G, H, A, B, C, D, E);
	R(12, E, F, G, H, A, B, C, D);
	R(13, D, E, F, G, H, A, B, C);
	R(14, C, D, E, F, G, H, A, B);
	R(15, B, C, D, E, F, G, H, A);
	R(16, A, B, C, D, E, F, G, H);
	R(17, H, A, B, C, D, E, F, G);
	R(18, G, H, A, B, C, D, E, F);
	R(19, F, G, H, A, B, C, D, E);
	R(20, E, F, G, H, A, B, C, D);
	R(21, D, E, F, G, H, A, B, C);
	R(22, C, D, E, F, G, H, A, B);
	R(23, B, C, D, E, F, G, H, A);
	R(24, A, B, C, D, E, F, G, H);
	R(25, H, A, B, C, D, E, F, G);
	R(26, G, H, A, B, C, D, E, F);
	R(27, F, G, H, A, B, C, D, E);
	R(28, E, F, G, H, A, B, C, D);
	R(29, D, E, F, G, H, A, B, C);
	R(30, C, D, E, F, G, H, A, B);
	R(31, B, C, D, E, F, G, H, A);
	R(32, A, B, C, D, E, F, G, H);
	R(33, H, A, B, C, D, E, F, G);
	R(34, G, H, A, B, C, D, E, F);
	R(35, F, G, H, A, B, C, D, E);
	R(36, E, F, G, H, A, B, C, D);
	R(37, D, E, F, G, H, A, B, C);
	R(38, C, D, E, F, G, H, A, B);
	R(39, B, C, D, E, F, G, H, A);
	R(40, A, B, C, D, E, F, G, H);
	R(41, H, A, B, C, D, E, F, G);
	R(42, G, H, A, B, C, D, E, F);
	R(43, F, G, H, A, B, C, D, E);
	R(44, E, F, G, H, A, B, C, D);
	R(45, D, E, F, G, H, A, B, C);
	R(46, C, D, E, F, G, H, A, B);
	R(47, B, C, D, E, F, G, H, A);
	R(48, A, B, C, D, E, F, G, H);
	R(49, H, A, B, C, D, E, F, G);
	R(50, G, H, A, B, C, D, E, F);
	R(51, F, G, H, A, B, C, D, E);
	R(52, E, F, G, H, A, B, C, D);
	R(53, D, E, F, G, H, A, B, C);
	R(54, C, D, E, F, G, H, A, B);
	R(55, B, C, D, E, F, G, H, A);
	R(56, A, B, C, D, E, F, G, H);
	R(57, H, A, B, C, D, E, F, G);
	R(58, G, H, A, B, C, D, E, F);
	R(59, F, G, H, A, B, C, D, E);
	R(60, E, F, G, H, A, B, C, D);
	R(61, D, E, F, G, H, A, B, C);
	R(62, C, D, E, F, G, H, A, B);
	R(63, B, C, D, E, F, G, H, A);
	R(64, A, B, C, D, E, F, G, H);
	R(65, H, A, B, C, D, E, F, G);
	R(66, G, H, A, B, C, D, E, F);
	R(67, F, G, H, A, B, C, D, E);
	R(68, E, F, G, H, A, B, C, D);
	R(69, D, E, F, G, H, A, B, C);
	R(70, C, D, E, F, G, H, A, B);
	R(71, B, C, D, E, F, G, H, A);
	R(72, A, B, C, D, E, F, G, H);
	R(73, H, A, B, C, D, E, F, G);
	R(74, G, H, A, B, C, D, E, F);
	R(75, F, G, H, A, B, C, D, E);
	R(76, E, F, G, H, A, B, C, D);
	R(77, D, E, F, G, H, A, B, C);
	R(78, C, D, E, F, G, H, A, B);
	R(79, B, C, D, E, F, G, H, A);

	ctx->h[0] += A;
	ctx->h[1] += B;
	ctx->h[2] += C;
	ctx->h[3] += D;
	ctx->h[4] += E;
	ctx->h[5] += F;
	ctx->h[6] += G;
	ctx->h[7] += H;
}

void jtr_sha512_init(jtr_sha512_ctx *ctx, int bIs512)
{
	ctx->total = 0;
	ctx->bIsQnxBuggy = 0;
	if ((ctx->bIs512 = bIs512))
	{
		/* SHA-512 */
		ctx->h[0] = 0x6A09E667F3BCC908ULL;
		ctx->h[1] = 0xBB67AE8584CAA73BULL;
		ctx->h[2] = 0x3C6EF372FE94F82BULL;
		ctx->h[3] = 0xA54FF53A5F1D36F1ULL;
		ctx->h[4] = 0x510E527FADE682D1ULL;
		ctx->h[5] = 0x9B05688C2B3E6C1FULL;
		ctx->h[6] = 0x1F83D9ABFB41BD6BULL;
		ctx->h[7] = 0x5BE0CD19137E2179ULL;
	}
	else
	{
		/* SHA-384 */
		ctx->h[0] = 0xCBBB9D5DC1059ED8ULL;
		ctx->h[1] = 0x629A292A367CD507ULL;
		ctx->h[2] = 0x9159015A3070DD17ULL;
		ctx->h[3] = 0x152FECD8F70E5939ULL;
		ctx->h[4] = 0x67332667FFC00B31ULL;
		ctx->h[5] = 0x8EB44A8768581511ULL;
		ctx->h[6] = 0xDB0C2E0D64F98FA7ULL;
		ctx->h[7] = 0x47B5481DBEFA4FA4ULL;
	}
}

void jtr_sha512_update(jtr_sha512_ctx *ctx, const void *_input, int ilenlft)
{
	int fill, left;
	const unsigned char *input;

	if (ilenlft <= 0)
		return;

	input = (const unsigned char*)_input;
	left = ctx->total & 0x7F;
	fill = 128 - left;
	ctx->total += ilenlft;

	if (left && ilenlft >= fill)
	{
		memcpy(ctx->buffer + left, input, fill);
		jtr_sha512_hash_block(ctx, ctx->buffer, 1);
		input += fill;
		ilenlft  -= fill;
		left = 0;
	}

	while(ilenlft >= 128)
	{
		jtr_sha512_hash_block(ctx, input, 1);
		input += 128;
		ilenlft  -= 128;
	}

	if (ilenlft > 0)
		memcpy(ctx->buffer + left, input, ilenlft);
}

void jtr_sha512_final(void *_output, jtr_sha512_ctx *ctx)
{
	uint32_t last, padcnt;
	uint64_t bits;
	union {
		uint64_t wlen[2];
		unsigned char mlen[16];  // need aligned on sparc
	} m;
	unsigned char *output = (unsigned char *)_output;

	bits = (ctx->total <<  3);
	m.wlen[0] = 0;
#if ARCH_LITTLE_ENDIAN
	m.wlen[1] = JOHNSWAP64(bits);
#else
	m.wlen[1] = bits;
#endif


	last = ctx->total & 0x7F;
	padcnt = (last < 112) ? (112 - last) : (240 - last);

	// QNX has a bug in it (for the QNX-sha512 hash. That bug is that
	// the final bit length data 'may' be dirty.  This dirty data is from
	// the prior block.Our method of using the 'padding' and padcnt is
	// different from QNX, so we have to preserve and copy this possibly
	// dirty data from the right spot in the buffer.  It looks like QNX
	// set the lower 8 bytes of bit count properly, but then used a 4 byte
	// int to set the top 8 bytes (leaving 4 bytes as dirty buffer). I am
	// not sure about this, but this is what it 'appears' to be. However,
	// this code does replicate the buggy the behavior.
	if (ctx->bIsQnxBuggy && ctx->total >= 116) {
		int off = ctx->total&0x7f;
		if (off >= 128-16 && off < 128-7) {
			ctx->buffer[off++] = 0x80;
			while (off < 128-7)
				ctx->buffer[off++] = 0;
		}
		memcpy(&m.mlen[4], &ctx->buffer[116], 4);
	}

	jtr_sha512_update(ctx, (unsigned char *) padding, padcnt);
	jtr_sha512_update(ctx, m.mlen, 16);

	if (!output) return;

	// the SHA2_GENERIC_DO_NOT_BUILD_ALIGNED == 1 is to force build on
	// required aligned systems without doing the alignment checking.
	// it IS faster (about 2.5%), and once the data is properly aligned
	// in the formats, the alignment checking is nore needed any more.
#if ARCH_ALLOWS_UNALIGNED == 1 || SHA2_GENERIC_DO_NOT_BUILD_ALIGNED == 1
	OUTBE64(ctx->h[0], output,  0);
	OUTBE64(ctx->h[1], output,  8);
	OUTBE64(ctx->h[2], output, 16);
	OUTBE64(ctx->h[3], output, 24);
	OUTBE64(ctx->h[4], output, 32);
	OUTBE64(ctx->h[5], output, 40);
	if (ctx->bIs512) {
		OUTBE64( ctx->h[6], output, 48 );
		OUTBE64( ctx->h[7], output, 56 );
	}
#else
	if (is_aligned(output,sizeof(uint64_t))) {
		OUTBE64(ctx->h[0], output,  0);
		OUTBE64(ctx->h[1], output,  8);
		OUTBE64(ctx->h[2], output, 16);
		OUTBE64(ctx->h[3], output, 24);
		OUTBE64(ctx->h[4], output, 32);
		OUTBE64(ctx->h[5], output, 40);
		if (ctx->bIs512) {
			OUTBE64( ctx->h[6], output, 48 );
			OUTBE64( ctx->h[7], output, 56 );
		}
	} else {
		union {
			uint64_t x[8];
			unsigned char c[64];
		} m;
		unsigned char *tmp = m.c;
		OUTBE64(ctx->h[0], tmp,  0);
		OUTBE64(ctx->h[1], tmp,  8);
		OUTBE64(ctx->h[2], tmp, 16);
		OUTBE64(ctx->h[3], tmp, 24);
		OUTBE64(ctx->h[4], tmp, 32);
		OUTBE64(ctx->h[5], tmp, 40);
		if (ctx->bIs512) {
			OUTBE64(ctx->h[6], tmp, 48);
			OUTBE64(ctx->h[7], tmp, 56);
			memcpy(output, tmp, 64);
		} else
			memcpy(output, tmp, 48);
	}
#endif
}

void sha512_reverse(uint64_t *hash)
{
	uint64_t a, b, c, d, e, f, g, h, s0, maj, tmp;

	a = hash[0] - INIT_A;
	b = hash[1] - INIT_B;
	c = hash[2] - INIT_C;
	d = hash[3] - INIT_D;
	e = hash[4] - INIT_E;
	f = hash[5] - INIT_F;
	g = hash[6] - INIT_G;
	h = hash[7] - INIT_H;

	s0 = ROR64(b, 28) ^ ROR64(b, 34) ^ ROR64(b, 39);
	maj = (b & c) ^ (b & d) ^ (c & d);
	tmp = d;
	d = e - (a - (s0 + maj));
	e = f;
	f = g;
	g = h;
	a = b;
	b = c;
	c = tmp;

	s0 = ROR64(b, 28) ^ ROR64(b, 34) ^ ROR64(b, 39);
	maj = (b & c) ^ (b & d) ^ (c & d);
	tmp = d;
	d = e - (a - (s0 + maj));
	e = f;
	f = g;
	a = b;
	b = c;
	c = tmp;

	s0 = ROR64(b, 28) ^ ROR64(b, 34) ^ ROR64(b, 39);
	maj = (b & c) ^ (b & d) ^ (c & d);
	tmp = d;
	d = e - (a - (s0 + maj));
	e = f;
	a = b;
	b = c;
	c = tmp;

	s0 = ROR64(b, 28) ^ ROR64(b, 34) ^ ROR64(b, 39);
	maj = (b & c) ^ (b & d) ^ (c & d);

	hash[0] = e - (a - (s0 + maj));
}
