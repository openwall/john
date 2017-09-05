// serpent.cpp - written and placed in the public domain by Wei Dai

/* Adapted for TrueCrypt */
/* Adapted for VeraCrypt */

#include <stdlib.h>
#include <string.h>

#include "serpent.h"
#include "arch.h"

#define rotr32(x,n)     (((x) >> n) | ((x) << (32 - n)))
#define rotl32(x,n)     (((x) << n) | ((x) >> (32 - n)))
#define rotr64(x,n)     (((x) >> n) | ((x) << (64 - n)))
#define rotl64(x,n)     (((x) << n) | ((x) >> (64 - n)))

uint32_t MirrorBytes32 (uint32_t x)
{
	uint32_t n = (uint8_t) x;

	n <<= 8; n |= (uint8_t) (x >> 8);
	n <<= 8; n |= (uint8_t) (x >> 16);

	return (n << 8) | (uint8_t) (x >> 24);
}

#if ARCH_LITTLE_ENDIAN
#       define LE32(x) (x)
#else
#       define LE32(x) MirrorBytes32(x)
#endif

// linear transformation
#define LT(i,a,b,c,d,e) { \
	a = rotl32(a, 13); \
	c = rotl32(c, 3); \
	d = rotl32(d ^ c ^ (a << 3), 7); \
	b = rotl32(b ^ a ^ c, 1); \
	a = rotl32(a ^ b ^ d, 5); \
	c = rotl32(c ^ d ^ (b << 7), 22); }

// inverse linear transformation
#define ILT(i,a,b,c,d,e) { \
	c = rotr32(c, 22); \
	a = rotr32(a, 5); \
	c ^= d ^ (b << 7); \
	a ^= b ^ d; \
	b = rotr32(b, 1); \
	d = rotr32(d, 7) ^ c ^ (a << 3); \
	b ^= a ^ c; \
	c = rotr32(c, 3); \
	a = rotr32(a, 13); }

// order of output from S-box functions
#define beforeS0(f) f(0,a,b,c,d,e)
#define afterS0(f) f(1,b,e,c,a,d)
#define afterS1(f) f(2,c,b,a,e,d)
#define afterS2(f) f(3,a,e,b,d,c)
#define afterS3(f) f(4,e,b,d,c,a)
#define afterS4(f) f(5,b,a,e,c,d)
#define afterS5(f) f(6,a,c,b,e,d)
#define afterS6(f) f(7,a,c,d,b,e)
#define afterS7(f) f(8,d,e,b,a,c)

// order of output from inverse S-box functions
#define beforeI7(f) f(8,a,b,c,d,e)
#define afterI7(f) f(7,d,a,b,e,c)
#define afterI6(f) f(6,a,b,c,e,d)
#define afterI5(f) f(5,b,d,e,c,a)
#define afterI4(f) f(4,b,c,e,a,d)
#define afterI3(f) f(3,a,b,e,c,d)
#define afterI2(f) f(2,b,d,e,c,a)
#define afterI1(f) f(1,a,b,c,e,d)
#define afterI0(f) f(0,a,d,b,e,c)

// The instruction sequences for the S-box functions
// come from Dag Arne Osvik's paper "Speeding up Serpent".

#define S0(i, r0, r1, r2, r3, r4) \
       {        \
    r3 ^= r0;   \
    r4 = r1;    \
    r1 &= r3;   \
    r4 ^= r2;   \
    r1 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r4;   \
    r4 ^= r3;   \
    r3 ^= r2;   \
    r2 |= r1;   \
    r2 ^= r4;   \
    r4 = ~r4;   \
    r4 |= r1;   \
    r1 ^= r3;   \
    r1 ^= r4;   \
    r3 |= r0;   \
    r1 ^= r3;   \
    r4 ^= r3;   \
            }

#define I0(i, r0, r1, r2, r3, r4) \
       {        \
    r2 = ~r2;   \
    r4 = r1;    \
    r1 |= r0;   \
    r4 = ~r4;   \
    r1 ^= r2;   \
    r2 |= r4;   \
    r1 ^= r3;   \
    r0 ^= r4;   \
    r2 ^= r0;   \
    r0 &= r3;   \
    r4 ^= r0;   \
    r0 |= r1;   \
    r0 ^= r2;   \
    r3 ^= r4;   \
    r2 ^= r1;   \
    r3 ^= r0;   \
    r3 ^= r1;   \
    r2 &= r3;   \
    r4 ^= r2;   \
            }

#define S1(i, r0, r1, r2, r3, r4) \
       {        \
    r0 = ~r0;   \
    r2 = ~r2;   \
    r4 = r0;    \
    r0 &= r1;   \
    r2 ^= r0;   \
    r0 |= r3;   \
    r3 ^= r2;   \
    r1 ^= r0;   \
    r0 ^= r4;   \
    r4 |= r1;   \
    r1 ^= r3;   \
    r2 |= r0;   \
    r2 &= r4;   \
    r0 ^= r1;   \
    r1 &= r2;   \
    r1 ^= r0;   \
    r0 &= r2;   \
    r0 ^= r4;   \
            }

#define I1(i, r0, r1, r2, r3, r4) \
       {        \
    r4 = r1;    \
    r1 ^= r3;   \
    r3 &= r1;   \
    r4 ^= r2;   \
    r3 ^= r0;   \
    r0 |= r1;   \
    r2 ^= r3;   \
    r0 ^= r4;   \
    r0 |= r2;   \
    r1 ^= r3;   \
    r0 ^= r1;   \
    r1 |= r3;   \
    r1 ^= r0;   \
    r4 = ~r4;   \
    r4 ^= r1;   \
    r1 |= r0;   \
    r1 ^= r0;   \
    r1 |= r4;   \
    r3 ^= r1;   \
            }

#define S2(i, r0, r1, r2, r3, r4) \
       {        \
    r4 = r0;    \
    r0 &= r2;   \
    r0 ^= r3;   \
    r2 ^= r1;   \
    r2 ^= r0;   \
    r3 |= r4;   \
    r3 ^= r1;   \
    r4 ^= r2;   \
    r1 = r3;    \
    r3 |= r4;   \
    r3 ^= r0;   \
    r0 &= r1;   \
    r4 ^= r0;   \
    r1 ^= r3;   \
    r1 ^= r4;   \
    r4 = ~r4;   \
            }

#define I2(i, r0, r1, r2, r3, r4) \
       {        \
    r2 ^= r3;   \
    r3 ^= r0;   \
    r4 = r3;    \
    r3 &= r2;   \
    r3 ^= r1;   \
    r1 |= r2;   \
    r1 ^= r4;   \
    r4 &= r3;   \
    r2 ^= r3;   \
    r4 &= r0;   \
    r4 ^= r2;   \
    r2 &= r1;   \
    r2 |= r0;   \
    r3 = ~r3;   \
    r2 ^= r3;   \
    r0 ^= r3;   \
    r0 &= r1;   \
    r3 ^= r4;   \
    r3 ^= r0;   \
            }

#define S3(i, r0, r1, r2, r3, r4) \
       {        \
    r4 = r0;    \
    r0 |= r3;   \
    r3 ^= r1;   \
    r1 &= r4;   \
    r4 ^= r2;   \
    r2 ^= r3;   \
    r3 &= r0;   \
    r4 |= r1;   \
    r3 ^= r4;   \
    r0 ^= r1;   \
    r4 &= r0;   \
    r1 ^= r3;   \
    r4 ^= r2;   \
    r1 |= r0;   \
    r1 ^= r2;   \
    r0 ^= r3;   \
    r2 = r1;    \
    r1 |= r3;   \
    r1 ^= r0;   \
            }

#define I3(i, r0, r1, r2, r3, r4) \
       {        \
    r4 = r2;    \
    r2 ^= r1;   \
    r1 &= r2;   \
    r1 ^= r0;   \
    r0 &= r4;   \
    r4 ^= r3;   \
    r3 |= r1;   \
    r3 ^= r2;   \
    r0 ^= r4;   \
    r2 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r1;   \
    r4 ^= r2;   \
    r2 &= r3;   \
    r1 |= r3;   \
    r1 ^= r2;   \
    r4 ^= r0;   \
    r2 ^= r4;   \
            }

#define S4(i, r0, r1, r2, r3, r4) \
       {        \
    r1 ^= r3;   \
    r3 = ~r3;   \
    r2 ^= r3;   \
    r3 ^= r0;   \
    r4 = r1;    \
    r1 &= r3;   \
    r1 ^= r2;   \
    r4 ^= r3;   \
    r0 ^= r4;   \
    r2 &= r4;   \
    r2 ^= r0;   \
    r0 &= r1;   \
    r3 ^= r0;   \
    r4 |= r1;   \
    r4 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r2;   \
    r2 &= r3;   \
    r0 = ~r0;   \
    r4 ^= r2;   \
            }

#define I4(i, r0, r1, r2, r3, r4) \
       {        \
    r4 = r2;    \
    r2 &= r3;   \
    r2 ^= r1;   \
    r1 |= r3;   \
    r1 &= r0;   \
    r4 ^= r2;   \
    r4 ^= r1;   \
    r1 &= r2;   \
    r0 = ~r0;   \
    r3 ^= r4;   \
    r1 ^= r3;   \
    r3 &= r0;   \
    r3 ^= r2;   \
    r0 ^= r1;   \
    r2 &= r0;   \
    r3 ^= r0;   \
    r2 ^= r4;   \
    r2 |= r3;   \
    r3 ^= r0;   \
    r2 ^= r1;   \
            }

#define S5(i, r0, r1, r2, r3, r4) \
       {        \
    r0 ^= r1;   \
    r1 ^= r3;   \
    r3 = ~r3;   \
    r4 = r1;    \
    r1 &= r0;   \
    r2 ^= r3;   \
    r1 ^= r2;   \
    r2 |= r4;   \
    r4 ^= r3;   \
    r3 &= r1;   \
    r3 ^= r0;   \
    r4 ^= r1;   \
    r4 ^= r2;   \
    r2 ^= r0;   \
    r0 &= r3;   \
    r2 = ~r2;   \
    r0 ^= r4;   \
    r4 |= r3;   \
    r2 ^= r4;   \
            }

#define I5(i, r0, r1, r2, r3, r4) \
       {        \
    r1 = ~r1;   \
    r4 = r3;    \
    r2 ^= r1;   \
    r3 |= r0;   \
    r3 ^= r2;   \
    r2 |= r1;   \
    r2 &= r0;   \
    r4 ^= r3;   \
    r2 ^= r4;   \
    r4 |= r0;   \
    r4 ^= r1;   \
    r1 &= r2;   \
    r1 ^= r3;   \
    r4 ^= r2;   \
    r3 &= r4;   \
    r4 ^= r1;   \
    r3 ^= r0;   \
    r3 ^= r4;   \
    r4 = ~r4;   \
            }

#define S6(i, r0, r1, r2, r3, r4) \
       {        \
    r2 = ~r2;   \
    r4 = r3;    \
    r3 &= r0;   \
    r0 ^= r4;   \
    r3 ^= r2;   \
    r2 |= r4;   \
    r1 ^= r3;   \
    r2 ^= r0;   \
    r0 |= r1;   \
    r2 ^= r1;   \
    r4 ^= r0;   \
    r0 |= r3;   \
    r0 ^= r2;   \
    r4 ^= r3;   \
    r4 ^= r0;   \
    r3 = ~r3;   \
    r2 &= r4;   \
    r2 ^= r3;   \
            }

#define I6(i, r0, r1, r2, r3, r4) \
       {        \
    r0 ^= r2;   \
    r4 = r2;    \
    r2 &= r0;   \
    r4 ^= r3;   \
    r2 = ~r2;   \
    r3 ^= r1;   \
    r2 ^= r3;   \
    r4 |= r0;   \
    r0 ^= r2;   \
    r3 ^= r4;   \
    r4 ^= r1;   \
    r1 &= r3;   \
    r1 ^= r0;   \
    r0 ^= r3;   \
    r0 |= r2;   \
    r3 ^= r1;   \
    r4 ^= r0;   \
            }

#define S7(i, r0, r1, r2, r3, r4) \
       {        \
    r4 = r2;    \
    r2 &= r1;   \
    r2 ^= r3;   \
    r3 &= r1;   \
    r4 ^= r2;   \
    r2 ^= r1;   \
    r1 ^= r0;   \
    r0 |= r4;   \
    r0 ^= r2;   \
    r3 ^= r1;   \
    r2 ^= r3;   \
    r3 &= r0;   \
    r3 ^= r4;   \
    r4 ^= r2;   \
    r2 &= r0;   \
    r4 = ~r4;   \
    r2 ^= r4;   \
    r4 &= r0;   \
    r1 ^= r3;   \
    r4 ^= r1;   \
            }

#define I7(i, r0, r1, r2, r3, r4) \
       {        \
    r4 = r2;    \
    r2 ^= r0;   \
    r0 &= r3;   \
    r2 = ~r2;   \
    r4 |= r3;   \
    r3 ^= r1;   \
    r1 |= r0;   \
    r0 ^= r2;   \
    r2 &= r4;   \
    r1 ^= r2;   \
    r2 ^= r0;   \
    r0 |= r2;   \
    r3 &= r4;   \
    r0 ^= r3;   \
    r4 ^= r1;   \
    r3 ^= r4;   \
    r4 |= r0;   \
    r3 ^= r2;   \
    r4 ^= r2;   \
            }

// key xor
#define KX(r, a, b, c, d, e)	{\
	a ^= k[4 * r + 0]; \
	b ^= k[4 * r + 1]; \
	c ^= k[4 * r + 2]; \
	d ^= k[4 * r + 3];}


void serpent_set_key(const uint8_t userKey[],uint8_t *ks)
{
	uint32_t a,b,c,d,e;
	uint32_t *k = (uint32_t *)ks;
	uint32_t t;
	int i;

	for (i = 0; i < 8; i++)
		k[i] = LE32(((uint32_t*)userKey)[i]);

	k += 8;
	t = k[-1];
	for (i = 0; i < 132; ++i)
		k[i] = t = rotl32(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
	k -= 20;

#define LK(r, a, b, c, d, e) {\
	a = k[(8-r)*4 + 0]; \
	b = k[(8-r)*4 + 1]; \
	c = k[(8-r)*4 + 2]; \
	d = k[(8-r)*4 + 3];}

#define SK(r, a, b, c, d, e) {\
	k[(8-r)*4 + 4] = a; \
	k[(8-r)*4 + 5] = b; \
	k[(8-r)*4 + 6] = c; \
	k[(8-r)*4 + 7] = d;}

	for (i=0; i<4; i++)
	{
		afterS2(LK); afterS2(S3); afterS3(SK);
		afterS1(LK); afterS1(S2); afterS2(SK);
		afterS0(LK); afterS0(S1); afterS1(SK);
		beforeS0(LK); beforeS0(S0); afterS0(SK);
		k += 8*4;
		afterS6(LK); afterS6(S7); afterS7(SK);
		afterS5(LK); afterS5(S6); afterS6(SK);
		afterS4(LK); afterS4(S5); afterS5(SK);
		afterS3(LK); afterS3(S4); afterS4(SK);
	}
	afterS2(LK); afterS2(S3); afterS3(SK);
}

void serpent_encrypt(const uint8_t *inBlock, uint8_t *outBlock, uint8_t *ks)
{
	uint32_t a, b, c, d, e;
	unsigned int i=1;
	const uint32_t *k = (uint32_t *)ks + 8;
	uint32_t *in = (uint32_t *) inBlock;
	uint32_t *out = (uint32_t *) outBlock;

	a = LE32(in[0]);
	b = LE32(in[1]);
	c = LE32(in[2]);
	d = LE32(in[3]);

	do
	{
		beforeS0(KX); beforeS0(S0); afterS0(LT);
		afterS0(KX); afterS0(S1); afterS1(LT);
		afterS1(KX); afterS1(S2); afterS2(LT);
		afterS2(KX); afterS2(S3); afterS3(LT);
		afterS3(KX); afterS3(S4); afterS4(LT);
		afterS4(KX); afterS4(S5); afterS5(LT);
		afterS5(KX); afterS5(S6); afterS6(LT);
		afterS6(KX); afterS6(S7);

		if (i == 4)
			break;

		++i;
		c = b;
		b = e;
		e = d;
		d = a;
		a = e;
		k += 32;
		beforeS0(LT);
	}
	while (1);

	afterS7(KX);

	out[0] = LE32(d);
	out[1] = LE32(e);
	out[2] = LE32(b);
	out[3] = LE32(a);
}

void serpent_decrypt(const uint8_t *inBlock, uint8_t *outBlock, uint8_t *ks)
{
	uint32_t a, b, c, d, e;
	const uint32_t *k = (uint32_t *)ks + 104;
	unsigned int i=4;
	uint32_t *in = (uint32_t *) inBlock;
	uint32_t *out = (uint32_t *) outBlock;

	a = LE32(in[0]);
	b = LE32(in[1]);
	c = LE32(in[2]);
	d = LE32(in[3]);

	beforeI7(KX);
	goto start;

	do
	{
		c = b;
		b = d;
		d = e;
		k -= 32;
		beforeI7(ILT);
start:
		beforeI7(I7); afterI7(KX);
		afterI7(ILT); afterI7(I6); afterI6(KX);
		afterI6(ILT); afterI6(I5); afterI5(KX);
		afterI5(ILT); afterI5(I4); afterI4(KX);
		afterI4(ILT); afterI4(I3); afterI3(KX);
		afterI3(ILT); afterI3(I2); afterI2(KX);
		afterI2(ILT); afterI2(I1); afterI1(KX);
		afterI1(ILT); afterI1(I0); afterI0(KX);
	}
	while (--i != 0);

	out[0] = LE32(a);
	out[1] = LE32(d);
	out[2] = LE32(b);
	out[3] = LE32(e);
}
