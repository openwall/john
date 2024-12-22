/*
 * This software is Copyright (c) 2024 magnum and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#include "opencl_md5.h"

#define RnA(a, b, s)        a = rotate(a, (uint)s) + b

#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

INLINE void md5x50_40(uint* msg)
{
	uint a, b, c, d;
	int i;

	a = msg[0];
	b = msg[1] & 0xff;
	c = 0;
	d = 0;

	for (i = 0; i < 50; ++i) {
		uint aa, bb;

		b |= 0x8000;

		bb = b;
		aa = a;

		/** round 1 */
#if 0
		a = INIT_A;
		b = INIT_B;
		c = INIT_C;
		d = INIT_D;
		MD5_STEP(MD5_F, a, b, c, d, aa, 0xd76aa478,  7);
		MD5_STEP(MD5_F, d, a, b, c, bb, 0xe8c7b756, 12);
		MD5_STEP(MD5_F, c, d, a, b,  0, 0x242070db, 17);
		MD5_STEP(MD5_F, b, c, d, a,  0, 0xc1bdceee, 22);
#else
		a += 0xd76aa477;
		RnA(a, INIT_B, 7);
		d = 0xf8fa0bcc + b + (INIT_C ^ (a & 0x77777777));
		RnA(d, a, 12);
		c = 0xbcdb4dd9 + (INIT_B ^ (d & (a ^ INIT_B)));
		RnA(c, d, 17);
		b = 0xb18b7a77 + (a ^ (c & (d ^ a)));
		RnA(b, c, 22);
#endif
		MD5_STEP(MD5_F, a, b, c, d,  0, 0xf57c0faf,  7);
		MD5_STEP(MD5_F, d, a, b, c,  0, 0x4787c62a, 12);
		MD5_STEP(MD5_F, c, d, a, b,  0, 0xa8304613, 17);
		MD5_STEP(MD5_F, b, c, d, a,  0, 0xfd469501, 22);
		MD5_STEP(MD5_F, a, b, c, d,  0, 0x698098d8,  7);
		MD5_STEP(MD5_F, d, a, b, c,  0, 0x8b44f7af, 12);
		MD5_STEP(MD5_F, c, d, a, b,  0, 0xffff5bb1, 17);
		MD5_STEP(MD5_F, b, c, d, a,  0, 0x895cd7be, 22);
		MD5_STEP(MD5_F, a, b, c, d,  0, 0x6b901122,  7);
		MD5_STEP(MD5_F, d, a, b, c,  0, 0xfd987193, 12);
		MD5_STEP(MD5_F, c, d, a, b, 40, 0xa679438e, 17);
		MD5_STEP(MD5_F, b, c, d, a,  0, 0x49b40821, 22);

		/** round 2 */
		MD5_STEP(MD5_G, a, b, c, d, bb, 0xf61e2562,  5);
		MD5_STEP(MD5_G, d, a, b, c,  0, 0xc040b340,  9);
		MD5_STEP(MD5_G, c, d, a, b,  0, 0x265e5a51, 14);
		MD5_STEP(MD5_G, b, c, d, a, aa, 0xe9b6c7aa, 20);
		MD5_STEP(MD5_G, a, b, c, d,  0, 0xd62f105d,  5);
		MD5_STEP(MD5_G, d, a, b, c,  0, 0x02441453,  9);
		MD5_STEP(MD5_G, c, d, a, b,  0, 0xd8a1e681, 14);
		MD5_STEP(MD5_G, b, c, d, a,  0, 0xe7d3fbc8, 20);
		MD5_STEP(MD5_G, a, b, c, d,  0, 0x21e1cde6,  5);
		MD5_STEP(MD5_G, d, a, b, c, 40, 0xc33707d6,  9);
		MD5_STEP(MD5_G, c, d, a, b,  0, 0xf4d50d87, 14);
		MD5_STEP(MD5_G, b, c, d, a,  0, 0x455a14ed, 20);
		MD5_STEP(MD5_G, a, b, c, d,  0, 0xa9e3e905,  5);
		MD5_STEP(MD5_G, d, a, b, c,  0, 0xfcefa3f8,  9);
		MD5_STEP(MD5_G, c, d, a, b,  0, 0x676f02d9, 14);
		MD5_STEP(MD5_G, b, c, d, a,  0, 0x8d2a4c8a, 20);

		/** round 3 */
		MD5_STEP(MD5_H,  a, b, c, d,  0, 0xfffa3942,  4);
		MD5_STEP(MD5_H2, d, a, b, c,  0, 0x8771f681, 11);
		MD5_STEP(MD5_H,  c, d, a, b,  0, 0x6d9d6122, 16);
		MD5_STEP(MD5_H2, b, c, d, a, 40, 0xfde5380c, 23);
		MD5_STEP(MD5_H,  a, b, c, d, bb, 0xa4beea44,  4);
		MD5_STEP(MD5_H2, d, a, b, c,  0, 0x4bdecfa9, 11);
		MD5_STEP(MD5_H,  c, d, a, b,  0, 0xf6bb4b60, 16);
		MD5_STEP(MD5_H2, b, c, d, a,  0, 0xbebfbc70, 23);
		MD5_STEP(MD5_H,  a, b, c, d,  0, 0x289b7ec6,  4);
		MD5_STEP(MD5_H2, d, a, b, c, aa, 0xeaa127fa, 11);
		MD5_STEP(MD5_H,  c, d, a, b,  0, 0xd4ef3085, 16);
		MD5_STEP(MD5_H2, b, c, d, a,  0, 0x04881d05, 23);
		MD5_STEP(MD5_H,  a, b, c, d,  0, 0xd9d4d039,  4);
		MD5_STEP(MD5_H2, d, a, b, c,  0, 0xe6db99e5, 11);
		MD5_STEP(MD5_H,  c, d, a, b,  0, 0x1fa27cf8, 16);
		MD5_STEP(MD5_H2, b, c, d, a,  0, 0xc4ac5665, 23);

		/** round 4 */
		MD5_STEP(MD5_I, a, b, c, d, aa, 0xf4292244,  6);
		MD5_STEP(MD5_I, d, a, b, c,  0, 0x432aff97, 10);
		MD5_STEP(MD5_I, c, d, a, b, 40, 0xab9423a7, 15);
		MD5_STEP(MD5_I, b, c, d, a,  0, 0xfc93a039, 21);
		MD5_STEP(MD5_I, a, b, c, d,  0, 0x655b59c3,  6);
		MD5_STEP(MD5_I, d, a, b, c,  0, 0x8f0ccc92, 10);
		MD5_STEP(MD5_I, c, d, a, b,  0, 0xffeff47d, 15);
		MD5_STEP(MD5_I, b, c, d, a, bb, 0x85845dd1, 21);
		MD5_STEP(MD5_I, a, b, c, d,  0, 0x6fa87e4f,  6);
		MD5_STEP(MD5_I, d, a, b, c,  0, 0xfe2ce6e0, 10);
		MD5_STEP(MD5_I, c, d, a, b,  0, 0xa3014314, 15);
		MD5_STEP(MD5_I, b, c, d, a,  0, 0x4e0811a1, 21);
		MD5_STEP(MD5_I, a, b, c, d,  0, 0xf7537e82,  6);
		MD5_STEP(MD5_I, d, a, b, c,  0, 0xbd3af235, 10);
		MD5_STEP(MD5_I, c, d, a, b,  0, 0x2ad7d2bb, 15);
		MD5_STEP(MD5_I, b, c, d, a,  0, 0xeb86d391, 21);

		a += INIT_A;
		b = (b + INIT_B) & 0xff;
		c = 0;
		d = 0;
	}

	msg[0] = a;
	msg[1] = b;
	msg[2] = 0;
	msg[3] = 0;
}

INLINE void md5x50_128(uint* msg)
{
	uint a, b, c, d;
	int i;

	a = msg[0];
	b = msg[1];
	c = msg[2];
	d = msg[3];

	for (i = 0; i < 50; ++i) {
		uint aa, bb, cc, dd;

		dd = d;
		cc = c;
		bb = b;
		aa = a;

		/** round 1 */
#if 0
		a = INIT_A;
		b = INIT_B;
		c = INIT_C;
		d = INIT_D;
		MD5_STEP(MD5_F, a, b, c, d, aa, 0xd76aa478,  7);
		MD5_STEP(MD5_F, d, a, b, c, bb, 0xe8c7b756, 12);
		MD5_STEP(MD5_F, c, d, a, b, cc, 0x242070db, 17);
		MD5_STEP(MD5_F, b, c, d, a, dd, 0xc1bdceee, 22);
#else
		a += 0xd76aa477;
		RnA(a, INIT_B, 7);
		d = 0xf8fa0bcc + b + (INIT_C ^ (a & 0x77777777));
		RnA(d, a, 12);
		c += 0xbcdb4dd9 + (INIT_B ^ (d & (a ^ INIT_B)));
		RnA(c, d, 17);
		b = 0xb18b7a77 + dd + (a ^ (c & (d ^ a)));
		RnA(b, c, 22);
#endif
		MD5_STEP(MD5_F, a, b, c, d, 0x80, 0xf57c0faf,  7);
		MD5_STEP(MD5_F, d, a, b, c,    0, 0x4787c62a, 12);
		MD5_STEP(MD5_F, c, d, a, b,    0, 0xa8304613, 17);
		MD5_STEP(MD5_F, b, c, d, a,    0, 0xfd469501, 22);
		MD5_STEP(MD5_F, a, b, c, d,    0, 0x698098d8,  7);
		MD5_STEP(MD5_F, d, a, b, c,    0, 0x8b44f7af, 12);
		MD5_STEP(MD5_F, c, d, a, b,    0, 0xffff5bb1, 17);
		MD5_STEP(MD5_F, b, c, d, a,    0, 0x895cd7be, 22);
		MD5_STEP(MD5_F, a, b, c, d,    0, 0x6b901122,  7);
		MD5_STEP(MD5_F, d, a, b, c,    0, 0xfd987193, 12);
		MD5_STEP(MD5_F, c, d, a, b,  128, 0xa679438e, 17);
		MD5_STEP(MD5_F, b, c, d, a,    0, 0x49b40821, 22);

		/** round 2 */
		MD5_STEP(MD5_G, a, b, c, d,   bb, 0xf61e2562,  5);
		MD5_STEP(MD5_G, d, a, b, c,    0, 0xc040b340,  9);
		MD5_STEP(MD5_G, c, d, a, b,    0, 0x265e5a51, 14);
		MD5_STEP(MD5_G, b, c, d, a,   aa, 0xe9b6c7aa, 20);
		MD5_STEP(MD5_G, a, b, c, d,    0, 0xd62f105d,  5);
		MD5_STEP(MD5_G, d, a, b, c,    0, 0x02441453,  9);
		MD5_STEP(MD5_G, c, d, a, b,    0, 0xd8a1e681, 14);
		MD5_STEP(MD5_G, b, c, d, a, 0x80, 0xe7d3fbc8, 20);
		MD5_STEP(MD5_G, a, b, c, d,    0, 0x21e1cde6,  5);
		MD5_STEP(MD5_G, d, a, b, c,  128, 0xc33707d6,  9);
		MD5_STEP(MD5_G, c, d, a, b,   dd, 0xf4d50d87, 14);
		MD5_STEP(MD5_G, b, c, d, a,    0, 0x455a14ed, 20);
		MD5_STEP(MD5_G, a, b, c, d,    0, 0xa9e3e905,  5);
		MD5_STEP(MD5_G, d, a, b, c,   cc, 0xfcefa3f8,  9);
		MD5_STEP(MD5_G, c, d, a, b,    0, 0x676f02d9, 14);
		MD5_STEP(MD5_G, b, c, d, a,    0, 0x8d2a4c8a, 20);

		/** round 3 */
		MD5_STEP(MD5_H,  a, b, c, d,    0, 0xfffa3942,  4);
		MD5_STEP(MD5_H2, d, a, b, c,    0, 0x8771f681, 11);
		MD5_STEP(MD5_H,  c, d, a, b,    0, 0x6d9d6122, 16);
		MD5_STEP(MD5_H2, b, c, d, a,  128, 0xfde5380c, 23);
		MD5_STEP(MD5_H,  a, b, c, d,   bb, 0xa4beea44,  4);
		MD5_STEP(MD5_H2, d, a, b, c, 0x80, 0x4bdecfa9, 11);
		MD5_STEP(MD5_H,  c, d, a, b,    0, 0xf6bb4b60, 16);
		MD5_STEP(MD5_H2, b, c, d, a,    0, 0xbebfbc70, 23);
		MD5_STEP(MD5_H,  a, b, c, d,    0, 0x289b7ec6,  4);
		MD5_STEP(MD5_H2, d, a, b, c,   aa, 0xeaa127fa, 11);
		MD5_STEP(MD5_H,  c, d, a, b,   dd, 0xd4ef3085, 16);
		MD5_STEP(MD5_H2, b, c, d, a,    0, 0x04881d05, 23);
		MD5_STEP(MD5_H,  a, b, c, d,    0, 0xd9d4d039,  4);
		MD5_STEP(MD5_H2, d, a, b, c,    0, 0xe6db99e5, 11);
		MD5_STEP(MD5_H,  c, d, a, b,    0, 0x1fa27cf8, 16);
		MD5_STEP(MD5_H2, b, c, d, a,   cc, 0xc4ac5665, 23);

		/** round 4 */
		MD5_STEP(MD5_I, a, b, c, d,   aa, 0xf4292244,  6);
		MD5_STEP(MD5_I, d, a, b, c,    0, 0x432aff97, 10);
		MD5_STEP(MD5_I, c, d, a, b,  128, 0xab9423a7, 15);
		MD5_STEP(MD5_I, b, c, d, a,    0, 0xfc93a039, 21);
		MD5_STEP(MD5_I, a, b, c, d,    0, 0x655b59c3,  6);
		MD5_STEP(MD5_I, d, a, b, c,   dd, 0x8f0ccc92, 10);
		MD5_STEP(MD5_I, c, d, a, b,    0, 0xffeff47d, 15);
		MD5_STEP(MD5_I, b, c, d, a,   bb, 0x85845dd1, 21);
		MD5_STEP(MD5_I, a, b, c, d,    0, 0x6fa87e4f,  6);
		MD5_STEP(MD5_I, d, a, b, c,    0, 0xfe2ce6e0, 10);
		MD5_STEP(MD5_I, c, d, a, b,    0, 0xa3014314, 15);
		MD5_STEP(MD5_I, b, c, d, a,    0, 0x4e0811a1, 21);
		MD5_STEP(MD5_I, a, b, c, d, 0x80, 0xf7537e82,  6);
		MD5_STEP(MD5_I, d, a, b, c,    0, 0xbd3af235, 10);
		MD5_STEP(MD5_I, c, d, a, b,   cc, 0x2ad7d2bb, 15);
		MD5_STEP(MD5_I, b, c, d, a,    0, 0xeb86d391, 21);

		a += INIT_A;
		b += INIT_B;
		c += INIT_C;
		d += INIT_D;
	}

	msg[0] = a;
	msg[1] = b;
	msg[2] = c;
	msg[3] = d;
}
