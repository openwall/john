/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "arch.h"
#include "math.h"

void add32to64(int64 *dst, unsigned int src)
{
	unsigned int saved;

	saved = dst->lo;
	dst->lo += src;

#if ARCH_INT_GT_32
	dst->lo &= 0xFFFFFFFF;
#endif

	if (dst->lo < saved) dst->hi++;
}

void add64to64(int64 *dst, int64 *src)
{
	add32to64(dst, src->lo);
	dst->hi += src->hi;
}

void neg64(int64 *dst)
{
	dst->lo = ~dst->lo; dst->hi = ~dst->hi;
	add32to64(dst, 1);
}

static void add32to64m(int64 *dst, unsigned int a)
{
	unsigned int saved;

	saved = dst->lo;
	dst->lo += a << 16;

#if ARCH_INT_GT_32
	dst->lo &= 0xFFFFFFFF;
#endif

	dst->hi += ((dst->lo < saved) ? 1 : 0) + (a >> 16);
}

void mul32by32(int64 *dst, unsigned int m1, unsigned int m2)
{
	dst->lo = (m1 & 0xFFFF) * (m2 & 0xFFFF);
	dst->hi = 0;

	add32to64m(dst, (m1 >> 16) * (m2 & 0xFFFF));
	add32to64m(dst, (m2 >> 16) * (m1 & 0xFFFF));

	dst->hi += (m1 >> 16) * (m2 >> 16);
}

void mul64by32(int64 *dst, unsigned int m)
{
	int64 tmp;

	mul32by32(&tmp, dst->hi, m);
	dst->hi = tmp.lo;
	mul32by32(&tmp, dst->lo, m);
	dst->lo = tmp.lo;
	dst->hi += tmp.hi;
}

unsigned int div64by32lo(int64 *src, unsigned int d)
{
	unsigned int lo, hi, q, s, mask;

	lo = src->lo; hi = src->hi;

#if ARCH_INT_GT_32
	hi += lo >> 32;
	lo &= 0xFFFFFFFF;
#endif

	if (hi >= d) return 0xFFFFFFFF;

	q = 0; mask = 0x80000000;
	do {
		s = hi;
		hi = (hi << 1) | (lo >> 31);
		lo <<= 1;

#if ARCH_INT_GT_32
		lo &= 0xFFFFFFFF;
#endif

		if ((s & 0x80000000) || hi >= d) {
			hi -= d;
			q |= mask;
		}
	} while (mask >>= 1);

	return q;
}

void div64by32(int64 *dst, unsigned int d)
{
	int64 tmp;

	tmp.lo = dst->lo;
	tmp.hi = dst->hi % d;
	dst->lo = div64by32lo(&tmp, d);
	dst->hi /= d;
}
