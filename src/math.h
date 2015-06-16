/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * 64-bit integer math functions.
 */

#ifndef _JOHN_MATH_H
#define _JOHN_MATH_H

#undef int64
#define int64 _john_int64_t

typedef struct {
	unsigned int lo, hi;
} int64;

extern void add32to64(int64 *dst, unsigned int src);
extern void add64to64(int64 *dst, int64 *src);
extern void neg64(int64 *dst);
extern void mul32by32(int64 *dst, unsigned int m1, unsigned int m2);
extern void mul64by32(int64 *dst, unsigned int m);
extern unsigned int div64by32lo(int64 *src, unsigned int d);
extern void div64by32(int64 *dst, unsigned int d);

#endif
