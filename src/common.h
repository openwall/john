/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2005,2009,2011 by Solar Designer
 */

/*
 * Things common to many ciphertext formats.
 */

#ifndef _JOHN_COMMON_H
#define _JOHN_COMMON_H

#include "arch.h"
#include "memory.h"

#if ARCH_INT_GT_32
typedef unsigned short ARCH_WORD_32;
typedef unsigned int ARCH_WORD_64;
#else
typedef unsigned int ARCH_WORD_32;
typedef unsigned long long ARCH_WORD_64;
#endif

/* ONLY use this to check alignments of even power of 2 (2, 4, 8, 16, etc) byte counts (CNT).
   the cast to void* MUST be done, due to C spec. http://stackoverflow.com/a/1898487 */
#define is_aligned(PTR, CNT) (((ARCH_WORD)(const void *)(PTR))&(CNT-1)==0)

#ifdef __GNUC__
#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define MAYBE_INLINE __attribute__((always_inline))
#else
#define MAYBE_INLINE __inline__
#endif
#elif __STDC_VERSION__ >= 199901L
#define MAYBE_INLINE inline
#else
#define MAYBE_INLINE
#endif

#if ((__GNUC__ == 2) && (__GNUC_MINOR__ >= 7)) || (__GNUC__ > 2)
#define CC_CACHE_ALIGN \
	__attribute__ ((aligned (MEM_ALIGN_CACHE)))
#else
#define CC_CACHE_ALIGN			/* nothing */
#endif

/*
 * This "shift" is the number of bytes that may be inserted between arrays the
 * size of which would be a multiple of cache line size (some power of two) and
 * that might be accessed simultaneously.  The purpose of the shift is to avoid
 * cache bank conflicts with such accesses, actually allowing them to proceed
 * simultaneously.  This number should be a multiple of the machine's word size
 * but smaller than cache line size.
 */
#define CACHE_BANK_SHIFT		ARCH_SIZE

/*
 * ASCII <-> binary conversion tables.
 */
extern char itoa64[64], atoi64[0x100];
extern char itoa16[16], atoi16[0x100];
extern char itoa16u[16]; // uppercase

/*
 * Initializes the tables.
 */
extern void common_init(void);

#endif
