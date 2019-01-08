/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99,2005,2009,2011,2013,2015 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Things common to many ciphertext formats.
 */

#ifndef _JOHN_COMMON_H
#define _JOHN_COMMON_H

#if !defined(_OPENCL_COMPILER)
#include <stdint.h>
#include "arch.h"
#include "memory.h"
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef ABS
#define ABS(a) ((a)<0?(0-(a)):(a))
#endif

/* sets v to the next higher even power of 2 */
#define get_power_of_two(v)                     \
{                                               \
    v--;                                        \
    v |= v >> 1;                                \
    v |= v >> 2;                                \
    v |= v >> 4;                                \
    v |= v >> 8;                                \
    v |= v >> 16;                               \
    v |= (v >> 16) >> 16;                       \
    v++;                                        \
}

#if !defined(_OPENCL_COMPILER)

/* ONLY use this to check alignments of even power of 2 (2, 4, 8, 16, etc) byte counts (CNT).
   The cast to void* MUST be done, due to C spec. http://stackoverflow.com/a/1898487 */
#define is_aligned(PTR, CNT) ((((ARCH_WORD)(const void *)(PTR))&(CNT-1))==0)

#ifdef __GNUC__
#if __GNUC__ >= 5
#define MAYBE_INLINE __attribute__((gnu_inline)) __attribute__((always_inline)) inline
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7) || defined(__INTEL_COMPILER) || __NVCC__
#define MAYBE_INLINE __attribute__((always_inline)) inline
#elif __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
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
#define DIGITCHARS   "0123456789"
#define HEXCHARS_lc  DIGITCHARS"abcdef"
#define HEXCHARS_uc  DIGITCHARS"ABCDEF"
#define HEXCHARS_all DIGITCHARS"abcdefABCDEF"
#define BASE64_CRYPT "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

extern const char itoa64[64]; /* crypt(3) base64 - not MIME Base64! */
extern unsigned char atoi64[0x100];
extern const char itoa16[16];
extern unsigned char atoi16[0x100], atoi16l[0x100], atoi16u[0x100];
extern const char itoa16u[16]; // uppercase

/*
 * Initializes the tables.
 */
extern void common_init(void);

/**************************************************************
 * added 'common' helper functions for things used in valid() *
 **************************************************************/

/* is string full valid hex string */
int ishex(const char *q);
/* Same as ishex(), BUT will still return true for an odd length string */
int ishex_oddOK(const char *q);
/* is string full valid hex string (only upper case letters) */
int ishexuc(const char *q);
/* is string full valid hex string (only lower case letters) */
int ishexlc(const char *q);
/* same as ishexuc/lc except odd length is ok */
int ishexuc_oddOK(const char *q);
int ishexlc_oddOK(const char *q);
/* provide a length field, so return true if 'n' bytes of the string are hex */
/* the n is length q, so there is no need for a 'odd' field. If checking for */
/* a 49 byte string, simply specify 49 */
int ishexn(const char *q, int n);
int ishexucn(const char *q, int n);
int ishexlcn(const char *q, int n);
/* length of hex. if extra_chars not null, it will be 1 if there are more
 * non-hex characters after the length of valid hex chars returned.
 * NOTE, the return will always be an even number (rounded down). so if we
 * want the length of "ABCDE", it will be 4 not 5.
 */
size_t hexlen(const char *q, int *extra_chars);
size_t hexlenl(const char *q, int *extra_chars); /* lower cased only */
size_t hexlenu(const char *q, int *extra_chars); /* upper cased only */
/* Is this a valid number <=10digits and in the range [0 .... <= 0x7fffffff]
 * ONLY positive numbers are valid. */
int isdec(const char *q);
/* Is this a valid number <=10digits.
 * Positive [0..<= 0x7fffffff] and negative [ <= 0x80000000] numbers are valid */
int isdec_negok(const char *q);
/* Is this a valid number <=10digits.ONLY positive [0..<=0xffffffff] numbers are valid */
int isdecu(const char *q);

#endif

#endif
