/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2003,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * FreeBSD-style MD5-based password hash implementation.
 */

#ifndef _JOHN_MD5_STD_H
#define _JOHN_MD5_STD_H

#include "arch.h"
#include "common.h"

typedef ARCH_WORD_32 MD5_word;

/*
 * Binary ciphertext type.
 */
typedef MD5_word MD5_binary[4];

/*
 * Various structures for internal use.
 */

typedef union {
	double dummy;
	MD5_word w[15];
	char b[60];
} MD5_block;

typedef struct {
	int length;
	MD5_block *even, *odd;
} MD5_pattern;

typedef struct {
	char s[8];
	struct {
		int p, s, ps, pp, psp;
	} l;
	struct {
		MD5_block p, sp, pp, spp;
	} e;
	struct {
		MD5_block p, ps, pp, psp;
	} o;
} MD5_pool;

#if !MD5_IMM
typedef struct {
	MD5_word AC[64];
	MD5_word IV[4];
	MD5_word masks[2];
} MD5_data;
#endif

#if MD5_X2
#define MD5_N				2
#else
#define MD5_N				1
#endif

typedef struct {
#if !MD5_IMM
	MD5_data data;
#endif

	MD5_binary out[MD5_N];

	MD5_block _block[MD5_N];
	MD5_pattern _order[21][MD5_N];
	MD5_pool _pool[MD5_N];
	char *prefix;
	int prelen;
} MD5_std_combined;

#if defined(_OPENMP) && !MD5_ASM
#define MD5_std_mt			1
#define MD5_std_cpt			128
#define MD5_std_mt_max			(MD5_std_cpt * 576)
extern MD5_std_combined *MD5_std_all_p;
extern int MD5_std_min_kpc, MD5_std_max_kpc;
extern int MD5_std_nt;
#define MD5_std_all_align		64
#define MD5_std_all_size \
	((sizeof(MD5_std_combined) + (MD5_std_all_align - 1)) & \
	    ~(MD5_std_all_align - 1))
#ifdef __GNUC__
#define MD5_std_all \
	(*(MD5_std_combined *)((char *)MD5_std_all_p + t))
#define for_each_t(n) \
	for (t = 0; t < (n) * MD5_std_all_size; t += MD5_std_all_size)
#define init_t() \
	int t = (unsigned int)index / MD5_N * MD5_std_all_size; \
	index = (unsigned int)index % MD5_N;
#else
/*
 * For compilers that complain about the above e.g. with "iteration expression
 * of omp for loop does not have a canonical shape".
 */
#define MD5_std_all \
	(*(MD5_std_combined *)((char *)MD5_std_all_p + t * MD5_std_all_size))
#define for_each_t(n) \
	for (t = 0; t < (n); t++)
#define init_t() \
	int t = (unsigned int)index / MD5_N; \
	index = (unsigned int)index % MD5_N;
#endif
#else
#define MD5_std_mt			0
extern MD5_std_combined MD5_std_all;
#define for_each_t(n)
#define init_t()
#endif

/*
 * MD5_std_crypt() output buffer.
 */
#define MD5_out				MD5_std_all.out

#if MD5_X2
#define MD5_ALGORITHM_NAME		"MD5 32/" ARCH_BITS_STR " X2"
#else
#define MD5_ALGORITHM_NAME		"MD5 32/" ARCH_BITS_STR
#endif

/*
 * Initializes the internal structures.
 */
extern void MD5_std_init(void);

/*
 * Sets a salt for MD5_std_crypt().
 */
extern void MD5_std_set_salt(char *salt);

/*
 * Sets a key for MD5_std_crypt().
 * Currently only supports keys up to 15 characters long.
 */
extern void MD5_std_set_key(char *key, int index);

/*
 * Main hashing routine, sets MD5_out.
 */
extern void MD5_std_crypt(int count);

/*
 * Returns the salt for MD5_std_set_salt().
 */
extern char *MD5_std_get_salt(char *ciphertext);

/*
 * Converts an ASCII ciphertext to binary.
 */
extern MD5_word *MD5_std_get_binary(char *ciphertext);

#endif
