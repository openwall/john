/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000 by Solar Designer
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
	double dummy;
#endif

	MD5_binary out[MD5_N];

	MD5_block block[MD5_N];
	MD5_pattern order[21][MD5_N];
	MD5_pool pool[MD5_N];
} MD5_std_combined;

extern MD5_std_combined MD5_std_all;

/*
 * MD5_std_crypt() output buffer.
 */
#define MD5_out				MD5_std_all.out

#if MD5_X2
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR " X2"
#else
#define MD5_ALGORITHM_NAME		"32/" ARCH_BITS_STR
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
 * Main encryption routine, sets MD5_out.
 */
extern void MD5_std_crypt(void);

/*
 * Returns the salt for MD5_std_set_salt().
 */
extern char *MD5_std_get_salt(char *ciphertext);

/*
 * Converts an ASCII ciphertext to binary.
 */
extern MD5_word *MD5_std_get_binary(char *ciphertext);

#endif
