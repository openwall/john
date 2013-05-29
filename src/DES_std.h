/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2000,2012 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * "Standard" (non-bitslice) DES implementation.
 */

#ifndef _JOHN_DES_STD_H
#define _JOHN_DES_STD_H

#include "arch.h"

#if ARCH_BITS >= 64
#define DES_SIZE			8
#else
#define DES_SIZE			4
#endif

/*
 * Various DES tables exported for use by other implementations.
 */
extern unsigned char DES_E[48];
extern unsigned char DES_PC1[56];
extern unsigned char DES_ROT[16];
extern unsigned char DES_PC2[48];

/*
 * Current key schedule.
 */
typedef ARCH_WORD DES_KS[128 / DES_SIZE];
extern DES_KS DES_KS_current;

/*
 * Binary ciphertext type.
 */
typedef unsigned ARCH_WORD DES_binary[16 / DES_SIZE];

/*
 * Initial value for DES_std_crypt().
 */
extern DES_binary DES_IV;

/*
 * Number of iterations for DES_std_crypt().
 */
extern ARCH_WORD DES_count;

/*
 * Some extra stuff has to be defined here to calculate DES_BINARY_MASK and
 * define the hash functions.
 */
#if DES_128K
#define DES_SIZE_FIX			3
#else
#if ARCH_BITS >= 64
/*
 * It is not possible to shift by 3 (no free bits), so we have to choose
 * between 0 and 2.
 */
#if DES_SCALE
#define DES_SIZE_FIX			0
#else
#define DES_SIZE_FIX			2
#endif
#else
#define DES_SIZE_FIX			2
#endif
#endif

#if DES_128K
#define DES_DO_SIZE_FIX(x) \
	(((((x) << 2) & 0x00FF00FF) | ((x) & 0xFF00FF00)) << 1)
#else
#define DES_DO_SIZE_FIX(x) \
	((x) << DES_SIZE_FIX)
#endif

/*
 * Masks used to extract data bits out of binary ciphertexts.
 */
#define DES_MASK_16			DES_DO_SIZE_FIX(0x1E1E1E1E)
#if ARCH_BITS >= 64
#define DES_BINARY_MASK \
	(DES_MASK_16 | ((ARCH_WORD)DES_MASK_16 << 32))
#else
#define DES_BINARY_MASK			DES_MASK_16
#endif

/*
 * Binary ciphertext hash functions.
 */
#define DES_STD_HASH_0(x) \
	(((x) >> (DES_SIZE_FIX + 1)) & 0xF)
#if DES_128K
#define DES_STD_HASH_1(x) \
	(DES_STD_HASH_0(x) | \
	(((x) >> (DES_SIZE_FIX + 3)) & 0xF0))
#else
#define DES_STD_HASH_1(x) \
	(DES_STD_HASH_0(x) | \
	(((x) >> (DES_SIZE_FIX + 5)) & 0xF0))
#endif
#define DES_STD_HASH_2(x) \
	(DES_STD_HASH_1(x) | \
	(((x) >> (DES_SIZE_FIX + 9)) & 0xF00))

#ifndef DES_STD_ALGORITHM_NAME
#if ARCH_BITS >= 64
#define DES_STD_ALGORITHM_BITS		"48/" ARCH_BITS_STR
#else
#define DES_STD_ALGORITHM_BITS		"24/32"
#endif
#if DES_128K
#define DES_STD_ALGORITHM_SIZE		"128K"
#else
#define DES_STD_ALGORITHM_SIZE		"4K"
#endif
#define DES_STD_ALGORITHM_NAME \
	"DES " DES_STD_ALGORITHM_BITS " " DES_STD_ALGORITHM_SIZE
#endif

/*
 * Initializes the internal structures.
 */
extern void DES_std_init(void);

/*
 * Sets a salt for DES_std_crypt().
 */
extern void DES_std_set_salt(ARCH_WORD salt);

/*
 * Sets a raw 8 character long key for DES_std_crypt(), in DES_KS_current.
 */
extern void DES_raw_set_key(char *key);

/*
 * Sets an ASCIIZ key for DES_std_crypt(), in DES_KS_current.
 */
extern void DES_std_set_key(char *key);

/*
 * Sets an initial value for DES_std_crypt().
 */
extern void DES_std_set_block(ARCH_WORD R, ARCH_WORD L);

/*
 * Returns the encryption result.
 */
extern void DES_std_get_block(DES_binary binary, unsigned ARCH_WORD out[2]);

/*
 * Main encryption routine.
 */
#if CPU_DETECT && !CPU_REQ
extern void (*DES_std_crypt)(DES_KS KS, DES_binary out);
#else
extern void DES_std_crypt(DES_KS KS, DES_binary out);
#endif

/*
 * Returns the salt.
 */
extern ARCH_WORD DES_raw_get_salt(char *ciphertext);

/*
 * Returns the salt for DES_std_set_salt().
 */
extern ARCH_WORD DES_std_get_salt(char *ciphertext);

/*
 * Returns the iteration count for DES_std_crypt().
 */
extern ARCH_WORD DES_raw_get_count(char *ciphertext);

/*
 * Does the Initial Permutation; to be used at startup only (doesn't require
 * that DES_std_init() has been called, is by far not as fast as it could be).
 */
extern ARCH_WORD *DES_do_IP(ARCH_WORD in[2]);

/*
 * Ditto for Final Permutation; to be used for reconstruction of source from
 * binary ciphertext at startup and when a password is successfully cracked.
 */
extern ARCH_WORD *DES_do_FP(ARCH_WORD in[2]);

/*
 * Converts an ASCII ciphertext to binary.
 */
extern ARCH_WORD *DES_raw_get_binary(char *ciphertext);

/*
 * Converts an ASCII ciphertext to binary to be compared against
 * DES_std_crypt() result.
 */
extern ARCH_WORD *DES_std_get_binary(char *ciphertext);

#endif
