/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005 by Solar Designer
 */

/*
 * Bitslice DES implementation.
 */

#ifndef _JOHN_DES_BS_H
#define _JOHN_DES_BS_H

#include "arch.h"

#ifndef DES_BS_ALGORITHM_NAME
#define DES_BS_ALGORITHM_NAME		ARCH_BITS_STR "/" ARCH_BITS_STR " BS"
#endif

#if DES_BS_VECTOR
#define DES_BS_DEPTH			(ARCH_BITS * DES_BS_VECTOR)
#else
#define DES_BS_DEPTH			ARCH_BITS
#endif

#if DES_BS_VECTOR
typedef ARCH_WORD DES_bs_vector[DES_BS_VECTOR];
#else
#define DES_bs_vector			ARCH_WORD
#endif

/*
 * All bitslice DES parameters combined into one struct for more efficient
 * cache usage. Don't re-order unless you know what you're doing, as there
 * is an optimization that would produce undefined results if you did.
 *
 * This must match the definition in x86-mmx.S.
 */
typedef struct {
#if DES_BS_EXPAND
	ARCH_WORD *KSp[0x300];	/* Initial key schedule (key bit pointers) */
#endif
	union {
		ARCH_WORD *p[0x300];	/* Key bit pointers */
#if DES_BS_EXPAND
		DES_bs_vector v[0x300];	/* Key bit values */
#endif
	} KS;			/* Current key schedule */
	union {
		ARCH_WORD *E[96];	/* Expansion function (data bit ptrs) */
		struct {
#if !DES_BS_VECTOR && ARCH_BITS >= 64
			unsigned char keys[DES_BS_DEPTH][8]; /* Current keys */
#endif
			unsigned char u[0x100];	/* Uppercase */
		} extras;		/* Re-use the cache space for LM */
	} E;
	DES_bs_vector K[56];	/* Keys */
	DES_bs_vector B[64];	/* Data blocks */
#if DES_BS_ASM
	DES_bs_vector tmp[16];	/* Miscellaneous temporary storage */
#endif
	unsigned char s1[0x100], s2[0x100];	/* Shift counts */
	int KS_updates;		/* Key schedule updates counter */
	int keys_changed;	/* If keys have changed since last expand */
	unsigned char keys[DES_BS_DEPTH][8];	/* Current keys */
} DES_bs_combined;

extern DES_bs_combined DES_bs_all;

/*
 * Initializes the internal structures.
 */
extern void DES_bs_init(int LM);

/*
 * Sets a salt for DES_bs_crypt().
 */
extern void DES_bs_set_salt(ARCH_WORD salt);

/*
 * Clears the bitslice keys if the key schedule has been updated too
 * many times without being fully regenerated. This should be called
 * whenever possible to reduce the impact of hardware faults.
 */
extern void DES_bs_clear_keys(void);
extern void DES_bs_clear_keys_LM(void);

/*
 * Sets a key for DES_bs_crypt().
 */
extern void DES_bs_set_key(char *key, int index);

/*
 * Initializes the key schedule with actual key bits. Not for LM.
 */
#if DES_BS_EXPAND
extern void DES_bs_expand_keys(void);
#else
#define DES_bs_expand_keys()
#endif

/*
 * Sets a key for DES_bs_crypt_LM().
 */
extern void DES_bs_set_key_LM(char *key, int index);

/*
 * Generic bitslice routine: 24 bit salts, variable iteration count.
 */
extern void DES_bs_crypt(int count);

/*
 * A simplified special-case version: 12 bit salts, 25 iterations.
 */
extern void DES_bs_crypt_25(void);

/*
 * Another special-case version: a non-zero IV, no salts, no iterations.
 */
extern void DES_bs_crypt_LM(void);

/*
 * Converts an ASCII ciphertext to binary to be used with one of the
 * comparison functions.
 */
extern ARCH_WORD *DES_bs_get_binary(char *ciphertext);

/*
 * Similarly, for LM hashes.
 */
extern ARCH_WORD *DES_bs_get_binary_LM(char *ciphertext);

/*
 * Calculates a hash for a DES_bs_crypt() output.
 */
extern int DES_bs_get_hash(int index, int count);

/*
 * Compares 32 bits of a given ciphertext against all the DES_bs_crypt()
 * outputs and returns zero if no matches detected.
 */
extern int DES_bs_cmp_all(ARCH_WORD *binary);

/*
 * Compares count bits of a given ciphertext against one of the outputs.
 */
extern int DES_bs_cmp_one(ARCH_WORD *binary, int count, int index);

#endif
