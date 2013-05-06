/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2005,2010-2012 by Solar Designer
 */

/*
 * Bitslice DES implementation.
 */

#ifndef _JOHN_DES_BS_H
#define _JOHN_DES_BS_H

#include "arch.h"
#include "common.h"

/* For struct db_salt */
#include "loader.h"

#ifndef DES_BS_ALGORITHM_NAME
#define DES_BS_ALGORITHM_NAME		"DES " ARCH_BITS_STR "/" ARCH_BITS_STR
#endif

#if DES_BS_VECTOR
#define DES_BS_DEPTH			(ARCH_BITS * DES_BS_VECTOR)
#else
#define DES_BS_DEPTH			ARCH_BITS
#endif

#if DES_BS_VECTOR
#ifndef DES_BS_VECTOR_SIZE
#define DES_BS_VECTOR_SIZE		DES_BS_VECTOR
#endif
typedef ARCH_WORD DES_bs_vector[DES_BS_VECTOR_SIZE];
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
		unsigned char u[0x100];	/* Uppercase (for LM) */
	} E;
	DES_bs_vector K[56];	/* Keys */
	DES_bs_vector B[64];	/* Data blocks */
#if DES_BS_ASM
	DES_bs_vector tmp[16];	/* Miscellaneous temporary storage */
#else
	DES_bs_vector zero;	/* All 0 bits */
	DES_bs_vector ones;	/* All 1 bits */
	DES_bs_vector masks[8];	/* Each byte set to 0x01 ... 0x80 */
#endif
	union {
		unsigned char c[8][8][sizeof(DES_bs_vector)];
		DES_bs_vector v[8][8];
	} xkeys;		/* Partially transposed key bits matrix */
	unsigned char *pxkeys[DES_BS_DEPTH]; /* Pointers into xkeys.c */
	int keys_changed;	/* If keys have changed */
	unsigned int salt;	/* Salt value corresponding to E[] contents */
	DES_bs_vector *Ens[48];	/* Pointers into B[] for non-salted E */
} DES_bs_combined;

#if defined(_OPENMP) && !DES_BS_ASM
#define DES_bs_mt			1
#define DES_bs_cpt			32
#define DES_bs_mt_max			(DES_bs_cpt * 576)
extern int DES_bs_min_kpc, DES_bs_max_kpc;
extern int DES_bs_nt;
extern DES_bs_combined *DES_bs_all_p;
#define DES_bs_all_align		64
#define DES_bs_all_size \
	((sizeof(DES_bs_combined) + (DES_bs_all_align - 1)) & \
	    ~(DES_bs_all_align - 1))
#define DES_bs_all_by_tnum(tnum) \
	(*(DES_bs_combined *)((char *)DES_bs_all_p + (tnum) * DES_bs_all_size))
#ifdef __GNUC__
#define DES_bs_all \
	(*(DES_bs_combined *)((char *)DES_bs_all_p + t))
#define for_each_t(n) \
	for (t = 0; t < (n) * DES_bs_all_size; t += DES_bs_all_size)
#define init_t() \
	int t = (unsigned int)index / DES_BS_DEPTH * DES_bs_all_size; \
	index = (unsigned int)index % DES_BS_DEPTH;
#else
/*
 * For compilers that complain about the above e.g. with "iteration expression
 * of omp for loop does not have a canonical shape".
 */
#define DES_bs_all \
	DES_bs_all_by_tnum(t)
#define for_each_t(n) \
	for (t = 0; t < (n); t++)
#define init_t() \
	int t = (unsigned int)index / DES_BS_DEPTH; \
	index = (unsigned int)index % DES_BS_DEPTH;
#endif
#else
#define DES_bs_mt			0
#define DES_bs_cpt			1
extern DES_bs_combined DES_bs_all;
#define for_each_t(n)
#define init_t()
#endif

/*
 * Initializes the internal structures.
 */
extern void DES_bs_init(int LM, int cpt);

/*
 * Sets a salt for DES_bs_crypt().
 */
extern void DES_bs_set_salt(ARCH_WORD salt);
#if DES_bs_mt
extern void DES_bs_set_salt_for_thread(int t, unsigned int salt);
#endif

/*
 * Set a key for DES_bs_crypt() or DES_bs_crypt_LM(), respectively.
 */
extern void DES_bs_set_key(char *key, int index);
extern void DES_bs_set_key_LM(char *key, int index);

/*
 * Almost generic implementation: 24-bit salts, variable iteration count.
 */
extern void DES_bs_crypt(int count, int keys_count);

/*
 * A simplified special-case implementation: 12-bit salts, 25 iterations.
 */
extern void DES_bs_crypt_25(int keys_count);

/*
 * Another special-case version: a non-zero IV, no salts, no iterations.
 */
extern int DES_bs_crypt_LM(int *keys_count, struct db_salt *salt);

/*
 * Converts an ASCII ciphertext to binary to be used with one of the
 * comparison functions.
 */
extern ARCH_WORD_32 *DES_bs_get_binary(char *ciphertext);

/*
 * Similarly, for LM hashes.
 */
extern ARCH_WORD_32 *DES_bs_get_binary_LM(char *ciphertext);

/*
 * The reverse of DES_bs_get_binary_LM().
 */
extern char *DES_bs_get_source_LM(ARCH_WORD_32 *raw);

/*
 * Calculate a hash for a DES_bs_crypt*() output.
 *
 * "t"-suffixed versions of these functions are for tripcodes (they skip
 * bits that are part of the base-64 character not included in tripcodes).
 * There's no DES_bs_get_hash_0t() because it would be exactly the same as
 * DES_bs_get_hash_0() (all four initial bits are included in tripcodes).
 */
extern int DES_bs_get_hash_0(int index);
extern int DES_bs_get_hash_1(int index);
extern int DES_bs_get_hash_2(int index);
extern int DES_bs_get_hash_3(int index);
extern int DES_bs_get_hash_4(int index);
extern int DES_bs_get_hash_5(int index);
extern int DES_bs_get_hash_6(int index);
extern int DES_bs_get_hash_1t(int index);
extern int DES_bs_get_hash_2t(int index);
extern int DES_bs_get_hash_3t(int index);
extern int DES_bs_get_hash_4t(int index);
extern int DES_bs_get_hash_5t(int index);
extern int DES_bs_get_hash_6t(int index);

/*
 * Compares 32 bits of a given ciphertext against at least the first count of
 * the DES_bs_crypt*() outputs and returns zero if no matches detected.
 */
extern int DES_bs_cmp_all(ARCH_WORD_32 *binary, int count);

/*
 * Compares count bits of a given ciphertext against one of the outputs.
 */
extern int DES_bs_cmp_one(ARCH_WORD_32 *binary, int count, int index);

#endif
