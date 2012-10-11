/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9 
 */


#ifndef _JOHN_DES_BS_H
#define _JOHN_DES_BS_H

#include "arch.h"
#include "common-opencl.h"
#include "opencl_DES_WGS.h"

#define DES_BS_OPENCL_ALGORITHM_NAME		"OpenCL"


#define DES_BS_DEPTH			32
#define DES_BS_LOG2			5

#define WORD                      	int

#define DES_bs_vector			WORD

#define MULTIPLIER                      (WORK_GROUP_SIZE*256)


#define MIN_KEYS_PER_CRYPT		(DES_BS_DEPTH*MULTIPLIER)
#define MAX_KEYS_PER_CRYPT		(DES_BS_DEPTH*MULTIPLIER)

unsigned int CC_CACHE_ALIGN index768[0x300];
unsigned int CC_CACHE_ALIGN index96[96];


#define	MAX_DEVICES_PER_PLATFORM	10
#define DES_BS_EXPAND                   1 
/*
 * All bitslice DES parameters combined into one struct for more efficient
 * cache usage. Don't re-order unless you know what you're doing, as there
 * is an optimization that would produce undefined results if you did.
 *
 * This must match the definition in x86-mmx.S.
 */
typedef struct {

	unsigned char *pxkeys[DES_BS_DEPTH]; /* Pointers into xkeys.c */
	unsigned int salt;	/* Salt value corresponding to E[] contents */
	DES_bs_vector *Ens[48];	/* Pointers into B[] for non-salted E */

  
} opencl_DES_bs_combined;

typedef struct{
	
	
	union {
		unsigned char c[8][8][sizeof(DES_bs_vector)];
		DES_bs_vector v[8][8];
	} xkeys;
		
	int keys_changed;
	
} opencl_DES_bs_transfer ;

/*
 * Various DES tables exported for use by other implementations.
 */

struct fmt_main;

#define DES_bs_cpt			1
extern opencl_DES_bs_combined opencl_DES_bs_all[MULTIPLIER];
extern opencl_DES_bs_transfer opencl_DES_bs_data[MULTIPLIER];
extern DES_bs_vector B[64*MULTIPLIER];
#define for_each_t(n)
#define init_t()

/*
 * Initializes the internal structures.
 */
extern void opencl_DES_bs_init(int LM, int cpt,int block);

/*
 * Sets a salt for DES_bs_crypt().
 */
extern void opencl_DES_bs_set_salt(WORD salt);


/*
 * Set a key for DES_bs_crypt() or DES_bs_crypt_LM(), respectively.
 */
extern void opencl_DES_bs_set_key(char *key, int index);
extern void opencl_DES_bs_set_key_LM(char *key, int index);

/*
 * Almost generic implementation: 24-bit salts, variable iteration count.
 */
/*
extern void opencl_DES_bs_crypt(int count, int keys_count);
*/
/*
 * A simplified special-case implementation: 12-bit salts, 25 iterations.
 */
extern void opencl_DES_bs_crypt_25(int keys_count);

/*
 * Another special-case version: a non-zero IV, no salts, no iterations.
 */
/*
extern void opencl_DES_bs_crypt_LM(int keys_count);
*/
/*
 * Converts an ASCII ciphertext to binary to be used with one of the
 * comparison functions.
 */
extern WORD *opencl_DES_bs_get_binary(char *ciphertext);

/*
 * Similarly, for LM hashes.
 */
extern WORD *opencl_DES_bs_get_binary_LM(char *ciphertext);

/*
 * Calculate a hash for a DES_bs_crypt() output.
 */
extern int opencl_DES_bs_get_hash_0(int index);
extern int opencl_DES_bs_get_hash_1(int index);
extern int opencl_DES_bs_get_hash_2(int index);
extern int opencl_DES_bs_get_hash_3(int index);
extern int opencl_DES_bs_get_hash_4(int index);
extern int opencl_DES_bs_get_hash_5(int index);
extern int opencl_DES_bs_get_hash_6(int index);

/*
 * Compares 32 bits of a given ciphertext against at least the first count of
 * the DES_bs_crypt*() outputs and returns zero if no matches detected.
 */
extern int opencl_DES_bs_cmp_all(WORD *binary, int count);

/*
 * Compares count bits of a given ciphertext against one of the outputs.
 */
extern int opencl_DES_bs_cmp_one(WORD *binary, int count, int index);

/*
 * Returns the salt.
 */
extern WORD opencl_DES_raw_get_salt(char *ciphertext);  

/*
 * Returns the iteration count for DES_std_crypt().
 */
extern WORD opencl_DES_raw_get_count(char *ciphertext);   

/*
 * Does the Initial Permutation; to be used at startup only (doesn't
 * require that DES_std_init() has been called, is not as fast as it
 * could be).
 */
extern WORD *opencl_DES_do_IP(WORD in[2]);       

/*
 * Converts an ASCII ciphertext to binary.
 */
extern WORD *opencl_DES_raw_get_binary(char *ciphertext);   

extern void DES_bs_select_device(int platform_no,int dev_no);


#endif
