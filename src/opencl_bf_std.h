/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */
#ifndef _OPENCL_BF_STD_H
#define _OPENCL_BF_STD_H

#include "arch.h"
#include "common.h"
#include "common-opencl.h"

typedef unsigned int BF_word;

/*
 * Binary salt type, also keeps the number of rounds and hash sub-type.
 */
typedef struct {
	BF_word salt[4];
	unsigned char rounds;
	char subtype;
} BF_salt;

/*
 * Binary ciphertext type.
 */
typedef BF_word BF_binary[6];

/*NOTE: If you change the WORK_GROUP_SIZE here it must also be changed in bf_kernel.cl*/
/*
 * WORK_GROUP_SIZE: Use trial and error to find best work group size. In any case it should not exceed 16.
 *                  E.g. For 7970 set it 8.
 *                       For 570  set it 4.
 * MULTIPLIER:      Increase keys per crypt using this parameter.
 * 
 */ 

#define WORK_GROUP_SIZE                 8
#define NUM_CHANNELS                    1
#define WAVEFRONT_SIZE                  1 
#define CHANNEL_INTERLEAVE              WAVEFRONT_SIZE*NUM_CHANNELS
#define MULTIPLIER                      1024
#define BF_N				CHANNEL_INTERLEAVE*MULTIPLIER
#define MAX_DEVICES_PER_PLATFORM        8

/*
 * BF_std_crypt() output buffer.
 */
extern BF_binary opencl_BF_out[BF_N];

/*
 * ASCII to binary conversion table, for use in BF_fmt.valid().
 */
extern unsigned char opencl_BF_atoi64[0x80];

/*
 * Sets a key for BF_std_crypt().
 */
extern void opencl_BF_std_set_key(char *key, int index, int sign_extension_bug);

/*
 * Main hashing routine, sets first two words of BF_out
 * (or all words in an OpenMP-enabled build).
 */
extern void opencl_BF_std_crypt(BF_salt *salt, int n);

/*
 * Calculates the rest of BF_out, for exact comparison.
 */
extern void opencl_BF_std_crypt_exact(int index);

/*
 * Returns the salt for BF_std_crypt().
 */
extern void *opencl_BF_std_get_salt(char *ciphertext);

/*
 * Converts an ASCII ciphertext to binary.
 */
extern void *opencl_BF_std_get_binary(char *ciphertext);

/*
 * Select a device: BF_select_device(platform_id,device_id)
 */

extern void BF_select_device(int,int);

/*
 * Clear all GPU Buffers
 */
extern void BF_clear_buffer(void);

#endif
