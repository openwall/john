/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

/*NOTE: Changing the following parameters to improve performance for different GPUs. WAVEFRONT_SIZE , NUM_CHANNELS and OFFSET here must be same as that in 'bf_kernel.cl'. 
 *      Threrefore if the above three parameters are changed here,it must be also changed in the kernel file.
 *  
 * WORK_GROUP_SIZE : Increase or decrease in multiples of 64
 * WAVEFRONT_SIZE  : For Nvidia GPUs it may be also called warp size.
 *                   Wavfront size is 64 for AMD GPUs.
 *                   Warp size is 32 for Nvidia GPUs.
 *                   Set it to integral multiple of 32 for Nv GPUs and integral multiple of 64 for AMD GPUs.
 *                   Size of 64 works well for both AMD and Nv GPUs.
 * NUM_CHANNELS    : Number of memory channels available for the device. eg  for GTX570 set it 10 +/- 1
 *                                                                           for HD4890 set it  8 +/- 1
 *									     for hd7970 set it 12 +/- 1										    
 * 	             Increasing or decreasing this parameter by 1 may improve performance.
 * MULTIPLIER      : Use this to increase BF_N		
 * OFFSET          : This is to fine tune performance.Set it between 0 to WAVEFRONT_SIZE inclusive 0.
 * 
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

#define WORK_GROUP_SIZE                  64

#define WAVEFRONT_SIZE                   64

#define NUM_CHANNELS                     13

#define OFFSET                           0

#define MULTIPLIER                       4

#define CHANNEL_INTERLEAVE              WAVEFRONT_SIZE*NUM_CHANNELS

#define BF_N				CHANNEL_INTERLEAVE*MULTIPLIER

#define MAX_DEVICES_PER_PLATFORM         8

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

extern void BF_select_device(int,int);

#endif
