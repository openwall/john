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
#include "opencl_bf_WGS.h"

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

/*
 * Parameters NUM_CHANNELS and WAVEFRONT_SIZE are kept to supprt legacy codes. Please don't change the parameters.
 */
#define NUM_CHANNELS                    1
#define WAVEFRONT_SIZE                  1
#define CHANNEL_INTERLEAVE              (WAVEFRONT_SIZE*NUM_CHANNELS)
#define MULTIPLIER                      1024
#define BF_N				(CHANNEL_INTERLEAVE*MULTIPLIER)
#define MAX_DEVICES_PER_PLATFORM        8
#define GWS_CONFIG		        "bf_GWS"

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

extern void BF_select_device(int,int,struct fmt_main*);

/*
 * Clear all GPU Buffers
 */
extern void BF_clear_buffer(void);

#endif
