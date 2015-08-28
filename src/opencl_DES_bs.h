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
#include "opencl_DES_hst_dev_shared.h"
#include "loader.h"

#define DES_BS_OPENCL_ALGORITHM_NAME		"DES OpenCL"

#define DES_BS_DEPTH			32
#define DES_BS_LOG2			5

#define WORD                      	int

#define DES_bs_vector			WORD

#define MULTIPLIER                      (WORK_GROUP_SIZE*256*16)
#define PLAINTEXT_LENGTH		8

#define MIN_KEYS_PER_CRYPT		(DES_BS_DEPTH*MULTIPLIER)
#define MAX_KEYS_PER_CRYPT		(DES_BS_DEPTH*MULTIPLIER)

#define GWS_CONFIG		        "des_GWS"

typedef unsigned WORD vtype;

unsigned int CC_CACHE_ALIGN opencl_DES_bs_index768[0x300];

typedef struct {
	unsigned char *pxkeys[DES_BS_DEPTH]; /* Pointers into xkeys.c */
} opencl_DES_bs_combined;

struct fmt_main;

struct fmt_main fmt_opencl_DES;
extern unsigned char opencl_DES_E[48];

extern opencl_DES_bs_combined *opencl_DES_bs_all;
extern opencl_DES_bs_transfer *opencl_DES_bs_keys;
extern int opencl_DES_bs_keys_changed;
extern DES_bs_vector *opencl_DES_bs_cracked_hashes;

extern void opencl_DES_bs_b_register_functions(struct fmt_main *);
extern void opencl_DES_bs_h_register_functions(struct fmt_main *);
extern void opencl_DES_bs_f_register_functions(struct fmt_main *);

extern void (*opencl_DES_bs_init_global_variables)(void);
extern void (*opencl_DES_bs_select_device)(struct fmt_main *);

extern int opencl_DES_bs_get_hash_0(int index);
extern int opencl_DES_bs_get_hash_1(int index);
extern int opencl_DES_bs_get_hash_2(int index);
extern int opencl_DES_bs_get_hash_3(int index);
extern int opencl_DES_bs_get_hash_4(int index);
extern int opencl_DES_bs_get_hash_5(int index);
extern int opencl_DES_bs_get_hash_6(int index);
extern void opencl_DES_bs_init(int block);
extern int opencl_DES_bs_cmp_one_b(WORD *binary, int count, int index);
extern WORD opencl_DES_raw_get_salt(char *ciphertext);
extern WORD *opencl_DES_bs_get_binary(char *ciphertext);
extern void opencl_DES_bs_set_key(char *key, int index);
extern void opencl_DES_bs_init_index();

#endif
