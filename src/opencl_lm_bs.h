/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar LMigner implementation of LM_bs_b.c in jtr-v1.7.9
 */


#ifndef _JOHN_LM_BS_H
#define _JOHN_LM_BS_H

#include "arch.h"
#include "common-opencl.h"
#include "opencl_lm_hst_dev_shared.h"
#include "loader.h"

#define LM_BS_OPENCL_ALGORITHM_NAME		"LM OpenCL(inefficient)"

#define LM_BS_DEPTH			32
#define LM_BS_LOG2			5

#define WORD                      	int

#define LM_bs_vector			WORD

#define MULTIPLIER                      (WORK_GROUP_SIZE*256)
#define PLAINTEXT_LENGTH		7

#define MIN_KEYS_PER_CRYPT		(LM_BS_DEPTH*MULTIPLIER)
#define MAX_KEYS_PER_CRYPT		(LM_BS_DEPTH*MULTIPLIER)

#define GWS_CONFIG		        "lm_GWS"

#define	MAX_DEVICES_PER_PLATFORM	10

#define get_key_body() {						\
	static char out[PLAINTEXT_LENGTH + 1];				\
	unsigned int section, block;					\
	unsigned char *src;						\
	char *dst;							\
									\
	if (cmp_out == NULL || cmp_out[0] == 0 ||			\
	    index > 32 * cmp_out[0] || cmp_out[0] > num_loaded_hashes)	\
		section = index / LM_BS_DEPTH;				\
	else								\
		section = cmp_out[2 * (index/LM_BS_DEPTH) + 1];	\
									\
	if (section > (num_set_keys + 31) / 32) {			\
		fprintf(stderr, "Get key error! %d %d\n", section,	\
			num_set_keys);					\
		section = 0;						\
		if (num_set_keys)					\
			error();					\
	}								\
	block  = index % LM_BS_DEPTH;					\
									\
	src = opencl_LM_bs_all[section].pxkeys[block];			\
	dst = out;							\
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {		\
		src += sizeof(LM_bs_vector) * 8;			\
		dst++;							\
	}								\
	*dst = 0;							\
									\
	return out;							\
}

typedef unsigned WORD vtype;

unsigned int CC_CACHE_ALIGN opencl_LM_bs_index768[0x300];

unsigned char opencl_LM_u[0x100];

typedef struct {
	unsigned char *pxkeys[LM_BS_DEPTH]; /* Pointers into xkeys.c */
} opencl_LM_bs_combined;

struct fmt_main;

struct fmt_main fmt_opencl_LM;

extern opencl_LM_bs_combined *opencl_LM_bs_all;
extern opencl_LM_bs_transfer *opencl_LM_bs_keys;
extern int opencl_LM_bs_keys_changed;
extern LM_bs_vector *opencl_LM_bs_cracked_hashes;

extern void opencl_LM_bs_b_register_functions(struct fmt_main *);

extern void (*opencl_LM_bs_init_global_variables)(void);
extern void (*opencl_LM_bs_select_device)(struct fmt_main *);


extern int opencl_LM_bs_get_hash_0(int index);
extern int opencl_LM_bs_get_hash_1(int index);
extern int opencl_LM_bs_get_hash_2(int index);
extern int opencl_LM_bs_get_hash_3(int index);
extern int opencl_LM_bs_get_hash_4(int index);
extern int opencl_LM_bs_get_hash_5(int index);
extern int opencl_LM_bs_get_hash_6(int index);
extern void opencl_LM_bs_init(int block);
extern int opencl_LM_bs_cmp_one_b(WORD *binary, int count, int index);
extern char *opencl_LM_bs_get_source_LM(WORD *raw);
extern WORD *opencl_get_binary_LM(char *ciphertext);
extern void opencl_LM_bs_set_key(char *key, int index);
extern void opencl_lm_init_index(void);

#endif
