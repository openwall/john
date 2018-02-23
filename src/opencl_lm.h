/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar LMigner implementation of LM_bs_b.c in jtr-v1.7.9
 */


#ifndef _JOHN_LM_BS_H
#define _JOHN_LM_BS_H

#include "arch.h"
#include "opencl_common.h"
#include "opencl_lm_hst_dev_shared.h"
#include "loader.h"

#define LM_OPENCL_ALGORITHM_NAME		"DES BS OpenCL"

#define LM_DEPTH			32
#define LM_LOG_DEPTH			5

#define WORD                      	int

#define lm_vector			WORD

#define MULTIPLIER                      (64 * 256)
#define PLAINTEXT_LENGTH		7

#define MIN_KEYS_PER_CRYPT		(LM_DEPTH * MULTIPLIER)
#define MAX_KEYS_PER_CRYPT		(LM_DEPTH * MULTIPLIER)

#define FORMAT_LABEL			"LM-opencl"

#define	MAX_DEVICES_PER_PLATFORM	10

#define get_key_body() {						\
	static char out[PLAINTEXT_LENGTH + 1];				\
	unsigned int section, block;					\
	unsigned char *src;						\
	char *dst;							\
									\
	if (hash_ids == NULL || hash_ids[0] == 0 ||			\
	    index > hash_ids[0] || hash_ids[0] > num_loaded_hashes) {	\
		section = 0;						\
		block = 0;						\
	}								\
	else {								\
		section = hash_ids[3 * index + 1] / 32;			\
		block  = hash_ids[3 * index + 1] & 31;			\
	}								\
									\
	if (section > global_work_size ) {				\
		/*fprintf(stderr, "Get key error! %u "Zu"\n", section, global_work_size);*/ \
		section = 0;						\
		block = 0;						\
	}								\
									\
	src = opencl_lm_all[section].pxkeys[block];			\
	dst = out;							\
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {		\
		src += sizeof(lm_vector) * 8;				\
		dst++;							\
	}								\
	*dst = 0;							\
									\
	return out;							\
}

typedef unsigned WORD vtype;

unsigned int CC_CACHE_ALIGN opencl_lm_index768[0x300];

unsigned char opencl_lm_u[0x100];

typedef struct {
	unsigned char *pxkeys[LM_DEPTH]; /* Pointers into xkeys.c */
} opencl_lm_combined;

struct fmt_main;

extern struct fmt_main fmt_opencl_lm;

extern opencl_lm_combined *opencl_lm_all;
extern opencl_lm_transfer *opencl_lm_keys;
extern unsigned int *opencl_lm_int_key_loc;

extern void opencl_lm_b_register_functions(struct fmt_main *);

extern void (*opencl_lm_init_global_variables)(void);

extern int opencl_lm_get_hash_0(int index);
extern int opencl_lm_get_hash_1(int index);
extern int opencl_lm_get_hash_2(int index);
extern int opencl_lm_get_hash_3(int index);
extern int opencl_lm_get_hash_4(int index);
extern int opencl_lm_get_hash_5(int index);
extern int opencl_lm_get_hash_6(int index);
extern void opencl_lm_init(int block);
extern char *opencl_lm_get_source(WORD *raw);
extern WORD *opencl_lm_get_binary(char *ciphertext);
extern void opencl_lm_set_key(char *key, int index);
extern void opencl_lm_set_key_mm(char *key, int index);
extern void opencl_lm_init_index(void);

#endif
