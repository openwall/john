/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */


#ifndef _JOHN_DES_BS_H
#define _JOHN_DES_BS_H

#include "arch.h"
#include "opencl_common.h"
#include "opencl_DES_hst_dev_shared.h"
#include "loader.h"

#if (!AC_BUILT || HAVE_FCNTL_H)
#include <fcntl.h>		// For file locks.
#endif

#define DES_BS_OPENCL_ALGORITHM_NAME	"DES OpenCL"

#define FORMAT_LABEL			"descrypt-opencl"

#define DES_BS_DEPTH			32
#define DES_LOG_DEPTH			5

#define WORD                      	int

#define DES_bs_vector			WORD

#define PLAINTEXT_LENGTH		8

#define MIN_KEYS_PER_CRYPT		DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT		DES_BS_DEPTH

#define GWS_CONFIG		        "des_GWS"

/* Common hash checking variables. */
extern DES_hash_check_params *hash_chk_params;
#define num_uncracked_hashes(k) hash_chk_params[k].num_uncracked_hashes

extern void build_tables(struct db_main *);
extern void release_tables();
extern void update_buffer(struct db_salt *);
extern int extract_info(size_t, size_t *, WORD);
extern size_t create_checking_kernel_set_args();
extern void set_common_kernel_args_kpc(cl_mem, cl_mem);
extern void init_checking();
extern void finish_checking();

extern void create_keys_buffer(size_t, size_t);
extern void create_int_keys_buffer(void);
extern void release_keys_buffer();
extern void release_int_keys_buffer(void);
extern void process_keys(size_t, size_t *);
extern size_t create_keys_kernel_set_args(int);

extern char *get_device_name(int);
extern void save_lws_config(const char *, int, size_t, unsigned int);
extern int restore_lws_config(const char *, int, size_t *, size_t, unsigned int *);

typedef unsigned WORD vtype;

unsigned int CC_CACHE_ALIGN opencl_DES_bs_index768[0x300];

struct fmt_main;

extern struct fmt_main fmt_opencl_DES;
extern unsigned char opencl_DES_E[48];

extern void opencl_DES_bs_b_register_functions(struct fmt_main *);
extern void opencl_DES_bs_h_register_functions(struct fmt_main *);
extern void opencl_DES_bs_f_register_functions(struct fmt_main *);

extern void (*opencl_DES_bs_init_global_variables)(void);

extern int opencl_DES_bs_get_hash_0(int index);
extern int opencl_DES_bs_get_hash_1(int index);
extern int opencl_DES_bs_get_hash_2(int index);
extern int opencl_DES_bs_get_hash_3(int index);
extern int opencl_DES_bs_get_hash_4(int index);
extern int opencl_DES_bs_get_hash_5(int index);
extern int opencl_DES_bs_get_hash_6(int index);
extern int opencl_DES_bs_cmp_one(void *binary, int index);
extern int opencl_DES_bs_cmp_exact(char *source, int index);
extern void opencl_DES_bs_set_key(char *key, int index);
extern char *opencl_DES_bs_get_key(int index);
extern void opencl_DES_bs_init_index(void);
extern void opencl_DES_bs_clear_keys(void);

#endif
