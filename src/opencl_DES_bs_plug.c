/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#ifdef HAVE_OPENCL

#include <string.h>
#include <fcntl.h>

#include "arch.h"
#include "common.h"
#include "opencl_DES_bs.h"
#include "../run/opencl/opencl_DES_hst_dev_shared.h"
#include "options.h"
#include "bt_interface.h"
#include "mask_ext.h"
#include "logger.h"

typedef struct {
	unsigned char *pxkeys[DES_BS_DEPTH]; /* Pointers into xkeys.c */
} des_combined;

static cl_kernel **cmp_kernel;
static cl_kernel kernel_high, kernel_low;
static cl_mem buffer_hash_ids, buffer_bitmap_dupe, *buffer_uncracked_hashes, *buffer_hash_tables, *buffer_offset_tables, *buffer_bitmaps;
static unsigned int *zero_buffer, **hash_tables;
static unsigned int *hash_ids;
static unsigned int max_uncracked_hashes, max_hash_table_size;
DES_hash_check_params *hash_chk_params;
static WORD current_salt;

static cl_kernel keys_kernel;
static cl_mem buffer_raw_keys, buffer_int_des_keys, buffer_int_key_loc;
static int new_keys = 1;
static des_combined *des_all;
static opencl_DES_bs_transfer *des_raw_keys;
static unsigned int *des_int_key_loc;
static unsigned int static_gpu_locations[MASK_FMT_INT_PLHDR];
static size_t process_key_gws;
unsigned int CC_CACHE_ALIGN opencl_DES_bs_index768[0x300];

unsigned char opencl_DES_E[48] = {
	31, 0, 1, 2, 3, 4,
	3, 4, 5, 6, 7, 8,
	7, 8, 9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31, 0
};

static unsigned char opencl_DES_PC1[56] = {
	56, 48, 40, 32, 24, 16, 8,
	0, 57, 49, 41, 33, 25, 17,
	9, 1, 58, 50, 42, 34, 26,
	18, 10, 2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	6, 61, 53, 45, 37, 29, 21,
	13, 5, 60, 52, 44, 36, 28,
	20, 12, 4, 27, 19, 11, 3
};

static unsigned char opencl_DES_ROT[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static unsigned char opencl_DES_PC2[48] = {
	13, 16, 10, 23, 0, 4,
	2, 27, 14, 5, 20, 9,
	22, 18, 11, 3, 25, 7,
	15, 6, 26, 19, 12, 1,
	40, 51, 30, 36, 46, 54,
	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31
};

#define num_uncracked_hashes(k) hash_chk_params[k].num_uncracked_hashes
#define hash_table_size(k) hash_chk_params[k].hash_table_size
#define offset_table_size(k) hash_chk_params[k].offset_table_size

#define LOW_THRESHOLD 		10

#define get_num_bits(r, v)			\
{						\
	r = (v & 0xAAAAAAAA) != 0;		\
	r |= ((v & 0xFFFF0000) != 0) << 4;	\
	r |= ((v & 0xFF00FF00) != 0) << 3;	\
	r |= ((v & 0xF0F0F0F0) != 0) << 2;	\
	r |= ((v & 0xCCCCCCCC) != 0) << 1;	\
}

static void prepare_bitmap_1(cl_ulong bmp_sz_bits, cl_uint **bitmaps_ptr, unsigned WORD *loaded_hashes, unsigned int num_uncracked_hashes)
{
	unsigned int i;
	MEM_FREE(*bitmaps_ptr);
	*bitmaps_ptr = (cl_uint*) mem_calloc((bmp_sz_bits >> 5), sizeof(cl_uint));

	for (i = 0; i < num_uncracked_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[2 * i + 1] & (bmp_sz_bits - 1);
		(*bitmaps_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));
	}
}

static void select_bitmap(unsigned int num_ld_hashes, WORD *uncracked_hashes_t, unsigned long *bitmap_size_bits, unsigned int **bitmaps_ptr, DES_hash_check_params *hash_chk_params)
{
	unsigned int cmp_steps = 1, bits_req = 32;

	if (num_ld_hashes <= 5100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			*bitmap_size_bits = 512 * 1024;

		else
			*bitmap_size_bits = 256 * 1024;

	}

	else if (num_ld_hashes <= 10100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			*bitmap_size_bits = 512 * 1024;

		else
			*bitmap_size_bits = 256 * 1024;
	}

	else if (num_ld_hashes <= 20100) {
		if (amd_gcn_10(device_info[gpu_id]))
			*bitmap_size_bits = 1024 * 1024;

		else
			*bitmap_size_bits = 512 * 1024;
	}

	else if (num_ld_hashes <= 250100)
		*bitmap_size_bits = 2048 * 1024;

	else if (num_ld_hashes <= 1100100) {
		if (!amd_gcn_11(device_info[gpu_id]))
			*bitmap_size_bits = 4096 * 1024;

		else
			*bitmap_size_bits = 2048 * 1024;
	}

	else if (num_ld_hashes <= 1500100)
		*bitmap_size_bits = 4096 * 1024 * 2;

	else if (num_ld_hashes <= 2700100)
		*bitmap_size_bits = 4096 * 1024 * 2 * 2;

	else {
		cl_ulong mult = num_ld_hashes / 2700100;
		cl_ulong buf_sz;
		*bitmap_size_bits = 4096 * 4096;
		get_power_of_two(mult);
		*bitmap_size_bits *= mult;
		buf_sz = get_max_mem_alloc_size(gpu_id);
		if (buf_sz & (buf_sz - 1)) {
			get_power_of_two(buf_sz);
			buf_sz >>= 1;
		}
		if (buf_sz >= 536870912)
			buf_sz = 536870912;
		if (((*bitmap_size_bits) >> 3) > buf_sz)
			*bitmap_size_bits = buf_sz << 3;
	}

	prepare_bitmap_1(*bitmap_size_bits, bitmaps_ptr, (unsigned WORD *)uncracked_hashes_t, num_ld_hashes);

	get_num_bits(bits_req, (*bitmap_size_bits));

	hash_chk_params->bitmap_size_bits = (unsigned int)(*bitmap_size_bits);
	hash_chk_params->cmp_steps = cmp_steps;
	hash_chk_params->cmp_bits = bits_req;

	*bitmap_size_bits *= cmp_steps;
}

static void fill_buffer(struct db_salt *salt, unsigned int *max_uncracked_hashes, unsigned int *max_hash_table_size)
{
	int i;
	WORD salt_val;
	WORD *binary;
	WORD *uncracked_hashes = NULL, *uncracked_hashes_t = NULL;
	struct db_password *pw, *last;
	OFFSET_TABLE_WORD *offset_table;
	unsigned int hash_table_size, offset_table_size;

	salt_val = *(WORD *)salt->salt;
	num_uncracked_hashes(salt_val) = salt->count;

	uncracked_hashes = (WORD *) mem_calloc(2 * num_uncracked_hashes(salt_val), sizeof(WORD));
	uncracked_hashes_t = (WORD *) mem_calloc(2 * num_uncracked_hashes(salt_val), sizeof(WORD));

	i = 0;
	last = pw = salt->list;
	do {
		binary = (WORD *)pw->binary;
		if (binary == NULL) {
			if (last == pw)
				salt->list = pw->next;
			else
				last->next = pw->next;
		} else {
			last = pw;
			uncracked_hashes_t[2 * i] = binary[0];
			uncracked_hashes_t[2 * i + 1] = binary[1];
			i++;
		}
	} while ((pw = pw->next));

	if (salt->count > *max_uncracked_hashes)
		*max_uncracked_hashes = salt->count;

	num_uncracked_hashes(salt_val) = bt_create_perfect_hash_table(64, (void *)uncracked_hashes_t,
				num_uncracked_hashes(salt_val),
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size, 0);

	hash_table_size(salt_val) = hash_table_size;
	offset_table_size(salt_val) = offset_table_size;

	if (hash_table_size(salt_val) > *max_hash_table_size)
		*max_hash_table_size = hash_table_size(salt_val);

	if (!num_uncracked_hashes(salt_val)) {
		MEM_FREE(bt_hash_table_64);
		MEM_FREE(offset_table);
		fprintf(stderr, "Failed to create Hash Table for cracking.\n");
		error();
	}

	hash_tables[salt_val] = bt_hash_table_64;

	/* uncracked_hashes_t is modified by bt_create_perfect_hash_table. */
	for (i = 0; i < num_uncracked_hashes(salt_val); i++) {
		uncracked_hashes[i] = uncracked_hashes_t[2 * i];
		uncracked_hashes[i + num_uncracked_hashes(salt_val)] = uncracked_hashes_t[2 * i + 1];
	}

	buffer_offset_tables[salt_val] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(OFFSET_TABLE_WORD) * offset_table_size , offset_table, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_offset_tables failed.\n");

	buffer_hash_tables[salt_val] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 2 * sizeof(unsigned int) * hash_table_size, bt_hash_table_64, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_hash_tables failed.\n");

	if (num_uncracked_hashes(salt_val) <= LOW_THRESHOLD) {
		buffer_uncracked_hashes[salt_val] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 2 * sizeof(WORD) * num_uncracked_hashes(salt_val), uncracked_hashes, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_uncracked_hashes failed.\n");
	}
	else {
		unsigned long bitmap_size_bits = 0;
		unsigned int *bitmaps = NULL;
		select_bitmap(num_uncracked_hashes(salt_val), uncracked_hashes_t, &bitmap_size_bits, &bitmaps, &hash_chk_params[salt_val]);
		buffer_bitmaps[salt_val] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, bitmap_size_bits >> 3, bitmaps, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_bitmaps failed.\n");
		MEM_FREE(bitmaps);
	}

	MEM_FREE(uncracked_hashes);
	MEM_FREE(uncracked_hashes_t);
	MEM_FREE(offset_table);
}

static void fill_buffer_self_test(unsigned int *max_uncracked_hashes, unsigned int *max_hash_table_size)
{
	char *ciphertext;
	WORD *binary;
	WORD salt_val;
	unsigned int offset_table_size, hash_table_size;
	unsigned long bitmap_size_bits = 0;
	unsigned int *bitmaps = NULL;
	WORD *uncracked_hashes = NULL, *uncracked_hashes_t = NULL;
	int i;
	OFFSET_TABLE_WORD *offset_table = NULL;
	DES_hash_check_params temp_param;

	while (fmt_opencl_DES.params.tests[*max_uncracked_hashes].ciphertext) {
		ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[*max_uncracked_hashes].ciphertext, 0, &fmt_opencl_DES);
		(*max_uncracked_hashes)++;
	}

	uncracked_hashes = (WORD *) mem_calloc(2 * *max_uncracked_hashes, sizeof(WORD));
	uncracked_hashes_t = (WORD *) mem_calloc(2 * *max_uncracked_hashes, sizeof(WORD));

	i = 0;
	while (fmt_opencl_DES.params.tests[i].ciphertext) {
		ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[i].ciphertext, 0, &fmt_opencl_DES);
		binary = (WORD *)fmt_opencl_DES.methods.binary(ciphertext);
		salt_val = *(WORD *)fmt_opencl_DES.methods.salt(ciphertext);
		uncracked_hashes_t[2 * i] = binary[0];
		uncracked_hashes_t[2 * i + 1] = binary[1];
		num_uncracked_hashes(salt_val) = 1;
		//fprintf(stderr, "C:%s B:%d \n", ciphertext, binary[1]);
		i++;
	}

	*max_uncracked_hashes = bt_create_perfect_hash_table(64, (void *)uncracked_hashes_t,
				*max_uncracked_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size, 0);
	*max_hash_table_size = hash_table_size;

	if (!*max_uncracked_hashes) {
		MEM_FREE(bt_hash_table_64);
		MEM_FREE(offset_table);
		fprintf(stderr, "Failed to create Hash Table for cracking.\n");
		error();
	}

	/* uncracked_hashes_t is modified by bt_create_perfect_hash_table. */
	for (i = 0; i < *max_uncracked_hashes; i++) {
		uncracked_hashes[i] = uncracked_hashes_t[2 * i];
		uncracked_hashes[i + *max_uncracked_hashes] = uncracked_hashes_t[2 * i + 1];
	}

	select_bitmap(*max_uncracked_hashes, uncracked_hashes_t, &bitmap_size_bits, &bitmaps, &temp_param);

	for (i = 0; i < 4096; i++) {
		if (!num_uncracked_hashes(i)) continue;
		hash_chk_params[i] = temp_param; /* Error if this statement is excuted later in the body of loop. */
		num_uncracked_hashes(i) = *max_uncracked_hashes;
		hash_table_size(i) = hash_table_size;
		offset_table_size(i) = offset_table_size;
		hash_tables[i] = (unsigned int *) mem_alloc(2 * sizeof(unsigned int) * hash_table_size);
		memcpy(hash_tables[i], bt_hash_table_64, 2 * sizeof(unsigned int) * hash_table_size);
		buffer_offset_tables[i] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(OFFSET_TABLE_WORD) * offset_table_size , offset_table, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_offset_tables failed.\n");
		buffer_hash_tables[i] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 2 * sizeof(unsigned int) * hash_table_size, bt_hash_table_64, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_hash_tables failed.\n");
		buffer_bitmaps[i] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, bitmap_size_bits >> 3, bitmaps, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_bitmaps failed.\n");
		buffer_uncracked_hashes[i] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 2 * sizeof(WORD) * *max_uncracked_hashes, uncracked_hashes, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_uncracked_hashes failed.\n");
	}

	MEM_FREE(uncracked_hashes);
	MEM_FREE(uncracked_hashes_t);
	MEM_FREE(offset_table);
	MEM_FREE(bt_hash_table_64);
	MEM_FREE(bitmaps);
}

static void release_fill_buffer(WORD i)
{
	if (buffer_uncracked_hashes[i] != (cl_mem)0) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_uncracked_hashes[i]), "Release buffer_uncracked_hashes failed.\n");
		buffer_uncracked_hashes[i] = (cl_mem)0;
	}
	if (buffer_offset_tables[i] != (cl_mem)0) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_offset_tables[i]), "Release buffer_offset_tables failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_tables[i]), "Release buffer_hash_tables failed.\n");
		buffer_hash_tables[i] = (cl_mem)0;
		buffer_offset_tables[i] = (cl_mem)0;
	}
	if (buffer_bitmaps[i] != (cl_mem)0) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmaps[i]), "Release buffer_bitmaps failed.\n");
		buffer_bitmaps[i] = (cl_mem)0;
	}
	if (hash_tables[i])
		MEM_FREE(hash_tables[i]);
	hash_tables[i] = 0;
}

static void release_fill_buffers()
{
	int i;

	for (i = 0; i < 4096; i++)
		release_fill_buffer(i);
}

static void create_aux_buffers(unsigned int max_uncracked_hashes, unsigned int max_hash_table_size)
{
	zero_buffer = (unsigned int *) mem_calloc((max_hash_table_size - 1) / 32 + 1, sizeof(unsigned int));

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((max_hash_table_size - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_bitmap_dupe failed.\n");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * max_uncracked_hashes + 1) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_hash_ids failed.\n");

	hash_ids = (unsigned int *) mem_calloc((2 * max_uncracked_hashes + 1), sizeof(unsigned int));

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "Failed to write buffer buffer_hash_ids.\n");
}

static void release_aux_buffers()
{
	if (zero_buffer) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Release buffer_bitmap_dupe failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Release buffer_hash_ids failed.\n");

		MEM_FREE(hash_ids);
		MEM_FREE(zero_buffer);
		zero_buffer = 0;
	}
}

void build_tables(struct db_main *db)
{
	buffer_uncracked_hashes = (cl_mem *) mem_calloc(4096, sizeof(cl_mem));
	hash_tables = (unsigned int **) mem_calloc(4096, sizeof(unsigned int *));
	buffer_offset_tables = (cl_mem *) mem_calloc(4096, sizeof(cl_mem));
	buffer_hash_tables = (cl_mem *) mem_calloc(4096, sizeof(cl_mem));
	buffer_bitmaps = (cl_mem *) mem_calloc(4096, sizeof(cl_mem));
	memset(hash_chk_params, 0, 4096 * sizeof(DES_hash_check_params));

	if (db) {
	struct db_salt *salt = db->salts;
	do {
		fill_buffer(salt, &max_uncracked_hashes, &max_hash_table_size);
	} while((salt = salt->next));
	}
	else {
		fill_buffer_self_test(&max_uncracked_hashes, &max_hash_table_size);
	}

	create_aux_buffers(max_uncracked_hashes, max_hash_table_size);
}

void release_tables()
{
	release_aux_buffers();

	if (buffer_uncracked_hashes) {
		release_fill_buffers();
		MEM_FREE(buffer_uncracked_hashes);
		MEM_FREE(buffer_offset_tables);
		MEM_FREE(buffer_hash_tables);
		MEM_FREE(buffer_bitmaps);
		MEM_FREE(hash_tables);
		hash_tables = 0;
		buffer_uncracked_hashes = 0;
	}
}

static void set_kernel_args_aux_buf()
{
	HANDLE_CLERROR(clSetKernelArg(kernel_low, 4, sizeof(cl_mem), &buffer_hash_ids), "Failed setting kernel argument buffer_hash_ids, kernel DES_bs_cmp_low.\n");
	HANDLE_CLERROR(clSetKernelArg(kernel_low, 5, sizeof(cl_mem), &buffer_bitmap_dupe), "Failed setting kernel argument buffer_bitmap_dupe, kernel DES_bs_cmp_low.\n");

	HANDLE_CLERROR(clSetKernelArg(kernel_high, 4, sizeof(cl_mem), &buffer_hash_ids), "Failed setting kernel argument buffer_hash_ids, kernel DES_bs_cmp.\n");
	HANDLE_CLERROR(clSetKernelArg(kernel_high, 5, sizeof(cl_mem), &buffer_bitmap_dupe), "Failed setting kernel argument buffer_bitmap_dupe, kernel DES_bs_cmp.\n");
}

size_t create_checking_kernel_set_args()
{
	int i;
	size_t min_lws;

	opencl_build_kernel("$JOHN/opencl/DES_bs_hash_checking_kernel.cl",
	                    gpu_id, NULL, 0);

	if (kernel_high == 0) {
		kernel_high = clCreateKernel(program[gpu_id], "DES_bs_cmp_high", &ret_code);
		HANDLE_CLERROR(ret_code, "Failed creating kernel DES_bs_cmp_high.\n");
	}
	if (kernel_low == 0) {
		kernel_low = clCreateKernel(program[gpu_id], "DES_bs_cmp", &ret_code);
		HANDLE_CLERROR(ret_code, "Failed creating kernel DES_bs_cmp.\n");
	}

	memset(cmp_kernel[gpu_id], 0, 4096 * sizeof(cl_kernel));

	for (i = 0; i < 4096; i++) {
		if (num_uncracked_hashes(i) <= LOW_THRESHOLD)
			cmp_kernel[gpu_id][i] = kernel_low;
		else
			cmp_kernel[gpu_id][i] = kernel_high;
	}

	set_kernel_args_aux_buf();

	min_lws = get_kernel_max_lws(gpu_id, kernel_high);

	if (min_lws > get_kernel_max_lws(gpu_id, kernel_low))
		return get_kernel_max_lws(gpu_id, kernel_low);

	return min_lws;
}

void set_common_kernel_args_kpc(cl_mem buffer_unchecked_hashes, cl_mem buffer_bs_keys)
{
	HANDLE_CLERROR(clSetKernelArg(kernel_low, 0, sizeof(cl_mem), &buffer_unchecked_hashes), "Failed setting kernel argument buffer_unchecked_hashes, kernel DES_bs_cmp.\n");
	HANDLE_CLERROR(clSetKernelArg(kernel_high, 0, sizeof(cl_mem), &buffer_unchecked_hashes), "Failed setting kernel argument buffer_unchecked_hashes, kernel DES_bs_cmp.\n");

	HANDLE_CLERROR(clSetKernelArg(keys_kernel, 0, sizeof(cl_mem), &buffer_raw_keys), "Failed setting kernel argument buffer_raw_keys, kernel DES_bs_finalize_keys.\n");
	HANDLE_CLERROR(clSetKernelArg(keys_kernel, 2, sizeof(cl_mem), &buffer_int_key_loc), "Failed setting kernel argument buffer_int_key_loc, kernel DES_bs_finalize_keys.\n");
	HANDLE_CLERROR(clSetKernelArg(keys_kernel, 3, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_finalize_keys.\n");
}

void update_buffer(struct db_salt *salt)
{
	unsigned int _max_uncracked_hashes = 0, _max_hash_table_size = 0;
	WORD salt_val = *(WORD *)salt->salt;
	release_fill_buffer(salt_val);

	if (salt->count > LOW_THRESHOLD &&
		(num_uncracked_hashes(salt_val) - num_uncracked_hashes(salt_val) / 10) < salt->count)
		return;

	fill_buffer(salt, &_max_uncracked_hashes, &_max_hash_table_size);

	if (_max_uncracked_hashes > max_uncracked_hashes || _max_hash_table_size > max_hash_table_size) {
		release_aux_buffers();
		create_aux_buffers(max_uncracked_hashes, max_hash_table_size);
		set_kernel_args_aux_buf();
		max_hash_table_size = _max_hash_table_size;
		max_uncracked_hashes = _max_uncracked_hashes;
	}

	if (num_uncracked_hashes(salt_val) <= LOW_THRESHOLD)
		cmp_kernel[gpu_id][salt_val] = kernel_low;
	else
		cmp_kernel[gpu_id][salt_val] = kernel_high;

	if (options.verbosity > VERB_LEGACY)
		fprintf(stderr,
		        "Updated internal tables and buffers for salt %d.\n", salt_val);
}

int extract_info(size_t current_gws, size_t *lws, WORD salt_val)
{
	current_salt = salt_val;

	HANDLE_CLERROR(clSetKernelArg(cmp_kernel[gpu_id][current_salt], 1, sizeof(cl_mem), &buffer_offset_tables[current_salt]), "Failed setting kernel argument buffer_offset_tables, kernel DES_bs_cmp.\n");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel[gpu_id][current_salt], 2, sizeof(cl_mem), &buffer_hash_tables[current_salt]), "Failed setting kernel argument buffer_hash_tables, kernel DES_bs_cmp.\n");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel[gpu_id][current_salt], 3, sizeof(DES_hash_check_params), &hash_chk_params[current_salt]), "Failed setting kernel argument num_uncracked_hashes, kernel DES_bs_cmp.\n");
	if (num_uncracked_hashes(current_salt) <= LOW_THRESHOLD)
		HANDLE_CLERROR(clSetKernelArg(cmp_kernel[gpu_id][current_salt], 6, sizeof(cl_mem), &buffer_uncracked_hashes[current_salt]), "Failed setting kernel argument buffer_uncracked_hashes, kernel DES_bs_cmp.\n");
	else
		HANDLE_CLERROR(clSetKernelArg(cmp_kernel[gpu_id][current_salt], 6, sizeof(cl_mem), &buffer_bitmaps[current_salt]), "Failed setting kernel argument buffer_bitmaps, kernel DES_bs_cmp_high.\n");

	ret_code = clEnqueueNDRangeKernel(queue[gpu_id], cmp_kernel[gpu_id][current_salt], 1, NULL, &current_gws, lws, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Enqueue kernel DES_bs_cmp failed.\n");

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Failed to read buffer buffer_hash_ids.\n");

	if (hash_ids[0] > num_uncracked_hashes(current_salt)) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (2 * hash_ids[0] + 1) * sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Failed to read buffer buffer_hash_ids.\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_TRUE, 0, ((hash_table_size(current_salt) - 1)/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "Failed to write buffer buffer_bitmap_dupe.\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "Failed to write buffer buffer_hash_ids.\n");
	}

	return hash_ids[0];
}

void init_checking()
{
	int i = 0;
	cmp_kernel = (cl_kernel **) mem_calloc(MAX_GPU_DEVICES, sizeof(cl_kernel *));
	for (i = 0; i < MAX_GPU_DEVICES; i++)
		cmp_kernel[i] = (cl_kernel *) mem_calloc(4096, sizeof(cl_kernel));
	hash_chk_params = (DES_hash_check_params *) mem_calloc(4096, sizeof(DES_hash_check_params));
}

void finish_checking()
{
	int i;

	if (kernel_high) {
		HANDLE_CLERROR(clReleaseKernel(kernel_high), "Error releasing kernel_high.");
		kernel_high = 0;
	}
	if (kernel_low) {
		HANDLE_CLERROR(clReleaseKernel(kernel_low), "Error releasing kernel_low.");
		kernel_low = 0;
	}
	for (i = 0; i < MAX_GPU_DEVICES; i++)
		MEM_FREE(cmp_kernel[i]);
	MEM_FREE(cmp_kernel);
	MEM_FREE(hash_chk_params);
}

int opencl_DES_bs_get_hash_0(int index)
{
	return hash_tables[current_salt][hash_ids[2 + 2 * index]] & PH_MASK_0;
}

int opencl_DES_bs_get_hash_1(int index)
{
	return hash_tables[current_salt][hash_ids[2 + 2 * index]] & PH_MASK_1;
}

int opencl_DES_bs_get_hash_2(int index)
{
	return hash_tables[current_salt][hash_ids[2 + 2 * index]] & PH_MASK_2;
}

int opencl_DES_bs_get_hash_3(int index)
{
	return hash_tables[current_salt][hash_ids[2 + 2 * index]] & PH_MASK_3;
}

int opencl_DES_bs_get_hash_4(int index)
{
	return hash_tables[current_salt][hash_ids[2 + 2 * index]] & PH_MASK_4;
}

int opencl_DES_bs_get_hash_5(int index)
{
	return hash_tables[current_salt][hash_ids[2 + 2 * index]] & PH_MASK_5;
}

int opencl_DES_bs_get_hash_6(int index)
{
	return hash_tables[current_salt][hash_ids[2 + 2 * index]] & PH_MASK_6;
}

int opencl_DES_bs_cmp_one(void *binary, int index)
{
	if (((int *)binary)[0] == hash_tables[current_salt][hash_ids[2 + 2 * index]])
		return 1;
	return 0;
}

int opencl_DES_bs_cmp_exact(char *source, int index)
{
	int *binary = fmt_opencl_DES.methods.binary(source);

	if (binary[1] == hash_tables[current_salt][hash_ids[2 + 2 * index] + hash_table_size(current_salt)])
		return 1;
	return 0;
}

/* End of hash checking. */

typedef union {
	unsigned char c[8][sizeof(DES_bs_vector)];
	DES_bs_vector v[8];
} key_page;

#define vxorf(a, b) 					\
	((a) ^ (b))
#define vnot(dst, a) 					\
	(dst) = ~(a)
#define vand(dst, a, b) 				\
	(dst) = (a) & (b)
#define vor(dst, a, b) 					\
	(dst) = (a) | (b)
#define vandn(dst, a, b) 				\
	(dst) = (a) & ~(b)
#define vxor(dst, a, b) 				\
	(dst) = vxorf((a), (b))
#define vshl(dst, src, shift) 				\
	(dst) = (src) << (shift)
#define vshr(dst, src, shift) 				\
	(dst) = (src) >> (shift)
#define vshl1(dst, src) 				\
	vshl((dst), (src), 1)

#define kvtype vtype
#define kvand vand
#define kvor vor
#define kvshl1 vshl1
#define kvshl vshl
#define kvshr vshr

#define mask01 0x01010101
#define mask02 0x02020202
#define mask04 0x04040404
#define mask08 0x08080808
#define mask10 0x10101010
#define mask20 0x20202020
#define mask40 0x40404040
#define mask80 0x80808080

#define kvand_shl1_or(dst, src, mask) 			\
	kvand(tmp, src, mask); 				\
	kvshl1(tmp, tmp); 				\
	kvor(dst, dst, tmp)

#define kvand_shl_or(dst, src, mask, shift) 		\
	kvand(tmp, src, mask); 				\
	kvshl(tmp, tmp, shift); 			\
	kvor(dst, dst, tmp)

#define kvand_shl1(dst, src, mask) 			\
	kvand(tmp, src, mask) ;				\
	kvshl1(dst, tmp)

#define kvand_or(dst, src, mask) 			\
	kvand(tmp, src, mask); 				\
	kvor(dst, dst, tmp)

#define kvand_shr_or(dst, src, mask, shift)		\
	kvand(tmp, src, mask); 				\
	kvshr(tmp, tmp, shift); 			\
	kvor(dst, dst, tmp)

#define kvand_shr(dst, src, mask, shift) 		\
	kvand(tmp, src, mask); 				\
	kvshr(dst, tmp, shift)

#define LOAD_V 						\
	kvtype v0 = *(kvtype *)&vp[0]; 	\
	kvtype v1 = *(kvtype *)&vp[1]; 	\
	kvtype v2 = *(kvtype *)&vp[2]; 	\
	kvtype v3 = *(kvtype *)&vp[3]; 	\
	kvtype v4 = *(kvtype *)&vp[4]; 	\
	kvtype v5 = *(kvtype *)&vp[5]; 	\
	kvtype v6 = *(kvtype *)&vp[6]; 	\
	kvtype v7 = *(kvtype *)&vp[7];

#define FINALIZE_NEXT_KEY_BIT_0g { 			\
	kvtype m = mask01, va, vb, tmp; 		\
	kvand(va, v0, m); 				\
	kvand_shl1(vb, v1, m); 				\
	kvand_shl_or(va, v2, m, 2); 			\
	kvand_shl_or(vb, v3, m, 3); 			\
	kvand_shl_or(va, v4, m, 4); 			\
	kvand_shl_or(vb, v5, m, 5); 			\
	kvand_shl_or(va, v6, m, 6); 			\
	kvand_shl_or(vb, v7, m, 7); 			\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}

#define FINALIZE_NEXT_KEY_BIT_1g { 			\
	kvtype m = mask02, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 1); 			\
	kvand(vb, v1, m); 				\
	kvand_shl1_or(va, v2, m); 			\
	kvand_shl_or(vb, v3, m, 2); 			\
	kvand_shl_or(va, v4, m, 3); 			\
	kvand_shl_or(vb, v5, m, 4); 			\
	kvand_shl_or(va, v6, m, 5); 			\
	kvand_shl_or(vb, v7, m, 6); 			\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}

#define FINALIZE_NEXT_KEY_BIT_2g { 			\
	kvtype m = mask04, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 2); 			\
	kvand_shr(vb, v1, m, 1); 			\
	kvand_or(va, v2, m); 				\
	kvand_shl1_or(vb, v3, m); 			\
	kvand_shl_or(va, v4, m, 2); 			\
	kvand_shl_or(vb, v5, m, 3); 			\
	kvand_shl_or(va, v6, m, 4); 			\
	kvand_shl_or(vb, v7, m, 5); 			\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}

#define FINALIZE_NEXT_KEY_BIT_3g { 			\
	kvtype m = mask08, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 3); 			\
	kvand_shr(vb, v1, m, 2); 			\
	kvand_shr_or(va, v2, m, 1); 			\
	kvand_or(vb, v3, m); 				\
	kvand_shl1_or(va, v4, m); 			\
	kvand_shl_or(vb, v5, m, 2); 			\
	kvand_shl_or(va, v6, m, 3); 			\
	kvand_shl_or(vb, v7, m, 4); 			\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}

#define FINALIZE_NEXT_KEY_BIT_4g { 			\
	kvtype m = mask10, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 4); 			\
	kvand_shr(vb, v1, m, 3); 			\
	kvand_shr_or(va, v2, m, 2); 			\
	kvand_shr_or(vb, v3, m, 1); 			\
	kvand_or(va, v4, m); 				\
	kvand_shl1_or(vb, v5, m); 			\
	kvand_shl_or(va, v6, m, 2); 			\
	kvand_shl_or(vb, v7, m, 3); 			\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}

#define FINALIZE_NEXT_KEY_BIT_5g { 			\
	kvtype m = mask20, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 5); 			\
	kvand_shr(vb, v1, m, 4); 			\
	kvand_shr_or(va, v2, m, 3); 			\
	kvand_shr_or(vb, v3, m, 2); 			\
	kvand_shr_or(va, v4, m, 1); 			\
	kvand_or(vb, v5, m); 				\
	kvand_shl1_or(va, v6, m); 			\
	kvand_shl_or(vb, v7, m, 2); 			\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}

#define FINALIZE_NEXT_KEY_BIT_6g { 			\
	kvtype m = mask40, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 6); 			\
	kvand_shr(vb, v1, m, 5); 			\
	kvand_shr_or(va, v2, m, 4); 			\
	kvand_shr_or(vb, v3, m, 3); 			\
	kvand_shr_or(va, v4, m, 2); 			\
	kvand_shr_or(vb, v5, m, 1); 			\
	kvand_or(va, v6, m); 				\
	kvand_shl1_or(vb, v7, m); 			\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}

static void des_finalize_int_keys()
{
	key_page *int_key_page[MASK_FMT_INT_PLHDR];
	unsigned int *final_key_pages[MASK_FMT_INT_PLHDR], i, j;

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		int_key_page[i] = (key_page *) mem_alloc(((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH) * sizeof(key_page));
		final_key_pages[i] = (unsigned int *) mem_alloc(7 * ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH) * sizeof(unsigned int));
		memset(int_key_page[i], 0x7f, ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH) * sizeof(key_page));
		memset(final_key_pages[i], 0xff, 7 * ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH) * sizeof(unsigned int));
	}

	for (i = 0; i < mask_int_cand.num_int_cand && mask_int_cand.int_cand; i++) {
		j = i >> DES_LOG_DEPTH;
		int_key_page[0][j].c[(i & (DES_BS_DEPTH - 1)) & 7][(i & (DES_BS_DEPTH - 1)) >> 3] = mask_int_cand.int_cand[i].x[0] & 0xFF;
#if MASK_FMT_INT_PLHDR > 1
		if (mask_skip_ranges[1] != -1)
			int_key_page[1][j].c[(i & (DES_BS_DEPTH - 1)) & 7][(i & (DES_BS_DEPTH - 1)) >> 3] = mask_int_cand.int_cand[i].x[1] & 0xFF;
#endif
#if MASK_FMT_INT_PLHDR > 2
		if (mask_skip_ranges[2] != -1)
			int_key_page[2][j].c[(i & (DES_BS_DEPTH - 1)) & 7][(i & (DES_BS_DEPTH - 1)) >> 3] = mask_int_cand.int_cand[i].x[2] & 0xFF;
#endif
#if MASK_FMT_INT_PLHDR > 3
		if (mask_skip_ranges[3] != -1)
			int_key_page[3][j].c[(i & (DES_BS_DEPTH - 1)) & 7][(i & (DES_BS_DEPTH - 1)) >> 3] = mask_int_cand.int_cand[i].x[3] & 0xFF;
#endif
	}

	for (j = 0; j < MASK_FMT_INT_PLHDR; j++) {
		if (mask_skip_ranges == NULL || mask_skip_ranges[j] == -1)
			continue;
		for (i = 0; i < ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH); i++) {
			DES_bs_vector *kp = (DES_bs_vector *)&final_key_pages[j][7 * i];
			DES_bs_vector *vp = (DES_bs_vector *)&int_key_page[j][i].v[0];
			LOAD_V
			FINALIZE_NEXT_KEY_BIT_0g
			FINALIZE_NEXT_KEY_BIT_1g
			FINALIZE_NEXT_KEY_BIT_2g
			FINALIZE_NEXT_KEY_BIT_3g
			FINALIZE_NEXT_KEY_BIT_4g
			FINALIZE_NEXT_KEY_BIT_5g
			FINALIZE_NEXT_KEY_BIT_6g
		}
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_des_keys, CL_TRUE, j * 7 * ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH) * sizeof(unsigned int),
			7 * ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH) * sizeof(unsigned int), final_key_pages[j], 0, NULL, NULL ), "Failed Copy data to gpu");
	}

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		MEM_FREE(int_key_page[i]);
		MEM_FREE(final_key_pages[i]);
	}
}

void opencl_DES_bs_init_index()
{
	int p,q,s,t ;
	int round, index, bit;

	s = 0;
	t = 0;
	for (round = 0; round < 16; round++) {
		s += opencl_DES_ROT[round];
		for (index = 0; index < 48; index++) {
			p = opencl_DES_PC2[index];
			q = p < 28 ? 0 : 28;
			p += s;
			while (p >= 28) p -= 28;
			bit = opencl_DES_PC1[p + q];
			bit ^= 070;
			bit -= bit >> 3;
			bit = 55 - bit;
			opencl_DES_bs_index768[t++] = bit;
		}
	}
}

static void DES_bs_init(int block)
{
	int index;

	for (index = 0; index < DES_BS_DEPTH; index++)
		des_all[block].pxkeys[index] =
			&des_raw_keys[block].xkeys.c[0][index & 7][index >> 3];
}

void create_keys_buffer(size_t gws, size_t padding)
{
	int i;

	des_all = (des_combined *) mem_alloc((gws + padding) * sizeof(des_combined));
	des_raw_keys = (opencl_DES_bs_transfer *) mem_alloc((gws + padding) * sizeof(opencl_DES_bs_transfer));
	des_int_key_loc = (unsigned int *) mem_calloc((gws + padding), sizeof(unsigned int));

	for (i = 0; i < gws; i++)
		DES_bs_init(i);

	buffer_raw_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, (gws + padding) * sizeof(opencl_DES_bs_transfer), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_raw_keys failed.\n");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws + padding) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_int_key_loc failed.\n");
}

void create_int_keys_buffer()
{
	unsigned int active_placeholders, i;

	active_placeholders = 0;
	if (mask_skip_ranges) {
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
			if (mask_skip_ranges[i] != -1)
				active_placeholders++;
		}
	} else {
		active_placeholders = 1;
	}

	buffer_int_des_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, active_placeholders * 7 * ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_int_des_keys failed.\n");
}

void release_int_keys_buffer()
{
	if (buffer_int_des_keys) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_des_keys), "Release buffer_int_des_keys failed.\n");
		HANDLE_CLERROR(clReleaseKernel(keys_kernel), "Release keys_kernel failed.\n");
		buffer_int_des_keys = 0;
	}
}

void release_keys_buffer()
{
	if (buffer_raw_keys) {
		MEM_FREE(des_all);
		MEM_FREE(des_raw_keys);
		MEM_FREE(des_int_key_loc);
		HANDLE_CLERROR(clReleaseMemObject(buffer_raw_keys), "Release buffer_raw_keys failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_key_loc), "Release buffer_int_key_loc failed.\n");
		buffer_raw_keys = 0;
	}
}

void opencl_DES_bs_set_key(char *key, int index)
{
	unsigned char *dst;
	unsigned int sector,key_index;
	unsigned int flag = key[0];

	sector = index >> DES_LOG_DEPTH;
	key_index = index & (DES_BS_DEPTH - 1);
	dst = des_all[sector].pxkeys[key_index];

	new_keys = 1;

	dst[0] = 				(!flag) ? 0 : key[0];
	dst[sizeof(DES_bs_vector) * 8]      =	(!flag) ? 0 : key[1];
	flag = flag&&key[1] ;
	dst[sizeof(DES_bs_vector) * 8 * 2]  =	(!flag) ? 0 : key[2];
	flag = flag&&key[2];
	dst[sizeof(DES_bs_vector) * 8 * 3]  =	(!flag) ? 0 : key[3];
	flag = flag&&key[3];
	dst[sizeof(DES_bs_vector) * 8 * 4]  =	(!flag) ? 0 : key[4];
	flag = flag&&key[4]&&key[5];
	dst[sizeof(DES_bs_vector) * 8 * 5]  =	(!flag) ? 0 : key[5];
	flag = flag&&key[6];
	dst[sizeof(DES_bs_vector) * 8 * 6]  =	(!flag) ? 0 : key[6];
	dst[sizeof(DES_bs_vector) * 8 * 7]  =	(!flag) ? 0 : key[7];

/*
	if (!key[0]) goto fill8;
	*dst = key[0];
	*(dst + sizeof(DES_bs_vector) * 8) = key[1];
	*(dst + sizeof(DES_bs_vector) * 8 * 2) = key[2];
	if (!key[1]) goto fill6;
	if (!key[2]) goto fill5;
	*(dst + sizeof(DES_bs_vector) * 8 * 3) = key[3];
	*(dst + sizeof(DES_bs_vector) * 8 * 4) = key[4];
	if (!key[3]) goto fill4;
	if (!key[4] || !key[5]) goto fill3;
	*(dst + sizeof(DES_bs_vector) * 8 * 5) = key[5];
	if (!key[6]) goto fill2;
	*(dst + sizeof(DES_bs_vector) * 8 * 6) = key[6];
	*(dst + sizeof(DES_bs_vector) * 8 * 7) = key[7];
	return;
fill8:
	dst[0] = 0;
	dst[sizeof(DES_bs_vector) * 8] = 0;
fill6:
	dst[sizeof(DES_bs_vector) * 8 * 2] = 0;
fill5:
	dst[sizeof(DES_bs_vector) * 8 * 3] = 0;
fill4:
	dst[sizeof(DES_bs_vector) * 8 * 4] = 0;
fill3:
	dst[sizeof(DES_bs_vector) * 8 * 5] = 0;
fill2:
	dst[sizeof(DES_bs_vector) * 8 * 6] = 0;
	dst[sizeof(DES_bs_vector) * 8 * 7] = 0;
	*/
}

char *opencl_DES_bs_get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int section, block;
	unsigned char *src;
	char *dst;

	if (hash_ids == NULL || hash_ids[0] == 0 ||
	    index >= hash_ids[0] || hash_ids[0] > num_uncracked_hashes(current_salt)) {
		section = 0;
		block = 0;
	}
	else {
		section = hash_ids[2 * index + 1] / 32;
		block  = hash_ids[2 * index + 1] & 31;

	}

	if (section > global_work_size) {
		//fprintf(stderr, "Get key error! %d "Zu"\n", section, global_work_size);
		section = 0;
	}

	src = des_all[section].pxkeys[block];
	dst = out;
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {
		src += sizeof(DES_bs_vector) * 8;
		dst++;
	}
	*dst = 0;

	return out;
}

static void set_key_mm(char *key, int index)
{
	unsigned int len = strlen(key);
	unsigned int i;
	unsigned long c;

	for (i = 0; i < len; i++) {
		c = (unsigned char) key[i];
		memset(des_raw_keys[index].xkeys.v[i], c, 8 * sizeof(DES_bs_vector));
	}

	for (i = len; i < PLAINTEXT_LENGTH; i++)
		memset(des_raw_keys[index].xkeys.v[i], 0, 8 * sizeof(DES_bs_vector));

	if (!mask_gpu_is_static) {
		des_int_key_loc[index] = 0;
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
			if (mask_skip_ranges[i] != -1)  {
				des_int_key_loc[index] |= ((mask_int_cand.
				int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset +
				mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos) & 0xff) << (i << 3);
			}
			else
				des_int_key_loc[index] |= 0x80 << (i << 3);
		}
	}

	new_keys = 1;
}

/* des_bs_key arrangement.
	iter 0			iter 1			iter n-1
0	w0 w1 w2.. w(gws-1)	w0 w1 w2.. w(gws-1) 	w0 w1 w2.. w(gws-1)
1	w0 w1 w2.. w(gws-1)	w0 w1 w2.. w(gws-1) 	w0 w1 w2.. w(gws-1)
2	w0 w1 w2.. w(gws-1)	w0 w1 w2.. w(gws-1) 	w0 w1 w2.. w(gws-1)
.
.
.
55 	w0 w1 w2.. w(gws-1)	w0 w1 w2.. w(gws-1) 	w0 w1 w2.. w(gws-1) */
static char *get_key_mm(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int section, depth, iter;
	unsigned char *src, i;
	char *dst;

	if (hash_ids == NULL || hash_ids[0] == 0 ||
	    index >= hash_ids[0] || hash_ids[0] > num_uncracked_hashes(current_salt)) {
		section = 0;
		depth = 0;
		iter = 0;
	}
	else {
		section = (hash_ids[2 * index + 1] >> DES_LOG_DEPTH) % process_key_gws;
		depth  = hash_ids[2 * index + 1] & (DES_BS_DEPTH - 1);
		iter = (hash_ids[2 * index + 1] >> DES_LOG_DEPTH) / process_key_gws;
	}

	if (section > process_key_gws) {
		fprintf(stderr, "Get key error! %u "Zu"\n", section,
			process_key_gws);
		section = 0;
		depth = 0;
		iter = 0;
	}

	if (mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			if (mask_gpu_is_static)
				des_raw_keys[section].xkeys.c[static_gpu_locations[i]][depth & 7][depth >> 3] = mask_int_cand.int_cand[iter * 32 + depth].x[i];
			else
				des_raw_keys[section].xkeys.c[(des_int_key_loc[section] & (0xff << (i * 8))) >> (i * 8)][depth & 7][depth >> 3] = mask_int_cand.int_cand[iter * 32 + depth].x[i];
	}

	src = des_all[section].pxkeys[depth];
	dst = out;
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {
		src += sizeof(DES_bs_vector) * 8;
		dst++;
	}
	*dst = 0;

	return out;
}

void opencl_DES_bs_clear_keys()
{	/* Auto-tune might set hash_ids[0] to some value, which interferes with
	set-key/get-key checking during self test. */
	hash_ids[0] = 0;
}

size_t create_keys_kernel_set_args(int mask_mode)
{
	char build_opts[400];
	cl_ulong const_cache_size;
	int i;

	if (mask_mode) {
		fmt_opencl_DES.methods.set_key = set_key_mm;
		fmt_opencl_DES.methods.get_key = get_key_mm;
	}

	des_finalize_int_keys();

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof(cl_ulong), &const_cache_size, 0), "failed to get CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE.");

	sprintf(build_opts, "-D ITER_COUNT=%u -D MASK_ENABLED=%d -D LOC_0=%d"
#if MASK_FMT_INT_PLHDR > 1
		" -D LOC_1=%d "
#endif
#if MASK_FMT_INT_PLHDR > 2
		"-D LOC_2=%d "
#endif
#if MASK_FMT_INT_PLHDR > 3
		"-D LOC_3=%d"
#endif
		" -D IS_STATIC_GPU_MASK=%d -D CONST_CACHE_SIZE=%llu"
		, ((mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH), mask_mode, static_gpu_locations[0]
#if MASK_FMT_INT_PLHDR > 1
		, static_gpu_locations[1]
#endif
#if MASK_FMT_INT_PLHDR > 2
		, static_gpu_locations[2]
#endif
#if MASK_FMT_INT_PLHDR > 3
		, static_gpu_locations[3]
#endif
		, mask_gpu_is_static, (unsigned long long)const_cache_size);

	opencl_build_kernel("$JOHN/opencl/DES_bs_finalize_keys_kernel.cl",
	                    gpu_id, build_opts, 0);
	keys_kernel = clCreateKernel(program[gpu_id], "DES_bs_finalize_keys", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel DES_bs_finalize_keys.\n");

	HANDLE_CLERROR(clSetKernelArg(keys_kernel, 1, sizeof(cl_mem), &buffer_int_des_keys), "Failed setting kernel argument buffer_int_des_keys, kernel DES_bs_finalize_keys.\n");

	return get_kernel_max_lws(gpu_id, keys_kernel);
}

void process_keys(size_t current_gws, size_t *lws)
{
	process_key_gws = current_gws;

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_raw_keys, CL_TRUE, 0, current_gws * sizeof(opencl_DES_bs_transfer), des_raw_keys, 0, NULL, NULL ), "Failed to write buffer buffer_raw_keys.\n");

		if (!mask_gpu_is_static)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_TRUE, 0, current_gws * sizeof(unsigned int), des_int_key_loc, 0, NULL, NULL ), "Failed Copy data to gpu");

		ret_code = clEnqueueNDRangeKernel(queue[gpu_id], keys_kernel, 1, NULL, &current_gws, lws, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Enqueue kernel DES_bs_finalize_keys failed.\n");

		new_keys = 0;
	}
}

char *get_device_name(int id)
{
	char *d_name;

	d_name = (char *) mem_calloc(600, sizeof(char));
	HANDLE_CLERROR(clGetDeviceInfo(devices[id], CL_DEVICE_NAME, 600, d_name, NULL), "Failed to get device name.\n");
	return d_name;
}

void save_lws_config(const char* config_file, int id_gpu, size_t lws, unsigned int forced_global_key)
{
	FILE *file;
	char config_file_name[PATH_BUFFER_SIZE];
	char *d_name;

	sprintf(config_file_name, config_file, d_name = get_device_name(id_gpu));
	MEM_FREE(d_name);
	strnzcpy(config_file_name, path_expand(config_file_name),
	         sizeof(config_file_name));

	file = fopen(config_file_name, "r");
	if (file != NULL) {
		fclose(file);
		return;
	}
	if (!(file = fopen(config_file_name, "w")))
		pexit("%s", config_file_name);

	jtr_lock(fileno(file), F_SETLKW, F_WRLCK, config_file_name);

	fprintf(file, ""Zu" %u", lws, forced_global_key);
	fclose(file);
}

int restore_lws_config(const char *config_file, int id_gpu, size_t *lws, size_t extern_lws_limit, unsigned int *forced_global_key)
{
	FILE *file;
	char config_file_name[PATH_BUFFER_SIZE];
	char *d_name;
	unsigned int param;

	sprintf(config_file_name, config_file, d_name = get_device_name(id_gpu));
	MEM_FREE(d_name);
	strnzcpy(config_file_name, path_expand(config_file_name),
	         sizeof(config_file_name));

	file = fopen(config_file_name, "r");
	if (file == NULL)
		return 0;

	jtr_lock(fileno(file), F_SETLKW, F_RDLCK, config_file_name);

	if (fscanf(file, ""Zu" %u", lws, &param) != 2 || *lws > extern_lws_limit) {
		if (forced_global_key)
			*forced_global_key = param;
		fclose(file);
		return 0;
	}

	fclose(file);
	return 1;
}
#endif /* HAVE_OPENCL */
