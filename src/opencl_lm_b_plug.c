/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>,
 * Copyright (c) 2015-2023 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#if HAVE_OPENCL

#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "opencl_lm.h"
#include "options.h"
#include "../run/opencl/opencl_lm_hst_dev_shared.h"
#include "bt_interface.h"
#include "mask_ext.h"
#include "logger.h"

#define PADDING 	2048

#define get_num_bits(r, v)			\
{						\
	r = (v & 0xAAAAAAAA) != 0;		\
	r |= ((v & 0xFFFF0000) != 0) << 4;	\
	r |= ((v & 0xFF00FF00) != 0) << 3;	\
	r |= ((v & 0xF0F0F0F0) != 0) << 2;	\
	r |= ((v & 0xCCCCCCCC) != 0) << 1;	\
}

static cl_mem buffer_lm_key_idx, buffer_raw_keys, buffer_lm_keys, buffer_int_lm_keys, buffer_int_key_loc, buffer_hash_ids, buffer_bitmap_dupe, buffer_offset_table, buffer_hash_table, buffer_bitmaps;
static unsigned int num_loaded_hashes, *hash_ids = NULL, *zero_buffer = NULL;
static size_t current_gws;
static unsigned int mask_mode;
static unsigned int static_gpu_locations[MASK_FMT_INT_PLHDR];

static unsigned int hash_table_size, offset_table_size;

static int lm_crypt(int *pcount, struct db_salt *salt);

typedef union {
	unsigned char c[8][sizeof(lm_vector)];
	lm_vector v[8];
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

#define FINALIZE_NEXT_KEY_BIT_7g { 			\
	kvtype m = mask80, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 7); 			\
	kvand_shr(vb, v1, m, 6); 			\
	kvand_shr_or(va, v2, m, 5); 			\
	kvand_shr_or(vb, v3, m, 4); 			\
	kvand_shr_or(va, v4, m, 3); 			\
	kvand_shr_or(vb, v5, m, 2); 			\
	kvand_shr_or(va, v6, m, 1); 			\
	kvand_or(vb, v7, m); 				\
	kvor(kp[0], va, vb); 				\
	kp += 1;					\
}


static void lm_finalize_int_keys()
{
	key_page *int_key_page[MASK_FMT_INT_PLHDR];
	unsigned int *final_key_pages[MASK_FMT_INT_PLHDR], i, j;

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		int_key_page[i] = (key_page *) mem_alloc(((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH) * sizeof(key_page));
		final_key_pages[i] = (unsigned int *) mem_alloc(8 * ((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH) * sizeof(unsigned int));
		memset(int_key_page[i], 0x7f, ((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH) * sizeof(key_page));
		memset(final_key_pages[i], 0xff, 8 * ((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH) * sizeof(unsigned int));
	}

	for (i = 0; i < mask_int_cand.num_int_cand && mask_int_cand.int_cand; i++) {
		j = i >> LM_LOG_DEPTH;
		int_key_page[0][j].c[(i & (LM_DEPTH - 1)) & 7][(i & (LM_DEPTH - 1)) >> 3] = opencl_lm_u[mask_int_cand.int_cand[i].x[0] & 0xFF];
#if MASK_FMT_INT_PLHDR > 1
		if (mask_skip_ranges[1] != -1)
			int_key_page[1][j].c[(i & (LM_DEPTH - 1)) & 7][(i & (LM_DEPTH - 1)) >> 3] = opencl_lm_u[mask_int_cand.int_cand[i].x[1] & 0xFF];
#endif
#if MASK_FMT_INT_PLHDR > 2
		if (mask_skip_ranges[2] != -1)
			int_key_page[2][j].c[(i & (LM_DEPTH - 1)) & 7][(i & (LM_DEPTH - 1)) >> 3] = opencl_lm_u[mask_int_cand.int_cand[i].x[2] & 0xFF];
#endif
#if MASK_FMT_INT_PLHDR > 3
		if (mask_skip_ranges[3] != -1)
			int_key_page[3][j].c[(i & (LM_DEPTH - 1)) & 7][(i & (LM_DEPTH - 1)) >> 3] = opencl_lm_u[mask_int_cand.int_cand[i].x[3] & 0xFF];
#endif
	}

	for (j = 0; j < MASK_FMT_INT_PLHDR; j++) {
		if (mask_skip_ranges == NULL || mask_skip_ranges[j] == -1)
			continue;
		for (i = 0; i < ((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH); i++) {
			lm_vector *kp = (lm_vector *)&final_key_pages[j][8 * i];
			lm_vector *vp = (lm_vector *)&int_key_page[j][i].v[0];
			LOAD_V
			FINALIZE_NEXT_KEY_BIT_0g
			FINALIZE_NEXT_KEY_BIT_1g
			FINALIZE_NEXT_KEY_BIT_2g
			FINALIZE_NEXT_KEY_BIT_3g
			FINALIZE_NEXT_KEY_BIT_4g
			FINALIZE_NEXT_KEY_BIT_5g
			FINALIZE_NEXT_KEY_BIT_6g
			FINALIZE_NEXT_KEY_BIT_7g
		}

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_lm_keys, CL_TRUE, j * 8 * ((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH) * sizeof(unsigned int),
				8 * ((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH) * sizeof(unsigned int), final_key_pages[j], 0, NULL, NULL ), "Failed Copy data to gpu");
	}

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		MEM_FREE(int_key_page[i]);
		MEM_FREE(final_key_pages[i]);
	}
}

static void release_buffer_gws();

static void create_buffer_gws(size_t gws)
{
	unsigned int i;

	release_buffer_gws();

	opencl_lm_all = (opencl_lm_combined*) mem_alloc ((gws + PADDING)* sizeof(opencl_lm_combined));
	opencl_lm_keys = (opencl_lm_transfer*) mem_alloc ((gws + PADDING)* sizeof(opencl_lm_transfer));
	opencl_lm_int_key_loc = (unsigned int*) mem_calloc((gws + PADDING), sizeof(unsigned int));

	memset(opencl_lm_keys, 0x6f, (gws + PADDING)* sizeof(opencl_lm_transfer));

	buffer_raw_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, (gws + PADDING) * sizeof(opencl_lm_transfer), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_raw_keys.");

	buffer_lm_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws + PADDING) * sizeof(lm_vector) * 56, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_keys.");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws + PADDING) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_keys.");

	for (i = 0; i < (gws + PADDING); i++)
		opencl_lm_init(i);
}

static void set_kernel_args_gws()
{
	size_t static_param_size = 101;
	char *kernel_name = (char *) mem_calloc(static_param_size, sizeof(char));
	cl_uint num_args;

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), &buffer_raw_keys), "Failed setting kernel argument buffer_raw_keys, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), &buffer_int_key_loc), "Failed setting kernel argument buffer_int_key_loc, kernel 0.");

	HANDLE_CLERROR(clGetKernelInfo(crypt_kernel, CL_KERNEL_FUNCTION_NAME, static_param_size - 1, kernel_name, NULL), "Failed to query kernel name.");
	HANDLE_CLERROR(clGetKernelInfo(crypt_kernel, CL_KERNEL_NUM_ARGS, sizeof(cl_uint), &num_args, NULL), "Failed to query kernel num args.");

	if (!strncmp(kernel_name, "lm_bs_b", 7) && num_args == 10)
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), &buffer_lm_keys), "Failed setting kernel argument buffer_lm_keys, kernel lm_bs_b.");

	if (!strncmp(kernel_name, "lm_bs_f", 7) && num_args == 9)
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), &buffer_lm_keys), "Failed setting kernel argument buffer_lm_keys, kernel lm_bs_f.");

	MEM_FREE(kernel_name);
}

static void release_buffer_gws()
{
	if (opencl_lm_all) {
		MEM_FREE(opencl_lm_all);
		MEM_FREE(opencl_lm_keys);
		MEM_FREE(opencl_lm_int_key_loc);
		HANDLE_CLERROR(clReleaseMemObject(buffer_raw_keys), "Error releasing buffer_raw_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_lm_keys), "Error releasing buffer_lm_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_key_loc), "Error releasing buffer_int_key_loc.");
	}
}

static void release_buffer();

static void create_buffer(unsigned int num_loaded_hashes, OFFSET_TABLE_WORD *offset_table, unsigned int ot_size, unsigned int ht_size, unsigned int *bitmaps, unsigned int bmp_size_bits)
{
	unsigned int active_placeholders, i;

	release_buffer();

	hash_ids     = (unsigned int *) mem_calloc (3 * num_loaded_hashes + 1, sizeof(unsigned int));
	zero_buffer = (unsigned int *) mem_calloc (((ht_size - 1) / 32 + 1), sizeof(unsigned int));

	opencl_lm_init_index();

	active_placeholders = 0;
	if (mask_skip_ranges) {
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
			if (mask_skip_ranges[i] != -1)
				active_placeholders++;
		}
	} else {
		active_placeholders = 1;
	}

	buffer_lm_key_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 768 * sizeof(unsigned int), opencl_lm_index768, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_key_idx.");

	buffer_int_lm_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, active_placeholders * 8 * ((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_int_lm_keys.");

	buffer_offset_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ot_size * sizeof(OFFSET_TABLE_WORD), offset_table, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_offset_table.");

	buffer_hash_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, ht_size * sizeof(unsigned int) * 2, bt_hash_table_64, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_hash_table.");

	buffer_bitmaps = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, bmp_size_bits >> 3, bitmaps, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmaps.");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (3 * num_loaded_hashes + 1) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_hash_ids.");

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((ht_size - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_bitmap_dupe.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");

	lm_finalize_int_keys();
}

static void set_kernel_args()
{
	size_t static_param_size = 101;
	unsigned int ctr = 2;
	char *kernel_name = (char *) mem_calloc(static_param_size, sizeof(char));
	cl_uint num_args;

	HANDLE_CLERROR(clGetKernelInfo(crypt_kernel, CL_KERNEL_FUNCTION_NAME, static_param_size - 1, kernel_name, NULL), "Failed to query kernel name.");
	HANDLE_CLERROR(clGetKernelInfo(crypt_kernel, CL_KERNEL_NUM_ARGS, sizeof(cl_uint), &num_args, NULL), "Failed to query kernel num args.");

	if (!strncmp(kernel_name, "lm_bs_b", 7)) {
		if (num_args == 10)
			ctr++;
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, ctr++, sizeof(cl_mem), &buffer_lm_key_idx), "Failed setting kernel argument buffer_lm_key_idx, kernel 0.");
	}
	if (!strncmp(kernel_name, "lm_bs_f", 7) && num_args == 9)
		ctr++;

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, ctr++, sizeof(cl_mem), &buffer_int_lm_keys), "Failed setting kernel argument buffer_int_lm_keys, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, ctr++, sizeof(cl_mem), &buffer_offset_table), "Failed setting kernel argument buffer_offset_table, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, ctr++, sizeof(cl_mem), &buffer_hash_table), "Failed setting kernel argument buffer_hash_table, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, ctr++, sizeof(cl_mem), &buffer_bitmaps), "Failed setting kernel argument buffer_bitmaps, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, ctr++, sizeof(cl_mem), &buffer_hash_ids), "Failed setting kernel argument buffer_hash_ids, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, ctr++, sizeof(cl_mem), &buffer_bitmap_dupe), "Failed setting kernel argument buffer_bitmap_dupe, kernel 0.");

	MEM_FREE(kernel_name);
}

static void release_buffer()
{
	if (buffer_bitmap_dupe) {
		MEM_FREE(hash_ids);
		MEM_FREE(zero_buffer);
		HANDLE_CLERROR(clReleaseMemObject(buffer_lm_key_idx), "Error releasing buffer_lm_key_idx");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Error releasing buffer_hash_ids.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_offset_table), "Error releasing buffer_offset_table.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_table), "Error releasing buffer_hash_table.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmaps), "Error releasing buffer_bitmaps.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error releasing buffer_bitmap_dupe.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_lm_keys), "Error releasing buffer_int_lm_keys.");
		buffer_bitmap_dupe = NULL;
	}
}

static void release_kernels();

static void init_kernels(char *bitmap_params, unsigned int full_unroll, size_t s_mem_lws, unsigned int use_local_mem, unsigned int use_last_build_opt)
{
	static unsigned int warned, last_build_opts[3];
	char build_opts[500];
	cl_ulong const_cache_size;
	unsigned int i;

	release_kernels();

	char *kernel, *lm_kernel, *force_kernel = getenv("JOHN_DES_KERNEL");

	if (force_kernel && !strcmp(force_kernel, "bs_f")) {
		if (!warned++) fprintf(stderr, "Using fully unrolled kernel (lm_bs_f)\n");
		full_unroll = 1;
		lm_kernel = "lm_bs_f";
		kernel = "$JOHN/opencl/lm_kernel_f.cl";
	} else if (force_kernel && !strcmp(force_kernel, "bs_b")) {
		if (!warned++) fprintf(stderr, "Using basic kernel (lm_bs_b)\n");
		full_unroll = 0;
		lm_kernel = "lm_bs_b";
		kernel = "$JOHN/opencl/lm_kernel_b.cl";
	} else
	if (use_last_build_opt ? last_build_opts[0] : full_unroll) {
		if (!warned++) log_event("- Using fully unrolled kernel (lm_bs_f)");
		lm_kernel = "lm_bs_f";
		kernel = "$JOHN/opencl/lm_kernel_f.cl";
	} else {
		if (!warned++) log_event("- Using basic kernel (lm_bs_b)");
		lm_kernel = "lm_bs_b";
		kernel = "$JOHN/opencl/lm_kernel_b.cl";
	}

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof(cl_ulong), &const_cache_size, 0), "failed to get CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE.");

	if (!use_last_build_opt) {
		sprintf(build_opts, "-D FULL_UNROLL=%u -D USE_LOCAL_MEM=%u -D WORK_GROUP_SIZE="Zu""
		" -D OFFSET_TABLE_SIZE=%u -D HASH_TABLE_SIZE=%u -D MASK_ENABLE=%u -D ITER_COUNT=%u -D LOC_0=%d"
#if MASK_FMT_INT_PLHDR > 1
		" -D LOC_1=%d "
#endif
#if MASK_FMT_INT_PLHDR > 2
		"-D LOC_2=%d "
#endif
#if MASK_FMT_INT_PLHDR > 3
		"-D LOC_3=%d"
#endif
		" -D IS_STATIC_GPU_MASK=%d -D CONST_CACHE_SIZE=%llu %s" ,
		full_unroll, use_local_mem, s_mem_lws, offset_table_size,  hash_table_size, mask_mode,
		((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH), static_gpu_locations[0]
#if MASK_FMT_INT_PLHDR > 1
		, static_gpu_locations[1]
#endif
#if MASK_FMT_INT_PLHDR > 2
		, static_gpu_locations[2]
#endif
#if MASK_FMT_INT_PLHDR > 3
		, static_gpu_locations[3]
#endif
		, mask_gpu_is_static, (unsigned long long)const_cache_size, bitmap_params);

		last_build_opts[0] = full_unroll;
		last_build_opts[1] = use_local_mem;
		last_build_opts[2] = s_mem_lws;
	}
	else {
		sprintf(build_opts, "-cl-kernel-arg-info -D FULL_UNROLL=%u -D USE_LOCAL_MEM=%u -D WORK_GROUP_SIZE="Zu""
		" -D OFFSET_TABLE_SIZE=%u -D HASH_TABLE_SIZE=%u -D MASK_ENABLE=%u -D ITER_COUNT=%u -D LOC_0=%d"
#if MASK_FMT_INT_PLHDR > 1
		" -D LOC_1=%d "
#endif
#if MASK_FMT_INT_PLHDR > 2
		"-D LOC_2=%d "
#endif
#if MASK_FMT_INT_PLHDR > 3
		"-D LOC_3=%d"
#endif
		" -D IS_STATIC_GPU_MASK=%d -D CONST_CACHE_SIZE=%llu %s" ,
		last_build_opts[0], last_build_opts[1], (size_t)last_build_opts[2], offset_table_size,  hash_table_size, mask_mode,
		((mask_int_cand.num_int_cand + LM_DEPTH - 1) >> LM_LOG_DEPTH), static_gpu_locations[0]
#if MASK_FMT_INT_PLHDR > 1
		, static_gpu_locations[1]
#endif
#if MASK_FMT_INT_PLHDR > 2
		, static_gpu_locations[2]
#endif
#if MASK_FMT_INT_PLHDR > 3
		, static_gpu_locations[3]
#endif
		, mask_gpu_is_static, (unsigned long long)const_cache_size, bitmap_params);
	}

	opencl_build_kernel(kernel, gpu_id, build_opts, 0);

	crypt_kernel = clCreateKernel(program[gpu_id], lm_kernel, &ret_code);
	HANDLE_CLERROR(ret_code, "Error building crypt kernel");
}

static void release_kernels()
{
	if (crypt_kernel) {
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Error releasing kernel 0");
		crypt_kernel = NULL;

		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
		program[gpu_id] = NULL;
	}
}

static void clean_all_buffers()
{
	release_buffer_gws();
	release_buffer();
	release_kernels();
	MEM_FREE(bt_hash_table_64);
	if (program[gpu_id]) {
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
			"Error releasing Program");
		program[gpu_id] = 0;
	}
}

/* if returns 0x800000, means there is no restriction on lws due to local memory limitations.*/
/* if returns 0, means local memory shouldn't be allocated.*/
static size_t find_smem_lws_limit(unsigned int full_unroll, unsigned int use_local_mem, unsigned int force_global_keys)
{
	cl_ulong s_mem_sz = get_local_memory_size(gpu_id);
	size_t expected_lws_limit;
	cl_uint warp_size;

	if (force_global_keys) {
		if (s_mem_sz > 768 * sizeof(cl_short) || full_unroll)
			return 0x800000;
		else
			return 0;
	}

	if (!s_mem_sz)
		return 0;

	if (gpu_amd(device_info[gpu_id])) {
		if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WAVEFRONT_WIDTH_AMD,
		                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
			warp_size = 64;
	}
	else if (gpu_nvidia(device_info[gpu_id])) {
		if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WARP_SIZE_NV,
		                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
			warp_size = 32;
	}
	else
		return 0;

	if (full_unroll || !use_local_mem) {
		expected_lws_limit = s_mem_sz /
				(sizeof(lm_vector) * 56);
		if (!expected_lws_limit)
			return 0;
		expected_lws_limit = GET_MULTIPLE_OR_ZERO(
				expected_lws_limit, warp_size);
	}
	else {
		if (s_mem_sz > 768 * sizeof(cl_short)) {
			s_mem_sz -= 768 * sizeof(cl_short);
			expected_lws_limit = s_mem_sz /
					(sizeof(lm_vector) * 56);
			if (!expected_lws_limit)
				return 0x800000;
			expected_lws_limit = GET_MULTIPLE_OR_ZERO(
				expected_lws_limit, warp_size);
		}
		else
			return 0;
	}

	if (warp_size == 1 && expected_lws_limit & (expected_lws_limit - 1)) {
		get_power_of_two(expected_lws_limit);
		expected_lws_limit >>= 1;
	}
	return expected_lws_limit;
}

#define calc_ms(start, end)	\
		((long double)(end.tv_sec - start.tv_sec) * 1000.000 + \
			(long double)(end.tv_usec - start.tv_usec) / 1000.000)

/* Sets global_work_size and max_keys_per_crypt. */
static void gws_tune(size_t gws_init, long double kernel_run_ms, int gws_tune_flag, struct fmt_main *format, int mask_mode)
{
	unsigned int i;
	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	struct timeval startc, endc;
	long double time_ms = 0;
	int pcount;
	unsigned int lm_log_depth = mask_mode ? 0 : LM_LOG_DEPTH;

	size_t gws_limit = get_max_mem_alloc_size(gpu_id) / sizeof(opencl_lm_transfer);
	if (gws_limit > PADDING)
		gws_limit -= PADDING;

	if (gws_limit & (gws_limit - 1)) {
		get_power_of_two(gws_limit);
		gws_limit >>= 1;
	}

#if SIZEOF_SIZE_T > 4
	/* We can't process more than 4G keys per crypt() */
	while (gws_limit * mask_int_cand.num_int_cand > 0xffffffffUL)
		gws_limit >>= 1;
#endif

	if (gws_tune_flag)
		global_work_size = gws_init;

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	if (gws_tune_flag) {
		release_buffer_gws();
		create_buffer_gws(global_work_size);
		set_kernel_args_gws();

		format->methods.clear_keys();
		for (i = 0; i < (global_work_size << lm_log_depth); i++) {
			key[i & 3] = i & 255;
			key[(i & 3) + 3] = i ^ 0x3E;
			format->methods.set_key(key, i);
		}

		gettimeofday(&startc, NULL);
		pcount = (int)(global_work_size << lm_log_depth);
		lm_crypt((int *)&pcount, NULL);
		gettimeofday(&endc, NULL);

		time_ms = calc_ms(startc, endc);
		global_work_size = (size_t)((kernel_run_ms / time_ms) * (long double)global_work_size);
	}

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	get_power_of_two(global_work_size);

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	release_buffer_gws();
	create_buffer_gws(global_work_size);
	set_kernel_args_gws();

	/* for hash_ids[3*x + 1], 27 bits for storing gid and 5 bits for bs depth. */
	//assert(global_work_size <= ((1U << 28) - 1));
	fmt_opencl_lm.params.max_keys_per_crypt = global_work_size << lm_log_depth;

	fmt_opencl_lm.params.min_keys_per_crypt =
		opencl_calc_min_kpc(local_work_size, global_work_size,
		                    1 << lm_log_depth);
}

static void auto_tune_all(char *bitmap_params, unsigned int num_loaded_hashes, long double kernel_run_ms, struct fmt_main *format, int mask_mode)
{
	unsigned int full_unroll = 0;
	unsigned int use_local_mem = 1;
	unsigned int force_global_keys = 1;
	unsigned int gws_tune_flag = 1;
	unsigned int lws_tune_flag = 1;

	size_t s_mem_limited_lws;

	struct timeval startc, endc;
	long double time_ms = 0;

	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	unsigned int lm_log_depth = mask_mode ? 0 : LM_LOG_DEPTH;

	if (cpu(device_info[gpu_id])) {
		force_global_keys = 1;
		use_local_mem = 0;
		full_unroll = 1;
		kernel_run_ms = 5;
	}
	else if (amd_vliw4(device_info[gpu_id]) || amd_vliw5(device_info[gpu_id]) || gpu_intel(device_info[gpu_id])) {
		force_global_keys = 0;
		use_local_mem = 1;
		full_unroll = 0;
	}
	else if (platform_apple(platform_id) && gpu_nvidia(device_info[gpu_id])) {
		force_global_keys = 1;
		use_local_mem = 0;
		full_unroll = 1;
	}
	else if (platform_apple(platform_id) && gpu_amd(device_info[gpu_id])) {
		force_global_keys = 1;
		use_local_mem = 1;
		full_unroll = 1;
	}
	else if (gpu(device_info[gpu_id])) {
		force_global_keys = 0;
		use_local_mem = 1;
		full_unroll = 1;
	}
	else {
		force_global_keys = 1;
		use_local_mem = 0;
		full_unroll = 0;
		kernel_run_ms = 40;
	}

	if (self_test_running) {
		opencl_get_sane_lws_gws_values();
	} else {
		local_work_size = 0;
		global_work_size = 0;
		opencl_get_user_preferences(FORMAT_LABEL);
	}
	if (global_work_size)
		gws_tune_flag = 0;
	if (local_work_size) {
		lws_tune_flag = 0;
		if (local_work_size & (local_work_size - 1)) {
			get_power_of_two(local_work_size);
		}
	}

	s_mem_limited_lws = find_smem_lws_limit(
			full_unroll, use_local_mem, force_global_keys);
#if 0
	fprintf(stdout, "%s() Limit_smem:"Zu", Full_unroll_flag:%u,"
		"Use_local_mem:%u, Force_global_keys:%u\n",
	        __FUNCTION__,
	        s_mem_limited_lws, full_unroll, use_local_mem,
	        force_global_keys);
#endif

	if (s_mem_limited_lws == 0x800000 || !s_mem_limited_lws) {
		long double best_time_ms;
		size_t best_lws, lws_limit;

		release_kernels();
		init_kernels(bitmap_params, full_unroll, 0, use_local_mem && s_mem_limited_lws, 0);
		set_kernel_args();

		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag, format, mask_mode);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, mask_mode);

		lws_limit = get_kernel_max_lws(gpu_id, crypt_kernel);

		if (lws_limit > global_work_size)
			lws_limit = global_work_size;

		if (lws_tune_flag) {
			if (gpu(device_info[gpu_id]) && lws_limit >= 32)
				local_work_size = 32;
			else
				local_work_size = get_kernel_preferred_multiple(gpu_id, crypt_kernel);
		}
		if (local_work_size > lws_limit)
			local_work_size = lws_limit;

		if (lws_tune_flag) {
			time_ms = 0;
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= lws_limit &&
				local_work_size <= PADDING) {
				int pcount, i;
				format->methods.clear_keys();
				for (i = 0; i < (global_work_size << lm_log_depth); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3F;
					format->methods.set_key(key, i);
				}
				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << lm_log_depth);
				lm_crypt((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);

				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: "Zu", LWS: "Zu", Limit_smem:"Zu", Limit_kernel:"Zu","
		"Current time:%Lf, Best time:%Lf\n",
		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, crypt_kernel), time_ms,
		best_time_ms);
#endif
				local_work_size *= 2;
			}
			local_work_size = best_lws;
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, mask_mode);
		}
	}

	else {
		long double best_time_ms;
		size_t best_lws;
		cl_uint warp_size;

		if (gpu_amd(device_info[gpu_id])) {
			if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WAVEFRONT_WIDTH_AMD,
			                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
				warp_size = 64;
		}
		else if (gpu_nvidia(device_info[gpu_id])) {
			if (clGetDeviceInfo(devices[gpu_id], CL_DEVICE_WARP_SIZE_NV,
			                    sizeof(cl_uint), &warp_size, 0) != CL_SUCCESS)
				warp_size = 32;
		}
		else {
			warp_size = 1;
			//fprintf(stderr, "Possible auto_tune fail!!.\n");
		}
		if (lws_tune_flag)
			local_work_size = warp_size;
		if (local_work_size > s_mem_limited_lws)
			local_work_size = s_mem_limited_lws;

		release_kernels();
		init_kernels(bitmap_params, full_unroll, local_work_size, use_local_mem, 0);

		if (local_work_size > get_kernel_max_lws(gpu_id, crypt_kernel)) {
			local_work_size = get_kernel_max_lws(gpu_id, crypt_kernel);
			release_kernels();
			init_kernels(bitmap_params, full_unroll, local_work_size, use_local_mem, 0);
		}

		set_kernel_args();
		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag, format, mask_mode);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, mask_mode);

		if (global_work_size < s_mem_limited_lws) {
			s_mem_limited_lws = global_work_size;
			if (local_work_size > s_mem_limited_lws)
				local_work_size = s_mem_limited_lws;
		}

		if (lws_tune_flag) {
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= s_mem_limited_lws &&
				local_work_size <= PADDING) {
				int pcount, i;

				release_kernels();
				init_kernels(bitmap_params, full_unroll, local_work_size, use_local_mem, 0);
				set_kernel_args();
				set_kernel_args_gws();

				format->methods.clear_keys();
				for (i = 0; i < (global_work_size << lm_log_depth); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3E;
					format->methods.set_key(key, i);
				}

				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << lm_log_depth);
				lm_crypt((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);
				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms &&
				  local_work_size <= get_kernel_max_lws(
				    gpu_id, crypt_kernel)) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: "Zu", LWS: "Zu", Limit_smem:"Zu", Limit_kernel:"Zu","
		"Current time:%Lf, Best time:%Lf\n",
		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, crypt_kernel), time_ms,
		best_time_ms);
#endif
				if (gpu(device_info[gpu_id])) {
					if (local_work_size < 16)
						local_work_size = 16;
					else if (local_work_size < 32)
						local_work_size = 32;
					else if (local_work_size < 64)
						local_work_size = 64;
					else if (local_work_size < 96)
						local_work_size = 96;
					else if (local_work_size < 128)
						local_work_size = 128;
					else
						local_work_size += warp_size;
				}
				else
					local_work_size *= 2;
			}
			local_work_size = best_lws;
			release_kernels();
			init_kernels(bitmap_params, full_unroll, local_work_size, use_local_mem, 0);
			set_kernel_args();
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag, format, mask_mode);
		}
	}

	if ((!self_test_running && options.verbosity >= VERB_DEFAULT) || ocl_always_show_ws) {
		if (mask_int_cand.num_int_cand > 1)
			fprintf(stderr, "LWS="Zu" GWS="Zu" x%d%s", local_work_size,
			        global_work_size, mask_int_cand.num_int_cand, (options.flags & FLG_TEST_CHK) ? " " : "\n");
		else
			fprintf(stderr, "LWS="Zu" GWS="Zu"%s", local_work_size,
			        global_work_size, (options.flags & FLG_TEST_CHK) ? " " : "\n");
	}
}

static void prepare_bitmap_2(cl_ulong bmp_sz_bits, cl_uint **bitmaps_ptr, int *loaded_hashes)
{
	unsigned int i;
	MEM_FREE(*bitmaps_ptr);
	*bitmaps_ptr = (cl_uint*) mem_calloc((bmp_sz_bits >> 4), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[2 * i + 1] & (bmp_sz_bits - 1);
		(*bitmaps_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[2 * i] & (bmp_sz_bits - 1);
		(*bitmaps_ptr)[(bmp_sz_bits >> 5) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));
	}
}

static void prepare_bitmap_1(cl_ulong bmp_sz_bits, cl_uint **bitmaps_ptr, int *loaded_hashes)
{
	unsigned int i;
	MEM_FREE(*bitmaps_ptr);
	*bitmaps_ptr = (cl_uint*) mem_calloc((bmp_sz_bits >> 5), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[2 * i + 1] & (bmp_sz_bits - 1);
		(*bitmaps_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));
	}
}

static char* select_bitmap(unsigned int num_ld_hashes, int *loaded_hashes, unsigned int *bitmap_size_bits, unsigned int **bitmaps_ptr)
{
	static char kernel_params[200];
	unsigned int cmp_steps = 2, bits_req = 32;

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

	else if (num_ld_hashes <= 1500100) {
		*bitmap_size_bits = 4096 * 1024 * 2;
		cmp_steps = 1;
	}

	else if (num_ld_hashes <= 2700100) {
		*bitmap_size_bits = 4096 * 1024 * 2 * 2;
		cmp_steps = 1;
	}

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
		cmp_steps = 1;
	}

	if (cmp_steps == 1)
		prepare_bitmap_1(*bitmap_size_bits, bitmaps_ptr, loaded_hashes);

	else
		prepare_bitmap_2(*bitmap_size_bits, bitmaps_ptr, loaded_hashes);

	get_num_bits(bits_req, (*bitmap_size_bits));

	sprintf(kernel_params,
	        "-D SELECT_CMP_STEPS=%u -D BITMAP_MASK=0x%xU -D REQ_BITMAP_BITS=%u",
	        cmp_steps, (uint32_t)((*bitmap_size_bits) - 1), bits_req);

	*bitmap_size_bits *= cmp_steps;

	return kernel_params;
}

static char* prepare_table(struct db_salt *salt, OFFSET_TABLE_WORD **offset_table_ptr, unsigned int *bitmap_size_bits, unsigned **bitmaps_ptr)
{
	int *bin, i;
	struct db_password *pw, *last;
	char *bitmap_params;
	int *loaded_hashes;

	num_loaded_hashes = salt->count;
	loaded_hashes = (int *)mem_alloc(num_loaded_hashes * sizeof(int) * 2);

	last = pw = salt->list;
	i = 0;
	do {
		bin = (int *)pw->binary;
		if (bin == NULL) {
			if (last == pw)
				salt->list = pw->next;
			else
				last->next = pw->next;
		} else {
			last = pw;
			loaded_hashes[2 * i] = bin[0];
			loaded_hashes[2 * i + 1] = bin[1];
			i++;
		}
	} while ((pw = pw->next)) ;

	if (i > (salt->count)) {
		fprintf(stderr,
			"Something went wrong while preparing hashes(%d, %d)..Exiting..\n", i, salt->count);
		error();
	}

	num_loaded_hashes = bt_create_perfect_hash_table(64, (void *)loaded_hashes,
				num_loaded_hashes,
			        offset_table_ptr,
			        &offset_table_size,
			        &hash_table_size, 0);

	if (!num_loaded_hashes) {
		MEM_FREE(bt_hash_table_64);
		MEM_FREE((*offset_table_ptr));
		fprintf(stderr, "Failed to create Hash Table for cracking.\n");
		error();
	}

	bitmap_params = select_bitmap(num_loaded_hashes, loaded_hashes, bitmap_size_bits, bitmaps_ptr);
	MEM_FREE(loaded_hashes);

	return bitmap_params;
}

static char *get_key(int index)
{
      get_key_body();
}

static char *get_key_mm(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int section, depth, iter;
	unsigned char *src, i;
	char *dst;

	if (hash_ids == NULL || hash_ids[0] == 0 ||
	    index > hash_ids[0] || hash_ids[0] > num_loaded_hashes) {
		section = 0;
		depth = 0;
		iter = 0;
	}
	else {
		section = hash_ids[3 * index + 1] / 32;
		depth  = hash_ids[3 * index + 1] & 31;
		iter = hash_ids[3 * index + 2];
	}

	if (section > global_work_size ) {
		//fprintf(stderr, "Get key error! %u "Zu"\n", section, global_work_size);
		section = 0;
		depth = 0;
		iter = 0;
	}

	if (mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			if (mask_gpu_is_static)
				opencl_lm_keys[section].xkeys.c[static_gpu_locations[i]][depth & 7][depth >> 3] = opencl_lm_u[mask_int_cand.int_cand[iter * 32 + depth].x[i]];
			else
				opencl_lm_keys[section].xkeys.c[(opencl_lm_int_key_loc[section] & (0xff << (i * 8))) >> (i * 8)][depth & 7][depth >> 3] = opencl_lm_u[mask_int_cand.int_cand[iter * 32 + depth].x[i]];
	}

	src = opencl_lm_all[section].pxkeys[depth];
	dst = out;
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {
		src += sizeof(lm_vector) * 8;
		dst++;
	}
	*dst = 0;

	return out;
}

static void reset(struct db_main *db)
{
	if (!self_test_running) {
		struct db_salt *salt;
		unsigned int *bitmaps = NULL;
		OFFSET_TABLE_WORD *offset_table = NULL;
		char *bitmap_params;
		unsigned int bitmap_size_bits = 0;

		release_buffer();
		release_buffer_gws();
		release_kernels();
		MEM_FREE(bt_hash_table_64);

		salt = db->salts;
		bitmap_params = prepare_table(salt, &offset_table, &bitmap_size_bits, &bitmaps);
		release_buffer();
		create_buffer(num_loaded_hashes, offset_table, offset_table_size, hash_table_size, bitmaps, bitmap_size_bits);

		if ((options.flags & FLG_MASK_CHK) && mask_int_cand.num_int_cand > 1) {
			mask_mode = 1;
			fmt_opencl_lm.methods.set_key = opencl_lm_set_key_mm;
			fmt_opencl_lm.methods.get_key = get_key_mm;
		}

		auto_tune_all(bitmap_params, num_loaded_hashes, 100, &fmt_opencl_lm, mask_mode);
		MEM_FREE(offset_table);
		MEM_FREE(bitmaps);
	}
	else {
		int i, *binary;
		char *ciphertext, *bitmap_params;
		unsigned int *bitmaps = NULL;
		unsigned int bitmap_size_bits = 0;
		OFFSET_TABLE_WORD *offset_table = NULL;
		int *loaded_hashes;

		num_loaded_hashes = 0;
		while (fmt_opencl_lm.params.tests[num_loaded_hashes].ciphertext) num_loaded_hashes++;

		loaded_hashes = (int *) mem_alloc (num_loaded_hashes * sizeof(int) * 2);

		i = 0;
		while (fmt_opencl_lm.params.tests[i].ciphertext) {
			char **fields = fmt_opencl_lm.params.tests[i].fields;
			if (!fields[1])
				fields[1] = fmt_opencl_lm.params.tests[i].ciphertext;
			ciphertext = fmt_opencl_lm.methods.split(fmt_opencl_lm.methods.prepare(fields, &fmt_opencl_lm), 0, &fmt_opencl_lm);
			binary = (int *)fmt_opencl_lm.methods.binary(ciphertext);
			loaded_hashes[2 * i] = binary[0];
			loaded_hashes[2 * i + 1] = binary[1];
			i++;
			//fprintf(stderr, "C:%s B:%d %d %d\n", ciphertext, binary[0], binary[1], i == num_loaded_hashes );
		}

		num_loaded_hashes = bt_create_perfect_hash_table(64, (void *)loaded_hashes,
				num_loaded_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size, 0);

		if (!num_loaded_hashes) {
			MEM_FREE(bt_hash_table_64);
			MEM_FREE(offset_table);
			fprintf(stderr, "Failed to create Hash Table for self test.\n");
			error();
		}
		bitmap_params = select_bitmap(num_loaded_hashes, loaded_hashes, &bitmap_size_bits, &bitmaps);
		release_buffer();
		create_buffer(num_loaded_hashes, offset_table, offset_table_size, hash_table_size, bitmaps, bitmap_size_bits);
		auto_tune_all(bitmap_params, num_loaded_hashes, 100, &fmt_opencl_lm, 0);

		MEM_FREE(offset_table);
		MEM_FREE(bitmaps);
		MEM_FREE(loaded_hashes);
		hash_ids[0] = 0;
	}
}

static void init_global_variables()
{
	mask_int_cand_target = opencl_speed_index(gpu_id) / 300;
}

static int lm_crypt(int *pcount, struct db_salt *salt)
{
	const int count = mask_mode ?
		*pcount : (*pcount + LM_DEPTH - 1) >> LM_LOG_DEPTH;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	current_gws = GET_NEXT_MULTIPLE(count, local_work_size);

#if 0
	fprintf(stderr, "pcount %d count %d lws "Zu" gws "Zu" cur_gws "Zu" static: %d\n", *pcount, count, local_work_size, global_work_size, current_gws, mask_gpu_is_static);
#endif
	if (salt != NULL && salt->count > 4500 &&
		(num_loaded_hashes - num_loaded_hashes / 10) > salt->count) {
		char *bitmap_params;
		unsigned int *bitmaps = NULL;
		unsigned int bitmap_size_bits = 0;
		OFFSET_TABLE_WORD *offset_table = NULL;

		release_buffer();
		release_kernels();
		MEM_FREE(bt_hash_table_64);

		bitmap_params = prepare_table(salt, &offset_table, &bitmap_size_bits, &bitmaps);
		release_buffer();
		create_buffer(num_loaded_hashes, offset_table, offset_table_size, hash_table_size, bitmaps, bitmap_size_bits);

		init_kernels(bitmap_params, 0, 0, 0, 1);

		set_kernel_args();
		set_kernel_args_gws();

		MEM_FREE(offset_table);
		MEM_FREE(bitmaps);
	}

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_raw_keys, CL_FALSE, 0, current_gws * sizeof(opencl_lm_transfer), opencl_lm_keys, 0, NULL, NULL ), "Failed Copy data to gpu");

	if (!mask_gpu_is_static)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_FALSE, 0, current_gws * sizeof(unsigned int), opencl_lm_int_key_loc, 0, NULL, NULL ), "Failed Copy data to gpu");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &current_gws, lws, 0, NULL, NULL), "Failed enqueue kernel lm_bs_*.");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Kernel failed");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Read FAILED\n");

	if (hash_ids[0] > num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (3 * hash_ids[0] + 1) * sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Read FAILED\n");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_TRUE, 0, ((hash_table_size - 1)/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmap_dupe.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
	}

	*pcount *= mask_int_cand.num_int_cand;

	return hash_ids[0];
}

int opencl_lm_get_hash_0(int index)
{
	return bt_hash_table_64[hash_ids[3 + 3 * index]] & PH_MASK_0;
}

int opencl_lm_get_hash_1(int index)
{
	return bt_hash_table_64[hash_ids[3 + 3 * index]] & PH_MASK_1;
}

int opencl_lm_get_hash_2(int index)
{
	return bt_hash_table_64[hash_ids[3 + 3 * index]] & PH_MASK_2;
}

int opencl_lm_get_hash_3(int index)
{
	return bt_hash_table_64[hash_ids[3 + 3 * index]] & PH_MASK_3;
}

int opencl_lm_get_hash_4(int index)
{
	return bt_hash_table_64[hash_ids[3 + 3 * index]] & PH_MASK_4;
}

int opencl_lm_get_hash_5(int index)
{
	return bt_hash_table_64[hash_ids[3 + 3 * index]] & PH_MASK_5;
}

int opencl_lm_get_hash_6(int index)
{
	return bt_hash_table_64[hash_ids[3 + 3 * index]] & PH_MASK_6;
}

static int cmp_one(void *binary, int index)
{
	if (((int *)binary)[0] == bt_hash_table_64[hash_ids[3 + 3 * index]])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	int *binary = opencl_lm_get_binary(source + 4);

	if (binary[1] == bt_hash_table_64[hash_ids[3 + 3 * index] + hash_table_size])
		return 1;
	return 0;
}

void opencl_lm_b_register_functions(struct fmt_main *fmt)
{
	fmt->methods.done = &clean_all_buffers;
	fmt->methods.reset = &reset;
	fmt->methods.get_key = &get_key;
	fmt->methods.crypt_all = &lm_crypt;
	fmt->methods.cmp_exact = cmp_exact;
	fmt->methods.cmp_one = cmp_one;
	opencl_lm_init_global_variables = &init_global_variables;
}

#endif /* #if HAVE_OPENCL */
