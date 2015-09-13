/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#ifdef HAVE_OPENCL

#include <assert.h>
#include <string.h>
#include <sys/time.h>

#include "options.h"
#include "opencl_DES_bs.h"
#include "opencl_DES_hst_dev_shared.h"
#include "mask_ext.h"

#define PADDING 	2048

static cl_kernel **kernels;
static cl_mem buffer_map, buffer_bs_keys, buffer_unchecked_hashes;
static WORD *marked_salts = NULL, current_salt = 0;
static unsigned int *processed_salts = NULL;
static unsigned int save_binary = 1;
static int num_compiled_salt = 0;

static int mask_mode = 0;

#include "memdbg.h"

static int des_crypt_25(int *pcount, struct db_salt *salt);

static void create_clobj_kpc(size_t gws)
{
	unsigned int iter_count = (mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;

	create_keys_buffer(gws, PADDING);

	buffer_bs_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws * iter_count + PADDING) * sizeof(DES_bs_vector) * 56, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_bs_keys failed.\n");

	buffer_unchecked_hashes = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws * iter_count + PADDING) * sizeof(DES_bs_vector) * 64, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_unchecked_hashes failed.\n");
}

static void release_clobj_kpc()
{
	if (buffer_bs_keys != (cl_mem)0) {
		release_keys_buffer();
		HANDLE_CLERROR(clReleaseMemObject(buffer_bs_keys), "Release buffer_bs_keys failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_unchecked_hashes), "Release buffer_unchecked_hashes failed.\n");
		buffer_bs_keys = (cl_mem)0;
	}
}

static void create_clobj(struct db_main *db)
{
	int i;

	marked_salts = (WORD *) mem_alloc(4096 * sizeof(WORD));

	for (i = 0; i < 4096; i++)
		marked_salts[i] = 0x7fffffff;

	opencl_DES_bs_init_index();

	buffer_map = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 768 * sizeof(unsigned int), opencl_DES_bs_index768, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_map.\n");

	create_int_keys_buffer();
	build_tables(db);
}

static void release_clobj()
{
	int i;

	if (buffer_map) {
		MEM_FREE(marked_salts);
		HANDLE_CLERROR(clReleaseMemObject(buffer_map), "Release buffer_map failed.\n");
		release_tables();
		release_int_keys_buffer();
		buffer_map = 0;
	}

	for (i = 0; i < 4096; i++)
		if (kernels[gpu_id][i]) {
			HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][i]), "Release kernel(crypt(i)) failed.\n");
			kernels[gpu_id][i] = 0;
		}
}

static void clean_all_buffers()
{
	int i;

	release_clobj();
	release_clobj_kpc();

	for( i = 0; i < 4096; i++)
		if (kernels[gpu_id][i])
		HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][i]), "Error releasing kernel");

	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Error releasing Program");

	for (i = 0; i < MAX_GPU_DEVICES; i++)
		MEM_FREE(kernels[i]);

	MEM_FREE(kernels);
	MEM_FREE(processed_salts);

	finish_checking();
}

/* First call must use salt = 0, to initialize processed_salts. */
static void build_salt(WORD salt)
{
	WORD new;
	static WORD old = 0xffffff;
	int dst;

	new = salt;
	for (dst = 0; dst < 24; dst++) {
		if ((new ^ old) & 1) {
			DES_bs_vector sp1, sp2;
			int src1 = dst;
			int src2 = dst + 24;
			if (new & 1) {
				src1 = src2;
				src2 = dst;
			}
			sp1 = opencl_DES_E[src1];
			sp2 = opencl_DES_E[src2];
			processed_salts[4096 * 96 + dst] = sp1;
			processed_salts[4096 * 96 + dst + 24] = sp2;
			processed_salts[4096 * 96 + dst + 48] = sp1 + 32;
			processed_salts[4096 * 96 + dst + 72] = sp2 + 32;
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}
	old = salt;
	memcpy(&processed_salts[salt * 96], &processed_salts[4096 * 96], 96 * sizeof(unsigned int));
}

static void reset(struct db_main *db)
{
	static int initialized;

	if (initialized) {
		int i;

		release_clobj_kpc();
		release_clobj();

		fmt_opencl_DES.params.max_keys_per_crypt = global_work_size * DES_BS_DEPTH;
		fmt_opencl_DES.params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;

		if (options.flags & FLG_MASK_CHK) {
			mask_mode = 1;
			fmt_opencl_DES.params.max_keys_per_crypt = global_work_size;
			fmt_opencl_DES.params.min_keys_per_crypt = local_work_size;
		}

		create_clobj_kpc(global_work_size);
		create_clobj(db);

		create_checking_kernel_set_args(buffer_unchecked_hashes);
		create_keys_kernel_set_args(buffer_bs_keys, mask_mode);

		for (i = 0; i < global_work_size; i++)
		opencl_DES_bs_init(i);
	}
	else {
		int i;

		local_work_size = 64;
		global_work_size = 131072;

		fmt_opencl_DES.params.max_keys_per_crypt = global_work_size * DES_BS_DEPTH;
		fmt_opencl_DES.params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;

		if (options.flags & FLG_MASK_CHK) {
			mask_mode = 1;
			fmt_opencl_DES.params.max_keys_per_crypt = global_work_size;
			fmt_opencl_DES.params.min_keys_per_crypt = local_work_size;
		}

		create_clobj_kpc(global_work_size);
		create_clobj(NULL);

		create_checking_kernel_set_args(buffer_unchecked_hashes);
		create_keys_kernel_set_args(buffer_bs_keys, 0);

		for (i = 0; i < global_work_size; i++)
			opencl_DES_bs_init(i);

		for (i = 0; i < 4096; i++)
			build_salt(i);

		initialized++;
	}
}

static void init_global_variables()
{
	int i;

	processed_salts = (unsigned int *) mem_calloc(4097, 96 * sizeof(unsigned int));

	kernels = (cl_kernel **) mem_calloc(MAX_GPU_DEVICES, sizeof(cl_kernel *));

	for (i = 0; i < MAX_GPU_DEVICES; i++)
		kernels[i] = (cl_kernel *) mem_calloc(4096, sizeof(cl_kernel));

	init_checking();

	mask_int_cand_target = 1024;
}

static void modify_src()
{
	  int i = 53, j = 1, tmp;
	  static char digits[10] = {'0','1','2','3','4','5','6','7','8','9'};
	  static unsigned int  index[48]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,
					     24,25,26,27,28,29,30,31,32,33,34,35,
					     48,49,50,51,52,53,54,55,56,57,58,59,
					     72,73,74,75,76,77,78,79,80,81,82,83};
	  for (j = 1; j <= 48; j++) {
		tmp = processed_salts[current_salt * 96 + index[j - 1]] / 10;
		if (tmp == 0)
			kernel_source[i + j * 17] = ' ' ;
		else
			kernel_source[i + j * 17] = digits[tmp];
		tmp = processed_salts[current_salt * 96 + index[j - 1]] % 10;
	     ++i;
	     kernel_source[i + j * 17 ] = digits[tmp];
	     ++i;
	  }
}

static void set_salt(void *salt)
{
	current_salt = *(WORD *)salt;
}

static void modify_build_save_restore(WORD cur_salt, int id_gpu) {
	char kernel_bin_name[200];
	FILE *file;

	sprintf(kernel_bin_name, "$JOHN/kernels/DES_bs_kernel_h_%d_%d.bin", cur_salt, id_gpu);

	file = fopen(path_expand(kernel_bin_name), "r");

	if (file == NULL) {
		char *build_opt = "-fno-bin-amdil -fno-bin-source -fbin-exe";
		opencl_read_source("$JOHN/kernels/DES_bs_kernel_h.cl");
		modify_src();
		if (get_platform_vendor_id(get_platform_id(id_gpu)) != DEV_AMD)
			build_opt = NULL;
		opencl_build(id_gpu, build_opt, save_binary, kernel_bin_name);
		fprintf(stderr, "Salt compiled from Source:%d\n", ++num_compiled_salt);
	}
	else {
		fclose(file);
		opencl_read_source(kernel_bin_name);
		opencl_build_from_binary(id_gpu);
		fprintf(stderr, "Salt compiled from Binary:%d\n", ++num_compiled_salt);
	}
}

static int des_crypt_25(int *pcount, struct db_salt *salt)
{
	const int count = mask_mode ? *pcount : (*pcount + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t current_gws = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;
	size_t iter_count = (mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;

	if (marked_salts[current_salt] != current_salt) {
		modify_build_save_restore(current_salt, gpu_id);

		kernels[gpu_id][current_salt] = clCreateKernel(program[gpu_id], "DES_bs_25", &ret_code);
		HANDLE_CLERROR(ret_code, "Create Kernel DES_bs_25 failed.\n");

		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][current_salt], 0, sizeof(cl_mem), &buffer_map), "Failed setting kernel argument buffer_map, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][current_salt], 1, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][current_salt], 2, sizeof(cl_mem), &buffer_unchecked_hashes), "Failed setting kernel argument buffer_unchecked_hashes, kernel DES_bs_25.\n");

		marked_salts[current_salt] = current_salt;
	}

	process_keys(current_gws, lws);

	if (salt && num_uncracked_hashes(current_salt) != salt -> count &&
	/* In case there are duplicate hashes, num_uncracked_hashes is always less than salt->count, as
	 * num_uncracked_hashes tracks only unique hashes. */
		num_uncracked_hashes(current_salt) > salt -> count)
		update_buffer(salt);

	current_gws *= iter_count;
	ret_code = clEnqueueNDRangeKernel(queue[gpu_id], kernels[gpu_id][current_salt], 1, NULL, &current_gws, lws, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Enque kernel DES_bs_25 failed.\n");

	*pcount = mask_mode ? *pcount * mask_int_cand.num_int_cand : *pcount;

	return extract_info(current_gws, lws, current_salt);
}

void opencl_DES_bs_h_register_functions(struct fmt_main *fmt)
{
	fmt -> methods.done = &clean_all_buffers;
	fmt -> methods.reset = &reset;
	fmt -> methods.set_salt = &set_salt;
	fmt -> methods.crypt_all = &des_crypt_25;

	opencl_DES_bs_init_global_variables = &init_global_variables;
}
#endif /* HAVE_OPENCL */
