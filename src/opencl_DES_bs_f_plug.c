/*
 * This software is Copyright (c) 2012-2015 Sayantan Datta <std2048 at gmail dot com>
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
static cl_mem buffer_bs_keys, buffer_unchecked_hashes;
static WORD *marked_salts = NULL, current_salt = 0;
static unsigned int *processed_salts = NULL;
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

	assert(gws * iter_count <= ((0x1 << 27) - 1));
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

	create_int_keys_buffer();
	build_tables(db);
}

static void release_clobj()
{
	int i;

	if (marked_salts) {
		MEM_FREE(marked_salts);
		release_tables();
		release_int_keys_buffer();
		marked_salts = 0;
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

static char* enc_salt(WORD salt_val)
{
	static unsigned int  index[48]  = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
				24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
				48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
				72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83};

	static char build_opts[10000];
	unsigned int i, j;

	for (i = 0, j = 0; i < 48; i++) {
		sprintf(build_opts + j, "-D index%u=%u ", index[i], processed_salts[salt_val * 96 + index[i]]);
		j = strlen(build_opts);
	}

	return build_opts;
}

static void set_salt(void *salt)
{
	current_salt = *(WORD *)salt;
}

static void modify_build_save_restore(WORD salt_val, int id_gpu, int save_binary, size_t lws) {
	char kernel_bin_name[200];
	FILE *file;

	sprintf(kernel_bin_name, "$JOHN/kernels/DES_bs_kernel_f_%d_%d.bin", salt_val, id_gpu);

	file = fopen(path_expand(kernel_bin_name), "r");

	if (file == NULL) {
		static char build_opts[10000];
		opencl_read_source("$JOHN/kernels/DES_bs_kernel_f.cl");
		if (get_platform_vendor_id(get_platform_id(id_gpu)) != DEV_AMD)
			sprintf(build_opts, "-D WORK_GROUP_SIZE=%zu %s", lws, enc_salt(salt_val));
		else
			sprintf(build_opts, "-D WORK_GROUP_SIZE=%zu -fno-bin-amdil -fno-bin-source -fbin-exe %s", lws, enc_salt(salt_val));

		opencl_build(id_gpu, build_opts, save_binary, kernel_bin_name);
		fprintf(stderr, "Salt compiled from Source:%d\n", ++num_compiled_salt);
	}
	else {
		fclose(file);
		opencl_read_source(kernel_bin_name);
		opencl_build_from_binary(id_gpu);
		fprintf(stderr, "Salt compiled from Binary:%d\n", ++num_compiled_salt);
	}
}

static void init_kernel(WORD salt_val, int id_gpu, int save_binary, size_t lws)
{
	if (marked_salts[salt_val] == salt_val) return;

	modify_build_save_restore(salt_val, id_gpu, save_binary, lws);

	kernels[id_gpu][salt_val] = clCreateKernel(program[id_gpu], "DES_bs_25", &ret_code);
	HANDLE_CLERROR(ret_code, "Create Kernel DES_bs_25 failed.\n");

	marked_salts[salt_val] = salt_val;
}

static void set_kernel_arg_kpc()
{
	int i;

	for (i = 0; i < 4096; i++) {
		if (marked_salts[i] == i) {
			HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][i], 0, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_25.\n");
			HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][i], 1, sizeof(cl_mem), &buffer_unchecked_hashes), "Failed setting kernel argument buffer_unchecked_hashes, kernel DES_bs_25.\n");
		}
	}

	set_common_kernel_args_kpc(buffer_unchecked_hashes, buffer_bs_keys);
}

/* if returns 0x800000, means there is no restriction on lws due to local memory limitations.*/
/* if returns 0, means local memory shouldn't be allocated.*/
/*static size_t find_smem_lws_limit(unsigned int force_global_keys)
{
	cl_ulong s_mem_sz = get_local_memory_size(gpu_id);
	size_t expected_lws_limit;
	cl_uint warp_size;

	if (force_global_keys)
		return 0x800000;

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

	expected_lws_limit = s_mem_sz /
			(sizeof(lm_vector) * 56);
	if (!expected_lws_limit)
		return 0;
	expected_lws_limit = GET_MULTIPLE_OR_ZERO(
			expected_lws_limit, warp_size);

	if (warp_size == 1 && expected_lws_limit & (expected_lws_limit - 1)) {
		get_power_of_two(expected_lws_limit);
		expected_lws_limit >>= 1;
	}

	return expected_lws_limit;
}*/

#define calc_ms(start, end)	\
		((long double)(end.tv_sec - start.tv_sec) * 1000.000 + \
			(long double)(end.tv_usec - start.tv_usec) / 1000.000)

/* Sets global_work_size and max_keys_per_crypt. */
/*static void gws_tune(size_t gws_init, long double kernel_run_ms, int gws_tune_flag, void (*set_key)(char *, int), int mask_mode)
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
	assert(gws_limit > PADDING);
	assert(!(gws_limit & (gws_limit - 1)));

	if (gws_tune_flag)
		global_work_size = gws_init;

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	if (gws_tune_flag) {
		release_buffer_gws();
		create_buffer_gws(global_work_size);
		set_kernel_args_gws();

		for (i = 0; i < (global_work_size << lm_log_depth); i++) {
			key[i & 3] = i & 255;
			key[(i & 3) + 3] = i ^ 0x3E;
			set_key(key, i);
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
	set_kernel_args_gws();*/

	/* for hash_ids[3*x + 1], 27 bits for storing gid and 5 bits for bs depth. */
	/*assert(global_work_size <= ((1U << 28) - 1));
	fmt_opencl_lm.params.max_keys_per_crypt = global_work_size << lm_log_depth;
	fmt_opencl_lm.params.min_keys_per_crypt = 1U << lm_log_depth;
}*/
static void reset(struct db_main *db)
{
	static int initialized;
	int i;

	if (initialized) {
		struct db_salt *salt;

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

		create_checking_kernel_set_args();
		create_keys_kernel_set_args(mask_mode);

		salt = db -> salts;
		do {
			init_kernel((*(WORD *)salt -> salt), gpu_id, 1, local_work_size);
		} while ((salt = salt -> next));

		set_kernel_arg_kpc();
	}
	else {
		char *ciphertext;
		WORD salt_val;

		local_work_size = 64;
		global_work_size = 16384;

		fmt_opencl_DES.params.max_keys_per_crypt = global_work_size * DES_BS_DEPTH;
		fmt_opencl_DES.params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;

		if (options.flags & FLG_MASK_CHK) {
			fmt_opencl_DES.params.max_keys_per_crypt = global_work_size;
			fmt_opencl_DES.params.min_keys_per_crypt = local_work_size;
		}

		create_clobj(NULL);
		create_clobj_kpc(global_work_size);

		create_checking_kernel_set_args();
		create_keys_kernel_set_args(0);

		for (i = 0; i < 4096; i++)
			build_salt((WORD)i);

		i = 0;
		while (fmt_opencl_DES.params.tests[i].ciphertext) {
			ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[i].ciphertext, 0, &fmt_opencl_DES);
			salt_val = *(WORD *)fmt_opencl_DES.methods.salt(ciphertext);
			init_kernel(salt_val, gpu_id, 1, local_work_size);
			i++;
		}

		set_kernel_arg_kpc();

		initialized++;
	}
}

static int des_crypt_25(int *pcount, struct db_salt *salt)
{
	const int count = mask_mode ? *pcount : (*pcount + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t current_gws = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;
	size_t iter_count = (mask_int_cand.num_int_cand + DES_BS_DEPTH - 1) >> DES_LOG_DEPTH;

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

void opencl_DES_bs_f_register_functions(struct fmt_main *fmt)
{
	fmt -> methods.done = &clean_all_buffers;
	fmt -> methods.reset = &reset;
	fmt -> methods.set_salt = &set_salt;
	fmt -> methods.crypt_all = &des_crypt_25;

	opencl_DES_bs_init_global_variables = &init_global_variables;
}
#endif /* HAVE_OPENCL */
