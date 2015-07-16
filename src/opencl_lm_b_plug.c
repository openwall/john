/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#ifdef HAVE_OPENCL

#include <assert.h>
#include <string.h>
#include <sys/time.h>

#include "options.h"
#include "opencl_lm.h"
#include "opencl_lm_hst_dev_shared.h"
#include "memdbg.h"

#define PADDING 	2048
#define get_power_of_two(v)	\
{				\
	v--;			\
	v |= v >> 1;		\
	v |= v >> 2;		\
	v |= v >> 4;		\
	v |= v >> 8;		\
	v |= v >> 16;		\
	v |= v >> 32;		\
	v++;			\
}

static cl_kernel **krnl = NULL;
static cl_int err;
static cl_mem buffer_lm_key_idx, buffer_raw_keys, buffer_lm_keys, buffer_return_hashes, buffer_hash_ids, buffer_loaded_hashes, buffer_bitmap_dupe;
static int *loaded_hashes = NULL;
static unsigned int num_loaded_hashes, *hash_ids = NULL, num_set_keys, *zero_buffer = NULL;
static size_t current_gws = 0;

static int lm_crypt(int *pcount, struct db_salt *salt);

static void create_buffer_gws(size_t gws)
{
	unsigned int i;

	opencl_lm_all = (opencl_lm_combined*) mem_alloc ((gws + PADDING)* sizeof(opencl_lm_combined));
	opencl_lm_keys = (opencl_lm_transfer*) mem_alloc ((gws + PADDING)* sizeof(opencl_lm_transfer));

	buffer_raw_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, (gws + PADDING) * sizeof(opencl_lm_transfer), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_raw_keys.");

	buffer_lm_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws + PADDING) * sizeof(lm_vector) * 56, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_keys.");

	for (i = 0; i < (gws + PADDING); i++)
		opencl_lm_init(i);
}

static void set_kernel_args_gws()
{
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 0, sizeof(cl_mem), &buffer_raw_keys), "Failed setting kernel argument 0, kernel 1.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 1, sizeof(cl_mem), &buffer_lm_keys), "Failed setting kernel argument 1, kernel 1.");

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 1, sizeof(cl_mem), &buffer_lm_keys), "Failed setting kernel argument 1, kernel 0.");
}

static void release_buffer_gws()
{
	if (opencl_lm_all) {
		MEM_FREE(opencl_lm_all);
		MEM_FREE(opencl_lm_keys);
		HANDLE_CLERROR(clReleaseMemObject(buffer_raw_keys), "Error releasing buffer_raw_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_lm_keys), "Error releasing buffer_lm_keys.");
		opencl_lm_all = 0;
	}
}

static void create_buffer(unsigned int num_loaded_hashes)
{
	loaded_hashes = (int *) mem_alloc (num_loaded_hashes * sizeof(int) * 2);
	hash_ids     = (unsigned int *) mem_calloc (2 * num_loaded_hashes + 1, sizeof(unsigned int));
	opencl_lm_cracked_hashes = (lm_vector*) mem_alloc (num_loaded_hashes * 64 * sizeof(lm_vector));
	zero_buffer = (unsigned int *) mem_calloc (((num_loaded_hashes - 1) / 32 + 1), sizeof(unsigned int));

	opencl_lm_init_index();

	buffer_lm_key_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 768 * sizeof(unsigned int), opencl_lm_index768, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_key_idx.");

	buffer_loaded_hashes = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, num_loaded_hashes * sizeof(int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_loaded_hashes.");

	buffer_return_hashes = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * num_loaded_hashes * sizeof(lm_vector), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_return_hashes.");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * num_loaded_hashes + 1) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_hash_ids.");

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((num_loaded_hashes - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &ret_code);
	HANDLE_CLERROR(err, "Failed creating buffer_bitmap_dupe.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
}

static void set_kernel_args()
{
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 0, sizeof(cl_mem), &buffer_lm_key_idx), "Failed setting kernel argument 0, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 2, sizeof(cl_mem), &buffer_return_hashes), "Failed setting kernel argument 2, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 3, sizeof(cl_mem), &buffer_loaded_hashes), "Failed setting kernel argument 3, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 4, sizeof(cl_mem), &buffer_hash_ids), "Failed setting kernel argument 4, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 5, sizeof(cl_mem), &buffer_bitmap_dupe), "Failed setting kernel argument 5, kernel 0.");
}

static void release_buffer()
{
	if (buffer_return_hashes) {
		MEM_FREE(loaded_hashes);
		MEM_FREE(hash_ids);
		MEM_FREE(opencl_lm_cracked_hashes);
		MEM_FREE(zero_buffer);
		HANDLE_CLERROR(clReleaseMemObject(buffer_lm_key_idx), "Error releasing buffer_lm_key_idx");
		HANDLE_CLERROR(clReleaseMemObject(buffer_loaded_hashes), "Error releasing buffer_loaded_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_return_hashes), "Error releasing buffer_return_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Error releasing buffer_hash_ids.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error releasing buffer_bitmap_dupe.");
		buffer_return_hashes = 0;
	}
}

static void init_kernels(unsigned int num_loaded_hashes, size_t s_mem_lws, unsigned int use_local_mem)
{
	static char build_opts[500];

	sprintf (build_opts, "-D NUM_LOADED_HASHES=%u -D USE_LOCAL_MEM=%u -D WORK_GROUP_SIZE=%zu",
		 num_loaded_hashes, use_local_mem, s_mem_lws);

	opencl_read_source("$JOHN/kernels/lm_kernel.cl");
	opencl_build(gpu_id, build_opts, 0, NULL);

	krnl[gpu_id][0] = clCreateKernel(program[gpu_id], "lm_bs", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel lm_bs.");

	opencl_read_source("$JOHN/kernels/lm_finalize_keys_kernel.cl");
	opencl_build(gpu_id, build_opts, 0, NULL);

	krnl[gpu_id][1] = clCreateKernel(program[gpu_id], "lm_bs_finalize_keys", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel lm_bs_finalize_keys.");
}

static void release_kernels()
{
	if (krnl[gpu_id][0]) {
		HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][0]), "Error releasing kernel 0");
		HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][1]), "Error releasing kernel 1");
		krnl[gpu_id][0] = 0;
	}
}

static void clean_all_buffers()
{
	int i;
	release_buffer_gws();
	release_buffer();
	release_kernels();
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
	               "Error releasing Program");
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		MEM_FREE(krnl[i]);
	MEM_FREE(krnl);
}

/* if returns 0x800000, means there is no restriction on lws due to local memory limitations.*/
/* if returns 0, means local memory shouldn't be allocated.*/
static size_t find_smem_lws_limit(unsigned int full_unroll, unsigned int use_local_mem, unsigned int force_global_keys)
{
	cl_ulong s_mem_sz = get_local_memory_size(gpu_id);
	size_t expected_lws_limit;
	cl_uint warp_size;

	if (force_global_keys) {
		if (s_mem_sz > 768 * sizeof(cl_short))
			return 0x800000;
		else
			return 0;
	}

	if (!s_mem_sz)
		return 0;

	if (gpu_amd(device_info[gpu_id])) {
		HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
		CL_DEVICE_WAVEFRONT_WIDTH_AMD,
		sizeof(cl_uint), &warp_size, 0),
		"failed to get CL_DEVICE_WAVEFRONT_WIDTH_AMD.");
		assert(warp_size == 64);
	}
	else if (gpu_nvidia(device_info[gpu_id])) {
		HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
		CL_DEVICE_WARP_SIZE_NV,
		sizeof(cl_uint), &warp_size, 0),
		"failed to get CL_DEVICE_WARP_SIZE_NV.");
		assert(warp_size >= 32);
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
static void gws_tune(size_t gws_init, long double kernel_run_ms, int gws_tune_flag)
{
	unsigned int i;
	char key[PLAINTEXT_LENGTH + 1] = "alterit";

	struct timeval startc, endc;
	long double time_ms = 0;
	int pcount;

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

		for (i = 0; i < (global_work_size << LM_LOG_DEPTH); i++) {
			key[i & 3] = i & 255;
			key[(i & 3) + 3] = i ^ 0x3E;
			opencl_lm_set_key(key, i);
		}

		gettimeofday(&startc, NULL);
		pcount = (int)(global_work_size << LM_LOG_DEPTH);
		lm_crypt((int *)&pcount, NULL);
		gettimeofday(&endc, NULL);

		time_ms = calc_ms(startc, endc);
		global_work_size = (size_t)((kernel_run_ms / time_ms) * (long double)global_work_size);
	}

	get_power_of_two(global_work_size);

	if (global_work_size > gws_limit)
		global_work_size = gws_limit;

	release_buffer_gws();
	create_buffer_gws(global_work_size);
	set_kernel_args_gws();

	fmt_opencl_lm.params.max_keys_per_crypt = global_work_size << LM_LOG_DEPTH;
	fmt_opencl_lm.params.min_keys_per_crypt = LM_DEPTH;
}

static void auto_tune_all(unsigned int num_loaded_hashes, long double kernel_run_ms)
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

	if (cpu(device_info[gpu_id])) {
		force_global_keys = 1;
		use_local_mem = 0;
		full_unroll = 0;
		kernel_run_ms = 5;
	}
	else if (gpu(device_info[gpu_id])) {
		force_global_keys = 0;
		use_local_mem = 1;
		full_unroll = 0;
	}
	else {
		force_global_keys = 1;
		use_local_mem = 0;
		full_unroll = 0;
		kernel_run_ms = 40;
	}

	local_work_size = 0;
	global_work_size = 0;
	gws_tune_flag = 1;
	lws_tune_flag = 1;
	opencl_get_user_preferences(FORMAT_LABEL);
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
	fprintf(stdout, "Limit_smem:%zu, Full_unroll_flag:%u,"
		"Use_local_mem:%u, Force_global_keys:%u\n",
 		s_mem_limited_lws, full_unroll, use_local_mem,
		force_global_keys);
#endif

	if (s_mem_limited_lws == 0x800000 || !s_mem_limited_lws) {
		long double best_time_ms;
		size_t best_lws, lws_limit;

		release_kernels();
		init_kernels(num_loaded_hashes, 0, use_local_mem && s_mem_limited_lws);
		set_kernel_args();

		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);

		lws_limit = get_kernel_max_lws(gpu_id, krnl[gpu_id][0]);

		if (lws_tune_flag) {
			if (gpu(device_info[gpu_id]) && lws_limit >= 32)
				local_work_size = 32;
			else
				local_work_size = get_kernel_preferred_multiple(gpu_id, krnl[gpu_id][0]);
		}
		if (local_work_size > lws_limit)
			local_work_size = lws_limit;

		assert(local_work_size <= lws_limit);

		if (lws_tune_flag) {
			time_ms = 0;
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= lws_limit) {
				int pcount, i;
				for (i = 0; i < (global_work_size << LM_LOG_DEPTH); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3F;
					opencl_lm_set_key(key, i);
				}
				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << LM_LOG_DEPTH);
				lm_crypt((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);

				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: %zu, LWS: %zu, Limit_smem:%zu, Limit_kernel:%zu,"
		"Current time:%Lf, Best time:%Lf\n",
 		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, krnl[gpu_id][0]), time_ms,
		best_time_ms);
#endif
				local_work_size *= 2;
			}
			local_work_size = best_lws;
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);
		}
	}

	else {
		long double best_time_ms;
		size_t best_lws;
		cl_uint warp_size;

		if (gpu_amd(device_info[gpu_id])) {
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_WAVEFRONT_WIDTH_AMD,
				sizeof(cl_uint), &warp_size, 0),
				"failed to get CL_DEVICE_WAVEFRONT_WIDTH_AMD.");
			assert(warp_size == 64);
		}

		else if (gpu_nvidia(device_info[gpu_id])) {
			HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id],
				CL_DEVICE_WARP_SIZE_NV,
				sizeof(cl_uint), &warp_size, 0),
				"failed to get CL_DEVICE_WARP_SIZE_NV.");
			assert(warp_size == 32);
		}
		else {
			warp_size = 1;
			fprintf(stderr, "Possible auto_tune fail!!.\n");
		}
		if (lws_tune_flag)
			local_work_size = warp_size;
		if (local_work_size > s_mem_limited_lws)
			local_work_size = s_mem_limited_lws;

		release_kernels();
		init_kernels(num_loaded_hashes, local_work_size, use_local_mem);

		if (local_work_size > get_kernel_max_lws(gpu_id, krnl[gpu_id][0])) {
			local_work_size = get_kernel_max_lws(gpu_id, krnl[gpu_id][0]);
			release_kernels();
			init_kernels(num_loaded_hashes, local_work_size, use_local_mem);
		}

		set_kernel_args();
		gws_tune(1024, 2 * kernel_run_ms, gws_tune_flag);
		gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);

		if (lws_tune_flag) {
			best_time_ms = 999999.00;
			best_lws = local_work_size;
			while (local_work_size <= s_mem_limited_lws) {
				int pcount, i;
				release_kernels();
				init_kernels(num_loaded_hashes, local_work_size, use_local_mem);
				set_kernel_args();
				set_kernel_args_gws();

				for (i = 0; i < (global_work_size << LM_LOG_DEPTH); i++) {
					key[i & 3] = i & 255;
					key[(i & 3) + 3] = i ^ 0x3E;
					opencl_lm_set_key(key, i);
				}

				gettimeofday(&startc, NULL);
				pcount = (int)(global_work_size << LM_LOG_DEPTH);
				lm_crypt((int *)&pcount, NULL);
				gettimeofday(&endc, NULL);
				time_ms = calc_ms(startc, endc);

				if (time_ms < best_time_ms && local_work_size <= get_kernel_max_lws(gpu_id, krnl[gpu_id][0])) {
					best_lws = local_work_size;
					best_time_ms = time_ms;
				}
#if 0
	fprintf(stdout, "GWS: %zu, LWS: %zu, Limit_smem:%zu, Limit_kernel:%zu,"
		"Current time:%Lf, Best time:%Lf\n",
 		global_work_size, local_work_size, s_mem_limited_lws,
		get_kernel_max_lws(gpu_id, krnl[gpu_id][0]), time_ms,
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
			init_kernels(num_loaded_hashes, local_work_size, use_local_mem);
			set_kernel_args();
			gws_tune(global_work_size, kernel_run_ms, gws_tune_flag);
		}
	}

	fprintf(stdout, "GWS: %zu, LWS: %zu\n",
		global_work_size, local_work_size);
}

static void reset(struct db_main *db)
{
	static int initialized;

	if (initialized) {
		int i;
		struct db_salt *salt;
		struct db_password *pw;

		release_buffer();
		release_buffer_gws();
		release_kernels();

		salt = db->salts;
		num_loaded_hashes = salt->count;

		create_buffer(num_loaded_hashes);

		i = 0;
		pw = salt->list;
		do {
			int *bin;
			if (!(bin = (int *)pw->binary))
				continue;
			loaded_hashes[i] = bin[0];
			loaded_hashes[i + salt -> count] = bin[1];
			i++;
		} while ((pw = pw -> next));
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_loaded_hashes, CL_TRUE, 0, num_loaded_hashes * sizeof(int) * 2, loaded_hashes, 0, NULL, NULL ), "Failed Copy data to gpu");

		auto_tune_all(num_loaded_hashes, 300);
		num_set_keys = fmt_opencl_lm.params.max_keys_per_crypt;
	}
	else {
		int i, *binary;
		char *ciphertext;

		num_loaded_hashes = 0;
		while (fmt_opencl_lm.params.tests[num_loaded_hashes].ciphertext) num_loaded_hashes++;

		create_buffer(num_loaded_hashes);

		i = 0;
		while (fmt_opencl_lm.params.tests[i].ciphertext) {
			char **fields = fmt_opencl_lm.params.tests[i].fields;
			if (!fields[1])
				fields[1] = fmt_opencl_lm.params.tests[i].ciphertext;
			ciphertext = fmt_opencl_lm.methods.split(fmt_opencl_lm.methods.prepare(fields, &fmt_opencl_lm), 0, &fmt_opencl_lm);
			binary = (int *)fmt_opencl_lm.methods.binary(ciphertext);
			loaded_hashes[i] = binary[0];
			loaded_hashes[i + num_loaded_hashes] = binary[1];
			i++;
			//fprintf(stderr, "C:%s B:%d %d\n", ciphertext, binary[0], i == num_loaded_hashes );
		}

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_loaded_hashes, CL_TRUE, 0, num_loaded_hashes * sizeof(int) * 2, loaded_hashes, 0, NULL, NULL ), "Failed Copy data to gpu");
		auto_tune_all(num_loaded_hashes, 300);
		num_set_keys = fmt_opencl_lm.params.max_keys_per_crypt;

		hash_ids[0] = 0;
		initialized++;
	}
}

static void init_global_variables()
{
	int i;

	krnl = (cl_kernel **) mem_calloc(MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM, sizeof(cl_kernel *));
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		krnl[i] = (cl_kernel *) mem_calloc(2, sizeof(cl_kernel));
}

static void select_device(struct fmt_main *fmt)
{
	//if (!local_work_size)
	//	local_work_size = WORK_GROUP_SIZE;

	/* Cap LWS at kernel limit */
	if (local_work_size > 64)
		local_work_size = 64;

	if (local_work_size >
	    get_kernel_max_lws(gpu_id, krnl[gpu_id][0]))
		local_work_size =
			get_kernel_max_lws(gpu_id, krnl[gpu_id][0]);

	if (local_work_size >
	    get_kernel_max_lws(gpu_id, krnl[gpu_id][1]))
		local_work_size =
			get_kernel_max_lws(gpu_id, krnl[gpu_id][1]);

	/* Cludge for buggy AMD CPU driver */
	if (cpu(device_info[gpu_id]) &&
	    get_platform_vendor_id(get_platform_id(gpu_id)) == DEV_AMD)
		local_work_size = 1;

	/* Cludge for old buggy Intel driver */
	if (cpu(device_info[gpu_id]) &&
	    get_platform_vendor_id(get_platform_id(gpu_id)) == DEV_INTEL) {
		char dev_ver[MAX_OCLINFO_STRING_LEN];

		clGetDeviceInfo(devices[gpu_id], CL_DEVICE_VERSION,
		                MAX_OCLINFO_STRING_LEN, dev_ver, NULL);
		if (strstr(dev_ver, "Build 15293.6649"))
			local_work_size = 1;
	}

	/* ...but ensure GWS is still a multiple of LWS */
	global_work_size = ((global_work_size + local_work_size - 1) /
	                    local_work_size) * local_work_size;




	/*if (!global_work_size)
		find_best_gws(fmt);
	else {
		if (options.verbosity > 3)
			fprintf(stderr, "Local worksize (LWS) "Zu", Global worksize (GWS) "Zu"\n", local_work_size, global_work_size);
		fmt -> params.max_keys_per_crypt = global_work_size * LM_BS_DEPTH;
		fmt -> params.min_keys_per_crypt = local_work_size * LM_BS_DEPTH;
	}*/
	num_set_keys = fmt -> params.max_keys_per_crypt;
}

static char *get_key(int index)
{
      get_key_body();
}

static int lm_crypt(int *pcount, struct db_salt *salt)
{
	cl_event evnt;
	const int count = (*pcount + LM_DEPTH - 1) >> LM_LOG_DEPTH;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	current_gws = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;

	assert(current_gws <= global_work_size + PADDING);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_raw_keys, CL_TRUE, 0, current_gws * sizeof(opencl_lm_transfer), opencl_lm_keys, 0, NULL, NULL ), "Failed Copy data to gpu");
	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][1], 1, NULL, &current_gws, lws, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");
	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][0], 1, NULL, &current_gws, lws, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");

	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Write FAILED\n");

	if (hash_ids[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (2 * num_loaded_hashes + 1) * sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_return_hashes, CL_TRUE, 0, hash_ids[0] * 64 * sizeof(lm_vector), opencl_lm_cracked_hashes, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_TRUE, 0, ((num_loaded_hashes - 1)/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmap_dupe.");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
	}

	return 32 * hash_ids[0];
}

void opencl_lm_b_register_functions(struct fmt_main *fmt)
{
	fmt->methods.done = &clean_all_buffers;
	fmt->methods.reset = &reset;
	fmt->methods.get_key = &get_key;
	fmt->methods.crypt_all = &lm_crypt;

	opencl_lm_init_global_variables = &init_global_variables;
	opencl_lm_select_device = &select_device;
}
#endif /* HAVE_OPENCL */
