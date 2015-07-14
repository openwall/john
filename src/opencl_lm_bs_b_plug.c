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
#include "opencl_lm_bs.h"
#include "opencl_lm_hst_dev_shared.h"
#include "memdbg.h"

static cl_kernel **krnl = NULL;
static cl_int err;
static cl_mem index768_gpu, keys_gpu, K_gpu, cracked_hashes_gpu, cmp_out_gpu, loaded_hash_gpu, bitmap;
static int *loaded_hash = NULL;
static unsigned int num_loaded_hashes, *cmp_out = NULL, num_set_keys, *zero_buffer = NULL;

static int lm_crypt(int *pcount, struct db_salt *salt);

static void create_buffer_gws(size_t gws)
{
	unsigned int i;

	opencl_LM_bs_all = (opencl_LM_bs_combined*) mem_alloc (gws * sizeof(opencl_LM_bs_combined));
	opencl_LM_bs_keys = (opencl_LM_bs_transfer*) mem_alloc (gws * sizeof(opencl_LM_bs_transfer));

	keys_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, gws * sizeof(opencl_LM_bs_transfer), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_raw_keys.");

	K_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, gws * sizeof(LM_bs_vector) * 56, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_keys.");

	for (i = 0; i < gws; i++)
		opencl_LM_bs_init(i);
}

static void set_kernel_args_gws()
{
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 0, sizeof(cl_mem), &keys_gpu), "Failed setting kernel argument 0, kernel 1.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 1, sizeof(cl_mem), &K_gpu), "Failed setting kernel argument 1, kernel 1.");

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 1, sizeof(cl_mem), &K_gpu), "Failed setting kernel argument 1, kernel 0.");
}

static void release_buffer_gws()
{
	if (opencl_LM_bs_all) {
		MEM_FREE(opencl_LM_bs_all);
		MEM_FREE(opencl_LM_bs_keys);
		HANDLE_CLERROR(clReleaseMemObject(keys_gpu), "Error releasing buffer_raw_keys.");
		HANDLE_CLERROR(clReleaseMemObject(K_gpu), "Error releasing buffer_lm_keys.");
		opencl_LM_bs_all = 0;
	}
}

static void create_buffer(unsigned int num_loaded_hashes)
{
	loaded_hash = (int *) mem_alloc (num_loaded_hashes * sizeof(int) * 2);
	cmp_out     = (unsigned int *) mem_calloc (2 * num_loaded_hashes + 1, sizeof(unsigned int));
	opencl_LM_bs_cracked_hashes = (LM_bs_vector*) mem_alloc (num_loaded_hashes * 64 * sizeof(LM_bs_vector));
	zero_buffer = (unsigned int *) mem_calloc (((num_loaded_hashes - 1) / 32 + 1), sizeof(unsigned int));

	opencl_lm_init_index();

	index768_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 768 * sizeof(unsigned int), opencl_LM_bs_index768, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_lm_key_idx.");

	loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, num_loaded_hashes * sizeof(int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_loaded_hashes.");

	cracked_hashes_gpu = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * num_loaded_hashes * sizeof(LM_bs_vector), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_return_hashes.");

	cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * num_loaded_hashes + 1) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating buffer_hash_ids.");

	bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((num_loaded_hashes - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &ret_code);
	HANDLE_CLERROR(err, "Failed creating buffer_bitmap_dupe.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
}

static void set_kernel_args()
{
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 0, sizeof(cl_mem), &index768_gpu), "Failed setting kernel argument 0, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 2, sizeof(cl_mem), &cracked_hashes_gpu), "Failed setting kernel argument 2, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 3, sizeof(cl_mem), &loaded_hash_gpu), "Failed setting kernel argument 3, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 4, sizeof(int), &num_loaded_hashes), "Failed setting kernel argument 4, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 5, sizeof(cl_mem), &cmp_out_gpu), "Failed setting kernel argument 5, kernel 0.");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 6, sizeof(cl_mem), &bitmap), "Failed setting kernel argument 6, kernel 0.");
}

static void release_buffer()
{
	if (cracked_hashes_gpu) {
		MEM_FREE(loaded_hash);
		MEM_FREE(cmp_out);
		MEM_FREE(opencl_LM_bs_cracked_hashes);
		MEM_FREE(zero_buffer);
		HANDLE_CLERROR(clReleaseMemObject(index768_gpu), "Error releasing buffer_lm_key_idx");
		HANDLE_CLERROR(clReleaseMemObject(loaded_hash_gpu), "Error releasing buffer_loaded_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(cracked_hashes_gpu), "Error releasing buffer_return_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(cmp_out_gpu), "Error releasing buffer_hash_ids.");
		HANDLE_CLERROR(clReleaseMemObject(bitmap), "Error releasing buffer_bitmap_dupe.");
		cracked_hashes_gpu = 0;
	}
}

static void init_kernels(unsigned int num_loaded_hashes)
{
	static char build_opts[500];

	sprintf (build_opts, "-D NUM_LOADED_HASHES=%u", num_loaded_hashes);

	opencl_read_source("$JOHN/kernels/lm_bs_kernel.cl");
	opencl_build(gpu_id, NULL, 0, build_opts);

	krnl[gpu_id][0] = clCreateKernel(program[gpu_id], "lm_bs", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel lm_bs.");

	opencl_read_source("$JOHN/kernels/lm_bs_finalize_keys_kernel.cl");
	opencl_build(gpu_id, NULL, 0, build_opts);

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
			loaded_hash[i] = bin[0];
			loaded_hash[i + salt -> count] = bin[1];
			i++;
		} while ((pw = pw -> next));
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], loaded_hash_gpu, CL_TRUE, 0, num_loaded_hashes * sizeof(int) * 2, loaded_hash, 0, NULL, NULL ), "Failed Copy data to gpu");

		init_kernels(num_loaded_hashes);

		set_kernel_args();

		create_buffer_gws(MULTIPLIER);
		set_kernel_args_gws();
	}
	else {
		int i, *binary;
		char *ciphertext;

		num_loaded_hashes = 0;
		while (fmt_opencl_LM.params.tests[num_loaded_hashes].ciphertext) num_loaded_hashes++;

		create_buffer(num_loaded_hashes);

		i = 0;
		while (fmt_opencl_LM.params.tests[i].ciphertext) {
			char **fields = fmt_opencl_LM.params.tests[i].fields;
			if (!fields[1])
				fields[1] = fmt_opencl_LM.params.tests[i].ciphertext;
			ciphertext = fmt_opencl_LM.methods.split(fmt_opencl_LM.methods.prepare(fields, &fmt_opencl_LM), 0, &fmt_opencl_LM);
			binary = (int *)fmt_opencl_LM.methods.binary(ciphertext);
			loaded_hash[i] = binary[0];
			loaded_hash[i + num_loaded_hashes] = binary[1];
			i++;
			//fprintf(stderr, "C:%s B:%d %d\n", ciphertext, binary[0], i == num_loaded_hashes );
		}

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], loaded_hash_gpu, CL_TRUE, 0, num_loaded_hashes * sizeof(int) * 2, loaded_hash, 0, NULL, NULL ), "Failed Copy data to gpu");
		init_kernels(num_loaded_hashes);

		set_kernel_args();

		create_buffer_gws(MULTIPLIER);
		set_kernel_args_gws();

		global_work_size = MULTIPLIER;
		local_work_size = 64;
		num_set_keys = fmt_opencl_LM.params.max_keys_per_crypt = (MULTIPLIER << LM_BS_LOG2);
		fmt_opencl_LM.params.max_keys_per_crypt = (MULTIPLIER << LM_BS_LOG2);

		cmp_out[0] = 0;
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
	if (!local_work_size)
		local_work_size = WORK_GROUP_SIZE;

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
	static unsigned int section = 1;
	cl_event evnt;
	static size_t N, M;

	if (*pcount != num_set_keys || section) {
		num_set_keys = *pcount;
		section = (((num_set_keys - 1) >> LM_BS_LOG2) + 1);
		M = local_work_size;
		N = ((section - 1) / M + 1) * M;
		N = N > MULTIPLIER ? MULTIPLIER : N;
		section = 0;
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], keys_gpu, CL_TRUE, 0, MULTIPLIER * sizeof(opencl_LM_bs_transfer), opencl_LM_bs_keys, 0, NULL, NULL ), "Failed Copy data to gpu");
	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][1], 1, NULL, &N, &M, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");
	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][0], 1, NULL, &N, &M, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");

	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(unsigned int), cmp_out, 0, NULL, NULL), "Write FAILED\n");

	if (cmp_out[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, (2 * num_loaded_hashes + 1) * sizeof(unsigned int), cmp_out, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cracked_hashes_gpu, CL_TRUE, 0, cmp_out[0] * 64 * sizeof(LM_bs_vector), opencl_LM_bs_cracked_hashes, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], bitmap, CL_TRUE, 0, ((num_loaded_hashes - 1)/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmap_dupe.");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
	}

	return 32 * cmp_out[0];
}

void opencl_LM_bs_b_register_functions(struct fmt_main *fmt)
{
	fmt->methods.done = &clean_all_buffers;
	fmt->methods.reset = &reset;
	fmt->methods.get_key = &get_key;
	fmt->methods.crypt_all = &lm_crypt;

	opencl_LM_bs_init_global_variables = &init_global_variables;
	opencl_LM_bs_select_device = &select_device;
}
#endif /* HAVE_OPENCL */
