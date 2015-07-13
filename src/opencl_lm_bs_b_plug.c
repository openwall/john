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
#include "opencl_lm_bs.h"
#include "opencl_lm_hst_dev_shared.h"
#include "memdbg.h"

static cl_kernel **krnl = NULL;
static cl_int err;
static cl_mem index768_gpu, keys_gpu, K_gpu, cracked_hashes_gpu, cmp_out_gpu, loaded_hash_gpu, bitmap;
static int *loaded_hash = NULL;
static unsigned int num_loaded_hashes, *cmp_out = NULL, num_set_keys;

static int lm_crypt(int *pcount, struct db_salt *salt);

static void clean_all_buffers()
{
	int i;
	const char* errMsg = "Release Memory Object :Failed";
	MEM_FREE(opencl_LM_bs_all);
	MEM_FREE(opencl_LM_bs_keys);
	MEM_FREE(opencl_LM_bs_cracked_hashes);
	MEM_FREE(loaded_hash);
	MEM_FREE(cmp_out);
	HANDLE_CLERROR(clReleaseMemObject(index768_gpu),errMsg);
	HANDLE_CLERROR(clReleaseMemObject(keys_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(cracked_hashes_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(K_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(cmp_out_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(loaded_hash_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(bitmap), errMsg);
	HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][0]), "Error releasing kernel 0");
	HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][1]), "Error releasing kernel 1");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
	               "Error releasing Program");
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		MEM_FREE(krnl[i]);
	MEM_FREE(krnl);
}

static void reset(struct db_main *db)
{
	const char* errMsg = "Release Memory Object :Failed";
	static int initialized;

	if (initialized) {
		int i, *bin;
		struct db_salt *salt;
		struct db_password *pw;

		MEM_FREE(loaded_hash);
		MEM_FREE(cmp_out);
		MEM_FREE(opencl_LM_bs_cracked_hashes);

		HANDLE_CLERROR(clReleaseMemObject(cmp_out_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(cracked_hashes_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(bitmap), errMsg);

		loaded_hash = (int *) mem_alloc((db->password_count) * sizeof(int) * 2);
		cmp_out     = (unsigned int *) mem_alloc((2 * db->password_count + 1) * sizeof(unsigned int));
		opencl_LM_bs_cracked_hashes = (LM_bs_vector*) mem_alloc(db->password_count * 64 * sizeof(LM_bs_vector));

		salt = db->salts;
		pw = salt->list;
		i = 0;
		do {
			if (!(bin = (int *)pw->binary))
				continue;
			loaded_hash[i] = bin[0];
			loaded_hash[i + salt -> count] = bin[1];
			i++;
			//printf("%d %d\n", i++, bin[0]);
		} while ((pw = pw -> next));

		loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (db->password_count) * sizeof(int) * 2, loaded_hash, &err);
		if (loaded_hash_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		cracked_hashes_gpu = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * db->password_count * sizeof(LM_bs_vector), NULL, &err);
		if (cracked_hashes_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * db->password_count + 1) * sizeof(unsigned int), NULL, &err);
		if (cmp_out_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, ((db->password_count - 1) / 32 + 1) * sizeof(unsigned int), NULL, &err);
		if (bitmap == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		num_loaded_hashes = salt->count;

	}
	else {
		int i, *binary;
		char *ciphertext;

		if (!loaded_hash)
			MEM_FREE(loaded_hash);
		if (!cmp_out)
			MEM_FREE(cmp_out);
		if (!opencl_LM_bs_cracked_hashes)
			MEM_FREE(opencl_LM_bs_cracked_hashes);

		HANDLE_CLERROR(clReleaseMemObject(cmp_out_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(loaded_hash_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(cracked_hashes_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(bitmap), errMsg);

		num_loaded_hashes = 0;
		while (fmt_opencl_LM.params.tests[num_loaded_hashes].ciphertext) num_loaded_hashes++;

		loaded_hash = (int *) mem_alloc(num_loaded_hashes * sizeof(int) * 2);
		cmp_out     = (unsigned int *) mem_alloc((2 * num_loaded_hashes + 1) * sizeof(unsigned int));
		opencl_LM_bs_cracked_hashes = (LM_bs_vector*) mem_alloc (num_loaded_hashes * 64 * sizeof(LM_bs_vector));

		cmp_out[0] = 0;

		cracked_hashes_gpu = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * num_loaded_hashes * sizeof(LM_bs_vector), NULL, &err);
		if (cracked_hashes_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, num_loaded_hashes * sizeof(int) * 2, NULL, &err);
		if (loaded_hash_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * num_loaded_hashes + 1)* sizeof(unsigned int), NULL, &err);
		if (cmp_out_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, ((num_loaded_hashes - 1) / 32 + 1) * sizeof(unsigned int), NULL, &err);
		if (bitmap == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

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
		initialized++;
	}

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 2, sizeof(cl_mem), &cracked_hashes_gpu), "Set Kernel Arg FAILED arg4\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 3, sizeof(cl_mem), &loaded_hash_gpu), "Set Kernel krnl Arg 5 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 5, sizeof(cl_mem), &cmp_out_gpu), "Set Kernel Arg krnl FAILED arg7\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 6, sizeof(cl_mem), &bitmap), "Set Kernel Arg krnl FAILED arg8\n");
}

static void init_global_variables()
{
	int i;

	opencl_LM_bs_all = (opencl_LM_bs_combined*) mem_alloc (MULTIPLIER * sizeof(opencl_LM_bs_combined));
	opencl_LM_bs_keys = (opencl_LM_bs_transfer*) mem_alloc (MULTIPLIER * sizeof(opencl_LM_bs_transfer));

	krnl = (cl_kernel **) mem_calloc(MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM, sizeof(cl_kernel *));
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		krnl[i] = (cl_kernel *) mem_calloc(2, sizeof(cl_kernel));
}

static void find_best_gws(struct fmt_main *fmt)
{
	struct timeval start, end;
	double savetime;
	long int count = 64;
	double speed = 999999, diff;
	int ccount;

	num_loaded_hashes = 1;
	cmp_out = (unsigned int *) mem_alloc((2 * num_loaded_hashes + 1) * sizeof(int));
	opencl_LM_bs_cracked_hashes = (LM_bs_vector*) mem_alloc(num_loaded_hashes * 64 * sizeof(LM_bs_vector));

	gettimeofday(&start, NULL);
	ccount = count * local_work_size * LM_BS_DEPTH;
	lm_crypt(&ccount, NULL);
	gettimeofday(&end, NULL);

	savetime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.000;
	speed = ((double)count) / savetime;
	do {
		count *= 2;
		if ((count * local_work_size) > MULTIPLIER) {
			count = count >> 1;
			break;
		}
		gettimeofday(&start, NULL);
		ccount = count * local_work_size * LM_BS_DEPTH;
		lm_crypt(&ccount, NULL);
		gettimeofday(&end, NULL);
		savetime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.000;
		diff = (((double)count) / savetime) / speed;
		if (diff < 1) {
			count = count >> 1;
			break;
		}
		diff = diff - 1;
		diff = (diff < 0) ? (-diff) : diff;
		speed = ((double)count) / savetime;
	} while(diff > 0.01);

	fmt -> params.max_keys_per_crypt = count * local_work_size * LM_BS_DEPTH;
	fmt -> params.min_keys_per_crypt = local_work_size * LM_BS_DEPTH;

	MEM_FREE(cmp_out);
	MEM_FREE(opencl_LM_bs_cracked_hashes);
	cmp_out = NULL;
	opencl_LM_bs_cracked_hashes = NULL;

	if (options.verbosity > 3)
		fprintf(stderr, "Local worksize (LWS) "Zu", Global worksize (GWS) "Zu"\n", local_work_size, count * local_work_size);
}

static void select_device(struct fmt_main *fmt)
{
	const char *errMsg;

	if (!local_work_size)
		local_work_size = WORK_GROUP_SIZE;

	opencl_prepare_dev(gpu_id);

	opencl_read_source("$JOHN/kernels/lm_bs_kernel.cl");
	opencl_build(gpu_id, NULL, 0, NULL);
	krnl[gpu_id][0] = clCreateKernel(program[gpu_id], "lm_bs", &err) ;
	if (err) {
		fprintf(stderr, "Create Kernel LM_bs_25_b FAILED\n");
		return;
	}

	opencl_read_source("$JOHN/kernels/lm_bs_finalize_keys_kernel.cl");
	opencl_build(gpu_id, NULL, 0, NULL);
	krnl[gpu_id][1] = clCreateKernel(program[gpu_id], "lm_bs_finalize_keys", &err) ;
	if (err) {
		fprintf(stderr, "failed create Kernel lm_bs_finalize_keys\n");
		return;
	}

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

	errMsg = "Create Buffer FAILED.";
	keys_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, MULTIPLIER * sizeof(opencl_LM_bs_transfer), NULL, &err);
	if (keys_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	K_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, MULTIPLIER * sizeof(LM_bs_vector) * 56, NULL, &err);
	if (K_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	index768_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 768 * sizeof(unsigned int), NULL, &err);
	if (index768_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	cracked_hashes_gpu = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * sizeof(LM_bs_vector), NULL, &err);
	if (cracked_hashes_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 2 * sizeof(int), NULL, &err);
	if(loaded_hash_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 3 * sizeof(unsigned int), NULL, &err);
	if(cmp_out_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(unsigned int), NULL, &err);
	if (bitmap == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 0, sizeof(cl_mem), &index768_gpu), "Set Kernel Arg FAILED arg0\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 1, sizeof(cl_mem), &K_gpu), "Set Kernel Arg FAILED arg1\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 2, sizeof(cl_mem), &cracked_hashes_gpu), "Set Kernel Arg FAILED arg2\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 3, sizeof(cl_mem), &loaded_hash_gpu), "Set Kernel krnl Arg 3 :FAILED") ;
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 5, sizeof(cl_mem), &cmp_out_gpu), "Set Kernel Arg krnl FAILED arg4\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 6, sizeof(cl_mem), &bitmap), "Set Kernel Arg krnl FAILED arg5\n");

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 0, sizeof(cl_mem), &keys_gpu), "Set Kernel Arg FAILED arg1\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][1], 1, sizeof(cl_mem), &K_gpu), "Set Kernel Arg FAILED arg2\n");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], index768_gpu, CL_TRUE, 0, 768*sizeof(unsigned int), opencl_LM_bs_index768, 0, NULL, NULL ), "Failed Copy data to gpu");

	if (!global_work_size)
		find_best_gws(fmt);
	else {
		if (options.verbosity > 3)
			fprintf(stderr, "Local worksize (LWS) "Zu", Global worksize (GWS) "Zu"\n", local_work_size, global_work_size);
		fmt -> params.max_keys_per_crypt = global_work_size * LM_BS_DEPTH;
		fmt -> params.min_keys_per_crypt = local_work_size * LM_BS_DEPTH;
	}

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

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 4, sizeof(int), &num_loaded_hashes), "Set Kernel krnl Arg 5 :FAILED") ;

	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][0], 1, NULL, &N, &M, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");

	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(unsigned int), cmp_out, 0, NULL, NULL), "Write FAILED\n");

	if (cmp_out[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, (2 * num_loaded_hashes + 1) * sizeof(unsigned int), cmp_out, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cracked_hashes_gpu, CL_TRUE, 0, cmp_out[0] * 64 * sizeof(LM_bs_vector), opencl_LM_bs_cracked_hashes, 0, NULL, NULL), "Write FAILED\n");
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
