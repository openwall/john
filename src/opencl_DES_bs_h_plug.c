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
#include "memdbg.h"

static cl_kernel **krnl;
static cl_int err;
static cl_mem index768_gpu, keys_gpu, cracked_hashes_gpu, K_gpu, cmp_out_gpu, loaded_hash_gpu, bitmap, *loaded_hash_gpu_salt = NULL;
static   WORD current_salt = 0;
static int *loaded_hash = NULL;
static unsigned int *hash_ids = NULL, num_loaded_hashes, num_set_keys;
static WORD *stored_salt;
static int num_compiled_salt;
static unsigned int *index96 = NULL, *zero_buffer = NULL;
static unsigned int save_binary = 1;

static int des_crypt_25(int *pcount, struct db_salt *salt);

static void clean_all_buffers()
{
	int i;
	const char* errMsg = "Release Memory Object :Failed";
	MEM_FREE(opencl_DES_bs_all);
	MEM_FREE(opencl_DES_bs_keys);
	MEM_FREE(opencl_DES_bs_cracked_hashes);
	MEM_FREE(loaded_hash);
	MEM_FREE(hash_ids);
	MEM_FREE(index96);
	MEM_FREE(zero_buffer);
	HANDLE_CLERROR(clReleaseMemObject(index768_gpu),errMsg);
	HANDLE_CLERROR(clReleaseMemObject(keys_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(cracked_hashes_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(K_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(cmp_out_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(loaded_hash_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(bitmap), errMsg);
	for( i = 0; i < 4097; i++)
		if (krnl[gpu_id][i])
			HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][i]),
				       "Error releasing kernel");
	if (loaded_hash_gpu_salt) {
		for (i = 0; i < 4096; i++)
			if (loaded_hash_gpu_salt[i] != (cl_mem)0)
				HANDLE_CLERROR(clReleaseMemObject(loaded_hash_gpu_salt[i]),
					       errMsg);
		MEM_FREE(loaded_hash_gpu_salt);
	}
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
	               "Error releasing Program");
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		MEM_FREE(krnl[i]);
	MEM_FREE(krnl);
	MEM_FREE(stored_salt);
}

static void reset(struct db_main *db)
{
	const char* errMsg = "Release Memory Object :Failed";
	static int initialized;

	if (initialized) {
		int i;

		MEM_FREE(loaded_hash);
		MEM_FREE(hash_ids);
		MEM_FREE(opencl_DES_bs_cracked_hashes);
		MEM_FREE(zero_buffer);

		HANDLE_CLERROR(clReleaseMemObject(cmp_out_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(cracked_hashes_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(bitmap), errMsg);

		loaded_hash = (int *) mem_alloc((db->password_count) * sizeof(int) * 2);
		hash_ids     = (unsigned int *) mem_alloc((2 * db->password_count + 1) * sizeof(unsigned int));
		opencl_DES_bs_cracked_hashes = (DES_bs_vector*) mem_alloc(db->password_count * 64 * sizeof(DES_bs_vector));
		loaded_hash_gpu_salt = (cl_mem *) mem_alloc(4096 * sizeof(cl_mem));
		zero_buffer = (unsigned int *) mem_calloc((db->password_count - 1) / 32 + 1, sizeof(unsigned int));

		for (i = 0; i < 4096; i++)
			loaded_hash_gpu_salt[i] = (cl_mem)0;

		cracked_hashes_gpu = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * db->password_count * sizeof(DES_bs_vector), NULL, &err);
		if (cracked_hashes_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * db->password_count + 1) * sizeof(unsigned int), NULL, &err);
		if (cmp_out_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((db->password_count - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &err);
		if (bitmap == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		for (i = 0; i < 4096; i++) {
			stored_salt[i] = 0x7fffffff;
			if (krnl[gpu_id][i]) {
				HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][i]), "Error releasing kernel");
				krnl[gpu_id][i] = 0;
			}
		}

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer cmp_out_gpu.");
	}
	else {
		int i, *binary;
		char *ciphertext;

		if (!loaded_hash)
			MEM_FREE(loaded_hash);
		if (!hash_ids)
			MEM_FREE(hash_ids);
		if (!opencl_DES_bs_cracked_hashes)
			MEM_FREE(opencl_DES_bs_cracked_hashes);

		HANDLE_CLERROR(clReleaseMemObject(cmp_out_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(loaded_hash_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(cracked_hashes_gpu), errMsg);
		HANDLE_CLERROR(clReleaseMemObject(bitmap), errMsg);

		num_loaded_hashes = 0;
		while (fmt_opencl_DES.params.tests[num_loaded_hashes].ciphertext) num_loaded_hashes++;

		loaded_hash = (int *) mem_alloc(num_loaded_hashes * sizeof(int) * 2);
		hash_ids     = (unsigned int *) mem_alloc((2 * num_loaded_hashes + 1) * sizeof(unsigned int));
		opencl_DES_bs_cracked_hashes = (DES_bs_vector*) mem_alloc (num_loaded_hashes * 64 * sizeof(DES_bs_vector));
		zero_buffer = (unsigned int *) mem_calloc((num_loaded_hashes - 1) / 32 + 1, sizeof(unsigned int));

		hash_ids[0] = 0;

		cracked_hashes_gpu = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * num_loaded_hashes * sizeof(DES_bs_vector), NULL, &err);
		if (cracked_hashes_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, num_loaded_hashes * sizeof(int) * 2, NULL, &err);
		if (loaded_hash_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * num_loaded_hashes + 1)* sizeof(unsigned int), NULL, &err);
		if (cmp_out_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((num_loaded_hashes - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &err);
		if (bitmap == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		i = 0;
		while (fmt_opencl_DES.params.tests[i].ciphertext) {
			ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[i].ciphertext, 0, &fmt_opencl_DES);
			binary = (int *)fmt_opencl_DES.methods.binary(ciphertext);
			loaded_hash[i] = binary[0];
			loaded_hash[i + num_loaded_hashes] = binary[1];
			i++;
			//fprintf(stderr, "C:%s B:%d %d\n", ciphertext, binary[0], i == num_loaded_hashes );
		}

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], loaded_hash_gpu, CL_TRUE, 0, num_loaded_hashes * sizeof(int) * 2, loaded_hash, 0, NULL, NULL ), "Failed Copy data to gpu");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer cmp_out_gpu.");

		initialized++;
	}
}

static void init_global_variables()
{
	int i;

	opencl_DES_bs_all = (opencl_DES_bs_combined*) mem_alloc(MULTIPLIER * sizeof(opencl_DES_bs_combined));
	opencl_DES_bs_keys = (opencl_DES_bs_transfer*) mem_alloc(MULTIPLIER * sizeof(opencl_DES_bs_transfer));
	index96 = (unsigned int *) mem_calloc(4097, 96 * sizeof(unsigned int));

	krnl = (cl_kernel **) mem_calloc(MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM, sizeof(cl_kernel *));
	for (i = 0; i < MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM; i++)
		krnl[i] = (cl_kernel *) mem_calloc(4097, sizeof(cl_kernel));

	stored_salt = (WORD *) mem_alloc(4096 * sizeof(WORD));
	for (i = 0; i < 4096; i++)
		stored_salt[i] = 0x7fffffff;
}

static void find_best_gws(struct fmt_main *fmt)
{
	struct timeval start, end;
	double savetime;
	long int count = 64;
	double speed = 999999, diff;
	int ccount;

	num_loaded_hashes = 1;
	hash_ids = (unsigned int *) mem_alloc((2 * num_loaded_hashes + 1) * sizeof(int));
	opencl_DES_bs_cracked_hashes = (DES_bs_vector*) mem_alloc(num_loaded_hashes * 64 * sizeof(DES_bs_vector));
	zero_buffer = (unsigned int *) mem_calloc((num_loaded_hashes - 1) / 32 + 1, sizeof(unsigned int));

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer cmp_out_gpu.");

	save_binary = 0;

	gettimeofday(&start, NULL);
	ccount = count * local_work_size * DES_BS_DEPTH;
	des_crypt_25(&ccount, NULL);
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
		ccount = count * local_work_size * DES_BS_DEPTH;
		des_crypt_25(&ccount, NULL);
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
	} while (diff > 0.01);

	fmt -> params.max_keys_per_crypt = count * local_work_size * DES_BS_DEPTH;
	fmt -> params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;

	MEM_FREE(hash_ids);
	MEM_FREE(opencl_DES_bs_cracked_hashes);
	MEM_FREE(zero_buffer);

	hash_ids = NULL;
	opencl_DES_bs_cracked_hashes = NULL;
	zero_buffer = NULL;

	stored_salt[0] = 0x7fffffff;
	HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][0]), "Error releasing kernel");

	save_binary = 1;

	if (options.verbosity > 3)
		fprintf(stderr, "Local worksize (LWS) "Zu", Global worksize (GWS) "Zu"\n", local_work_size, count * local_work_size);
}

static void init_dev()
{
	keys_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, MULTIPLIER * sizeof(opencl_DES_bs_transfer), NULL, &err);
	if(keys_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	index768_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 768 * sizeof(unsigned int), NULL, &err);
	if(index768_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	cracked_hashes_gpu = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * sizeof(DES_bs_vector), NULL, &err);
	if (cracked_hashes_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	K_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, MULTIPLIER * sizeof(DES_bs_vector) * 56, NULL, &err);
	if (K_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 2 * sizeof(int), NULL, &err);
	if(loaded_hash_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 3 * sizeof(unsigned int), NULL, &err);
	if(cmp_out_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(unsigned int), NULL, &err);
	if (bitmap == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][4096], 0, sizeof(cl_mem), &keys_gpu), "Set Kernel Arg FAILED arg1\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][4096], 1, sizeof(cl_mem), &K_gpu), "Set Kernel Arg FAILED arg2\n");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], index768_gpu, CL_TRUE, 0, 768 * sizeof(unsigned int), opencl_DES_bs_index768, 0, NULL, NULL ), "Failed Copy data to gpu");
}

static void modify_src()
{

	  int i = 53, j = 1, tmp;
	  static char digits[10] = {'0','1','2','3','4','5','6','7','8','9'} ;
	  static unsigned int  index[48]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,
					     24,25,26,27,28,29,30,31,32,33,34,35,
					     48,49,50,51,52,53,54,55,56,57,58,59,
					     72,73,74,75,76,77,78,79,80,81,82,83 } ;
	  for (j = 1; j <= 48; j++) {
		tmp = index96[current_salt * 96 + index[j - 1]] / 10;
		if (tmp == 0)
			kernel_source[i + j * 17] = ' ' ;
		else
			kernel_source[i + j * 17] = digits[tmp];
		tmp = index96[current_salt * 96 + index[j - 1]] % 10;
	     ++i;
	     kernel_source[i + j * 17 ] = digits[tmp];
	     ++i;
	  }
}

static void build_salt(WORD salt)
{
	unsigned int new = salt;
	unsigned int old;
	int dst;

	new = salt;
	old = opencl_DES_bs_all[0].salt;
	opencl_DES_bs_all[0].salt = new;

	for (dst = 0; dst < 24; dst++) {
		if ((new ^ old) & 1) {
			DES_bs_vector sp1, sp2;
			int src1 = dst;
			int src2 = dst + 24;
			if (new & 1) {
				src1 = src2;
				src2 = dst;
			}
			sp1 = opencl_DES_bs_all[0].Ens[src1];
			sp2 = opencl_DES_bs_all[0].Ens[src2];
			index96[4096 * 96 + dst] = sp1;
			index96[4096 * 96 + dst + 24] = sp2;
			index96[4096 * 96 + dst + 48] = sp1 + 32;
			index96[4096 * 96 + dst + 72] = sp2 + 32;
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}
	memcpy(&index96[salt * 96], &index96[4096 * 96], 96 * sizeof(unsigned int));
}

static void select_device(struct fmt_main *fmt)
{
	int i;

	if (!local_work_size)
		local_work_size = WORK_GROUP_SIZE;

	opencl_prepare_dev(gpu_id);

	opencl_read_source("$JOHN/kernels/DES_bs_finalize_keys_kernel.cl");
	opencl_build(gpu_id, NULL, 0, NULL);
	krnl[gpu_id][4096] = clCreateKernel(program[gpu_id], "DES_bs_finalize_keys", &err) ;
	if (err) {
		fprintf(stderr, "Create Kernel DES_bs_finalize_keys\n");
		return;
	}

	/* Build dummy kernel for querying */
	opencl_read_source("$JOHN/kernels/DES_bs_kernel_h.cl");
	opencl_build(gpu_id, NULL, 0, NULL);
	krnl[gpu_id][0] = clCreateKernel(program[gpu_id], "DES_bs_25", &err) ;
	if (err) {
		fprintf(stderr, "Create Kernel DES_bs_25\n");
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
	    get_kernel_max_lws(gpu_id, krnl[gpu_id][4096]))
		local_work_size =
			get_kernel_max_lws(gpu_id, krnl[gpu_id][4096]);

	/* ...but ensure GWS is still a multiple of LWS */
	global_work_size = ((global_work_size + local_work_size - 1) /
	                    local_work_size) * local_work_size;

	/* Release dummy kernel. */
	HANDLE_CLERROR(clReleaseKernel(krnl[gpu_id][0]), "Error releasing kernel 0");
	krnl[gpu_id][0] = 0;

	init_dev();

	if (!global_work_size)
		find_best_gws(fmt);
	else {
		if (options.verbosity > 3)
			fprintf(stderr, "Local worksize (LWS) "Zu", Global worksize (GWS) "Zu"\n", local_work_size, global_work_size);
		fmt -> params.max_keys_per_crypt = global_work_size * DES_BS_DEPTH;
		fmt -> params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;
	}

	num_set_keys = fmt -> params.max_keys_per_crypt;

	for (i = 0; i < 4096; i++)
		build_salt(i);
}

static void set_salt(void *salt)
{
	current_salt = *(WORD *)salt;
}

static char *get_key(int index)
{
      get_key_body();
}

static void modify_build_save_restore(int cur_salt, int id_gpu) {
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
	int i;
	static unsigned int section = 1;
	cl_event evnt;
	static size_t N, M;

	if (*pcount != num_set_keys || section) {
		num_set_keys = *pcount;
		section = (((num_set_keys - 1) >> DES_BS_LOG2) + 1);
		M = local_work_size;
		N = ((section - 1) / M + 1) * M;
		N = N > MULTIPLIER ? MULTIPLIER : N;
		section = 0;
	}

	{
		unsigned int found = 0;
		if (stored_salt[current_salt] == current_salt)
			found = 1;

		if (found == 0) {
			modify_build_save_restore(current_salt, gpu_id);
			krnl[gpu_id][current_salt] = clCreateKernel(program[gpu_id], "DES_bs_25", &err) ;
			if (err) {
				fprintf(stderr, "Create Kernel DES_bs_25 FAILED\n");
				return 0;
			}

			HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 0, sizeof(cl_mem), &index768_gpu), "Set Kernel Arg FAILED arg0\n");
			HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 1, sizeof(cl_mem), &K_gpu), "Set Kernel Arg FAILED arg2\n");
			HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 2, sizeof(cl_mem), &cracked_hashes_gpu), "Set Kernel Arg FAILED arg3\n");
			HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 3, sizeof(cl_mem), &loaded_hash_gpu), "Set Kernel krnl Arg 4 :FAILED") ;
			HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 5, sizeof(cl_mem), &cmp_out_gpu), "Set Kernel Arg krnl FAILED arg6\n");
			HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 6, sizeof(cl_mem), &bitmap), "Set Kernel Arg krnl FAILED arg7\n");

			stored_salt[current_salt] = current_salt;
		}
	}

	if (opencl_DES_bs_keys_changed) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], keys_gpu, CL_TRUE, 0, MULTIPLIER * sizeof(opencl_DES_bs_transfer), opencl_DES_bs_keys, 0, NULL, NULL ), "Failed Copy data to gpu");
		err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][4096], 1, NULL, &N, &M, 0, NULL, &evnt);
		HANDLE_CLERROR(err, "Enque Kernel Failed");
		clWaitForEvents(1, &evnt);
		clReleaseEvent(evnt);
		opencl_DES_bs_keys_changed = 0;
	}

	if (salt) {
		static unsigned int num_loaded_hashes_salt[4096];
		num_loaded_hashes = (salt -> count);
		if (num_loaded_hashes_salt[current_salt] != salt->count) {
			int *bin;
			struct db_password *pw;
			i = 0;
			pw = salt -> list;
			do {
				if (!(bin = (int *)pw->binary))
					continue;
				loaded_hash[i] = bin[0] ;
				loaded_hash[i + salt -> count] = bin[1];
				i++ ;
				//printf("%d %d\n", i++, bin[0]);
			} while ((pw = pw -> next)) ;

			//printf("%d\n",loaded_hash[salt->count-1 + salt -> count]);
			if (num_loaded_hashes_salt[current_salt] < salt->count) {
				if (loaded_hash_gpu_salt[current_salt] != (cl_mem)0)
					HANDLE_CLERROR(clReleaseMemObject(loaded_hash_gpu_salt[current_salt]), "Error releasing Memory Object");
				loaded_hash_gpu_salt[current_salt] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 2 * sizeof(int) * num_loaded_hashes, NULL, &err);
				HANDLE_CLERROR(err, "Failed to Create Buffer loaded_hash_gpu_salt");
			}
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], loaded_hash_gpu_salt[current_salt], CL_TRUE, 0, num_loaded_hashes * sizeof(int) * 2, loaded_hash, 0, NULL, NULL ), "Failed Copy data to gpu");
			num_loaded_hashes_salt[current_salt] = salt ->count;
		}
		HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 3, sizeof(cl_mem), &loaded_hash_gpu_salt[current_salt]), "Set Kernel krnl Arg 4 :FAILED");
	}

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][current_salt], 4, sizeof(int), &num_loaded_hashes), "Set Kernel krnl Arg 5 :FAILED") ;

	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][current_salt], 1, NULL, &N, &M, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");

	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Write FAILED\n");

	if (hash_ids[0] > num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, (2 * num_loaded_hashes + 1) * sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cracked_hashes_gpu, CL_TRUE, 0, hash_ids[0] * 64 * sizeof(DES_bs_vector), opencl_DES_bs_cracked_hashes, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], bitmap, CL_TRUE, 0, ((num_loaded_hashes - 1)/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer bitmap.");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer cmp_out_gpu.");
	}

	return 32 * hash_ids[0];
}

void opencl_DES_bs_h_register_functions(struct fmt_main *fmt)
{
	fmt->methods.done = &clean_all_buffers;
	fmt->methods.reset = &reset;
	fmt->methods.set_salt = &set_salt;
	fmt->methods.get_key = &get_key;
	fmt->methods.crypt_all = &des_crypt_25;

	opencl_DES_bs_init_global_variables = &init_global_variables;
	opencl_DES_bs_select_device = select_device;
}
#endif /* HAVE_OPENCL */
