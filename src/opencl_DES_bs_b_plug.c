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

#define PADDING 	2048

static cl_kernel **kernels;
static cl_mem buffer_map, buffer_raw_keys, buffer_cracked_hashes, buffer_bs_keys, buffer_hash_ids, buffer_bitmap_dupe, *buffer_uncracked_hashes = NULL, *buffer_processed_salts = NULL;
static unsigned int *hash_ids = NULL, *num_uncracked_hashes = NULL;
static WORD *marked_salts = NULL, current_salt = 0;
static unsigned int *zero_buffer = NULL;

static int des_crypt_25(int *pcount, struct db_salt *salt);

static void create_clobj_kpc(size_t gws)
{
	opencl_DES_bs_all = (opencl_DES_bs_combined *) mem_alloc((gws + PADDING) * sizeof(opencl_DES_bs_combined));
	opencl_DES_bs_keys = (opencl_DES_bs_transfer *) mem_alloc((gws + PADDING) * sizeof(opencl_DES_bs_transfer));

	buffer_raw_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, (gws + PADDING) * sizeof(opencl_DES_bs_transfer), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_raw_keys failed.\n");

	buffer_bs_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (gws + PADDING) * sizeof(DES_bs_vector) * 56, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_bs_keys failed.\n");
}

static void release_clobj_kpc()
{
	if (buffer_raw_keys != (cl_mem)0) {
		MEM_FREE(opencl_DES_bs_all);
		MEM_FREE(opencl_DES_bs_keys);
		HANDLE_CLERROR(clReleaseMemObject(buffer_raw_keys), "Release buffer_raw_keys failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bs_keys), "Release buffer_bs_keys failed.\n");
		buffer_raw_keys = (cl_mem)0;
	}
}

static void create_clobj(unsigned int *num_uncracked_hashes, unsigned int max_uncracked_hashes)
{
	int i;

	buffer_uncracked_hashes = (cl_mem *) mem_alloc(4096 * sizeof(cl_mem));
	buffer_processed_salts = (cl_mem *) mem_alloc(4096 * sizeof(cl_mem));
	marked_salts = (WORD *) mem_alloc(4096 * sizeof(WORD));

	for (i = 0; i < 4096; i++) {
		buffer_uncracked_hashes[i] = (cl_mem)0;
		marked_salts[i] = 0x7fffffff;
	}

	for (i = 0; i < 4096; i++) {
		if (!num_uncracked_hashes[i]) continue;
		buffer_uncracked_hashes[i] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 2 * sizeof(int) * num_uncracked_hashes[i], NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_uncracked_hashes failed.\n");
		fprintf(stderr, "Create buf: %d\n", i);
	}

	for (i = 0; i < 4096; i++) {
		buffer_processed_salts[i] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 96 * sizeof(unsigned int), NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Create buffer_processed_salts failed.\n");
	}

	opencl_DES_bs_init_index();

	buffer_map = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 768 * sizeof(unsigned int), opencl_DES_bs_index768, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_map.\n");

	buffer_cracked_hashes = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 64 * max_uncracked_hashes * sizeof(DES_bs_vector), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_cracked_hashes failed.\n");

	zero_buffer = (unsigned int *) mem_calloc((max_uncracked_hashes - 1) / 32 + 1, sizeof(unsigned int));

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((max_uncracked_hashes - 1) / 32 + 1) * sizeof(unsigned int), zero_buffer, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_bitmap_dupe failed.\n");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * max_uncracked_hashes + 1) * sizeof(unsigned int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Create buffer_hash_ids failed.\n");

	hash_ids = (unsigned int *) mem_calloc((2 * max_uncracked_hashes + 1), sizeof(unsigned int));
	opencl_DES_bs_cracked_hashes = (DES_bs_vector*) mem_alloc(max_uncracked_hashes * 64 * sizeof(DES_bs_vector));
}

static void release_clobj()
{
	if (buffer_hash_ids != (cl_mem)0) {
		int i;

		MEM_FREE(hash_ids);
		MEM_FREE(opencl_DES_bs_cracked_hashes);
		MEM_FREE(zero_buffer);
		MEM_FREE(marked_salts);

		HANDLE_CLERROR(clReleaseMemObject(buffer_map), "Release buffer_map failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Release buffer_hash_ids failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_cracked_hashes), "Release buffer_cracked_hashes failed.\n");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Release buffer_bitmap_dupe failed.\n");

		if (buffer_uncracked_hashes) {
		for (i = 0; i < 4096; i++)
			if (buffer_uncracked_hashes[i] != (cl_mem)0)
				HANDLE_CLERROR(clReleaseMemObject(buffer_uncracked_hashes[i]), "Release buffer_uncracked_hashes failed.\n");
		MEM_FREE(buffer_uncracked_hashes);
		}
		if (buffer_processed_salts) {
		for (i = 0; i < 4096; i++)
			if (buffer_processed_salts[i] != (cl_mem)0)
				HANDLE_CLERROR(clReleaseMemObject(buffer_processed_salts[i]), "Release buffer_processed_salts failed.\n");
		MEM_FREE(buffer_processed_salts);
		}
		buffer_hash_ids = (cl_mem)0;
	}
}

static void clean_all_buffers()
{
	int i;

	release_clobj();
	release_clobj_kpc();

	for( i = 0; i < 2; i++)
		if (kernels[gpu_id][i])
		HANDLE_CLERROR(clReleaseKernel(kernels[gpu_id][i]), "Error releasing kernel");

	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Error releasing Program");

	for (i = 0; i < MAX_GPU_DEVICES; i++)
		MEM_FREE(kernels[i]);

	MEM_FREE(kernels);
	MEM_FREE(num_uncracked_hashes);
}

/* First call must use salt = 0, to initialize processed_salt. */
static void build_salt(WORD salt)
{
	unsigned int new;
	static unsigned int old = 0xffffff;
	static unsigned int processed_salt[96];
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
			processed_salt[dst] = sp1;
			processed_salt[dst + 24] = sp2;
			processed_salt[dst + 48] = sp1 + 32;
			processed_salt[dst + 72] = sp2 + 32;
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}
	old = salt;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_processed_salts[salt], CL_TRUE, 0, 96 * sizeof(unsigned int), processed_salt, 0, NULL, NULL), "Failed to write buffer buffer_processed_salts.\n");
}

static void reset(struct db_main *db)
{
	static int initialized;

	if (initialized) {
		int i;
		struct db_salt *salt;
		unsigned int max_uncracked_hashes;
		int *uncracked_hashes;

		release_clobj_kpc();
		release_clobj();
		memset(num_uncracked_hashes, 0, 4096 * sizeof(unsigned int));

		max_uncracked_hashes = 0;
		salt = db->salts;
		do {
			struct db_password *pw = salt->list;
			do {
				num_uncracked_hashes[*(int *)(salt->salt)]++;
			} while ((pw = pw -> next));
			if (salt->count > max_uncracked_hashes)
				max_uncracked_hashes = salt->count;
		} while((salt = salt->next));

		create_clobj(num_uncracked_hashes, max_uncracked_hashes);
		create_clobj_kpc(global_work_size);

		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][1], 0, sizeof(cl_mem), &buffer_raw_keys), "Failed setting kernel argument buffer_raw_keys, kernel DES_bs_finalize_keys.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][1], 1, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_finalize_keys.\n");

		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 0, sizeof(cl_mem), &buffer_map), "Failed setting kernel argument buffer_map, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 2, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 3, sizeof(cl_mem), &buffer_cracked_hashes), "Failed setting kernel argument buffer_cracked_hashes, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 6, sizeof(cl_mem), &buffer_hash_ids), "Failed setting kernel argument buffer_hash_ids, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 7, sizeof(cl_mem), &buffer_bitmap_dupe), "Failed setting kernel argument buffer_bitmap_dupe, kernel DES_bs_25.\n");

		for (i = 0; i < global_work_size; i++)
			opencl_DES_bs_init(i);

		build_salt(0);

		uncracked_hashes = (int *) mem_calloc(2 * max_uncracked_hashes, sizeof(int));
		salt = db->salts;
		do {
			struct db_password *pw = salt->list;
			int bin_salt;

			bin_salt = *(int *)(salt->salt);
			i = 0;
			do {
				int *binary;
				if (!(binary = (int *)pw->binary))
					continue;
				uncracked_hashes[i] = binary[0];
				uncracked_hashes[i + salt->count] = binary[1];
				i++;
			} while ((pw = pw -> next));
			build_salt(bin_salt);
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_uncracked_hashes[bin_salt], CL_TRUE, 0, (salt->count) * sizeof(int) * 2, uncracked_hashes, 0, NULL, NULL ), "Failed to write buffer buffer_uncracked_hashes.\n");
		} while((salt = salt->next));

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "Failed to write buffer buffer_hash_ids.\n");
		hash_ids[0] = 0;
		MEM_FREE(uncracked_hashes);
	}
	else {
		int i, *binary;
		char *ciphertext;
		unsigned int tot_uncracked_hashes;
		unsigned int *ctr;

		tot_uncracked_hashes = 0;
		while (fmt_opencl_DES.params.tests[tot_uncracked_hashes].ciphertext) {
			int salt;
			ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[tot_uncracked_hashes].ciphertext, 0, &fmt_opencl_DES);
			salt = *(int *)fmt_opencl_DES.methods.salt(ciphertext);
			fprintf(stderr, "Salt:%d\n", salt);
			num_uncracked_hashes[salt]++;
			tot_uncracked_hashes++;
		}


		create_clobj(num_uncracked_hashes, tot_uncracked_hashes);
		create_clobj_kpc(global_work_size);

		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][1], 0, sizeof(cl_mem), &buffer_raw_keys), "Failed setting kernel argument buffer_raw_keys, kernel DES_bs_finalize_keys.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][1], 1, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_finalize_keys.\n");

		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 0, sizeof(cl_mem), &buffer_map), "Failed setting kernel argument buffer_map, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 2, sizeof(cl_mem), &buffer_bs_keys), "Failed setting kernel argument buffer_bs_keys, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 3, sizeof(cl_mem), &buffer_cracked_hashes), "Failed setting kernel argument buffer_cracked_hashes, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 6, sizeof(cl_mem), &buffer_hash_ids), "Failed setting kernel argument buffer_hash_ids, kernel DES_bs_25.\n");
		HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 7, sizeof(cl_mem), &buffer_bitmap_dupe), "Failed setting kernel argument buffer_bitmap_dupe, kernel DES_bs_25.\n");

		for (i = 0; i < global_work_size; i++)
			opencl_DES_bs_init(i);

		build_salt(0);

		hash_ids[0] = 0;
		i = 0;
		ctr = (unsigned int *) mem_calloc(4096, sizeof(unsigned int));
		while (fmt_opencl_DES.params.tests[i].ciphertext) {
			int salt;
			ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[i].ciphertext, 0, &fmt_opencl_DES);
			binary = (int *)fmt_opencl_DES.methods.binary(ciphertext);
			salt = *(int *)fmt_opencl_DES.methods.salt(ciphertext);
			build_salt(salt);
			fprintf(stderr, "Salt:%d\n", salt);
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_uncracked_hashes[salt], CL_TRUE, ctr[salt] * sizeof(int), sizeof(int), &binary[0], 0, NULL, NULL ), "Failed to write buffer buffer_uncracked_hashes.\n");
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_uncracked_hashes[salt], CL_TRUE, (ctr[salt] + num_uncracked_hashes[salt]) * sizeof(int), sizeof(int), &binary[1], 0, NULL, NULL ), "Failed to write buffer buffer_uncracked_hashes.\n");
			i++;
			ctr[salt]++;
			//fprintf(stderr, "C:%s B:%d %d\n", ciphertext, binary[0], i == num_loaded_hashes );
		}
		MEM_FREE(ctr);

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "Failed to write buffer buffer_hash_ids.\n");

		initialized++;
	}
}

static void init_global_variables()
{
	int i;

	kernels = (cl_kernel **) mem_calloc(MAX_GPU_DEVICES, sizeof(cl_kernel *));
	for (i = 0; i < MAX_GPU_DEVICES; i++)
		kernels[i] = (cl_kernel *) mem_calloc(2, sizeof(cl_kernel));

	num_uncracked_hashes = (unsigned int *) mem_calloc(4096, sizeof(unsigned int));
}

static void select_device(struct fmt_main *fmt)
{
	opencl_prepare_dev(gpu_id);

	opencl_read_source("$JOHN/kernels/DES_bs_finalize_keys_kernel.cl");
	opencl_build(gpu_id, NULL, 0, NULL);
	kernels[gpu_id][1] = clCreateKernel(program[gpu_id], "DES_bs_finalize_keys", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel DES_bs_finalize_keys.\n");

	opencl_read_source("$JOHN/kernels/DES_bs_kernel.cl");
	opencl_build(gpu_id, NULL, 0, NULL);
	kernels[gpu_id][0] = clCreateKernel(program[gpu_id], "DES_bs_25_b", &ret_code);
	HANDLE_CLERROR(ret_code, "Failed creating kernel DES_bs_25_b.\n");

	local_work_size = 64;
	global_work_size = 131072;

	fmt -> params.max_keys_per_crypt = global_work_size * DES_BS_DEPTH;
	fmt -> params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;
}

static void set_salt(void *salt)
{
	current_salt = *(WORD *)salt;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int section, block;
	unsigned char *src;
	char *dst;

	if (hash_ids == NULL || hash_ids[0] == 0 ||
	    index > 32 * hash_ids[0] || hash_ids[0] > num_uncracked_hashes[current_salt])
		section = 0;
	else
		section = hash_ids[2 * (index/DES_BS_DEPTH) + 1];

	if (section > global_work_size) {
		fprintf(stderr, "Get key error! %d %zu\n", section,
			global_work_size);
		section = 0;
	}
	block  = index % DES_BS_DEPTH;

	src = opencl_DES_bs_all[section].pxkeys[block];
	dst = out;
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {
		src += sizeof(DES_bs_vector) * 8;
		dst++;
	}
	*dst = 0;

	return out;
}


static int des_crypt_25(int *pcount, struct db_salt *salt)
{
	cl_event evnt;
	const int count = (*pcount + DES_BS_DEPTH - 1) >> DES_BS_LOG2;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t current_gws = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;

	if (opencl_DES_bs_keys_changed) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_raw_keys, CL_TRUE, 0, current_gws * sizeof(opencl_DES_bs_transfer), opencl_DES_bs_keys, 0, NULL, NULL ), "Failed to write buffer buffer_raw_keys.\n");

		ret_code = clEnqueueNDRangeKernel(queue[gpu_id], kernels[gpu_id][1], 1, NULL, &current_gws, lws, 0, NULL, &evnt);
		HANDLE_CLERROR(ret_code, "Enque kernel DES_bs_finalize_keys failed.\n");
		clWaitForEvents(1, &evnt);
		clReleaseEvent(evnt);

		opencl_DES_bs_keys_changed = 0;
	}

	if (salt) {
		if (num_uncracked_hashes[current_salt] != salt->count) {
			int i, *bin, *uncracked_hashes;
			struct db_password *pw;

			uncracked_hashes = (int *) mem_calloc(2 * (salt -> count), sizeof(int));
			num_uncracked_hashes[current_salt] = salt ->count;
			i = 0;
			pw = salt -> list;
			do {
				if (!(bin = (int *)pw->binary))
					continue;
				uncracked_hashes[i] = bin[0];
				uncracked_hashes[i + salt -> count] = bin[1];
				i++;
				//printf("%d %d\n", i++, bin[0]);
			} while ((pw = pw -> next));

			if (num_uncracked_hashes[current_salt] < salt->count) {
				if (buffer_uncracked_hashes[current_salt] != (cl_mem)0)
					HANDLE_CLERROR(clReleaseMemObject(buffer_uncracked_hashes[current_salt]), "Release buffer_uncracked_hashes failed.\n");
				buffer_uncracked_hashes[current_salt] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 2 * sizeof(int) * num_uncracked_hashes[current_salt], NULL, &ret_code);
				HANDLE_CLERROR(ret_code, "Create buffer_uncracked_hashes failed.\n");
			}

			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_uncracked_hashes[current_salt], CL_TRUE, 0, num_uncracked_hashes[current_salt] * sizeof(int) * 2, uncracked_hashes, 0, NULL, NULL ), "Failed to write buffer buffer_uncracked_hashes.\n");
			fprintf(stderr, "Execute.\n");
			MEM_FREE(uncracked_hashes);
		}

		fprintf(stderr, "ExecSalt:%d\n", *(int *)(salt->salt));
	}

	HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 1, sizeof(cl_mem), &buffer_processed_salts[current_salt]), "Failed setting kernel argument buffer_processed_salts, kernel DES_bs_25.\n");
	HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 4, sizeof(cl_mem), &buffer_uncracked_hashes[current_salt]), "Failed setting kernel argument buffer_uncracked_hashes, kernel DES_bs_25.\n");
	HANDLE_CLERROR(clSetKernelArg(kernels[gpu_id][0], 5, sizeof(int), &num_uncracked_hashes[current_salt]), "Failed setting kernel argument num_uncracked_hashes, kernel DES_bs_25.\n");

	ret_code = clEnqueueNDRangeKernel(queue[gpu_id], kernels[gpu_id][0], 1, NULL, &current_gws, lws, 0, NULL, &evnt);
	HANDLE_CLERROR(ret_code, "Enque kernel DES_bs_25 failed.\n");

	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Failed to read buffer buffer_hash_ids.\n");
	fprintf(stderr, "Hash ID0: %d\n", hash_ids[0]);

	if (hash_ids[0] > num_uncracked_hashes[current_salt]) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (2 * num_uncracked_hashes[current_salt] + 1) * sizeof(unsigned int), hash_ids, 0, NULL, NULL), "Failed to read buffer buffer_hash_ids.\n");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_cracked_hashes, CL_TRUE, 0, hash_ids[0] * 64 * sizeof(DES_bs_vector), opencl_DES_bs_cracked_hashes, 0, NULL, NULL), "Failed to read buffer buffer_cracked_hashes.\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_TRUE, 0, ((num_uncracked_hashes[current_salt] - 1)/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "Failed to write buffer buffer_bitmap_dupe.\n");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "Failed to write buffer buffer_hash_ids.\n");
	}

	return 32 * hash_ids[0];
}

void opencl_DES_bs_b_register_functions(struct fmt_main *fmt)
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
