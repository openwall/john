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
#include "memdbg.h"

#if !HARDCODE_SALT
typedef unsigned WORD vtype;

opencl_DES_bs_transfer *opencl_DES_bs_data;
DES_bs_vector *B = NULL;

static cl_kernel krnl[MAX_PLATFORMS * MAX_DEVICES_PER_PLATFORM][4096];
static cl_int err;
static cl_mem index768_gpu, index96_gpu, opencl_DES_bs_data_gpu, B_gpu, cmp_out_gpu, loaded_hash_gpu, bitmap;
static int set_salt = 0;
static   WORD current_salt;
static int *loaded_hash = NULL;
static unsigned int num_loaded_hashes, *cmp_out = NULL;

void DES_opencl_clean_all_buffer()
{
	const char* errMsg = "Release Memory Object :Failed";
	MEM_FREE(opencl_DES_bs_all);
	MEM_FREE(opencl_DES_bs_data);
	MEM_FREE(B);
	MEM_FREE(loaded_hash);
	MEM_FREE(cmp_out);
	HANDLE_CLERROR(clReleaseMemObject(index768_gpu),errMsg);
	HANDLE_CLERROR(clReleaseMemObject(index96_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(opencl_DES_bs_data_gpu), errMsg);
	HANDLE_CLERROR(clReleaseMemObject(B_gpu), errMsg);
	clReleaseMemObject(cmp_out_gpu);
	clReleaseMemObject(loaded_hash_gpu);
	clReleaseMemObject(bitmap);
	clReleaseKernel(krnl[gpu_id][0]);
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
	               "Error releasing Program");
}

void opencl_DES_reset(struct db_main *db) {

	if (db) {
		MEM_FREE(loaded_hash);
		MEM_FREE(cmp_out);
		MEM_FREE(B);

		clReleaseMemObject(cmp_out_gpu);
		clReleaseMemObject(loaded_hash_gpu);
		clReleaseMemObject(B_gpu);
		clReleaseMemObject(bitmap);

		loaded_hash = (int *) mem_alloc((db->password_count) * sizeof(int) * 2);
		cmp_out     = (unsigned int *) mem_alloc((2 * db->password_count + 1) * sizeof(unsigned int));
		B = (DES_bs_vector*) mem_alloc(db->password_count * 64 * sizeof(DES_bs_vector));

		B_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 64 * db->password_count * sizeof(DES_bs_vector), NULL, &err);
		if (B_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (db->password_count)*sizeof(int)*2, NULL, &err);
		if (loaded_hash_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * db->password_count + 1) * sizeof(unsigned int), NULL, &err);
		if (cmp_out_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, ((db->password_count - 1) / 32 + 1) * sizeof(unsigned int), NULL, &err);
		if (bitmap == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");
	}
	else {
		int i, *binary;
		char *ciphertext;

		if (!loaded_hash)
			MEM_FREE(loaded_hash);
		if (!cmp_out)
			MEM_FREE(cmp_out);
		if (!B)
			MEM_FREE(B);

		clReleaseMemObject(cmp_out_gpu);
		clReleaseMemObject(loaded_hash_gpu);
		clReleaseMemObject(B_gpu);
		clReleaseMemObject(bitmap);

		fprintf(stderr, "ciphertext:%s\n", fmt_opencl_DES.params.tests[0].ciphertext);

		num_loaded_hashes = 0;
		while (fmt_opencl_DES.params.tests[num_loaded_hashes].ciphertext) num_loaded_hashes++;

		loaded_hash = (int *) mem_alloc(num_loaded_hashes * sizeof(int) * 2);
		cmp_out     = (unsigned int *) mem_alloc((2 * num_loaded_hashes + 1) * sizeof(unsigned int));
		B = (DES_bs_vector*) mem_alloc (num_loaded_hashes * 64 * sizeof(DES_bs_vector));

		B_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 64 * num_loaded_hashes * sizeof(DES_bs_vector), NULL, &err);
		if (B_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, num_loaded_hashes * sizeof(int) * 2, NULL, &err);
		if (loaded_hash_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (2 * num_loaded_hashes + 1)* sizeof(unsigned int), NULL, &err);
		if (cmp_out_gpu == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, ((num_loaded_hashes - 1) / 32 + 1) * sizeof(unsigned int), NULL, &err);
		if (bitmap == (cl_mem)0)
			HANDLE_CLERROR(err, "Create Buffer FAILED\n");

		i = 0;
		while (fmt_opencl_DES.params.tests[i].ciphertext) {
			ciphertext = fmt_opencl_DES.methods.split(fmt_opencl_DES.params.tests[i].ciphertext, 0, &fmt_opencl_DES);
			binary = (int *)fmt_opencl_DES.methods.binary(ciphertext);
			loaded_hash[i] = binary[0];
			loaded_hash[i + num_loaded_hashes] = binary[1];
			i++;
			fprintf(stderr, "C:%s B:%d %d\n", ciphertext, binary[0], i == num_loaded_hashes );
		}

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], loaded_hash_gpu, CL_TRUE, 0, num_loaded_hashes * sizeof(int) * 2, loaded_hash, 0, NULL, NULL ), "Failed Copy data to gpu");
	}
}

void opencl_DES_bs_init_global_variables() {
	opencl_DES_bs_all = (opencl_DES_bs_combined*) mem_alloc (MULTIPLIER * sizeof(opencl_DES_bs_combined));
	opencl_DES_bs_data = (opencl_DES_bs_transfer*) mem_alloc (MULTIPLIER * sizeof(opencl_DES_bs_transfer));
}


int opencl_DES_bs_cmp_all(WORD *binary, int count)
{
	return 1;
}

inline int opencl_DES_bs_cmp_one(void *binary, int index)
{
	return opencl_DES_bs_cmp_one_b((WORD*)binary, 32, index);
}

int opencl_DES_bs_cmp_one_b(WORD *binary, int count, int index)
{
	int bit;
	DES_bs_vector *b;
	int depth;
	unsigned int section;

	section = index >> DES_BS_LOG2;
	index &= (DES_BS_DEPTH - 1);
	depth = index >> 3;
	index &= 7;

	b = (DES_bs_vector *)((unsigned char *)&B[section * 64] + depth);

#define GET_BIT \
	((unsigned WORD)*(unsigned char *)&b[0] >> index)

	for (bit = 0; bit < 31; bit++, b++)
		if ((GET_BIT ^ (binary[0] >> bit)) & 1)
			return 0;

	for (; bit < count; bit++, b++)
		if ((GET_BIT ^ (binary[bit >> 5] >> (bit & 0x1F))) & 1)
			return 0;
#undef GET_BIT
	return 1;
}

static void find_best_gws(struct fmt_main *fmt)
{
	struct timeval start, end;
	double savetime;
	long int count = 64;
	double speed = 999999, diff;
	int ccount;

	gettimeofday(&start, NULL);
	ccount = count * local_work_size * DES_BS_DEPTH;
	num_loaded_hashes = 1;
	cmp_out = (unsigned int *) malloc((2 * num_loaded_hashes + 1) * sizeof(int));
	B = (DES_bs_vector*) mem_alloc (num_loaded_hashes * 64 * sizeof(DES_bs_vector));
	opencl_DES_bs_crypt_25(&ccount, NULL);
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
		opencl_DES_bs_crypt_25(&ccount, NULL);
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

	fmt -> params.max_keys_per_crypt = count * local_work_size * DES_BS_DEPTH;
	fmt -> params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;

	MEM_FREE(cmp_out);
	MEM_FREE(B);
	cmp_out = NULL;
	B = NULL;

	if (options.verbosity > 2)
		fprintf(stderr, "Local worksize (LWS) %zu, Global worksize (GWS) %zu\n", local_work_size, count * local_work_size);
}

void DES_bs_select_device(struct fmt_main *fmt)
{
	const char *errMsg;

	if (!local_work_size)
		local_work_size = WORK_GROUP_SIZE;

	opencl_init("$JOHN/kernels/DES_bs_kernel.cl", gpu_id, NULL);

	krnl[gpu_id][0] = clCreateKernel(program[gpu_id], "DES_bs_25_b", &err) ;
	if (err) {
		fprintf(stderr, "Create Kernel DES_bs_25_b FAILED\n");
		return ;
	}

	/* Cap LWS at kernel limit */
	if (local_work_size > 64)
		local_work_size = 64;

	if (local_work_size >
	    get_kernel_max_lws(gpu_id, krnl[gpu_id][0]))
		local_work_size =
			get_kernel_max_lws(gpu_id, krnl[gpu_id][0]);

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
	opencl_DES_bs_data_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, MULTIPLIER * sizeof(opencl_DES_bs_transfer), NULL, &err);
	if (opencl_DES_bs_data_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	index768_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 768 * sizeof(unsigned int), NULL, &err);
	if (index768_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	index96_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 96 * sizeof(unsigned int), NULL, &err);
	if (index96_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	B_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 64 * sizeof(DES_bs_vector), NULL, &err);
	if (B_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	loaded_hash_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 2 * sizeof(int), NULL, &err);
	if(loaded_hash_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	cmp_out_gpu = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 3 * sizeof(unsigned int), NULL, &err);
	if(cmp_out_gpu == (cl_mem)0)
		HANDLE_CLERROR(err, errMsg);

	bitmap = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(unsigned int), NULL, &err);
	if (bitmap == (cl_mem)0)
		HANDLE_CLERROR(err, "Create Buffer FAILED\n");

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 0, sizeof(cl_mem), &index768_gpu), "Set Kernel Arg FAILED arg0\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 1, sizeof(cl_mem), &index96_gpu), "Set Kernel Arg FAILED arg1\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 2, sizeof(cl_mem), &opencl_DES_bs_data_gpu), "Set Kernel Arg FAILED arg2\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 3, sizeof(cl_mem), &B_gpu), "Set Kernel Arg FAILED arg4\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 4, sizeof(cl_mem), &loaded_hash_gpu), "Set Kernel krnl Arg 4 :FAILED") ;
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 6, sizeof(cl_mem), &cmp_out_gpu), "Set Kernel Arg krnl FAILED arg6\n");
	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 7, sizeof(cl_mem), &bitmap), "Set Kernel Arg krnl FAILED arg7\n");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], index768_gpu, CL_TRUE, 0, 768*sizeof(unsigned int), index768, 0, NULL, NULL ), "Failed Copy data to gpu");

	if (!global_work_size)
		find_best_gws(fmt);
	else {
		if (options.verbosity > 2)
			fprintf(stderr, "Local worksize (LWS) %zu, Global worksize (GWS) %zu\n", local_work_size, global_work_size);
		fmt -> params.max_keys_per_crypt = global_work_size * DES_BS_DEPTH;
		fmt -> params.min_keys_per_crypt = local_work_size * DES_BS_DEPTH;
	}
}

void opencl_DES_bs_set_salt(WORD salt)
{
	unsigned int new = salt, section = 0;
	unsigned int old;
	int dst;

	for (section = 0; section < MAX_KEYS_PER_CRYPT / DES_BS_DEPTH; section++) {
	new = salt;
	old = opencl_DES_bs_all[section].salt;
	opencl_DES_bs_all[section].salt = new;
	}
	section = 0;
	current_salt = salt ;
	for (dst = 0; dst < 24; dst++) {
		if ((new ^ old) & 1) {
			DES_bs_vector sp1, sp2;
			int src1 = dst;
			int src2 = dst + 24;
			if (new & 1) {
				src1 = src2;
				src2 = dst;
			}
			sp1 = opencl_DES_bs_all[section].Ens[src1];
			sp2 = opencl_DES_bs_all[section].Ens[src2];

			index96[dst] = sp1;
			index96[dst + 24] = sp2;
			index96[dst + 48] = sp1 + 32;
			index96[dst + 72] = sp2 + 32;
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}

	set_salt = 1;
}

char *opencl_DES_bs_get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	unsigned int section, block;
	unsigned char *src;
	char *dst;

	if (cmp_out == NULL || cmp_out[0] == 0 ||
	    index > 32 * cmp_out[0] || cmp_out[0] > num_loaded_hashes)
		section = index / DES_BS_DEPTH;
	else
		section = cmp_out[2 * (index/DES_BS_DEPTH) + 1];

	if (section > global_work_size) {
		fprintf(stderr, "Get key error! %d %d\n", section, index);
		section = 0;
	}
	block  = index % DES_BS_DEPTH;

	init_t();

	src = opencl_DES_bs_all[section].pxkeys[block];
	dst = out;
	while (dst < &out[PLAINTEXT_LENGTH] && (*dst = *src)) {
		src += sizeof(DES_bs_vector) * 8;
		dst++;
	}
	*dst = 0;

	return out;
}
int opencl_DES_bs_crypt_25(int *pcount, struct db_salt *salt)
{
	int keys_count = *pcount, i;
	unsigned int section = 0, keys_count_multiple;
	cl_event evnt;
	size_t N, M;

	if (keys_count % DES_BS_DEPTH == 0)
		keys_count_multiple = keys_count;
	else
		keys_count_multiple = (keys_count / DES_BS_DEPTH + 1) * DES_BS_DEPTH;

	section = keys_count_multiple / DES_BS_DEPTH;
	M = local_work_size;

	if (section % local_work_size != 0)
		N = (section / local_work_size + 1) * local_work_size ;
	else
		N = section;

	if (set_salt == 1) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], index96_gpu, CL_TRUE, 0, 96 * sizeof(unsigned int), index96, 0, NULL, NULL), "Failed Copy data to gpu");
		HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 3, sizeof(cl_mem), &B_gpu), "Set Kernel Arg FAILED arg4\n");
		HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 4, sizeof(cl_mem), &loaded_hash_gpu), "Set Kernel krnl Arg 4 :FAILED");
		HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 6, sizeof(cl_mem), &cmp_out_gpu), "Set Kernel Arg krnl FAILED arg6\n");
		HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 7, sizeof(cl_mem), &bitmap), "Set Kernel Arg krnl FAILED arg7\n");
		set_salt = 0;
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], opencl_DES_bs_data_gpu, CL_TRUE, 0, MULTIPLIER * sizeof(opencl_DES_bs_transfer), opencl_DES_bs_data, 0, NULL, NULL ), "Failed Copy data to gpu");

	if (salt) {
		int *bin;
		struct db_password *pw;

		i = 0;
		pw = salt -> list;
		do {
			  bin = (int *)pw -> binary;
			  loaded_hash[i] = bin[0] ;
			  loaded_hash[i + salt -> count] = bin[1];
			  i++ ;
			  //printf("%d %d\n", i++, bin[0]);
		} while ((pw = pw -> next)) ;
		num_loaded_hashes = (salt -> count);
		//printf("%d\n",loaded_hash[salt->count-1 + salt -> count]);
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], loaded_hash_gpu, CL_TRUE, 0, (salt -> count) * sizeof(int) * 2, loaded_hash, 0, NULL, NULL ), "Failed Copy data to gpu");
	}

	HANDLE_CLERROR(clSetKernelArg(krnl[gpu_id][0], 5, sizeof(int), &num_loaded_hashes), "Set Kernel krnl Arg 5 :FAILED") ;

	err = clEnqueueNDRangeKernel(queue[gpu_id], krnl[gpu_id][0], 1, NULL, &N, &M, 0, NULL, &evnt);
	HANDLE_CLERROR(err, "Enque Kernel Failed");

	clWaitForEvents(1, &evnt);
	clReleaseEvent(evnt);

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, sizeof(unsigned int), cmp_out, 0, NULL, NULL), "Write FAILED\n");

	if (cmp_out[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cmp_out_gpu, CL_TRUE, 0, (2 * num_loaded_hashes + 1) * sizeof(unsigned int), cmp_out, 0, NULL, NULL), "Write FAILED\n");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], B_gpu, CL_TRUE, 0, cmp_out[0] * 64 * sizeof(DES_bs_vector), B, 0, NULL, NULL), "Write FAILED\n");
	}

	return 32 * cmp_out[0];
}
#endif
#endif /* HAVE_OPENCL */
