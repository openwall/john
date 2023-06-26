/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 * magnum added -p mode support, using code based on libclamav
 * and OMP, AES-NI and OpenCL support.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012-2020, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 * Huge thanks to Marc Bevand <m.bevand (at) gmail.com> for releasing unrarhp
 * (http://www.zorinaq.com/unrarhp/) and documenting the RAR encryption scheme.
 * This patch is made possible by unrarhp's documentation.
 *
 * http://anrieff.net/ucbench/technical_qna.html is another useful reference
 * for RAR encryption scheme.
 *
 * Thanks also to Pavel Semjanov for crucial help with Huffman table checks.
 *
 * For type = 0 for files encrypted with "rar -hp ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(partial-file-contents):type::::archive_name
 *
 * For type = 1 for files encrypted with "rar -p ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*archive_name*offset-for-ciphertext*method:type::file_name
 *
 * or (inlined binary)
 *
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*1*hex(full encrypted file)*method:type::file_name
 *
 */

#if HAVE_OPENCL

#if AC_BUILT
#include "autoconfig.h"
#endif
#include "arch.h"

#if ARCH_ALLOWS_UNALIGNED || __ARM_FEATURE_UNALIGNED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rar;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rar);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "sha.h"
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "dyna_salt.h"
#include "memory.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "johnswap.h"
#include "unrar.h"
#include "opencl_common.h"
#include "config.h"
#include "jumbo.h"

#define FORMAT_LABEL		"rar-opencl"
#define FORMAT_NAME		"RAR3"
#define ALGORITHM_NAME		"SHA1 OpenCL AES"

/*
 * This format's speed is *highly* dependant on pw length (longer = slower)
 *
 * cRARk and hashcat use 5-char passwords for GPU benchmark, so we do too
 */
#define BENCHMARK_COMMENT	" (length 5)"
#define BENCHMARK_LENGTH	0x105

#define PLAINTEXT_LENGTH	22 /* Max. currently supported is 22 */
#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

typedef struct {
	uint round;
	union {
		unsigned char c[20]; /* When finished key.w[0..3] is the AES key, key[4] is early reject flag */
		unsigned int w[5];
	} key;
	unsigned char iv[16];
} rar_out;

static const char * warn[] = {
	"key xfer: ",  ", len xfer: ",  ", init: ",  ", loop: ",  ", final: ",  ", post: "
};

static int split_events[] = { 3, -1, -1 };

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

#define ITERATIONS		0x40000
#define HASH_LOOPS		0x4000 // Max. 0x4000

static struct fmt_main *self;

static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_OutputBuf, cl_FileBuf;
static cl_mem pinned_saved_key, pinned_saved_len, pinned_salt;
static cl_kernel RarInit, RarFinal, RarCheck;

static rar_out *output;
static size_t max_blob_size;
static int salt_single;

#define RAR_OPENCL_FORMAT
#include "rar_common.c"

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int i;
	int bench_len = strlen(self->params.tests[0].plaintext) * 2;

	release_clobj();

	pinned_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, UNICODE_LENGTH * gws, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, UNICODE_LENGTH * gws, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_key = (unsigned char*)clEnqueueMapBuffer(queue[gpu_id], pinned_saved_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, UNICODE_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_key");
	memset(saved_key, 0, UNICODE_LENGTH * gws);

	pinned_saved_len = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_saved_len = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_len = (unsigned int*)clEnqueueMapBuffer(queue[gpu_id], pinned_saved_len, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_int) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_len");
	for (i = 0; i < gws; i++)
		saved_len[i] = bench_len;

	pinned_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 8, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 8, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_salt = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 8, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_salt");
	memset(saved_salt, 0, 8);

	cl_OutputBuf = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(rar_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");

	cl_FileBuf = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, max_blob_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");

	HANDLE_CLERROR(clSetKernelArg(RarInit, 0, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 4");

	HANDLE_CLERROR(clSetKernelArg(RarFinal, 0, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(RarFinal, 1, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(RarCheck, 0, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(RarCheck, 1, sizeof(cl_mem), (void*)&cl_FileBuf), "Error setting argument 1");

	output = mem_alloc(sizeof(rar_out) * gws);
	cracked = mem_alloc(sizeof(*cracked) * gws);
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s = autotune_get_task_max_work_group_size(FALSE, 0, RarInit);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, RarFinal));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, RarCheck));
	return s;
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release saved_key");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_len), "Release saved_len");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release salt");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_key), "Release saved_key");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_len), "Release saved_len");
		HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release salt");
		HANDLE_CLERROR(clReleaseMemObject(cl_OutputBuf), "Release OutputBuf");
		HANDLE_CLERROR(clReleaseMemObject(cl_FileBuf), "Release FileBuf");

		MEM_FREE(output);
		MEM_FREE(cracked);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(RarInit), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(RarFinal), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(RarCheck), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		MEM_FREE(unpack_data);

		program[gpu_id] = NULL;
	}
}

static void clear_keys(void)
{
	memset(saved_len, 0, sizeof(int) * global_work_size);
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_prepare_dev(gpu_id);

#ifdef DEBUG
	self->params.benchmark_comment = " (1-16 characters)";
#endif
	/* We mimic the lengths of cRARk for comparisons */
	if (!cpu(device_info[gpu_id])) {
#ifndef DEBUG
		self->params.benchmark_comment = " (length 5)";
#endif
		self->params.tests = gpu_tests;
	}

#if defined (_OPENMP)
	threads = omp_get_max_threads();
#endif /* _OPENMP */

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);

	unpack_data = mem_calloc(threads, sizeof(unpack_data_t));

	/* CRC-32 table init, do it before we start multithreading */
	{
		CRC32_t crc;
		CRC32_Init(&crc);
	}
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts), "-DPLAINTEXT_LENGTH=%u -DHASH_LOOPS=0x%x", PLAINTEXT_LENGTH, HASH_LOOPS);
		opencl_init("$JOHN/opencl/rar_kernel.cl", gpu_id, build_opts);

		// create kernels to execute
		RarInit = clCreateKernel(program[gpu_id], "RarInit", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		crypt_kernel = clCreateKernel(program[gpu_id], "RarHashLoop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		RarFinal = clCreateKernel(program[gpu_id], "RarFinal", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		RarCheck = clCreateKernel(program[gpu_id], "RarCheck", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
	                       warn, 3, self,
	                       create_clobj, release_clobj,
	                       UNICODE_LENGTH, 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ITERATIONS, 0, 200);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int k;
	struct db_password *pw;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	salt_single = (salt->count == 1);

	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * gws, saved_key, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer saved_key");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * gws, saved_len, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer saved_len");

		new_keys = 0;
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarInit, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");

	WAIT_INIT(gws)
	for (k = 0; k < (ocl_autotune_running ? 1 : (ITERATIONS / HASH_LOOPS)); k++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		WAIT_UPDATE
		opencl_process_event();
	}
	WAIT_DONE

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarFinal, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

	/*
	 * Walk the blobs for this salt, early-rejecting on GPU
	 */
	if ((pw = salt->list))
	do {
		fmt_data *blob = pw->binary;
		rar_file *file = blob->blob;

		WAIT_INIT(gws)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_FileBuf, CL_FALSE, 0,
		                                    sizeof(rar_file) + file->gpu_size, file, 0, NULL, NULL),
		               "failed in reading result");
		BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarCheck, 1, NULL, &gws, lws, 0, NULL,
		                                      multi_profilingEvent[5]),
		               "failed in clEnqueueNDRangeKernel");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_OutputBuf, CL_FALSE, 0, sizeof(rar_out) * gws, output, 0,
		                                   NULL, NULL), "failed in reading result");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
		WAIT_UPDATE
		WAIT_DONE

		for (k = 0; k < count; k++)
			if (output[k].key.w[4])
				return count;
	} while ((pw = pw->next));

	return 0;
}

static int cmp_all(void *binary, int count)
{
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);
	fmt_data *blob = binary;
	rar_file *file = blob->blob;
	int index;

	if (count && !salt_single) {
		WAIT_INIT(gws)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_FileBuf, CL_FALSE, 0,
		                                    sizeof(rar_file) + file->gpu_size, file, 0, NULL, NULL),
		               "failed in reading result");
		BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarCheck, 1, NULL, &gws, lws, 0, NULL, NULL),
		               "failed in clEnqueueNDRangeKernel");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_OutputBuf, CL_FALSE, 0, sizeof(rar_out) * gws, output, 0,
		                                   NULL, NULL), "failed in reading result");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
		WAIT_UPDATE
		WAIT_DONE
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (output[index].key.w[4])
			check_rar(file, index, output[index].key.c, output[index].iv);
		else
			cracked[index] = 0;
	}

	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

struct fmt_main fmt_opencl_rar = {
{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_OMP | FMT_BLOB | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		cpu_tests // Changed in init if GPU
	},{
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#else
#if !defined(FMT_EXTERNS_H) && !defined(FMT_REGISTERS_H)
#ifdef __GNUC__
#warning ": target system requires aligned memory access, RAR OpenCL format disabled:"
#elif _MSC_VER
#pragma message(": target system requires aligned memory access, RAR OpenCL format disabled:")
#endif
#endif

#endif /* ARCH_ALLOWS_UNALIGNED || __ARM_FEATURE_UNALIGNED */
#endif /* HAVE_OPENCL */
