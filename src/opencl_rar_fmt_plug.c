/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 * magnum added -p mode support, using code based on libclamav
 * and OMP, AES-NI and OpenCL support.
 *
 * This software is Copyright (c) 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum and it is hereby released to the general public
 * under the following terms:
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

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_rar;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_rar);
#else

#include <string.h>
#if AC_BUILT
#include "autoconfig.h"
#endif
#if _MSC_VER || __MINGW32__ || __MINGW64__ || __CYGWIN__ || HAVE_WINDOWS_H
#include "win32_memmap.h"
#ifndef __CYGWIN__
#include "mmap-windows.c"
#elif defined HAVE_MMAP
#include <sys/mman.h>
#endif
#elif defined(HAVE_MMAP)
#include <sys/mman.h>
#endif
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
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
#include "common-opencl.h"
#include "config.h"
#include "jumbo.h"

#define FORMAT_LABEL		"rar-opencl"
#define FORMAT_NAME		"RAR3"
#define ALGORITHM_NAME		"SHA1 OpenCL AES"
#ifdef DEBUG
#define BENCHMARK_COMMENT	" (length 1-16)"
#else
#define BENCHMARK_COMMENT	" (length 4)"
#endif
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	22 /* Max. currently supported is 22 */
#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define BINARY_SIZE		0
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define SALT_SIZE		sizeof(rarfile*)
#define SALT_ALIGN		sizeof(rarfile*)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static const char * warn[] = {
	"key xfer: "  ,  ", len xfer: "   , ", init: " , ", loop: " ,
	", final: ", ", key xfer: ", ", iv xfer: "
};

static int split_events[] = { 3, -1, -1 };

#define STEP			0
#define SEED			256

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

#define ITERATIONS		0x40000
#define HASH_LOOPS		0x4000 // Max. 0x4000

static int new_keys;
static struct fmt_main *self;

static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_OutputBuf, cl_round, cl_aes_key, cl_aes_iv;
static cl_mem pinned_saved_key, pinned_saved_len, pinned_salt, pinned_aes_key, pinned_aes_iv;
static cl_kernel RarInit, RarFinal;

#define RAR_OPENCL_FORMAT
#include "rar_common.c"

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int i;
	int bench_len = strlen(self->params.tests[0].plaintext) * 2;

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

	cl_OutputBuf = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_int) * 5 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");

	cl_round = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");

	// aes_key is uchar[16] but kernel treats it as uint[4]
	pinned_aes_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_aes_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_uint) * 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	aes_key = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_aes_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * 4 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory aes_key");
	memset(aes_key, 0, 16 * gws);

	pinned_aes_iv = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_aes_iv = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	aes_iv = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_aes_iv, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 16 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory aes_iv");
	memset(aes_iv, 0, 16 * gws);

	HANDLE_CLERROR(clSetKernelArg(RarInit, 0, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(RarInit, 1, sizeof(cl_mem), (void*)&cl_round), "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_round), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem), (void*)&cl_aes_iv), "Error setting argument 5");

	HANDLE_CLERROR(clSetKernelArg(RarFinal, 0, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(RarFinal, 1, sizeof(cl_mem), (void*)&cl_OutputBuf), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(RarFinal, 2, sizeof(cl_mem), (void*)&cl_aes_key), "Error setting argument 2");

	cracked = mem_alloc(sizeof(*cracked) * gws);
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return MIN(
		MIN(autotune_get_task_max_work_group_size(FALSE, 0, RarInit),
		    autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel)),
		autotune_get_task_max_work_group_size(FALSE, 0, RarFinal));
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_aes_key, aes_key, 0, NULL, NULL), "Error Unmapping aes_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_aes_iv, aes_iv, 0, NULL, NULL), "Error Unmapping aes_iv");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(cl_aes_key), "Release aes_key");
		HANDLE_CLERROR(clReleaseMemObject(cl_aes_iv), "Release aes_iv");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release saved_key");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_len), "Release saved_len");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release salt");
		HANDLE_CLERROR(clReleaseMemObject(pinned_aes_key), "Release aes_key");
		HANDLE_CLERROR(clReleaseMemObject(pinned_aes_iv), "Release aes_iv");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_key), "Release saved_key");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_len), "Release saved_len");
		HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release salt");
		HANDLE_CLERROR(clReleaseMemObject(cl_OutputBuf), "Release OutputBuf");

		MEM_FREE(cracked);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(RarInit), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(RarFinal), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		MEM_FREE(unpack_data);

		autotuned--;
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
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts), "-DPLAINTEXT_LENGTH=%u -DHASH_LOOPS=0x%x", PLAINTEXT_LENGTH, HASH_LOOPS);
		opencl_init("$JOHN/kernels/rar_kernel.cl", gpu_id, build_opts);

		// create kernels to execute
		RarInit = clCreateKernel(program[gpu_id], "RarInit", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		crypt_kernel = clCreateKernel(program[gpu_id], "RarHashLoop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		RarFinal = clCreateKernel(program[gpu_id], "RarFinal", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
		                       warn, 3, self,
		                       create_clobj, release_clobj,
		                       UNICODE_LENGTH + sizeof(cl_int) * 14, 0, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, ITERATIONS, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int k;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (ocl_autotune_running || new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * gws, saved_key, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer saved_key");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * gws, saved_len, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer saved_len");
		new_keys = 0;
	}
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarInit, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");
	for (k = 0; k < (ocl_autotune_running ? 1 : (ITERATIONS / HASH_LOOPS)); k++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], RarFinal, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");
	// read back aes key & iv
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_key, CL_FALSE, 0, 16 * gws, aes_key, 0, NULL, multi_profilingEvent[5]), "failed in reading key back");
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_iv, CL_TRUE, 0, 16 * gws, aes_iv, 0, NULL, multi_profilingEvent[6]), "failed in reading iv back");

	if (!ocl_autotune_running)
		check_rar(count);

	return count;
}

struct fmt_main fmt_ocl_rar = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
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
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
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

#endif /* HAVE_OPENCL */
