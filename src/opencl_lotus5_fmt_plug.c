/*
 * This software is Copyright (c) 2014 Sayantan Datta <std2048 at gmail dot com>
 * and Copyright (c) 2014-2016 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on CPU version by Jeff Fay, bartavelle and Solar Designer.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_lotus5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_lotus5);
#else

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "opencl_common.h"
#include "../run/opencl/opencl_lotus5_fmt.h"
#include "options.h"

/*preprocessor constants that John The Ripper likes*/
#define FORMAT_LABEL                   "lotus5-opencl"
#define FORMAT_NAME                    "Lotus Notes/Domino 5"
#define ALGORITHM_NAME                 "OpenCL"
#define BENCHMARK_COMMENT              ""
#define BENCHMARK_LENGTH               0x107
#define CIPHERTEXT_LENGTH              32
#define SALT_SIZE                      0
#define BINARY_ALIGN                   MEM_ALIGN_WORD
#define SALT_ALIGN                     1
#define MIN_KEYS_PER_CRYPT             1
#define MAX_KEYS_PER_CRYPT             1
#define KEY_SIZE_IN_BYTES              sizeof(lotus5_key)

/*A struct used for JTR's benchmarks*/
static struct fmt_tests tests[] = {
  {"06E0A50B579AD2CD5FFDC48564627EE7", "secret"},
  {"355E98E7C7B59BD810ED845AD0FD2FC4", "password"},
  {"CD2D90E8E00D8A2A63A81F531EA8A9A3", "lotus"},
  {"69D90B46B1AC0912E5CCF858094BBBFC", "dirtydog"},
  {NULL}
};

/*Some more JTR variables*/
static cl_uint *crypt_key;
static lotus5_key *saved_key;
static struct fmt_main *self;

static cl_mem cl_tx_keys, cl_tx_binary;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t max_lws = get_kernel_max_lws(gpu_id, crypt_kernel);

	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			max_lws : 1;
	return max_lws;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	size_t mem_alloc_sz;

	release_clobj();

	mem_alloc_sz = KEY_SIZE_IN_BYTES * gws;
	cl_tx_keys = clCreateBuffer(context[gpu_id],
				    CL_MEM_READ_ONLY,
			            mem_alloc_sz, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed to create buffer cl_tx_keys.");

	mem_alloc_sz = BINARY_SIZE * gws;
	cl_tx_binary = clCreateBuffer(context[gpu_id],
				      CL_MEM_WRITE_ONLY,
			              mem_alloc_sz, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed to create buffer cl_tx_binary.");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0,
				      sizeof(cl_mem), &cl_tx_keys),
		                      "Failed to set kernel argument 0, cl_tx_keys.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1,
				      sizeof(cl_mem), &cl_tx_binary),
		                      "Failed to set kernel argument 1, cl_tx_binary.");

	crypt_key = mem_calloc(gws, BINARY_SIZE);
	saved_key = mem_calloc(gws, KEY_SIZE_IN_BYTES);
}

static void release_clobj(void)
{
	if (crypt_key) {
		HANDLE_CLERROR(clReleaseMemObject(cl_tx_keys),
			       "Failed to release buffer cl_tx_keys.");
		HANDLE_CLERROR(clReleaseMemObject(cl_tx_binary),
			       "Failed to release buffer cl_tx_binary.");

		MEM_FREE(saved_key);
		MEM_FREE(crypt_key);
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		opencl_init("$JOHN/opencl/lotus5_kernel.cl", gpu_id, NULL);

		crypt_kernel = clCreateKernel(program[gpu_id], "lotus5", &ret_code);
		HANDLE_CLERROR(ret_code, "Failed to create kernel lotus5.");

	}

	size_t gws_limit = get_max_mem_alloc_size(gpu_id) / KEY_SIZE_IN_BYTES;

	if (gws_limit & (gws_limit - 1)) {
		get_power_of_two(gws_limit);
		gws_limit >>= 1;
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       KEY_SIZE_IN_BYTES, gws_limit, db);

	// Auto tune execution from shared/included code.
	autotune_run_extra(self, 1, gws_limit, 200, CL_TRUE);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel),
		               "Release kernel lotus5.");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
		               "Release Program");

		program[gpu_id] = NULL;
	}
}

/*Utility function to convert hex to bin */
static void *get_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;
	for (i = 0; i < BINARY_SIZE; i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	return ((void *) realcipher);
}

/*Another function required by JTR: decides whether we have a valid
 * ciphertext */
static int valid (char *ciphertext, struct fmt_main *self)
{
	int i;

	for (i = 0; i < CIPHERTEXT_LENGTH; i++)
		if (!(((ciphertext[i] >= '0') && (ciphertext[i] <= '9'))
		      || ((ciphertext[i] >= 'A') && (ciphertext[i] <= 'F'))))
		{
			return 0;
		}
	return !ciphertext[i];
}

/*sets the value of saved_key so we can play with it*/
static void set_key (char *key, int index)
{
	int len = strlen(key);

	memset(saved_key[index].v.c, 0, PLAINTEXT_LENGTH);
	memcpy(saved_key[index].v.c, key, len);
	saved_key[index].l = len;
}

/*retrieves the saved key; used by JTR*/
static char *get_key (int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int len = saved_key[index].l;

	memcpy(out, saved_key[index].v.c, len);
	out[len] = 0;

	return out;
}

static int cmp_all (void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key + index * BINARY_SIZE_IN_uint32_t, BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one (void *binary, int index)
{
	return !memcmp(binary, crypt_key + index * BINARY_SIZE_IN_uint32_t, BINARY_SIZE);
}

static int cmp_exact (char *source, int index)
{
	return 1;
}

/*the last public function; generates ciphertext*/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t mem_cpy_sz;
	size_t N, *M;

	M = local_work_size ? &local_work_size : NULL;
	N = GET_NEXT_MULTIPLE(count, local_work_size);

	mem_cpy_sz = N * KEY_SIZE_IN_BYTES;
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
					    cl_tx_keys, CL_FALSE, 0,
					    mem_cpy_sz, saved_key,
					    0, NULL, multi_profilingEvent[0]),
					    "Failed to write buffer cl_tx_keys.");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					      crypt_kernel, 1,
					      NULL, &N, M, 0, NULL, multi_profilingEvent[1]),
					      "Failed to enqueue kernel lotus5.");

	mem_cpy_sz = count * BINARY_SIZE;
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id],
					   cl_tx_binary, CL_TRUE, 0,
					   mem_cpy_sz, crypt_key, 0,
					   NULL, multi_profilingEvent[2]),
					   "Failed to read buffer cl_tx_binary.");

	return count;
}

static int get_hash_0(int index) { return crypt_key[index * BINARY_SIZE_IN_uint32_t] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index * BINARY_SIZE_IN_uint32_t] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index * BINARY_SIZE_IN_uint32_t] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index * BINARY_SIZE_IN_uint32_t] & PH_MASK_3; }
static int get_hash_4(int index) { return crypt_key[index * BINARY_SIZE_IN_uint32_t] & PH_MASK_4; }
static int get_hash_5(int index) { return crypt_key[index * BINARY_SIZE_IN_uint32_t] & PH_MASK_5; }
static int get_hash_6(int index) { return crypt_key[index * BINARY_SIZE_IN_uint32_t] & PH_MASK_6; }

/* C's version of a class specifier */
struct fmt_main fmt_opencl_lotus5 = {
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
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
