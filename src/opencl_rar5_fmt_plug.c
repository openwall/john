/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>,
 * Copyright (c) 2013 Dhiru Kholia and
 * Copyright (c) 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * http://www.rarlab.com/technote.htm
 *
 * $rar5$<salt_len>$<salt>$<iter_log2>$<iv>$<pswcheck_len>$<pswcheck>
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_rar5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_rar5);
#else

#include <ctype.h>
#include <string.h>
#include <assert.h>

//#define DEBUG

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "stdint.h"
#include "formats.h"
#include "options.h"
#include "common-opencl.h"
#include "rar5_common.h"

#define SIZE_SALT50 16
#define SIZE_PSWCHECK 8
#define SIZE_PSWCHECK_CSUM 4
#define SIZE_INITV 16

#define FORMAT_LABEL		"RAR5-opencl"
#define FORMAT_NAME		""
#define FORMAT_TAG  		"$rar5$"
#define TAG_LENGTH  		6
#define ALGORITHM_NAME		"PBKDF2-SHA256 OpenCL"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define DEFAULT_LWS		64
#define DEFAULT_GWS		1024
#define STEP			0
#define SEED			1024

#define BINARY_ALIGN		4
#define SALT_ALIGN		1

#define PLAINTEXT_LENGTH	55
#define BINARY_SIZE		SIZE_PSWCHECK
#define SALT_SIZE		sizeof(struct custom_salt)

#define KERNEL_NAME		"pbkdf2_sha256_kernel"
#define SPLIT_KERNEL_NAME	"pbkdf2_sha256_loop"

#define HASH_LOOPS		(3*13*29) // factors 3, 13, 29, 29
#define ITERATIONS		(32800 - 1)

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[8];
} crack_t;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	uint32_t rounds;
} salt_t;

typedef struct {
	uint32_t ipad[8];
	uint32_t opad[8];
	uint32_t hash[8];
	uint32_t W[8];
	uint32_t rounds;
} state_t;

static pass_t *host_pass;			      /** plain ciphertexts **/
static salt_t *host_salt;			      /** salt **/
static crack_t *host_crack;			      /** hash**/
static cl_int cl_error;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel split_kernel;
static struct fmt_main *self;

static const char * warn[] = {
        "P xfer: "  ,  ", S xfer: "   , ", init: " , ", crypt: ",
        ", res xfer: "
};

static int split_events[] = { 3, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static void create_clobj(size_t kpc, struct fmt_main *self)
{
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)\
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);\
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	host_pass = mem_calloc(kpc, sizeof(pass_t));
	host_crack = mem_calloc(kpc, sizeof(crack_t));
	host_salt = mem_calloc(1, sizeof(salt_t));

	mem_in =
		CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
		"Cannot allocate mem in");
	mem_salt =
		CLCREATEBUFFER(CL_RO, sizeof(salt_t), "Cannot allocate mem salt");
	mem_out =
		CLCREATEBUFFER(CL_WO, kpc * sizeof(crack_t),
		"Cannot allocate mem out");
	mem_state =
		CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
		"Cannot allocate mem state");

	crypt_out = mem_alloc(sizeof(*crypt_out) * kpc);

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
	CLKERNELARG(split_kernel, 1 ,mem_out, "Error while setting mem_out");
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, split_kernel));
	return s;
}

static void release_clobj(void)
{
	if (crypt_out) {
		MEM_FREE(crypt_out);

		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");

		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(host_crack);
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%u",
		         HASH_LOOPS, PLAINTEXT_LENGTH);

		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha256_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel =
			clCreateKernel(program[gpu_id], KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
		                       3, self, create_clobj, release_clobj,
		                       sizeof(state_t), 0, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, ITERATIONS, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel 1");
		HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel 2");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
		               "Release Program");

		autotuned--;
	}
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	host_salt->rounds = cur_salt->iterations + 32; // We only need PswCheck
	host_salt->length = cur_salt->saltlen;
	memcpy(host_salt->salt, cur_salt->salt, cur_salt->saltlen);
#if 0
	fprintf(stderr, "Setting salt iter %d len %d ", host_salt->rounds, host_salt->length);
	dump_stuff(host_salt->salt, SIZE_SALT50);
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	int loops = host_salt->rounds / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	loops += host_salt->rounds % HASH_LOOPS > 0;

#if 0
	printf("crypt_all(%d)\n", count);
	printf("LWS = %d, GWS = %d\n", (int)local_work_size, (int)global_work_size);
#endif

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in,
		CL_FALSE, 0, global_work_size * sizeof(pass_t), host_pass, 0,
		NULL, multi_profilingEvent[0]), "Copy data to gpu");
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(salt_t), host_salt, 0, NULL, multi_profilingEvent[1]),
	    "Copy salt to gpu");

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
		1, NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[2]), "Run kernel");

	for(i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], split_kernel,
			1, NULL, &global_work_size, lws, 0, NULL,
			multi_profilingEvent[3]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}
	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out,
		CL_TRUE, 0, global_work_size * sizeof(crack_t), host_crack, 0,
		NULL, multi_profilingEvent[4]), "Copy result back");

	// special wtf processing [SIC]
	for (i = 0; i < count; i++) {
		crypt_out[i][0] = host_crack[i].hash[0];
		crypt_out[i][1] = host_crack[i].hash[1];
		crypt_out[i][0] ^= host_crack[i].hash[2];
		crypt_out[i][1] ^= host_crack[i].hash[3];
		crypt_out[i][0] ^= host_crack[i].hash[4];
		crypt_out[i][1] ^= host_crack[i].hash[5];
		crypt_out[i][0] ^= host_crack[i].hash[6];
		crypt_out[i][1] ^= host_crack[i].hash[7];
	}

	return count;
}

static void set_key(char *key, int index)
{
	int saved_len = MIN(strlen(key), PLAINTEXT_LENGTH);

	memcpy(host_pass[index].v, key, saved_len);
	host_pass[index].length = saved_len;
#if 0
	fprintf(stderr, "%s(%s)\n", __FUNCTION__, key);
#endif
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
	return ret;
}

struct fmt_main fmt_ocl_rar5 = {
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
	1,
	1,
	FMT_CASE | FMT_8_BIT,
	{
		"iteration count",
	},
	tests
}, {
	init,
	done,
	reset,
	fmt_default_prepare,
	valid,
	fmt_default_split,
	get_binary,
	get_salt,
	{
		iteration_count,
	},
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
	set_salt,
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
}};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
