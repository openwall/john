/*
 * KeePass OpenCL cracker for JtR.
 *
 * This software is Copyright (c) 2018 magnum,
 * Copyright (c) 2016 Fist0urs <eddy.maaalou at gmail.com>,
 * Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis),
 * Copyright (c) 2012 Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_KeePass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_KeePass);
#else

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "keepass_common.h"
#include "opencl_common.h"

#define FORMAT_LABEL            "KeePass-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA256 AES/Twofish/ChaCha OpenCL"

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} password;

typedef struct {
	uint32_t cracked;
} result;

typedef struct {
	uint32_t iterations;
	uint8_t  hash[32];
	uint8_t  akey[724]; /* sizeof(AES_CTX) on GPU side */
} keepass_state;

static int new_keys;
static cl_int cl_error;
static password *inbuffer;
static result *outbuffer;
static cl_mem mem_in, mem_salt, mem_state, mem_out;
static struct fmt_main *self;
#define kernel_loop crypt_kernel
static cl_kernel kernel_init, kernel_final;

static size_t insize, outsize, saltsize;

#define STEP			0
#define SEED			256

#define HASH_LOOPS		100

#define LOOP_COUNT		((keepass_salt->key_transf_rounds + HASH_LOOPS - 1) / HASH_LOOPS)

static int split_events[] = { 2, -1, -1 };

static const char *warn[] = {
	"xfer: ",  ", init: ",  ", loop: ",  ", final: ", ", xfer: "
};

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s = autotune_get_task_max_work_group_size(FALSE, 0, kernel_init);

	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, kernel_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, kernel_final));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	size_t statesize;

	release_clobj();

	statesize = sizeof(keepass_state) * gws;
	insize = sizeof(password) * gws;
	outsize = sizeof(result) * gws;
	saltsize = sizeof(keepass_salt_t);

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
		&cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
		NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_state =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
			statesize, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem state");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
		&cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	// Set kernel args
	HANDLE_CLERROR(clSetKernelArg(kernel_init, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(kernel_init, 1, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(kernel_init, 2, sizeof(mem_state),
		&mem_state), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(kernel_loop, 0, sizeof(mem_state),
		&mem_state), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(kernel_final, 0, sizeof(mem_state),
		&mem_state), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(kernel_final, 1, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(kernel_final, 2, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (outbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
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
		char build_opts[96];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DHASH_LOOPS=%d -DMAX_CONT_SIZE=%d",
		         PLAINTEXT_LENGTH, HASH_LOOPS, MAX_CONT_SIZE);
		opencl_init("$JOHN/opencl/keepass_kernel.cl", gpu_id,  build_opts);

		kernel_init =
			clCreateKernel(program[gpu_id], "keepass_init", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		kernel_loop =
			clCreateKernel(program[gpu_id], "keepass_loop", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		kernel_final =
			clCreateKernel(program[gpu_id], "keepass_final", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn, 2, self,
	                       create_clobj, release_clobj,
	                       sizeof(keepass_state), 0, db);

	// iterations for benchmarking
	int iter = db->salts->cost[0];

	// Auto tune execution from shared/included code, max. 200ms total.
	autotune_run(self, iter, 0, 200);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(kernel_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(kernel_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(kernel_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void clear_keys(void)
{
	memset(inbuffer, 0, insize);
}

static void set_key(char *key, int index)
{
	uint32_t length = strlen(key);

	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);

	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint32_t length = inbuffer[index].length;

	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static void set_salt(void *salt)
{
	keepass_salt = salt;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, keepass_salt, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		kernel_init, 1, NULL,
		&global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
			kernel_loop, 1, NULL,
			&global_work_size, lws, 0, NULL,
			multi_profilingEvent[2]), "Run kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		kernel_final, 1, NULL,
		&global_work_size, lws, 0, NULL,
		multi_profilingEvent[3]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[4]),
		"Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (outbuffer[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return outbuffer[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_ocl_KeePass = {
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
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
		{
			"iteration count",
			"version",
			"algorithm [0=AES 1=TwoFish 2=ChaCha]",
		},
		{ FORMAT_TAG },
		keepass_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		keepass_valid,
		fmt_default_split,
		fmt_default_binary,
		keepass_get_salt,
		{
			keepass_iteration_count,
			keepass_version,
			keepass_algorithm,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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
