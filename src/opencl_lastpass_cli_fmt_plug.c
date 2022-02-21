/*
 * This software is Copyright (c) 2017 Dhiru Kholia <kholia at kth.se> and it
 * is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * salt length increase. HAS to match pbkdf2_hmac_sha256_kernel.cl code
 *  Now uses a common header file.  Dec 2017, JimF.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_lastpass_cli;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_lastpass_cli);
#else

#include <string.h>

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "aes.h"
#include "lastpass_cli_common.h"
#include "opencl_common.h"

#define FORMAT_LABEL            "lpcli-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(*cur_salt)
#define SALT_ALIGN              sizeof(int)

#define HASH_LOOPS              (13*71) // factors 13, 13, 71
#define ITERATIONS              12000

#include "../run/opencl/opencl_pbkdf2_hmac_sha256.h"

typedef struct {
	salt_t pbkdf2;
	uint8_t iv[16];
} lpcli_salt_t;

static pass_t *host_pass;			      /** plain ciphertexts **/
static lpcli_salt_t *host_salt;			      /** salt **/
static cl_int cl_error;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel split_kernel, final_kernel;
static struct fmt_main *self;

static int new_keys;
static struct custom_salt *cur_salt;
static uint32_t (*crypt_out)[BINARY_SIZE * 2 / sizeof(uint32_t)];

#define STEP			0
#define SEED			1024

static const char * warn[] = {
        "xfer: ",  ", init: ", ", crypt: ", ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static void release_clobj(void);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	release_clobj();

#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)\
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);\
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	host_pass = mem_calloc(kpc, sizeof(pass_t));
	crypt_out = mem_calloc(kpc, sizeof(*crypt_out));
	host_salt = mem_calloc(1, sizeof(lpcli_salt_t));

	mem_in = CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
	                        "Cannot allocate mem in");
	mem_salt = CLCREATEBUFFER(CL_RO, sizeof(lpcli_salt_t),
	                          "Cannot allocate mem salt");
	mem_out = CLCREATEBUFFER(CL_WO, kpc * sizeof(crack_t),
	                         "Cannot allocate mem out");
	mem_state = CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
	                           "Cannot allocate mem state");

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");

	CLKERNELARG(final_kernel, 0, mem_out, "Error while setting mem_out");
	CLKERNELARG(final_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(final_kernel, 2, mem_state, "Error while setting mem_state");
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, split_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
	return s;
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");

		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(crypt_out);
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
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%u",
		         HASH_LOOPS, PLAINTEXT_LENGTH);
		opencl_init("$JOHN/opencl/lastpass_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel =
			clCreateKernel(program[gpu_id], "pbkdf2_sha256_init", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], "pbkdf2_sha256_loop", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		final_kernel =
			clCreateKernel(program[gpu_id], "lastpass_cli_final", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating final kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
	                       2, self, create_clobj, release_clobj,
	                       sizeof(state_t), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ITERATIONS, 0, 200);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel 1");
		HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel 2");
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel 3");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;

	memcpy(host_salt->pbkdf2.salt, cur_salt->salt, cur_salt->salt_length);
	host_salt->pbkdf2.length = cur_salt->salt_length;
	host_salt->pbkdf2.rounds = cur_salt->iterations;
	memcpy(host_salt->iv, cur_salt->iv, 16);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(lpcli_salt_t), host_salt, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	int loops = (host_salt->pbkdf2.rounds + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	if (new_keys) {
		// Copy data to gpu
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in,
			CL_FALSE, 0, global_work_size * sizeof(pass_t), host_pass, 0,
			NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], split_kernel,
			1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel,
		1, NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[3]), "Run final kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out,
		CL_TRUE, 0, global_work_size * sizeof(*crypt_out), crypt_out, 0,
		NULL, multi_profilingEvent[4]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	int saved_len = MIN(strlen(key), PLAINTEXT_LENGTH);

	memcpy(host_pass[index].v, key, saved_len);
	host_pass[index].length = saved_len;
	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[host_pass[index].length] = 0;
	return ret;
}

struct fmt_main fmt_opencl_lastpass_cli = {
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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		lastpass_cli_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		lastpass_cli_common_valid,
		fmt_default_split,
		lastpass_cli_common_get_binary,
		lastpass_cli_common_get_salt,
		{
			lastpass_cli_common_iteration_count,
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
		fmt_default_clear_keys,
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
