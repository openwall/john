/*
 * This software is Copyright (c) 2017 Dhiru Kholia <kholia at kth.se> and
 * Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net> and it is
 * hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * salt length increase. HAS to match pbkdf2_hmac_sha256_kernel.cl code
 *  Now uses a common header file.  Dec 2017, JimF.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_ethereum;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_ethereum);
#else

#include <string.h>

#include "misc.h"
#include "arch.h"
#include "ethereum_common.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "opencl_common.h"

#define FORMAT_NAME             "Ethereum Wallet"
#define FORMAT_LABEL            "ethereum-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA256 Keccak OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(*cur_salt)
#define SALT_ALIGN              sizeof(uint64_t)

#define HASH_LOOPS              (3*3*7*19)
#define ITERATIONS              262144

struct fmt_tests opencl_ethereum_tests[] = {
        // https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition, v3 wallets
        {"$ethereum$p*262144*ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd*5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46*517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2", "testpassword"},
	// artificial hash for testing
	{"$ethereum$p*1024*30323330313838333730333538343831*6dcfca7cbd44eb3ca7f11162b996b98dd46fb68e1afb095686fe944fcbdb3b59*b3a766d8c1390462304af979c6f709ba54a23ff135d1ffcdef485dcc7f79b5f2", "6023"},
	{NULL}
};

#include "../run/opencl/opencl_pbkdf2_hmac_sha256.h"

// input
typedef struct {
	salt_t pbkdf2;
	uint8_t encseed[1024];
	uint32_t eslen;
} ethereum_salt_t;

// output
typedef struct {
	uint32_t hash[BINARY_SIZE / 4];
} hash_t;

static int new_keys;
static pass_t *host_pass;                 /** plain ciphertexts **/
static ethereum_salt_t *host_salt;        /** salt **/
static hash_t *host_crack;                /** hash**/
static cl_int cl_error;
static cl_mem mem_in, mem_pbkdf2_out, mem_salt, mem_state, mem_out;
static cl_kernel split_kernel, final_kernel;
static struct fmt_main *self;

static custom_salt *cur_salt;

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

#define CLKERNELARG(kernel, id, arg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg),\
	               "Error setting kernel args");

	host_pass = mem_calloc(kpc, sizeof(pass_t));
	host_crack = mem_calloc(kpc, sizeof(hash_t));
	host_salt = mem_calloc(1, sizeof(ethereum_salt_t));

	mem_in = CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
	                        "Cannot allocate mem in");
	mem_salt = CLCREATEBUFFER(CL_RO, sizeof(ethereum_salt_t),
	                          "Cannot allocate mem salt");
	mem_pbkdf2_out = CLCREATEBUFFER(CL_RW, kpc * sizeof(crack_t),
	                                "Cannot allocate pbkdf2 out");
	mem_state = CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
	                           "Cannot allocate mem state");
	mem_out = CLCREATEBUFFER(CL_WO, kpc * sizeof(hash_t),
	                         "Cannot allocate mem out");

	CLKERNELARG(crypt_kernel, 0, mem_in);
	CLKERNELARG(crypt_kernel, 1, mem_salt);
	CLKERNELARG(crypt_kernel, 2, mem_state);

	CLKERNELARG(split_kernel, 0, mem_state);

	CLKERNELARG(final_kernel, 0, mem_pbkdf2_out);
	CLKERNELARG(final_kernel, 1, mem_salt);
	CLKERNELARG(final_kernel, 2, mem_state);
	CLKERNELARG(final_kernel, 3, mem_out);
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
	if (host_crack) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_pbkdf2_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

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
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%u",
		         HASH_LOOPS, PLAINTEXT_LENGTH);
		opencl_init("$JOHN/opencl/ethereum_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel =
			clCreateKernel(program[gpu_id], "pbkdf2_sha256_init", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], "pbkdf2_sha256_loop", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		final_kernel =
			clCreateKernel(program[gpu_id], "ethereum_process", &cl_error);
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
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
		               "Release Program");

		program[gpu_id] = NULL;
	}
}

static int ethereum_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // type
		goto err;
	if (*p != 'p')
		goto err;
	if (*p == 'p') {
		if ((p = strtokm(NULL, "*")) == NULL)   // iterations
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // salt
			goto err;
		if (hexlenl(p, &extra) > 64 * 2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)   // mac
			goto err;
		if (hexlenl(p, &extra) != 64 || extra)
			goto err;
	}

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void set_salt(void *salt)
{
	cur_salt = (custom_salt*)salt;

	memcpy(host_salt->pbkdf2.salt, cur_salt->salt, cur_salt->saltlen);
	host_salt->pbkdf2.length = cur_salt->saltlen;
	host_salt->pbkdf2.rounds = cur_salt->iterations;

	host_salt->eslen = cur_salt->ctlen;
	memcpy(host_salt->encseed, cur_salt->ct, cur_salt->ctlen);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(ethereum_salt_t), host_salt, 0, NULL, NULL),
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

	// Copy data to gpu
	if (new_keys) {
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
		CL_TRUE, 0, global_work_size * sizeof(hash_t), host_crack, 0,
		NULL, multi_profilingEvent[4]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, host_crack[index].hash, ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, host_crack[index].hash, BINARY_SIZE);
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

struct fmt_main fmt_opencl_ethereum = {
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
		},
		{ FORMAT_TAG },
		opencl_ethereum_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		ethereum_valid,
		fmt_default_split,
		ethereum_get_binary,
		ethereum_common_get_salt,
		{
			ethereum_common_iteration_count,
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
			fmt_default_get_hash  // required due to usage of FMT_HUGE_INPUT
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
