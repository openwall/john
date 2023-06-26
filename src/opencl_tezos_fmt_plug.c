/*
 * This software is
 * Copyright (c) 2018 Dhiru Kholia
 * Copyright (c) 2021 Solar Designer
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on opencl_pbkdf2_hmac_sha512_fmt_plug.c file.
 *
 * Update to implement and use on-device ed25519_publickey() and BLAKE2b for
 * great speedup was funded by the Tezos Foundation.
 */

#include "arch.h"
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_tezos;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_tezos);
#else

#include <stdint.h>
#include <string.h>

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "opencl_common.h"
#include "tezos_common.h"
#include "johnswap.h"
#include "pbkdf2_hmac_common.h"

#define FORMAT_NAME             "Tezos Key"
#define FORMAT_LABEL            "tezos-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA512 OpenCL"
#define BINARY_SIZE             0
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        48
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define INIT_KERNEL_NAME        "pbkdf2_sha512_tezos_init"
#define SPLIT_KERNEL_NAME       "pbkdf2_sha512_loop"
#define FINAL_KERNEL_NAME       "pbkdf2_sha512_tezos_final"

#define HASH_LOOPS              512
#define ITERATIONS              2048

static struct custom_salt *cur_salt;

typedef struct {
	// for plaintext, we must make sure it is a full uint64_t width.
	uint64_t v[(PLAINTEXT_LENGTH + 7) / 8]; // v must be kept aligned(8)
	uint64_t length; // keep 64 bit aligned, length is overkill, but easiest way to stay aligned.
} pass_t;

typedef struct {
	uint64_t hash[8];
} crack_t;

typedef struct {
	uint64_t ipad[8];
	uint64_t opad[8];
	uint64_t hash[8];
	uint64_t W[8];
	cl_uint rounds;
} state_t;

typedef struct {
	// for salt, we append \x00\x00\x00\x01\x80 and must make sure it is a full uint64 width
	uint64_t salt[(PBKDF2_64_MAX_SALT_SIZE + 1 + 4 + 7) / 8]; // salt must be kept aligned(8)
	uint32_t length;
	uint32_t rounds;
} salt_t;

typedef struct {
	salt_t pbkdf2;
	uint32_t mnemonic_length;
	unsigned char mnemonic[128];
	unsigned char pkh[20];
} tezos_salt_t;

static uint32_t *cracked;
static size_t cracked_size;
static pass_t *host_pass;  /** plain ciphertexts **/
static tezos_salt_t *host_salt;  /** salt **/
static cl_mem mem_in, mem_out, mem_salt, mem_state, mem_final;
static cl_kernel split_kernel, final_kernel;
static cl_int cl_error;
static int new_keys;
static size_t max_key_length;
static struct fmt_main *self;

#define STEP                    0
#define SEED                    256

static const char *warn[] = {
        "xfer: ",  ", init: " , ", crypt: ", ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static size_t final_kernel_max_lws;

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	final_kernel_max_lws = autotune_get_task_max_work_group_size(FALSE, 0, final_kernel);
	size_t min_lws = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	return MIN(min_lws, autotune_get_task_max_work_group_size(FALSE, 0, split_kernel));
}

static void release_clobj(void);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	release_clobj();

	host_pass = mem_calloc(kpc, sizeof(pass_t));
	host_salt = mem_calloc(1, sizeof(tezos_salt_t));
	cracked_size = sizeof(*cracked) * (1 + kpc);
	cracked = mem_alloc(cracked_size);
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)	  \
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error); \
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)	  \
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	mem_in = CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
			"Cannot allocate mem in");
	mem_salt = CLCREATEBUFFER(CL_RO, sizeof(tezos_salt_t),
			"Cannot allocate mem salt");
	mem_out = CLCREATEBUFFER(CL_WO, kpc * sizeof(crack_t),
			"Cannot allocate mem out");
	mem_state = CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
			"Cannot allocate mem state");
	mem_final = CLCREATEBUFFER(CL_RW, cracked_size,
			"Cannot allocate mem final");

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
	CLKERNELARG(split_kernel, 1, mem_out, "Error while setting mem_out");

	CLKERNELARG(final_kernel, 0, mem_out, "Error while setting mem_out");
	CLKERNELARG(final_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(final_kernel, 2, mem_final, "Error while setting mem_final");

	*cracked = 1; /* Trigger zeroization and transfer of cracked[] to device */
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%d -DPBKDF2_64_MAX_SALT_SIZE=%d",
		         HASH_LOOPS, PLAINTEXT_LENGTH, PBKDF2_64_MAX_SALT_SIZE);

		opencl_init("$JOHN/opencl/tezos_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], INIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating init kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		final_kernel =
			clCreateKernel(program[gpu_id], FINAL_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating final kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
	                       2, self, create_clobj, release_clobj,
	                       sizeof(state_t), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ITERATIONS, 0, 200);
}

static void release_clobj(void)
{
	if (host_pass) {
		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(cracked);

		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_final), "Release mem final");
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;

	memcpy(host_salt->pbkdf2.salt, cur_salt->email, cur_salt->email_length);
	host_salt->pbkdf2.length = cur_salt->email_length;
	host_salt->pbkdf2.rounds = ITERATIONS;
	memcpy(host_salt->mnemonic, cur_salt->mnemonic, cur_salt->mnemonic_length);
	host_salt->mnemonic_length = cur_salt->mnemonic_length;
	memcpy(host_salt->pkh, cur_salt->raw_address + 2, 20);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(tezos_salt_t), host_salt, 0, NULL, NULL),
		"Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	int loops = (ITERATIONS + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	if (*cracked) {
		memset(cracked, 0, cracked_size);
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_final, CL_FALSE, 0,
			cracked_size, cracked, 0, NULL, NULL),
			"Initial transfer");
		BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	}

	static int warned;
	if (!warned && 8 + cur_salt->email_length + max_key_length > 107) {
		warned = 1;
		fprintf(stderr, "Warning: over-long combination(s) of e-mail address and candidate password\n");
	}

	if (new_keys || ocl_autotune_running) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			gws * sizeof(pass_t), host_pass, 0, NULL,
			multi_profilingEvent[0]), "Keys transfer");
		new_keys = 0;
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
				NULL, &gws, lws, 0, NULL,
				multi_profilingEvent[1]), "Run kernel");

	// Better precision for WAIT_ macros
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	WAIT_INIT(gws)
	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					split_kernel, 1, NULL,
					&gws, lws, 0, NULL,
					multi_profilingEvent[2]), "Run split kernel");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		WAIT_UPDATE
		opencl_process_event();
	}
	WAIT_DONE

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
				final_kernel, 1, NULL,
				&gws, (local_work_size <= final_kernel_max_lws) ? lws : NULL, 0, NULL,
				multi_profilingEvent[3]), "Run final kernel");
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_final, CL_FALSE, 0,
				sizeof(*cracked), cracked,
				0, NULL, multi_profilingEvent[4]), "Copy result back");

	WAIT_INIT(gws)
	BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
	WAIT_UPDATE
	WAIT_DONE

	if (*cracked) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_final, CL_TRUE, 0,
					(count + 1) * sizeof(*cracked), cracked,
					0, NULL, multi_profilingEvent[4]), "Copy result back");
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return *cracked;
}

static int cmp_one(void *binary, int index)
{
	uint32_t magic = cracked[1 + index];
	if (!magic || magic == 0x486954)
		return magic;
	fprintf(stderr, FORMAT_LABEL ": Cracked something, but the magic 0x%08x is bad, skipping\n", magic);
	return 0;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	size_t saved_len = strnlen(key, PLAINTEXT_LENGTH);
	memcpy(host_pass[index].v, key, saved_len);
	host_pass[index].length = saved_len;
	new_keys = 1;
	if (saved_len > max_key_length)
		max_key_length = saved_len;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];

	memcpy(ret, host_pass[index].v, host_pass[index].length);
	ret[host_pass[index].length] = 0;

	return ret;
}

struct fmt_main fmt_opencl_tezos = {
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
		{ NULL },
		{ FORMAT_TAG },
		tezos_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		tezos_valid,
		fmt_default_split,
		fmt_default_binary,
		tezos_get_salt,
		{ NULL },
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
