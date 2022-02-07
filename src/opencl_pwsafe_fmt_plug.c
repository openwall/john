/*
 * Password Safe cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * OpenCL port by Lukas Odzioba <ukasz at openwall.net>.
 *
 * Split kernel implemented and plaintext extension by Brian Wallace <brian.wallace9809 at gmail.com>.
 *
 * This software is Copyright (c) 2012-2013, Dhiru Kholia <dhiru.kholia at
 * gmail.com> and Brian Wallace <brian.wallace9809 at gmail.com>, and it is
 * hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_pwsafe;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_pwsafe);
#else

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "opencl_common.h"
#include "pwsafe_common.h"
#include "memory.h"

#define FORMAT_LABEL            "pwsafe-opencl"
#define ALGORITHM_NAME          "SHA256 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        87
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_ALIGN              MEM_ALIGN_WORD
#define KERNEL_INIT_NAME        "pwsafe_init"
#define KERNEL_RUN_NAME         "pwsafe_iter"
#define KERNEL_FINISH_NAME      "pwsafe_check"
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define STEP                    0
#define SEED                    256
#define ROUNDS_DEFAULT          2048

static const char * warn[] = {
	"pass xfer: "  ,  ", init: "    ,  ", loop: ",
	", final: "  ,  ", result xfer: "
};

#include "opencl_autotune.h"

cl_kernel init_kernel;
cl_kernel finish_kernel;

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return MIN(
		MIN(autotune_get_task_max_work_group_size(FALSE, 0, init_kernel),
		    autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel)),
		autotune_get_task_max_work_group_size(FALSE, 0, finish_kernel));
}

 #define SWAP32(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

static int split_events[3] = { 2, -1, -1 };

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pwsafe_pass;

typedef struct {
	uint32_t v[8];
	uint32_t iterations;
} pwsafe_state;

typedef struct {
	uint32_t cracked;
} pwsafe_hash;

typedef struct {
	int version;
	uint32_t iterations;
	uint8_t hash[32];
	uint8_t salt[32];
} pwsafe_salt;

#define SALT_SIZE               sizeof(pwsafe_salt)

static int new_keys;
static cl_mem mem_in, mem_out, mem_state, mem_salt;

#define insize (sizeof(pwsafe_pass) * global_work_size)
#define statesize (sizeof(pwsafe_state) * global_work_size)
#define outsize (sizeof(pwsafe_hash) * global_work_size)
#define saltsize (sizeof(pwsafe_salt))

static pwsafe_pass *host_pass; /** binary ciphertexts **/
static pwsafe_salt *host_salt; /** salt **/
static pwsafe_hash *host_hash; /** calculated hashes **/
static struct fmt_main *self;

static void release_clobj(void)
{
	if (host_pass) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(host_pass);
		MEM_FREE(host_hash);
		MEM_FREE(host_salt);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(init_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(finish_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void set_key(char *key, int index)
{
	int saved_len = MIN(strlen(key), PLAINTEXT_LENGTH);
	memcpy(host_pass[index].v, key, saved_len);
	host_pass[index].length = saved_len;

	new_keys = 1;
}

static void release_clobj(void);

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	global_work_size = gws; /* needed for size macros */

	host_pass = mem_calloc(1, insize);
	host_hash = mem_calloc(1, outsize);
	host_salt = mem_calloc(1, saltsize);

	// Allocate memory on the GPU
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for salt");
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for passwords");
	mem_state =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, statesize, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for state");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for hashes");

	// Assign kernel parameters
	clSetKernelArg(init_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(init_kernel, 1, sizeof(mem_state), &mem_state);
	clSetKernelArg(init_kernel, 2, sizeof(mem_salt), &mem_salt);

	clSetKernelArg(crypt_kernel, 0, sizeof(mem_state), &mem_state);

	clSetKernelArg(finish_kernel, 0, sizeof(mem_state), &mem_state);
	clSetKernelArg(finish_kernel, 1, sizeof(mem_out), &mem_out);
	clSetKernelArg(finish_kernel, 2, sizeof(mem_salt), &mem_salt);
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		opencl_init("$JOHN/opencl/pwsafe_kernel.cl", gpu_id, NULL);

		init_kernel = clCreateKernel(program[gpu_id], KERNEL_INIT_NAME, &ret_code);
		HANDLE_CLERROR(ret_code, "Error while creating init kernel");

		crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_RUN_NAME, &ret_code);
		HANDLE_CLERROR(ret_code, "Error while creating crypt kernel");

		finish_kernel = clCreateKernel(program[gpu_id], KERNEL_FINISH_NAME, &ret_code);
		HANDLE_CLERROR(ret_code, "Error while creating finish kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, ROUNDS_DEFAULT/8, split_events,
	                       warn, 2, self, create_clobj,
	                       release_clobj, sizeof(pwsafe_pass), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ROUNDS_DEFAULT, 0, 200);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static pwsafe_salt *salt_struct;

	if (!salt_struct)
		salt_struct = mem_calloc_tiny(sizeof(pwsafe_salt),
				MEM_ALIGN_WORD);
	ctcopy += FORMAT_TAG_LEN;               /* skip over "$pwsafe$*" */
	p = strtokm(ctcopy, "*");
	salt_struct->version = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	salt_struct->iterations = (unsigned int) atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->hash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	alter_endianity(salt_struct->hash, 32);
	return (void *) salt_struct;
}

static void set_salt(void *salt)
{
	memcpy(host_salt, salt, SALT_SIZE);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
	        CL_FALSE, 0, saltsize, host_salt, 0, NULL, NULL),
	        "Copy memsalt");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i = 0;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to GPU memory
	if (new_keys) {
		WAIT_INIT(global_work_size)
		BENCH_CLERROR(clEnqueueWriteBuffer
			(queue[gpu_id], mem_in, CL_FALSE, 0, insize, host_pass, 0, NULL,
			 multi_profilingEvent[0]), "Copy memin");

		BENCH_CLERROR(clFlush(queue[gpu_id]), "Error in clFlush");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error transferring keys");
		WAIT_UPDATE
		WAIT_DONE

		new_keys = 0;
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel
			(queue[gpu_id], init_kernel, 1, NULL, &global_work_size, lws,
			 0, NULL, multi_profilingEvent[1]), "Set ND range");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running init kernel");

	// Run kernel
	WAIT_INIT(global_work_size)
	for (i = 0; i < (ocl_autotune_running ? 1 : 8); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel
			(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws,
			0, NULL, multi_profilingEvent[2]), "Set ND range");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
		WAIT_UPDATE
	}
	WAIT_DONE

	BENCH_CLERROR(clEnqueueNDRangeKernel
	    (queue[gpu_id], finish_kernel, 1, NULL, &global_work_size, lws,
		0, NULL, multi_profilingEvent[3]), "Set ND range");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, host_hash, 0, NULL, multi_profilingEvent[4]),
	    "Copy data back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (host_hash[i].cracked == 1)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return host_hash[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return host_hash[index].cracked;
}


static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];

	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;

	return ret;
}

static unsigned int iteration_count(void *salt)
{
	pwsafe_salt *my_salt;

	my_salt = salt;

	return (unsigned int) my_salt->iterations;
}

struct fmt_main fmt_opencl_pwsafe = {
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
		BINARY_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		pwsafe_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		pwsafe_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
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
