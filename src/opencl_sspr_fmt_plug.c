/*
 * OpenCL format for cracking NetIQ SSPR hashes.
 *
 * This software is
 * Copyright (c) 2018 Dhiru Kholia <dhiru at openwall.com>
 * Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is based on opencl_gpg_fmt_plug.c file which is,
 *
 * Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com>, Copyright (c) 2012
 * Lukas Odzioba <ukasz@openwall.net>, Copyright (c) 2016 Jim Fougeron, and
 * licensed under the same terms as above.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_sspr;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_sspr);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "options.h"
#include "opencl_common.h"
#include "sspr_common.h"

#define FORMAT_LABEL            "sspr-opencl"
#define ALGORITHM_NAME          "MD5/SHA1/SHA2 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        64
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define SALT_LENGTH             32

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

typedef union {
	uint8_t  b[SHA512_DIGEST_LENGTH];
	uint32_t w[SHA512_DIGEST_LENGTH / sizeof(uint32_t)];
	uint64_t W[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
} hash512_t;

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} sspr_password;

typedef struct {
	uint8_t v[BINARY_SIZE_MIN];
} sspr_hash;

typedef struct {
	uint32_t length;
	uint32_t count;
	uint8_t salt[SALT_LENGTH];
} sspr_salt;

typedef struct {
	hash512_t hash;
	uint32_t  count;
} sspr_state;

static struct custom_salt *cur_salt;

static cl_int cl_error;
static sspr_password *inbuffer;
static sspr_hash *outbuffer;
static sspr_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting, mem_state;
static struct fmt_main *self;
static cl_kernel sspr_kernel[5], loop_kernel[5];

static size_t insize, outsize, settingsize;
static int new_keys;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS		(3*271) // 3 3 41 271

#define LOOP_COUNT		(((cur_salt->iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)

static int split_events[] = { 2, -1, -1 };

static const char *warn[] = {
	"xfer: ",  ", init: ",  ", loop: ", ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	int i;
	size_t max =
		autotune_get_task_max_work_group_size(FALSE, 0, sspr_kernel[0]);

	max = MIN(max,
		autotune_get_task_max_work_group_size(FALSE, 0, loop_kernel[0]));
	for (i = 1; i < 5; i++) {
		max = MIN(max,
			autotune_get_task_max_work_group_size(FALSE, 0, sspr_kernel[i]));
		max = MIN(max,
			autotune_get_task_max_work_group_size(FALSE, 0, loop_kernel[i]));
	}
	return max;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int i;
	size_t statesize = sizeof(sspr_state) * gws;

	release_clobj();

	insize = sizeof(sspr_password) * gws;
	outsize = sizeof(sspr_hash) * gws;
	settingsize = sizeof(sspr_salt);

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_state =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, statesize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem state");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	for (i = 0; i < 5; i++) {
		HANDLE_CLERROR(clSetKernelArg(sspr_kernel[i], 0, sizeof(mem_in),
			&mem_in), "Error while setting mem_in kernel argument");
		HANDLE_CLERROR(clSetKernelArg(sspr_kernel[i], 1, sizeof(mem_out),
			&mem_out), "Error while setting mem_out kernel argument");
		HANDLE_CLERROR(clSetKernelArg(sspr_kernel[i], 2, sizeof(mem_setting),
			&mem_setting), "Error while setting mem_salt kernel argument");
		HANDLE_CLERROR(clSetKernelArg(sspr_kernel[i], 3, sizeof(mem_state),
			&mem_state), "Error while setting mem_state kernel argument");

		HANDLE_CLERROR(clSetKernelArg(loop_kernel[i], 0, sizeof(mem_out),
			&mem_out), "Error while setting mem_out kernel argument");
		HANDLE_CLERROR(clSetKernelArg(loop_kernel[i], 1, sizeof(mem_state),
			&mem_state), "Error while setting mem_state kernel argument");
	}
}

static void release_clobj(void)
{
	if (outbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
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
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DSALT_LENGTH=%d -DHASH_LOOPS=%d",
		         PLAINTEXT_LENGTH, SALT_LENGTH, HASH_LOOPS);
		opencl_init("$JOHN/opencl/sspr_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel =
			sspr_kernel[0] = clCreateKernel(program[gpu_id], "sspr_md5", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		loop_kernel[0] = clCreateKernel(program[gpu_id], "loop_md5", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sspr_kernel[1] = clCreateKernel(program[gpu_id], "sspr_sha1", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		loop_kernel[1] = clCreateKernel(program[gpu_id], "loop_sha1", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sspr_kernel[2] = clCreateKernel(program[gpu_id], "sspr_salted_sha1", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		loop_kernel[2] = clCreateKernel(program[gpu_id], "loop_sha1", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sspr_kernel[3] = clCreateKernel(program[gpu_id], "sspr_salted_sha256", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		loop_kernel[3] = clCreateKernel(program[gpu_id], "loop_sha256", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sspr_kernel[4] = clCreateKernel(program[gpu_id], "sspr_salted_sha512", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		loop_kernel[4] = clCreateKernel(program[gpu_id], "loop_sha512", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn, 2, self,
	                       create_clobj, release_clobj,
	                       sizeof(sspr_state), 0, db);

	// Auto tune execution from shared/included code, 200ms crypt_all() max.
	autotune_run(self, 100000, 0, 200);
}

static void done(void)
{
	if (program[gpu_id]) {
		int i;

		release_clobj();

		for (i = 0; i < 5; i++) {
			HANDLE_CLERROR(clReleaseKernel(sspr_kernel[i]), "Release kernel");
			HANDLE_CLERROR(clReleaseKernel(loop_kernel[i]), "Release kernel");
		}
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	currentsalt.length = cur_salt->saltlen;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->saltlen);
	currentsalt.count = cur_salt->iterations;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static void set_key(char *key, int index)
{
	uint32_t length = strlen(key);

	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	int krnl = cur_salt->fmt;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	// Run 1st kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		sspr_kernel[krnl], 1, NULL,
		&global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]), "Run init kernel");

	// Run loop kernel
	for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
			loop_kernel[krnl], 1, NULL,
			&global_work_size, lws, 0, NULL,
			multi_profilingEvent[2]), "Run loop kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[3]),
		"Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, outbuffer[index].v, ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, outbuffer[index].v, BINARY_SIZE_MIN);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_sspr = {
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
			"KDF [0:MD5 1:SHA1 2:SHA1_SALT 3:SHA256_SALT 4:SHA512_SALT]",
			"iteration count",
		},
		{ FORMAT_TAG },
		sspr_tests
	},
	{
		init,
		done,
		reset,
		fmt_default_prepare,
		sspr_valid,
		fmt_default_split,
		sspr_get_binary,
		sspr_get_salt,
		{
			sspr_get_kdf_type,
			sspr_get_iteration_count,
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
