/*
 * JtR OpenCL format to crack SolarWinds Orion hashes.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * The OpenCL boilerplate code is borrowed from other OpenCL formats.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_solarwinds;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_solarwinds);
#else

#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "solarwinds_common.h"
#include "options.h"
#include "jumbo.h"
#include "opencl_common.h"
#include "misc.h"
#define OUTLEN                  1024
#define PLAINTEXT_LENGTH        28
#include "../run/opencl/opencl_pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL            "solarwinds-opencl"
#define OCL_ALGORITHM_NAME      "PBKDF2-SHA1 OpenCL"
#define ALGORITHM_NAME          OCL_ALGORITHM_NAME
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define BINARY_SIZE             64
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               sizeof(*cur_salt)
#define SALT_ALIGN              MEM_ALIGN_WORD

/* This handles all widths */
#define GETPOS(i, index)        (((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static struct custom_salt *cur_salt;

typedef struct {
	unsigned int key[((OUTLEN + 19) / 20) * 20 / sizeof(uint32_t)];
} solarwinds_out;

typedef struct {
	unsigned char hash[12];
} solarwinds_final_out;

typedef struct {
	unsigned int  length;
	unsigned int  outlen;
	unsigned int  iterations;
	unsigned char salt[8];
} solarwinds_salt;

static size_t key_buf_size, outsize, final_outsize;
static unsigned int *inbuffer;
static solarwinds_out *output;
static solarwinds_final_out *final_output;
static solarwinds_salt currentsalt;
static cl_mem mem_in, mem_out, mem_salt, mem_state, mem_final_out;
static size_t key_buf_size;
static int new_keys;
static struct fmt_main *self;
static cl_kernel pbkdf2_init, pbkdf2_loop, solarwinds_loop, solarwinds_final;

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS              (333)
#define ITERATIONS              1000
#define LOOP_COUNT              (((currentsalt.iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define STEP                    0
#define SEED                    128

static const char *warn[] = {
	"P xfer: ",  ", init: ",  ", loop: ",  ", swloop: ",  ", final: ",  ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, solarwinds_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, solarwinds_final));
	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	key_buf_size = 64 * gws;
	outsize = sizeof(solarwinds_out) * gws;
	final_outsize = sizeof(solarwinds_final_out) * gws;

	// Allocate memory
	inbuffer = mem_calloc(1, key_buf_size);
	output = mem_alloc(outsize);
	final_output = mem_alloc(final_outsize);

	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(solarwinds_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");
	mem_final_out = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, final_outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem final out");
	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(solarwinds_loop, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(solarwinds_loop, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(solarwinds_loop, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(solarwinds_final, 0, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(solarwinds_final, 1, sizeof(mem_final_out), &mem_final_out), "Error while setting mem_final_out kernel argument");
}

static void release_clobj(void)
{
	if (output) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_final_out), "Release mem final out");

		MEM_FREE(inbuffer);
		MEM_FREE(output);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(solarwinds_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(solarwinds_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
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
		         "-DHASH_LOOPS=%u -DOUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u -DITERATIONS=%u",
		         HASH_LOOPS, OUTLEN, PLAINTEXT_LENGTH, ITERATIONS - 1);
		opencl_init("$JOHN/opencl/solarwinds_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		solarwinds_loop = clCreateKernel(program[gpu_id], "solarwinds_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		solarwinds_final = clCreateKernel(program[gpu_id], "solarwinds_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 2 * HASH_LOOPS, split_events,
	                       warn, 2, self, create_clobj,
	                       release_clobj,
	                       sizeof(pbkdf2_state), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 2 * (ITERATIONS - 1) + 4, 0, 200);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	/* PBKDF2 */
	memcpy((char*)currentsalt.salt, cur_salt->salt, 8);
	currentsalt.length = 8;
	currentsalt.iterations = 1000;
	currentsalt.outlen = 1024;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0,
		sizeof(solarwinds_salt), &currentsalt, 0, NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static void clear_keys(void)
{
	memset(inbuffer, 0, key_buf_size);
}

static void solarwinds_set_key(char *key, int index)
{
	int i;
	int length = strlen(key);

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];

	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i = 0;

	while (i < PLAINTEXT_LENGTH &&
	       (ret[i] = ((char*)inbuffer)[GETPOS(i, index)]))
		i++;
	ret[i] = 0;

	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, j;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_KPC_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (j = 0; j < (ocl_autotune_running ? 1 : (currentsalt.outlen + 19) / 20); j++) {
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], solarwinds_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], solarwinds_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[4]), "Run final kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_final_out, CL_TRUE, 0, final_outsize, final_output, 0, NULL, multi_profilingEvent[5]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, final_output[index].hash, ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, final_output[index].hash, 12);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_solarwinds = {
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
		{ FORMAT_TAG },
		solarwinds_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		solarwinds_valid,
		fmt_default_split,
		solarwinds_get_binary,
		solarwinds_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		solarwinds_set_key,
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
