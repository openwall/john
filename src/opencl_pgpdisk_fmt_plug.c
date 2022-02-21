/*
 * Format for brute-forcing PGP Virtual Disk images.
 *
 * This software is Copyright (c) 2017 Dhiru Kholia <dhiru at openwall.net> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_pgpdisk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_pgpdisk);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "opencl_common.h"
#include "options.h"
#include "pgpdisk_common.h"

#define FORMAT_LABEL            "pgpdisk-opencl"
#define ALGORITHM_NAME          "SHA1 AES/TwoFish/CAST OpenCL"
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        124
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pgpdisk_password;

typedef struct {
	uint8_t v[BINARY_SIZE];
} pgpdisk_hash;

typedef struct {
	uint32_t saltlen;
	uint32_t iterations;
	uint32_t key_len;
	uint32_t algorithm;
	uint8_t salt[16];
} pgpdisk_salt;

static struct custom_salt *cur_salt;

static cl_int cl_error;
static pgpdisk_password *inbuffer;
static pgpdisk_hash *outbuffer;
static pgpdisk_salt currentsalt;
static cl_kernel aes_kernel, twofish_kernel, cast_kernel;
static cl_mem mem_in, mem_out, mem_salt;
static struct fmt_main *self;
static int new_keys;

static size_t insize, outsize, saltsize;

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

static size_t get_task_max_work_group_size()
{
	size_t s = autotune_get_task_max_work_group_size(FALSE, 0, aes_kernel);

	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, twofish_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, cast_kernel));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	insize = sizeof(pgpdisk_password) * gws;
	outsize = sizeof(pgpdisk_hash) * gws;
	saltsize = sizeof(pgpdisk_salt);

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
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(aes_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(aes_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(aes_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");

	HANDLE_CLERROR(clSetKernelArg(twofish_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(twofish_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(twofish_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");

	HANDLE_CLERROR(clSetKernelArg(cast_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(cast_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(cast_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (inbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
	Twofish_initialise();
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DBINARY_SIZE=%d",
		         PLAINTEXT_LENGTH, BINARY_SIZE);
		opencl_init("$JOHN/opencl/pgpdisk_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = aes_kernel = clCreateKernel(program[gpu_id], "pgpdisk_aes", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		twofish_kernel = clCreateKernel(program[gpu_id], "pgpdisk_twofish", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		cast_kernel = clCreateKernel(program[gpu_id], "pgpdisk_cast", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       sizeof(pgpdisk_password), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 200);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(aes_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(twofish_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(cast_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	currentsalt.iterations = cur_salt->iterations;
	currentsalt.algorithm = cur_salt->algorithm;
	if (cur_salt->algorithm == 3) {
		currentsalt.key_len = 16;
		currentsalt.saltlen= 8;
	} else {
		currentsalt.key_len = 32;
		currentsalt.saltlen = 16;
	}
	memcpy((char*)currentsalt.salt, cur_salt->salt, currentsalt.saltlen);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
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
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	// Run kernel
	if (cur_salt->algorithm == 3) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], cast_kernel, 1,
			NULL, &global_work_size, lws, 0, NULL,
			multi_profilingEvent[1]),
			"Run kernel");
	} else if (cur_salt->algorithm == 4) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], twofish_kernel, 1,
			NULL, &global_work_size, lws, 0, NULL,
			multi_profilingEvent[1]),
			"Run kernel");
	} else /* if (cur_salt->algorithm >= 5) */ {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], aes_kernel, 1,
			NULL, &global_work_size, lws, 0, NULL,
			multi_profilingEvent[1]),
			"Run kernel");
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
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
	return !memcmp(binary, outbuffer[index].v, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_pgpdisk = {
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
			"algorithm [3=CAST 4=TwoFish 5/6/7=AES]",
		},
		{ FORMAT_TAG },
		pgpdisk_tests,
	},
	{
		init,
		done,
		reset,
		fmt_default_prepare,
		pgpdisk_common_valid,
		fmt_default_split,
		get_binary,
		pgpdisk_common_get_salt,
		{
			pgpdisk_common_iteration_count,
			pgpdisk_common_algorithm,
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
