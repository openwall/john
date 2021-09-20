/*
 * This software is
 * Copyright (c) 2018 magnum
 * Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_phpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_phpass);
#else

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "options.h"
#include "opencl_common.h"
#include "phpass_common.h"

#define FORMAT_LABEL            "phpass-opencl"
#define FORMAT_NAME             ""

#define ALGORITHM_NAME          "MD5 OpenCL"

#define BENCHMARK_COMMENT       " ($P$9)"

#define ACTUAL_SALT_SIZE        8
#define SALT_SIZE               (ACTUAL_SALT_SIZE + 1) // 1 char for iterations
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

typedef struct {
	unsigned char v[(PLAINTEXT_LENGTH + 3) / 4 * 4];
	unsigned int length;
} phpass_password;

typedef struct {
	uint32_t v[4];		// 128bits for hash
} phpass_hash;

static phpass_password *inbuffer;		/** plaintext ciphertexts **/
static phpass_hash *outbuffer;			/** calculated hashes **/

// OpenCL variables:
static cl_int cl_error;
static cl_mem mem_in, mem_out, mem_salt;
static size_t insize, outsize, saltsize;
static int new_keys;
static struct fmt_main *self;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	release_clobj();

	kpc *= ocl_v_width;

	insize = sizeof(phpass_password) * kpc;
	outsize = sizeof(phpass_hash) * kpc;
	saltsize = sizeof(uint8_t) * ACTUAL_SALT_SIZE + 4;

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

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (outbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void set_key(char *key, int index)
{
	inbuffer[index].length = strlen(key);
	strncpy((char*)inbuffer[index].v, key, sizeof(inbuffer[index].v));
	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];

	memcpy(ret, inbuffer[index].v, inbuffer[index].length);
	ret[inbuffer[index].length] = 0;
	return ret;
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);

	opencl_get_vector_width(gpu_id, sizeof(cl_int));
	if (ocl_v_width > 1) {
		static char valgo[sizeof(ALGORITHM_NAME) + 12] = "";

		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DV_WIDTH=%u -DPLAINTEXT_LENGTH=%u",
		         ocl_v_width, PLAINTEXT_LENGTH);
		opencl_init("$JOHN/opencl/phpass_kernel.cl", gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "phpass", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1,
	                       self, create_clobj, release_clobj,
	                       sizeof(phpass_password) * ocl_v_width, 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 200);
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];

	memcpy(salt, &ciphertext[FORMAT_TAG_LEN+1], ACTUAL_SALT_SIZE);
	salt[ACTUAL_SALT_SIZE] = ciphertext[FORMAT_TAG_LEN];
	return salt;
}


static void set_salt(void *salt)
{
	static unsigned int setting[ACTUAL_SALT_SIZE / 4 + 1];
	unsigned char *currentsalt = salt;

	// Prepare setting format: salt+count_log2
	memcpy(setting, salt, ACTUAL_SALT_SIZE);
	setting[ACTUAL_SALT_SIZE / 4] = 1 << atoi64[ARCH_INDEX(currentsalt[8])];

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, setting, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_KPC_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");
		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	return count;
}

static int binary_hash_0(void *binary)
{
	return (((uint32_t*)binary)[0] & PH_MASK_0);
}

static int get_hash_0(int index)
{
	return outbuffer[index].v[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return outbuffer[index].v[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return outbuffer[index].v[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return outbuffer[index].v[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return outbuffer[index].v[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return outbuffer[index].v[0] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return outbuffer[index].v[0] & PH_MASK_6;
}

static int cmp_all(void *binary, int count)
{
	uint32_t b = ((uint32_t *) binary)[0];
	uint32_t i;

	for (i = 0; i < count; i++) {
		if (b == outbuffer[i].v[0]) {
			return 1;
		}
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (t[i] != outbuffer[index].v[i]) {
			return 0;
		}
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_phpass = {
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
		{ FORMAT_TAG, FORMAT_TAG2, FORMAT_TAG3 },
		phpass_common_tests
	}, {
		init,
		done,
		reset,
		phpass_common_prepare,
		phpass_common_valid,
		phpass_common_split,
		phpass_common_binary,
		get_salt,
		{
			phpass_common_iteration_count,
		},
		fmt_default_source,
		{
			binary_hash_0,
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
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
