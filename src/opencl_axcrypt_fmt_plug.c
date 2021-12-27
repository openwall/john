/*
 * This software is Copyright (c) 2018 Dhiru Kholia <kholia at kth dot se> and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on opencl_pfx_fmt_plug.c file, and other files which are,
 *
 * Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>, Copyright (c) JimF,
 * and Copyright (c) magnum.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_axcrypt;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_axcrypt);
#else

#include <stdint.h>
#include <string.h>

#include "misc.h"
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "opencl_common.h"
#include "options.h"
#include "axcrypt_common.h"
#define VERSION_1_SUPPORT 1
#include "axcrypt_variable_code.h"

#define FORMAT_LABEL            "axcrypt-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "SHA1 AES OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_SIZE               sizeof(struct custom_salt *)
#define SALT_ALIGN              sizeof(struct custom_salt *)
#define PLAINTEXT_LENGTH        64
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

// input
typedef struct {
	uint32_t length;
	unsigned char v[PLAINTEXT_LENGTH];
} axcrypt_password;

typedef struct {
	uint32_t cracked;
} axcrypt_out;

// input
typedef struct {
	int version;
	uint32_t key_wrapping_rounds;
	int keyfile_length;
	unsigned char salt[16];
	unsigned char wrappedkey[24];
	char keyfile[4096];
} axcrypt_salt;

static axcrypt_out *output;
static struct custom_salt *cur_salt;
static cl_int cl_error;
static axcrypt_password *inbuffer;
static axcrypt_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;
static int new_keys;

static size_t insize, outsize, settingsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	insize = sizeof(axcrypt_password) * gws;
	outsize = sizeof(axcrypt_out) * gws;
	settingsize = sizeof(axcrypt_salt);

	inbuffer = mem_calloc(1, insize);
	output = mem_alloc(outsize);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (output) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(output);
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
			 "-DPLAINTEXT_LENGTH=%d", PLAINTEXT_LENGTH);
		opencl_init("$JOHN/opencl/axcrypt_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "axcrypt", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       sizeof(axcrypt_password), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 800);
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

static int axcrypt_valid(char *ciphertext, struct fmt_main *self)
{
	return axcrypt_common_valid(ciphertext, self, 1);
}

static void set_salt(void *salt)
{
	cur_salt = *(struct custom_salt **) salt;

	currentsalt.key_wrapping_rounds = cur_salt->key_wrapping_rounds;

	currentsalt.keyfile_length = 0;
	if (cur_salt->keyfile != NULL) {
		currentsalt.keyfile_length = strlen(cur_salt->keyfile);
		memcpy((char*)currentsalt.keyfile, cur_salt->keyfile, currentsalt.keyfile_length);
	}
	memcpy((char*)currentsalt.salt, cur_salt->salt, 16);
	memcpy((char*)currentsalt.wrappedkey, cur_salt->wrappedkey, 24);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
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
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &gws, lws, 0, NULL,
		multi_profilingEvent[1]),
		"Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, outsize, output, 0, NULL, multi_profilingEvent[2]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (output[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return output[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_axcrypt = {
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
		FMT_CASE | FMT_8_BIT | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		axcrypt_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		axcrypt_valid,
		fmt_default_split,
		fmt_default_binary,
		axcrypt_get_salt,
		{
			axcrypt_iteration_count,
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
