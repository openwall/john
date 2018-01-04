/*
 * OpenCL format for cracking NetIQ SSPR hashes.
 *
 * This software is Copyright (c) 2018 Dhiru Kholia <dhiru at openwall.com>,
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
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "options.h"
#include "common-opencl.h"
#include "sspr_common.h"
#include "sspr_variable_code.h"

#define FORMAT_LABEL            "sspr-opencl"
#define ALGORITHM_NAME          "SHA1/SHA2 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define PLAINTEXT_LENGTH        64
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define SALT_LENGTH             32

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} sspr_password;

typedef struct {
	uint8_t v[20];
} sspr_hash;

typedef struct {
	uint32_t length;
	uint32_t count;
	uint8_t salt[SALT_LENGTH];
} sspr_salt;

static uint32_t (*crypt_out)[32 / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

static cl_int cl_error;
static sspr_password *inbuffer;
static sspr_hash *outbuffer;
static sspr_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;
static cl_kernel crypt_kernel_sha1, crypt_kernel_sha256, crypt_kernel_sha512;

size_t insize, outsize, settingsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(sspr_password) * gws;
	outsize = sizeof(sspr_hash) * gws;
	settingsize = sizeof(sspr_salt);

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	crypt_out = mem_calloc(gws, sizeof(*crypt_out));

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	// Salted SHA-1
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");

	// Unsalted SHA-1
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha1, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha1, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha1, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");

	// Salted SHA-256
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha256, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha256, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha256, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");

	// Salted SHA-512
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha512, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha512, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel_sha512, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
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
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DSALT_LENGTH=%d",
		         PLAINTEXT_LENGTH, SALT_LENGTH);
		opencl_init("$JOHN/kernels/sspr_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "sspr_salted_sha1", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		crypt_kernel_sha1 = clCreateKernel(program[gpu_id], "sspr_sha1", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		crypt_kernel_sha256 = clCreateKernel(program[gpu_id], "sspr_salted_sha256", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		crypt_kernel_sha512 = clCreateKernel(program[gpu_id], "sspr_salted_sha512", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(sspr_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 300);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return sspr_valid(ciphertext, self, 0);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	currentsalt.length = cur_salt->saltlen;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->saltlen);
	currentsalt.count = cur_salt->iterations;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	uint32_t length = strlen(key);

	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
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
	int index = 0;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
		"Copy data to gpu");

	// Run kernel
	if (cur_salt->fmt == 2) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					crypt_kernel, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[1]), "Run kernel");
	} else if (cur_salt->fmt == 1) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					crypt_kernel_sha1, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[1]), "Run kernel");
	} else if (cur_salt->fmt == 3) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					crypt_kernel_sha256, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[1]), "Run kernel");
	} else if (cur_salt->fmt == 4) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					crypt_kernel_sha512, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[1]), "Run kernel");
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		memcpy((unsigned char*)crypt_out[index], outbuffer[index].v, BINARY_SIZE_MIN);
	}

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
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_MIN);
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
		FMT_CASE | FMT_8_BIT,
		{
			"KDF [1:SHA1 2:SHA1_SALT 3:SHA256_SALT 4:SHA512_SALT]",
		},
		{ FORMAT_TAG },
		sspr_tests
	},
	{
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		sspr_get_binary,
		sspr_get_salt,
		{
			sspr_get_kdf_type,
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
