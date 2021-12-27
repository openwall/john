/*
 * This software is Copyright (c) 2019 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_zed;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_zed);
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
#include "unicode.h"
#include "zed_common.h"

#define FORMAT_LABEL            "zed-opencl"
#define FORMAT_NAME             "Prim'X Zed! encrypted archives"
#define ALGORITHM_NAME          "PKCS#12 PBE (SHA1/SHA256) OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        48
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

// input
typedef struct {
	uint32_t length;
	uint32_t v[PLAINTEXT_LENGTH / 4];
} zed_password;

// output
typedef struct {
	uint32_t v[key_len / 4];
} zed_hash;

// input
typedef struct {
	uint32_t algo;
	uint32_t iterations;
	uint32_t salt[salt_len / 4];
} zed_salt;

static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static struct custom_salt *cur_salt;
static cl_int cl_error;
static zed_password *inbuffer;
static zed_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;

static size_t insize, outsize, settingsize;
static int new_keys;

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

	insize = sizeof(zed_password) * gws;
	outsize = sizeof(zed_hash) * gws;
	settingsize = sizeof(zed_salt);

	inbuffer = mem_calloc(1, insize);
	crypt_out = mem_alloc(outsize);

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
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(crypt_out);
		crypt_out = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);

	/* The third test vector only works in UTF-8 mode */
	if (options.target_enc == CP1252)
		zed_tests[2].plaintext = "Op\x80nwal\xa3";
	else if (options.target_enc != UTF_8)
		zed_tests[2].ciphertext = zed_tests[2].plaintext = NULL;
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -D%s -D%s", PLAINTEXT_LENGTH,
		         cp_id2macro(options.target_enc),
		         options.internal_cp == UTF_8 ? cp_id2macro(ENC_RAW) :
		         cp_id2macro(options.internal_cp));

		opencl_init("$JOHN/opencl/zed_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "zed", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       sizeof(zed_password), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 1000);
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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;

	currentsalt.iterations = cur_salt->iteration_count;
	currentsalt.algo = cur_salt->algo;
	memcpy((char*)currentsalt.salt, cur_salt->salt, salt_len);

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

	/* Ensure truncation due to over-length or invalid UTF-8 is made like in GPU code. */
	if (options.target_enc == UTF_8)
		truncate_utf8((UTF8*)ret, PLAINTEXT_LENGTH);

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
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]),
		"Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, crypt_out, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

struct fmt_main fmt_opencl_zed = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC,
		{
			"iteration count",
			"hash-func [21:SHA1 22:SHA256]",
		},
		{ FORMAT_TAG },
		zed_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		zed_valid,
		fmt_default_split,
		zed_common_get_binary,
		zed_common_get_salt,
		{
			zed_iteration_count,
			zed_get_mac_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		zed_salt_hash,
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
