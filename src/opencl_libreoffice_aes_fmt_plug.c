/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for ODF AES format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and Copyright (c) 2017 magnum, and it is hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_odf_aes;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_odf_aes);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "options.h"
#include "aes.h"
#include "libreoffice_common.h"
#define INCLUDE_AES_HASHES      1
#include "libreoffice_variable_code.h"
#include "common-opencl.h"

#define FORMAT_LABEL            "ODF-AES-opencl"
#define ALGORITHM_NAME          "SHA256 PBKDF2-SHA1 AES OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#undef BINARY_SIZE
#define BINARY_SIZE             (256/8)
#define PLAINTEXT_LENGTH        63
#define SALT_SIZE               sizeof(struct custom_salt)
#define AES_LEN                 1024

typedef struct {
	char v[PLAINTEXT_LENGTH + 1];
} odf_password;

typedef struct {
	uint8_t v[256/8];
} odf_sha_key;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  aes_ct[AES_LEN]; /* ciphertext */
	uint32_t aes_len;         /* actual data length (up to AES_LEN) */
	uint8_t  iv[16];
	uint8_t  salt[64];
	uint8_t  length;
} odf_salt;

typedef struct {
	uint v[BINARY_SIZE / sizeof(uint)]; /* output from final SHA-256 */
} odf_out;

static cl_int cl_error;
static cl_mem mem_in, mem_out, mem_setting, mem_key;
static odf_password *saved_key;
static odf_out *crypt_out;
static odf_salt currentsalt;

size_t insize, outsize, settingsize, cracked_size, sha_size;

static struct custom_salt *cur_salt;

#define STEP			0
#define SEED			256

static struct fmt_main *self;

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(odf_password) * gws;
	settingsize = sizeof(odf_salt);
	sha_size = sizeof(odf_sha_key) * gws;
	outsize = sizeof(odf_out) * gws;

	saved_key = mem_calloc(1, insize);
	crypt_out = mem_alloc(outsize);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_key =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sha_size, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem key");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(mem_key),
		&mem_key), "Error while setting mem_key kernel argument");
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_key), "Release mem key");

		MEM_FREE(saved_key);
		MEM_FREE(crypt_out);
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

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d -DAES_LEN=%d",
		         PLAINTEXT_LENGTH,
		         (int)sizeof(odf_sha_key),
		         (int)sizeof(currentsalt.salt),
		         (int)sizeof(odf_out),
		         AES_LEN);
		opencl_init("$JOHN/kernels/odf_aes_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "dk_decrypt", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(odf_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return libreoffice_valid(ciphertext, self, 0, 2);	// types=2 gives sha256 only
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	memcpy(currentsalt.salt, cur_salt->salt, cur_salt->salt_length);
	memcpy(currentsalt.aes_ct, cur_salt->content, cur_salt->content_length);
	memcpy(currentsalt.iv, cur_salt->iv, 16);
	currentsalt.aes_len = cur_salt->content_length;
	currentsalt.length = cur_salt->salt_length;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.outlen = cur_salt->key_size;
	currentsalt.skip_bytes = 0;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy salt to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index].v, key, sizeof(saved_key[index].v));
}

static char *get_key(int index)
{
	return saved_key[index].v;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, saved_key, 0, NULL, multi_profilingEvent[0]),
		"Copy data to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]), "Run kernel");

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
		if (!memcmp(binary, crypt_out[index].v, BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index].v, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_odf_aes = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		4,
		SALT_SIZE,
		4,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		libreoffice_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		libreoffice_get_binary,
		libreoffice_get_salt,
		{
			libreoffice_iteration_count,
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
