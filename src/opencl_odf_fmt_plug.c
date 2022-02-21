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

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_OPENCL && HAVE_LIBCRYPTO

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
#include "odf_common.h"
#include "opencl_common.h"

#define FORMAT_LABEL            "ODF-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA1 BF/AES OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define BINARY_SIZE             (256/8)
#define PLAINTEXT_LENGTH        63
#define SALT_SIZE               sizeof(struct custom_salt)
#define CT_LEN                  1024

typedef struct {
	char v[PLAINTEXT_LENGTH + 1];
} odf_password;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  content[CT_LEN]; /* ciphertext */
	uint32_t content_length;  /* actual data length (up to CT_LEN) */
	uint32_t original_length;
	uint8_t  iv[16];
	uint8_t  salt[64];
	uint32_t cipher_type;
	uint32_t  length;
} odf_salt;

typedef struct {
	uint32_t v[BINARY_SIZE / sizeof(uint32_t)]; /* output from final SHA-256 */
} odf_out;

static cl_int cl_error;
static cl_mem mem_in, mem_out, mem_setting;
static odf_password *saved_key;
static odf_out *crypt_out;
static odf_salt currentsalt;
static int new_keys;

static size_t insize, outsize, settingsize;

static struct custom_salt *cur_salt;

#define STEP			0
#define SEED			256

static struct fmt_main *self;

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

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	insize = sizeof(odf_password) * gws;
	settingsize = sizeof(odf_salt);
	outsize = sizeof(odf_out) * gws;

	saved_key = mem_calloc(1, insize);
	crypt_out = mem_alloc(outsize);

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
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(saved_key);
		MEM_FREE(crypt_out);
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
		         "-DPLAINTEXT_LENGTH=%d -DSALTLEN=%d -DOUTLEN=%d -DCT_LEN=%d",
		         PLAINTEXT_LENGTH, (int)sizeof(currentsalt.salt),
		         (int)sizeof(odf_out), CT_LEN);
		opencl_init("$JOHN/opencl/odf_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "odf", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       sizeof(odf_password), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 1000);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	memcpy(currentsalt.salt, cur_salt->salt, cur_salt->salt_length);
	memcpy(currentsalt.content, cur_salt->content, cur_salt->content_length);
	memcpy(currentsalt.iv, cur_salt->iv, 16);
	currentsalt.content_length = cur_salt->content_length;
	currentsalt.original_length = cur_salt->original_length;
	currentsalt.length = cur_salt->salt_length;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.outlen = cur_salt->key_size;
	currentsalt.cipher_type = cur_salt->cipher_type;
	currentsalt.skip_bytes = 0;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index].v, key, sizeof(saved_key[index].v));

	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index].v;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, saved_key, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

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
		if (((uint32_t*)binary)[0] == crypt_out[index].v[0])
			return 1;

/* Check alternative hash (32 first bits stored in v[5]) for StarOffice bug */
	if (cur_salt->cipher_type == 0 &&
	    (cur_salt->original_length & 63) >> 2 == 13)
		for (index = 0; index < count; index++)
			if (((uint32_t*)binary)[0] == crypt_out[index].v[5])
				return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	const int binary_size = cur_salt->cipher_type ? 32 : 16;

	return (!memcmp(binary, crypt_out[index].v, binary_size) ||
	        (cur_salt->cipher_type == 0 &&
	         (cur_salt->original_length & 63) >> 2 == 13 &&
	         ((uint32_t*)binary)[0] == crypt_out[index].v[5]));
}

static int cmp_exact(char *source, int index)
{
	if (cur_salt->cipher_type != 0 ||
	    (cur_salt->original_length & 63) >> 2 != 13)
		return 1;
	else
		return odf_common_cmp_exact(source, saved_key[index].v, cur_salt);
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
			"crypto [0=Blowfish 1=AES]",
		},
		{ FORMAT_TAG },
		odf_tests
	}, {
		init,
		done,
		reset,
		odf_prepare,
		odf_valid,
		fmt_default_split,
		odf_get_binary,
		odf_get_salt,
		{
			odf_iteration_count,
			odf_crypto,
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

#endif /* HAVE_OPENCL && HAVE_LIBCRYPTO */
