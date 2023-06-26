/*
 * This software is Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com>
 * with some code Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * improvements Copyright (c) 2014 by JimF, Copyright (c) 2014-2021 by magnum.
 *
 * This is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_zip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_zip);
#else

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "opencl_common.h"
#include "pkzip.h"
#include "dyna_salt.h"
#include "options.h"

#define FORMAT_LABEL        "ZIP-opencl"
#define FORMAT_NAME         "WinZip"
#define ALGORITHM_NAME      "PBKDF2-SHA1 OpenCL"
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#define BINARY_ALIGN        sizeof(uint32_t)
#define PLAINTEXT_LENGTH    64
#define SALT_SIZE           sizeof(winzip_salt*)
#define SALT_ALIGN          sizeof(size_t)
#define BLK_SZ              20

typedef struct {
	uint in_idx;
	uint8_t v[BLK_SZ]; /* MAX(BLK_SZ, WINZIP_BINARY_SIZE) */
} zip_hash;

typedef struct {
	uint32_t iterations;
	uint32_t key_len;
	uint32_t length;
	uint8_t  salt[64];
	uint32_t autotune;
	uint64_t comp_len;
	uint8_t  passverify[2];
} zip_salt;

static winzip_salt *saved_salt;
static zip_salt currentsalt;

static char *saved_key;
static int new_keys;

static unsigned int *saved_idx, key_idx;
static zip_hash *outbuffer;
static unsigned int crack_count_ret;
static size_t key_offset, idx_offset;
static cl_mem pinned_key, pinned_idx, pinned_result;
static cl_mem cl_saved_key, cl_saved_idx, cl_result, cl_crack_count_ret, cl_salt, cl_data;
static cl_kernel final_kernel;

static struct fmt_main *self;

static size_t saltsize, datasize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"xfer: ",  ", crypt: ",  ", final: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);

	return MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	size_t insize, idxsize, outsize;

	release_clobj();

	insize = PLAINTEXT_LENGTH * gws;
	idxsize = sizeof(cl_uint) * (gws + 1);
	outsize = sizeof(zip_hash) * gws;
	saltsize = sizeof(zip_salt);
	datasize = MAX(datasize, 1024);

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, insize, NULL, &ret_code);
	if (ret_code == CL_SUCCESS) {
		saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, insize, 0, NULL, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error mapping saved_key");
	} else {
		/* Silent fallback to non-pinned memory */
		saved_key = mem_alloc(insize);
	}
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	pinned_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, idxsize, NULL, &ret_code);
	if (ret_code == CL_SUCCESS) {
		saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, idxsize, 0, NULL, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error mapping saved_idx");
	} else {
		/* Silent fallback to non-pinned memory */
		saved_idx = mem_alloc(idxsize);
	}
	cl_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, idxsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, outsize, NULL, &ret_code);
	if (ret_code == CL_SUCCESS) {
		outbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, outsize, 0, NULL, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error mapping outbuffer");
	} else {
		/* Silent fallback to non-pinned memory */
		outbuffer = mem_alloc(outsize);
	}
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_data = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, datasize, NULL, &ret_code);

	cl_crack_count_ret = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	crack_count_ret = 0;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &crack_count_ret, 0, NULL, NULL), "Failed resetting crack return");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), &cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), &cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), &cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), &cl_crack_count_ret), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem), &cl_result), "Error setting argument 4");

	HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(cl_mem), &cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(cl_mem), &cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(cl_mem), &cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_mem), &cl_data), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(final_kernel, 4, sizeof(cl_mem), &cl_crack_count_ret), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(final_kernel, 5, sizeof(cl_mem), &cl_result), "Error setting argument 5");
}

static void release_clobj(void)
{
	if (outbuffer) {
		if (pinned_result) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, outbuffer, 0, NULL, NULL), "Error Unmapping outbuffer");
			HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
		} else
			MEM_FREE(outbuffer);

		if (pinned_key) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
			HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
		} else
			MEM_FREE(saved_key);

		if (pinned_idx) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
			HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
		} else
			MEM_FREE(saved_idx);

		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release salt buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_data), "Release salt datablob");
		HANDLE_CLERROR(clReleaseMemObject(cl_crack_count_ret), "Release crack count buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");

		outbuffer = NULL;
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
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
	size_t gws_limit = 4 << 20;
	char build_opts[64];

	if (crypt_kernel)
		done();

	snprintf(build_opts, sizeof(build_opts), "-DPLAINTEXT_LENGTH=%u -DSALTLEN=%d",
	         PLAINTEXT_LENGTH, (int)sizeof(currentsalt.salt));

	if (!program[gpu_id])
		opencl_init("$JOHN/opencl/zip_kernel.cl", gpu_id, build_opts);

	crypt_kernel = clCreateKernel(program[gpu_id], "zip", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating zip kernel");

	final_kernel = clCreateKernel(program[gpu_id], "zip_final", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating zip_final kernel");

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1,
	                       self, create_clobj, release_clobj,
	                       PLAINTEXT_LENGTH + 4 + sizeof(zip_hash), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 2 * KEYING_ITERATIONS + 2, gws_limit, 2000);
}

static void set_salt(void *salt)
{
	saved_salt = *((winzip_salt**)salt);

	memcpy((char*)currentsalt.salt, saved_salt->salt, SALT_LENGTH(saved_salt->v.mode));
	memcpy((char*)currentsalt.passverify, saved_salt->passverify, PWD_VER_LENGTH);
	currentsalt.length = SALT_LENGTH(saved_salt->v.mode);
	currentsalt.iterations = KEYING_ITERATIONS;
	currentsalt.key_len = KEY_LENGTH(saved_salt->v.mode);
	currentsalt.comp_len = saved_salt->comp_len;
	currentsalt.autotune = ocl_autotune_running;

	if (saved_salt->comp_len > datasize) {
		datasize = saved_salt->comp_len;
		HANDLE_CLERROR(clReleaseMemObject(cl_data), "Release mem data");
		cl_data = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, datasize, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_data), &cl_data),
		               "Error while setting mem_salt kernel argument");
	}
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
	               "Failed transferring salt");
	if (saved_salt->comp_len)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_data, CL_FALSE, 0,
			saved_salt->comp_len, saved_salt->datablob, 0, NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void clear_keys(void)
{
	key_idx = 0;
	saved_idx[0] = 0;
	key_offset = 0;
	idx_offset = 0;
}

static void set_key(char *key, int index)
{
	while (*key)
		saved_key[key_idx++] = *key++;

	saved_idx[index + 1] = key_idx;
	new_keys = 1;

	/* Early partial transfer to GPU */
	if (index && !(index & (64 * 1024 - 1))) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		key_offset = key_idx;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * index - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, NULL), "Failed transferring index");
		idx_offset = 4 * index;
		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		new_keys = 0;
	}
}

static char *get_key(int out_index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	char *key;
	int i, len;
	int index = crack_count_ret ? outbuffer[out_index].in_idx : out_index; /* Self-test & status kludge */

	len = saved_idx[index + 1] - saved_idx[index];
	key = (char*)&saved_key[saved_idx[index]];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	if (new_keys) {
		if (idx_offset > 4 * (gws + 1))
			idx_offset = 0;	/* Self-test kludge */

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, multi_profilingEvent[0]), "Failed transferring keys");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (gws + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, multi_profilingEvent[0]), "Failed transferring index");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");

		new_keys = 0;
	}

	WAIT_INIT(gws)
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[1]), "Failed running crypt kernel");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &crack_count_ret, 0, NULL, NULL), "failed reading results back");

	BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	WAIT_UPDATE
	WAIT_DONE

	if (crack_count_ret) {
		if (crack_count_ret > count)
			error_msg("Corrupt return: Got a claimed %u cracks out of %d\n", crack_count_ret, count);

		gws = GET_NEXT_MULTIPLE(crack_count_ret, local_work_size);
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "Failed running crypt kernel");
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, sizeof(zip_hash) * crack_count_ret, outbuffer, 0, NULL, multi_profilingEvent[3]), "failed reading results back");

		static const cl_uint zero = 0;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL), "Failed resetting crack return");
	}

	return crack_count_ret;
}

static int cmp_all(void *binary, int count)
{
	return crack_count_ret;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(outbuffer[index].v, binary, WINZIP_BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}


static unsigned int cost_hmac_len(void *salt)
{
	winzip_salt *s = *((winzip_salt**)salt);

	return s->comp_len;
}

struct fmt_main fmt_opencl_zip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		WINZIP_BENCHMARK_COMMENT,
		WINZIP_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		WINZIP_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"HMAC size"
		},
		{ WINZIP_FORMAT_TAG },
		winzip_common_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		winzip_common_valid,
		winzip_common_split,
		winzip_common_binary,
		winzip_common_get_salt,
		{
			cost_hmac_len
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		set_key,
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
