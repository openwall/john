/*
 * This software is Copyright (c) 2021, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Cracker for cryptoSafe vaults, as found at https://github.com/Anubis901/SafeCrypto
 * Vault file is loaded as-is; there's no "cryptosafe2john" or such involved.
 */

#define FORMAT_STRUCT fmt_opencl_cryptosafe

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main FORMAT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FORMAT_STRUCT);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "opencl_common.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "cryptosafe_common.h"
#include "mask_ext.h"

#define FORMAT_LABEL        "cryptosafe-opencl"
#define FORMAT_NAME         ""
#define ALGORITHM_NAME      "AES-256-CBC OpenCL"

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static struct custom_salt *cur_salt;

static char *saved_key;
static int new_keys;

static unsigned int *saved_idx, key_idx;
static unsigned int *cracked, crack_count_ret;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_salt, cl_result, cl_crack_count_ret;
static cl_mem pinned_key, pinned_idx, pinned_result;
static cl_mem pinned_int_key_loc, buffer_int_keys, buffer_int_key_loc;
static cl_uint *saved_int_key_loc;
static int static_gpu_locations[MASK_FMT_INT_PLHDR];
static struct fmt_main *self;

#define STEP			0
#define SEED			1024

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"xP: ",  ", xI: ",  ", crypt: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	unsigned int dummy = 0;

	release_clobj();

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * (gws + 1), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_idx");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(unsigned int) * gws * mask_int_cand.num_int_cand, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(unsigned int) * gws * mask_int_cand.num_int_cand, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	cracked = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(unsigned int) * gws * mask_int_cand.num_int_cand, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping cracked");

	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(struct custom_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_crack_count_ret = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	crack_count_ret = 0;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &crack_count_ret, 0, NULL, NULL), "Failed resetting crack return");

	pinned_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_int_key_loc.");
	saved_int_key_loc = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_int_key_loc, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_int_key_loc.");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer_int_key_loc.");

	buffer_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 4 * mask_int_cand.num_int_cand, mask_int_cand.int_cand ? mask_int_cand.int_cand : (void *)&dummy, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_keys.");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem), (void*)&cl_crack_count_ret), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(buffer_int_key_loc), (void *) &buffer_int_key_loc), "Error setting argument 5.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_int_keys), (void *) &buffer_int_keys), "Error setting argument 6.");
}

static void release_clobj(void)
{
	if (cl_salt) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, cracked, 0, NULL, NULL), "Error Unmapping cracked");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc, saved_int_key_loc, 0, NULL, NULL), "Error Unmapping saved_int_key_loc.");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_crack_count_ret), "Release crack flag buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release salt buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_keys), "Error Releasing buffer_int_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_key_loc), "Error Releasing buffer_int_key_loc.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_int_key_loc), "Error Releasing pinned_int_key_loc.");

		cl_salt = NULL;
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		crypt_kernel = NULL;
		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_prepare_dev(gpu_id);

	mask_int_cand_target = opencl_speed_index(gpu_id) / 10000;
}

static void reset(struct db_main *db)
{
	size_t gws_limit = 4 << 20;
	cl_ulong const_cache_size;
	char build_opts[1024];
	int i;

	if (crypt_kernel)
		done();

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof(cl_ulong), &const_cache_size, 0), "failed to get CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE.");

	snprintf(build_opts, sizeof(build_opts),
	         "-DPLAINTEXT_LENGTH=%u"
	         " -DCONST_CACHE_SIZE=%llu -DLOC_0=%d"
#if MASK_FMT_INT_PLHDR > 1
	         " -DLOC_1=%d"
#endif
#if MASK_FMT_INT_PLHDR > 2
	         " -DLOC_2=%d"
#endif
#if MASK_FMT_INT_PLHDR > 3
	         " -DLOC_3=%d"
#endif
	         " -DNUM_INT_KEYS=%u -DIS_STATIC_GPU_MASK=%d",
	         PLAINTEXT_LENGTH,
	         (unsigned long long)const_cache_size,
	         static_gpu_locations[0],
#if MASK_FMT_INT_PLHDR > 1
	         static_gpu_locations[1],
#endif
#if MASK_FMT_INT_PLHDR > 2
	         static_gpu_locations[2],
#endif
#if MASK_FMT_INT_PLHDR > 3
	         static_gpu_locations[3],
#endif
	         mask_int_cand.num_int_cand, mask_gpu_is_static
		);

	if (!program[gpu_id])
		opencl_init("$JOHN/opencl/cryptosafe_kernel.cl", gpu_id, build_opts);

	/* create kernels to execute */
	if (!crypt_kernel) {
		crypt_kernel = clCreateKernel(program[gpu_id], "cryptoSafe", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 2, self, create_clobj,
	                       release_clobj, PLAINTEXT_LENGTH, gws_limit, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, gws_limit, 100);

	new_keys = 1;
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
	if (mask_int_cand.num_int_cand > 1 && !mask_gpu_is_static) {
		int i;

		saved_int_key_loc[index] = 0;
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
			if (mask_skip_ranges[i] != -1)  {
				saved_int_key_loc[index] |= ((mask_int_cand.
				int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset +
				mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos) & 0xff) << (i << 3);
			}
			else
				saved_int_key_loc[index] |= 0x80 << (i << 3);
		}
	}

	while (*key)
		saved_key[key_idx++] = *key++;

	saved_idx[index + 1] = key_idx;
	new_keys = 1;

	/* Early partial transfer to GPU */
	if (index && !(index & (256*1024 - 1))) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (index + 2) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, NULL), "Failed transferring index");

		if (!mask_gpu_is_static)
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_FALSE, idx_offset, 4 * (index + 1) - idx_offset, saved_int_key_loc + (idx_offset / 4), 0, NULL, NULL), "failed transferring buffer_int_key_loc.");

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");

		key_offset = key_idx;
		idx_offset = 4 * (index + 1);
		new_keys = 0;
	}
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	char *key;
	int i, len;
	int t = index;
	int int_index = 0;

	if (mask_int_cand.num_int_cand) {
		t = index / mask_int_cand.num_int_cand;
		int_index = index % mask_int_cand.num_int_cand;
	}
	else if (t >= global_work_size)
		t = 0;

	len = saved_idx[t + 1] - saved_idx[t];
	key = (char*)&saved_key[saved_idx[t]];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	/* Apply GPU-side mask */
	if (len && mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			if (mask_gpu_is_static)
				out[static_gpu_locations[i]] =
					mask_int_cand.int_cand[int_index].x[i];
			else
				out[(saved_int_key_loc[t] & (0xff << (i * 8))) >> (i * 8)] =
					mask_int_cand.int_cand[int_index].x[i];
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = salt;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, sizeof(struct custom_salt), cur_salt, 0, NULL, NULL), "Failed transferring salt");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

/* Returns the last output index for which there might be a match (against the
 * supplied salt's hashes) plus 1.  A return value of zero indicates no match.*/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	*pcount *= mask_int_cand.num_int_cand;

	if (new_keys) {
		/* Self-test kludge */
		if (idx_offset > 4 * (gws + 1))
			idx_offset = 0;

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, multi_profilingEvent[0]), "Failed transferring keys");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (gws + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, multi_profilingEvent[1]), "Failed transferring index");

		if (!mask_gpu_is_static)
			BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_FALSE, idx_offset, 4 * gws - idx_offset, saved_int_key_loc + (idx_offset / 4), 0, NULL, NULL), "failed transferring buffer_int_key_loc.");

		new_keys = 0;
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "Failed running crypt kernel");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_crack_count_ret, CL_TRUE, 0, sizeof(int), &crack_count_ret, 0, NULL, NULL), "failed reading results back");

	if (crack_count_ret) {
		if (crack_count_ret > *pcount)
			error_msg("Corrupt return: Got a claimed %u cracks out of %d\n", crack_count_ret, *pcount);

		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, sizeof(unsigned int) * crack_count_ret, cracked, 0, NULL, NULL), "failed reading results back");

		cl_uint zero = 0;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL), "Failed resetting crack return");
	}

	return crack_count_ret;
}

static int cmp_all(void *binary, int count)
{
	return count;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main FORMAT_STRUCT = {
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
		FMT_CASE | FMT_8_BIT | FMT_UTF8 | FMT_HUGE_INPUT | FMT_MASK,
		{
			NULL
		},
		{ FORMAT_TAG },
		cryptosafe_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		cryptosafe_valid,
		cryptosafe_split,
		fmt_default_binary,
		cryptosafe_get_salt,
		{
			NULL
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
