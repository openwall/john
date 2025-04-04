/*
 * Based on work by Tim Medin, Michael Kramer (SySS GmbH) and Fist0urs
 *
 * This software is Copyright (c) 2023 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL
#define FMT_STRUCT fmt_opencl_krb5tgs

#if FMT_EXTERNS_H
extern struct fmt_main FMT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FMT_STRUCT);
#else

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "opencl_common.h"
#include "misc.h"
#include "formats.h"
#include "common.h"
#include "dyna_salt.h"
#include "krb5_tgs_common.h"
#include "unicode.h"
#include "mask_ext.h"

#define FORMAT_LABEL         "krb5tgs-opencl"
#define ALGORITHM_NAME       "MD4 HMAC-MD5 RC4 OpenCL"
#define PLAINTEXT_LENGTH     27
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1

static size_t key_offset, idx_offset;
static unsigned int *saved_idx, key_idx, crack_count_ret;
static char *saved_key;
static int new_keys;

static krb5tgs_salt *cur_salt;

typedef struct {
	uint32_t saved_K1[16/4];
} krb5tgs_state;

typedef struct {
	uint32_t orig_index;
} krb5tgs_out;

static krb5tgs_out *result;
static struct fmt_main *self;
static cl_kernel init_kernel;
static cl_mem pinned_key, pinned_idx, pinned_int_key_loc, cl_int_keys, cl_int_key_loc;
static cl_mem cl_saved_key, cl_saved_idx, cl_crack_count_ret, cl_state, cl_result, cl_salt;
static cl_uint *saved_int_key_loc;
static cl_int cl_error;
static int static_gpu_locations[MASK_FMT_INT_PLHDR];
static size_t outsize, saltsize, idxsize, intkeysize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"key xfer: ",  ", idx xfer: ",  ", init: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t ls = gpu_amd(device_info[gpu_id]) ? 64 :
		gpu(device_info[gpu_id]) ? 32 : 1024;

	size_t s = MIN(autotune_get_task_max_work_group_size(FALSE, 0, init_kernel), ls);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	static size_t insize, statesize;

	release_clobj();

	insize = PLAINTEXT_LENGTH * gws;
	idxsize = sizeof(cl_uint) * (gws + 1);
	intkeysize = sizeof(cl_uint) * gws;
	statesize = sizeof(krb5tgs_state) * gws * mask_int_cand.num_int_cand;
	outsize = sizeof(krb5tgs_out) * gws * mask_int_cand.num_int_cand;
	saltsize = sizeof(krb5tgs_salt) + krb5tgs_max_data_len;

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, insize, NULL, &ret_code);
	if (ret_code == CL_SUCCESS)
		saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_WRITE, 0, insize, 0, NULL, NULL, &ret_code);
	if (ret_code != CL_SUCCESS)	/* Silent fallback to non-pinned memory */
		saved_key = mem_alloc(insize);
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, insize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer");

	pinned_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, idxsize, NULL, &ret_code);
	if (ret_code == CL_SUCCESS)
		saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_idx, CL_TRUE, CL_MAP_WRITE, 0, idxsize, 0, NULL, NULL, &ret_code);
	if (ret_code != CL_SUCCESS)	/* Silent fallback to non-pinned memory */
		saved_idx = mem_alloc(idxsize);
	cl_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, idxsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer");

	pinned_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, intkeysize, NULL, &ret_code);
	if (ret_code == CL_SUCCESS)
		saved_int_key_loc = clEnqueueMapBuffer(queue[gpu_id], pinned_int_key_loc, CL_TRUE, CL_MAP_WRITE, 0, intkeysize, 0, NULL, NULL, &ret_code);
	if (ret_code != CL_SUCCESS)	/* Silent fallback to non-pinned memory */
		saved_int_key_loc = mem_alloc(intkeysize);
	cl_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, intkeysize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer");

	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY, saltsize, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	cl_crack_count_ret = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating mem crack count");
	cl_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, statesize, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");
	result = mem_calloc(outsize, 1);

	unsigned int dummy = 0;
	cl_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_HOST_WRITE_ONLY | CL_MEM_COPY_HOST_PTR, 4 * mask_int_cand.num_int_cand, mask_int_cand.int_cand ? mask_int_cand.int_cand : (void *)&dummy, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument cl_int_keys.");

	crack_count_ret = 0;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_crack_count_ret, CL_TRUE, 0, sizeof(cl_uint), &crack_count_ret, 0, NULL, NULL), "Failed resetting crack return");

	HANDLE_CLERROR(clSetKernelArg(init_kernel, 0, sizeof(cl_mem), &cl_saved_key), "Error setting argument");
	HANDLE_CLERROR(clSetKernelArg(init_kernel, 1, sizeof(cl_mem), &cl_saved_idx), "Error setting argument");
	HANDLE_CLERROR(clSetKernelArg(init_kernel, 2, sizeof(cl_mem), &cl_state), "Error setting argument");
	HANDLE_CLERROR(clSetKernelArg(init_kernel, 3, sizeof(cl_mem), &cl_int_key_loc), "Error setting argument");
	HANDLE_CLERROR(clSetKernelArg(init_kernel, 4, sizeof(cl_mem), &cl_int_keys), "Error setting argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), &cl_salt), "Error setting argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), &cl_state), "Error setting argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), &cl_crack_count_ret), "Error setting argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), &cl_result), "Error setting argument");
}

static void release_clobj(void)
{
	if (result) {
		if (pinned_int_key_loc) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc, saved_int_key_loc, 0, NULL, NULL), "Error Unmapping outbuffer");
			HANDLE_CLERROR(clReleaseMemObject(pinned_int_key_loc), "Release pinned int_key_loc buffer");
		} else
			MEM_FREE(saved_int_key_loc);

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

		HANDLE_CLERROR(clReleaseMemObject(cl_int_keys), "Error releasing memory");
		HANDLE_CLERROR(clReleaseMemObject(cl_result), "Error releasing memory");
		HANDLE_CLERROR(clReleaseMemObject(cl_state), "Error releasing memory");
		HANDLE_CLERROR(clReleaseMemObject(cl_crack_count_ret), "Error releasing memory");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Error releasing memory");

		MEM_FREE(result);
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);

	mask_int_cand_target = opencl_speed_index(gpu_id) >> 16;
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Error releasing kernel");
		HANDLE_CLERROR(clReleaseKernel(init_kernel), "Error releasing kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Error releasing Program");

		program[gpu_id] = NULL;
	}
}

static void reset(struct db_main *db)
{
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
	         "-DPLAINTEXT_LENGTH=%u -DDATA_LEN=%zu"
#if !NT_FULL_UNICODE
	         " -DUCS_2"
#endif
	         " -DCONST_CACHE_SIZE=%llu -D%s -D%s -DLOC_0=%d"
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
	         krb5tgs_max_data_len,
	         (unsigned long long)const_cache_size,
	         cp_id2macro(options.internal_cp),
	         options.internal_cp == UTF_8 ? cp_id2macro(ENC_RAW) :
	         cp_id2macro(options.internal_cp), static_gpu_locations[0],
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

	if (!program[gpu_id]) {
		opencl_init("$JOHN/opencl/krb5tgs_kernel.cl", gpu_id, build_opts);

		init_kernel = clCreateKernel(program[gpu_id], "krb5tgs_init", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
		crypt_kernel = clCreateKernel(program[gpu_id], "krb5tgs_crypt", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	size_t gws_limit = ((1 << 25) / mask_int_cand.num_int_cand);
	size_t largest_buf_size = MAX(PLAINTEXT_LENGTH, sizeof(krb5tgs_state) * mask_int_cand.num_int_cand);

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       largest_buf_size, gws_limit, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, gws_limit, 200);
}

static void set_salt(void *salt)
{
	cur_salt = *(krb5tgs_salt**)salt;

	if (cur_salt->edata2len > krb5tgs_max_data_len)
		error_msg("This should not happen, please report.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0,
	                                    saltsize, cur_salt, 0, NULL, NULL),
	               "Failed transferring salt");
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

	/* Early partial transfer to GPU every 2 MB */
	if ((key_idx - key_offset) > (2 << 20)) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (index + 2) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, NULL), "Failed transferring index");

		if (!mask_gpu_is_static)
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_int_key_loc, CL_FALSE, idx_offset, 4 * (index + 1) - idx_offset, saved_int_key_loc + (idx_offset / 4), 0, NULL, NULL), "failed transferring cl_int_key_loc.");

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");

		key_offset = key_idx;
		idx_offset = 4 * (index + 1);

		// Can't zero new_keys because we run a kernel depending on it
	}
}

static char *get_key(int index)
{
	static UTF16 u16[PLAINTEXT_LENGTH + 1];
	static UTF8 out[3 * PLAINTEXT_LENGTH + 1];
	UTF8 *ret;
	int i, len;
	UTF8 *key;
	if (crack_count_ret)
		index = result[index].orig_index;
	int t = index;
	int int_index = 0;

	if (mask_int_cand.num_int_cand) {
		t = index / mask_int_cand.num_int_cand;
		int_index = index % mask_int_cand.num_int_cand;
	}
	else if (t >= global_work_size)
		t = 0;

	len = saved_idx[t + 1] - saved_idx[t];
	key = (UTF8*)&saved_key[saved_idx[t]];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	/* Ensure we truncate just like the GPU conversion does */
	enc_to_utf16(u16, PLAINTEXT_LENGTH, (UTF8*)out, len);
	ret = utf16_to_enc(u16);

	/* Apply GPU-side mask */
	if (len && mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			if (mask_gpu_is_static)
				ret[static_gpu_locations[i]] =
					mask_int_cand.int_cand[int_index].x[i];
			else
				ret[(saved_int_key_loc[t] & (0xff << (i * 8))) >> (i * 8)] =
					mask_int_cand.int_cand[int_index].x[i];
	}

	/* Ensure truncation due to over-length or invalid UTF-8 is made like in GPU code. */
	if (options.target_enc == UTF_8)
		truncate_utf8((UTF8*)out, PLAINTEXT_LENGTH);

	return (char*)ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	size_t lws = local_work_size ? local_work_size : 32;
	size_t gws = GET_NEXT_MULTIPLE(count, lws);

	*pcount *= mask_int_cand.num_int_cand;

	/* Safety for when count < GWS */
	for (int i = count; i <= gws; i++)
		saved_idx[i] = key_idx;

	if (new_keys) {
		/* Self-test kludge */
		if (idx_offset > idxsize)
			idx_offset = 0;

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, multi_profilingEvent[0]), "Failed transferring keys");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, idxsize - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, multi_profilingEvent[1]), "Failed transferring index");

		if (!mask_gpu_is_static)
			BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_int_key_loc, CL_FALSE, idx_offset, intkeysize - idx_offset, saved_int_key_loc + (idx_offset / 4), 0, NULL, NULL), "failed transferring cl_int_key_loc.");

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], init_kernel, 1,
			NULL, &gws, &lws, 0, NULL,
			multi_profilingEvent[2]),
			"Run kernel");

		new_keys = 0;
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &gws, &lws, 0, NULL,
		multi_profilingEvent[3]),
		"Run kernel");

	// Query how many candidates passed the early-rejection
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_crack_count_ret, CL_TRUE, 0, sizeof(cl_uint), &crack_count_ret, 0, NULL, multi_profilingEvent[4]), "failed reading results back");

	if (crack_count_ret) {
		if (crack_count_ret > count * mask_int_cand.num_int_cand)
			error_msg("Corrupt return: Got a claimed %u cracks out of %d\n",
			          crack_count_ret, count * mask_int_cand.num_int_cand);

		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, sizeof(krb5tgs_out) * crack_count_ret, result, 0, NULL, NULL), "failed reading results back");

		static const cl_uint zero = 0;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL), "Failed resetting crack return");
	}

	return crack_count_ret;
}

static int cmp_all(void *binary, int count)
{
	return (crack_count_ret > 0);
}

static int cmp_one(void *binary, int index)
{
	return (crack_count_ret && index < crack_count_ret);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main FMT_STRUCT = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_DYNA_SALT | FMT_HUGE_INPUT | FMT_MASK,
		{NULL},
		{ FORMAT_TAG },
		krb5tgs_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		krb5tgs_valid,
		krb5tgs_split,
		fmt_default_binary,
		krb5tgs_get_salt,
		{NULL},
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
