/*
 * This software is Copyright (c) 2024 magnum and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */

#define FORMAT_STRUCT fmt_opencl_pdf

#ifdef HAVE_OPENCL

#if FMT_REGISTERS_H
john_register_one(&FORMAT_STRUCT);
#else
extern struct fmt_main FORMAT_STRUCT;

#include "pdf_common.h"
#include "opencl_common.h"
#include "opencl_helper_macros.h"
#include "mask_ext.h"

#define FORMAT_LABEL        "pdf-opencl"
#define ALGORITHM_NAME      ALGORITHM_BASE " OpenCL"
#define MAX_KEYS_PER_CRYPT  1

static int new_keys;

/* Boilerplate OpenCL stuff */
static char *saved_key;
static unsigned int *saved_idx, key_idx;
static unsigned int *result, crack_count_ret;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_salt, cl_result, cl_crack_count_ret;
static cl_mem pinned_saved_key, pinned_saved_idx, pinned_result;
static cl_mem pinned_saved_int_key_loc, cl_buffer_int_keys, cl_saved_int_key_loc;
static cl_uint *saved_int_key_loc;
static int static_gpu_locations[MASK_FMT_INT_PLHDR];
static const cl_uint zero = 0;

static cl_kernel pdf_kernel[4];
static char *kernel_name[4] = { "pdf_r2", "pdf_r34", "pdf_r5", "pdf_r6" };

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
	int i;
	size_t s = gpu_amd(device_info[gpu_id]) ? 64 :
		gpu(device_info[gpu_id]) ? 32 : 1024;

	for (i = 0; i < 4; i++)
		s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pdf_kernel[i]));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int i;

	release_clobj();

	CLCREATEPINNED(saved_key, CL_RO, PLAINTEXT_LENGTH * gws);
	CLCREATEPINNED(saved_idx, CL_RO, sizeof(cl_uint) * (gws + 1));
	CLCREATEPINNED(result, CL_WO, sizeof(cl_uint) * gws * mask_int_cand.num_int_cand);
	CLCREATEBUFFER(cl_salt, CL_RO, sizeof(pdf_salt_type));
	CLCREATEBUFFER(cl_crack_count_ret, CL_RW, sizeof(cl_uint));

	/* For GPU-side mask */
	CLCREATEPINNED(saved_int_key_loc, CL_RO, sizeof(cl_uint) * gws);
	CLCREATEBUFCOPY(cl_buffer_int_keys, CL_RO, 4 * mask_int_cand.num_int_cand,
	                mask_int_cand.int_cand ? mask_int_cand.int_cand : (void*)&zero);

	crack_count_ret = 0;
	CLWRITE(cl_crack_count_ret, CL_TRUE, 0, sizeof(cl_uint), &crack_count_ret, NULL);

	for (i = 0; i < 4; i++) {
		CLKERNELARG(pdf_kernel[i], 0, cl_saved_key);
		CLKERNELARG(pdf_kernel[i], 1, cl_saved_idx);
		CLKERNELARG(pdf_kernel[i], 2, cl_salt);
		CLKERNELARG(pdf_kernel[i], 3, cl_result);
		CLKERNELARG(pdf_kernel[i], 4, cl_crack_count_ret);
		CLKERNELARG(pdf_kernel[i], 5, cl_saved_int_key_loc);
		CLKERNELARG(pdf_kernel[i], 6, cl_buffer_int_keys);
	}
}

static void release_clobj(void)
{
	if (cl_salt) {
		CLRELEASEPINNED(result);
		CLRELEASEPINNED(saved_key);
		CLRELEASEPINNED(saved_idx);
		CLRELEASEPINNED(saved_int_key_loc);
		CLRELEASEBUFFER(cl_crack_count_ret);
		CLRELEASEBUFFER(cl_salt);
		CLRELEASEBUFFER(cl_buffer_int_keys);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		int i;

		release_clobj();

		for (i = 0; i < 4; i++)
			HANDLE_CLERROR(clReleaseKernel(pdf_kernel[i]), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		crypt_kernel = NULL;
		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *self)
{
	opencl_prepare_dev(gpu_id);

	/*
	 * For lack of a better scheme.  Once we know what is actually loaded, it's
	 * too late to set the internal mask target.
	 */
	if (options.loader.max_cost[0] <= 6) {
		switch (options.loader.max_cost[0])
		{
		case 6:
			mask_int_cand_target = 0;
			break;
		case 5:
			mask_int_cand_target = opencl_speed_index(gpu_id) / 10000;
			break;
		case 2:
			mask_int_cand_target = opencl_speed_index(gpu_id) / 20000;
			break;
		default: // rev 3 and 4, RC4-40 and -128
			mask_int_cand_target = opencl_speed_index(gpu_id) / 100000;
		}
	} else if (options.loader.min_cost[0] == 6)
		mask_int_cand_target = 0;
	else
		mask_int_cand_target = opencl_speed_index(gpu_id) / 100000;
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
	         "-DPLAINTEXT_LENGTH=%u -DMAX_KEY_SIZE=%u"
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
	         MAX_KEY_SIZE,
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
		opencl_init("$JOHN/opencl/pdf_kernel.cl", gpu_id, build_opts);

	/* create kernels to execute */
	if (!crypt_kernel) {
		for(i = 0; i < 4; i++)
			CLCREATEKERNEL(pdf_kernel[i], kernel_name[i]);
		crypt_kernel = pdf_kernel[0];
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 2, &FORMAT_STRUCT, create_clobj,
	                       release_clobj, PLAINTEXT_LENGTH, gws_limit, db);

	// Auto tune execution from shared/included code.
	autotune_run(&FORMAT_STRUCT, 1, gws_limit, 500);

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
		CLWRITE(cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, NULL);
		CLWRITE(cl_saved_idx, CL_FALSE, idx_offset, 4 * (index + 2) - idx_offset, saved_idx + (idx_offset / 4), NULL);

		if (!mask_gpu_is_static)
			CLWRITE(cl_saved_int_key_loc, CL_FALSE, idx_offset, 4 * (index + 1) - idx_offset, saved_int_key_loc + (idx_offset / 4), NULL);

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
	int krn;

	pdf_salt = salt;

	if (pdf_salt->R == 2)
		krn = 0;
	else if (pdf_salt->R == 3 || pdf_salt->R ==4)
		krn = 1;
	else if (pdf_salt->R == 5)
		krn = 2;
	else //if (pdf_salt->R == 6)
		krn = 3;

	crypt_kernel = pdf_kernel[krn];

	CLWRITE(cl_salt, CL_FALSE, 0, sizeof(pdf_salt_type), pdf_salt, NULL);
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

		/* Safety for when count < GWS */
		for (int i = count; i <= gws; i++)
			saved_idx[i] = key_idx;

		CLWRITE_CRYPT(cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, multi_profilingEvent[0]);
		CLWRITE_CRYPT(cl_saved_idx, CL_FALSE, idx_offset, 4 * (gws + 1) - idx_offset, saved_idx + (idx_offset / 4), multi_profilingEvent[1]);

		if (!mask_gpu_is_static)
			CLWRITE_CRYPT(cl_saved_int_key_loc, CL_FALSE, idx_offset, 4 * gws - idx_offset, saved_int_key_loc + (idx_offset / 4), NULL);

		new_keys = 0;
	}

	WAIT_INIT(gws)
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "Failed running crypt kernel");
	CLFLUSH();
	WAIT_SLEEP
	CLREAD_CRYPT(cl_crack_count_ret, CL_TRUE, 0, sizeof(cl_uint), &crack_count_ret, NULL);
	WAIT_UPDATE
	WAIT_DONE

	if (crack_count_ret) {
		/* This is benign - may happen when gws > count due to GET_NEXT_MULTIPLE() */
		if (crack_count_ret > *pcount)
			crack_count_ret = *pcount;

		CLREAD_CRYPT(cl_result, CL_TRUE, 0, sizeof(cl_uint) * crack_count_ret, result, NULL);

		CLWRITE_CRYPT(cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &zero, NULL);
	}

	return crack_count_ret;
}

static int cmp_all(void *binary, int count)
{
	return count;
}

static int cmp_one(void *binary, int index)
{
	return result[index];
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
		FMT_CASE | FMT_8_BIT | FMT_MASK,
		{
			"revision",
			"key length"
		},
		{ FORMAT_TAG, FORMAT_TAG_OLD },
		pdf_tests
	}, {
		init,
		done,
		reset,
		pdf_prepare,
		pdf_valid,
		fmt_default_split,
		fmt_default_binary,
		pdf_get_salt,
		{
			pdf_revision,
			pdf_keylen
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
