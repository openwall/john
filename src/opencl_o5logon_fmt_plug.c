/*
 * Cracker for Oracle's O5LOGON protocol hashes. Hacked together during
 * September of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * O5LOGON is used since version 11g. CVE-2012-3137 applies to Oracle 11.1
 * and 11.2 databases. Oracle has "fixed" the problem in version 11.2.0.3.
 * Oracle 12 support is now added as well.
 *
 * This software is
 * Copyright (c) 2025 magnum
 * Copyright (c) 2014 Harrison Neal
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#ifdef HAVE_OPENCL

#define FORMAT_STRUCT fmt_opencl_o5logon

#if FMT_REGISTERS_H
john_register_one(&FORMAT_STRUCT);
#else
extern struct fmt_main FORMAT_STRUCT;

#include "o5logon_common.h"
#include "opencl_common.h"
#include "mask_ext.h"
#include "opencl_helper_macros.h"

#define FORMAT_LABEL        "o5logon-opencl"
#define ALGORITHM_NAME      "MD5 SHA1 AES OpenCL"
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

// Shared auto-tune stuff
#define STEP                0
#define SEED                1024
#define ROUNDS              1

static const char * warn[] = {
	"pass xfer: ",  ", index xfer: ",  ", crypt: ",  ", res xfer: "
};

static char *key_buf;
static unsigned int *key_idx, key_buf_end;
static unsigned int crack_count_ret, *out_index;
static size_t key_offset, idx_offset;
static cl_mem cl_key_buf, cl_key_idx, cl_salt, cl_crack_count_ret, cl_out_index;
static cl_mem pinned_key_buf, pinned_key_idx, pinned_out_index;
static cl_mem pinned_saved_int_key_loc, cl_buffer_int_keys, cl_saved_int_key_loc;
static cl_uint *saved_int_key_loc;
static int static_gpu_locations[MASK_FMT_INT_PLHDR];
static const cl_uint zero = 0;

static int new_keys;

#include "opencl_autotune.h" // Must come after auto-tune definitions

static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	CLCREATEPINNED(key_buf, CL_RO, PLAINTEXT_LENGTH * gws);
	CLCREATEPINNED(key_idx, CL_RO, sizeof(cl_uint) * (gws + 1));
	CLCREATEPINNED(out_index, CL_RW, sizeof(cl_uint) * gws * mask_int_cand.num_int_cand);
	CLCREATEBUFFER(cl_salt, CL_RO, sizeof(o5logon_salt));
	CLCREATEBUFFER(cl_crack_count_ret, CL_RW, sizeof(cl_uint));

	/* For GPU-side mask */
	CLCREATEPINNED(saved_int_key_loc, CL_RO, sizeof(cl_uint) * gws);
	CLCREATEBUFCOPY(cl_buffer_int_keys, CL_RO, 4 * mask_int_cand.num_int_cand,
	                mask_int_cand.int_cand ? mask_int_cand.int_cand : (void*)&zero);

	crack_count_ret = 0;
	CLWRITE(cl_crack_count_ret, CL_TRUE, 0, sizeof(cl_uint), &crack_count_ret, NULL);

	CLKERNELARG(crypt_kernel, 0, cl_key_buf);
	CLKERNELARG(crypt_kernel, 1, cl_key_idx);
	CLKERNELARG(crypt_kernel, 2, cl_salt);
	CLKERNELARG(crypt_kernel, 3, cl_crack_count_ret);
	CLKERNELARG(crypt_kernel, 4, cl_out_index);
	CLKERNELARG(crypt_kernel, 5, cl_saved_int_key_loc);
	CLKERNELARG(crypt_kernel, 6, cl_buffer_int_keys);
}

static void release_clobj(void)
{
	if (cl_salt) {
		CLRELEASEPINNED(out_index);
		CLRELEASEPINNED(key_buf);
		CLRELEASEPINNED(key_idx);
		CLRELEASEPINNED(saved_int_key_loc);
		CLRELEASEBUFFER(cl_crack_count_ret);
		CLRELEASEBUFFER(cl_salt);
		CLRELEASEBUFFER(cl_buffer_int_keys);
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

static void init(struct fmt_main *self)
{
	opencl_prepare_dev(gpu_id);

	// Tuned on 2080ti
	mask_int_cand_target = opencl_speed_index(gpu_id) / 2048;
}

static void reset(struct db_main *db)
{
	char build_opts[256];
	size_t gws_limit = UINT_MAX / PLAINTEXT_LENGTH;
	int i;

	if (crypt_kernel)
		done();

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

	snprintf(build_opts, sizeof(build_opts),
	         "-DPLAINTEXT_LENGTH=%u -DCIPHERTEXT_LENGTH=%u -DSALT_LENGTH=%u"
	         " -DLOC_0=%d"
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
	         CIPHERTEXT_LENGTH,
	         SALT_LENGTH,
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
		opencl_init("$JOHN/opencl/o5logon_kernel.cl", gpu_id, build_opts);

	/* create kernels to execute */
	if (!crypt_kernel)
		CLCREATEKERNEL(crypt_kernel, "o5logon_kernel");

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 2, &FORMAT_STRUCT, create_clobj,
	                       release_clobj, PLAINTEXT_LENGTH, gws_limit, db);

	// Auto tune execution from shared/included code.
	autotune_run(&FORMAT_STRUCT, 1, gws_limit, 200);
}

static void clear_keys(void)
{
	key_buf_end = 0;
	key_idx[0] = 0;
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

	//printf("\n%s(%d) '%s'\n", __FUNCTION__, index, key);

	while (*key)
		key_buf[key_buf_end++] = *key++;

	key_idx[index + 1] = key_buf_end;
	new_keys = 1;

	/* Early partial transfer to GPU */
	if (index && !(index & (256 * 1024 - 1))) {
		CLWRITE(cl_key_buf, CL_FALSE, key_offset, key_buf_end - key_offset, key_buf + key_offset, NULL);
		CLWRITE(cl_key_idx, CL_FALSE, idx_offset, 4 * (index + 2) - idx_offset, key_idx + (idx_offset / 4), NULL);

		if (!mask_gpu_is_static)
			CLWRITE(cl_saved_int_key_loc, CL_FALSE, idx_offset, 4 * (index + 1) - idx_offset, saved_int_key_loc + (idx_offset / 4), NULL);

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");

		key_offset = key_buf_end;
		idx_offset = 4 * (index + 1);
		new_keys = 0;
	}
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	char *key;
	int i, len;
	int int_index = 0;

	if (crack_count_ret)
		index = out_index[index];
	if (mask_int_cand.num_int_cand) {
		int_index = index % mask_int_cand.num_int_cand;
		index /= mask_int_cand.num_int_cand;
	}

	key = &key_buf[key_idx[index]];
	len = key_idx[index + 1] - key_idx[index];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	/* Re-apply GPU-side mask */
	if (len && mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			if (mask_gpu_is_static)
				out[static_gpu_locations[i]] =
					mask_int_cand.int_cand[int_index].x[i];
			else
				out[(saved_int_key_loc[index] & (0xff << (i * 8))) >> (i * 8)] =
					mask_int_cand.int_cand[int_index].x[i];
	}

	return out;
}

static void set_salt(void *salt)
{
	CLWRITE(cl_salt, CL_FALSE, 0, sizeof(o5logon_salt), salt, NULL);
	CLFLUSH();
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	*pcount *= mask_int_cand.num_int_cand;

	//printf("\n%s(%d) %zu/%zu\n", __FUNCTION__, count, gws, local_work_size);
	if (new_keys) {
		/* Self-test kludge */
		if (idx_offset > 4 * (count + 1))
			idx_offset = 0;

		/* Safety for when count < GWS */
		for (int i = count; i <= gws; i++)
			key_idx[i] = key_buf_end;

		CLWRITE_CRYPT(cl_key_buf, CL_FALSE, key_offset, key_buf_end - key_offset, key_buf + key_offset, multi_profilingEvent[0]);
		CLWRITE_CRYPT(cl_key_idx, CL_FALSE, idx_offset, 4 * (gws + 1) - idx_offset, key_idx + (idx_offset / 4), multi_profilingEvent[1]);

		if (!mask_gpu_is_static)
			CLWRITE_CRYPT(cl_saved_int_key_loc, CL_FALSE, idx_offset, 4 * gws - idx_offset, saved_int_key_loc + (idx_offset / 4), NULL);

		new_keys = 0;
	}

	WAIT_INIT(gws)
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "Failed running crypt kernel");
	CLFLUSH();
	WAIT_SLEEP
	WAIT_UPDATE
	CLREAD_CRYPT(cl_crack_count_ret, CL_TRUE, 0, sizeof(cl_uint), &crack_count_ret, multi_profilingEvent[3]);
	WAIT_DONE

	if (crack_count_ret) {
		/*
		 * This is benign - may happen when gws > count due to
		 * GET_NEXT_MULTIPLE(), particularly during self-test.
		 */
		if (crack_count_ret > *pcount)
			crack_count_ret = *pcount;

		CLREAD_CRYPT(cl_out_index, CL_TRUE, 0, sizeof(cl_uint) * crack_count_ret, out_index, NULL);

		CLWRITE_CRYPT(cl_crack_count_ret, CL_FALSE, 0, sizeof(cl_uint), &zero, NULL);
	}

	return crack_count_ret;
}

static int cmp_all(void *binary, int count)
{
	return count;
}

/*
 * This confuses me at times, so documenting for myself:
 * If we got here, it's *always* a crack - but the 'index' is a mapped one.
 * So how does core know /what/ hash is cracked? Simple - this is a salt-only
 * format with no binary so there can only be one!
 * The subsequent call to get_key() will map the out-index back to original
 * and re-apply the GPU-side mask so we know what candidate cracked it.
 * -- magnum
 */
static int cmp_one(void *binary, int index)
{
	return crack_count_ret;
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
		{ NULL },
		{ FORMAT_TAG },
		o5logon_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		o5logon_valid,
		fmt_default_split,
		fmt_default_binary,
		o5logon_get_salt,
		{ NULL },
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
