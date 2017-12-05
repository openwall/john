/*
 * This software is Copyright (c) 2017 magnum,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_wpapsk_pmk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_wpapsk_pmk);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "config.h"
#include "options.h"
#include "common-opencl.h"

static cl_mem mem_in, mem_out, mem_salt, mem_state, pinned_in, pinned_out;
static cl_kernel wpapmk_init, wpapsk_final_md5, wpapsk_final_sha1, wpapsk_final_sha256;
static size_t key_buf_size;
static unsigned int *inbuffer;
static struct fmt_main *self;
static int new_keys;

#define JOHN_OCL_WPAPMK
#include "wpapmk.h"

#define FORMAT_LABEL        "wpapsk-pmk-opencl"
#define FORMAT_NAME         "WPA/WPA2/PMF master key"
#define ALGORITHM_NAME      "MD5/SHA-1/SHA-2 OpenCL"

#define SEED                256

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#define OCL_CONFIG          "wpapsk_pmk"

/* This handles all sizes */
//#define GETPOS(i, index)	(((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 32 * ocl_v_width)
/* This is faster but can't handle size 3 */
#define GETPOS(i, index)	(((index) & (ocl_v_width - 1)) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 32 * ocl_v_width)

extern wpapsk_salt currentsalt;
extern mic_t *mic;
extern hccap_t hccap;

typedef struct {
	cl_uint W[5];
	cl_uint ipad[5];
	cl_uint opad[5];
	cl_uint out[5];
	cl_uint partial[5];
} wpapsk_state;

static const char * warn[] = {
	"xfer: ", ", init: ", ", final: ", ", xfer: "
};

static int split_events[] = { -1, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, wpapmk_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_md5));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_sha1));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_sha256));
	return s;
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= ocl_v_width;

	key_buf_size = 32 * gws;

	/// Allocate memory
	pinned_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned in");
	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	inbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, key_buf_size, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(wpapsk_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(wpapsk_salt), &currentsalt, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");

	pinned_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(mic_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned out");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(mic_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");
	mic = clEnqueueMapBuffer(queue[gpu_id], pinned_out, CL_TRUE, CL_MAP_READ, 0, sizeof(mic_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	HANDLE_CLERROR(clSetKernelArg(wpapmk_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapmk_init, 1, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha256, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha256, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha256, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (mem_state) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_in, inbuffer, 0, NULL, NULL), "Error Unmapping mem in");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_out, mic, 0, NULL, NULL), "Error Unmapping mem in");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_in), "Release pinned_in");
		HANDLE_CLERROR(clReleaseMemObject(pinned_out), "Release pinned_out");
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release pinned_in");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		mem_state = NULL;
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(wpapmk_init), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_final_md5), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_final_sha1), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_final_sha256), "Release Kernel");

		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void set_key(char *key, int index)
{
	int i;

	for (i = 0; i < 32; i++)
		((unsigned char*)inbuffer)[GETPOS(i, index)] =
			(atoi16[ARCH_INDEX(key[i << 1])] << 4) |
			atoi16[ARCH_INDEX(key[(i << 1) + 1])];
	new_keys = 1;
}

static char* get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i;

	for (i = 0; i < 32; i++) {
		ret[i << 1] =
			itoa16[ARCH_INDEX(((unsigned char*)inbuffer)[GETPOS(i, index)] >> 4)];
		ret[(i << 1) + 1] =
			itoa16[ARCH_INDEX(((unsigned char*)inbuffer)[GETPOS(i, index)] & 0x0f)];
	}
	return ret;
}

static void init(struct fmt_main *_self)
{
	static char valgo[32] = "";

	self = _self;

	opencl_prepare_dev(gpu_id);
	/* VLIW5 does better with just 2x vectors due to GPR pressure */
	if (!options.v_width && amd_vliw5(device_info[gpu_id]))
		ocl_v_width = 2;
	else
		ocl_v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	/* Vectorizing disabled until fixed for keyver 3 */
	ocl_v_width = 1;

	if (ocl_v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char *custom_opts;
		char build_opts[256];

		if (!(custom_opts = getenv(OCL_CONFIG "_BuildOpts")))
			custom_opts = cfg_get_param(SECTION_OPTIONS,
			                            SUBSECTION_OPENCL,
			                            OCL_CONFIG "_BuildOpts");

		snprintf(build_opts, sizeof(build_opts),
		         "%s%s-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u -DWPAPMK",
		         custom_opts ? custom_opts : "",
		         custom_opts ? " " : "",
		         PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/kernels/wpapsk_kernel.cl", gpu_id, build_opts);

		// create kernels to execute
		crypt_kernel = wpapmk_init = clCreateKernel(program[gpu_id], "wpapmk_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		wpapsk_final_md5 = clCreateKernel(program[gpu_id], "wpapsk_final_md5", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		wpapsk_final_sha1 = clCreateKernel(program[gpu_id], "wpapsk_final_sha1", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		wpapsk_final_sha256 = clCreateKernel(program[gpu_id], "wpapsk_final_sha256", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 1, split_events,
		                       warn, 2, self,
		                       create_clobj, release_clobj,
		                       2 * ocl_v_width * sizeof(wpapsk_state), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	extern volatile int bench_running;

	global_work_size = GET_MULTIPLE_OR_BIGGER_VW(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	/// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, scalar_gws * 32, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");

		/// Call init kernel
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapmk_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run final kernel (MD5)");

		new_keys = 0;
	}

	if (hccap.keyver == 1)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_md5, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run final kernel (MD5)");
	else if (hccap.keyver == 2)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_sha1, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run final kernel (SHA1)");
	else
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_sha256, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run final kernel (SHA256)");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Failed running final kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(mic_t) * scalar_gws, mic, 0, NULL, multi_profilingEvent[3]), "Copy result back");

	return count;
}

struct fmt_main fmt_opencl_wpapsk_pmk = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_MIN_LEN,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		0,
		{
			"key version [1:WPA 2:WPA2 3:802.11w]"
		},
		{ FORMAT_TAG},
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			get_keyver,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		salt_compare,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
