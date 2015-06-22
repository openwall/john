/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>
 * and Copyright (c) 2012-2014 magnum, and it is hereby released to the general
 * public under the following terms: Redistribution and use in source and
 * binary forms, with or without modification, are permitted.
 *
 * Code was at some point based on Aircrack-ng source
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_wpapsk;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_wpapsk);
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
static cl_kernel wpapsk_init, wpapsk_loop, wpapsk_pass2, wpapsk_final_md5, wpapsk_final_sha1;
static unsigned int v_width = 1;	/* Vector width of kernel */
static size_t key_buf_size;
static unsigned int *inbuffer;
static struct fmt_main *self;

#define JOHN_OCL_WPAPSK
#include "wpapsk.h"

#define FORMAT_LABEL		"wpapsk-opencl"
#define FORMAT_NAME		"WPA/WPA2 PSK"
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL"

#define BENCHMARK_LENGTH	-1

#define ITERATIONS		4095
#define HASH_LOOPS		105 // factors 3, 3, 5, 7, 13
#define SEED			256

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define OCL_CONFIG		"wpapsk"

/* This handles all sizes */
#define GETPOS(i, index)	(((index) % v_width) * 4 + ((i) & ~3U) * v_width + (((i) & 3) ^ 3) + ((index) / v_width) * 64 * v_width)
/* This is faster but can't handle size 3 */
//#define GETPOS(i, index)	(((index) & (v_width - 1)) * 4 + ((i) & ~3U) * v_width + (((i) & 3) ^ 3) + ((index) / v_width) * 64 * v_width)

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
	"xfer: ", ", init: ", ", loop: ", ", pass2: ", ", final: ", ", xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_pass2));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_md5));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_sha1));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
#if 1
	return get_task_max_work_group_size(); // GTX980: 195629 c/s
#elif 1
	return 0; // 190650 c/s
#else
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64; // 181414 c/s
#endif
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= v_width;

	key_buf_size = 64 * gws;

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

	HANDLE_CLERROR(clSetKernelArg(wpapsk_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_pass2, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_pass2, 1, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
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
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(wpapsk_init), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_loop), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_pass2), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_final_md5), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_final_sha1), "Release Kernel");

	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

static void clear_keys(void) {
	memset(inbuffer, 0, key_buf_size);
	new_keys = 1;
}

static void set_key(char *key, int index)
{
	int i;
	int length = strlen(key);

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];
	new_keys = 1;
}

static char* get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i = 0;

	while ((ret[i] = ((char*)inbuffer)[GETPOS(i, index)]))
		i++;

	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *salt);

static void init(struct fmt_main *_self)
{
	char *custom_opts;
	char build_opts[256];
	static char valgo[32] = "";

	self = _self;

	opencl_preinit();
	/* VLIW5 does better with just 2x vectors due to GPR pressure */
	if (!options.v_width && amd_vliw5(device_info[gpu_id]))
		v_width = 2;
	else
		v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	if (v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", v_width);
		self->params.algorithm_name = valgo;
	}

	if (!(custom_opts = getenv(OCL_CONFIG "_BuildOpts")))
		custom_opts = cfg_get_param(SECTION_OPTIONS,
		                            SUBSECTION_OPENCL,
		                            OCL_CONFIG "_BuildOpts");

	snprintf(build_opts, sizeof(build_opts),
	         "%s%s-DHASH_LOOPS=%u -DITERATIONS=%u "
	         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
	         custom_opts ? custom_opts : "",
	         custom_opts ? " " : "",
	         HASH_LOOPS, ITERATIONS,
	         PLAINTEXT_LENGTH, v_width);
	opencl_init("$JOHN/kernels/wpapsk_kernel.cl", gpu_id, build_opts);

	// create kernels to execute
	crypt_kernel = wpapsk_init = clCreateKernel(program[gpu_id], "wpapsk_init", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_loop = clCreateKernel(program[gpu_id], "wpapsk_loop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_pass2 = clCreateKernel(program[gpu_id], "wpapsk_pass2", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_final_md5 = clCreateKernel(program[gpu_id], "wpapsk_final_md5", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_final_sha1 = clCreateKernel(program[gpu_id], "wpapsk_final_sha1", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
}

static void reset(struct db_main *db)
{
	if (!db) {
		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 2 * HASH_LOOPS, split_events,
		                       warn, 2, self,
		                       create_clobj, release_clobj,
		                       2 * v_width * sizeof(wpapsk_state), 0);

		// Auto tune execution from shared/included code.
		self->methods.crypt_all = crypt_all_benchmark;
		autotune_run(self, 2 * ITERATIONS * 2 + 2, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
		self->methods.crypt_all = crypt_all;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	size_t scalar_gws;

	global_work_size = ((count + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size;
	scalar_gws = global_work_size * v_width;

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, scalar_gws * 64, inbuffer, 0, NULL, NULL), "Copy data to gpu");

	/// Run kernel
	if (new_keys || strcmp(last_ssid, hccap.essid)) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_init, 1, NULL, &global_work_size, &local_work_size, 0, NULL, firstEvent), "Run initial kernel");

		for (i = 0; i < ITERATIONS / HASH_LOOPS; i++) {
			HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel");
			HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_pass2, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run intermediate kernel");

		for (i = 0; i < ITERATIONS / HASH_LOOPS; i++) {
			HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel (2nd pass)");
			HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		new_keys = 0;
		strcpy(last_ssid, hccap.essid);
	}

	if (hccap.keyver == 1)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_md5, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "Run final kernel (MD5)");
	else
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_sha1, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "Run final kernel (SHA1)");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Failed running final kernel");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(mic_t) * scalar_gws, mic, 0, NULL, NULL), "Copy result back");

	return count;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = local_work_size ? ((count + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size : count / v_width;

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");

	/// Run kernels, no iterations for fast enumeration
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running kernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_loop, 1, NULL, &global_work_size, lws, 0, NULL, NULL), "Run loop kernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_pass2, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_loop, 1, NULL, &global_work_size, lws, 0, NULL, NULL), "Run loop kernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_final_sha1, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[4]), "Run final kernel (SHA1)");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(mic_t) * count, mic, 0, NULL, multi_profilingEvent[5]), "Copy result back");

	return count;
}

struct fmt_main fmt_opencl_wpapsk = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		8,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			binary_hash_0,
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
		clear_keys,
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
