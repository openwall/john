/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>
 * and Copyright (c) 2012-2019 magnum, and it is hereby released to the general
 * public under the following terms: Redistribution and use in source and
 * binary forms, with or without modification, are permitted.
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
#include "unicode.h"
#include "opencl_common.h"

static cl_mem mem_in, mem_salt, mem_state, mem_out, mem_data;
static cl_mem pinned_in, pinned_out;
static cl_kernel wpapsk_init, wpapsk_loop, wpapsk_pass2, wpapsk_final_md5, wpapsk_final_sha1, wpapsk_final_sha256, wpapsk_final_pmkid;
static size_t key_buf_size;
static unsigned int *inbuffer;
static struct fmt_main *self;
static int new_keys;

#define JOHN_OCL_WPAPSK
#include "wpapsk.h"

#define FORMAT_LABEL		"wpapsk-opencl"
#define FORMAT_NAME		"WPA/WPA2/PMF/PMKID PSK"
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL"

#define ITERATIONS		4095
#define HASH_LOOPS		105 // factors 3, 3, 5, 7, 13
#define SEED			256

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define OCL_CONFIG		"wpapsk"

/* This handles all sizes */
#define GETPOS(i, index)	(((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)
/* This is faster but can't handle size 3 */
//#define GETPOS(i, index)	(((index) & (ocl_v_width - 1)) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

typedef struct {
	cl_uint W[5];
	cl_uint ipad[5];
	cl_uint opad[5];
	cl_uint out[5];
	cl_uint partial[5];
} wpapsk_state;

extern mic_t *mic;
extern hccap_t hccap;

static const char * warn[] = {
	"xfer: ", ", init: ", ", loop: ", ", pass2: ",
	", blob_xfer: ", ", final: ", ", xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_pass2));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_md5));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_sha1));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_sha256));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, wpapsk_final_pmkid));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	gws *= ocl_v_width;

	key_buf_size = 64 * gws;

	// Allocate memory
	pinned_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned in");
	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	inbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, key_buf_size, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(wpapsk_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(wpapsk_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem salt");

	mem_data = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(wpapsk_data), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem data");

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
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 1, sizeof(mem_data), &mem_data), "Error while setting mem_data kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 1, sizeof(mem_data), &mem_data), "Error while setting mem_data kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha256, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha256, 1, sizeof(mem_data), &mem_data), "Error while setting mem_data kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha256, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_pmkid, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_pmkid, 1, sizeof(mem_data), &mem_data), "Error while setting mem_data kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_pmkid, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
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
		HANDLE_CLERROR(clReleaseMemObject(mem_data), "Release mem_data");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		mem_state = NULL;
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(wpapsk_init), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_loop), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_pass2), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_final_md5), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_final_sha1), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_final_sha256), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(wpapsk_final_pmkid), "Release Kernel");

		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void clear_keys(void) {
	memset(inbuffer, 0, key_buf_size);
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

static void init(struct fmt_main *_self)
{
	static char valgo[32] = "";

	self = _self;

	/*
	 * Implementations seen IRL that have 8 *bytes* (of eg. UTF-8) passwords
	 * as opposed to 8 *characters*. This hack is not ideal.
	 */
	if (options.target_enc == UTF_8 && options.internal_cp != UTF_8)
		self->params.plaintext_min_length = 2;

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
	if (!program[gpu_id]) {
		const char *custom_opts;
		char build_opts[256];

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
		         PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/opencl/wpapsk_kernel.cl", gpu_id, build_opts);

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
		wpapsk_final_sha256 = clCreateKernel(program[gpu_id], "wpapsk_final_sha256", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		wpapsk_final_pmkid = clCreateKernel(program[gpu_id], "wpapsk_final_pmkid", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 2 * HASH_LOOPS, split_events,
	                       warn, 2, self,
	                       create_clobj, release_clobj,
	                       2 * ocl_v_width * sizeof(wpapsk_state), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 2 * ITERATIONS * 2 + 2, 0, 200);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_KPC_MULTIPLE(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	// Copy data to gpu
	if (new_keys) {
		WAIT_INIT(global_work_size)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, scalar_gws * 64, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error transferring keys");
		WAIT_UPDATE
		WAIT_DONE
		new_keys = 0;
	}

	// Run kernel
	WAIT_INIT(global_work_size)
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error transferring keys");
	WAIT_UPDATE
	WAIT_DONE

	WAIT_INIT(global_work_size)
	for (i = 0; i < (ocl_autotune_running ? 1 : ITERATIONS / HASH_LOOPS); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		WAIT_UPDATE
		opencl_process_event();
	}
	WAIT_DONE

	WAIT_INIT(global_work_size)
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_pass2, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error transferring keys");
	WAIT_UPDATE
	WAIT_DONE

	WAIT_INIT(global_work_size)
	for (i = 0; i < (ocl_autotune_running ? 1 : ITERATIONS / HASH_LOOPS); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], wpapsk_loop, 1, NULL, &global_work_size, lws, 0, NULL, NULL), "Run loop kernel (2nd pass)");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		WAIT_UPDATE
		opencl_process_event();
	}
	WAIT_DONE

	return count;
}

struct fmt_main fmt_opencl_wpapsk = {
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
		FMT_8_BIT | FMT_CASE | FMT_BLOB,
		{
			NULL // "key version [0:PMKID 1:WPA 2:WPA2 3:802.11w]"
		},
		{
			FORMAT_TAG, ""
		},
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
			NULL //get_keyver,
		},
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		salt_compare,
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
