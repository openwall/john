/*
 * This software is
 * Copyright (c) 2018 magnum
 * Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_phpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_phpass);
#else

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "options.h"
#include "opencl_common.h"
#include "phpass_common.h"

#define FORMAT_LABEL            "phpass-opencl"
#define FORMAT_NAME             ""

#define ALGORITHM_NAME          "MD5 OpenCL"

#define BENCHMARK_COMMENT       " ($P$9)"

#define ACTUAL_SALT_SIZE        8
#define SALT_SIZE               (ACTUAL_SALT_SIZE + 1) // 1 char for iterations
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

typedef struct {
	uint32_t v[4];		// 128bits for hash
} phpass_hash;

static uint *key_buf, *key_idx, idx;    /** plaintext ciphertexts **/
static phpass_hash *outbuffer;          /** calculated hashes **/

// OpenCL variables:
static cl_int cl_error;
static cl_mem mem_in, mem_idx, mem_out, mem_salt;
static size_t insize, outsize, saltsize;
static struct fmt_main *self;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"key xfer: ",  ", idx xfer: ",  ", crypt: ",  ", res xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	kpc *= ocl_v_width;

	insize = (PLAINTEXT_LENGTH + 3) / 4 * 4 * kpc;
	outsize = sizeof(phpass_hash) * kpc;
	saltsize = sizeof(uint8_t) * ACTUAL_SALT_SIZE + 4;

	key_buf = mem_calloc(1, insize);
	key_idx = mem_calloc(sizeof(int), kpc);
	outbuffer = mem_alloc(outsize);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_idx =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(int) * kpc,
			NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem idx");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_idx),
		&mem_idx), "Error while setting mem_idx kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (outbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_idx), "Release mem idx");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(key_buf);
		MEM_FREE(key_idx);
		MEM_FREE(outbuffer);
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

static void clear_keys(void)
{
	idx = 0;
}

static void set_key(char *key, int index)
{
	const unsigned int *key32 = (unsigned int*)key;
	int len = strlen(key);

	key_idx[index] = (idx << 6) | len;

	while (len > 4) {
		key_buf[idx++] = *key32++;
		len -= 4;
	}
	if (len)
		key_buf[idx++] = *key32 & (0xffffffffU >> (32 - (len << 3)));
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = key_idx[index] & 63;
	char *key = (char*)&key_buf[key_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = key[i];

	out[i] = 0;

	return out;
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);

	opencl_get_vector_width(gpu_id, sizeof(cl_int));
	if (ocl_v_width > 1) {
		static char valgo[sizeof(ALGORITHM_NAME) + 4] = "";

		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DV_WIDTH=%u -DPLAINTEXT_LENGTH=%u",
		         ocl_v_width, PLAINTEXT_LENGTH);
		opencl_init("$JOHN/kernels/phpass_kernel.cl", gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "phpass", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1,
		                       self, create_clobj, release_clobj,
		                       PLAINTEXT_LENGTH * ocl_v_width, 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 2, 0, 200);
	}
}

static void *get_salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];

	memcpy(salt, &ciphertext[FORMAT_TAG_LEN+1], ACTUAL_SALT_SIZE);
	salt[ACTUAL_SALT_SIZE] = ciphertext[FORMAT_TAG_LEN];
	return salt;
}


static void set_salt(void *salt)
{
	static unsigned int setting[ACTUAL_SALT_SIZE / 4 + 1];
	unsigned char *currentsalt = salt;

	// Prepare setting format: salt+count_log2
	memcpy(setting, salt, ACTUAL_SALT_SIZE);
	setting[ACTUAL_SALT_SIZE / 4] = 1 << atoi64[ARCH_INDEX(currentsalt[8])];

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, setting, 0, NULL, NULL),
	    "Copy salt to gpu");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER_VW(count, local_work_size);

	//fprintf(stderr, "%s(%d) gws %zu idx %u\n", __FUNCTION__, count, global_work_size, idx);

	// Copy data to gpu
	if (idx) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			4 * idx, key_buf, 0, NULL, multi_profilingEvent[0]),
			"Copy keys to gpu");
	}
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_idx, CL_FALSE, 0,
		4 * count, key_idx, 0, NULL, multi_profilingEvent[1]),
		"Copy index to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[2]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		16 * count, outbuffer, 0, NULL, multi_profilingEvent[3]),
		"Copy result back");

	return count;
}

static int binary_hash_0(void *binary)
{
	return (((uint32_t*)binary)[0] & PH_MASK_0);
}

static int get_hash_0(int index)
{
	return outbuffer[index].v[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return outbuffer[index].v[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return outbuffer[index].v[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return outbuffer[index].v[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return outbuffer[index].v[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return outbuffer[index].v[0] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return outbuffer[index].v[0] & PH_MASK_6;
}

static int cmp_all(void *binary, int count)
{
	uint32_t b = ((uint32_t *) binary)[0];
	uint32_t i;

	for (i = 0; i < count; i++) {
		if (b == outbuffer[i].v[0]) {
			return 1;
		}
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (t[i] != outbuffer[index].v[i]) {
			return 0;
		}
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_phpass = {
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
		FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		{ FORMAT_TAG, FORMAT_TAG2, FORMAT_TAG3 },
		phpass_common_tests
	}, {
		init,
		done,
		reset,
		phpass_common_prepare,
		phpass_common_valid,
		phpass_common_split,
		phpass_common_binary,
		get_salt,
		{
			phpass_common_iteration_count,
		},
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
		NULL,
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
