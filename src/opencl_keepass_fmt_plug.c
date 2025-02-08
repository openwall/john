/*
 * KeePass OpenCL cracker for JtR.
 *
 * This software is Copyright (c) 2018-2024 magnum,
 * Copyright (c) 2016 Fist0urs <eddy.maaalou at gmail.com>,
 * Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis),
 * Copyright (c) 2012 Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_KeePass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_KeePass);
#else

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "config.h"
#include "opencl_common.h"
#include "opencl_helper_macros.h"

#define KEEPASS_AES                     1
#define KEEPASS_ARGON2                  0
#define KEEPASS_REAL_COST_TEST_VECTORS  0
#include "keepass_common.h"

#define FORMAT_LABEL            "KeePass-opencl"
#define FORMAT_NAME             ""
#if KEEPASS_ARGON2
#define ALGORITHM_NAME          "AES/Argon2 OpenCL"
#else
#define ALGORITHM_NAME          "AES OpenCL"
#endif

typedef struct {
	uint32_t length;
	uint8_t v[KEEPASS_PLAINTEXT_LENGTH];
} password;

typedef struct {
	uint32_t cracked;
} result;

typedef struct {
#if KEEPASS_AES
	uint32_t iterations;
#endif
	uint8_t hash[32];
} keepass_state;

static int new_keys;
static password *inbuffer;
static result *outbuffer;
static cl_mem mem_in, mem_salt, mem_state, mem_out, mem_autotune;
static struct fmt_main *self;
#define kernel_init crypt_kernel
static cl_kernel kernel_loop_aes, kernel_final;

static size_t insize, outsize;
static size_t saltsize = sizeof(keepass_salt_t) + 32 - 1; // Min. content size is 32

#if KEEPASS_ARGON2
static cl_mem mem_pool;
static cl_kernel kernel_argon2;
static size_t keepass_max_argon2_memory;
#endif

#define STEP			0
#define SEED			256

#define HASH_LOOPS		1000

#define LOOP_COUNT		((keepass_salt->t_cost + HASH_LOOPS - 1) / HASH_LOOPS)

static int split_events[] = { 2, -1, -1 };

static const char *warn[] = {
	"xfer: ",  ", init: ",  ", loop: ",  ", final: ", ", xfer: "
};

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s = autotune_get_task_max_work_group_size(FALSE, 0, kernel_init);

	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, kernel_loop_aes));
#if KEEPASS_ARGON2
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, kernel_argon2));
#endif
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, kernel_final));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	size_t statesize = sizeof(keepass_state) * gws;
	insize = sizeof(password) * gws;
	outsize = sizeof(result) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);

	CLCREATEBUFFER(mem_in, CL_RO, insize);
	CLCREATEBUFFER(mem_salt, CL_RO, saltsize);
	CLCREATEBUFFER(mem_state, CL_RW, statesize);
	CLCREATEBUFFER(mem_out, CL_WO, outsize);
	CLCREATEBUFFER(mem_autotune, CL_RO, sizeof(ocl_autotune_running));

	// Set kernel args
	CLKERNELARG(kernel_init, 0, mem_in);
	CLKERNELARG(kernel_init, 1, mem_salt);
	CLKERNELARG(kernel_init, 2, mem_state);

	CLKERNELARG(kernel_loop_aes, 0, mem_state);
	CLKERNELARG(kernel_loop_aes, 1, mem_salt);

	CLKERNELARG(kernel_final, 0, mem_state);
	CLKERNELARG(kernel_final, 1, mem_salt);
	CLKERNELARG(kernel_final, 2, mem_out);

#if KEEPASS_ARGON2
	size_t poolsize = MAX(keepass_max_argon2_memory * gws, 1);
	CLCREATEBUFFER(mem_pool, CL_RW, poolsize);
	CLKERNELARG(kernel_argon2, 0, mem_state);
	CLKERNELARG(kernel_argon2, 1, mem_salt);
	CLKERNELARG(kernel_argon2, 2, mem_pool);
	CLKERNELARG(kernel_argon2, 3, mem_autotune);
#endif
}

static void release_clobj(void)
{
	if (outbuffer) {
		CLRELEASEBUFFER(mem_in);
		CLRELEASEBUFFER(mem_salt);
		CLRELEASEBUFFER(mem_state);
		CLRELEASEBUFFER(mem_out);
#if KEEPASS_ARGON2
		CLRELEASEBUFFER(mem_pool);
#endif

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
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
		         "-DPLAINTEXT_LENGTH=%d -DHASH_LOOPS=%d -DMAX_CONTENT_SIZE=%d -DKEEPASS_AES%s",
		         KEEPASS_PLAINTEXT_LENGTH, HASH_LOOPS, KEEPASS_MAX_CONTENT_SIZE,
		         KEEPASS_ARGON2 ? " -DKEEPASS_ARGON2" : "");

		opencl_init("$JOHN/opencl/keepass_kernel.cl", gpu_id,  build_opts);

		CLCREATEKERNEL(kernel_init, "keepass_init");
		CLCREATEKERNEL(kernel_loop_aes, "keepass_loop_aes");
#if KEEPASS_ARGON2
		CLCREATEKERNEL(kernel_argon2, "keepass_argon2");
#endif
		CLCREATEKERNEL(kernel_final, "keepass_final");
	}

#if KEEPASS_ARGON2
	/* Argon2 has tough memory requirements for a GPU */
	uint32_t iter, lanes, m_cost;
	if (self_test_running) {
		iter = db->max_cost[0];
		m_cost = db->max_cost[1];
		lanes = db->max_cost[2];
	} else {
		iter = MIN(db->max_cost[0], options.loader.max_cost[0]);
		m_cost = MIN(db->max_cost[1], options.loader.max_cost[1]);
		lanes = MIN(db->max_cost[2], options.loader.max_cost[2]);
	}

	/* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
	keepass_max_argon2_memory = MAX(m_cost, 8 * lanes) * 1024;

	size_t gws_limit = get_max_mem_alloc_size(gpu_id) / MAX(keepass_max_argon2_memory, sizeof(keepass_state));
	uint32_t loops = iter < 100 ? iter : HASH_LOOPS;
	size_t dimensioning_memory_need = MAX(keepass_max_argon2_memory, sizeof(keepass_state));
#else
	size_t gws_limit = get_max_mem_alloc_size(gpu_id) / sizeof(keepass_state);
	uint32_t loops = HASH_LOOPS;
	size_t dimensioning_memory_need = sizeof(keepass_state);
#endif

	opencl_init_auto_setup(SEED, loops, split_events, warn, 2, self,
	                       create_clobj, release_clobj,
	                       dimensioning_memory_need, gws_limit, db);

	/* Auto tune execution from shared/included code, max. 200 ms per kernel invocation */
	autotune_run(self, loops, gws_limit, 200);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(kernel_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(kernel_loop_aes), "Release kernel");
#if KEEPASS_ARGON2
		HANDLE_CLERROR(clReleaseKernel(kernel_argon2), "Release kernel");
#endif
		HANDLE_CLERROR(clReleaseKernel(kernel_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void clear_keys(void)
{
	memset(inbuffer, 0, insize);
}

static void set_key(char *key, int index)
{
	uint32_t length = strlen(key);

	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);

	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[KEEPASS_PLAINTEXT_LENGTH + 1];
	uint32_t length = inbuffer[index].length;

	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static void set_salt(void *salt)
{
	keepass_salt = *((keepass_salt_t**)salt);

	if (sizeof(keepass_salt_t) + keepass_salt->content_size - 1 > saltsize) {
		CLRELEASEBUFFER(mem_salt);
		saltsize = sizeof(keepass_salt_t) + keepass_salt->content_size - 1;
		CLCREATEBUFFER(mem_salt, CL_RO, saltsize);
		CLKERNELARG(kernel_init, 1, mem_salt);
		CLKERNELARG(kernel_loop_aes, 1, mem_salt);
		CLKERNELARG(kernel_final, 1, mem_salt);
#if KEEPASS_ARGON2
		CLKERNELARG(kernel_argon2, 1, mem_salt);
#endif
	}

	CLWRITE(mem_salt, CL_FALSE, 0, saltsize, keepass_salt, NULL);
	CLWRITE(mem_autotune, CL_FALSE, 0, sizeof(ocl_autotune_running),
	        &ocl_autotune_running, NULL);
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		CLWRITE_CRYPT(mem_in, CL_FALSE, 0, insize, inbuffer, multi_profilingEvent[0]);
		new_keys = 0;
	}

	// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		kernel_init, 1, NULL,
		&global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]), "Run kernel");

	WAIT_INIT(global_work_size)
	if (keepass_salt->kdf == 0) {
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
			                                     kernel_loop_aes, 1, NULL,
			                                     &global_work_size, lws, 0, NULL,
			                                     multi_profilingEvent[2]), "Run kernel");
			WAIT_SLEEP
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			WAIT_UPDATE
			opencl_process_event();
		}
	}
#if KEEPASS_ARGON2
	else {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		                                     kernel_argon2, 1, NULL,
		                                     &global_work_size, lws, 0, NULL,
		                                     multi_profilingEvent[2]), "Run kernel");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		WAIT_UPDATE
		opencl_process_event();
	}
#endif
	WAIT_DONE

	WAIT_INIT(global_work_size)
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		kernel_final, 1, NULL,
		&global_work_size, lws, 0, NULL,
		multi_profilingEvent[3]), "Run kernel");

	// Read the result back
	CLREAD_CRYPT(mem_out, CL_FALSE, 0, outsize, outbuffer, multi_profilingEvent[4]);

	BENCH_CLERROR(clFlush(queue[gpu_id]), "Error in clFlush");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error in clFinish");
	WAIT_UPDATE
	WAIT_DONE

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (outbuffer[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return outbuffer[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_KeePass = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		KEEPASS_BENCHMARK_COMMENT,
		KEEPASS_BENCHMARK_LENGTH,
		0,
		KEEPASS_PLAINTEXT_LENGTH,
		KEEPASS_BINARY_SIZE,
		KEEPASS_BINARY_ALIGN,
		KEEPASS_SALT_SIZE,
		KEEPASS_SALT_ALIGN,
		KEEPASS_MIN_KEYS_PER_CRYPT,
		KEEPASS_MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"t (rounds)",
#if KEEPASS_ARGON2
			"m",
			"p",
			"KDF [0=Argon2d 2=Argon2id 3=AES]",
#endif
		},
		{ KEEPASS_FORMAT_TAG },
		keepass_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		keepass_valid,
		fmt_default_split,
		fmt_default_binary,
		keepass_get_salt,
		{
			keepass_cost_t,
#if KEEPASS_ARGON2
			keepass_cost_m,
			keepass_cost_p,
			keepass_kdf,
#endif
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
