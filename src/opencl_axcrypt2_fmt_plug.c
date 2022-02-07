/*
 * This software is Copyright (c) 2018, Dhiru Kholia <kholia at kth dot se>,
 * Copyright (c) 2012-2013 Lukas Odzioba, Copyright (c) 2014 JimF, Copyright
 * (c) 2014 magnum, and it is hereby released to the general public under the
 * following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on opencl_pbkdf2_hmac_sha512_fmt_plug.c file.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_axcrypt2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_axcrypt2);
#else

#include <stdint.h>
#include <string.h>

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "opencl_common.h"
#include "axcrypt_common.h"
#define VERSION_2_SUPPORT 1
#include "axcrypt_variable_code.h"
#include "pbkdf2_hmac_common.h"

#define FORMAT_NAME             "AxCrypt 2.x"
#define FORMAT_LABEL            "axcrypt2-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA512 AES OpenCL"
#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               sizeof(struct custom_salt *)
#define SALT_ALIGN              sizeof(struct custom_salt *)
#define PLAINTEXT_LENGTH        110
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define KERNEL_NAME             "pbkdf2_sha512_kernel"
#define SPLIT_KERNEL_NAME       "pbkdf2_sha512_loop"
#define FINAL_KERNEL_NAME       "axcrypt2_final"

#define HASH_LOOPS              250
#define ITERATIONS              25000

typedef struct {
	// for plaintext, we must make sure it is a full uint64_t width.
	uint64_t v[(PLAINTEXT_LENGTH + 7) / 8]; // v must be kept aligned(8)
	uint64_t length; // keep 64 bit aligned, length is overkill, but easiest way to stay aligned.
} pass_t;

typedef struct {
	uint64_t hash[8];
} crack_t;

typedef struct {
	// for salt, we append \x00\x00\x00\x01\x80 and must make sure it is a full uint64 width
	uint64_t salt[(PBKDF2_64_MAX_SALT_SIZE + 1 + 4 + 7) / 8]; // salt must be kept aligned(8)
	uint32_t length;
	uint32_t rounds;
} salt_t;

typedef struct {
	uint64_t ipad[8];
	uint64_t opad[8];
	uint64_t hash[8];
	uint64_t W[8];
	cl_uint rounds;
} state_t;

typedef struct {
	salt_t pbkdf2;
	uint32_t key_wrapping_rounds;
	unsigned char salt[64];
	unsigned int wrappedkey[144/4];
} axcrypt2_salt_t;

typedef struct {
	uint32_t cracked;
} out_t;

static struct custom_salt *cur_salt;
static int new_keys;

static pass_t *host_pass;
static axcrypt2_salt_t *host_salt;
static out_t *host_crack;
static cl_mem mem_in, mem_salt, mem_state, mem_dk, mem_out;
static cl_kernel split_kernel, final_kernel;
static cl_int cl_error;
static struct fmt_main *self;

#define STEP                    0
#define SEED                    256

static const char *warn[] = {
	"xfer: ",  ", init: " , ", crypt: ", ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, split_kernel));
	return MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
}

static void release_clobj(void);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	release_clobj();

	host_pass = mem_calloc(kpc, sizeof(pass_t));
	host_crack = mem_calloc(kpc, sizeof(out_t));
	host_salt = mem_calloc(1, sizeof(axcrypt2_salt_t));

#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)  \
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);  \
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)  \
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	mem_salt = CLCREATEBUFFER(CL_RO, sizeof(axcrypt2_salt_t),
			"Cannot allocate mem salt");
	mem_in = CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
			"Cannot allocate mem in");
	mem_state = CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
			"Cannot allocate mem state");
	mem_dk = CLCREATEBUFFER(CL_RW, kpc * sizeof(crack_t),
			"Cannot allocate mem dk");
	mem_out = CLCREATEBUFFER(CL_WO, kpc * sizeof(out_t),
			"Cannot allocate mem out");

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
	CLKERNELARG(split_kernel, 1, mem_dk, "Error while setting mem_dk");

	CLKERNELARG(final_kernel, 0, mem_dk, "Error while setting mem_dk");
	CLKERNELARG(final_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(final_kernel, 2, mem_out, "Error while setting mem_out");
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
				"-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%d -DPBKDF2_64_MAX_SALT_SIZE=%d",
				HASH_LOOPS, PLAINTEXT_LENGTH, PBKDF2_64_MAX_SALT_SIZE);

		opencl_init("$JOHN/opencl/axcrypt2_kernel.cl", gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		final_kernel =
			clCreateKernel(program[gpu_id], FINAL_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating final kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn, 2,
	                       self, create_clobj, release_clobj,
	                       sizeof(state_t), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ITERATIONS, 0, 200);
}

static void release_clobj(void)
{
	if (host_pass) {
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_dk), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(host_crack);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static int axcrypt2_valid(char *ciphertext, struct fmt_main *self)
{
	return axcrypt_common_valid(ciphertext, self, 2);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	static void *ptr;
	int saltlen = 0;
	int wrappedkeylen;

	memset(&cs, 0, sizeof(cs));
	cs.keyfile = NULL;
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);

	saltlen = 64;  // WrapSalt
	wrappedkeylen = 144;

	p = strtokm(NULL, "*");
	cs.key_wrapping_rounds = (uint32_t) atoi(p);

	p = strtokm(NULL, "*");
	for (i = 0; i < saltlen; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "*");
	for (i = 0; i < wrappedkeylen; i++)
		cs.wrappedkey[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	if (cs.version == 2) {
		p = strtokm(NULL, "*");
		cs.deriv_iterations = atoi(p);
		p = strtokm(NULL, "*");

		for (i = 0; i < 32; i++)
			cs.deriv_salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	// we append the count and EOM here, one time.
	memcpy(cs.deriv_salt + 32, "\x0\x0\x0\x1\x80", 5);
	cs.deriv_salt_length = 32 + 5; // we include the x80 byte in our saltlen, but the .cl kernel knows to reduce saltlen by 1 */

	MEM_FREE(keeptr);

	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt, salt);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt, salt, wrappedkey, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memcpy(ptr, &cs, sizeof(struct custom_salt));

	return (void *)&ptr;
}

static void set_salt(void *salt)
{
	cur_salt = *(struct custom_salt **) salt;

	memcpy(host_salt->pbkdf2.salt, cur_salt->deriv_salt, cur_salt->deriv_salt_length);
	host_salt->pbkdf2.length = cur_salt->deriv_salt_length;
	host_salt->pbkdf2.rounds = cur_salt->deriv_iterations;

	memcpy(host_salt->salt, cur_salt->salt, 64);
	memcpy(host_salt->wrappedkey, cur_salt->wrappedkey, 144);

	host_salt->key_wrapping_rounds = cur_salt->key_wrapping_rounds;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
			CL_FALSE, 0, sizeof(axcrypt2_salt_t), host_salt, 0, NULL, NULL),
			"Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, loops = (host_salt->pbkdf2.rounds + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			gws * sizeof(pass_t), host_pass,
			0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	// Run standard PBKDF2 kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
				NULL, &gws, lws, 0, NULL,
				multi_profilingEvent[1]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					split_kernel, 1, NULL,
					&gws, lws, 0, NULL,
					multi_profilingEvent[2]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}

	// Run GELI post-processing kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1,
				NULL, &gws, lws, 0, NULL,
				multi_profilingEvent[3]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
				gws * sizeof(out_t), host_crack,
				0, NULL, multi_profilingEvent[4]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (host_crack[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return host_crack[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	int saved_len = MIN(strlen(key), PLAINTEXT_LENGTH);

	// make sure LAST uint64 that has any key in it gets null, since we simply
	// ^= the whole uint64 with the ipad/opad mask
	strncpy((char*)host_pass[index].v, key, PLAINTEXT_LENGTH);
	host_pass[index].length = saved_len;

	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];

	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[host_pass[index].length] = 0;

	return ret;
}

struct fmt_main fmt_opencl_axcrypt2 = {
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
		FMT_CASE | FMT_8_BIT | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		axcrypt_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		axcrypt2_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			axcrypt_iteration_count,
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
		fmt_default_clear_keys,
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
