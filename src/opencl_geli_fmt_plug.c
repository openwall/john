/*
 * This software is Copyright (c) 2017 Dhiru Kholia, Copyright (c) 2012-2013
 * Lukas Odzioba, Copyright (c) 2014 JimF, Copyright (c) 2014 magnum, and it is
 * hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on opencl_pbkdf2_hmac_sha512_fmt_plug.c file.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_geli;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_geli);
#else

#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "common-opencl.h"
#include "sha2.h"
#include "geli_common.h"
#include "johnswap.h"
#include "hmac_sha.h"
#undef FORMAT_NAME
#include "pbkdf2_hmac_common.h"

#undef FORMAT_NAME
#define FORMAT_NAME             "FreeBSD GELI"
#define FORMAT_LABEL            "geli-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA512 OpenCL AES"
#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               sizeof(custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        110
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define KERNEL_NAME             "pbkdf2_sha512_kernel"
#define SPLIT_KERNEL_NAME       "pbkdf2_sha512_loop"
#define CONFIG_NAME             "pbkdf2_sha512"

#define HASH_LOOPS              250
#define ITERATIONS              10000

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

static unsigned int *cracked;
static custom_salt *cur_salt;

static pass_t *host_pass;
static salt_t *host_salt;
static crack_t *host_crack;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel split_kernel;
static cl_int cl_error;
static struct fmt_main *self;

#define STEP			0
#define SEED			256

static const char *warn[] = {
        "xfer: ",  ", init: " , ", crypt: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t min_lws =
		autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	return MIN(min_lws, autotune_get_task_max_work_group_size(FALSE, 0,
				split_kernel));
}

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	host_pass = mem_calloc(kpc, sizeof(pass_t));
	host_crack = mem_calloc(kpc, sizeof(crack_t));
	host_salt = mem_calloc(1, sizeof(salt_t));
	cracked = mem_calloc(kpc, sizeof(*cracked));
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)	  \
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error); \
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)	  \
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	mem_in = CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
			"Cannot allocate mem in");
	mem_salt = CLCREATEBUFFER(CL_RO, sizeof(salt_t),
			"Cannot allocate mem salt");
	mem_out = CLCREATEBUFFER(CL_WO, kpc * sizeof(crack_t),
			"Cannot allocate mem out");
	mem_state = CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
			"Cannot allocate mem state");

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
	CLKERNELARG(split_kernel, 1, mem_out, "Error while setting mem_out");
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
				"-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%d -DPBKDF2_64_MAX_SALT_SIZE=%d",
				HASH_LOOPS, PLAINTEXT_LENGTH, PBKDF2_64_MAX_SALT_SIZE);

		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha512_kernel.cl",
				gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn, 2,
				self, create_clobj, release_clobj,
				sizeof(state_t), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, ITERATIONS, 0,
				(cpu(device_info[gpu_id]) ?  1000000000 : 10000000000ULL)); }
}

static void release_clobj(void)
{
	if (host_pass) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");

		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(host_crack);
		MEM_FREE(cracked);
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

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static custom_salt *cur_salt;

	cur_salt = mem_calloc_tiny(sizeof(custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cur_salt->md_ealgo = atoi(p);
	p = strtokm(NULL, "$");
	cur_salt->md_keylen = atoi(p);
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cur_salt->md_keys = atoi(p);
	p = strtokm(NULL, "$");
	cur_salt->md_iterations = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < G_ELI_SALTLEN; i++)
		cur_salt->md_salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	for (i = 0; i < (G_ELI_MAXMKEYS * G_ELI_MKEYLEN); i++)
		cur_salt->md_mkeys[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	// we append the count and EOM here, one time.
	memcpy(&cur_salt->md_salt[G_ELI_SALTLEN], "\x0\x0\x0\x1\x80", 5);
	cur_salt->saltlen = G_ELI_SALTLEN + 5; // we include the x80 byte in our saltlen, but the .cl kernel knows to reduce saltlen by 1

	MEM_FREE(keeptr);

	return (void *)cur_salt;
}

static void set_salt(void *salt)
{
	cur_salt = (custom_salt*)salt;

	memcpy(host_salt->salt, cur_salt->md_salt, cur_salt->saltlen);
	host_salt->length = cur_salt->saltlen;
	host_salt->rounds = cur_salt->md_iterations;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE,
				0, sizeof(salt_t), host_salt, 0, NULL, NULL),
				"Copy salt to gpu");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	int index;
	int loops = (host_salt->rounds + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
				global_work_size * sizeof(pass_t), host_pass,
				0, NULL, multi_profilingEvent[0]),
				"Copy data to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
				NULL, &global_work_size, lws, 0, NULL,
				multi_profilingEvent[1]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					split_kernel, 1, NULL,
					&global_work_size, lws, 0, NULL,
					multi_profilingEvent[2]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
				global_work_size * sizeof(crack_t), host_crack,
				0, NULL, multi_profilingEvent[3]), "Copy result back");

	if (!ocl_autotune_running) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (index = 0; index < count; index++) {
			union {
				uint64_t u[8];
				unsigned char bytes[64];
			} key;
			int j;

			memcpy(key.bytes, host_crack[index].hash, 64);
			for (j = 0; j < 8; j++)
				key.u[j] = JOHNSWAP64(key.u[j]);
			JTR_hmac_sha512((const unsigned char*)"", 0, key.bytes, G_ELI_USERKEYLEN, key.bytes, G_ELI_USERKEYLEN);
			cracked[index] = geli_decrypt_verify(cur_salt, key.bytes);
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
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
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[host_pass[index].length] = 0;
	return ret;
}

struct fmt_main fmt_opencl_geli = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		geli_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		geli_common_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			geli_common_iteration_count,
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
