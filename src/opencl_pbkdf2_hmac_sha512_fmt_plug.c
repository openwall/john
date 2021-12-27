/*
 * This software is
 * Copyright (c) 2012, 2013 Lukas Odzioba <ukasz at openwall dot net>
 * Copyright (c) 2014 JimF
 * Copyright (c) 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_pbkdf2_hmac_sha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_pbkdf2_hmac_sha512);
#else

#include <stdint.h>
#include <ctype.h>
#include <string.h>

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "opencl_common.h"
#include "johnswap.h"
#include "pbkdf2_hmac_common.h"

#define FORMAT_LABEL             "PBKDF2-HMAC-SHA512-opencl"
#define FORMAT_NAME              "GRUB2 / OS X 10.8+"
#define ALGORITHM_NAME           "PBKDF2-SHA512 OpenCL"
#define BINARY_ALIGN             8
#define PLAINTEXT_LENGTH         110
#define SALT_SIZE                sizeof(salt_t)
#define SALT_ALIGN               sizeof(uint64_t)
#define KERNEL_NAME              "pbkdf2_sha512_kernel"
#define SPLIT_KERNEL_NAME        "pbkdf2_sha512_loop"

#define HASH_LOOPS               250
#define ITERATIONS               10000

typedef struct {
	// for plaintext, we must make sure it is a full uint64 width.
	uint64_t v[(PLAINTEXT_LENGTH+7)/8]; // v must be kept aligned(8)
	uint64_t length; // keep 64 bit aligned. length is overkill, but easiest way to stay aligned.
} pass_t;

typedef struct {
	uint64_t hash[8];
} crack_t;

typedef struct {
	// for salt, we append \x00\x00\x00\x01\x80 and must make sure it is a full uint64 width
	uint64_t salt[(PBKDF2_64_MAX_SALT_SIZE+1+4+7)/8]; // salt must be kept aligned(8)
	uint32_t length;
	uint32_t rounds;
} salt_t;

typedef struct {
	cl_ulong ipad[8];
	cl_ulong opad[8];
	cl_ulong hash[8];
	cl_ulong W[8];
	cl_uint rounds;
} state_t;

// #define DEBUG
static pass_t *host_pass; // plain ciphertexts
static salt_t *host_salt;  // salt
static crack_t *host_crack;  // cracked or not
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel split_kernel;
static cl_int cl_error;
static struct fmt_main *self;
static int new_keys;

#define STEP                     0
#define SEED                     256

static const char * warn[] = {
	"xfer: ",  ", init: " , ", crypt: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t min_lws =
		autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	return MIN(min_lws, autotune_get_task_max_work_group_size(FALSE, 0,
	                                                          split_kernel));
}

static void release_clobj(void);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	release_clobj();

	host_pass = mem_calloc(kpc, sizeof(pass_t));
	host_crack = mem_calloc(kpc, sizeof(crack_t));
	host_salt = mem_calloc(1, sizeof(salt_t));
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)  \
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error); \
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)  \
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
	if (!program[gpu_id]) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%d -DPBKDF2_64_MAX_SALT_SIZE=%d",
		         HASH_LOOPS, PLAINTEXT_LENGTH, PBKDF2_64_MAX_SALT_SIZE);

		opencl_init("$JOHN/opencl/pbkdf2_hmac_sha512_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
	                       2, self, create_clobj, release_clobj,
	                       sizeof(state_t), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ITERATIONS, 0, 200);
}

static void release_clobj(void)
{
	if (host_pass) {
		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(host_crack);

		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void *get_binary(char *ciphertext)
{
	uint64_t *u = pbkdf2_hmac_sha512_binary(ciphertext);
	int i;

	// swap here, so we do not have to swap at end of GPU code.
	for (i = 0; i < PBKDF2_SHA512_BINARY_SIZE/8; ++i)
		u[i] = JOHNSWAP64(u[i]);
	return u;
}

static void *get_salt(char *ciphertext)
{
	static salt_t cs;
	uint8_t salt[PBKDF2_64_MAX_SALT_SIZE+1+4+1];
	char *p;
	int saltlen;
	char delim;

	memset(&cs, 0, sizeof(cs));
	ciphertext += PBKDF2_SHA512_TAG_LEN;
	cs.rounds = atou(ciphertext);
	delim = strchr(ciphertext, '.') ? '.' : '$';
	ciphertext = strchr(ciphertext, delim) + 1;
	p = strchr(ciphertext, delim);
	saltlen = 0;
	while (ciphertext < p) {  // extract salt
		salt[saltlen++] =
			atoi16[ARCH_INDEX(ciphertext[0])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[1])];
		ciphertext += 2;
	}
	// we append the count and EOM here, one time.
	memcpy(&salt[saltlen], "\x0\x0\x0\x1\x80", 5);
	memcpy(cs.salt, salt, saltlen+5);
	cs.length = saltlen+5; // we include the x80 byte in our saltlen, but the .cl kernel knows to reduce saltlen by 1

	return (void *)&cs;
}

static void set_salt(void *salt)
{
	memcpy(host_salt, salt, SALT_SIZE);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(salt_t), host_salt, 0, NULL, NULL),
		"Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	int loops = (host_salt->rounds + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

#if 0
	printf("crypt_all(%d)\n", count);
	printf("LWS = %d, GWS = %d, loops=%d\n",(int)local_work_size, (int)global_work_size, loops);
#endif

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			global_work_size * sizeof(pass_t), host_pass, 0, NULL,
			multi_profilingEvent[0]), "Copy data to gpu");

		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		        split_kernel,
			1, NULL, &global_work_size, lws, 0, NULL,
			multi_profilingEvent[2]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}
	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		global_work_size * sizeof(crack_t), host_crack, 0, NULL,
		 multi_profilingEvent[3]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		if (host_crack[i].hash[0] == ((uint64_t*)binary)[0])
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return host_crack[index].hash[0] == ((uint64_t*)binary)[0];
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

static int cmp_exact(char *source, int index)
{
	// NOTE, salt and salt length includes \x0\x0\x0\x1\x80. we have to 'remove' that.
	return pbkdf2_hmac_sha512_cmp_exact(get_key(index), source, (unsigned char*)host_salt->salt, host_salt->length-5, host_salt->rounds);
}

static int binary_hash_0(void *binary)
{
	return (((uint32_t *) binary)[0] & PH_MASK_0);
}

static int binary_hash_1(void *binary) { return (((uint32_t *) binary)[0] & PH_MASK_1); }
static int binary_hash_2(void *binary) { return (((uint32_t *) binary)[0] & PH_MASK_2); }
static int binary_hash_3(void *binary) { return (((uint32_t *) binary)[0] & PH_MASK_3); }
static int binary_hash_4(void *binary) { return (((uint32_t *) binary)[0] & PH_MASK_4); }
static int binary_hash_5(void *binary) { return (((uint32_t *) binary)[0] & PH_MASK_5); }
static int binary_hash_6(void *binary) { return (((uint32_t *) binary)[0] & PH_MASK_6); }

static int get_hash_0(int index)
{
	return host_crack[index].hash[0] & PH_MASK_0;
}

static int get_hash_1(int index) { return host_crack[index].hash[0] & PH_MASK_1; }
static int get_hash_2(int index) { return host_crack[index].hash[0] & PH_MASK_2; }
static int get_hash_3(int index) { return host_crack[index].hash[0] & PH_MASK_3; }
static int get_hash_4(int index) { return host_crack[index].hash[0] & PH_MASK_4; }
static int get_hash_5(int index) { return host_crack[index].hash[0] & PH_MASK_5; }
static int get_hash_6(int index) { return host_crack[index].hash[0] & PH_MASK_6; }

static unsigned int iteration_count(void *salt)
{
	salt_t *my_salt = salt;

	return (unsigned int) my_salt->rounds;
}

struct fmt_main fmt_opencl_pbkdf2_hmac_sha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		PBKDF2_SHA512_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		1,
		1,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{
			"iteration count",
		},
		{
			PBKDF2_SHA512_FORMAT_TAG,
			FORMAT_TAG_ML,
			FORMAT_TAG_GRUB
		},
		pbkdf2_hmac_sha512_common_tests
	}, {
		init,
		done,
		reset,
		pbkdf2_hmac_sha512_prepare,
		pbkdf2_hmac_sha512_valid,
		pbkdf2_hmac_sha512_split,
		get_binary,
		get_salt,
		{
			iteration_count,
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
		fmt_default_salt_hash,
		NULL,
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
