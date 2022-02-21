/*
 * This software is Copyright (c) 2015-2020 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_sevenzip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_sevenzip);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#if !AC_BUILT
#define HAVE_LIBZ 1 /* legacy build has -lz in LDFLAGS */
#endif
#if HAVE_LIBZ
#include <zlib.h>
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "formats.h"
#include "common.h"
#include "misc.h"
#include "opencl_common.h"
#include "options.h"
#include "unicode.h"
#include "dyna_salt.h"
#include "config.h"

#define FORMAT_LABEL		"7z-opencl"
#define ALGORITHM_NAME		"SHA256 AES OpenCL"
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define PLAINTEXT_LENGTH	((55-8)/2) // 23, rar3 uses 22
#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)

#include "7z_common.h"

typedef struct {
	uint32_t length;
	uint16_t v[PLAINTEXT_LENGTH];
} sevenzip_password;

typedef struct {
	uint32_t key[32/4];
	uint32_t round;
	uint32_t reject;
} sevenzip_hash;

typedef struct {
	size_t aes_length;
	size_t packed_size;
	uint32_t iterations;
	//uint32_t salt_size;
	//uint8_t salt[16];
	uint8_t data[32]; /* Last two blocks of data */
} sevenzip_data;

typedef struct {
	cl_uint total[2];
	cl_uint state[8];
	cl_uchar buffer[64];
} SHA256_CTX;

typedef struct {
	cl_ulong t;
	SHA256_CTX ctx;
	cl_uint len;
	cl_ushort buffer[PLAINTEXT_LENGTH];
} sevenzip_state;

static int *cracked;
static int any_cracked;
static int new_keys;

static sevenzip_password *inbuffer;
static sevenzip_hash *outbuffer;
static sevenzip_data currentsalt;
static cl_mem mem_in, mem_out, mem_salt;
static cl_kernel sevenzip_init, sevenzip_final, sevenzip_aes;

#define insize (sizeof(sevenzip_password) * global_work_size)
#define outsize (sizeof(sevenzip_hash) * global_work_size)
#define statesize (sizeof(sevenzip_state) * global_work_size)
#define saltsize sizeof(sevenzip_data)
#define cracked_size (sizeof(*cracked) * global_work_size)

static struct fmt_main *self;

#define HASH_LOOPS	0x4000 // Must be multiple of 32
#define LOOP_COUNT	((1 << currentsalt.iterations) / HASH_LOOPS)
#define STEP		0
#define SEED		16

static int split_events[] = { 2, -1, -1 };

static const char *warn[] = {
	"xfer: ",  ", init: ",  ", crypt: ",  ", final: ",  ", aes: ",  ", xfer: "
};

// This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, sevenzip_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, sevenzip_final));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, sevenzip_aes));
	return s;
}

static void release_clobj(void);

static void create_clobj(size_t global_work_size, struct fmt_main *self)
{
	cl_int cl_error;

	release_clobj();

	inbuffer = (sevenzip_password*) mem_calloc(1, insize);
	outbuffer = (sevenzip_hash*) mem_alloc(outsize);

	cracked = mem_calloc(1, cracked_size);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(sevenzip_init, 0, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(sevenzip_final, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_final, 1, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_final, 2, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(sevenzip_aes, 0, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_aes, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(sevenzip_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(sevenzip_final), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(sevenzip_aes), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	CRC32_t crc;

	self = _self;
	opencl_prepare_dev(gpu_id);

	CRC32_Init(&crc);

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);

	if (cfg_get_bool(SECTION_FORMATS, "7z", "TrustPadding", 0))
		sevenzip_trust_padding = 1;
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];
		cl_int cl_error;

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DHASH_LOOPS=%d",
		         PLAINTEXT_LENGTH, HASH_LOOPS);
		opencl_init("$JOHN/opencl/7z_kernel.cl",
		            gpu_id, build_opts);

		sevenzip_init = clCreateKernel(program[gpu_id], "sevenzip_init",
		                               &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		crypt_kernel = clCreateKernel(program[gpu_id], "sevenzip_loop",
		                              &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sevenzip_final = clCreateKernel(program[gpu_id], "sevenzip_final",
		                               &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		sevenzip_aes = clCreateKernel(program[gpu_id], "sevenzip_aes",
		                              &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
	                       warn, 2, self,
	                       create_clobj, release_clobj,
	                       sizeof(sevenzip_state), 0, db);

	//  Auto tune execution from shared/included code.
	autotune_run(self, 1 << 19, 0, 200);
}

static void set_salt(void *salt)
{
	sevenzip_salt = *((sevenzip_salt_t**)salt);

	//memcpy(currentsalt.salt, cur_salt->salt, cur_salt->SaltSize);
	//currentsalt.salt_size = cur_salt->SaltSize;

	if (currentsalt.iterations != sevenzip_salt->NumCyclesPower)
		new_keys = 1;

	if (sevenzip_salt->aes_length >= 32)
		memcpy(currentsalt.data, sevenzip_salt->data + sevenzip_salt->aes_length - 32, 32);

	currentsalt.aes_length = sevenzip_salt->aes_length;
	currentsalt.packed_size = sevenzip_salt->packed_size;
	currentsalt.iterations = sevenzip_salt->NumCyclesPower;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
		"Transfer salt to gpu");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void clear_keys(void)
{
	memset(inbuffer, 0, insize);
}

static void set_key(char *key, int index)
{
	UTF16 c_key[PLAINTEXT_LENGTH + 1];
	int length = strlen(key);

	/* Convert password to utf-16-le format (--encoding aware) */
	length = enc_to_utf16(c_key, PLAINTEXT_LENGTH,
	                      (UTF8*)key, length);
	if (length <= 0)
		length = strlen16(c_key);
	length *= 2;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, c_key, length);

	new_keys = 1;
}

static char *get_key(int index)
{
	UTF16 c_key[PLAINTEXT_LENGTH + 1];
	int length = inbuffer[index].length;

	memcpy(c_key, inbuffer[index].v, length);
	c_key[length / 2] = 0;

	return (char*)utf16_to_enc(c_key);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	/* Note: This format is effectively unsalted */
	if (new_keys) {
		int i;

		// Copy data to gpu
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		// Run 1st kernel
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_init, 1,
			NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]),
			"Run init kernel");

		// Better precision for WAIT_ macros
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

		// Run loop kernel
		WAIT_INIT(global_work_size)
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
				crypt_kernel, 1, NULL, &global_work_size, lws, 0,
				NULL, multi_profilingEvent[2]),
				"Run loop kernel");
			WAIT_SLEEP
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			WAIT_UPDATE
			opencl_process_event();
		}
		WAIT_DONE

		// Run final kernel
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_final, 1,
			NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]),
			"Run final loop kernel");

		new_keys = 0;
	}

	if (sevenzip_trust_padding || sevenzip_salt->type == 0x80) {
		// Run AES kernel (only for truncated hashes)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_aes, 1,
			NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[4]),
			"Run AES kernel");
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[5]),
		"Copy result back");

	if (!ocl_autotune_running) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (index = 0; index < count; index++) {
			sevenzip_hash *derived = (sevenzip_hash*)&outbuffer[index];

			if (derived->reject && (sevenzip_trust_padding || sevenzip_salt->type == 0x80))
				continue;

			/* decrypt and check */
			if ((cracked[index] = sevenzip_decrypt((uint8_t*)derived->key)))
			{
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_sevenzip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_ENC | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{
			"iteration count",
			"padding size",
			"compression type",
			"data length"
		},
		{ FORMAT_TAG },
		sevenzip_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		sevenzip_valid,
		fmt_default_split,
		fmt_default_binary,
		sevenzip_get_salt,
		{
			sevenzip_iteration_count,
			sevenzip_padding_size,
			sevenzip_compression_type,
			sevenzip_data_len
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		sevenzip_salt_compare,
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
