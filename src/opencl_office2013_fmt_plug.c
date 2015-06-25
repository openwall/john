/* MS Office 2013 cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * This OpenCL format by magnum.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum and it is hereby released to the general public
 * under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_office2013;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_office2013);
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <openssl/aes.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "common-opencl.h"
#include "office_common.h"
#include "config.h"
#include "sha2.h"

#define PLAINTEXT_LENGTH	47
#define UNICODE_LENGTH		96 /* In octets, including 0x80 */

#define FORMAT_LABEL		"office2013-opencl"
#define FORMAT_NAME		"MS Office 2013"
#define OCL_ALGORITHM_NAME	"SHA512 OpenCL"
#define CPU_ALGORITHM_NAME	" AES"
#define ALGORITHM_NAME		OCL_ALGORITHM_NAME CPU_ALGORITHM_NAME
#define BENCHMARK_COMMENT	" (100,000 iterations)"
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_LENGTH		16
#define SALT_SIZE		sizeof(*cur_salt)
#define SALT_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests tests[] = {
	/* 2013-openwall.pptx */
	{"$office$*2013*100000*256*16*9b12805dd6d56f46d07315153f3ecb9c*c5a4a167b51faa6629f6a4caf0b4baa8*87397e0659b2a6fff90291f8e6d6d0018b750b792fefed77001edbafba7769cd", "openwall"},
	/* 365-2013-openwall.docx */
	{"$office$*2013*100000*256*16*774a174239a7495a59cac39a122d991c*b2f9197840f9e5d013f95a3797708e83*ecfc6d24808691aac0daeaeba72aba314d72c6bbd12f7ff0ea1a33770187caef", "openwall"},
	/* 365-2013-password.docx */
	{"$office$*2013*100000*256*16*d4fc9302eedabf9872b24ca700a5258b*7c9554d582520747ec3e872f109a7026*1af5b5024f00e35eaf5fd8148b410b57e7451a32898acaf14275a8c119c3a4fd", "password"},
	/* 365-2013-password.xlsx */
	{"$office$*2013*100000*256*16*59b49c64c0d29de733f0025837327d50*70acc7946646ea300fc13cfe3bd751e2*627c8bdb7d9846228aaea81eeed434d022bb93bb5f4da146cb3ad9d847de9ec9", "password"},
	/* 365-2013-strict-password.docx */
	{"$office$*2013*100000*256*16*f1c23049d85876e6b20e95ab86a477f1*13303dbd27a38ea86ef11f1b2bc56225*9a69596de0655a6c6a5b2dc4b24d6e713e307fb70af2d6b67b566173e89f941d", "password"},
	{NULL}
};

static ms_office_custom_salt *cur_salt;

static int *cracked, any_cracked;
static unsigned int v_width = 1;	/* Vector width of kernel */

static char *saved_key;	/* Password encoded in UCS-2 */
static int *saved_len;	/* UCS-2 password length, in octets */
static char *saved_salt;
static unsigned char *key;	/* Output key from kernel */
static int new_keys, spincount;

static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_pwhash, cl_key, cl_spincount;
static cl_mem pinned_saved_key, pinned_saved_len, pinned_salt, pinned_key;
static cl_kernel GenerateSHA512pwhash, Generate2013key;
static struct fmt_main *self;

#define HASH_LOOPS		100 /* Lower figure gives less X hogging */
#define ITERATIONS		100000
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"xfer: ", ", xfer: ", ", init: ", ", loop: ", ",  final: ", ", xfer: "
};

static int split_events[] = { 3, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, GenerateSHA512pwhash);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Generate2013key));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
#if 1
	return get_task_max_work_group_size(); // GTX980: 1292 c/s
#elif 1
	return 0; // 1290 c/s
#else
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64; // 1290 c/s
#endif
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int i;
	int bench_len = strlen(tests[0].plaintext) * 2;

	gws *= v_width;

	pinned_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, UNICODE_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, UNICODE_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_key = (char*)clEnqueueMapBuffer(queue[gpu_id], pinned_saved_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, UNICODE_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_key");
	memset(saved_key, 0, UNICODE_LENGTH * gws);

	pinned_saved_len = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_saved_len = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_len = (int*)clEnqueueMapBuffer(queue[gpu_id], pinned_saved_len, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_int) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_len");
	for (i = 0; i < gws; i++)
		saved_len[i] = bench_len;

	pinned_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, SALT_LENGTH, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, SALT_LENGTH, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	saved_salt = (char*) clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, SALT_LENGTH, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_salt");
	memset(saved_salt, 0, SALT_LENGTH);

	cl_pwhash = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_ulong) * 9 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device state buffer");

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 128 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 128 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	key = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 128 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory verifier keys");
	memset(key, 0, 128 * gws);

	cl_spincount = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_USE_HOST_PTR, sizeof(cl_int), &spincount, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping spincount");

	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 3, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(Generate2013key, 0, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(Generate2013key, 1, sizeof(cl_mem), (void*)&cl_key), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(Generate2013key, 2, sizeof(cl_mem), (void*)&cl_spincount), "Error setting argument 2");

	cracked = mem_alloc(sizeof(*cracked) * gws);
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, key, 0, NULL, NULL), "Error Unmapping key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(cl_spincount), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_len), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_len), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_pwhash), "Release GPU buffer");

		MEM_FREE(cracked);
	}
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(GenerateSHA512pwhash), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(Generate2013key), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

static void clear_keys(void)
{
	memset(saved_key, 0, UNICODE_LENGTH * global_work_size * v_width);
	memset(saved_len, 0, sizeof(*saved_len) * global_work_size * v_width);
}

static void set_key(char *key, int index)
{
	UTF16 *utfkey = (UTF16*)&saved_key[index * UNICODE_LENGTH];

	/* convert key to UTF-16LE */
	saved_len[index] = enc_to_utf16(utfkey, PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(utfkey);

	/* Prepare for GPU */
	utfkey[saved_len[index]] = 0x80;

	saved_len[index] <<= 1;

	new_keys = 1;
}

static void set_salt(void *salt)
{
	cur_salt = (ms_office_custom_salt *)salt;
	memcpy(saved_salt, cur_salt->osalt, SALT_LENGTH);
	spincount = cur_salt->spinCount;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, SALT_LENGTH, saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_salt");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_spincount, CL_FALSE, 0, 4, &spincount, 0, NULL, NULL), "failed in clEnqueueWriteBuffer spincount");
}

static int crypt_all(int *pcount, struct db_salt *salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *salt);

static void init(struct fmt_main *_self)
{
	char build_opts[64];
	static char valgo[32] = "";

	self = _self;

	opencl_preinit();
	/* VLIW5 can't take the register pressure from vectorizing this.
	   Well it can, and it does get faster but only at a GWS that will
	   give a total time for crypt_all() of > 30 seconds. */
	if (options.v_width || !amd_vliw5(device_info[gpu_id]))
	if ((v_width = opencl_get_vector_width(gpu_id,
	                                       sizeof(cl_long))) > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         OCL_ALGORITHM_NAME " %ux" CPU_ALGORITHM_NAME, v_width);
		self->params.algorithm_name = valgo;
	}

	snprintf(build_opts, sizeof(build_opts),
	         "-DHASH_LOOPS=%u -DUNICODE_LENGTH=%u -DV_WIDTH=%u",
	         HASH_LOOPS,
	         UNICODE_LENGTH,
	         v_width);
	opencl_init("$JOHN/kernels/office2013_kernel.cl", gpu_id,
	            build_opts);

	// Create kernels to execute
	GenerateSHA512pwhash = clCreateKernel(program[gpu_id], "GenerateSHA512pwhash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[gpu_id], "HashLoop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	Generate2013key = clCreateKernel(program[gpu_id], "Generate2013key", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static void reset(struct db_main *db)
{
	if (!db) {
		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
		                       3, self, create_clobj, release_clobj,
		                       v_width * UNICODE_LENGTH, 0);

		//Auto tune execution from shared/included code.
		self->methods.crypt_all = crypt_all_benchmark;
		autotune_run(self, ITERATIONS + 4, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
		self->methods.crypt_all = crypt_all;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t gws, scalar_gws;

	gws = ((count + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size;
	scalar_gws = gws * v_width;

	if (any_cracked) {
		memset(cracked, 0, count * sizeof(*cracked));
		any_cracked = 0;
	}

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * scalar_gws, saved_key, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_key");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * scalar_gws, saved_len, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_len");
		new_keys = 0;
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA512pwhash, 1, NULL, &scalar_gws, &local_work_size, 0, NULL, firstEvent), "failed in clEnqueueNDRangeKernel");

	for (index = 0; index < spincount / HASH_LOOPS; index++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2013key, 1, NULL, &gws, &local_work_size, 0, NULL, lastEvent), "failed in clEnqueueNDRangeKernel");

	// read back verifier keys
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_key, CL_TRUE, 0, 128 * scalar_gws, key, 0, NULL, NULL), "failed in reading key back");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA512_CTX ctx;
		unsigned char decryptedVerifierHashInputBytes[16], decryptedVerifierHashBytes[32];
		unsigned char hash[64];

		ms_office_common_DecryptUsingSymmetricKeyAlgorithm(cur_salt, &key[128*index], cur_salt->encryptedVerifier, decryptedVerifierHashInputBytes, 16);
		ms_office_common_DecryptUsingSymmetricKeyAlgorithm(cur_salt, &key[128*index+64], cur_salt->encryptedVerifierHash, decryptedVerifierHashBytes, 32);
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, decryptedVerifierHashInputBytes, 16);
		SHA512_Final(hash, &ctx);
		if (!memcmp(hash, decryptedVerifierHashBytes, 20))
		{
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}
	return count;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t gws, scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = ((count + (v_width * (local_work_size ? local_work_size : 1) - 1)) / (v_width * (local_work_size ? local_work_size : 1))) * (local_work_size ? local_work_size : 1);
	scalar_gws = gws * v_width;

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * scalar_gws, saved_key, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer saved_key");
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * scalar_gws, saved_len, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer saved_len");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA512pwhash, 1, NULL, &scalar_gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2013key, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

	// read back aes key
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_key, CL_TRUE, 0, 16 * scalar_gws, key, 0, NULL, multi_profilingEvent[5]), "failed in reading key back");

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

static char *get_key(int index)
{
	UTF16 buf[PLAINTEXT_LENGTH + 1];

	memcpy(buf, &saved_key[index * UNICODE_LENGTH], saved_len[index]);
	buf[saved_len[index] >> 1] = 0;
	return (char*)utf16_to_enc(buf);
}

struct fmt_main fmt_opencl_office2013 = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		ms_office_common_valid_2013,
		fmt_default_split,
		fmt_default_binary,
		ms_office_common_get_salt,
#if FMT_MAIN_VERSION > 11
		{
			ms_office_common_iteration_count,
		},
#endif
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
