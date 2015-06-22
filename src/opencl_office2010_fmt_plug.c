/* MS Office 2010 cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * OpenCL support by magnum.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum and it is hereby released to the general public
 * under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_office2010;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_office2010);
#else

#include "sha.h"
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

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

#define PLAINTEXT_LENGTH	51
#define UNICODE_LENGTH		104 /* In octets, including 0x80 */

#define FORMAT_LABEL		"office2010-opencl"
#define FORMAT_NAME		"MS Office 2010"
#define OCL_ALGORITHM_NAME	"SHA1 OpenCL"
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
	/* 2010-Default_myhovercraftisfullofeels_.docx */
	{"$office$*2010*100000*128*16*213aefcafd9f9188e78c1936cbb05a44*d5fc7691292ab6daf7903b9a8f8c8441*46bfac7fb87cd43bd0ab54ebc21c120df5fab7e6f11375e79ee044e663641d5e", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.dotx */
	{"$office$*2010*100000*128*16*0907ec6ecf82ede273b7ee87e44f4ce5*d156501661638cfa3abdb7fdae05555e*4e4b64e12b23f44d9a8e2e00196e582b2da70e5e1ab4784384ad631000a5097a", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.xlsb */
	{"$office$*2010*100000*128*16*71093d08cf950f8e8397b8708de27c1f*00780eeb9605c7e27227c5619e91dc21*90aaf0ea5ccc508e699de7d62c310f94b6798ae77632be0fc1a0dc71600dac38", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.xlsx */
	{"$office$*2010*100000*128*16*71093d08cf950f8e8397b8708de27c1f*ef51883a775075f30d2207e87987e6a3*a867f87ea955d15d8cb08dc8980c04bf564f8af060ab61bf7fa3543853e0d11a", "myhovercraftisfullofeels"},
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
static struct fmt_main *self;

static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_pwhash, cl_key, cl_spincount;
static cl_mem pinned_saved_key, pinned_saved_len, pinned_salt, pinned_key;
static cl_kernel GenerateSHA1pwhash, Generate2010key;

#define HASH_LOOPS		500 /* Lower figure gives less X hogging */
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

	s = autotune_get_task_max_work_group_size(FALSE, 0, GenerateSHA1pwhash);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Generate2010key));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
#if 1
	return get_task_max_work_group_size(); // GTX980: 29454 c/s
#elif 1
	return 0; // 29454 c/s
#else
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64; // 27536 c/s
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

	cl_pwhash = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cl_uint) * 6 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device state buffer");

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 32 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 32 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	key = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 32 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory verifier keys");
	memset(key, 0, 32 * gws);

	cl_spincount = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_USE_HOST_PTR, sizeof(cl_int), &spincount, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping spincount");

	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 3, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(Generate2010key, 0, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(Generate2010key, 1, sizeof(cl_mem), (void*)&cl_key), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(Generate2010key, 2, sizeof(cl_mem), (void*)&cl_spincount), "Error setting argument 2");

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
	HANDLE_CLERROR(clReleaseKernel(GenerateSHA1pwhash), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(Generate2010key), "Release kernel");
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

	if ((v_width = opencl_get_vector_width(gpu_id,
	                                       sizeof(cl_int))) > 1) {
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
	opencl_init("$JOHN/kernels/office2010_kernel.cl", gpu_id,
	            build_opts);

	// create kernel to execute
	GenerateSHA1pwhash = clCreateKernel(program[gpu_id], "GenerateSHA1pwhash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[gpu_id], "HashLoop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	Generate2010key = clCreateKernel(program[gpu_id], "Generate2010key", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static void reset(struct db_main *db)
{
	if (!db) {
		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
		                       3, self, create_clobj, release_clobj,
		                       2 * v_width * UNICODE_LENGTH, 0);

		// Auto tune execution from shared/included code.
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

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA1pwhash, 1, NULL, &scalar_gws, &local_work_size, 0, NULL, firstEvent), "failed in clEnqueueNDRangeKernel");

	for (index = 0; index < spincount / HASH_LOOPS; index++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2010key, 1, NULL, &gws, &local_work_size, 0, NULL, lastEvent), "failed in clEnqueueNDRangeKernel");

	// read back verifier keys
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_key, CL_TRUE, 0, 32 * scalar_gws, key, 0, NULL, NULL), "failed in reading key back");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA_CTX ctx;
		unsigned char hash[20];
		unsigned char decryptedVerifierHashInputBytes[16], decryptedVerifierHashBytes[32];
		ms_office_common_DecryptUsingSymmetricKeyAlgorithm(cur_salt, &key[32*index], cur_salt->encryptedVerifier, decryptedVerifierHashInputBytes, 16);
		ms_office_common_DecryptUsingSymmetricKeyAlgorithm(cur_salt, &key[32*index+16], cur_salt->encryptedVerifierHash, decryptedVerifierHashBytes, 32);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, decryptedVerifierHashInputBytes, 16);
		SHA1_Final(hash, &ctx);
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

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA1pwhash, 1, NULL, &scalar_gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2010key, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

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

struct fmt_main fmt_opencl_office2010 = {
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
		ms_office_common_valid_2010,
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
