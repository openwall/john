/* MS Office 2007 cracker patch for JtR. Hacked together during March of 2012 by
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
extern struct fmt_main fmt_opencl_office2007;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_office2007);
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

#define FORMAT_LABEL		"office2007-opencl"
#define FORMAT_NAME		"MS Office 2007"
#define OCL_ALGORITHM_NAME	"SHA1 OpenCL"
#define CPU_ALGORITHM_NAME	" AES"
#define ALGORITHM_NAME		OCL_ALGORITHM_NAME CPU_ALGORITHM_NAME
#define BENCHMARK_COMMENT	" (50,000 iterations)"
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		16
#define BINARY_ALIGN		4
#define SALT_LENGTH		16
#define SALT_SIZE		sizeof(*cur_salt)
#define SALT_ALIGN		1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests tests[] = {
	{"$office$*2007*20*128*16*8b2c9e8c878844fc842012273be4bea8*aa862168b80d8c45c852696a8bb499eb*a413507fabe2d87606595f987f679ff4b5b4c2cd", "Password"},
	/* 2007-Default_myhovercraftisfullofeels_.docx */
	{"$office$*2007*20*128*16*91f095a1fd02595359fe3938fa9236fd*e22668eb1347957987175079e980990f*659f50b9062d36999bf3d0911068c93268ae1d86", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.dotx */
	{"$office$*2007*20*128*16*56ea65016fbb4eac14a6770b2dbe7e99*8cf82ce1b62f01fd3b2c7666a2313302*21443fe938177e648c482da72212a8848c2e9c80", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xlsb */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*3a040a9cef3d3675009b22f99718e39c*48053b27e95fa53b3597d48ca4ad41eec382e0c8", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xlsm */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*92bb2ef34ca662ca8a26c8e2105b05c0*0261ba08cd36a324aa1a70b3908a24e7b5a89dd6", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xlsx */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*46bef371486919d4bffe7280110f913d*b51af42e6696baa097a7109cebc3d0ff7cc8b1d8", "myhovercraftisfullofeels"},
	/* 2007-Default_myhovercraftisfullofeels_.xltx */
	{"$office$*2007*20*128*16*fbd4cc5dab9b8e341778ddcde9eca740*1addb6823689aca9ce400be8f9e55fc9*e06bf10aaf3a4049ffa49dd91cf9e7bbf88a1b3b", "myhovercraftisfullofeels"},
	{NULL}
};

static ms_office_custom_salt *cur_salt;

static ARCH_WORD_32 (*crypt_key)[4];
static unsigned int v_width = 1;	/* Vector width of kernel */

static char *saved_key;	/* Password encoded in UCS-2 */
static int *saved_len;	/* UCS-2 password length, in octets */
static char *saved_salt;
static unsigned char *key;	/* Output key from kernel */
static int new_keys;

static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_pwhash, cl_key;
static cl_mem pinned_saved_key, pinned_saved_len, pinned_salt, pinned_key;
static cl_kernel GenerateSHA1pwhash, Generate2007key;
static struct fmt_main *self;

#define HASH_LOOPS		500 /* Lower figure gives less X hogging */
#define ITERATIONS		50000
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
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Generate2007key));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
#if 1
	return get_task_max_work_group_size(); // GTX980: 58975 c/s
#elif 1
	return 0; // 58975 c/s
#else
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64; // 55072 c/s
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

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	key = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 16 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory key");
	memset(key, 0, 16 * gws);

	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 3, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(Generate2007key, 0, sizeof(cl_mem), (void*)&cl_pwhash), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(Generate2007key, 1, sizeof(cl_mem), (void*)&cl_key), "Error setting argument 1");

	crypt_key = mem_calloc(gws, sizeof(*crypt_key));
}

static void release_clobj(void)
{
	if (crypt_key) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, key, 0, NULL, NULL), "Error Unmapping key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_len), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_len), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_pwhash), "Release GPU buffer");

		MEM_FREE(crypt_key);
	}
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(GenerateSHA1pwhash), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(Generate2007key), "Release kernel");
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
	//dump_stuff_msg("key buffer", &saved_key[index*UNICODE_LENGTH], UNICODE_LENGTH);
}

static void set_salt(void *salt)
{
	cur_salt = (ms_office_custom_salt *)salt;
	memcpy(saved_salt, cur_salt->osalt, SALT_LENGTH);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, SALT_LENGTH, saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_salt");
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
	opencl_init("$JOHN/kernels/office2007_kernel.cl", gpu_id,
	            build_opts);

	// create kernel to execute
	GenerateSHA1pwhash = clCreateKernel(program[gpu_id], "GenerateSHA1pwhash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[gpu_id], "HashLoop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	Generate2007key = clCreateKernel(program[gpu_id], "Generate2007key", &ret_code);
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
		                       v_width * UNICODE_LENGTH, 0);

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

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * scalar_gws, saved_key, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_key");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * scalar_gws, saved_len, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_len");
		new_keys = 0;
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA1pwhash, 1, NULL, &scalar_gws, &local_work_size, 0, NULL, firstEvent), "failed in clEnqueueNDRangeKernel");

	for (index = 0; index < 50000 / HASH_LOOPS; index++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2007key, 1, NULL, &gws, &local_work_size, 0, NULL, lastEvent), "failed in clEnqueueNDRangeKernel");

	// read back aes key
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_key, CL_TRUE, 0, 16 * scalar_gws, key, 0, NULL, NULL), "failed in reading key back");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
		ms_office_common_PasswordVerifier(cur_salt, &key[index*16], crypt_key[index]);
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

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2007key, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

	// read back aes key
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_key, CL_TRUE, 0, 16 * scalar_gws, key, 0, NULL, multi_profilingEvent[5]), "failed in reading key back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++) {
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_key[index][0] )
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int get_hash_0(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_key[index][0] & 0x7ffffff; }

static char *get_key(int index)
{
	UTF16 buf[PLAINTEXT_LENGTH + 1];

	memcpy(buf, &saved_key[index * UNICODE_LENGTH], saved_len[index]);
	buf[saved_len[index] >> 1] = 0;
	return (char*)utf16_to_enc(buf);
}

struct fmt_main fmt_opencl_office2007 = {
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
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		ms_office_common_valid_2007,
		fmt_default_split,
		ms_office_common_binary,
		ms_office_common_get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
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
