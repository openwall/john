/*
 * MS Office >= 2007 cracker for JtR. OpenCL support by magnum.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012-2021, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_office;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_office);
#else

#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "opencl_common.h"
#include "office_common.h"
#include "config.h"

#define PLAINTEXT_LENGTH    47 /* 2007 and 2010 can do 51/104 */
#define UNICODE_LENGTH      96 /* In octets, including 0x80 */

#define FORMAT_LABEL        "office-opencl"
#define FORMAT_NAME         "MS Office"
#define OCL_ALGORITHM_NAME  "SHA1/SHA512 AES OpenCL"
#define ALGORITHM_NAME      OCL_ALGORITHM_NAME
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static struct fmt_tests tests[] = {
	{"$office$*2007*20*128*16*8b2c9e8c878844fc842012273be4bea8*aa862168b80d8c45c852696a8bb499eb*a413507fabe2d87606595f987f679ff4b5b4c2cd", "Password"},
	/* 2007-Default_myhovercraftisfullofeels_.docx */
	{"$office$*2007*20*128*16*91f095a1fd02595359fe3938fa9236fd*e22668eb1347957987175079e980990f*659f50b9062d36999bf3d0911068c93268ae1d86", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.docx */
	{"$office$*2010*100000*128*16*213aefcafd9f9188e78c1936cbb05a44*d5fc7691292ab6daf7903b9a8f8c8441*46bfac7fb87cd43bd0ab54ebc21c120df5fab7e6f11375e79ee044e663641d5e", "myhovercraftisfullofeels"},
	/* 2013-openwall.pptx */
	{"$office$*2013*100000*256*16*9b12805dd6d56f46d07315153f3ecb9c*c5a4a167b51faa6629f6a4caf0b4baa8*87397e0659b2a6fff90291f8e6d6d0018b750b792fefed77001edbafba7769cd", "openwall"},
	/* Github issue #4780 (256-bit key length) */
	{"$office$*2007*20*256*16*3e94c22e93f35e14162402da444dec28*7057eb00b1e0e1cce5c85ba0727e9686*ff4f3a5a9e872c364e6d83f07af904ce518b53e6", "12Qwaszx"},
#if DEBUG
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

	/* 2010-Default_myhovercraftisfullofeels_.dotx */
	{"$office$*2010*100000*128*16*0907ec6ecf82ede273b7ee87e44f4ce5*d156501661638cfa3abdb7fdae05555e*4e4b64e12b23f44d9a8e2e00196e582b2da70e5e1ab4784384ad631000a5097a", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.xlsb */
	{"$office$*2010*100000*128*16*71093d08cf950f8e8397b8708de27c1f*00780eeb9605c7e27227c5619e91dc21*90aaf0ea5ccc508e699de7d62c310f94b6798ae77632be0fc1a0dc71600dac38", "myhovercraftisfullofeels"},
	/* 2010-Default_myhovercraftisfullofeels_.xlsx */
	{"$office$*2010*100000*128*16*71093d08cf950f8e8397b8708de27c1f*ef51883a775075f30d2207e87987e6a3*a867f87ea955d15d8cb08dc8980c04bf564f8af060ab61bf7fa3543853e0d11a", "myhovercraftisfullofeels"},

	/* 365-2013-openwall.docx */
	{"$office$*2013*100000*256*16*774a174239a7495a59cac39a122d991c*b2f9197840f9e5d013f95a3797708e83*ecfc6d24808691aac0daeaeba72aba314d72c6bbd12f7ff0ea1a33770187caef", "openwall"},
	/* 365-2013-password.docx */
	{"$office$*2013*100000*256*16*d4fc9302eedabf9872b24ca700a5258b*7c9554d582520747ec3e872f109a7026*1af5b5024f00e35eaf5fd8148b410b57e7451a32898acaf14275a8c119c3a4fd", "password"},
	/* 365-2013-password.xlsx */
	{"$office$*2013*100000*256*16*59b49c64c0d29de733f0025837327d50*70acc7946646ea300fc13cfe3bd751e2*627c8bdb7d9846228aaea81eeed434d022bb93bb5f4da146cb3ad9d847de9ec9", "password"},
	/* 365-2013-strict-password.docx */
	{"$office$*2013*100000*256*16*f1c23049d85876e6b20e95ab86a477f1*13303dbd27a38ea86ef11f1b2bc56225*9a69596de0655a6c6a5b2dc4b24d6e713e307fb70af2d6b67b566173e89f941d", "password"},
#endif /* DEBUG */
	{NULL}
};

typedef struct {
	uint32_t pass;
	uint32_t dummy;
	union {
		uint32_t w[512/8/4];
		uint64_t l[512/8/8];
	} ctx;
} ms_office_state;

typedef struct {
        uint32_t cracked;
} ms_office_out;

static ms_office_custom_salt *cur_salt;

static char *saved_key;	/* Password encoded in UCS-2 */
static int *saved_len;	/* UCS-2 password length, in octets */
static ms_office_binary_blob *blob;
static ms_office_out *out;	/* Output from kernel */
static int new_keys;
static size_t outsize;

static cl_mem cl_saved_key, cl_saved_len, cl_blob, cl_state, cl_out, cl_salt;
static cl_mem pinned_saved_key, pinned_saved_len, pinned_out, pinned_blob;
static cl_kernel GenerateSHA1pwhash, Loop0710, Final2007;
static cl_kernel Generate2010key;
static cl_kernel GenerateSHA512pwhash, Loop13, Generate2013key;
static struct fmt_main *self;

#define HASH_LOOPS0710      2500 /* Lower figure gives less X hogging */
#define HASH_LOOPS13        500 /* Lower figure gives less X hogging */
#define ITERATIONS2007      50000
#define STEP                0
#define SEED                128

static const char * warn[] = {
	"xfer: ", ", xfer: ", ", init: ", ", loop: ", ",  final: ", ", xfer: "
};

static int split_events[] = { 3, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, GenerateSHA1pwhash);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Loop0710));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Final2007));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Generate2010key));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, GenerateSHA512pwhash));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Loop13));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, Generate2013key));
	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	int i;
	int bench_len = strlen(tests[0].plaintext) * 2;

	release_clobj();

	outsize = sizeof(ms_office_out) * gws;

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

	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(ms_office_custom_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");

	pinned_blob = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(ms_office_binary_blob), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_blob = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(ms_office_binary_blob), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	blob = (ms_office_binary_blob*) clEnqueueMapBuffer(queue[gpu_id], pinned_blob, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(ms_office_binary_blob), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory blob");
	memset(blob, 0, sizeof(ms_office_binary_blob));

	cl_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(ms_office_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device state buffer");

	pinned_out = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating page-locked memory");
	cl_out = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating device memory");
	out = clEnqueueMapBuffer(queue[gpu_id], pinned_out, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, outsize, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out");
	memset(out, 0, outsize);

	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA1pwhash, 3, sizeof(cl_mem), (void*)&cl_state), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(GenerateSHA512pwhash, 3, sizeof(cl_mem), (void*)&cl_state), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(Loop0710, 0, sizeof(cl_mem), (void*)&cl_state), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(Loop13, 0, sizeof(cl_mem), (void*)&cl_state), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(Final2007, 0, sizeof(cl_mem), (void*)&cl_state), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(Final2007, 1, sizeof(cl_mem), (void*)&cl_out), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(Final2007, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(Final2007, 3, sizeof(cl_mem), (void*)&cl_blob), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(Generate2010key, 0, sizeof(cl_mem), (void*)&cl_state), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(Generate2010key, 1, sizeof(cl_mem), (void*)&cl_out), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(Generate2010key, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(Generate2010key, 3, sizeof(cl_mem), (void*)&cl_blob), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(Generate2013key, 0, sizeof(cl_mem), (void*)&cl_state), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(Generate2013key, 1, sizeof(cl_mem), (void*)&cl_out), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(Generate2013key, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(Generate2013key, 3, sizeof(cl_mem), (void*)&cl_blob), "Error setting argument 3");
}

static void release_clobj(void)
{
	if (pinned_out) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_out, out, 0, NULL, NULL), "Error Unmapping out");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_blob, blob, 0, NULL, NULL), "Error Unmapping blob");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_out), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_len), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_blob), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_out), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_len), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_blob), "Release GPU buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_state), "Release GPU buffer");

		pinned_out = NULL;
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(GenerateSHA1pwhash), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(GenerateSHA512pwhash), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(Loop0710), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(Loop13), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(Final2007), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(Generate2010key), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(Generate2013key), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void clear_keys(void)
{
	memset(saved_key, 0, UNICODE_LENGTH * global_work_size);
	memset(saved_len, 0, sizeof(*saved_len) * global_work_size);
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

static char *get_key(int index)
{
	UTF16 buf[PLAINTEXT_LENGTH + 1];

	memcpy(buf, &saved_key[index * UNICODE_LENGTH], saved_len[index]);
	buf[saved_len[index] >> 1] = 0;
	return (char*)utf16_to_enc(buf);
}

static void set_salt(void *salt)
{
	cur_salt = (ms_office_custom_salt *)salt;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, sizeof(ms_office_custom_salt), cur_salt, 0, NULL, NULL), "Copy setting to gpu");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_prepare_dev(gpu_id);
	if (options.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS0710=%u -DHASH_LOOPS13=%u -DUNICODE_LENGTH=%u",
		         HASH_LOOPS0710, HASH_LOOPS13, UNICODE_LENGTH);
		opencl_init("$JOHN/opencl/office_kernel.cl", gpu_id, build_opts);

		// create kernels to execute
		GenerateSHA1pwhash = clCreateKernel(program[gpu_id], "GenerateSHA1pwhash", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		crypt_kernel = Loop0710 = clCreateKernel(program[gpu_id], "HashLoop0710", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		Final2007 = clCreateKernel(program[gpu_id], "Final2007", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		Generate2010key = clCreateKernel(program[gpu_id], "Generate2010key", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		GenerateSHA512pwhash = clCreateKernel(program[gpu_id], "GenerateSHA512pwhash", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		Loop13 = clCreateKernel(program[gpu_id], "HashLoop13", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		Generate2013key = clCreateKernel(program[gpu_id], "Generate2013key", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	}

	int loops = HASH_LOOPS0710;
	int iterations = ITERATIONS2007;

	if (options.loader.min_cost[0]) {
		iterations = options.loader.min_cost[0] == 2007 ? 50000 : 100000;
		loops = options.loader.min_cost[0] == 2013 ? HASH_LOOPS13 : HASH_LOOPS0710;
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, loops, split_events, warn,
	                       3, self, create_clobj, release_clobj,
	                       UNICODE_LENGTH, 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, iterations + 4, 0, 200);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_NEXT_MULTIPLE(count, local_work_size);

	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * gws, saved_key, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer saved_key");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * gws, saved_len, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer saved_len");

		new_keys = 0;
	}

	if (cur_salt->version == 2013) {

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA512pwhash, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

		// Better precision for WAIT_ macros
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

		WAIT_INIT(global_work_size)
		for (index = 0; index < (ocl_autotune_running ? 1 : cur_salt->spinCount / HASH_LOOPS13); index++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Loop13, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");
			WAIT_SLEEP
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			WAIT_UPDATE
			opencl_process_event();
		}
		WAIT_DONE

	} else { /* 2007 or 2010 */

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA1pwhash, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

		// Better precision for WAIT_ macros
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

		WAIT_INIT(global_work_size)
		for (index = 0; index < (ocl_autotune_running ? 1 : cur_salt->spinCount / HASH_LOOPS0710); index++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Loop0710, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");
			WAIT_SLEEP
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			WAIT_UPDATE
			opencl_process_event();
		}
		WAIT_DONE

	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	fmt_data *blob_bin = binary;
	ms_office_binary_blob *binary_blob = blob_bin->blob;

	gws = GET_NEXT_MULTIPLE(count, local_work_size);

	memcpy(blob, binary_blob, sizeof(ms_office_binary_blob));
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_blob, CL_FALSE, 0, sizeof(ms_office_binary_blob), blob, 0, NULL, NULL), "failed in clEnqueueWriteBuffer blob");

	if (cur_salt->version == 2013) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2013key, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

	} else { /* 2007 or 2010 */

		if (cur_salt->version == 2007)
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Final2007, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");
		else /* 2010 */
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2010key, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

	}

	// Get results
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_out, CL_FALSE, 0, outsize, out, 0, NULL, multi_profilingEvent[5]), "failed in reading results");

	WAIT_INIT(gws)
	BENCH_CLERROR(clFlush(queue[gpu_id]), "clFlush");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
	WAIT_UPDATE
	WAIT_DONE

	for (index = 0; index < count; index++)
		if (out[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return out[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_office = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_BLOB,
		{
			"MS Office version",
			"iteration count",
		},
		{ FORMAT_TAG_OFFICE },
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		ms_office_common_valid,
		fmt_default_split,
		ms_office_common_binary,
		ms_office_common_get_salt,
		{
			ms_office_common_version,
			ms_office_common_iteration_count,
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
