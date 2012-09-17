/* Office 2007 cracker patch for JtR. Hacked together during March of 2012 by
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
#include <openssl/sha.h>
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
#include "base64.h"
#include "unicode.h"
#include "common-opencl.h"
#include "config.h"

#define FORMAT_LABEL		"office-opencl"
//#define FORMAT_NAME		"Office 2007/2010 (SHA-1) / 2013 (SHA-512), with AES"
#define FORMAT_NAME		"Office 2007 SHA-1 AES"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	19 /* Keeps first SHA-1 in one block. 51 is max for two blocks. */
#define UNICODE_LENGTH		((PLAINTEXT_LENGTH + 1) * 2) /* Including 0x0080 */
#define BINARY_SIZE		0
#define SALT_LENGTH		16
#define SALT_SIZE		sizeof(*cur_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define LWS_CONFIG		"office_LWS"
#define GWS_CONFIG		"office_GWS"
#define DUR_CONFIG		"office_MaxDuration"

#ifdef DEBUG
/* Non-blocking requests may postpone errors, causing confusion */
#define BLOCK_IF_DEBUG	CL_TRUE
#else
#define BLOCK_IF_DEBUG	CL_FALSE
#endif

/*
 * MBPr CPU       OMP-CPU  OCL-CPU   GT650M
 * 2007 156 c/s            406 c/s   2068 c/s
 * 2010 39 c/s
 * 2013 12.4 c/s
 */
static struct fmt_tests tests[] = {
	{"$office$*2007*20*128*16*8b2c9e8c878844fc842012273be4bea8*aa862168b80d8c45c852696a8bb499eb*a413507fabe2d87606595f987f679ff4b5b4c2cd", "Password"},
#if 0 /* These are length 24 */
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
#endif
	{NULL}
};

static struct custom_salt {
	char unsigned osalt[SALT_LENGTH];
	char unsigned encryptedVerifier[16];
	char unsigned encryptedVerifierHash[32];
	int version;
	int verifierHashSize;
	int keySize;
	int saltSize;
	/* Office 2010/2013 */
	//int spinCount;
} *cur_salt;

static int *cracked;

static char *saved_key;	/* Password encoded in UCS-2 */
static int *saved_len;	/* UCS-2 password length, in octets */
static char *saved_salt;
static unsigned char *key;	/* Output key from kernel */
static int new_keys;

static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_key;

/* Office 2010/2013 */
//static const unsigned char encryptedVerifierHashInputBlockKey[] = { 0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79 };
//static const unsigned char encryptedVerifierHashValueBlockKey[] = { 0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e };

static void create_clobj(int gws)
{
	int i;
	int bench_len = strlen(tests[0].plaintext) * 2;

	global_work_size = gws;
#ifdef DEBUG
	fprintf(stderr, "Creating %d bytes of key buffer\n", UNICODE_LENGTH * gws);
#endif
	cl_saved_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, UNICODE_LENGTH * gws, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_key = (char*)clEnqueueMapBuffer(queue[ocl_gpu_id], cl_saved_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, UNICODE_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_key");
	memset(saved_key, 0, UNICODE_LENGTH * gws);

#ifdef DEBUG
	fprintf(stderr, "Creating %lu bytes of key_len buffer\n", sizeof(cl_int) * gws);
#endif
	cl_saved_len = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_len = (int*)clEnqueueMapBuffer(queue[ocl_gpu_id], cl_saved_len, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_int) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_len");
	for (i = 0; i < gws; i++)
		saved_len[i] = bench_len;

#ifdef DEBUG
	fprintf(stderr, "Creating 16 bytes of salt buffer\n");
#endif
	cl_salt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, SALT_LENGTH, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_salt = (char*) clEnqueueMapBuffer(queue[ocl_gpu_id], cl_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, SALT_LENGTH, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_salt");
	memset(saved_salt, 0, SALT_LENGTH);

#ifdef DEBUG
	fprintf(stderr, "Creating %d bytes output key buffer\n", 16 * gws);
#endif
	cl_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	key = (unsigned char*) clEnqueueMapBuffer(queue[ocl_gpu_id], cl_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * 4 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory key");
	memset(key, 0, 16 * gws);

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void*)&cl_key), "Error setting argument 3");
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_key, key, 0, NULL, NULL), "Error Unmapping key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
	key = NULL; saved_key = NULL; saved_len = NULL; saved_salt = NULL;
}

static void set_key(char *key, int index)
{
	UTF16 *utfkey = (UTF16*)&saved_key[index * UNICODE_LENGTH];

	//printf("set_key(%u): '%s'\n", index, key);
	/* Clean slate */
	memset(utfkey, 0, UNICODE_LENGTH);

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

static cl_ulong gws_test(int gws)
{
	cl_ulong startTime, endTime, run_time;
	cl_command_queue queue_prof;
	cl_event myEvent;
	cl_int ret_code;
	int i;
	int num = gws;

	create_clobj(gws);
	queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i = 0; i < num; i++)
		set_key(tests[0].plaintext, i);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_salt, BLOCK_IF_DEBUG, 0, SALT_LENGTH, saved_salt, 0, NULL, NULL), "Failed transferring salt");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_saved_key, BLOCK_IF_DEBUG, 0, UNICODE_LENGTH * num, saved_key, 0, NULL, NULL), "Failed transferring keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_saved_len, BLOCK_IF_DEBUG, 0, sizeof(int) * num, saved_len, 0, NULL, NULL), "Failed transferring lengths");
	ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &myEvent);
	if (ret_code != CL_SUCCESS) {
		fprintf(stderr, "Error: %s\n", get_error_name(ret_code));
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}
	HANDLE_CLERROR(clFinish(queue_prof), "Failed running kernel");
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL);
	run_time = endTime - startTime;
	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, cl_key, CL_TRUE, 0, 16 * num, key, 0, NULL, &myEvent), "Failed reading key back");
	HANDLE_CLERROR(clFinish(queue_prof), "Failed reading results back");
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL);
	clReleaseCommandQueue(queue_prof);
	release_clobj();

	return (run_time + endTime - startTime);
}

static void find_best_gws(int do_benchmark)
{
	int num;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	unsigned int SHAspeed, bestSHAspeed = 0;
	int optimal_gws = local_work_size;
	const int sha1perkey = 50004;
	char *conf;
	unsigned long long int MaxRunTime = 5000000000ULL;

	if ((conf = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, DUR_CONFIG)))
		MaxRunTime = atoi(conf) * 1000000000UL;

#ifndef DEBUG
	if (do_benchmark)
#endif
	{
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size; num; num *= 2) {
		if (!(run_time = gws_test(num)))
			break;

		SHAspeed = sha1perkey * (1000000000UL * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

#ifndef DEBUG
		if (do_benchmark)
#endif
		fprintf(stderr, "gws %6d\t%4llu c/s%14u sha1/s%8.3f sec per crypt_all()", num, (1000000000ULL * num / run_time), SHAspeed, (float)run_time / 1000000000.);

		if (((float)run_time / (float)min_time) < ((float)SHAspeed / (float)bestSHAspeed)) {
#ifndef DEBUG
			if (do_benchmark)
#endif
				fprintf(stderr, "!\n");
			bestSHAspeed = SHAspeed;
			optimal_gws = num;
		} else {

			if (run_time > MaxRunTime) {
#ifndef DEBUG
				if (do_benchmark)
#endif
					fprintf(stderr, "\n");
				break;
			}

			if (SHAspeed > bestSHAspeed) {
#ifndef DEBUG
				if (do_benchmark)
#endif
					fprintf(stderr, "+");
				bestSHAspeed = SHAspeed;
				optimal_gws = num;
			}
#ifndef DEBUG
			if (do_benchmark)
#endif
				fprintf(stderr, "\n");
		}
	}
	if (get_device_type(ocl_gpu_id) != CL_DEVICE_TYPE_CPU) {
		fprintf(stderr, "Optimal keys per crypt %d\n",(int)optimal_gws);
		fprintf(stderr, "(to avoid this test on next run, put \""
		        GWS_CONFIG " = %d\" in john.conf, section ["
		        SECTION_OPTIONS
		        SUBSECTION_OPENCL "])\n", (int)optimal_gws);
	}
	global_work_size = optimal_gws;
}

static void init(struct fmt_main *self)
{
	char *temp;
	cl_ulong maxsize;

	global_work_size = 0;

	opencl_init("$JOHN/office_kernel.cl", ocl_gpu_id, platform_id);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "Generate2007key", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(temp);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, GWS_CONFIG)))
		global_work_size = atoi(temp);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);

	/* Note: we ask for this kernel's max size, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");

#ifdef DEBUG
	fprintf(stderr, "Max allowed local work size %d\n", (int)maxsize);
#endif

	if (!local_work_size) {
		if (get_device_type(ocl_gpu_id) == CL_DEVICE_TYPE_CPU) {
			if (get_platform_vendor_id(platform_id) == INTEL)
				local_work_size = 8;
			else
				local_work_size = 1;
		} else {
			local_work_size = 64;
		}
	}

	if (local_work_size > maxsize) {
		fprintf(stderr, "LWS %d is too large for this GPU. Max allowed is %d, using that.\n", (int)local_work_size, (int)maxsize);
		local_work_size = maxsize;
	}

	if (!global_work_size)
		find_best_gws(temp == NULL ? 0 : 1);

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);

	create_clobj(global_work_size);

#ifdef DEBUG
	{
		cl_ulong loc_mem_size;
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_LOCAL_MEM_SIZE, sizeof(loc_mem_size), &loc_mem_size, NULL), "Query local memory usage");
		fprintf(stderr, "Kernel using %lu bytes of local memory out of %lu available\n", loc_mem_size, get_local_memory_size(ocl_gpu_id));
	}
#endif

	atexit(release_clobj);

	self->params.min_keys_per_crypt =
		self->params.max_keys_per_crypt =
		global_work_size;

	cracked = mem_calloc_tiny(sizeof(*cracked) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	if (options.utf8)
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$office$*2007*", 14);
}

static void *get_salt(char *ciphertext)
{
	int i, length;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy, *p;
	ctcopy += 9;	/* skip over "$office$*" */
	cur_salt = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtok(ctcopy, "*");
	cur_salt->version = atoi(p);
	p = strtok(NULL, "*");
	if(cur_salt->version == 2007) {
		cur_salt->verifierHashSize = atoi(p);
	}
	p = strtok(NULL, "*");
	cur_salt->keySize = atoi(p);
	p = strtok(NULL, "*");
	cur_salt->saltSize = atoi(p);
	if (cur_salt->saltSize > SALT_LENGTH) {
		fprintf(stderr, "** error: salt longer than supported:\n%s\n", ciphertext);
		cur_salt->saltSize = SALT_LENGTH; /* will not work, but protects us from segfault */
	}
	p = strtok(NULL, "*");
	for (i = 0; i < cur_salt->saltSize; i++)
		cur_salt->osalt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		cur_salt->encryptedVerifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	length = strlen(p) / 2;
	for (i = 0; i < length; i++)
		cur_salt->encryptedVerifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cur_salt;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy(saved_salt, cur_salt->osalt, SALT_LENGTH);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_salt, BLOCK_IF_DEBUG, 0, SALT_LENGTH, saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_salt");
}

static int PasswordVerifier(unsigned char *key)
{
	unsigned char decryptedVerifier[16];
	AES_KEY akey;
	SHA_CTX ctx;
	unsigned char checkHash[20];
	unsigned char decryptedVerifierHash[32];

	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed!\n");
		return 0;
	}
	AES_ecb_encrypt(cur_salt->encryptedVerifier, decryptedVerifier, &akey, AES_DECRYPT);
	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed!\n");
		return 0;
	}
	AES_ecb_encrypt(cur_salt->encryptedVerifierHash, decryptedVerifierHash, &akey, AES_DECRYPT);
	AES_ecb_encrypt(cur_salt->encryptedVerifierHash+16, decryptedVerifierHash+16, &akey, AES_DECRYPT);

	/* find SHA1 hash of decryptedVerifier */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decryptedVerifier, 16);
	SHA1_Final(checkHash, &ctx);

	return !memcmp(checkHash, decryptedVerifierHash, 16);
}

static void crypt_all(int count)
{
	int index;

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, BLOCK_IF_DEBUG, 0, UNICODE_LENGTH * global_work_size, saved_key, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_key");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_len, BLOCK_IF_DEBUG, 0, sizeof(int) * global_work_size, saved_len, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_len");
		new_keys = 0;
	}
#ifdef DEBUG
	fprintf(stderr, "GPU: lws %d gws %d count %d\n", (int)local_work_size, (int)global_work_size, count);
#endif
	//if(cur_salt->version == 2007) {
		//unsigned char encryptionKey[256];
		//GeneratePasswordHashUsingSHA1(saved_key, saved_len, encryptionKey);

		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
#ifdef DEBUG
		HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Failed running kernel");
#endif
		// read back aes key
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_key, CL_TRUE, 0, 16 * global_work_size, key, 0, NULL, NULL), "failed in reading key back");

		//dump_stuff_msg("\nsha1(salt.pw)", &key[(count-1)*16], 16);

#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (index = 0; index < count; index++)
			cracked[index] = PasswordVerifier(&key[index*16]);
	//}
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

static char *get_key(int index)
{
	static UTF8 out[PLAINTEXT_LENGTH + 1];
	utf16_to_enc_r(out, PLAINTEXT_LENGTH + 1, (UTF16*)&saved_key[index * UNICODE_LENGTH]);
	out[saved_len[index]>>1] = 0;
	return (char*)out;
}

struct fmt_main fmt_opencl_office = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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
