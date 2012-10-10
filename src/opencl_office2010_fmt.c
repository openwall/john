/* Office 2010 cracker patch for JtR. Hacked together during March of 2012 by
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

#define PLAINTEXT_LENGTH	51
#define UNICODE_LENGTH		104 /* In octets, including 0x80 */
#define HASH_LOOPS		256 /* Lower figure gives less X hogging */

#define FORMAT_LABEL		"office2010-opencl"
#define FORMAT_NAME		"Office 2010 SHA-1 AES"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	" (100,000 iterations)"
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define SALT_LENGTH		16
#define SALT_SIZE		sizeof(*cur_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define LWS_CONFIG		"office2010_LWS"
#define GWS_CONFIG		"office2010_GWS"

#define MIN(a, b)		(a > b) ? (b) : (a)
#define MAX(a, b)		(a > b) ? (a) : (b)

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

static struct custom_salt {
	char unsigned osalt[SALT_LENGTH];
	char unsigned encryptedVerifier[16];
	char unsigned encryptedVerifierHash[32];
	int version;
	int spinCount;
	int keySize;
	int saltSize;
} *cur_salt;

static int *cracked;
static int VF = 1;	/* Will be set to 4 when we run vectorized */

static char *saved_key;	/* Password encoded in UCS-2 */
static int *saved_len;	/* UCS-2 password length, in octets */
static char *saved_salt;
static unsigned char *key;	/* Output key from kernel */
static int new_keys, *spincount;

static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_pwhash, cl_key, cl_spincount;
static cl_kernel GenerateSHA1pwhash, Generate2010key;

static void create_clobj(int gws, struct fmt_main *self)
{
	int i;
	int bench_len = strlen(tests[0].plaintext) * 2;

	global_work_size = gws;
	gws *= VF;
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;
	cl_saved_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, UNICODE_LENGTH * gws, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_key = (char*)clEnqueueMapBuffer(queue[ocl_gpu_id], cl_saved_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, UNICODE_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_key");
	memset(saved_key, 0, UNICODE_LENGTH * gws);

	cl_saved_len = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_len = (int*)clEnqueueMapBuffer(queue[ocl_gpu_id], cl_saved_len, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_int) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_len");
	for (i = 0; i < gws; i++)
		saved_len[i] = bench_len;

	cl_salt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, SALT_LENGTH, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_salt = (char*) clEnqueueMapBuffer(queue[ocl_gpu_id], cl_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, SALT_LENGTH, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_salt");
	memset(saved_salt, 0, SALT_LENGTH);

	cl_pwhash = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, sizeof(cl_uint) * 6 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");

	cl_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 32 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	key = (unsigned char*) clEnqueueMapBuffer(queue[ocl_gpu_id], cl_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 32 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory verifier keys");
	memset(key, 0, 32 * gws);

	cl_spincount = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	spincount = (int*) clEnqueueMapBuffer(queue[ocl_gpu_id], cl_spincount, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_int), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory spincount");
	memset(spincount, 0, sizeof(cl_int));

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
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_spincount, spincount, 0, NULL, NULL), "Error Unmapping spincount");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_key, key, 0, NULL, NULL), "Error Unmapping key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
	spincount = NULL; key = NULL; saved_key = NULL; saved_len = NULL; saved_salt = NULL;
	MEM_FREE(cracked);
}

static void set_key(char *key, int index)
{
	UTF16 *utfkey = (UTF16*)&saved_key[index * UNICODE_LENGTH];

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
	cur_salt->spinCount = atoi(p);
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
	*spincount = cur_salt->spinCount;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_salt, CL_FALSE, 0, SALT_LENGTH, saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_salt");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_spincount, CL_FALSE, 0, 4, spincount, 0, NULL, NULL), "failed in clEnqueueWriteBuffer spincount");
}

static cl_ulong gws_test(int gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_command_queue queue_prof;
	cl_event Event[6];
	cl_int ret_code;
	int i;
	size_t scalar_gws = VF * gws;

	create_clobj(gws, self);
	queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i = 0; i < scalar_gws; i++)
		set_key(tests[0].plaintext, i);
	set_salt(get_salt(tests[0].ciphertext));

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_saved_key, CL_TRUE, 0, UNICODE_LENGTH * scalar_gws, saved_key, 0, NULL, &Event[0]), "Failed transferring keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_saved_len, CL_TRUE, 0, sizeof(int) * scalar_gws, saved_len, 0, NULL, &Event[1]), "Failed transferring lengths");

	ret_code = clEnqueueNDRangeKernel(queue_prof, GenerateSHA1pwhash, 1, NULL, &scalar_gws, &local_work_size, 0, NULL, &Event[2]);
	if (ret_code != CL_SUCCESS) {
		fprintf(stderr, "Error: %s\n", get_error_name(ret_code));
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

	for (i = 0; i < *spincount / HASH_LOOPS - 1; i++) {
		ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL);
		if (ret_code != CL_SUCCESS) {
			fprintf(stderr, "Error: %s\n", get_error_name(ret_code));
			clReleaseCommandQueue(queue_prof);
			release_clobj();
			return 0;
		}
	}
	ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[3]);

	ret_code = clEnqueueNDRangeKernel(queue_prof, Generate2010key, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[4]);
	if (ret_code != CL_SUCCESS) {
		fprintf(stderr, "Error: %s\n", get_error_name(ret_code));
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, cl_key, CL_TRUE, 0, 32 * scalar_gws, key, 0, NULL, &Event[5]), "failed in reading key back");

#if 0
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
			CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
			NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
			CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
			NULL), "Failed to get profiling info");
	fprintf(stderr, "GenerateSHA1pwhash kernel duration: %llu us, ", (endTime-startTime)/1000ULL);
#endif

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
			CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
			NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
			CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
			NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "%.2f ms x %u = %.2f s\t", (float)((endTime - startTime)/1000000.), *spincount/HASH_LOOPS, (float)(*spincount/HASH_LOOPS) * (endTime - startTime) / 1000000000.);

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "- exceeds 200 ms\n");
		return 0;
	}

#if 0
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[4],
			CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
			NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[4],
			CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
			NULL), "Failed to get profiling info");
	fprintf(stderr, "Generate2010key kernel duration: %llu us\n", (endTime-startTime)/1000ULL);
#endif

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
			CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
			NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[5],
			CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
			NULL), "Failed to get profiling info");
	clReleaseCommandQueue(queue_prof);
	release_clobj();

	return (endTime - startTime);
}

static void find_best_gws(int do_benchmark, struct fmt_main *self)
{
	int num;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	unsigned int SHAspeed, bestSHAspeed = 0;
	int optimal_gws = local_work_size;
	int sha1perkey;
	unsigned long long int MaxRunTime = 5000000000ULL;

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size; num; num *= 2) {
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		sha1perkey = cur_salt->spinCount + 4;
		SHAspeed = sha1perkey * (1000000000UL * VF * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d%8llu c/s%14u sha1/s%8.3f sec per crypt_all()", num, (1000000000ULL * VF * num / run_time), SHAspeed, (float)run_time / 1000000000.);

		if (((float)run_time / (float)min_time) < ((float)SHAspeed / (float)bestSHAspeed)) {
			if (do_benchmark)
				fprintf(stderr, "!\n");
			bestSHAspeed = SHAspeed;
			optimal_gws = num;
		} else {
			if (run_time < MaxRunTime && SHAspeed > (bestSHAspeed * 1.01)) {
				if (do_benchmark)
					fprintf(stderr, "+\n");
				bestSHAspeed = SHAspeed;
				optimal_gws = num;
				continue;
			}
			if (do_benchmark)
				fprintf(stderr, "\n");
			if (run_time >= MaxRunTime)
				break;
		}
	}
	global_work_size = optimal_gws;
}

static void init(struct fmt_main *self)
{
	char *temp;
	cl_ulong maxsize, maxsize2;
	char build_opts[64];

	global_work_size = 0;

	snprintf(build_opts, sizeof(build_opts), "-DHASH_LOOPS=%u -DUNICODE_LENGTH=%u", HASH_LOOPS, UNICODE_LENGTH);
	opencl_init_opt("$JOHN/office2010_kernel.cl", ocl_gpu_id, platform_id, build_opts);

	// create kernel to execute
	GenerateSHA1pwhash = clCreateKernel(program[ocl_gpu_id], "GenerateSHA1pwhash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "HashLoop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	Generate2010key = clCreateKernel(program[ocl_gpu_id], "Generate2010key", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	if (gpu_nvidia(device_info[ocl_gpu_id]) || amd_gcn(device_info[ocl_gpu_id])) {
		/* Run scalar code */
		VF = 1;
	} else {
		/* Run vectorized code */
		VF = 4;
		self->params.algorithm_name = "OpenCL 4x";
	}

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(temp);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, GWS_CONFIG)))
		global_work_size = atoi(temp);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(GenerateSHA1pwhash, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(Generate2010key, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;

#if 0
	/* Our use of local memory sets a limit for LWS */
	maxsize2 = get_local_memory_size(ocl_gpu_id) / (24 * VF);
	while (maxsize > maxsize2)
		maxsize >>= 1;
#endif

	/* maxsize is the lowest figure from the three different kernels */
	if (!local_work_size) {
		if (getenv("LWS")) {
			/* LWS was explicitly set to 0 */
			int temp = global_work_size;
			local_work_size = maxsize;
			global_work_size = global_work_size ? global_work_size : 4 * maxsize;
			create_clobj(global_work_size, self);
			opencl_find_best_workgroup_limit(self, maxsize);
			release_clobj();
			global_work_size = temp;
		} else {
			if (cpu(device_info[ocl_gpu_id])) {
				if (get_platform_vendor_id(platform_id) == DEV_INTEL)
					local_work_size = MIN(maxsize, 8);
				else
					local_work_size = 1;
			} else
				local_work_size = MIN(maxsize, 64);
		}
	}

	if (local_work_size > maxsize) {
		fprintf(stderr, "LWS %d is too large for this GPU. Max allowed is %d, using that.\n", (int)local_work_size, (int)maxsize);
		local_work_size = maxsize;
	}

	if (!global_work_size)
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
	create_clobj(global_work_size, self);
	atexit(release_clobj);

	if (options.utf8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$office$*2010", 13);
}

static void DecryptUsingSymmetricKeyAlgorithm(unsigned char *verifierInputKey, unsigned char *encryptedVerifier, const unsigned char *decryptedVerifier, int length)
{
	unsigned char iv[32];
	AES_KEY akey;
	memcpy(iv, cur_salt->osalt, 16);
	memset(&iv[16], 0, 16);
	memset(&akey, 0, sizeof(AES_KEY));
	if(cur_salt->keySize == 128) {
		if(AES_set_decrypt_key(verifierInputKey, 128, &akey) < 0) {
			fprintf(stderr, "AES_set_decrypt_key failed!\n");
		}
	}
	else {
		if(AES_set_decrypt_key(verifierInputKey, 256, &akey) < 0) {
			fprintf(stderr, "AES_set_decrypt_key failed!\n");
		}
	}
	AES_cbc_encrypt(encryptedVerifier, (unsigned char*)decryptedVerifier, length, &akey, iv, AES_DECRYPT);
}

static void crypt_all(int count)
{
	int index;
	size_t scalar_gws = VF * global_work_size;

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * VF * global_work_size, saved_key, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_key");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * VF * global_work_size, saved_len, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_len");
		new_keys = 0;
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], GenerateSHA1pwhash, 1, NULL, &scalar_gws, &local_work_size, 0, NULL, firstEvent), "failed in clEnqueueNDRangeKernel");

	for (index = 0; index < *spincount / HASH_LOOPS; index++)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], Generate2010key, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "failed in clEnqueueNDRangeKernel");

	// read back verifier keys
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_key, CL_TRUE, 0, 32 * VF * global_work_size, key, 0, NULL, NULL), "failed in reading key back");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA_CTX ctx;
		unsigned char hash[20];
		unsigned char decryptedVerifierHashInputBytes[16], decryptedVerifierHashBytes[32];
		DecryptUsingSymmetricKeyAlgorithm(&key[32*index], cur_salt->encryptedVerifier, decryptedVerifierHashInputBytes, 16);
		DecryptUsingSymmetricKeyAlgorithm(&key[32*index+16], cur_salt->encryptedVerifierHash, decryptedVerifierHashBytes, 32);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, decryptedVerifierHashInputBytes, 16);
		SHA1_Final(hash, &ctx);
		cracked[index] = !memcmp(hash, decryptedVerifierHashBytes, 20);
	}
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

struct fmt_main fmt_opencl_office2010 = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP,
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
