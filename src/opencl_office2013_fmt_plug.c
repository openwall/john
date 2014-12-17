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

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

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

static struct custom_salt {
	char unsigned osalt[SALT_LENGTH];
	char unsigned encryptedVerifier[16];
	char unsigned encryptedVerifierHash[32];
	int version;
	int spinCount;
	int keySize;
	int saltSize;
} *cur_salt;

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

#define HASH_LOOPS		100 /* Lower figure gives less X hogging */
#define ITERATIONS		100000
#define STEP			0
#define SEED			128
#define OCL_CONFIG		"office2013"

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
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64;
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

static void *get_salt(char *ciphertext)
{
	int i, length;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy, *p;

	cur_salt = mem_calloc_tiny(sizeof(struct custom_salt),
	                           MEM_ALIGN_WORD);

	ctcopy += 9;	/* skip over "$office$*" */
	p = strtok(ctcopy, "*");
	cur_salt->version = atoi(p);
	p = strtok(NULL, "*");
	cur_salt->spinCount = atoi(p);
	p = strtok(NULL, "*");
	cur_salt->keySize = atoi(p);
	p = strtok(NULL, "*");
	cur_salt->saltSize = atoi(p);
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
	spincount = cur_salt->spinCount;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, SALT_LENGTH, saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_salt");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_spincount, CL_FALSE, 0, 4, &spincount, 0, NULL, NULL), "failed in clEnqueueWriteBuffer spincount");
}

static int crypt_all(int *pcount, struct db_salt *salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *salt);

static void init(struct fmt_main *self)
{
	char build_opts[64];
	static char valgo[32] = "";

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

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
		warn, 3, self, create_clobj, release_clobj,
		UNICODE_LENGTH, 0);

	//Auto tune execution from shared/included code.
	self->methods.crypt_all = crypt_all_benchmark;
	autotune_run(self, ITERATIONS + 4, 0,
	             (cpu(device_info[gpu_id]) ? 1000000000 : 10000000000ULL));
	self->methods.crypt_all = crypt_all;

	self->params.min_keys_per_crypt = local_work_size * v_width;
	self->params.max_keys_per_crypt = global_work_size * v_width;

	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static int ishex(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int res;

	if (strncmp(ciphertext, "$office$*2013*", 14))
		return 0;
	if (!(ctcopy = strdup(ciphertext))) {
		fprintf(stderr, "Memory allocation failed in %s, unable to check if hash is valid!", FORMAT_LABEL);
		return 0;
	}
	keeptr = ctcopy;
	ctcopy += 15;
	if (!(ptr = strtok(ctcopy, "*"))) /* hash size or iterations */
		goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (strncmp(ptr, "128", 3) && strncmp(ptr, "256", 3)) /* key size */
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* salt size */
		goto error;
	res = atoi(ptr);
	if (res != 16) /* can we handle other values? */
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* salt */
		goto error;
	if (strlen(ptr) != res * 2)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* encrypted verifier */
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* encrypted verifier hash */
		goto error;
	if (!ishex(ptr))
		goto error;
	if (strlen(ptr) > 64)
		goto error;
	if ((ptr = strtok(NULL, "*")))
		goto error;

	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
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

		DecryptUsingSymmetricKeyAlgorithm(&key[128*index], cur_salt->encryptedVerifier, decryptedVerifierHashInputBytes, 16);
		DecryptUsingSymmetricKeyAlgorithm(&key[128*index+64], cur_salt->encryptedVerifierHash, decryptedVerifierHashBytes, 32);
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

	gws = ((count + (v_width * local_work_size - 1)) / (v_width * local_work_size)) * local_work_size;
	scalar_gws = gws * v_width;

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, 0, UNICODE_LENGTH * scalar_gws, saved_key, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer saved_key");
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, CL_FALSE, 0, sizeof(int) * scalar_gws, saved_len, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer saved_len");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], GenerateSHA512pwhash, 1, NULL, &scalar_gws, &local_work_size, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, &local_work_size, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], Generate2013key, 1, NULL, &gws, &local_work_size, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueNDRangeKernel");

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

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
        /*
	 * Is spinCount always 100000, or just in our format tests?
	 */
	return (unsigned int) my_salt->spinCount;
}
#endif

struct fmt_main fmt_opencl_office2013 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
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
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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
