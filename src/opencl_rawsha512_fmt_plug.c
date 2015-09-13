/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Note: using myrice idea.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rawsha512;
extern struct fmt_main fmt_opencl_xsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rawsha512);
john_register_one(&fmt_opencl_xsha512);
#else

#include <string.h>

#include "sha.h"
#include "sha2.h"
#include "johnswap.h"
#include "common-opencl.h"
#include "config.h"
#include "options.h"
#include "opencl_rawsha512.h"
#define __RAWSHA512_CREATE_PROPER_TESTS_ARRAY__
#define __XSHA512_CREATE_PROPER_TESTS_ARRAY__
#include "rawSHA512_common.h"

//Copied from the past.
#define BINARY_SIZE		64
#define SHORT_BINARY_SIZE	4
#define SALT_SIZE_RAW           0
#define SALT_SIZE_X             4
#define SALT_ALIGN_RAW          1
#define SALT_ALIGN_X            4

#define FORMAT_LABEL			"Raw-SHA512-opencl"
#define FORMAT_NAME			""

#define X_FORMAT_LABEL			"XSHA512-opencl"
#define X_FORMAT_NAME			"Mac OS X 10.7 salted"

#define ALGORITHM_NAME			"SHA512 OpenCL (inefficient, development use mostly)"

static sha512_salt			* salt;
static uint32_t				* plaintext, * saved_idx;	// plaintext ciphertexts
static uint32_t				* calculated_hash;		// calculated (partial) hashes

static cl_mem salt_buffer;		//Salt information.
static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem hash_buffer;		//Partial hash keys (output).
static cl_mem idx_buffer;		//Sizes and offsets buffer.
static cl_mem p_binary_buffer;		//To compare partial binary ([3]).
static cl_mem result_buffer;		//To get the if a hash was found.
static cl_mem pinned_saved_keys, pinned_saved_idx, pinned_partial_hashes;
static struct fmt_main *self;

static cl_kernel cmp_kernel;
static int new_keys, hash_found, salted_format = 0;
static uint32_t key_idx = 0;
static size_t offset = 0, offset_idx = 0;

#define _RAWSHA512_H
#define _XSHA512_H
#include "rawSHA512_common.h"
#undef _RAWSHA512_H
#undef _XSHA512_H

//This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	return MIN(s, 512);
}

static void crypt_one(int index, sha512_hash * hash) {
	SHA512_CTX ctx;

	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, key, len);
	SHA512_Final((unsigned char *) (hash), &ctx);
}

static void crypt_one_x(int index, sha512_hash * hash) {
	SHA512_CTX ctx;

	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, (char *) &salt->salt, SALT_SIZE_X);
	SHA512_Update(&ctx, key, len);
	SHA512_Final((unsigned char *) (hash), &ctx);
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main * self)
{
	int position = 0;

	pinned_saved_keys = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	plaintext = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_keys, CL_TRUE, CL_MAP_WRITE, 0,
			BUFFER_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory plaintext");

	pinned_saved_idx = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");

	saved_idx = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_idx, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id],
			CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

	// create arguments (buffers)
	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha512_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument pass_buffer");

	idx_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
		sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument idx_buffer");

	hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument hash_buffer");

	p_binary_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(uint32_t), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument p_binary_buffer");

	result_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
			sizeof(int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument result_buffer");

	//Set kernel arguments
	if (salted_format) {
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &salt_buffer), "Error setting argument 0");
	}
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument p0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &idx_buffer), "Error setting argument p1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, position++, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument p2");

	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 0, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 1, sizeof(cl_mem),
			(void *) &p_binary_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 2, sizeof(cl_mem),
			(void *) &result_buffer), "Error setting argument 2");

	memset(plaintext, '\0', BUFFER_SIZE * gws);
	memset(saved_idx, '\0', sizeof(uint32_t) * gws);
}

static void release_clobj(void) {
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
			plaintext, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping keys");
	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx,
			saved_idx, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping indexes");
	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
			calculated_hash, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping partial hashes");
	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	               "Error releasing memory mappings");

	ret_code = clReleaseMemObject(salt_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing salt_buffer");
	ret_code = clReleaseMemObject(pass_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
	ret_code = clReleaseMemObject(hash_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing hash_buffer");
	ret_code = clReleaseMemObject(idx_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing idx_buffer");

	ret_code = clReleaseMemObject(p_binary_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing p_binary_buffer");
	ret_code = clReleaseMemObject(result_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing result_buffer");

	ret_code = clReleaseMemObject(pinned_saved_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
	ret_code = clReleaseMemObject(pinned_saved_idx);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_idx");
	ret_code = clReleaseMemObject(pinned_partial_hashes);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Salt functions ------- */
static void * get_salt(char *ciphertext) {
	static union {
		unsigned char c[SALT_SIZE_X];
		ARCH_WORD dummy;
	} out;
	char *p;
	int i;

	ciphertext += 6;
	p = ciphertext;
	for (i = 0; i < sizeof (out.c); i++) {
		out.c[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out.c;
}

static void set_salt(void * salt_info) {

	salt = salt_info;

	//Send salt information to GPU.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0,
		sizeof(sha512_salt), salt, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer salt_buffer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static int salt_hash(void * salt) {

	return common_salt_hash(salt, SALT_SIZE_X, SALT_HASH_SIZE);
}

static void clear_keys(void) {
	offset = 0;
	offset_idx = 0;
	key_idx = 0;
}

static void set_key(char * _key, int index) {

	const ARCH_WORD_32 * key = (ARCH_WORD_32 *) _key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		plaintext[key_idx++] = *key++;
		len -= 4;
	}

	if (len > 0)
		plaintext[key_idx++] = *key;

	//Batch transfers to GPU.
	if ((index % TRANSFER_SIZE) == 0 && (index > 0)) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			plaintext + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer pass_buffer");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			saved_idx + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer idx_buffer");

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		offset += TRANSFER_SIZE;
		offset_idx = key_idx;
	}
	new_keys = 1;
}

static char * get_key(int index) {
	static char * ret;
	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	if (!ret) ret = mem_alloc_tiny(PLAINTEXT_LENGTH + 1, MEM_ALIGN_WORD);

	memcpy(ret, key, PLAINTEXT_LENGTH);
	ret[len] = '\0';

	return ret;
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *_self) {

	self = _self;
}

/* ------- Key functions ------- */
static void reset(struct db_main *db) {
	offset = 0;
	offset_idx = 0;
	key_idx = 0;

	if (!autotuned) {
            	char * task = "$JOHN/kernels/sha512_kernel.cl";
		size_t gws_limit;

                opencl_prepare_dev(gpu_id);
                opencl_build_kernel(task, gpu_id, NULL, 1);

                // create kernel(s) to execute
                if (salted_format)
                        crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt_xsha", &ret_code);
                else
                        crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt_raw", &ret_code);
                HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
                cmp_kernel = clCreateKernel(program[gpu_id], "kernel_cmp", &ret_code);
                HANDLE_CLERROR(ret_code, "Error creating kernel_cmp. Double-check kernel name?");

		gws_limit = MIN((0xf << 22) * 4 / BUFFER_SIZE,
		                get_max_mem_alloc_size(gpu_id) / BUFFER_SIZE);

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1,
		                       self, create_clobj, release_clobj,
		                       2 * BUFFER_SIZE, gws_limit);

		//Auto tune execution from shared/included code.
		autotune_run(self, 1, gws_limit, 500ULL);
	}
}

static void init_x(struct fmt_main * self) {
	salted_format = 1;
	init(self);
}

static void done(void) {

        if (autotuned) {
                release_clobj();

                HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
                HANDLE_CLERROR(clReleaseKernel(cmp_kernel), "Release kernel");
                HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

                autotuned = 0;
        }
}

/* ------- To binary functions ------- */
static void * get_short_binary(char *ciphertext) {
	static unsigned char *out;
	uint64_t * b;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	if (salted_format)
		ciphertext += 6;

	p = ciphertext + 8;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint64_t *) out;
	b[0] = SWAP64((unsigned long long) b[3]) - H3;

	return out;
}

static void * get_full_binary(char *ciphertext) {
	unsigned char * out;

	if (salted_format)
		out = sha512_common_binary_xsha(ciphertext);
	else
		out = sha512_common_binary(ciphertext);

	alter_endianity_to_BE64 (out, BINARY_SIZE/8);

	return out;
}

/* ------- Crypt function ------- */
static int crypt_all(int *pcount, struct db_salt *_salt) {
	const int count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys && key_idx > offset)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE,
			sizeof(uint32_t) * offset,
			sizeof(uint32_t) * (key_idx - offset),
			plaintext + offset, 0, NULL, multi_profilingEvent[0]),
			"failed in clEnqueueWriteBuffer pass_buffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer, CL_FALSE,
		sizeof(uint32_t) * offset,
		sizeof(uint32_t) * (gws - offset),
		saved_idx + offset, 0, NULL, multi_profilingEvent[3]),
		"failed in clEnqueueWriteBuffer idx_buffer");

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(uint32_t) * gws, calculated_hash, 0,
			NULL, multi_profilingEvent[2]),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

	return count;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
	uint32_t partial_binary;
	size_t gws;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);
	partial_binary = (int) ((uint64_t *) binary)[0];
	hash_found = 0;

	//Send data to device.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], p_binary_buffer, CL_FALSE, 0,
			sizeof(uint32_t), &partial_binary, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer p_binary_buffer");

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], cmp_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel");

	//Read results back.
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], result_buffer, CL_FALSE, 0,
			sizeof(int), &hash_found, 0, NULL, NULL),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");

	return hash_found;
}

static int cmp_one(void *binary, int index) {
	return (calculated_hash[index] == (int) ((uint64_t *) binary)[0]);
}

static int cmp_exact(char *source, int index) {
	//I don't know why, but this is called and i have to recheck.
	//If i skip this final test i get:
	//form=raw-sha512-opencl	 guesses: 1468 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]
	//.pot CHK:raw-sha512-opencl	 guesses: 1452 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]

	uint64_t * binary;
	sha512_hash full_hash;

	crypt_one(index, &full_hash);

	binary = (uint64_t *) get_full_binary(source);
	return !memcmp(binary, (void *) &full_hash, BINARY_SIZE);
}

static int cmp_exact_x(char *source, int index) {
	//I don't know why, but this is called and i have to recheck.
	//If i skip this final test i get:
	//form=raw-sha512-opencl		 guesses: 1468 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]
	//.pot CHK:raw-sha512-opencl	 guesses: 1452 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]

	uint64_t * binary;
	sha512_hash full_hash;

	crypt_one_x(index, &full_hash);

	binary = (uint64_t *) get_full_binary(source);
	return !memcmp(binary, (void *) &full_hash, BINARY_SIZE);
}

/* ------- Binary Hash functions group ------- */
#if 0
static void print_binary(void * binary) {
	uint64_t *bin = binary;
	uint64_t tmp = bin[0] + H3;
	tmp = SWAP64(tmp);

	fprintf(stderr, "%016lx ", bin[0]);
	fprintf(stderr, "%016lx \n", tmp);
	puts("(Ok)");
}

static void print_hash(int index) {
	int i;
	sha512_hash hash;
	crypt_one(index, &hash);

	fprintf(stderr, "\n");
	for (i = 0; i < 8; i++)
		fprintf(stderr, "%016lx ", hash.v[i]);
	puts("");
}
#endif

static int binary_hash_0(void * binary) {
#if 0
	print_binary(binary);
#endif
	return *(ARCH_WORD_32 *) binary & 0xF;
}

//Get Hash functions group.
static int get_hash_0(int index) {
#if 0
	print_hash(index);
#endif
	return calculated_hash[index] & 0xF;
}
static int get_hash_1(int index) { return calculated_hash[index] & 0xff; }
static int get_hash_2(int index) { return calculated_hash[index] & 0xfff; }
static int get_hash_3(int index) { return calculated_hash[index] & 0xffff; }
static int get_hash_4(int index) { return calculated_hash[index] & 0xfffff; }
static int get_hash_5(int index) { return calculated_hash[index] & 0xffffff; }
static int get_hash_6(int index) { return calculated_hash[index] & 0x7ffffff; }

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_rawsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		SHORT_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_RAW,
		SALT_ALIGN_RAW,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		sha512_common_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		sha512_common_valid,
		sha512_common_split,
		get_short_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
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

struct fmt_main fmt_opencl_xsha512 = {
	{
		X_FORMAT_LABEL,
		X_FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		XSHA512_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		SHORT_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_X,
		SALT_ALIGN_X,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		sha512_common_tests_xsha512
	}, {
		init_x,
		done,
		reset,
		sha512_common_prepare_xsha,
		sha512_common_valid_xsha,
		sha512_common_split_xsha,
		get_short_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
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
		cmp_exact_x
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
