/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for StarOffice format.
 *
 * This software is Copyright (c) 2012 Dhiru Kholia, Copyright (c) 2012 Lukas
 * Odzioba <ukasz@openwall.net> and it is hereby released to the general public
 * under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_sxc;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_sxc);
#else

#include <string.h>
#include <stdint.h>
#include <openssl/blowfish.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha.h"
#include "aes.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "options.h"
#include "staroffice_common.h"
#define OPENCL_FORMAT
#include "pbkdf2_hmac_sha1.h"
#include "common-opencl.h"

#define FORMAT_LABEL            "sxc-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA1 OpenCL Blowfish"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
// keep plaintext length under 52 bytes to avoid SHA1 bug from Star/Libre office
#define PLAINTEXT_LENGTH        51
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_ALIGN              4

typedef struct {
	uint32_t length;
	uint8_t v[20];	// hash of password
} sxc_password;

typedef struct {
	uint32_t v[16/4];
} sxc_hash;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  length;
	uint8_t  salt[64];
} sxc_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[32 / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

static cl_int cl_error;
static sxc_password *inbuffer;
static sxc_hash *outbuffer;
static sxc_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;

static size_t insize, outsize, settingsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(sxc_password) * gws;
	outsize = sizeof(sxc_hash) * gws;
	settingsize = sizeof(sxc_salt);

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	saved_key = mem_calloc(gws, sizeof(*saved_key));
	crypt_out = mem_calloc(gws, sizeof(*crypt_out));

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(saved_key);
		MEM_FREE(crypt_out);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
		         (int)sizeof(inbuffer->v),
		         (int)sizeof(currentsalt.salt),
		         (int)sizeof(outbuffer->v));
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_unsplit_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "derive_key", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1,
		                       self, create_clobj, release_clobj,
		                       sizeof(sxc_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->salt_length);
	currentsalt.length = cur_salt->salt_length;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.outlen = cur_salt->key_size;
	currentsalt.skip_bytes = 0;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy salt to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char hash[20];
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
		SHA1_Final((unsigned char *)hash, &ctx);
		memcpy(inbuffer[index].v, hash, 20);
		inbuffer[index].length = 20;
	}

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
	        "Copy data to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
	        multi_profilingEvent[1]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]), "Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		BF_KEY bf_key;
		SHA_CTX ctx;
		int bf_ivec_pos;
		unsigned char ivec[8];
		unsigned char output[1024];
		unsigned int crypt[5];

		bf_ivec_pos = 0;
		memcpy(ivec, cur_salt->iv, 8);
		BF_set_key(&bf_key, cur_salt->key_size, (const unsigned char*)outbuffer[index].v);
		BF_cfb64_encrypt(cur_salt->content, output, cur_salt->length, &bf_key, ivec, &bf_ivec_pos, 0);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, output, cur_salt->original_length);
		SHA1_Final((unsigned char*)crypt, &ctx);
		crypt_out[index][0] = crypt[0];
		if (cur_salt->original_length % 64 >= 52 && cur_salt->original_length % 64 <= 55) {
			SHA1_Libre_Buggy(output, cur_salt->original_length, crypt);
		}
		crypt_out[index][1] = crypt[0];
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++) {
		if (!memcmp(binary, crypt_out[index], 4))
			return 1;
		if (!memcmp(binary, &crypt_out[index][1], 4))
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (!memcmp(binary, crypt_out[index], 4))
		return 1;
	if (!memcmp(binary, &crypt_out[index][1], 4))
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	unsigned char key[32];
	unsigned char hash[20];
	unsigned char *binary;
	BF_KEY bf_key;
	int bf_ivec_pos;
	unsigned char ivec[8];
	unsigned char output[1024];
	unsigned int crypt[5];
	SHA_CTX ctx;

	binary = staroffice_get_binary(source);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
	SHA1_Final(hash, &ctx);
	pbkdf2_sha1(hash, 20, cur_salt->salt,
		       cur_salt->salt_length,
		       cur_salt->iterations, key,
		       cur_salt->key_size, 0);
	bf_ivec_pos = 0;
	memcpy(ivec, cur_salt->iv, 8);
	BF_set_key(&bf_key, cur_salt->key_size, key);
	BF_cfb64_encrypt(cur_salt->content, output, cur_salt->length, &bf_key, ivec, &bf_ivec_pos, 0);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, output, cur_salt->original_length);
	SHA1_Final((unsigned char*)crypt, &ctx);
	if (!memcmp(crypt, binary, 20))
		return 1;
	// try the buggy version.
	if (cur_salt->original_length % 64 >= 52 && cur_salt->original_length % 64 <= 55) {
		SHA1_Libre_Buggy(output, cur_salt->original_length, crypt);
		if (!memcmp(crypt, binary, 20))
			return 1;
	}
	return 0;
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}

struct fmt_main fmt_opencl_sxc = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		staroffice_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		staroffice_valid,
		fmt_default_split,
		staroffice_get_binary,
		staroffice_get_salt,
		{
			iteration_count,
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
