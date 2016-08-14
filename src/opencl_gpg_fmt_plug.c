/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for GPG format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * converted to use 'common' code, Feb29-Mar1 2016, JimF.  Also, added
 * CPU handling of all 'types' which we do not yet have in GPU.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_gpg;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_gpg);
#else

#include <string.h>
#include <openssl/aes.h>
#include <assert.h>
#include <openssl/blowfish.h>
#include <openssl/ripemd.h>
#include <openssl/cast.h>
#include "idea-JtR.h"
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "md5.h"
#include "rc4.h"
#include "pdfcrack_md5.h"
#include "sha.h"
#include "common-opencl.h"
#include "options.h"
#include "sha2.h"
#include "stdint.h"
#include "gpg_common.h"

#define FORMAT_LABEL		"gpg-opencl"
#define FORMAT_NAME		"OpenPGP / GnuPG Secret Key"
#define ALGORITHM_NAME		"SHA1 OpenCL"
#define SALT_SIZE		sizeof(struct gpg_common_custom_salt)

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

extern volatile int bench_running;

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} gpg_password;

typedef struct {
	uint8_t v[32];
} gpg_hash;

typedef struct {
	uint32_t length;
	uint32_t count;
	uint32_t key_len;
	uint8_t salt[SALT_LENGTH];
} gpg_salt;

static int *cracked;
static int any_cracked;

static cl_int cl_error;
static gpg_password *inbuffer;
static gpg_hash *outbuffer;
static gpg_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;

size_t insize, outsize, settingsize, cracked_size;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
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
	insize = sizeof(gpg_password) * gws;
	outsize = sizeof(gpg_hash) * gws;
	settingsize = sizeof(gpg_salt);
	cracked_size = sizeof(*cracked) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	cracked = mem_calloc(1, cracked_size);

	/// Allocate memory
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
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
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
		         "-DPLAINTEXT_LENGTH=%d -DSALT_LENGTH=%d",
		         PLAINTEXT_LENGTH, SALT_LENGTH);
		opencl_init("$JOHN/kernels/gpg_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "gpg", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(gpg_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 300);
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

static void set_salt(void *salt)
{
	gpg_common_cur_salt = (struct gpg_common_custom_salt *)salt;
	currentsalt.length = SALT_LENGTH;
	memcpy((char*)currentsalt.salt, gpg_common_cur_salt->salt, currentsalt.length);
	currentsalt.count = gpg_common_cur_salt->count;
	currentsalt.key_len = gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	uint32_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint32_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

//	printf ("spec=%s pk_algorithm=%d hash_algorithm=%d cipher_algorithm=%d key_size=%d\n",
//		gpg_common_cur_salt->spec==SPEC_SIMPLE?"SIMPLE":(gpg_common_cur_salt->spec==SPEC_SALTED?"SALTED":"ISALTED"),
//		gpg_common_cur_salt->pk_algorithm,
//		gpg_common_cur_salt->hash_algorithm,
//		gpg_common_cur_salt->cipher_algorithm,
//		gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm));

	// Ok, if a format we do NOT handle, then use CPU code.
	// Right now we ONLY handle 'simple' SHA1 spec-iterated-salt in GPU
	if (gpg_common_cur_salt->spec != SPEC_ITERATED_SALTED ||
	    gpg_common_cur_salt->hash_algorithm != HASH_SHA1/* ||
	    gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm) > 20*/
		) {
		// Code taken straight from the CPU version.  Since we do not
		// have 'special' GPU support, we simply fall back.
		static int warned_once = 0;
		int ks = gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm);

		if (!warned_once && !bench_running) {
			fprintf(stderr, "[-] WARNING there are some input gpg hashes which"
			                " will be run using CPU code, not GPU code\n");
			warned_once = 1;
		}
#ifdef _OPENMP
#pragma omp parallel for
		for (index = 0; index < count; index++)
#endif
		{
			int res;
			char pass[128];
			unsigned char keydata[64];

			memcpy(pass, inbuffer[index].v, inbuffer[index].length);
			pass[inbuffer[index].length] = '\0';
			gpg_common_cur_salt->s2kfun(pass, keydata, ks);
			res = gpg_common_check(keydata, ks);
			if (res) {
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}

		return count;
	}

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
		"Copy data to gpu");

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
		multi_profilingEvent[1]),
		"Run kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	if (gpg_common_check(outbuffer[index].v, gpg_common_keySize(gpg_common_cur_salt->cipher_algorithm)))
	{
		cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
		any_cracked |= 1;
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

/*
 * Report gpg --s2k-count n as 1st tunable cost,
 * hash algorithm as 2nd tunable cost,
 * cipher algorithm as 3rd tunable cost.
 */

struct fmt_main fmt_opencl_gpg = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"s2k-count", /* only for gpg --s2k-mode 3, see man gpg, option --s2k-count n */
			"hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]",
			"cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256]",
		},
		{ FORMAT_TAG },
		gpg_common_gpg_tests
	},
	{
		init,
		done,
		reset,
		fmt_default_prepare,
		gpg_common_valid,
		fmt_default_split,
		fmt_default_binary,
		gpg_common_get_salt,
		{
			gpg_common_gpg_s2k_count,
			gpg_common_gpg_hash_algorithm,
			gpg_common_gpg_cipher_algorithm,
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
