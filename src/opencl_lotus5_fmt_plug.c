/*
 * This software is Copyright (c) 2014 Sayantan Datta <std2048 at gmail dot com>
 * and Copyright (c) 2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on CPU version by Jeff Fay, bartavelle and Solar Designer.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_1otus5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_1otus5);
#else

#include <stdio.h>
#include <string.h>
#include "misc.h"
#include "formats.h"
#include "common.h"
#include "common-opencl.h"
#include "opencl_lotus5_fmt.h"
#include "options.h"

/*preprocessor constants that John The Ripper likes*/
#define FORMAT_LABEL                   "lotus5-opencl"
#define FORMAT_NAME                    "Lotus Notes/Domino 5"
#define ALGORITHM_NAME                 "OpenCL"
#define BENCHMARK_COMMENT              ""
#define BENCHMARK_LENGTH               -1
#define CIPHERTEXT_LENGTH              32
#define SALT_SIZE                      0
#define BINARY_ALIGN                   MEM_ALIGN_WORD
#define SALT_ALIGN                     1
#define MIN_KEYS_PER_CRYPT             1
#define MAX_KEYS_PER_CRYPT             1
#define KEY_SIZE_IN_BYTES              (((PLAINTEXT_LENGTH >> 2) + 1) << 2)

/*A struct used for JTR's benchmarks*/
static struct fmt_tests tests[] = {
  {"06E0A50B579AD2CD5FFDC48564627EE7", "secret"},
  {"355E98E7C7B59BD810ED845AD0FD2FC4", "password"},
  {"CD2D90E8E00D8A2A63A81F531EA8A9A3", "lotus"},
  {"69D90B46B1AC0912E5CCF858094BBBFC", "dirtydog"},
  {NULL}
};

static const unsigned int lotus_magic_table[256] = {
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
  0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
  0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
  0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
  0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
  0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
  0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
  0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
  0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
  0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
  0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
  0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
  0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
  0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
  0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
  0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
  0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
  0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
  0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
  0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
  0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
  0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
};

/*Some more JTR variables*/
static cl_uint *crypt_key;
static char *saved_key;
static struct fmt_main *self;

static cl_int err;
static cl_mem cl_tx_keys, cl_tx_binary, cl_magic_table;

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
	size_t mem_alloc_sz;
	char *err_msg = "Create Buffer FAILED";

	mem_alloc_sz = KEY_SIZE_IN_BYTES * gws;
	cl_tx_keys = clCreateBuffer(context[gpu_id],
				    CL_MEM_READ_ONLY,
			            mem_alloc_sz, NULL, &err);
	HANDLE_CLERROR(err, err_msg);

	mem_alloc_sz = BINARY_SIZE * gws;
	cl_tx_binary = clCreateBuffer(context[gpu_id],
				      CL_MEM_WRITE_ONLY,
			              mem_alloc_sz, NULL, &err);
	HANDLE_CLERROR(err, err_msg);

	mem_alloc_sz = sizeof(cl_uint) * 256;
	cl_magic_table = clCreateBuffer(context[gpu_id],
					CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
				        mem_alloc_sz, (cl_uint *)lotus_magic_table,
					&err);
	HANDLE_CLERROR(err, err_msg);

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0,
				      sizeof(cl_mem), &cl_tx_keys),
		                      "Set Kernel Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1,
				      sizeof(cl_mem), &cl_magic_table),
		                      "Set Kernel Arg 0 :FAILED");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2,
				      sizeof(cl_mem), &cl_tx_binary),
		                      "Set Kernel Arg 1 :FAILED");

	crypt_key = mem_calloc(gws, BINARY_SIZE);
	saved_key = mem_calloc(gws, KEY_SIZE_IN_BYTES);
}

static void release_clobj(void)
{
	const char * err_msg = "Release Memory Object FAILED.";

	if (crypt_key) {
		HANDLE_CLERROR(clReleaseMemObject(cl_tx_keys), err_msg);
		HANDLE_CLERROR(clReleaseMemObject(cl_tx_binary), err_msg);
		HANDLE_CLERROR(clReleaseMemObject(cl_magic_table), err_msg);

		MEM_FREE(saved_key);
		MEM_FREE(crypt_key);
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_init("$JOHN/kernels/lotus5_kernel.cl", gpu_id, NULL);

	crypt_kernel = clCreateKernel(program[gpu_id], "lotus5", &err);
	HANDLE_CLERROR(err, "Create kernel FAILED.");
}

static void reset(struct db_main *db)
{
	if (!db) {
		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       2 * KEY_SIZE_IN_BYTES, 0);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static void done(void)
{
	release_clobj();
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel),
		       "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
		       "Release Program");
}

/*Utility function to convert hex to bin */
static void * get_binary(char *ciphertext)
{
  static char realcipher[BINARY_SIZE];
  int i;
  for (i = 0; i < BINARY_SIZE; i++)
      realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
  return ((void *) realcipher);
}

/*Another function required by JTR: decides whether we have a valid
 * ciphertext */
static int valid (char *ciphertext, struct fmt_main *self)
{
  int i;

  for (i = 0; i < CIPHERTEXT_LENGTH; i++)
	  if (!(((ciphertext[i] >= '0') && (ciphertext[i] <= '9'))
				  || ((ciphertext[i] >= 'a') && (ciphertext[i] <= 'f'))
				  || ((ciphertext[i] >= 'A') && (ciphertext[i] <= 'F'))))
	  {
		  return 0;
	  }
  return !ciphertext[i];
}

/*sets the value of saved_key so we can play with it*/
static void set_key (char *key, int index)
{
  memset (saved_key + index *
	  KEY_SIZE_IN_BYTES, 0,
	  KEY_SIZE_IN_BYTES);
  saved_key[index *
	    KEY_SIZE_IN_BYTES +
	    KEY_SIZE_IN_BYTES - 1] = strlen(key);
  strnzcpy (saved_key + index *
	    KEY_SIZE_IN_BYTES, key,
	    saved_key[index *
	    KEY_SIZE_IN_BYTES +
	    KEY_SIZE_IN_BYTES - 1] + 1);

}

/*retrieves the saved key; used by JTR*/
static char * get_key (int index)
{
	return (saved_key + index * KEY_SIZE_IN_BYTES);
}

static int cmp_all (void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key + index * BINARY_SIZE_IN_ARCH_WORD_32, BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one (void *binary, int index)
{
	return !memcmp(binary, crypt_key + index * BINARY_SIZE_IN_ARCH_WORD_32, BINARY_SIZE);
}

static int cmp_exact (char *source, int index)
{
	return 1;
}

/*the last public function; generates ciphertext*/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t mem_cpy_sz;
	size_t N, *M;

	mem_cpy_sz = count * KEY_SIZE_IN_BYTES;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id],
					    cl_tx_keys, CL_FALSE, 0,
					    mem_cpy_sz, saved_key,
					    0, NULL, multi_profilingEvent[0]),
					    "Failed:Copy data to gpu.");

	M = local_work_size ? &local_work_size : NULL;
	N = local_work_size ?
		(count + (local_work_size - 1)) /
		local_work_size * local_work_size : count;
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					      crypt_kernel, 1,
					      NULL, &N, M,
	                                      0, NULL, multi_profilingEvent[1]),
					      "Enqueue Kernel Failed.");

	mem_cpy_sz = count * BINARY_SIZE;
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id],
					   cl_tx_binary, CL_TRUE, 0,
					   mem_cpy_sz, crypt_key, 0,
					   NULL, multi_profilingEvent[2]),
					   "Failed:Copy data from gpu.");

	return count;
}

static int get_hash1(int index) { return crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] & 0xf; }
static int get_hash2(int index) { return crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] & 0xff; }
static int get_hash3(int index) { return crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] & 0xfff; }
static int get_hash4(int index) { return crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] & 0xffff; }
static int get_hash5(int index) { return crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] & 0xfffff; }
static int get_hash6(int index) { return crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] & 0xffffff; }
static int get_hash7(int index) { return crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] & 0x7ffffff; }

/* C's version of a class specifier */
struct fmt_main fmt_opencl_1otus5 = {
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
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash1,
			get_hash2,
			get_hash3,
			get_hash4,
			get_hash5,
			get_hash6,
			get_hash7
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
