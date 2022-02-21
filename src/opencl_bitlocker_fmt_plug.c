/*
 * BitLocker-OpenCL format developed by Elenago
 * <elena dot ago at gmail dot com> in 2015
 *
 * Copyright (c) 2015-2017 Elenago <elena dot ago at gmail dot com>
 * and Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor
 * implied. See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * More info here: http://openwall.info/wiki/john/OpenCL-BitLocker
 *
 * A standalone CUDA implementation is available here: https://github.com/e-ago/bitcracker
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_bitlocker;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_bitlocker);
#else

#include <ctype.h>
#include <string.h>
#include <assert.h>
#include "misc.h"
#include "arch.h"
#include "base64_convert.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "opencl_common.h"
#include "bitlocker_common.h"
#include "bitlocker_variable_code.h"

#define FORMAT_LABEL            "BitLocker-opencl"
#define ALGORITHM_NAME          "SHA256 AES OpenCL"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x108
#define SALT_SIZE               sizeof(bitlocker_custom_salt)
#define SALT_ALIGN              sizeof(int)
#define HASH_LOOPS              256
#define ITERATIONS              1048576 //4096 (/ 256)
#define STEP                    0
#define SEED                    1024

static const char * warn[] = {
	"init: ", ", loop: ", ", final: ", ", xfer: "
};

static int split_events[] = { 1, -1, -1};

#define BL_SINGLE_BLOCK_SHA_SIZE                64
#define BITLOCKER_PADDING_SIZE                  40
#define BITLOCKER_ITERATION_NUMBER              0x100000
#define BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH   88
#define BITLOCKER_INT_HASH_SIZE                 8
#define BITLOCKER_SALT_SIZE                     16
#define BITLOCKER_MAC_SIZE                      16
#define BITLOCKER_NONCE_SIZE                    12
#define BITLOCKER_IV_SIZE                       16
#define BITLOCKER_VMK_SIZE                      60
#define BITLOCKER_VMK_HEADER_SIZE               12
#define BITLOCKER_VMK_BODY_SIZE                 32
#define BITLOCKER_VMK_FULL_SIZE                 44
#define FALSE                                   0
#define TRUE                                    1
#define BITLOCKER_ENABLE_DEBUG                  0
#define WBLOCKS_KERNEL_NAME                     "opencl_bitlocker_wblocks"
#define INIT_KERNEL_NAME                        "opencl_bitlocker_attack_init"
#define ATTACK_KERNEL_NAME                      "opencl_bitlocker_attack_loop"
#define FINAL_KERNEL_NAME                       "opencl_bitlocker_attack_final"

#define BITLOCKER_PSW_CHAR_MIN_SIZE             8
#define BITLOCKER_PSW_CHAR_MAX_SIZE             55
#define BITLOCKER_PSW_INT_SIZE                  32
#define BITLOCKER_FIRST_LENGTH                  27

#ifndef UINT32_C
	#define UINT32_C(c) c ## UL
#endif

static struct fmt_main *self;
static bitlocker_custom_salt *cur_salt;
static cl_kernel init_kernel, final_kernel, block_kernel;
static cl_int cl_error;

static cl_mem d_salt, d_pad, d_wblocks,
       d_pswI, d_pswSize, d_found, d_numPsw,
       d_firstHash, d_outHash, d_startIndex, d_attack, d_loopHash;

static cl_mem d_vmk, d_mac;
static cl_mem d_vmkIV0, d_vmkIV4, d_vmkIV8, d_vmkIV12;
static cl_mem d_macIV0, d_macIV4, d_macIV8, d_macIV12;
static cl_mem d_cMacIV0, d_cMacIV4, d_cMacIV8, d_cMacIV12;

static unsigned int *h_wblocks, *hash_zero, *h_pswI;
static int *h_pswSize, *h_found, i, *h_numPsw, *h_attack, h_loopIter=0;
static unsigned char *h_pswC, *h_vmkIV, *h_mac, *h_macIV, *h_cMacIV;

static int w_block_precomputed(unsigned char *salt);
// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)\
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);\
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	int arg=0;

	// ============================================= HOST =============================================
	h_pswC = (unsigned char *)mem_calloc(BITLOCKER_PSW_CHAR_MAX_SIZE * gws, sizeof(unsigned char));
	h_pswI = (unsigned int *)mem_calloc(BITLOCKER_PSW_INT_SIZE * gws, sizeof(unsigned int));
	h_pswSize = (int *)mem_calloc(gws, sizeof(int));
	h_found = (int *)mem_calloc(1, sizeof(int));
	h_wblocks = (unsigned int *)mem_calloc((BL_SINGLE_BLOCK_SHA_SIZE *BITLOCKER_ITERATION_NUMBER), sizeof(unsigned int));
	hash_zero = (unsigned int *)mem_calloc(gws * BITLOCKER_INT_HASH_SIZE, sizeof(unsigned int));
	h_attack = (int *)mem_calloc(1, sizeof(int));
	h_mac = (unsigned char *)mem_calloc(BITLOCKER_MAC_SIZE, sizeof(unsigned char));
	h_vmkIV = (unsigned char *)mem_calloc(BITLOCKER_IV_SIZE, sizeof(unsigned char));
	h_macIV = (unsigned char *)mem_calloc(BITLOCKER_IV_SIZE, sizeof(unsigned char));
	h_cMacIV = (unsigned char *)mem_calloc(BITLOCKER_IV_SIZE, sizeof(unsigned char));

	// ============================================= DEVICE =============================================
	d_attack = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(int), "Cannot allocate device memory");
	d_loopHash = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(int), "Cannot allocate device memory");
	// ===== IV fast attack
	d_vmkIV0 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_vmkIV4 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_vmkIV8 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_vmkIV12 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	// ===== IV MAC verification
	d_mac = CLCREATEBUFFER(CL_MEM_READ_ONLY, BITLOCKER_MAC_SIZE*sizeof(unsigned char), "Cannot allocate device memory");
	d_macIV0 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_macIV4 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_macIV8 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_macIV12 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_cMacIV0 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_cMacIV4 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_cMacIV8 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");
	d_cMacIV12 = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate device memory");

	d_numPsw = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(int),
			"Cannot allocate d_numPsw");

	d_vmk = CLCREATEBUFFER(CL_MEM_READ_ONLY,
			BITLOCKER_VMK_SIZE * sizeof(char), "Cannot allocate d_vmk");

	d_pswI = CLCREATEBUFFER(CL_MEM_READ_ONLY, BITLOCKER_PSW_INT_SIZE*gws*sizeof(unsigned int),
			"Cannot allocate d_pswI");

	//1 or 2
	d_pswSize = CLCREATEBUFFER(CL_MEM_READ_ONLY, gws*sizeof(unsigned int),
			"Cannot allocate d_pswSize");

	d_found = CLCREATEBUFFER(CL_MEM_WRITE_ONLY, sizeof(int),
			"Cannot allocate d_found");

	d_wblocks = CLCREATEBUFFER(CL_MEM_READ_WRITE,
			BL_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
			sizeof(unsigned int), "Cannot allocate w blocks");

	d_firstHash = CLCREATEBUFFER(CL_MEM_READ_WRITE,
			gws * BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int),
			"Cannot allocate d_firstHash");

	d_outHash = CLCREATEBUFFER(CL_MEM_READ_WRITE,
			gws * BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int),
			"Cannot allocate d_outHash");

	d_startIndex = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(int),
			"Cannot allocate d_startIndex");

	// =========================== Init kernel ===========================
	arg=0;
	CLKERNELARG(init_kernel, arg++, d_numPsw,
			"Error while setting d_numPsw");
	CLKERNELARG(init_kernel, arg++, d_pswI,
			"Error while setting d_pswI");
	CLKERNELARG(init_kernel, arg++, d_pswSize,
			"Error while setting d_pswSize");
	CLKERNELARG(init_kernel, arg++, d_firstHash,
			"Error while setting d_firstHash");
	CLKERNELARG(init_kernel, arg++, d_outHash,
			"Error while setting d_outHash");
	CLKERNELARG(init_kernel, arg++, d_attack,
			"Error while setting d_attack");

	// =========================== Loop kernel ===========================
	arg=0;
	CLKERNELARG(crypt_kernel, arg++, d_numPsw,
			"Error while setting d_numPsw");
	CLKERNELARG(crypt_kernel, arg++, d_wblocks,
			"Error while setting d_wblocks");
	CLKERNELARG(crypt_kernel, arg++, d_firstHash,
			"Error while setting d_firstHash");
	CLKERNELARG(crypt_kernel, arg++, d_outHash,
			"Error while setting d_outHash");
	CLKERNELARG(crypt_kernel, arg++, d_startIndex,
			"Error while setting d_startIndex");
	CLKERNELARG(crypt_kernel, arg++, d_loopHash,
			"Error while setting d_loopHash");

	// =========================== Final kernel ===========================
	arg=0;
	CLKERNELARG(final_kernel, arg++, d_numPsw,
			"Error while setting d_numPsw");
	CLKERNELARG(final_kernel, arg++, d_found,
			"Error while setting d_found");
	CLKERNELARG(final_kernel, arg++, d_vmk,
			"Error while setting d_vmk");
	CLKERNELARG(final_kernel, arg++, d_outHash,
			"Error while setting d_outHash");

	CLKERNELARG(final_kernel, arg++, d_attack,
			"Error while setting d_attack");
	CLKERNELARG(final_kernel, arg++, d_vmkIV0,
			"Error while setting d_vmkIV0");
	CLKERNELARG(final_kernel, arg++, d_vmkIV4,
			"Error while setting d_vmkIV4");
	CLKERNELARG(final_kernel, arg++, d_vmkIV8,
			"Error while setting d_vmkIV8");
	CLKERNELARG(final_kernel, arg++, d_vmkIV12,
			"Error while setting d_vmkIV12");

	CLKERNELARG(final_kernel, arg++, d_macIV0,
			"Error while setting d_macIV0");
	CLKERNELARG(final_kernel, arg++, d_macIV4,
			"Error while setting d_macIV4");
	CLKERNELARG(final_kernel, arg++, d_macIV8,
			"Error while setting d_macIV8");
	CLKERNELARG(final_kernel, arg++, d_macIV12,
			"Error while setting d_macIV12");

	CLKERNELARG(final_kernel, arg++, d_cMacIV0,
			"Error while setting d_cMacIV0");
	CLKERNELARG(final_kernel, arg++, d_cMacIV4,
			"Error while setting d_cMacIV4");
	CLKERNELARG(final_kernel, arg++, d_cMacIV8,
			"Error while setting d_cMacIV8");
	CLKERNELARG(final_kernel, arg++, d_cMacIV12,
			"Error while setting d_cMacIV12");

	CLKERNELARG(final_kernel, arg++, d_mac,
			"Error while setting d_mac");

	d_salt = CLCREATEBUFFER(CL_MEM_READ_ONLY,
			BITLOCKER_SALT_SIZE * sizeof(unsigned char), "Cannot allocate d_salt");

	d_pad = CLCREATEBUFFER(CL_MEM_READ_ONLY, BITLOCKER_PADDING_SIZE * sizeof(unsigned char),
				"Cannot allocate d_pad");

	CLKERNELARG(block_kernel, 0, d_salt, "Error while setting d_salt");
	CLKERNELARG(block_kernel, 1, d_pad, "Error while setting d_pad");
	CLKERNELARG(block_kernel, 2, d_wblocks, "Error while setting d_wblocks");
}

static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, init_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
	//s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, block_kernel));

	return s;
}

static void release_clobj(void)
{
	if (h_found) {
		HANDLE_CLERROR(clReleaseMemObject(d_vmk), "Release");
		HANDLE_CLERROR(clReleaseMemObject(d_pswI), "Release");
		HANDLE_CLERROR(clReleaseMemObject(d_pswSize), "Release");
		HANDLE_CLERROR(clReleaseMemObject(d_found), "Release");
		HANDLE_CLERROR(clReleaseMemObject(d_wblocks), "Release");
		HANDLE_CLERROR(clReleaseMemObject(d_salt), "Release");
		HANDLE_CLERROR(clReleaseMemObject(d_pad), "Release");

		MEM_FREE(h_found);
		MEM_FREE(h_wblocks);
		MEM_FREE(h_numPsw);
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {

		//char build_opts[64];
		//snprintf(build_opts, sizeof(build_opts), "-DHASH_LOOPS=%u", HASH_LOOPS);

		opencl_init("$JOHN/opencl/bitlocker_kernel.cl", gpu_id, NULL);

		block_kernel =
			clCreateKernel(program[gpu_id], WBLOCKS_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error,
		               "Error creating block kernel");

		init_kernel =
			clCreateKernel(program[gpu_id], INIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		crypt_kernel =
			clCreateKernel(program[gpu_id], ATTACK_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		final_kernel =
			clCreateKernel(program[gpu_id], FINAL_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");
	}

	/*
	 * Initialize openCL tuning (library) for this format.
	 * Autotuning with default parameters:
	 * HASH_LOOP = 256
	 * ITERATIONS = 1048576
	 */

	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
	                       1, self, create_clobj, release_clobj,
	                       BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int),
	                       0, db);

	/* Autotune for max. 20ms single-call duration (5 for CPU device) */
	autotune_run(self, ITERATIONS, 0, (cpu(device_info[gpu_id]) ? 5 : 20));
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(block_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(init_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static int w_block_precomputed(unsigned char *salt)
{
	unsigned char *padding;
	uint64_t msgLen;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	if (salt == NULL)
		return 0;

	global_work_size = GET_NEXT_MULTIPLE(1, local_work_size); //count

	padding =
	    (unsigned char *)mem_calloc(BITLOCKER_PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding + 1, 0, 31);
	msgLen = (BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (i = 0; i < 8; i++)
		padding[BITLOCKER_PADDING_SIZE - 1 - i] =
		    (uint8_t)(msgLen >> (i * 8));

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_salt,
		CL_TRUE, 0, BITLOCKER_SALT_SIZE * sizeof(char), salt, 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_pad,
		CL_TRUE, 0, BITLOCKER_PADDING_SIZE * sizeof(char), padding, 0,
		NULL, NULL), "clEnqueueWriteBuffer");


	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], block_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, NULL), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], d_wblocks,
		CL_TRUE, 0, BL_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
		sizeof(unsigned int), h_wblocks, 0,
		NULL, NULL), "clEnqueueReadBuffer");

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	return 1;
}

static void set_salt(void * cipher_salt_input)
{
	cur_salt = (bitlocker_custom_salt *) cipher_salt_input;

	w_block_precomputed(cur_salt->salt);
	if (!h_wblocks) {
		error_msg("Error... Exit\n");
	}

	memset(h_vmkIV, 0, BITLOCKER_IV_SIZE);
	memcpy(h_vmkIV + 1, cur_salt->iv, BITLOCKER_NONCE_SIZE);
	h_vmkIV[0] = (unsigned char)(BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1);
	h_vmkIV[BITLOCKER_IV_SIZE - 1] = 1;

	h_attack[0] = cur_salt->attack_type;
	memcpy(h_mac, cur_salt->mac, BITLOCKER_MAC_SIZE);

	//-------- macIV setup ------
	memset(h_macIV, 0, BITLOCKER_IV_SIZE);
	h_macIV[0] = (unsigned char)(BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1);
	memcpy(h_macIV + 1, cur_salt->iv, BITLOCKER_NONCE_SIZE);
	h_macIV[BITLOCKER_IV_SIZE-1] = 0;
	// -----------------------

	//-------- cMacIV setup ------
	memset(h_cMacIV, 0, BITLOCKER_IV_SIZE);
	h_cMacIV[0] = 0x3a;
	memcpy(h_cMacIV + 1, cur_salt->iv, BITLOCKER_NONCE_SIZE);
	h_cMacIV[BITLOCKER_IV_SIZE-1] = 0x2c;
	// -----------------------
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, startIndex=0, h_loopHash=0;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);
	h_found[0] = -1;
	h_loopIter=cur_salt->iterations/HASH_LOOPS;
	if(cur_salt->iterations%HASH_LOOPS != 0) h_loopIter++;
	h_loopHash = HASH_LOOPS;

	// =========================== Init kernel ===========================
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_numPsw,
		CL_FALSE, 0, sizeof(int), pcount, 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_pswI,
		CL_FALSE, 0, count * BITLOCKER_PSW_INT_SIZE * sizeof(unsigned int), h_pswI, 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_pswSize,
		CL_FALSE, 0, count * sizeof(int), h_pswSize, 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_attack,
		CL_FALSE, 0, sizeof(int), h_attack, 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_outHash,
		CL_FALSE, 0, count * BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int),
		hash_zero, 0, NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], init_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[0]), "Run kernel");

	// =========================== Loop kernel ===========================
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_wblocks,
		CL_FALSE, 0, (BL_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER) * sizeof(unsigned int),
		h_wblocks, 0, NULL, NULL), "clEnqueueWriteBuffer");

	for (i = 0; i < (ocl_autotune_running ? 1 : h_loopIter); i++) {

		if( ( (HASH_LOOPS * i) + HASH_LOOPS) > cur_salt->iterations)
			h_loopHash = (cur_salt->iterations % HASH_LOOPS);

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_startIndex,
				CL_FALSE, 0, sizeof(int), &startIndex, 0,
				NULL, NULL), "Copy iter num to gpu");

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_loopHash,
				CL_FALSE, 0, sizeof(int), &h_loopHash, 0,
				NULL, NULL), "clEnqueueWriteBuffer");

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
				1, NULL, &global_work_size, lws, 0,
				NULL, multi_profilingEvent[1]), "Run loop kernel");

		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();

		startIndex += h_loopHash;
	}

	// =========================== Final kernel ===========================
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_found,
		CL_FALSE, 0, sizeof(int), h_found, 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_vmk,
		CL_FALSE, 0, BITLOCKER_VMK_SIZE * sizeof(char), cur_salt->data, 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	// =============== vmkIV ===============
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_vmkIV0,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_vmkIV)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_vmkIV4,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_vmkIV+4)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_vmkIV8,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_vmkIV+8)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_vmkIV12,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_vmkIV+12)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");
	// =======================================

	// ================== macIV ==================
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_macIV0,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_macIV)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_macIV4,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_macIV+4)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_macIV8,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_macIV+8)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_macIV12,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_macIV+12)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");
	// ===========================================

	// =============== cMacIV ==============
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_cMacIV0,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_cMacIV)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_cMacIV4,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_cMacIV+4)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_cMacIV8,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_cMacIV+8)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_cMacIV12,
		CL_FALSE, 0, sizeof(unsigned int), (void*)((unsigned int *)(h_cMacIV+12)), 0,
		NULL, NULL), "clEnqueueWriteBuffer");
	// ===========================================

	// =================== MAC ===================
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], d_mac,
		CL_FALSE, 0, BITLOCKER_MAC_SIZE, (void*)h_mac, 0,
		NULL, NULL), "clEnqueueWriteBuffer");
	// ===========================================

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run kernel");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], d_found,
		CL_TRUE, 0, sizeof(int), h_found, 0,
		NULL, multi_profilingEvent[3]), "clEnqueueReadBuffer");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
	opencl_process_event();


	return count;
}

static int cmp_all(void *binary, int count)
{
	if (h_found[0] >= 0) {
#if BITLOCKER_ENABLE_DEBUG == 1

		fprintf(stdout, "\n[BitCracker] -> Password found: #%d, %.*s\n",
		        h_found[0] + 1, BITLOCKER_PSW_CHAR_MAX_SIZE,
		        (char *)(h_pswC +
				(h_found[0] * BITLOCKER_PSW_CHAR_MAX_SIZE)));
#endif
		return 1;
	} else
		return 0;
}

static int cmp_one(void *binary, int index)
{
	if (h_found[0] == index)
		return 1;
	else
		return 0;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	int j=0, k=0, size=0, count=0;
	char tmp[BITLOCKER_PSW_CHAR_MAX_SIZE + 1], tmp2[BITLOCKER_PSW_CHAR_MAX_SIZE], *p;
	int8_t check_digit;

	size = strlen(key);
	if (size > BITLOCKER_PSW_CHAR_MAX_SIZE)
		size = BITLOCKER_PSW_CHAR_MAX_SIZE;

	memset(tmp, 0, sizeof(tmp));
	memcpy(tmp, key, size);

	memset((h_pswC)+(index*BITLOCKER_PSW_CHAR_MAX_SIZE), 0, BITLOCKER_PSW_CHAR_MAX_SIZE*sizeof(unsigned char));
	memcpy((h_pswC+(index*BITLOCKER_PSW_CHAR_MAX_SIZE)), tmp, size);

	memset((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE), 0, BITLOCKER_PSW_INT_SIZE*sizeof(unsigned int));

        //Recovery password
	if(h_attack[0] == BITLOCKER_HASH_RP || h_attack[0] == BITLOCKER_HASH_RP_MAC)
	{
		memset(tmp2, 0, BITLOCKER_PSW_CHAR_MAX_SIZE);
		p = strtokm(tmp, "-");
		while (p)
		{
			//Dislocker, Recovery Password checks
			int v = atoi(p);
			if( ((v % 11) != 0) || (v >= 0x10000 * 11) ) break;
			check_digit = (int8_t) ( p[0] - p[1] + p[2] - p[3] + p[4] - 48 ) % 11;
			if( check_digit < 0 ) check_digit = (int8_t) check_digit + 11;
			if( check_digit != (p[5] - 48)) break;
			v /= 11;
			((unsigned char *)tmp2)[count] = v;
			((unsigned char *)tmp2)[count + 1] = v >> 8;
			p = strtokm(NULL, "-");
			count+=2;
		}

#if 0
		/* XXX: Just returning is wrong - we can't reject a key from here */
		if(count != (RECOVERY_PASS_BLOCKS*2)) return;
#endif

		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[0] = ( (((unsigned int)tmp2[0]  ) << 24) & 0xFF000000) |
							( (((unsigned int)tmp2[0+1]) << 16) & 0x00FF0000) |
							( (((unsigned int)tmp2[0+2])  << 8) & 0x0000FF00)  |
							( (((unsigned int)tmp2[0+3])  << 0) & 0x000000FF);

		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[1] = 	( (((unsigned int)tmp2[4]) << 24) & 0xFF000000) |
							( (((unsigned int)tmp2[4+1]) << 16) & 0x00FF0000) |
							( (((unsigned int)tmp2[4+2]) << 8) & 0x0000FF00)  |
							( (((unsigned int)tmp2[4+3]) << 0) & 0x000000FF);

		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[2] = 	( (((unsigned int)tmp2[8]) << 24) & 0xFF000000) |
							( (((unsigned int)tmp2[8+1]) << 16) & 0x00FF0000) |
							( (((unsigned int)tmp2[8+2]) << 8) & 0x0000FF00)  |
							( (((unsigned int)tmp2[8+3]) << 0) & 0x000000FF);

		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[3] = 	( (((unsigned int)tmp2[12]) << 24) & 0xFF000000) |
							( (((unsigned int)tmp2[12+1]) << 16) & 0x00FF0000) |
							( (((unsigned int)tmp2[12+2]) << 8) & 0x0000FF00)  |
							( (((unsigned int)tmp2[12+3]) << 0) & 0x000000FF);

		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[4] = 0x80000000;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[5] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[6] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[7] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[8] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[9] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[10] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[11] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[12] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[13] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[14] = 0;
		((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE))[15] = 0x80;

		h_pswSize[index]=1;
	}
	else //User Password
	{
		tmp[size] = 0x80;
		do
		{
			((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE)+j)[0] = ( (((unsigned int)tmp[k]) << 24) & 0xFF000000);
			k++;

			if(k <= size)
				((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE)+j)[0] = ((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE)+j)[0] | ( (((unsigned int)tmp[k]) << 8) & 0x0000FF00);

			j++;
			k++;
		} while(k <= size);

		if(size <= BITLOCKER_FIRST_LENGTH)
		{
			//16 int
			h_pswSize[index]=1;
			((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE)+14)[0] = 0;
			((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE)+15)[0] = ((int)(((size*2) << 3) >> 8)) << 8 | ((int)((size*2) << 3));
		}
		else
		{
			//32 int
			h_pswSize[index]=2;
			((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE)+30)[0] = 0;
			((h_pswI)+(index*BITLOCKER_PSW_INT_SIZE)+31)[0] = ((uint8_t)(((size*2) << 3) >> 8)) << 8 | ((uint8_t)((size*2) << 3));
		}
	}
}

static char *get_key(int index)
{
	static char ret[BITLOCKER_PSW_CHAR_MAX_SIZE + 1];

	memset(ret, 0, BITLOCKER_PSW_CHAR_MAX_SIZE + 1);
	memcpy(ret, h_pswC + (index * BITLOCKER_PSW_CHAR_MAX_SIZE), BITLOCKER_PSW_CHAR_MAX_SIZE);

	return ret;
}

struct fmt_main fmt_opencl_bitlocker = {
{
	FORMAT_LABEL,
	FORMAT_NAME,
	ALGORITHM_NAME,
	BENCHMARK_COMMENT,
	BENCHMARK_LENGTH,
	BITLOCKER_PSW_CHAR_MIN_SIZE,
	BITLOCKER_PSW_CHAR_MAX_SIZE,
	BINARY_SIZE,
	BINARY_ALIGN,
	SALT_SIZE,
	SALT_ALIGN,
	MIN_KEYS_PER_CRYPT,
	MAX_KEYS_PER_CRYPT,
	FMT_CASE | FMT_8_BIT | FMT_NOT_EXACT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		bitlocker_tests
}, {
	init,
	done,
	reset,
	fmt_default_prepare,
	bitlocker_common_valid,
	fmt_default_split,
	fmt_default_binary,
	bitlocker_common_get_salt,
	{
		bitlocker_common_iteration_count,
	},
	fmt_default_source,
	{
		fmt_default_binary_hash,
	},
	fmt_default_salt_hash,
	NULL,
	set_salt,
	set_key,
	get_key,
	fmt_default_clear_keys,
	crypt_all,
	{
		fmt_default_get_hash,
	},
	cmp_all,
	cmp_one,
	cmp_exact
}};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
