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
 * This is a research project, for more informations: http://openwall.info/wiki/john/OpenCL-BitLocker
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
#include "common-opencl.h"
#include "bitlocker_common.h"

#define FORMAT_LABEL		    "BitLocker-opencl"
#define ALGORITHM_NAME          "SHA256 AES OpenCL"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define BITLOCKER_JTR_HASH_SIZE 45
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1

#define BITLOCKER_HASH_SIZE 8   //32
#define BITLOCKER_SINGLE_BLOCK_SHA_SIZE 64
#define BITLOCKER_PADDING_SIZE 40
#define BITLOCKER_ITERATION_NUMBER 0x100000
#define BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH 88
#define BITLOCKER_MAX_INPUT_PASSWORD_LEN 16
#define BITLOCKER_MIN_INPUT_PASSWORD_LEN 8
#define BITLOCKER_INT_HASH_SIZE 8

#define FALSE 0
#define TRUE 1
#define BITLOCKER_SALT_SIZE 16
#define SALT_SIZE               sizeof(bitlocker_custom_salt)
#define SALT_ALIGN              sizeof(int)

#define BITLOCKER_MAC_SIZE 16
#define BITLOCKER_NONCE_SIZE 12
#define BITLOCKER_IV_SIZE 16
#define BITLOCKER_VMK_SIZE 60 //44
#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

#define BITLOCKER_ENABLE_DEBUG 		0
#define WBLOCKS_KERNEL_NAME  		"opencl_bitlocker_wblocks"
#define PREPARE_KERNEL_NAME			"opencl_bitlocker_attack_init"
#define ATTACK_KERNEL_NAME			"opencl_bitlocker_attack_loop"
#define FINAL_KERNEL_NAME			"opencl_bitlocker_attack_final"

#define HASH_LOOPS		256
#define ITERATIONS		4096 // 1048576 / 256

static struct fmt_tests opencl_bitlocker_tests[] = {
	// Windows 10 generated BitLocker image
	{"$bitlocker$0$16$134bd2634ba580adc3758ca5a84d8666$1048576$12$9080903a0d9dd20103000000$60$0c52fdd87f17ac55d4f4b82a00b264070f36a84ead6d4cd330368f7dddfde1bdc9f5d08fa526dae361b3d64875f76a077fe9c67f44e08d56f0131bb2", "openwall@123"},
	// Windows 10
	{"$bitlocker$0$16$73926f843bbb41ea2a89a28b114a1a24$1048576$12$30a81ef90c9dd20103000000$60$942f852f2dc4ba8a589f35e750f33a5838d3bdc1ed77893e02ae1ac866f396f8635301f36010e0fcef0949078338f549ddb70e15c9a598e80c905baa", "password@123"},
	// Windows 8.1
	{"$bitlocker$0$16$5e0686b4e7ce8a861b75bab3e8f1d424$1048576$12$90928da8c019d00103000000$60$ee5ce06cdc89b9fcdcd24bb854842fc8b715bb36c86c19e73ddb8a409718cac412f0416a51b1e0472fad8edb34d9208dd874dcadbf4779aaf01dfa74", "openwall@123"},
	{NULL}
};


static cl_mem salt_d, padding_d, w_blocks_d, deviceEncryptedVMK,
       devicePassword, devicePasswordSize, deviceFound, numPasswordsKernelDev,
       first_hash, output_hash, currentIterPtr, IV0_dev, IV4_dev, IV8_dev, IV12_dev;
static cl_int cl_error;

static unsigned int *w_blocks_h, *hash_zero;
static unsigned char *tmpIV, *inbuffer;
static int *inbuffer_size;

//k93Lm;ld

static int *hostFound, i;
static unsigned int tmp_global;
static unsigned int *IV0, *IV4, *IV8, *IV12;
static int *numPasswordsKernel;

//#define DEBUG
static cl_int cl_error;
static cl_kernel prepare_kernel, final_kernel;
static cl_kernel block_kernel;
static struct fmt_main *self;

static bitlocker_custom_salt *cur_salt;

#define STEP			0
#define SEED			1024

static const char *warn[] = {
        "xfer: ",  ", ",  ", ",  ", ",  ", ",
        ", ",  ", ",  ", ",  ", ",  ", ",
        ", ",  ", ",  ", prepare: " ,  ", xfer: ",  ", crypt: ",
        ", final: ",  ", res xfer: "
};

static int split_events[] = { 14, -1, -1 };

static int w_block_precomputed(unsigned char *salt);


// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static void create_clobj(size_t gws, struct fmt_main *self)
{
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)\
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);\
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	size_t input_password_number = BITLOCKER_MAX_INPUT_PASSWORD_LEN * gws;

	// ---- MAIN ATTACK
	inbuffer = (unsigned char *)mem_calloc(input_password_number, sizeof(unsigned char));
	inbuffer_size = (int *)mem_calloc(input_password_number, sizeof(int));
	hostFound = (int *)mem_calloc(1, sizeof(int));
	w_blocks_h = (unsigned int *)mem_calloc((BITLOCKER_SINGLE_BLOCK_SHA_SIZE *
	                                        BITLOCKER_ITERATION_NUMBER), sizeof(unsigned int));

	hash_zero = (unsigned int *)mem_calloc(input_password_number * BITLOCKER_INT_HASH_SIZE, sizeof(unsigned int));

	IV0 = (unsigned int *)mem_calloc(1, sizeof(unsigned int));
	IV4 = (unsigned int *)mem_calloc(1, sizeof(unsigned int));
	IV8 = (unsigned int *)mem_calloc(1, sizeof(unsigned int));
	IV12 = (unsigned int *)mem_calloc(1, sizeof(unsigned int));


	IV0_dev = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate numPass");
	IV4_dev = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate numPass");
	IV8_dev = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate numPass");
	IV12_dev = CLCREATEBUFFER(CL_MEM_READ_ONLY, sizeof(unsigned int), "Cannot allocate numPass");

	numPasswordsKernelDev = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                                    sizeof(int), "Cannot allocate numPass");

	deviceEncryptedVMK = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                                    BITLOCKER_VMK_SIZE * sizeof(char), "Cannot allocate vmk");

	devicePassword = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                                input_password_number * sizeof(unsigned char), "Cannot allocate inbuffer");

	devicePasswordSize = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                                    input_password_number * sizeof(unsigned char), "Cannot allocate inbuffer size");

	deviceFound = CLCREATEBUFFER(CL_MEM_WRITE_ONLY,
	                             sizeof(int), "Cannot allocate device found");

	w_blocks_d = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                            BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                            sizeof(unsigned int), "Cannot allocate w blocks");

	first_hash = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                            input_password_number * BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int),
	                            "Cannot allocate first hash");

	output_hash = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                            input_password_number * BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int),
	                            "Cannot allocate first hash");

	currentIterPtr = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                            sizeof(int),
	                            "Cannot allocate first hash");

	//Prepare kernel
	CLKERNELARG(prepare_kernel, 0, numPasswordsKernelDev,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(prepare_kernel, 1, devicePassword,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(prepare_kernel, 2, devicePasswordSize,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(prepare_kernel, 3, first_hash,
	            "Error while setting first_hash");
	CLKERNELARG(prepare_kernel, 4, output_hash,
	            "Error while setting output_hash");

	//Crypt kernel
	CLKERNELARG(crypt_kernel, 0, numPasswordsKernelDev,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 1, w_blocks_d,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 2, first_hash,
	            "Error while setting first_hash");
	CLKERNELARG(crypt_kernel, 3, output_hash,
	            "Error while setting output_hash");
	CLKERNELARG(crypt_kernel, 4, currentIterPtr,
	            "Error while setting currentIterPtr");

	//Final kernel
	CLKERNELARG(final_kernel, 0, numPasswordsKernelDev,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(final_kernel, 1, deviceFound,
	            "Error while setting deviceFound");
	CLKERNELARG(final_kernel, 2, deviceEncryptedVMK,
	            "Error while setting deviceEncryptedVMK");
	CLKERNELARG(final_kernel, 3, w_blocks_d,
	            "Error while setting w_blocks_d");
	CLKERNELARG(final_kernel, 4, IV0_dev,
	            "Error while setting IV0");
	CLKERNELARG(final_kernel, 5, IV4_dev,
	            "Error while setting IV4");
	CLKERNELARG(final_kernel, 6, IV8_dev,
	            "Error while setting IV8");
	CLKERNELARG(final_kernel, 7, IV12_dev,
	            "Error while setting IV12");
	CLKERNELARG(final_kernel, 8, output_hash,
	            "Error while setting output_hash");

	salt_d = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                        BITLOCKER_SALT_SIZE * sizeof(unsigned char), "Cannot allocate salt_d");
	padding_d =
	    CLCREATEBUFFER(CL_MEM_READ_ONLY, BITLOCKER_PADDING_SIZE * sizeof(unsigned char),
	                   "Cannot allocate padding_d");

	CLKERNELARG(block_kernel, 0, salt_d, "Error while setting salt_d");
	CLKERNELARG(block_kernel, 1, padding_d, "Error while setting padding_d");
	CLKERNELARG(block_kernel, 2, w_blocks_d, "Error while setting w_blocks_d");
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, prepare_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, block_kernel));

	return s;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(deviceEncryptedVMK), "Release encrypted VMK");
	HANDLE_CLERROR(clReleaseMemObject(devicePassword), "Release encrypted VMK");
	HANDLE_CLERROR(clReleaseMemObject(devicePasswordSize), "Release encrypted VMK");
	HANDLE_CLERROR(clReleaseMemObject(deviceFound), "Release encrypted VMK");
	HANDLE_CLERROR(clReleaseMemObject(w_blocks_d), "Release encrypted VMK");
	HANDLE_CLERROR(clReleaseMemObject(salt_d), "Release encrypted VMK");
	HANDLE_CLERROR(clReleaseMemObject(padding_d), "Release encrypted VMK");

	MEM_FREE(hostFound);
	MEM_FREE(w_blocks_h);
	MEM_FREE(numPasswordsKernel);
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

		snprintf(build_opts, sizeof(build_opts), "-DHASH_LOOPS=%u", HASH_LOOPS);

		opencl_init("$JOHN/kernels/bitlocker_kernel.cl", gpu_id, NULL);

		block_kernel =
		    clCreateKernel(program[gpu_id], WBLOCKS_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error,
		               "Error creating block kernel");

		prepare_kernel =
			clCreateKernel(program[gpu_id], PREPARE_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		crypt_kernel =
			clCreateKernel(program[gpu_id], ATTACK_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		final_kernel =
			clCreateKernel(program[gpu_id], FINAL_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
		                       14, self, create_clobj, release_clobj,
		                       BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int),
		                       0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, HASH_LOOPS * ITERATIONS, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(block_kernel), "Release kernel W");
		HANDLE_CLERROR(clReleaseKernel(prepare_kernel), "Release kernel A");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel A");
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel A");

		//HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel 2");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
		               "Release Program");

		autotuned--;
	}
}

static int w_block_precomputed(unsigned char *salt)
{
	unsigned char *padding;
	uint64_t msgLen;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	if (salt == NULL)
		return 0;

	global_work_size = GET_MULTIPLE_OR_BIGGER(1, local_work_size); //count

	padding =
	    (unsigned char *)calloc(BITLOCKER_PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding + 1, 0, 31);
	msgLen = (BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (i = 0; i < 8; i++)
		padding[BITLOCKER_PADDING_SIZE - 1 - i] =
		    (uint8_t)(msgLen >> (i * 8));

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_d,
		CL_TRUE, 0, BITLOCKER_SALT_SIZE * sizeof(char), salt, 0,
		NULL, multi_profilingEvent[0]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], padding_d,
		CL_TRUE, 0, BITLOCKER_PADDING_SIZE * sizeof(char), padding, 0,
		NULL, multi_profilingEvent[1]), "Copy data to gpu");


	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], block_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], w_blocks_d,
		CL_TRUE, 0, BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
		sizeof(unsigned int), w_blocks_h, 0,
		NULL, multi_profilingEvent[3]), "Copy result back");

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	return 1;
}



static void set_salt(void * cipher_salt_input)
{
	cur_salt = (bitlocker_custom_salt *) cipher_salt_input;

	w_block_precomputed(cur_salt->salt);
	if (!w_blocks_h) {
		error_msg("Error... Exit\n");
	}

#if 0
	printf("salt %x %x %x %x\n", cur_salt->salt[0], cur_salt->salt[1], cur_salt->salt[2], cur_salt->salt[3]);
	printf("nonce %x %x %x %x\n", cur_salt->iv[0], cur_salt->iv[1], cur_salt->iv[2], cur_salt->iv[3]);
	printf("wblocks %x %x %x %x\n", w_blocks_h[0], w_blocks_h[1], w_blocks_h[2], w_blocks_h[3]);
	printf("VMK %x %x %x %x\n", cur_salt->data[0], cur_salt->data[1], cur_salt->data[2], cur_salt->data[3]);
#endif

	tmpIV = (unsigned char *)calloc(BITLOCKER_IV_SIZE, sizeof(unsigned char));

	memset(tmpIV, 0, BITLOCKER_IV_SIZE);
	memcpy(tmpIV + 1, cur_salt->iv /* nonce */, BITLOCKER_NONCE_SIZE);
//	if (BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1 < 0)
//		error_msg("Nonce Error");

	*tmpIV = (unsigned char)(BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1);
	tmpIV[BITLOCKER_IV_SIZE - 1] = 1;

	tmp_global = (((unsigned int *)(tmpIV))[0]);
	IV0[0] =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);

	tmp_global = ((unsigned int *)(tmpIV + 4))[0];
	IV4[0] =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);

	tmp_global = ((unsigned int *)(tmpIV + 8))[0];
	IV8[0] =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);

	tmp_global = ((unsigned int *)(tmpIV + 12))[0];
	IV12[0] =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

#if 0
printf("crypt_all(%d), LWS = %d, GWS = %d w_blocks_h: %x, encryptedVMK[0]: %x [1]: %x [2]: %x\n", count, (int)*lws, (int)global_work_size, w_blocks_h[0], encryptedVMK[0], encryptedVMK[1], encryptedVMK[2]);
printf("crypt_all wblocks %x %x %x %x\n", w_blocks_h[0], w_blocks_h[1], w_blocks_h[2], w_blocks_h[3]);
printf("crypt_all VMK %x %x %x %x\n", cur_salt->data[0], cur_salt->data[1], cur_salt->data[2], cur_salt->data[3]);
printf("nonce %x %x %x %x\n", cur_salt->iv[0], cur_salt->iv[1], cur_salt->iv[2], cur_salt->iv[3]);
printf("IV0 %x  IV4 %x IV8 %x IV12 %x\n", IV0[0], IV4[0], IV8[0], IV12[0]);
#endif

	hostFound[0] = -1;

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], numPasswordsKernelDev,
		CL_FALSE, 0, sizeof(int), pcount, 0,
		NULL, multi_profilingEvent[0]), "Copy data to gpu");


	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], deviceEncryptedVMK,
		CL_FALSE, 0, BITLOCKER_VMK_SIZE * sizeof(char), cur_salt->data /* encryptedVMK */, 0,
		NULL, multi_profilingEvent[1]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], devicePassword,
		CL_FALSE, 0, count * BITLOCKER_MAX_INPUT_PASSWORD_LEN * sizeof(char), inbuffer, 0,
		NULL, multi_profilingEvent[2]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], devicePasswordSize,
		CL_FALSE, 0, count * sizeof(int), inbuffer_size, 0,
		NULL, multi_profilingEvent[3]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], deviceFound,
		CL_FALSE, 0, sizeof(int), hostFound, 0,
		NULL, multi_profilingEvent[4]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], w_blocks_d,
		CL_FALSE, 0, (BITLOCKER_SINGLE_BLOCK_SHA_SIZE *
	                                        BITLOCKER_ITERATION_NUMBER) * sizeof(unsigned int),
		w_blocks_h, 0,
		NULL, multi_profilingEvent[5]), "Copy data to gpu");

	i=0;
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], currentIterPtr,
		CL_FALSE, 0, sizeof(int), &i, 0,
		NULL, multi_profilingEvent[6]), "Copy data to gpu");


	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], output_hash,
		CL_FALSE, 0, count * BITLOCKER_INT_HASH_SIZE * sizeof(unsigned int), hash_zero, 0,
		NULL, multi_profilingEvent[7]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], IV0_dev,
		CL_FALSE, 0, sizeof(unsigned int), IV0, 0,
		NULL, multi_profilingEvent[8]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], IV4_dev,
		CL_FALSE, 0, sizeof(unsigned int), IV4, 0,
		NULL, multi_profilingEvent[9]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], IV8_dev,
		CL_FALSE, 0, sizeof(unsigned int), IV8, 0,
		NULL, multi_profilingEvent[10]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], IV12_dev,
		CL_FALSE, 0, sizeof(unsigned int), IV12, 0,
		NULL, multi_profilingEvent[11]), "Copy data to gpu");

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[12]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : ITERATIONS); i++) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], currentIterPtr,
		CL_FALSE, 0, sizeof(int), &i, 0,
		NULL, multi_profilingEvent[13]), "Copy iter num to gpu");

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[14]), "Run loop kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		opencl_process_event();
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[15]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], deviceFound,
		CL_TRUE, 0, sizeof(int), hostFound, 0,
		NULL, multi_profilingEvent[16]), "Copy result back");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	return count;
}

static int cmp_all(void *binary, int count)
{
	if (hostFound[0] >= 0) {
#if BITLOCKER_ENABLE_DEBUG == 1

		fprintf(stdout, "\n[BitCracker] -> Password found: #%d, %.*s\n",
		        hostFound[0] + 1, BITLOCKER_MAX_INPUT_PASSWORD_LEN,
		        (char *)(inbuffer +
		                 (hostFound[0] * BITLOCKER_MAX_INPUT_PASSWORD_LEN)));
#endif

		return 1;
	} else
		return 0;
}

static int cmp_one(void *binary, int index)
{
	if (hostFound[0] == index)
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
	char tmp[BITLOCKER_MAX_INPUT_PASSWORD_LEN + 2];
	int size = strlen(key);

	inbuffer_size[index] = size;
	memset(tmp, 0, BITLOCKER_MAX_INPUT_PASSWORD_LEN + 2);
	memcpy(tmp, key, size);
	if (size < 16)
		tmp[size] = 0x80;

	memcpy((inbuffer + (index * BITLOCKER_MAX_INPUT_PASSWORD_LEN)), tmp,
	       BITLOCKER_MAX_INPUT_PASSWORD_LEN);

}

static char *get_key(int index)
{
	static char ret[BITLOCKER_MAX_INPUT_PASSWORD_LEN + 1];

	memset(ret, '\0', BITLOCKER_MAX_INPUT_PASSWORD_LEN + 1);
	memcpy(ret, inbuffer + (index * BITLOCKER_MAX_INPUT_PASSWORD_LEN),
	       inbuffer_size[index]);

	return ret;
}

struct fmt_main fmt_opencl_bitlocker = {
{
	FORMAT_LABEL,
	FORMAT_NAME,
	ALGORITHM_NAME,
	BENCHMARK_COMMENT,
	BENCHMARK_LENGTH,
	BITLOCKER_MIN_INPUT_PASSWORD_LEN,
	BITLOCKER_MAX_INPUT_PASSWORD_LEN,
	BINARY_SIZE,
	BINARY_ALIGN,
	SALT_SIZE,
	SALT_ALIGN,
	MIN_KEYS_PER_CRYPT,
	MAX_KEYS_PER_CRYPT,
	FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		//NULL
	opencl_bitlocker_tests
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
