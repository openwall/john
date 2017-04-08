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
 * This is a research project, therefore please contact or cite if
 * you want to use this source code.
 * More informations here: http://openwall.info/wiki/john/OpenCL-BitLocker
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
#include "stdint.h"
#include "formats.h"
#include "options.h"
#include "common-opencl.h"

#define FORMAT_LABEL            "bitlocker-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES OpenCL"
#define FORMAT_TAG              "$bitlocker$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define SALT_ALIGN		1
#define BITLOCKER_JTR_HASH_SIZE 45
#define BITLOCKER_JTR_HASH_SIZE_CHAR 77
#define MIN_KEYS_PER_CRYPT  1   /* These will change in init() */
#define MAX_KEYS_PER_CRYPT  1

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1

/*
#define PLAINTEXT_LENGTH	55
#define SALT_SIZE		sizeof(salt_t)
*/

#define BITLOCKER_HASH_SIZE 8   //32
#define BITLOCKER_ROUND_SHA_NUM 64
#define BITLOCKER_SINGLE_BLOCK_SHA_SIZE 64
#define BITLOCKER_SINGLE_BLOCK_W_SIZE 64
#define BITLOCKER_PADDING_SIZE 40
#define BITLOCKER_ITERATION_NUMBER 0x100000
#define BITLOCKER_WORD_SIZE 4
#define BITLOCKER_INPUT_SIZE 512
#define BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH 88
#define BITLOCKER_BLOCK_UNIT 32
#define BITLOCKER_HASH_SIZE_STRING 32
#define BITLOCKER_MAX_INPUT_PASSWORD_LEN 16
#define BITLOCKER_MIN_INPUT_PASSWORD_LEN 8

#define AUTHENTICATOR_LENGTH 16
#define AES_CTX_LENGTH 256
#define FALSE 0
#define TRUE 1
#define BITLOCKER_SALT_SIZE 16
#define BITLOCKER_MAC_SIZE 16
#define BITLOCKER_NONCE_SIZE 12
#define BITLOCKER_IV_SIZE 16
#define BITLOCKER_VMK_SIZE 44
#define VMK_DECRYPT_SIZE 16
#define DICT_BUFSIZE    (50*1024*1024)
#define MAX_PLEN 32
#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

#define BITLOCKER_ENABLE_DEBUG 1
#define WBLOCKS_KERNEL_NAME  		"opencl_bitlocker_wblocks"
#define ATTACK_KERNEL_NAME			"opencl_bitlocker_attack"
//#define ATTACK_SPLIT_KERNEL_NAME	"pbkdf2_sha256_loop"

#define HASH_LOOPS		1 //(13*71) // factors 13, 13, 71
#define ITERATIONS		1

/*
typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[8];
} crack_t;

typedef struct {
	uint8_t length;
	uint8_t salt[PBKDF2_32_MAX_SALT_SIZE];
	uint32_t rounds;
} salt_t;

typedef struct {
	uint32_t ipad[8];
	uint32_t opad[8];
	uint32_t hash[8];
	uint32_t W[8];
	uint32_t rounds;
} state_t;
*/

//NEW VAR BITLOCKER
static cl_kernel block_kernel;
static struct fmt_tests bitlocker_tests[] = {
	{"$bitlocker$b0599ad6c6a1cf0103000000$0a8b9d0655d3900e9f67280adc27b5d7$033a16cb", "paperino"},
	{NULL}
};

static cl_mem salt_d, padding_d, w_blocks_d, deviceEncryptedVMK,
       devicePassword, devicePasswordSize, deviceFound, numPasswordsKernelDev;
//static cl_int numPasswordsKernelDev;
static cl_int ciErr1;
static cl_int cl_error;

static unsigned int *w_blocks_h;
static unsigned char salt[BITLOCKER_SALT_SIZE], nonce[BITLOCKER_NONCE_SIZE],
       encryptedVMK[BITLOCKER_VMK_SIZE];
static unsigned char *tmpIV, *inbuffer;
static int *inbuffer_size;

//k93Lm;ld

static int *hostFound, totPsw, i;
static unsigned int tmp_global, IV0, IV4, IV8, IV12;

static int *numPasswordsKernel;

//#define DEBUG
static cl_int cl_error;
static cl_kernel split_kernel;
static cl_kernel block_kernel;
static struct fmt_main *self;

#define STEP			0
#define SEED			1024

static const char * warn[] = {
        "xfer: ",  ", init: " , ", crypt: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

static int w_block_precomputed(unsigned char *salt);


// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static int salt_evaluated=0;

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
	
	size_t in_size = BITLOCKER_MAX_INPUT_PASSWORD_LEN * gws;

	// ---- MAIN ATTACK
	inbuffer = (unsigned char *)mem_calloc(in_size, sizeof(unsigned char));
	inbuffer_size = (int *)mem_calloc(in_size, sizeof(int));
	hostFound = (int *)mem_calloc(1, sizeof(int));
	w_blocks_h = (unsigned int *)mem_calloc((BITLOCKER_SINGLE_BLOCK_SHA_SIZE *
	                                        BITLOCKER_ITERATION_NUMBER), sizeof(unsigned int));

	numPasswordsKernelDev = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                                    sizeof(int), "Cannot allocate numPass");


	deviceEncryptedVMK = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                                    VMK_DECRYPT_SIZE * BITLOCKER_MAX_INPUT_PASSWORD_LEN *
	                                    sizeof(unsigned char), "Cannot allocate vmk");

	devicePassword = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                                in_size * sizeof(unsigned char), "Cannot allocate inbuffer");

	devicePasswordSize = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                                    in_size * sizeof(unsigned char), "Cannot allocate inbuffer size");

	deviceFound = CLCREATEBUFFER(CL_MEM_WRITE_ONLY,
	                             sizeof(int), "Cannot allocate device found");

	w_blocks_d = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                            BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                            sizeof(unsigned int), "Cannot allocate w blocks");

	CLKERNELARG(crypt_kernel, 0, numPasswordsKernelDev,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 1, devicePassword,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 2, devicePasswordSize,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 3, deviceFound,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 4, deviceEncryptedVMK,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 5, w_blocks_d,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 6, IV0,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 7, IV4,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 8, IV8,
	            "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 9, IV12,
	            "Error while setting numPasswordsKernelDev");

	//memset(inbuffer, '\0', in_size);

	if(salt_evaluated == 0)
	{
		printf("imposto salt, BITLOCKER_SALT_SIZE: %d\n", BITLOCKER_SALT_SIZE);
		// ---- W BLOCKS
		salt_d = CLCREATEBUFFER(CL_MEM_READ_ONLY,
		                        BITLOCKER_SALT_SIZE * sizeof(unsigned char), "Cannot allocate salt_d");
		padding_d =
		    CLCREATEBUFFER(CL_MEM_READ_ONLY, BITLOCKER_PADDING_SIZE * sizeof(unsigned char),
		                   "Cannot allocate padding_d");

		CLKERNELARG(block_kernel, 0, salt_d, "Error while setting salt_d");
		CLKERNELARG(block_kernel, 1, padding_d, "Error while setting padding_d");
		CLKERNELARG(block_kernel, 2, w_blocks_d, "Error while setting w_blocks_d");		
	}

//	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, block_kernel /* split_kernel */));
	return s;
}

static void release_clobj(void)
{
	if (hostFound[0] >= 0) {
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
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
/*
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%u",
		         HASH_LOOPS, PLAINTEXT_LENGTH);
*/
		opencl_init("$JOHN/kernels/bitlocker_kernel.cl", gpu_id, NULL);

		crypt_kernel =
			clCreateKernel(program[gpu_id], ATTACK_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

		block_kernel =
		    clCreateKernel(program[gpu_id], WBLOCKS_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error,
		               "Error creating block kernel");

/*
		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");
*/

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
		                       2, self, create_clobj, release_clobj,
		                       BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
		                       sizeof(int) /*sizeof(state_t)*/, 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, ITERATIONS, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel A");
		HANDLE_CLERROR(clReleaseKernel(block_kernel), "Release kernel W");
		
		//HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel 2");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
		               "Release Program");

		autotuned--;
	}
}

static void *get_salt(char *ciphertext)
{
	int i = 0;
	char *hash_format;
	char *p;

	memset(salt, 0, sizeof(salt));

	hash_format = strdup(ciphertext);
	hash_format += FORMAT_TAG_LEN;

	p = strtokm(hash_format, "$");
	if (strlen(p) != BITLOCKER_NONCE_SIZE * 2)
		return NULL;

	for (i = 0; i < BITLOCKER_NONCE_SIZE; i++) {
		nonce[i] =
		    (p[2 * i] <=
		     '9' ? p[2 * i] - '0' : toupper(p[2 * i]) - 'A' + 10) << 4;
		nonce[i] |=
		    p[(2 * i) + 1] <=
		    '9' ? p[(2 * i) + 1] - '0' : toupper(p[(2 * i) + 1]) - 'A' + 10;
#if BITLOCKER_ENABLE_DEBUG == 1
		printf("nonce[%d]=%02x\n", i, nonce[i]);
#endif
	}

	p = strtokm(NULL, "$");
	if (strlen(p) != BITLOCKER_SALT_SIZE * 2)
		return NULL;

	for (i = 0; i < BITLOCKER_SALT_SIZE; i++) {
		salt[i] =
		    (p[2 * i] <=
		     '9' ? p[2 * i] - '0' : toupper(p[2 * i]) - 'A' + 10) << 4;
		salt[i] |=
		    p[(2 * i) + 1] <=
		    '9' ? p[(2 * i) + 1] - '0' : toupper(p[(2 * i) + 1]) - 'A' + 10;
#if BITLOCKER_ENABLE_DEBUG == 1
		printf("salt[%d]=%02x\n", i, salt[i]);
#endif
	}

	p = strtokm(NULL, "");
	if (strlen(p) != 8)
		return NULL;

	for (i = 0; i < 4; i++) {
		encryptedVMK[i] =
		    (p[2 * i] <=
		     '9' ? p[2 * i] - '0' : toupper(p[2 * i]) - 'A' + 10) << 4;
		encryptedVMK[i] |=
		    p[(2 * i) + 1] <=
		    '9' ? p[(2 * i) + 1] - '0' : toupper(p[(2 * i) + 1]) - 'A' + 10;
#if BITLOCKER_ENABLE_DEBUG == 1
		printf("encryptedVMK[%d]=%02x\n", i, encryptedVMK[i]);
#endif
	}

	return salt;

//	return (void *)&salt;
}

int w_block_precomputed(unsigned char *salt)
{
	unsigned char *padding;
	uint64_t msgLen;

	if (salt == NULL)
		return 0;

	printf("local_work_size: %zu\n", local_work_size);
	size_t *lws = local_work_size ? &local_work_size : NULL;
	global_work_size = GET_MULTIPLE_OR_BIGGER(1, local_work_size); //count


	padding =
	    (unsigned char *)calloc(BITLOCKER_PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding + 1, 0, 31);
	msgLen = (BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (i = 0; i < 8; i++)
		padding[BITLOCKER_PADDING_SIZE - 1 - i] =
		    (uint8_t)(msgLen >> (i * 8));

	/*
	    salt_d =
	        clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                       BITLOCKER_SALT_SIZE * sizeof(unsigned char), NULL, &ciErr1);
	    HANDLE_CLERROR(ciErr1, "clCreateBuffer");

	    padding_d =
	        clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                       BITLOCKER_PADDING_SIZE * sizeof(unsigned char), NULL, &ciErr1);
	    HANDLE_CLERROR(ciErr1, "clCreateBuffer");

	    w_blocks_d_local = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
	                                BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                                sizeof(int), NULL, &ciErr1);
	    HANDLE_CLERROR(ciErr1, "clCreateBuffer");
	*/

//  opencl_build_kernel("$JOHN/kernels/wblock_kernel.cl", gpu_id, NULL, 0);

	printf("w_block_precomputed 0, salt[0]: %x, salt[1]: %x\n", salt[0], salt[1]);

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_d,
		CL_TRUE, 0, BITLOCKER_SALT_SIZE * sizeof(char), salt, 0,
		NULL, multi_profilingEvent[0]), "Copy data to gpu");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], padding_d,
		CL_TRUE, 0, BITLOCKER_PADDING_SIZE * sizeof(char), padding, 0,
		NULL, multi_profilingEvent[1]), "Copy data to gpu");

/*
	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], salt_d, CL_TRUE, 0,
	                         BITLOCKER_SALT_SIZE * sizeof(char), salt, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	printf("w_block_precomputed 1\n");


	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], padding_d, CL_TRUE, 0,
	                         BITLOCKER_PADDING_SIZE * sizeof(char), padding, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");
*/
	//printf("w_block_precomputed 3\n");

	/*
	    ciErr1 =
	        clSetKernelArg(block_kernel, 0, sizeof(cl_int), (void *)&iter_num);
	    HANDLE_CLERROR(ciErr1, "clSetKernelArg");
	*/
	/*
	   ciErr1 =
	   clSetKernelArg(block_kernel, 0, sizeof(cl_mem), (void *)&salt_d);
	   HANDLE_CLERROR(ciErr1, "clSetKernelArg");
	   ciErr1 =
	   clSetKernelArg(block_kernel, 1, sizeof(cl_mem), (void *)&padding_d);
	   HANDLE_CLERROR(ciErr1, "clSetKernelArg");
	   ciErr1 =
	   clSetKernelArg(block_kernel, 2, sizeof(cl_mem), (void *)&w_blocks_d);
	   HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	   max_compute_units = get_max_compute_units(gpu_id);
	   szLocalWorkSize = get_kernel_max_lws(gpu_id, block_kernel);
	   szGlobalWorkSize = szLocalWorkSize * max_compute_units;

	   printf("dopo di szLocalWorkSize: %zu, szGlobalWorkSize: %zu\n",
	   szLocalWorkSize, szGlobalWorkSize);
	 */
	fprintf(stderr, "lws %zu gws %zu\n", *lws, global_work_size);
#if 0
	
	ciErr1 =
	    clEnqueueNDRangeKernel(queue[gpu_id], block_kernel, 1, NULL,
	                           &global_work_size, &local_work_size, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");

	ciErr1 = clEnqueueReadBuffer(queue[gpu_id], w_blocks_d, CL_TRUE, 0,
	                             BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                             sizeof(unsigned int), w_blocks_h, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");
#endif 

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], block_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], w_blocks_d,
		CL_TRUE, 0, BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
		sizeof(unsigned int), w_blocks_h, 0,
		NULL, multi_profilingEvent[3]), "Copy result back");


//	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");
//	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	//HANDLE_CLERROR(clReleaseKernel(block_kernel), "clReleaseKernel");

	//clReleaseMemObject(salt_d);
//	clReleaseMemObject(padding_d);
//	free(padding);

	return 1;
}


static void set_salt(void *salt)
{
	unsigned char *local_salt = (unsigned char *)salt;

//	if(salt_evaluated > 0)
//		return;

//	salt_evaluated = 1;

// avoid repeat salt calculation??	
	printf("set local_salt: %x - %x\n", local_salt[0], local_salt[1]);
	w_block_precomputed(local_salt);
	if (!w_blocks_h) {
		error_msg("Error... Exit\n");
	}

//	printf("w_blocks_h: %x\n", w_blocks_h[0]);
	tmpIV = (unsigned char *)calloc(BITLOCKER_IV_SIZE, sizeof(unsigned char));

	memset(tmpIV, 0, BITLOCKER_IV_SIZE);
	memcpy(tmpIV + 1, nonce, BITLOCKER_NONCE_SIZE);
	if (BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1 < 0)
		error_msg("Nonce Error");

	*tmpIV = (unsigned char)(BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1);
	tmpIV[BITLOCKER_IV_SIZE - 1] = 1;

	tmp_global = (((unsigned int *)(tmpIV))[0]);
	IV0 =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);
//	printf("IV0: %x\n", IV0);

	tmp_global = ((unsigned int *)(tmpIV + 4))[0];
	IV4 =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);

	tmp_global = ((unsigned int *)(tmpIV + 8))[0];
	IV8 =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);

	tmp_global = ((unsigned int *)(tmpIV + 12))[0];
	IV12 =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	//int loops = (host_salt->rounds + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);	
	printf("crypt_all(%d), LWS = %d, GWS = %d w_blocks_h: %x\n", count, (int)*lws, (int)global_work_size, w_blocks_h[0]);

	hostFound[0] = -1;

	//for(i=0; i<count; i++)
	//		printf("inbuffer[%d]: %s, inbuffer_size[%d]: %d, pcount=%d\n", i, inbuffer[i], i, inbuffer_size[i], count);

printf("encryptedVMK[0]: %x [1]: %x [2]: %x\n", encryptedVMK[0], encryptedVMK[1], encryptedVMK[2]);

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], numPasswordsKernelDev,
		CL_FALSE, 0, sizeof(int), pcount, 0,
		NULL, multi_profilingEvent[0]), "Copy data to gpu");


	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], deviceEncryptedVMK,
		CL_FALSE, 0, BITLOCKER_VMK_SIZE * sizeof(char), encryptedVMK, 0,
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


//#if BITLOCKER_ENABLE_DEBUG == 1
//	time(&start);
//#endif

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
		1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[6]), "Run kernel");

/*
	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], split_kernel,
			1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}
*/
	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], deviceFound,
		CL_TRUE, 0, sizeof(int), hostFound, 0,
		NULL, multi_profilingEvent[7]), "Copy result back");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

/*
#if BITLOCKER_ENABLE_DEBUG == 1

	time(&end);
	dif = difftime(end, start);

	printf
	("[BitCracker] -> Attack stats: %d passwords evaluated in %.2lf seconds => %.2f pwd/s\n",
	 count, dif, (double)(count / dif));

#endif
*/
	totPsw += count;

	return count;
}

static int cmp_all(void *binary, int count)
{
	//printf("hostFound[0]: %d, count: %d\n", hostFound[0], count);
	if (hostFound[0] >= 0) {
//#if BITLOCKER_ENABLE_DEBUG == 1

		fprintf(stdout, "\n[BitCracker] -> Password found: #%d, %.*s\n",
		        hostFound[0] + 1, BITLOCKER_MAX_INPUT_PASSWORD_LEN,
		        (char *)(inbuffer +
		                 (hostFound[0] * BITLOCKER_MAX_INPUT_PASSWORD_LEN)));
//#endif

		return 1; //hostFound[0]+1;
	} else
		return 0;
}

static int cmp_one(void *binary, int index)
{
	//printf("cmp_one, hostFound[0]: %d, index: %d, binary: %s\n", hostFound[0], index, binary);
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

	//printf("set_key, index=%d, key=%s\n", index, tmp);

	memcpy((inbuffer + (index * BITLOCKER_MAX_INPUT_PASSWORD_LEN)), tmp,
	       BITLOCKER_MAX_INPUT_PASSWORD_LEN);

}

static char *get_key(int index)
{
	static char ret[BITLOCKER_MAX_INPUT_PASSWORD_LEN + 1];

	memset(ret, '\0', BITLOCKER_MAX_INPUT_PASSWORD_LEN + 1);
	memcpy(ret, inbuffer + (index * BITLOCKER_MAX_INPUT_PASSWORD_LEN),
	       inbuffer_size[index]);

	//printf("get_key(%d), inbuffer_size[index]=%d, ret=%s", index, inbuffer_size[index], ret);

	return ret;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *hash_format;
	char *p;
	int i;

	if (strlen(ciphertext) != BITLOCKER_JTR_HASH_SIZE_CHAR)
		return 0;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	hash_format = strdup(ciphertext);
	hash_format += FORMAT_TAG_LEN;

	p = strtokm(hash_format, "$");
	if (strlen(p) != BITLOCKER_NONCE_SIZE * 2)
		return 0;

	for (i = 0; i < BITLOCKER_NONCE_SIZE; i++) {
		nonce[i] =
		    (p[2 * i] <=
		     '9' ? p[2 * i] - '0' : toupper(p[2 * i]) - 'A' + 10) << 4;
		nonce[i] |=
		    p[(2 * i) + 1] <=
		    '9' ? p[(2 * i) + 1] - '0' : toupper(p[(2 * i) + 1]) - 'A' + 10;
#if BITLOCKER_ENABLE_DEBUG == 1
		printf("nonce_valid[%d]=%02x\n", i, nonce[i]);
#endif
	}

	p = strtokm(NULL, "$");
	if (strlen(p) != BITLOCKER_SALT_SIZE * 2)
		return 0;

	p = strtokm(NULL, "");
	if (strlen(p) != 8)
		return 0;

	for (i = 0; i < 4; i++) {
		encryptedVMK[i] =
		    (p[2 * i] <=
		     '9' ? p[2 * i] - '0' : toupper(p[2 * i]) - 'A' + 10) << 4;
		encryptedVMK[i] |=
		    p[(2 * i) + 1] <=
		    '9' ? p[(2 * i) + 1] - '0' : toupper(p[(2 * i) + 1]) - 'A' + 10;
#if BITLOCKER_ENABLE_DEBUG == 1
		printf("encryptedVMK_valid[%d]=%02x\n", i, encryptedVMK[i]);
#endif
	}

	return 1;
}

#if 0
	static int binary_hash_0(void *binary)
	{
	#if 0
		uint32_t i, *b = binary;
		puts("binary");
		for (i = 0; i < 8; i++)
			printf("%08x ", b[i]);
		puts("");
	#endif
		return (((uint32_t *) binary)[0] & PH_MASK_0);
	}

	static int get_hash_0(int index)
	{
	#if 0
		uint32_t i;
		puts("get_hash");
		for (i = 0; i < 8; i++)
			printf("%08x ", ((uint32_t *) host_crack[index].hash)[i]);
		puts("");
	#endif
		return host_crack[index].hash[0] & PH_MASK_0;
	}

	static int get_hash_1(int index)
	{
		return host_crack[index].hash[0] & PH_MASK_1;
	}

	static int get_hash_2(int index)
	{
		return host_crack[index].hash[0] & PH_MASK_2;
	}

	static int get_hash_3(int index)
	{
		return host_crack[index].hash[0] & PH_MASK_3;
	}

	static int get_hash_4(int index)
	{
		return host_crack[index].hash[0] & PH_MASK_4;
	}

	static int get_hash_5(int index)
	{
		return host_crack[index].hash[0] & PH_MASK_5;
	}

	static int get_hash_6(int index)
	{
		return host_crack[index].hash[0] & PH_MASK_6;
	}
#endif

static unsigned int iteration_count(void *salt)
{
	//return randoms num
	return 1;
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
	0, //BITLOCKER_JTR_HASH_SIZE_CHAR, //BINARY_SIZE,
	MEM_ALIGN_WORD,     //BINARY_ALIGN,
	BITLOCKER_SALT_SIZE,
	SALT_ALIGN,
	1,
	1,
	FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		//NULL
	bitlocker_tests
}, {
	init,
	done,
	reset,
	fmt_default_prepare,
	valid,
	fmt_default_split,
	fmt_default_binary,
	get_salt,
		{
			iteration_count,
		},
	fmt_default_source,
	{
		fmt_default_binary_hash,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
		/*
		binary_hash_0,
		fmt_default_binary_hash_1,
		fmt_default_binary_hash_2,
		fmt_default_binary_hash_3,
		fmt_default_binary_hash_4,
		fmt_default_binary_hash_5,
		fmt_default_binary_hash_6
*/
	},
	fmt_default_salt_hash,
	NULL,
	set_salt,
	set_key,
	get_key,
	fmt_default_clear_keys,
	crypt_all,
	{
		fmt_default_get_hash,   //get_hash_0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	},
	cmp_all,
	cmp_one,
	cmp_exact
}};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
