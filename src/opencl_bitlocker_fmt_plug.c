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

#include <string.h>
#include "common-opencl.h"
#include "opencl_device_info.h"
#include "config.h"
#include "options.h"
#include "misc.h"
#include <time.h>
#include <ctype.h>

#define CIPHERTEXT_LENGTH   64
#define BINARY_SIZE     32
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define FORMAT_LABEL            "bitlocker-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES OpenCL"

#define MAX_PASSWORD_THREAD 8
#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 172032
/*
 * On a GeForce Titan X: Assuming 896 threads for 24 SMs,
 * 8 password for each thread -> 896x24x8
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

#define BITLOCKER_ENABLE_DEBUG 0

#define BITLOCKER_JTR_HASH_SIZE 45
#define BITLOCKER_JTR_HASH_SIZE_CHAR 77
#define BITLOCKER_FORMAT_TAG           "$bitlocker$"
#define BITLOCKER_FORMAT_TAG_LEN       (sizeof(BITLOCKER_FORMAT_TAG)-1)

static cl_kernel prepare_kernel;
static struct fmt_main *self;

static cl_mem salt_d, padding_d, w_blocks_d, deviceEncryptedVMK,
       devicePassword, devicePasswordSize, deviceFound;
static cl_int ciErr1;
static size_t szGlobalWorkSize, szLocalWorkSize, maxDeviceWorkgroupSize;
static unsigned int *w_blocks_h;
static unsigned char salt[BITLOCKER_SALT_SIZE], nonce[BITLOCKER_NONCE_SIZE],
       encryptedVMK[BITLOCKER_VMK_SIZE];
static uint8_t tmpIV[BITLOCKER_IV_SIZE], *inbuffer, *outbuffer;
static int *inbuffer_size;

//static FILE *diskImage;
static int *hostFound, passwordBufferSize, numPassword, totPsw, i;
static int max_compute_units = 0;
static int num_pass_per_thread = 0;

static int var_max_keys_per_crypt = MAX_KEYS_PER_CRYPT;

static struct fmt_tests BitLocker_tests[] = {
	{"$bitlocker$b0599ad6c6a1cf0103000000$0a8b9d0655d3900e9f67280adc27b5d7$033a16cb"},  // password --> "paperino"
	{NULL}
};

static void w_block_precomputed(unsigned char *salt);

//void cpu_print_hex(unsigned char hash[], int size);
//void readData(FILE *diskImage);
//void fillBuffer(FILE *fp, unsigned char *buffer, int size);

#include "opencl-autotune.h"

static void reset(struct db_main *db)
{
	char fileNameAttack[] = "$JOHN/kernels/bitlocker_kernel.cl", opt[1024];
	size_t deviceGlobalMem = 0;
	long int globalMemRequired = 0;

	num_pass_per_thread = MAX_PASSWORD_THREAD;

	if (gpu_nvidia(device_info[gpu_id])) {
		if (nvidia_sm_5x(device_info[gpu_id]))
			snprintf(opt, sizeof(opt), "-D DEV_NVIDIA_SM50=1"); //-cl-nv-verbose
		else
			snprintf(opt, sizeof(opt), "-D DEV_NVIDIA_SM50=0");
	} else
		snprintf(opt, sizeof(opt), "-D DEV_NVIDIA_SM50=0");

	opencl_build_kernel(fileNameAttack, gpu_id, opt, 0);
	crypt_kernel =
	    clCreateKernel(program[gpu_id], "opencl_bitlocker_attack", &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateKernel");

	while (1) {
		szLocalWorkSize =
		    autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
		szGlobalWorkSize = autotune_get_task_max_size(1, 0, num_pass_per_thread,
		                   crypt_kernel); // num_pass_per_thread

		deviceGlobalMem = get_max_mem_alloc_size(gpu_id);
		globalMemRequired = (BITLOCKER_SINGLE_BLOCK_SHA_SIZE *
		                     BITLOCKER_ITERATION_NUMBER * sizeof(int))    //FIXED AMOUNT REQUIRED
		                    + 40 + 16 +
		                    (szGlobalWorkSize /* * num_pass_per_thread */  *
		                     BITLOCKER_MAX_INPUT_PASSWORD_LEN)
		                    * BITLOCKER_MAX_INPUT_PASSWORD_LEN * sizeof(unsigned char);

		if (globalMemRequired > deviceGlobalMem)
			num_pass_per_thread--;
		else
			break;

		if (num_pass_per_thread < 1) {
			error_msg
			("Error global memory size! Required: %ld, Available: %ld GPU_ID: %d\n",
			 globalMemRequired, deviceGlobalMem, gpu_id);
		}
	}

	if (num_pass_per_thread < 1)
		error_msg
		("Error global memory size! Required: %ld, Available: %ld GPU_ID: %d\n",
		 globalMemRequired, deviceGlobalMem, gpu_id);

	db->format->params.max_keys_per_crypt =
	    szGlobalWorkSize;   //*num_pass_per_thread;
	var_max_keys_per_crypt = szGlobalWorkSize;
	numPassword = szGlobalWorkSize; //num_pass_per_thread;

	deviceEncryptedVMK =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	                   VMK_DECRYPT_SIZE * BITLOCKER_MAX_INPUT_PASSWORD_LEN * sizeof(uint8_t),
	                   NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");

	devicePassword =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                   numPassword * BITLOCKER_MAX_INPUT_PASSWORD_LEN * sizeof(unsigned char),
	                   NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");

	devicePasswordSize =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                   numPassword * sizeof(int), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");


	deviceFound =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
	                   sizeof(unsigned int), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");


	w_blocks_d =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                   BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                   sizeof(unsigned int), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");
	return;
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_prepare_dev(gpu_id);
	max_compute_units = get_max_compute_units(gpu_id);
	maxDeviceWorkgroupSize = get_device_max_lws(gpu_id);

	inbuffer = NULL;
	inbuffer_size = NULL;
	outbuffer = NULL;

	numPassword =
	    (int)maxDeviceWorkgroupSize * max_compute_units *
	    BITLOCKER_MAX_INPUT_PASSWORD_LEN;
	passwordBufferSize =
	    (int)numPassword * BITLOCKER_MAX_INPUT_PASSWORD_LEN *
	    sizeof(unsigned char);

	inbuffer =
	    (unsigned char *)calloc(passwordBufferSize, sizeof(unsigned char));
	inbuffer_size = (int *)calloc(MAX_KEYS_PER_CRYPT, sizeof(int));
	hostFound = (int *)calloc(1, sizeof(int));
	outbuffer =
	    (unsigned char *)calloc(BITLOCKER_MAX_INPUT_PASSWORD_LEN + 2,
	                            sizeof(unsigned char));

	memset(inbuffer, 0,
	       (sizeof(uint8_t) * (BITLOCKER_MAX_INPUT_PASSWORD_LEN +
	                           2) * MAX_KEYS_PER_CRYPT));
	memset(inbuffer_size, 0, (sizeof(int) * MAX_KEYS_PER_CRYPT));
	memset(outbuffer, 0,
	       (sizeof(uint8_t) * (BITLOCKER_MAX_INPUT_PASSWORD_LEN + 2) * 1));

}

void w_block_precomputed(unsigned char *salt)
{
	char fileNameWBlocks[] = "$JOHN/kernels/bitlocker_kernel.cl";
	char *opt = NULL;
	unsigned char *padding;
	uint64_t msgLen;
	int iter_num = BITLOCKER_ITERATION_NUMBER;

	if (salt == NULL)
		return;

	padding =
	    (unsigned char *)calloc(BITLOCKER_PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding + 1, 0, 31);
	msgLen = (BITLOCKER_FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (i = 0; i < 8; i++)
		padding[BITLOCKER_PADDING_SIZE - 1 - i] =
		    (uint8_t)(msgLen >> (i * 8));

	salt_d =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                   BITLOCKER_SALT_SIZE * sizeof(unsigned char), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");

	padding_d =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                   BITLOCKER_PADDING_SIZE * sizeof(unsigned char), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");

	w_blocks_d = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
	                            BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                            sizeof(int), NULL, &ciErr1);
	HANDLE_CLERROR(ciErr1, "clCreateBuffer");

	w_blocks_h = (unsigned int *)calloc((BITLOCKER_SINGLE_BLOCK_SHA_SIZE *
	                                     BITLOCKER_ITERATION_NUMBER), sizeof(unsigned int));
	if (!w_blocks_h)
		goto out;

	opencl_build_kernel(fileNameWBlocks, gpu_id, opt, 0);
	prepare_kernel =
	    clCreateKernel(program[gpu_id], "opencl_bitlocker_wblocks", &ciErr1);
	HANDLE_CLERROR(ciErr1,
	               "Error creating kernel_prepare. Double-check kernel name?");

	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], salt_d, CL_TRUE, 0,
	                         BITLOCKER_SALT_SIZE * sizeof(unsigned char), salt, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");
	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], padding_d, CL_TRUE, 0,
	                         BITLOCKER_PADDING_SIZE * sizeof(unsigned char), padding, 0, NULL,
	                         NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	ciErr1 =
	    clSetKernelArg(prepare_kernel, 0, sizeof(cl_int), (void *)&iter_num);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");
	ciErr1 =
	    clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem), (void *)&salt_d);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");
	ciErr1 =
	    clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem), (void *)&padding_d);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");
	ciErr1 =
	    clSetKernelArg(prepare_kernel, 3, sizeof(cl_mem), (void *)&w_blocks_d);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	szLocalWorkSize = get_kernel_max_lws(gpu_id, prepare_kernel);
	szGlobalWorkSize = szLocalWorkSize * max_compute_units;

	ciErr1 =
	    clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1, NULL,
	                           &szGlobalWorkSize, &szLocalWorkSize, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");

	ciErr1 = clEnqueueReadBuffer(queue[gpu_id], w_blocks_d, CL_TRUE, 0,
	                             BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                             sizeof(unsigned int), w_blocks_h, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

out:

	HANDLE_CLERROR(clReleaseKernel(prepare_kernel), "clReleaseKernel");

	clReleaseMemObject(salt_d);
	clReleaseMemObject(padding_d);
	clReleaseMemObject(w_blocks_d);
	free(padding);

	return;
}



static int valid(char *ciphertext, struct fmt_main *self)
{
	int i = 0;
	char *hash_format;
	char *p;

	if (!ciphertext)
		error_msg("No hash specified\n");

	if (ciphertext[0] == '*' && strlen(ciphertext) == 1)
		error_msg("Error ciphertext, '*' returned\n");

	if (strlen(ciphertext) != BITLOCKER_JTR_HASH_SIZE_CHAR)
		error_msg("Incorrect input hash format size");

	if (strncmp(ciphertext, BITLOCKER_FORMAT_TAG, BITLOCKER_FORMAT_TAG_LEN))
		error_msg("Incorrect input hash format");

	hash_format = strdup(ciphertext);
	hash_format += BITLOCKER_FORMAT_TAG_LEN;

	p = strtokm(hash_format, "$");
	if (strlen(p) != BITLOCKER_NONCE_SIZE * 2)
		error_msg("Incorrect input hash format");

	p = strtokm(NULL, "$");
	if (strlen(p) != BITLOCKER_SALT_SIZE * 2)
		error_msg("Incorrect input hash format");

	p = strtokm(NULL, "");
	if (strlen(p) != 8)
		error_msg("Incorrect input hash format");

	return 1;
}

static void *get_binary(char *ciphertext)
{
	return ciphertext;
}

static void *get_salt(char *ciphertext)
{
	int i = 0;
	char *hash_format;
	char *p;

	hash_format = strdup(ciphertext);
	hash_format += BITLOCKER_FORMAT_TAG_LEN;

	p = strtokm(hash_format, "$");
	if (strlen(p) != BITLOCKER_NONCE_SIZE * 2)
		error_msg("Incorrect input hash format");
		          strlen(p));
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
		error_msg("Incorrect input hash format");
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
		error_msg("Incorrect input hash format");
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

	w_block_precomputed(salt);
	if (!w_blocks_h) {
		error_msg("Error... Exit\n");
	}

	memset(tmpIV, 0, BITLOCKER_IV_SIZE);
	memcpy(tmpIV + 1, nonce, BITLOCKER_NONCE_SIZE);
	if (BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1 < 0)
		error_msg("Nonce Error");

	*tmpIV = (unsigned char)(BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1);
	tmpIV[BITLOCKER_IV_SIZE - 1] = 1;

	return tmpIV;
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

	memcpy(ret, inbuffer + (index * BITLOCKER_MAX_INPUT_PASSWORD_LEN),
	       inbuffer_size[index]);
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int numPassword = count;
	unsigned int tmp_global, IV0, IV4, IV8, IV12;

#if BITLOCKER_ENABLE_DEBUG == 1
	time_t start, end;
	double dif;
#endif

	numPassword = count;
	passwordBufferSize =
	    numPassword * BITLOCKER_MAX_INPUT_PASSWORD_LEN * sizeof(uint8_t);

#if BITLOCKER_ENABLE_DEBUG == 1
	printf
	("\n[BitCracker] -> Starting Attack, #Passwords: %d, Global Work Size: %zu, Local Work Size: %zu\n",
	 numPassword, szGlobalWorkSize, szLocalWorkSize);
#endif

	tmp_global = (unsigned int)(((unsigned int *)tmpIV)[0]);
	IV0 =
	    (unsigned int)(((unsigned int)(tmp_global & 0xff000000)) >> 24) |
	    (unsigned int)((unsigned int)(tmp_global & 0x00ff0000) >> 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x0000ff00) << 8) |
	    (unsigned int)((unsigned int)(tmp_global & 0x000000ff) << 24);

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

	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], w_blocks_d, CL_TRUE, 0,
	                         BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                         sizeof(int), w_blocks_h, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], deviceEncryptedVMK, CL_TRUE, 0,
	                         BITLOCKER_VMK_SIZE * sizeof(char), encryptedVMK, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");


	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], devicePassword, CL_TRUE, 0,
	                         passwordBufferSize, inbuffer, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], devicePasswordSize, CL_TRUE, 0,
	                         numPassword * sizeof(int), inbuffer_size, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	hostFound[0] = -1;
	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], deviceFound, CL_TRUE, 0,
	                         sizeof(int), hostFound, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	ciErr1 =
	    clSetKernelArg(crypt_kernel, 0, sizeof(cl_int), (void *)&numPassword);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |=
	    clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
	                   (void *)&devicePassword);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |=
	    clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
	                   (void *)&devicePasswordSize);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |=
	    clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void *)&deviceFound);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |=
	    clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem),
	                   (void *)&deviceEncryptedVMK);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |=
	    clSetKernelArg(crypt_kernel, 5, sizeof(cl_mem), (void *)&w_blocks_d);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |= clSetKernelArg(crypt_kernel, 6, sizeof(cl_int), (void *)&IV0);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |= clSetKernelArg(crypt_kernel, 7, sizeof(cl_int), (void *)&IV4);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |= clSetKernelArg(crypt_kernel, 8, sizeof(cl_int), (void *)&IV8);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

	ciErr1 |= clSetKernelArg(crypt_kernel, 9, sizeof(cl_int), (void *)&IV12);
	HANDLE_CLERROR(ciErr1, "clSetKernelArg");

#if BITLOCKER_ENABLE_DEBUG == 1
	time(&start);
#endif


	ciErr1 =
	    clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
	                           &szGlobalWorkSize, &szLocalWorkSize, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");

	ciErr1 =
	    clEnqueueReadBuffer(queue[gpu_id], deviceFound, CL_TRUE, 0,
	                        sizeof(unsigned int), hostFound, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");

#if BITLOCKER_ENABLE_DEBUG == 1

	time(&end);
	dif = difftime(end, start);

	printf
	("[BitCracker] -> Attack stats: %d passwords evaluated in %.2lf seconds => %.2f pwd/s\n",
	 numPassword, dif, (double)(numPassword / dif));

#endif

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	totPsw += numPassword;

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

		return hostFound[0];
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
	if (hostFound[0] == index)
		return 1;
	else
		return 0;
}

static void done(void)
{
	if (w_blocks_d)
		HANDLE_CLERROR(clReleaseMemObject(w_blocks_d), "clReleaseMemObject");
	if (devicePassword)
		HANDLE_CLERROR(clReleaseMemObject(devicePassword),
		               "clReleaseMemObject");
	if (devicePasswordSize)
		HANDLE_CLERROR(clReleaseMemObject(devicePasswordSize),
		               "clReleaseMemObject");
	if (deviceEncryptedVMK)
		HANDLE_CLERROR(clReleaseMemObject(deviceEncryptedVMK),
		               "clReleaseMemObject");
	if (deviceFound)
		HANDLE_CLERROR(clReleaseMemObject(deviceFound), "clReleaseMemObject");
	if (crypt_kernel)
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "clReleaseKernel");


	return;
}

/*
static char *split(char *ciphertext, int index, struct fmt_main *self)
{
    return ciphertext;
}


static int get_hash_0(int index)
{
    return 0;
}
*/
struct fmt_main fmt_opencl_bitlocker = {
	{

		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		BITLOCKER_MIN_INPUT_PASSWORD_LEN,
		BITLOCKER_MAX_INPUT_PASSWORD_LEN,   //PLAINTEXT_LENGTH,
		BINARY_SIZE,
		MEM_ALIGN_WORD,     //BINARY_ALIGN,
		10,                 //BITLOCKER_SALT_SIZE,
		MEM_ALIGN_WORD,     //SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{NULL},
		{NULL},
		BitLocker_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,  //split
		get_binary,
		get_salt,
		{NULL},
		fmt_default_source,
		{
			fmt_default_binary_hash,    //binary_hash_0
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL
		},
		fmt_default_salt_hash,  //salt_hash
		NULL,
		fmt_default_set_salt,
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
	}
};

#endif                          /* plugin stanza */

#endif                          /* HAVE_OPENCL */
