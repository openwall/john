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
#include <time.h>
#include <ctype.h>

#include "common-opencl.h"
#include "opencl_device_info.h"
#include "config.h"
#include "options.h"
#include "misc.h"

#define CIPHERTEXT_LENGTH   64
#define BINARY_SIZE     0
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define FORMAT_LABEL            "bitlocker-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES OpenCL"
#define FORMAT_TAG				"$bitlocker$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)

#define BITLOCKER_JTR_HASH_SIZE 45
#define BITLOCKER_JTR_HASH_SIZE_CHAR 77
/*
#define MAX_PASSWORD_THREAD 8
#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 172032
*/
#define MIN_KEYS_PER_CRYPT	1 /* These will change in init() */
#define MAX_KEYS_PER_CRYPT	1
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
#define KERNEL_NAME "opencl_bitlocker_attack"
//Start size for gws
#define SEED 1024

static cl_kernel block_kernel;
static struct fmt_main *self;

static cl_mem salt_d, padding_d, w_blocks_d, deviceEncryptedVMK,
	devicePassword, devicePasswordSize, deviceFound;
static cl_int numPasswordsKernelDev;
static cl_int ciErr1;
static cl_int cl_error;

static unsigned int *w_blocks_h;
static unsigned char salt[BITLOCKER_SALT_SIZE], nonce[BITLOCKER_NONCE_SIZE],
       encryptedVMK[BITLOCKER_VMK_SIZE];
static unsigned char *tmpIV, *inbuffer;
static int *inbuffer_size;

//static FILE *diskImage;
static int *hostFound, totPsw, i;
static 	unsigned int tmp_global, IV0, IV4, IV8, IV12;

static int * numPasswordsKernel;
static int salt_done=0;

static struct fmt_tests tests[] = {
	{"$bitlocker$b0599ad6c6a1cf0103000000$0a8b9d0655d3900e9f67280adc27b5d7$033a16cb", "paperino"},
	{NULL}
};

static const char * warn[] = {
	"vmk xfer: ", "pw xfer: ", "pw_sz xfer: ", "found xfer: ", ", crypt: ", ", res xfer: "
};

static void w_block_precomputed(unsigned char *salt);

#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	size_t in_size = BITLOCKER_MAX_INPUT_PASSWORD_LEN * gws;

#define CLCREATEBUFFER(_flags, _size, _string)\
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);\
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);


	inbuffer = (unsigned char *)mem_calloc(in_size, sizeof(unsigned char));
	inbuffer_size = (int *)mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(int));
	hostFound = (int *)mem_calloc(1, sizeof(int));
	numPasswordsKernel = (int *)mem_calloc(1, sizeof(int));

	w_blocks_h = (unsigned int *)mem_calloc((BITLOCKER_SINGLE_BLOCK_SHA_SIZE *
	                                     BITLOCKER_ITERATION_NUMBER), sizeof(unsigned int));

	deviceEncryptedVMK = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                   					VMK_DECRYPT_SIZE * BITLOCKER_MAX_INPUT_PASSWORD_LEN * sizeof(unsigned char),
	                   					"Cannot allocate vmk");

	devicePassword = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                   					in_size * sizeof(unsigned char),
	                   					"Cannot allocate inbuffer");

	devicePasswordSize = CLCREATEBUFFER(CL_MEM_READ_ONLY,
	                   					in_size * sizeof(unsigned char),
	                   					"Cannot allocate inbuffer size");

	deviceFound = CLCREATEBUFFER(CL_MEM_WRITE_ONLY,
	                   					sizeof(int),
	                   					"Cannot allocate device found");

	w_blocks_d = CLCREATEBUFFER(CL_MEM_READ_WRITE,
	                   					BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER * sizeof(unsigned int),
	                   					"Cannot allocate w blocks");



	salt_d = CLCREATEBUFFER(CL_MEM_READ_ONLY,
           					BITLOCKER_SALT_SIZE * sizeof(char),
           					"Cannot allocate salt_d");

	printf("salt_d %p allocato %zu byte\n", salt_d, BITLOCKER_SALT_SIZE * sizeof(char));
	padding_d = CLCREATEBUFFER(CL_MEM_READ_ONLY,
           					BITLOCKER_PADDING_SIZE * sizeof(char),
           					"Cannot allocate padding_d");

	CLKERNELARG(crypt_kernel, 0, numPasswordsKernelDev, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 1, devicePassword, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 2, devicePasswordSize, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 3, deviceFound, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 4, deviceEncryptedVMK, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 5, w_blocks_d, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 6, IV0, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 7, IV4, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 8, IV8, "Error while setting numPasswordsKernelDev");
	CLKERNELARG(crypt_kernel, 9, IV12, "Error while setting numPasswordsKernelDev");

	memset(inbuffer, '\0', in_size);
/*
	CLKERNELARG(block_kernel, 0, salt_d, "Error while setting salt_d");
	CLKERNELARG(block_kernel, 1, padding_d, "Error while setting padding_d");
	CLKERNELARG(block_kernel, 2, w_blocks_d, "Error while setting w_blocks_d");
*/
}

static void release_clobj(void)
{
	if (deviceFound) {
		printf("release_clobj\n");
		//HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_in, inbuffer, 0, NULL, NULL), "Error Unmapping inbuffer");
		//HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_out, outbuffer, 0, NULL, NULL), "Error Unmapping outbuffer");
		//HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(deviceEncryptedVMK), "Release pinned_in");
		HANDLE_CLERROR(clReleaseMemObject(devicePassword), "Release mem_in");
		HANDLE_CLERROR(clReleaseMemObject(devicePasswordSize), "Release mem_salt");
		HANDLE_CLERROR(clReleaseMemObject(deviceFound), "Release pinned_out");

		//free(inbuffer);
		//free(inbuffer_size);
		//free(hostFound);
		//free(numPasswordsKernel);

		deviceFound = NULL;
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();
		HANDLE_CLERROR(clReleaseMemObject(w_blocks_d), "Release mem_out");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[512];

		printf("reset\n");
		opencl_init("$JOHN/kernels/bitlocker_kernel.cl", gpu_id, build_opts);

		//opencl_build_kernel("$JOHN/kernels/bitlocker_kernel.cl", gpu_id, build_opts, 0);

		///Create Kernel
		crypt_kernel = clCreateKernel(program[gpu_id], "opencl_bitlocker_attack", &ret_code);
		HANDLE_CLERROR(ret_code, "Error while creating kernel");

		block_kernel = clCreateKernel(program[gpu_id], "opencl_bitlocker_wblocks", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel_prepare. Double-check kernel name?");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER * sizeof(int), 0, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, 1000, 0, 500);
	}
#if 0
	char fileNameAttack[] = "$JOHN/kernels/bitlocker_kernel.cl", opt[1024];
	size_t deviceGlobalMem = 0;
	long int globalMemRequired = 0;

	num_pass_per_thread = MAX_PASSWORD_THREAD;



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
#endif
	return;
}

/* ------- Initialization  ------- */
static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

void w_block_precomputed(unsigned char *salt)
{
	unsigned char *padding;
	uint64_t msgLen;

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

//	opencl_build_kernel("$JOHN/kernels/wblock_kernel.cl", gpu_id, NULL, 0);

		printf("w_block_precomputed 0, salt[0]_ %x\n", salt[0]);


	printf("salt_d %p write %zu byte\n", salt_d, BITLOCKER_SALT_SIZE * sizeof(char));


	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], salt_d, CL_TRUE, 0,
	                         BITLOCKER_SALT_SIZE * sizeof(char), salt, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	printf("w_block_precomputed 1\n");


	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], padding_d, CL_TRUE, 0,
	                         BITLOCKER_PADDING_SIZE * sizeof(char), padding, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	printf("w_block_precomputed 3\n");

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

	ciErr1 =
	    clEnqueueNDRangeKernel(queue[gpu_id], block_kernel, 1, NULL,
	                           &global_work_size, &local_work_size,
	                           0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");

	ciErr1 = clEnqueueReadBuffer(queue[gpu_id], w_blocks_d, CL_TRUE, 0,
	                             BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                             sizeof(unsigned int), w_blocks_h, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	//HANDLE_CLERROR(clReleaseKernel(block_kernel), "clReleaseKernel");

	//clReleaseMemObject(salt_d);
	clReleaseMemObject(padding_d);
	free(padding);

	return;
}



static int valid(char *ciphertext, struct fmt_main *self)
{
	char *hash_format;
	char *p;

	if (strlen(ciphertext) != BITLOCKER_JTR_HASH_SIZE_CHAR)
		return 0;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	hash_format = strdup(ciphertext);
	hash_format += FORMAT_TAG_LEN;

	p = strtokm(hash_format, "$");
	if (strlen(p) != BITLOCKER_NONCE_SIZE * 2)
		return 0;

	p = strtokm(NULL, "$");
	if (strlen(p) != BITLOCKER_SALT_SIZE * 2)
		return 0;

	p = strtokm(NULL, "");
	if (strlen(p) != 8)
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	int i = 0;
	char *hash_format;
	char *p;

	memset(salt, 0, sizeof(salt));
	printf("get_salt, salt_done: %d\n", salt_done);
	if (salt_done > 0)
		return salt;

	salt_done=1;

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
}


static void set_salt(void *psalt)
{
	unsigned char * local_salt = (unsigned char *) salt;

	if (salt_done == 2)
		return;

	salt_done=2;

	printf("salt_done: %d set local_salt: %x - %x\n", salt_done, local_salt[0], local_salt[1]);
	w_block_precomputed(local_salt);
	if (!w_blocks_h) {
		error_msg("Error... Exit\n");
	}

	printf("w_blocks_h: %x\n", w_blocks_h[0]);
	tmpIV = (unsigned char *)calloc(BITLOCKER_IV_SIZE, sizeof(unsigned char));

	memset(tmpIV, 0, BITLOCKER_IV_SIZE);
	memcpy(tmpIV + 1, nonce, BITLOCKER_NONCE_SIZE);
	if (BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1 < 0)
		error_msg("Nonce Error");

	*tmpIV = (unsigned char)(BITLOCKER_IV_SIZE - 1 - BITLOCKER_NONCE_SIZE - 1);
	tmpIV[BITLOCKER_IV_SIZE - 1] = 1;

	tmp_global =
	(((unsigned int *)(tmpIV)) [0]);
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

static int crypt_all(int *count, struct db_salt *salt)
{
	int numPassword[1];
	size_t *lws = local_work_size ? &local_work_size : NULL;

	numPassword[0] = *count;
	global_work_size = GET_MULTIPLE_OR_BIGGER(numPassword[0], local_work_size);

#if BITLOCKER_ENABLE_DEBUG == 1
	time_t start, end;
	double dif;
	printf("\n[BitCracker] -> Starting Attack, #Passwords: %d\n", numPassword[0]);
	//, , Global Work Size: %zu, Local Work Size: %zu szGlobalWorkSize, szLocalWorkSize);
#endif

	printf("crypt all, numPassword: %d\n", numPassword[0]);

	numPasswordsKernelDev = numPassword[0];

/*
	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], w_blocks_d, CL_TRUE, 0,
	                         BITLOCKER_SINGLE_BLOCK_SHA_SIZE * BITLOCKER_ITERATION_NUMBER *
	                         sizeof(int), w_blocks_h, 0, NULL, multi_profilingEvent[1]);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");
*/

	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], deviceEncryptedVMK, CL_TRUE, 0,
	                         BITLOCKER_VMK_SIZE * sizeof(char), encryptedVMK, 0, NULL, multi_profilingEvent[0]);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");


	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], devicePassword, CL_TRUE, 0,
	                         numPassword[0] * BITLOCKER_MAX_INPUT_PASSWORD_LEN, inbuffer, 0, NULL, multi_profilingEvent[1]);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], devicePasswordSize, CL_TRUE, 0,
	                         numPassword[0] * sizeof(int), inbuffer_size, 0, NULL, multi_profilingEvent[2]);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

	hostFound[0] = -1;
	ciErr1 =
	    clEnqueueWriteBuffer(queue[gpu_id], deviceFound, CL_TRUE, 0,
	                         sizeof(int), hostFound, 0, NULL, multi_profilingEvent[3]);
	HANDLE_CLERROR(ciErr1, "clEnqueueWriteBuffer");

#if BITLOCKER_ENABLE_DEBUG == 1
	time(&start);
#endif

	//Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[4]),
		"Set ND range");
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], deviceFound, CL_TRUE, 0,
					sizeof(int), hostFound, 0, NULL, multi_profilingEvent[5]), "Copy data back");

	//Await completion of all the above
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish error");



#if 0

		ciErr1 =
	    clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
	                           &szGlobalWorkSize, &szLocalWorkSize, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");

	ciErr1 =
	    clEnqueueReadBuffer(queue[gpu_id], deviceFound, CL_TRUE, 0,
	                        sizeof(unsigned int), hostFound, 0, NULL, NULL);
	HANDLE_CLERROR(ciErr1, "clEnqueueNDRangeKernel");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");
#endif

#if BITLOCKER_ENABLE_DEBUG == 1

	time(&end);
	dif = difftime(end, start);

	printf
	("[BitCracker] -> Attack stats: %d passwords evaluated in %.2lf seconds => %.2f pwd/s\n",
	 numPassword[0], dif, (double)(numPassword[0] / dif));

#endif

	//HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	totPsw += numPassword[0];

	return numPassword[0];
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
		BITLOCKER_MAX_INPUT_PASSWORD_LEN,   //PLAINTEXT_LENGTH,
		BINARY_SIZE,
		MEM_ALIGN_WORD,     //BINARY_ALIGN,
		10,                 //BITLOCKER_SALT_SIZE,
		MEM_ALIGN_WORD,     //SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{NULL},
		{
			FORMAT_TAG
		},
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,  //split
		fmt_default_binary,
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
	}
};

#endif                          /* plugin stanza */

#endif /* HAVE_OPENCL */
