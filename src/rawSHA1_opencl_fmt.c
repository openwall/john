/*
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * samu at linuxasylum dot net
 * Released under GPL license 
 */

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "common-opencl.h"

#define FORMAT_LABEL			"raw-sha1-opencl"
#define FORMAT_NAME			"Raw SHA-1 OpenCL"
#define ALGORITHM_NAME			"raw-sha1-opencl"
#define SHA_TYPE                        "SHA-1"
#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			0

#define SHA_BLOCK           		16
#define SSHA_NUM_KEYS               	1024*128

#define MIN_KEYS_PER_CRYPT		SSHA_NUM_KEYS
#define MAX_KEYS_PER_CRYPT		SSHA_NUM_KEYS

#ifndef uint32_t
#define uint32_t unsigned int
#endif

typedef struct {
	uint32_t h0,h1,h2,h3,h4;
} SHA_DEV_CTX;


cl_command_queue queue_prof;
cl_int ret_code;
cl_kernel sha1_crypt_kernel;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys, buffer_hash, len_buffer, data_info;
static cl_uint *outbuffer;
static char *inbuffer;
static size_t global_work_size = SSHA_NUM_KEYS;
static unsigned int datai[2];

static struct fmt_tests rawsha1_tests[] = {
	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{NULL}
};

static char saved_key[SSHA_NUM_KEYS][PLAINTEXT_LENGTH];

static void find_best_workgroup(void){
	cl_event myEvent;
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	size_t my_work_group = 1;
	cl_int ret_code;
	int i = 0;
	size_t max_group_size;

	clGetDeviceInfo(devices,CL_DEVICE_MAX_WORK_GROUP_SIZE,sizeof(max_group_size),&max_group_size,NULL );
	queue_prof = clCreateCommandQueue( context, devices, CL_QUEUE_PROFILING_ENABLE, &ret_code);
	printf("Max Group Work Size %d ",(int)max_group_size);
	local_work_size = 1;

	// Set keys
	for (; i < SSHA_NUM_KEYS; i++){
		memcpy(&(inbuffer[i*SHA_BLOCK]),"aaaaaaaa",SHA_BLOCK);
		inbuffer[i*SHA_BLOCK+8] = 0x80;
	}
        clEnqueueWriteBuffer(queue_prof, data_info, CL_TRUE, 0, sizeof(unsigned int)*2, datai, 0, NULL, NULL);
	clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_TRUE, 0, (SHA_BLOCK) * SSHA_NUM_KEYS, inbuffer, 0, NULL, NULL);

	// Find minimum time
	for(my_work_group=1 ;(int) my_work_group <= (int) max_group_size; my_work_group*=2){
    		ret_code = clEnqueueNDRangeKernel( queue_prof, sha1_crypt_kernel, 1, NULL, &global_work_size, &my_work_group, 0, NULL, &myEvent);
		clFinish(queue_prof);

		if(ret_code != CL_SUCCESS){
			printf("Errore %d\n",ret_code);
			continue;
		}

		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);

		if((endTime-startTime) < kernelExecTimeNs) {
			kernelExecTimeNs = endTime-startTime;
			local_work_size = my_work_group;
		}
		//printf("%d time=%ld\n",(int) my_work_group, endTime-startTime);
		//printf("wgS = %d\n",(int)my_work_group);
	}
	printf("Optimal Group work Size = %d\n",(int)local_work_size);
	clReleaseCommandQueue(queue_prof);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!((('0' <= ciphertext[i]) && (ciphertext[i] <= '9')) ||
			(('a' <= ciphertext[i]) && (ciphertext[i] <= 'f'))
			|| (('A' <= ciphertext[i]) && (ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void rawsha1_set_salt(void *salt)
{
}

static void rawsha1_opencl_init(struct fmt_main *pFmt)
{
    opencl_init("$JOHN/sha1_opencl_kernel.cl", CL_DEVICE_TYPE_GPU);

    // create kernel to execute
    sha1_crypt_kernel = clCreateKernel(program, "sha1_crypt_kernel", &ret_code);
    if_error_log(ret_code, "Error creating kernel. Double-check kernel name?");

    // create Page-Locked (Pinned) memory for higher bandwidth between host and device (Nvidia Best Practices)
    pinned_saved_keys = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (SHA_BLOCK)*SSHA_NUM_KEYS, NULL, &ret_code);
    if_error_log (ret_code, "Error creating page-locked memory");
    inbuffer = (char*)clEnqueueMapBuffer(queue, pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0, (SHA_BLOCK)*SSHA_NUM_KEYS, 0, NULL, NULL, &ret_code);
    if_error_log (ret_code, "Error mapping page-locked memory inbuffer");

    memset(inbuffer, 0, SHA_BLOCK * SSHA_NUM_KEYS);


    pinned_partial_hashes = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * SSHA_NUM_KEYS, NULL, &ret_code);
    if_error_log(ret_code, "Error creating page-locked memory");

    outbuffer = (cl_uint *) clEnqueueMapBuffer(queue, pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, sizeof(cl_uint) * SSHA_NUM_KEYS, 0, NULL, NULL, &ret_code);
    if_error_log(ret_code, "Error mapping page-locked memory outbuffer");

    // create and set arguments
    buffer_keys = clCreateBuffer(context, CL_MEM_READ_ONLY, (SHA_BLOCK) * SSHA_NUM_KEYS, NULL, &ret_code);
    if_error_log(ret_code, "Error creating buffer keys argument");

    buffer_out = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_uint) * 5 * SSHA_NUM_KEYS, NULL, &ret_code);
    if_error_log(ret_code, "Error creating buffer out argument");

    data_info = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int) * 2, NULL, &ret_code);
    if_error_log(ret_code, "Error creating data_info out argument");

    ret_code = clSetKernelArg(sha1_crypt_kernel, 0, 2 * sizeof(unsigned int), (void *) &data_info);
    if_error_log(ret_code, "Error setting argument 1");

    ret_code = clSetKernelArg(sha1_crypt_kernel, 1, sizeof(buffer_keys), (void *) &buffer_keys);
    if_error_log(ret_code, "Error setting argument 1");

    ret_code = clSetKernelArg(sha1_crypt_kernel, 2, sizeof(buffer_out), (void *) &buffer_out);
    if_error_log(ret_code, "Error setting argument 2");

    //local_work_size = 256;	// TODO: detect dynamically

    datai[0] = SHA_BLOCK;
    datai[1] = SSHA_NUM_KEYS;
    find_best_workgroup();
}

static void rawsha1_set_key(char *key, int index)
{
	int lenpwd;

	memset(saved_key[index], 0, PLAINTEXT_LENGTH);

	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH);
	lenpwd = strlen(saved_key[index]);

	memcpy(&(inbuffer[index * SHA_BLOCK]), saved_key[index], lenpwd);
	inbuffer[index * SHA_BLOCK + lenpwd] = 0x80;
}

static char *rawsha1_get_key(int index)
{
	return saved_key[index];
}

static int rawsha1_cmp_all(void *binary, int count)
{
	unsigned int i = 0;
	unsigned int b = ((unsigned int *) binary)[0];

	for (; i < count; i++)
		if (b == outbuffer[i])
			return 1;
	return 0;
}

static int rawsha1_cmp_exact(char *source, int count)
{
	return (1);
}

static int rawsha1_cmp_one(void *binary, int index)
{
	unsigned int *t = (unsigned int *) binary;
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;

	clEnqueueReadBuffer(queue, buffer_out, CL_TRUE,
	    sizeof(cl_uint) * (1 * SSHA_NUM_KEYS + index), sizeof(a),
	    (void *) &a, 0, NULL, NULL);
	if (t[1] != a)
		return 0;
	clEnqueueReadBuffer(queue, buffer_out, CL_TRUE,
	    sizeof(cl_uint) * (2 * SSHA_NUM_KEYS + index), sizeof(b),
	    (void *) &b, 0, NULL, NULL);
	if (t[2] != b)
		return 0;
	clEnqueueReadBuffer(queue, buffer_out, CL_TRUE,
	    sizeof(cl_uint) * (3 * SSHA_NUM_KEYS + index), sizeof(c),
	    (void *) &c, 0, NULL, NULL);
	if (t[3] != c)
		return 0;
	clEnqueueReadBuffer(queue, buffer_out, CL_TRUE,
	    sizeof(cl_uint) * (4 * SSHA_NUM_KEYS + index), sizeof(d),
	    (void *) &d, 0, NULL, NULL);
	return t[4] == d;

}

static void rawsha1_crypt_all(int count)
{
	cl_int code;

	code =
	    clEnqueueWriteBuffer(queue, data_info, CL_TRUE, 0,
	    sizeof(unsigned int) * 2, datai, 0, NULL, NULL);
	if (code != CL_SUCCESS) {
		printf
		    ("failed in clEnqueueWriteBuffer data_info with code %d\n",
		    code);
		exit(-1);
	}
	code =
	    clEnqueueWriteBuffer(queue, buffer_keys, CL_TRUE, 0,
	    (SHA_BLOCK) * SSHA_NUM_KEYS, inbuffer, 0, NULL, NULL);
	if (code != CL_SUCCESS) {
		printf
		    ("failed in clEnqueueWriteBuffer inbuffer with code %d\n",
		    code);
		exit(-1);
	}
	// execute ssha kernel
	code =
	    clEnqueueNDRangeKernel(queue, sha1_crypt_kernel, 1, NULL,
	    &global_work_size, &local_work_size, 0, NULL, NULL);
	if (code != CL_SUCCESS) {
		printf("failed in clEnqueueNDRangeKernel with code %d\n",
		    code);
		exit(-1);
	}
	clFinish(queue);
	// read back partial hashes
	clEnqueueReadBuffer(queue, buffer_out, CL_TRUE, 0,
	    sizeof(cl_uint) * SSHA_NUM_KEYS, outbuffer, 0, NULL, NULL);
}

static void *rawsha1_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;

	for (i = 0; i < BINARY_SIZE; i++) {
		realcipher[i] =
		    atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void *) realcipher;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }

static int get_hash_0(int index) { return outbuffer[index] & 0xF; }
static int get_hash_1(int index) { return outbuffer[index] & 0xFF; }
static int get_hash_2(int index) { return outbuffer[index] & 0xFFF; }
static int get_hash_3(int index) { return outbuffer[index] & 0xFFFF; }
static int get_hash_4(int index) { return outbuffer[index] & 0xFFFFF; }

struct fmt_main fmt_opencl_rawSHA1 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		rawsha1_tests
	}, {
		rawsha1_opencl_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		rawsha1_binary,
		fmt_default_salt,
		{
		     	binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		fmt_default_salt_hash,
		rawsha1_set_salt,
		rawsha1_set_key,
		rawsha1_get_key,
		fmt_default_clear_keys,
		rawsha1_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		rawsha1_cmp_all,
		rawsha1_cmp_one,
		rawsha1_cmp_exact
	}

};
