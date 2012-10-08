/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 *
 * MD5 OpenCL code is based on Alain Espinosa's OpenCL patches.
 *
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"

#define MD4_NUM_KEYS        1024*2048
#define PLAINTEXT_LENGTH    31
#define FORMAT_LABEL        "raw-md4-opencl"
#define FORMAT_NAME         "Raw MD4"
#define ALGORITHM_NAME      "OpenCL (inefficient, development use only)"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define CIPHERTEXT_LENGTH   32
#define BINARY_SIZE         16
#define SALT_SIZE           0

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys, data_info;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static char *saved_plain;
static char get_key_saved[PLAINTEXT_LENGTH + 1];

#define MIN_KEYS_PER_CRYPT      2048
#define MAX_KEYS_PER_CRYPT      MD4_NUM_KEYS
static unsigned int datai[2];
static int have_full_hashes;

static int max_keys_per_crypt = MD4_NUM_KEYS;

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{"$MD4$6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"$MD4$31d6cfe0d16ae931b73c59d7e0c089c0", "" },
	{"$MD4$934eb897904769085af8101ad9dabca2", "John the ripper" },
	{"$MD4$cafbb81fb64d9dd286bc851c4c6e0d21", "lolcode" },
	{"$MD4$585028aa0f794af812ee3be8804eb14a", "123456" },
	{"$MD4$23580e2a459f7ea40f9efa148b63cafb", "12345" },
	{"$MD4$2ae523785d0caf4d2fb557c12016185c", "123456789" },
	{"$MD4$f3e80e83b29b778bc092bf8a7c6907fe", "iloveyou" },
	{"$MD4$4d10a268a303379f224d8852f2d13f11", "princess" },
	{"$MD4$bf75555ca19051f694224f2f5e0b219d", "1234567" },
	{"$MD4$41f92cf74e3d2c3ba79183629a929915", "rockyou" },
	{"$MD4$012d73e0fab8d26e0f4d65e36077511e", "12345678" },
	{"$MD4$0ceb1fd260c35bd50005341532748de6", "abc123" },
	{NULL}
};

static void create_clobj(int kpc){
	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
		(PLAINTEXT_LENGTH + 1) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	saved_plain = (char *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys,
		CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0,
		(PLAINTEXT_LENGTH + 1) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");
	res_hashes = malloc(sizeof(cl_uint) * 3 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id],
		CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id],
		pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
		(PLAINTEXT_LENGTH + 1) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,
		BINARY_SIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	data_info = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, sizeof(unsigned int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating data_info out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(data_info),
		(void *) &data_info), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_keys),
		(void *) &buffer_keys), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out),
		(void *) &buffer_out), "Error setting argument 2");

	datai[0] = PLAINTEXT_LENGTH;
	datai[1] = kpc;
	global_work_size = kpc;
}

static void release_clobj(void){
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL);
	HANDLE_CLERROR(ret_code, "Error Ummapping partial_hashes");
	ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Ummapping saved_plain");
	ret_code = clReleaseMemObject(buffer_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
	ret_code = clReleaseMemObject(buffer_out);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");
	ret_code = clReleaseMemObject(data_info);
	HANDLE_CLERROR(ret_code, "Error Releasing data_info");
	ret_code = clReleaseMemObject(pinned_saved_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
	ret_code = clReleaseMemObject(pinned_partial_hashes);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
	MEM_FREE(res_hashes);
}

static void find_best_kpc(void){
	int num;
	cl_event myEvent;
	cl_ulong startTime, endTime, tmpTime;
	int kernelExecTimeNs = 6969;
	cl_int ret_code;
	int optimal_kpc=2048;
	int i = 0;
	cl_uint *tmpbuffer;

	fprintf(stderr, "Calculating best keys per crypt, this will take a while ");
	for( num=MD4_NUM_KEYS; num > 4096 ; num -= 4096){
		release_clobj();
		create_clobj(num);
		advance_cursor();
		queue_prof = clCreateCommandQueue( context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
		for (i=0; i < num; i++){
			memcpy(&(saved_plain[i * (PLAINTEXT_LENGTH + 1)]), "abcaaeaf", PLAINTEXT_LENGTH + 1);
			saved_plain[i * (PLAINTEXT_LENGTH + 1) + 8] = 0x80;
		}
        	clEnqueueWriteBuffer(queue_prof, data_info, CL_TRUE, 0, sizeof(unsigned int)*2, datai, 0, NULL, NULL);
		clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_TRUE, 0, (PLAINTEXT_LENGTH + 1) * num, saved_plain, 0, NULL, NULL);
    		ret_code = clEnqueueNDRangeKernel( queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &myEvent);
		if(ret_code != CL_SUCCESS) {
			HANDLE_CLERROR(ret_code, "Error running kernel in find_best_KPC()");
			continue;
		}
		clFinish(queue_prof);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);
		tmpTime = endTime-startTime;
		tmpbuffer = malloc(sizeof(cl_uint) * num);
		clEnqueueReadBuffer(queue_prof, buffer_out, CL_TRUE, 0, sizeof(cl_uint) * num, tmpbuffer, 0, NULL, &myEvent);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);
		tmpTime = tmpTime + (endTime-startTime);
		if( ((int)( ((float) (tmpTime) / num) * 10 )) <= kernelExecTimeNs) {
			kernelExecTimeNs = ((int) (((float) (tmpTime) / num) * 10) ) ;
			optimal_kpc = num;
		}
		MEM_FREE(tmpbuffer);
		clReleaseCommandQueue(queue_prof);
	}
	fprintf(stderr, "Optimal keys per crypt %d\n(to avoid this test on next run do \"export GWS=%d\")\n",optimal_kpc,optimal_kpc);
	max_keys_per_crypt = optimal_kpc;
	release_clobj();
	create_clobj(optimal_kpc);
}

static void init(struct fmt_main *self) {
	char *kpc;

	global_work_size = MAX_KEYS_PER_CRYPT;

	opencl_init("$JOHN/md4_kernel.cl", ocl_gpu_id, platform_id);
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "md4", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	create_clobj(MD4_NUM_KEYS);
	opencl_find_best_workgroup(self);
	release_clobj();
	if( (kpc = getenv("GWS")) == NULL){
		max_keys_per_crypt = MD4_NUM_KEYS;
		create_clobj(MD4_NUM_KEYS);
	} else {
		if (atoi(kpc) == 0){
			//user chose to die of boredom
			max_keys_per_crypt = MD4_NUM_KEYS;
			create_clobj(MD4_NUM_KEYS);
			find_best_kpc();
		} else {
			max_keys_per_crypt = atoi(kpc);
			create_clobj(max_keys_per_crypt);
		}
	}
	fprintf(stderr, "Local work size (LWS) %d, Global work size (GWS) %d\n",(int)local_work_size, max_keys_per_crypt);
	self->params.max_keys_per_crypt = max_keys_per_crypt;
}

static int valid(char *ciphertext, struct fmt_main *self) {
	char *p, *q;
	p = ciphertext;
	if (!strncmp(p, "$MD4$", 5))
		p += 5;
	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index) {
	static char out[5 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$MD4$", 5))
		return ciphertext;

	memcpy(out, "$MD4$", 5);
	memcpy(out + 5, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext) {
	static unsigned char out[BINARY_SIZE];
	char *p;
	int i;
	p = ciphertext + 5;
	for (i = 0; i < sizeof(out); i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}
static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *) binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

static int get_hash_0(int index) { return partial_hashes[index] & 0x0F; }
static int get_hash_1(int index) { return partial_hashes[index] & 0xFF; }
static int get_hash_2(int index) { return partial_hashes[index] & 0xFFF; }
static int get_hash_3(int index) { return partial_hashes[index] & 0xFFFF; }
static int get_hash_4(int index) { return partial_hashes[index] & 0xFFFFF; }
static int get_hash_5(int index) { return partial_hashes[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return partial_hashes[index] & 0x7FFFFFF; }

static void set_salt(void *salt) { }

static void set_key(char *key, int index) {
	int length = -1;
	int base = index * (PLAINTEXT_LENGTH + 1);
	do {
		length++;
		saved_plain[base + length] = key[length];
	}
	while (key[length]);
	memset(&saved_plain[base + length + 1], 0, 7);	// ugly hack which "should" work!
}

static char *get_key(int index) {
	int length = -1;
	int base = index * (PLAINTEXT_LENGTH + 1);
	do {
		length++;
		get_key_saved[length] = saved_plain[base + length];
	}
	while (get_key_saved[length]);
	get_key_saved[length] = 0;
	return get_key_saved;
}

static void crypt_all(int count)
{
#ifdef DEBUGVERBOSE
	int i, j;
	unsigned char *p = (unsigned char *) saved_plain;
	count--;
	for (i = 0; i < count + 1; i++) {
		fprintf(stderr, "\npassword : ");
		for (j = 0; j < 64; j++) {
			fprintf(stderr, "%02x ", p[i * 64 + j]);
		}
	}
	fprintf(stderr, "\n");
#endif
	// copy keys to the device
	HANDLE_CLERROR( clEnqueueWriteBuffer(queue[ocl_gpu_id], data_info, CL_TRUE, 0,
	    sizeof(unsigned int) * 2, datai, 0, NULL, NULL),
	    "failed in clEnqueueWriteBuffer data_info");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
	    (PLAINTEXT_LENGTH + 1) * max_keys_per_crypt, saved_plain, 0, NULL, NULL),
	    "failed in clEnqueueWriteBuffer buffer_keys");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
	    &global_work_size, &local_work_size, 0, NULL, profilingEvent),
	    "failed in clEnqueueNDRangeKernel");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]),"failed in clFinish");
	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0,
	    sizeof(cl_uint) * max_keys_per_crypt, partial_hashes, 0, NULL, NULL),
	    "failed in reading data back");
	have_full_hashes = 0;

#ifdef DEBUGVERBOSE
	p = (unsigned char *) partial_hashes;
	for (i = 0; i < 2; i++) {
		fprintf(stderr, "\n\npartial_hashes : ");
		for (j = 0; j < 16; j++)
			fprintf(stderr, "%02x ", p[i * 16 + j]);
	}
	fprintf(stderr, "\n");;
#endif
}

static int cmp_one(void *binary, int index){
	unsigned int *t = (unsigned int *) binary;

	if (t[0] == partial_hashes[index])
		return 1;
	return 0;
}

static int cmp_all(void *binary, int count) {
	unsigned int i = 0;
	unsigned int b = ((unsigned int *) binary)[0];
	for (; i < count; i++)
		if (b == partial_hashes[i])
			return 1;
	return 0;
}

static int cmp_exact(char *source, int count){
	unsigned int *t = (unsigned int *) get_binary(source);

	if (!have_full_hashes){
	clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
		sizeof(cl_uint) * (max_keys_per_crypt),
		sizeof(cl_uint) * 3 * max_keys_per_crypt, res_hashes, 0,
		NULL, NULL);
		have_full_hashes = 1;
	}

	if (t[1]!=res_hashes[count])
		return 0;
	if (t[2]!=res_hashes[1*max_keys_per_crypt+count])
		return 0;
	if (t[3]!=res_hashes[2*max_keys_per_crypt+count])
		return 0;
	return 1;
}

struct fmt_main fmt_opencl_rawMD4 = {
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
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
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
