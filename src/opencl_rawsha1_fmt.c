/*
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * samu at linuxasylum dot net
 * This program comes with ABSOLUTELY NO WARRANTY; express or
 * implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
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
#define FORMAT_NAME			"Raw SHA-1"
#define ALGORITHM_NAME			"OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			0

#define SHA_NUM_KEYS               	1024*2048

#define MIN_KEYS_PER_CRYPT		2048
#define MAX_KEYS_PER_CRYPT		SHA_NUM_KEYS

#ifndef uint32_t
#define uint32_t unsigned int
#endif

typedef struct {
	uint32_t h0,h1,h2,h3,h4;
} SHA_DEV_CTX;


cl_command_queue queue_prof;
cl_int ret_code;
cl_kernel crypt_kernel;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys, data_info;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static char *saved_plain;
static unsigned int datai[2];
static int have_full_hashes;

static int max_keys_per_crypt = SHA_NUM_KEYS;

static struct fmt_tests tests[] = {
	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{"2fbf0eba37de1d1d633bc1ed943b907f9b360d4c", "azertyuiop1"},
	{"f879f8090e92232ed07092ebed6dc6170457a21d", "azertyuiop2"},
	{"1813c12f25e64931f3833b26e999e26e81f9ad24", "azertyuiop3"},
	{NULL}
};

//static char *saved_key;

static int valid(char *ciphertext, struct fmt_main *self){
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

static void set_salt(void *salt) { }

static void create_clobj(int kpc){
	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (PLAINTEXT_LENGTH)*kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_plain = (char*)clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ, 0, (PLAINTEXT_LENGTH)*kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");
	memset(saved_plain, 0, PLAINTEXT_LENGTH * kpc);
	res_hashes = malloc(sizeof(cl_uint) * 4 * kpc);
	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, (PLAINTEXT_LENGTH) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");
	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, sizeof(cl_uint) * 5 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");
	data_info = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, sizeof(unsigned int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating data_info out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(data_info), (void *) &data_info), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 2");

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

/*
   this function could be used to calculated the best num
   of keys per crypt for the given format
*/

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
	for( num=SHA_NUM_KEYS; num >= 4096 ; num -= 4096){
		release_clobj();
		create_clobj(num);
		advance_cursor();
		queue_prof = clCreateCommandQueue( context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
		for (i=0; i < num; i++){
			memcpy(&(saved_plain[i*PLAINTEXT_LENGTH]),"abacaeaf",PLAINTEXT_LENGTH);
		}
		clEnqueueWriteBuffer(queue_prof, data_info, CL_TRUE, 0, sizeof(unsigned int)*2, datai, 0, NULL, NULL);
		clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_TRUE, 0, (PLAINTEXT_LENGTH) * num, saved_plain, 0, NULL, NULL);
		ret_code = clEnqueueNDRangeKernel( queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &myEvent);
		if(ret_code != CL_SUCCESS){
			fprintf(stderr, "Error %d\n",ret_code);
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
	fprintf(stderr, "Optimal keys per crypt %d\n(to avoid this test on next run do export GWS=%d)\n",optimal_kpc,optimal_kpc);
	max_keys_per_crypt = optimal_kpc;
	release_clobj();
	create_clobj(optimal_kpc);
}

static void fmt_rawsha1_init(struct fmt_main *self) {
	char *kpc;

	global_work_size = MAX_KEYS_PER_CRYPT;

	opencl_init("$JOHN/sha1_kernel.cl", ocl_gpu_id, platform_id);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "sha1_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	create_clobj(SHA_NUM_KEYS);
	opencl_find_best_workgroup(self);
	release_clobj();
	if( (kpc = getenv("GWS")) == NULL){
		max_keys_per_crypt = SHA_NUM_KEYS;
		create_clobj(SHA_NUM_KEYS);
	} else {
		if (atoi(kpc) == 0){
			//user chose to die of boredom
			max_keys_per_crypt = SHA_NUM_KEYS;
			create_clobj(SHA_NUM_KEYS);
			find_best_kpc();
		} else {
			max_keys_per_crypt = atoi(kpc);
			create_clobj(max_keys_per_crypt);
		}
	}
	fprintf(stderr, "Local work size (LWS) %d, Global work size (GWS) %d\n",(int)local_work_size, max_keys_per_crypt);
	self->params.max_keys_per_crypt = max_keys_per_crypt;
}

static void set_key(char *key, int index){
	memcpy(&(saved_plain[index*PLAINTEXT_LENGTH]), key, PLAINTEXT_LENGTH);
}

static char *get_key(int index) {
	return &(saved_plain[index*PLAINTEXT_LENGTH]);
}

static void *binary(char *ciphertext){
	static char realcipher[BINARY_SIZE];
	int i;

	for (i = 0; i < BINARY_SIZE; i++) {
		realcipher[i] =
		    atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void *) realcipher;
}

static int cmp_all(void *binary, int count){
	unsigned int i = 0;
	unsigned int b = ((unsigned int *) binary)[0];

	for (; i < count; i++){
		if (b == partial_hashes[i])
			return 1;
	}
	return 0;
}

static int cmp_exact(char *source, int count){
	unsigned int *t = (unsigned int *) binary(source);

	if (!have_full_hashes){
		clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
			sizeof(cl_uint) * (max_keys_per_crypt),
			sizeof(cl_uint) * 4 * max_keys_per_crypt, res_hashes, 0,
			NULL, NULL);
		have_full_hashes = 1;
	}

	if (t[1]!=res_hashes[count])
		return 0;
	if (t[2]!=res_hashes[1*max_keys_per_crypt+count])
		return 0;
	if (t[3]!=res_hashes[2*max_keys_per_crypt+count])
		return 0;
	if (t[4]!=res_hashes[3*max_keys_per_crypt+count])
		return 0;
	return 1;
}

static int cmp_one(void *binary, int index){
	unsigned int *t = (unsigned int *) binary;

	if (t[0] == partial_hashes[index])
		return 1;
	return 0;
}

static void crypt_all(int count){
	HANDLE_CLERROR( clEnqueueWriteBuffer(queue[ocl_gpu_id], data_info, CL_TRUE, 0,
		sizeof(unsigned int) * 2, datai, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer data_info");
	HANDLE_CLERROR( clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
		(PLAINTEXT_LENGTH) * max_keys_per_crypt, saved_plain, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer saved_plain");

	HANDLE_CLERROR( clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
		&global_work_size, &local_work_size, 0, NULL, profilingEvent),
		"failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]),"failed in clFinish");
	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0,
		sizeof(cl_uint) * max_keys_per_crypt, partial_hashes, 0, NULL, NULL),
		"failed in reading data back");
	have_full_hashes = 0;
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0x7ffffff; }

static int get_hash_0(int index) { return partial_hashes[index] & 0xF; }
static int get_hash_1(int index) { return partial_hashes[index] & 0xFF; }
static int get_hash_2(int index) { return partial_hashes[index] & 0xFFF; }
static int get_hash_3(int index) { return partial_hashes[index] & 0xFFFF; }
static int get_hash_4(int index) { return partial_hashes[index] & 0xFFFFF; }
static int get_hash_5(int index) { return partial_hashes[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return partial_hashes[index] & 0x7FFFFFF; }

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
		tests
	}, {
		fmt_rawsha1_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
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
