/*
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * samu at linuxasylum dot net
 * and Copyright (c) 2012, magnum
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
#include "options.h"

#define FORMAT_LABEL			"raw-sha1-opencl"
#define FORMAT_NAME			"Raw SHA-1"
#define ALGORITHM_NAME			"OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		40

#define DIGEST_SIZE			20
#define BINARY_SIZE			4
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
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static char *saved_plain;
static int have_full_hashes;
static int keybuf_size = PLAINTEXT_LENGTH;

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

static struct fmt_tests tests[] = {
	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{"095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{NULL}
};

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

static void create_clobj(int kpc){
	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, keybuf_size*kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_plain = (char*)clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, keybuf_size*kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");
	memset(saved_plain, 0, keybuf_size * kpc);

	res_hashes = malloc(sizeof(cl_uint) * 4 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, keybuf_size * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");
	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, sizeof(cl_uint) * 5 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 1");

	global_work_size = kpc;
}

static void release_clobj(void){
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Unmapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
	HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes), "Error Releasing pinned_partial_hashes");
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
	int kernelExecTimeNs = INT_MAX;
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
			strcpy(&(saved_plain[i * keybuf_size]), tests[0].plaintext);
		}
		clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_TRUE, 0, keybuf_size * num, saved_plain, 0, NULL, NULL);
		ret_code = clEnqueueNDRangeKernel( queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &myEvent);
		if(ret_code != CL_SUCCESS){
			fprintf(stderr, "Error %d\n",ret_code);
			continue;
		}
		clFinish(queue_prof);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);
		tmpTime = endTime-startTime;
		tmpbuffer = mem_alloc(sizeof(cl_uint) * num);
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
	global_work_size = optimal_kpc;
	release_clobj();
	create_clobj(optimal_kpc);
}

static void fmt_rawsha1_init(struct fmt_main *self) {
	char build_opts[64];
	char *kpc;

	global_work_size = MAX_KEYS_PER_CRYPT;

	/* Reduced length can give a significant boost. */
	if (options.force_maxlength && options.force_maxlength < PLAINTEXT_LENGTH) {
		keybuf_size = MAX(options.force_maxlength, 8);
		self->params.benchmark_comment = mem_alloc_tiny(20, MEM_ALIGN_NONE);
		sprintf(self->params.benchmark_comment, " (max length %d)",
		        keybuf_size);
	}
	snprintf(build_opts, sizeof(build_opts),
	         "-DKEY_LENGTH=%d", keybuf_size);
	opencl_init_opt("$JOHN/kernels/sha1_kernel.cl", ocl_gpu_id, platform_id, build_opts);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "sha1_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	create_clobj(SHA_NUM_KEYS);
	opencl_find_best_workgroup(self);
	release_clobj();
	if( (kpc = getenv("GWS")) == NULL){
		global_work_size = SHA_NUM_KEYS;
		create_clobj(SHA_NUM_KEYS);
	} else {
		if (atoi(kpc) == 0){
			//user chose to die of boredom
			global_work_size = SHA_NUM_KEYS;
			create_clobj(SHA_NUM_KEYS);
			find_best_kpc();
		} else {
			global_work_size = atoi(kpc);
			create_clobj(global_work_size);
		}
	}
	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n",(int)local_work_size, (int)global_work_size);

	self->params.min_keys_per_crypt = local_work_size < 8 ?
		8 : local_work_size;
	self->params.max_keys_per_crypt = global_work_size;
}

static void clear_keys(void)
{
	memset(saved_plain, 0, keybuf_size * global_work_size);
}

static void set_key(char *key, int index) {
	char *dst = (char*)&saved_plain[index * keybuf_size];

	while (*key)
		*dst++ = *key++;
}

static char *get_key(int index) {
	int length = 0;
	static char out[PLAINTEXT_LENGTH + 1];
	char *key = &saved_plain[index * keybuf_size];

	while (length < keybuf_size && *key)
		out[length++] = *key++;
	out[length] = 0;
	return out;
}

static void *binary(char *ciphertext){
	static char realcipher[DIGEST_SIZE];
	int i;

	for (i = 0; i < DIGEST_SIZE; i++) {
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

static int cmp_one(void *binary, int index){
	unsigned int *t = (unsigned int *) binary;

	if (t[0] == partial_hashes[index])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int count){
	unsigned int *t = (unsigned int *) binary(source);

	if (!have_full_hashes){
		clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
			sizeof(cl_uint) * (global_work_size),
			sizeof(cl_uint) * 4 * global_work_size, res_hashes, 0,
			NULL, NULL);
		have_full_hashes = 1;
	}

	if (t[1]!=res_hashes[count])
		return 0;
	if (t[2]!=res_hashes[1*global_work_size+count])
		return 0;
	if (t[3]!=res_hashes[2*global_work_size+count])
		return 0;
	if (t[4]!=res_hashes[3*global_work_size+count])
		return 0;
	return 1;
}

static void crypt_all(int count){
	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	HANDLE_CLERROR( clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, keybuf_size * global_work_size, saved_plain, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_plain");

	HANDLE_CLERROR( clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent), "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]),"failed in clFinish");
	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, partial_hashes, 0, NULL, NULL), "failed in reading data back");
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
		fmt_default_set_salt,
		set_key,
		get_key,
		clear_keys,
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
