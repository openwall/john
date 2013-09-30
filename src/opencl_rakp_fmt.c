/*
 * Code based on:
 * - Assorted OpenCL JtR plugins
 * - RAKP JtR plugin, (C) 2012 magnum, (C) 2013 Dhiru Kholia
 *
 * OpenCL RAKP JtR plugin (C) 2013 by Harrison Neal
 * Packed key buffer and other optimizations (c) magnum 2013
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor implied.
 * See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include "common-opencl.h"
#include "options.h"

#define FORMAT_LABEL            "RAKP-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "IPMI 2.0 RAKP (RMCP+) OpenCL"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1000

#define BLOCK_SIZE              64
#define PAD_SIZE                BLOCK_SIZE
#define SALT_STORAGE_SIZE       (BLOCK_SIZE*2)
#define SALT_SIZE               (SALT_STORAGE_SIZE - 9)
#define SALT_MIN_SIZE           (SALT_SIZE - BLOCK_SIZE + 1)

#define PLAINTEXT_LENGTH        (PAD_SIZE - 1)

#define DIGEST_SIZE             20
#define BINARY_SIZE             DIGEST_SIZE

#define MIN_KEYS_PER_CRYPT      (1024*2048)
#define MAX_KEYS_PER_CRYPT      MIN_KEYS_PER_CRYPT

#define FORMAT_TAG              "$rakp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define BINARY_ALIGN            1
#define SALT_ALIGN              1

#define HEXCHARS			"0123456789abcdef"

#ifndef uint32_t
#define uint32_t unsigned int
#endif

static unsigned char salt_storage[SALT_STORAGE_SIZE];

cl_command_queue queue_prof;
cl_int ret_code;
cl_kernel crypt_kernel;
cl_mem salt_buffer, keys_buffer, idx_buffer, digest_buffer;

static unsigned int *keys;
static unsigned int *idx;
static ARCH_WORD_32 (*digest)[BINARY_SIZE / sizeof(ARCH_WORD_32)];
static unsigned int key_idx = 0;

#define MIN(a, b)               (((a) > (b)) ? (b) : (a))
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))

static struct fmt_tests tests[] = {
	{"$rakp$a4a3a2a03f0b000094272eb1ba576450b0d98ad10727a9fb0ab83616e099e8bf5f7366c9c03d36a3000000000000000000000000000000001404726f6f74$0ea27d6d5effaa996e5edc855b944e179a2f2434", "calvin"},
	{"$rakp$c358d2a72f0c00001135f9b254c274629208b22f1166d94d2eba47f21093e9734355a33593da16f2000000000000000000000000000000001404726f6f74$41fce60acf2885f87fcafdf658d6f97db12639a9", "calvin"},
	{"$rakp$b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174$472bdabe2d5d4bffd6add7b3ba79a291d104a9ef", "hashcat"},
	{NULL}
};

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q = NULL;;
	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = strrchr(ciphertext, '$');
	if (!q)
		return 0;
	q = q + 1;
	if (strspn(q, HEXCHARS) != BINARY_SIZE * 2)
		return 0;

	if (strspn(p, HEXCHARS) > SALT_SIZE * 2)
		return 0;

	if ( (q - p) > SALT_SIZE * 2)
		return 0;

	if ( (q - p) < SALT_MIN_SIZE * 2)
		return 0;

	return 1;
}

static void clear_keys(void);
static void set_key(char *key, int index);

static void create_clobj(int kpc){
	keys = mem_alloc((PLAINTEXT_LENGTH + 1) * kpc);
	idx = mem_alloc(sizeof(*idx) * kpc);
	digest = mem_alloc(sizeof(*digest) * kpc);

	salt_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, SALT_STORAGE_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	keys_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, (PLAINTEXT_LENGTH + 1) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating keys_buffer out argument");

	idx_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating idx_buffer out argument");

	digest_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, DIGEST_SIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating digest_buffer in argument");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 0, sizeof(salt_buffer), (void *) &salt_buffer),
		"Error attaching salt_buffer to kernel");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 1, sizeof(keys_buffer), (void *) &keys_buffer),
		"Error attaching keys_buffer to kernel");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 2, sizeof(idx_buffer), (void *) &idx_buffer),
		"Error attaching idx_buffer to kernel");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 3, sizeof(digest_buffer), (void *) &digest_buffer),
		"Error attaching digest_buffer to kernel");

	global_work_size = kpc;
}

static void release_clobj(void){
	MEM_FREE(keys);
	MEM_FREE(idx);
	MEM_FREE(digest);

	HANDLE_CLERROR(clReleaseMemObject(salt_buffer), "Error releasing salt_buffer");
	HANDLE_CLERROR(clReleaseMemObject(keys_buffer), "Error releasing keys_buffer");
	HANDLE_CLERROR(clReleaseMemObject(idx_buffer), "Error releasing idx_buffer");
	HANDLE_CLERROR(clReleaseMemObject(digest_buffer), "Error releasing digest_buffer");
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Error releasing kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Error releasing program");
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
	for( num=MAX_KEYS_PER_CRYPT; num >= 4096 ; num -= 4096){
		release_clobj();
		create_clobj(num);
		advance_cursor();
		queue_prof = clCreateCommandQueue( context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
		clear_keys();
		for (i=0; i < num; i++)
			set_key(tests[0].plaintext, i);

		clEnqueueWriteBuffer(queue[ocl_gpu_id], keys_buffer, CL_FALSE, 0, 4 * key_idx, keys, 0, NULL, NULL);
		clEnqueueWriteBuffer(queue[ocl_gpu_id], idx_buffer, CL_FALSE, 0, 4 * global_work_size, idx, 0, NULL, NULL);

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
		clEnqueueReadBuffer(queue_prof, digest_buffer, CL_TRUE, 0, sizeof(cl_uint) * num, tmpbuffer, 0, NULL, &myEvent);
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

static void init(struct fmt_main *self) {
	char *temp;
	cl_ulong maxsize;

	local_work_size = global_work_size = 0;

	opencl_init("$JOHN/kernels/rakp_kernel.cl", ocl_gpu_id, NULL);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "rakp_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Error requesting max workgroup size");

	if ((temp = getenv("LWS"))) {
		local_work_size = atoi(temp);

		while (local_work_size > maxsize)
			local_work_size >>= 1;
	}

	if (!local_work_size) {
		create_clobj(MAX_KEYS_PER_CRYPT);
		opencl_find_best_workgroup(self);
		release_clobj();
	}

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);
	else
		global_work_size = MAX_KEYS_PER_CRYPT;

	if (!global_work_size) {
		// User chose to die of boredom
		global_work_size = MAX_KEYS_PER_CRYPT;
		create_clobj(MAX_KEYS_PER_CRYPT);
		find_best_kpc();
	} else {
		create_clobj(global_work_size);
	}

	if (options.verbosity > 2)
		fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n",(int)local_work_size, (int)global_work_size);

	self->params.max_keys_per_crypt = global_work_size;

	self->params.min_keys_per_crypt = local_work_size;
}

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *key, int index)
{
	const unsigned int *key32 = (unsigned int*)key;
	int len = strlen(key);

	idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		keys[key_idx++] = *key32++;
		len -= 4;
	}
	if (len)
		keys[key_idx++] = *key32 & (0xffffffffU >> (32 - (len << 3)));
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = idx[index] & 63;
	char *key = (char*)&keys[idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = key[i];

	out[i] = 0;

	return out;
}

static void *binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	/* Endian swap once now instead of billions of times later */
	alter_endianity(out, BINARY_SIZE);

	return out;
}

static void *salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	unsigned int i, len;

	if (!strncmp(ctcopy, FORMAT_TAG, TAG_LENGTH))
		ctcopy += TAG_LENGTH;

	p = strtok(ctcopy, "$");
	len = strlen(p) / 2;
	for (i = 0; i < len; i++) {
		salt_storage[i ^ 3] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	salt_storage[len ^ 3] = 0x80;
	for (i = len + 1; i < SALT_STORAGE_SIZE - 2; i++) {
		salt_storage[i ^ 3] = 0;
	}
	len += 64;
	len *= 8;
	salt_storage[(SALT_STORAGE_SIZE - 1) ^ 3] = len & 0xffU;
	salt_storage[(SALT_STORAGE_SIZE - 2) ^ 3] = (len >> 8) & 0xffU;
	MEM_FREE(keeptr);
	return (void *)&salt_storage;
}

static void set_salt(void *salt)
{
	HANDLE_CLERROR(
		clEnqueueWriteBuffer(queue[ocl_gpu_id], salt_buffer, CL_FALSE, 0, sizeof(salt_storage), (void*) salt, 0, NULL, NULL),
		"Error updating contents of salt_buffer");
	HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "failed in clFlush");
}

static int cmp_all(void *binary, int count){
	int index = 0;
	for (; index < count; index++) {
		if (!memcmp(binary, digest[index], BINARY_SIZE)) {
			return 1;
		}
	}
	return 0;
}

static int cmp_one(void *binary, int index){
	return !memcmp(binary, digest[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	if (key_idx) {
		HANDLE_CLERROR(
			clEnqueueWriteBuffer(queue[ocl_gpu_id], keys_buffer, CL_FALSE, 0, 4 * key_idx, keys, 0, NULL, NULL),
			"Error updating contents of keys_buffer");

		HANDLE_CLERROR(
			clEnqueueWriteBuffer(queue[ocl_gpu_id], idx_buffer, CL_FALSE, 0, 4 * global_work_size, idx, 0, NULL, NULL),
			"Error updating contents of idx_buffer");
	}

	HANDLE_CLERROR(
		clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent),
		"Error beginning execution of the kernel");

	HANDLE_CLERROR(
		clFinish(queue[ocl_gpu_id]),
		"Error waiting for kernel to finish executing");

	HANDLE_CLERROR(
		clEnqueueReadBuffer(queue[ocl_gpu_id], digest_buffer, CL_TRUE, 0, BINARY_SIZE * global_work_size, digest, 0, NULL, NULL),
		"Error reading results from digest_buffer");

	return count;
}

static int get_hash_0(int index) { return digest[index][0] & 0xf; }
static int get_hash_1(int index) { return digest[index][0] & 0xff; }
static int get_hash_2(int index) { return digest[index][0] & 0xfff; }
static int get_hash_3(int index) { return digest[index][0] & 0xffff; }
static int get_hash_4(int index) { return digest[index][0] & 0xfffff; }
static int get_hash_5(int index) { return digest[index][0] & 0xffffff; }
static int get_hash_6(int index) { return digest[index][0] & 0x7ffffff; }

struct fmt_main fmt_opencl_rakp = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_STORAGE_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		0,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
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
		set_salt,
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
