/*
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * samu at linuxasylum dot net
 * Copyright (c) 2012, magnum
 * and Copyright (c) 2013, Sayantan Datta <std2048 at gmail.com>
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
#include "johnswap.h"
#include "common-opencl.h"
#include "options.h"
#include "opencl_rawsha1_fmt.h"

#define FORMAT_LABEL			"Raw-SHA1-opencl"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"SHA1 OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH    	55 /* Max. is 55 with current kernel */
#define BUFSIZE				((PLAINTEXT_LENGTH+3)/4*4)
#define HASH_LENGTH			(2 * DIGEST_SIZE)
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define DIGEST_SIZE			20
#define BINARY_SIZE			16
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		(1024*2048)
#define MAX_KEYS_PER_CRYPT		MIN_KEYS_PER_CRYPT

#define FORMAT_TAG			"$dynamic_26$"
#define TAG_LENGTH			(sizeof(FORMAT_TAG) - 1)

#ifndef uint32_t
#define uint32_t unsigned int
#endif

typedef struct {
	uint32_t h0,h1,h2,h3,h4;
} SHA_DEV_CTX;


cl_command_queue queue_prof;
cl_int ret_code;
cl_kernel crypt_kernel;
cl_mem pinned_saved_keys, pinned_saved_idx, pinned_partial_hashes, buffer_out;
cl_mem buffer_keys, buffer_idx, buffer_ld_hashes, buffer_bitmap, buffer_outKeyIdx;
cl_kernel crk_kernel;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static unsigned int *saved_plain, *saved_idx, *loaded_hashes, *outKeyIdx;
static int have_full_hashes, loaded_count = 0;
static unsigned int key_idx = 0, cmp_out = 0;
static unsigned int benchmark = 1; // Used as a flag
static struct bitmap_ctx bitmap;

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

static struct fmt_tests tests[] = {
	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{FORMAT_TAG "095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{NULL}
};

static void set_key(char *_key, int index);
static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_self_test(int *pcount, struct db_salt *_salt);
static char *get_key_self_test(int index);
static char *get_key(int index);

static int valid(char *ciphertext, struct fmt_main *self){
	int i;

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	if (strlen(ciphertext) != HASH_LENGTH) return 0;
	for (i = 0; i < HASH_LENGTH; i++){
		if (!((('0' <= ciphertext[i]) && (ciphertext[i] <= '9')) ||
			(('a' <= ciphertext[i]) && (ciphertext[i] <= 'f'))
			|| (('A' <= ciphertext[i]) && (ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	strncpy(out, FORMAT_TAG, sizeof(out));

	memcpy(&out[TAG_LENGTH], ciphertext, HASH_LENGTH);
	out[CIPHERTEXT_LENGTH] = 0;

	strlwr(&out[TAG_LENGTH]);

	return out;
}

static void create_clobj(int kpc){
	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE*kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_plain = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE*kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_saved_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	saved_idx = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	res_hashes = malloc(sizeof(cl_uint) * 4 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");
	buffer_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx");

	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, sizeof(cl_uint) * 5 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 2");

	global_work_size = kpc;
}

static void release_clobj(void){
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Unmapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
	HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes), "Error Releasing pinned_partial_hashes");
	MEM_FREE(res_hashes);

	if(!benchmark) {

		MEM_FREE(loaded_hashes);
		MEM_FREE(outKeyIdx);

		HANDLE_CLERROR(clReleaseMemObject(buffer_ld_hashes), "Release loaded hashes");
		HANDLE_CLERROR(clReleaseMemObject(buffer_outKeyIdx), "Release output key indeces");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap), "Release output key indeces");
	}
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(crk_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
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
		for (i=0; i < num; i++)
			set_key(tests[0].plaintext, i);

		clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_keys";
		clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_idx";

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
	char *temp;
	cl_ulong maxsize;

	local_work_size = global_work_size = 0;

	opencl_init("$JOHN/kernels/sha1_kernel.cl", ocl_gpu_id, NULL);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "sha1_self_test", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crk_kernel = clCreateKernel(program[ocl_gpu_id], "sha1_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max workgroup size");

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
	self->methods.crypt_all = crypt_all_self_test;
	self->methods.get_key = get_key_self_test;
}

static void clear_keys(void)
{
	key_idx = 0;
}

static void opencl_sha1_reset(struct db_main *db) {


	if(db) {
	int argIndex;

	loaded_hashes = (unsigned int*)mem_alloc(((db->password_count) * 4 + 1)*sizeof(unsigned int));
	outKeyIdx     = (unsigned int*)mem_calloc((db->password_count) * sizeof(unsigned int) * 2);

	buffer_ld_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, ((db->password_count) * 4 + 1)*sizeof(int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer arg loaded_hashes\n");

	buffer_outKeyIdx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, (db->password_count) * sizeof(unsigned int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer cmp_out\n");

	buffer_bitmap = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, sizeof(struct bitmap_ctx), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer arg loaded_hashes\n");

	argIndex = 0;

	HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_keys), (void*) &buffer_keys),
		"Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_idx), (void*) &buffer_idx ),
		"Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_out), (void*) &buffer_out ),
		"Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_ld_hashes), (void*) &buffer_ld_hashes ),
		"Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_outKeyIdx), (void*) &buffer_outKeyIdx ),
		"Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_bitmap), (void*) &buffer_bitmap ),
		"Error setting argument 5");

	benchmark = 0;

	// Hardcoded for cracking kernels.
	local_work_size = LWS;

	if (options.verbosity > 2)
		fprintf(stderr,
		        "New local worksize (LWS) %zd\n",
		        local_work_size);

	db->format->methods.crypt_all = crypt_all;
	db->format->methods.get_key = get_key;
	db->format->params.min_keys_per_crypt = local_work_size;

	}
}

static void load_hash(struct db_salt *salt) {

	unsigned int *bin, i;
	struct db_password *pw;

	loaded_count = (salt->count);
	loaded_hashes[0] = loaded_count;
	pw = salt -> list;
	i = 0;
	do {
		bin = (unsigned int *)pw -> binary;
		// Potential segfault if removed
		if(bin != NULL) {
			loaded_hashes[i*4 + 1] = bin[0];
			loaded_hashes[i*4 + 2] = bin[1];
			loaded_hashes[i*4 + 3] = bin[2];
			loaded_hashes[i*4 + 4] = bin[3];
			i++ ;
		}
	} while ((pw = pw -> next)) ;

	if(i != (salt->count)) {
		fprintf(stderr, "Something went wrong while loading hashes to gpu..Exiting..\n");
		exit(0);
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_ld_hashes, CL_TRUE, 0, (i * 4 + 1) * sizeof(unsigned int) , loaded_hashes, 0, NULL, NULL), "failed in clEnqueueWriteBuffer loaded_hashes");
}

static void load_bitmap(unsigned int num_loaded_hashes, unsigned int index, unsigned int *bitmap, size_t szBmp) {
	unsigned int i, hash;
	memset(bitmap, 0, szBmp);

	for(i = 0; i < num_loaded_hashes; i++) {
		hash = loaded_hashes[index + i * 4 + 1] & (szBmp * 8 - 1);
		// divide by 32 , harcoded here and correct only for unsigned int
		bitmap[hash >> 5] |= (1U << (hash & 31));
	}
}

static void set_key(char *_key, int index)
{
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));
}

static char *get_key_self_test(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index] & 63;
	char *key = (char*)&saved_plain[saved_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = key[i];
	out[i] = 0;
	return out;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i , len;
	char *key;

	if(index < loaded_count)
		index = outKeyIdx[index];

	len = saved_idx[index] & 63;
	key = (char*)&saved_plain[saved_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = key[i];
	out[i] = 0;
	return out;
}



static void *binary(char *ciphertext)
{
	static unsigned char *realcipher;
	int i;

	if (!realcipher)
		realcipher = mem_alloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	ciphertext += TAG_LENGTH;

	for(i=0;i<DIGEST_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 +
			atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *) realcipher;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i;
	unsigned int b = ((unsigned int *) binary)[0];

	if(!benchmark) return 1;

	for (i = 0; i < count; i++)
		if (b == partial_hashes[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if(!benchmark) return 1;
	return (((unsigned int*)binary)[0] == partial_hashes[index]);
}


static int cmp_exact(char *source, int count) {

	if(benchmark || cmp_out) {
		unsigned int *t = (unsigned int *) binary(source);
		unsigned int num = benchmark ? global_work_size: loaded_count;
		if (!have_full_hashes){
			clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
				sizeof(cl_uint) * num,
				sizeof(cl_uint) * 4 * num, res_hashes, 0,
				NULL, NULL);
			have_full_hashes = 1;
		}

		if (t[1]!=res_hashes[count])
			return 0;
		if (t[2]!=res_hashes[1 * num + count])
			return 0;
		if (t[3]!=res_hashes[2 * num + count])
			return 0;
		if (t[4]!=res_hashes[3 * num + count])
		return 0;
		return 1;
	}

	return 0;
}

static int crypt_all_self_test(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_idx");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent), "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]),"failed in clFinish");

	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, partial_hashes, 0, NULL, NULL), "failed in reading data back");
	have_full_hashes = 0;

	return count;
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount, i;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	if(loaded_count != (salt->count)) {
		load_hash(salt);
		load_bitmap(loaded_count, 0, &bitmap.bitmap0[0], (BITMAP_SIZE_1 / 8));
		load_bitmap(loaded_count, 1, &bitmap.bitmap1[0], (BITMAP_SIZE_1 / 8));
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_bitmap, CL_TRUE, 0, sizeof(struct bitmap_ctx), &bitmap, 0, NULL, NULL ), "Failed Copy data to gpu");
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_idx");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crk_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent), "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]),"failed in clFinish");

	// read back compare results
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_outKeyIdx, CL_TRUE, 0, sizeof(cl_uint) * loaded_count, outKeyIdx, 0, NULL, NULL), "failed in reading cracked key indices back");
	cmp_out = 0;

	// If a positive match is found outKeyIdx contains some positive value else contains 0
	for(i = 0; i < (loaded_count & (~cmp_out)); i++)
		cmp_out = outKeyIdx[i]?0xffffffff:0;


	if(cmp_out) {
		// read back partial hashes
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * loaded_count, partial_hashes, 0, NULL, NULL), "failed in reading data back");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_outKeyIdx, CL_TRUE, 0, sizeof(cl_uint) * loaded_count * 2, outKeyIdx, 0, NULL, NULL), "failed in reading cracked key indices back");
		have_full_hashes = 0;

		return loaded_count;
	}

	else return 0;
}

static int get_hash_0(int index) { return partial_hashes[index] & 0xf; }
static int get_hash_1(int index) { return partial_hashes[index] & 0xff; }
static int get_hash_2(int index) { return partial_hashes[index] & 0xfff; }
static int get_hash_3(int index) { return partial_hashes[index] & 0xffff; }
static int get_hash_4(int index) { return partial_hashes[index] & 0xfffff; }
static int get_hash_5(int index) { return partial_hashes[index] & 0xffffff; }
static int get_hash_6(int index) { return partial_hashes[index] & 0x7ffffff; }

struct fmt_main fmt_opencl_rawSHA1 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		fmt_rawsha1_init,
		done,
		opencl_sha1_reset,
		fmt_default_prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		set_key,
		get_key,
		clear_keys,
		crypt_all_self_test,
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
