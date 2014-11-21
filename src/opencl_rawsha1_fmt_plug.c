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

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rawSHA1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rawSHA1);
#else

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

#define FORMAT_LABEL			"Raw-SHA1-opencl"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"SHA1 OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		55 /* Max. is 55 with current kernel */
#define BUFSIZE				((PLAINTEXT_LENGTH+3)/4*4)
#define HASH_LENGTH			(2 * DIGEST_SIZE)
#define CIPHERTEXT_LENGTH		(HASH_LENGTH + TAG_LENGTH)

#define DIGEST_SIZE			20
#define BINARY_SIZE			4
#define BINARY_ALIGN			4
#define SALT_SIZE			0
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

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
cl_mem buffer_keys, buffer_idx;
static cl_uint *partial_hashes, *saved_plain, *saved_idx;
static int have_full_hashes;
static unsigned int key_idx = 0;

#define MIN(a, b)		(((a) > (b)) ? (b) : (a))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))

#define OCL_CONFIG		"raw-sha1"

// Shared auto-tune stuff
#define STEP                    0
#define SEED                    65536
#define ROUNDS			1

static const char * warn[] = {
	"pass xfer: ",  ", index xfer: ",  ", crypt: ",  ", result xfer: "
};

static int crypt_all(int *pcount, struct db_salt *_salt);

#include "opencl-autotune.h"
#include "memdbg.h"

static struct fmt_tests tests[] = {
	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc"},
	{FORMAT_TAG "095bec1163897ac86e393fa16d6ae2c2fce21602", "7850"},
	{"dd3fbb0ba9e133c4fd84ed31ac2e5bc597d61774", "7858"},
	{"207db421a91dc3eb1d976e1925fe97313a1ae0b3", "Skipping and& Dipping__1"},
	{NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	return 0;
}

static void set_key(char *_key, int index);

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

static void create_clobj(size_t gws, struct fmt_main *self)
{
	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_plain = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	saved_idx = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, DIGEST_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, DIGEST_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	buffer_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BUFSIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");

	buffer_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx");

	buffer_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, DIGEST_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 2");

	global_work_size = gws;
}

static void release_clobj(void){
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Unmapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	               "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");

	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Error Releasing pinned_saved_idx");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
	HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes), "Error Releasing pinned_partial_hashes");
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

static void init(struct fmt_main *self)
{
	size_t gws_limit;

	opencl_init("$JOHN/kernels/sha1_kernel.cl", gpu_id, NULL);

	// Current key_idx can only hold 26 bits of offset so
	// we can't reliably use a GWS higher than 4.7M or so.
	gws_limit = MIN((1 << 26) * 4 / BUFSIZE,
			get_max_mem_alloc_size(gpu_id) / BUFSIZE);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[gpu_id], "sha1_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	//Warm up.
	create_clobj((1024 * 1024), self);
	release_clobj();

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 2,
	                       self, create_clobj, release_clobj,
	                       BUFSIZE, gws_limit);

	//Limit worksize using index limitation.
	while (global_work_size > gws_limit)
		global_work_size -= local_work_size;

	//Auto tune execution from shared/included code.
	autotune_run(self, ROUNDS, gws_limit,
		(cpu(device_info[gpu_id]) ? 500000000ULL : 1000000000ULL));
}

static void clear_keys(void)
{
	key_idx = 0;
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

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index] & 63;
	char *key = (char*)&saved_plain[saved_idx[index] >> 6];

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

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) binary(source);

	if (!have_full_hashes){
		clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE,
			sizeof(cl_uint) * (global_work_size),
			sizeof(cl_uint) * 4 * global_work_size,
			partial_hashes + global_work_size, 0,
			NULL, NULL);
		have_full_hashes = 1;
	}
	if (t[1]!=partial_hashes[1*global_work_size+index])
		return 0;
	if (t[2]!=partial_hashes[2*global_work_size+index])
		return 0;
	if (t[3]!=partial_hashes[3*global_work_size+index])
		return 0;
	if (t[4]!=partial_hashes[4*global_work_size+index])
		return 0;
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	if (local_work_size)
		gws = (count + local_work_size - 1) / local_work_size * local_work_size;
	else
		gws = (count + 64 - 1) / 64 * 64;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer buffer_keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_TRUE, 0, 4 * gws, saved_idx, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer buffer_idx");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFinish(queue[gpu_id]),"failed in clFinish");

	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * gws, partial_hashes, 0, NULL, multi_profilingEvent[3]), "failed in reading data back");
	have_full_hashes = 0;

	return count;
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
