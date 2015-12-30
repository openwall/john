/*
 * Copyright (c) 2012 Samuele Giovanni Tonon
 * samu at linuxasylum dot net, and
 * Copyright (c) 2012, 2013 magnum
 * This program comes with ABSOLUTELY NO WARRANTY; express or
 * implied.
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_mysqlsha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_mysqlsha1);
#else

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "sha.h"
#include "common-opencl.h"

#define FORMAT_LABEL            "mysql-sha1-opencl"
#define FORMAT_NAME             "MySQL 4.1+"
#define ALGORITHM_NAME          "SHA1 OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1

#define PLAINTEXT_LENGTH        55
#define CIPHERTEXT_LENGTH       41

#define BINARY_SIZE             20
#define BINARY_ALIGN            1
#define SALT_SIZE               0
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define STEP 0
#define SEED 256

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  "xfer: ",  ", crypt: ",  ", xfer: "
};

typedef struct {
	unsigned int h0,h1,h2,h3,h4;
} SHA_DEV_CTX;


static char *saved_key;
static unsigned int *output, *saved_idx, key_idx;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_result;
static cl_mem pinned_key, pinned_idx, pinned_result;
static int partial_output;
static struct fmt_main *self;

static struct fmt_tests tests[] = {
	{"*5AD8F88516BD021DD43F171E2C785C69F8E54ADB", "tere"},
	{"*2c905879f74f28f8570989947d06a8429fb943e6", "verysecretpassword"},
	{"*A8A397146B1A5F8C8CF26404668EFD762A1B7B82", "________________________________"},
	{"*F9F1470004E888963FB466A5452C9CBD9DF6239C", "12345678123456781234567812345678"},
	{"*97CF7A3ACBE0CA58D5391AC8377B5D9AC11D46D9", "' OR 1 /*'"},
	{"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "password"},
	{"*7534F9EAEE5B69A586D1E9C1ACE3E3F9F6FCC446", "5"},
	{"*be1bdec0aa74b4dcb079943e70528096cca985f8", ""},
	{"*0D3CED9BEC10A777AEC23CCC353A8C08A633045E", "abc"},
	{"*18E70DF2758EE4C0BD954910E5808A686BC38C6A", "VAwJsrUcrchdG9"},
	{"*440F91919FD39C01A9BC5EDB6E1FE626D2BFBA2F", "lMUXgJFc2rNnn"},
	{"*171A78FB2E228A08B74A70FE7401C807B234D6C9", "TkUDsVJC"},
	{"*F7D70FD3341C2D268E98119ED2799185F9106F5C", "tVDZsHSG"},
	{NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * (gws + 1), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_idx");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BINARY_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key),"Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 1");
}

static void release_clobj(void){
	if (cl_saved_idx) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");

		cl_saved_idx = NULL;
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static int valid(char *ciphertext, struct fmt_main *self){
	int i;

	if (ciphertext[0] != '*')
		return 0;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 1; i < CIPHERTEXT_LENGTH; i++) {
		if (!( (('0' <= ciphertext[i])&&(ciphertext[i] <= '9'))
		       || (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		       || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
		{
			return 0;
		}
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, sizeof(out));
	strupr(out);
	return out;
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		size_t gws_limit;
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%u", PLAINTEXT_LENGTH);
		opencl_init("$JOHN/kernels/msha_kernel.cl", gpu_id, build_opts);

		// create kernel to execute
		crypt_kernel = clCreateKernel(program[gpu_id], "mysqlsha1_crypt_kernel", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

		// Current key_idx can only hold 26 bits of offset so
		// we can't reliably use a GWS higher than 4M or so.
		gws_limit = MIN((1 << 26) * 4 / PLAINTEXT_LENGTH,
		                get_max_mem_alloc_size(gpu_id) / PLAINTEXT_LENGTH);

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 2,
		                       self, create_clobj, release_clobj,
		                       2 * PLAINTEXT_LENGTH, gws_limit, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, 2, gws_limit, 200);
	}
}

static void clear_keys(void)
{
	key_idx = 0;
	saved_idx[0] = 0;
	key_offset = 0;
	idx_offset = 0;
}

static void set_key(char *key, int index)
{
	while (*key)
		saved_key[key_idx++] = *key++;

	saved_idx[index + 1] = key_idx;

	/* Early partial transfer to GPU every 256K keys */
	if (index && !(index & (256 * 1024 - 1))) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		key_offset = key_idx;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, sizeof(cl_uint) * index - idx_offset, saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL, NULL), "Failed transferring index");
		idx_offset = sizeof(cl_uint) * index;
		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	}
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index + 1] - saved_idx[index];
	char *key = (char*)&saved_key[saved_idx[index]];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	return out;
}

static void *get_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;

	ciphertext += 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		/* endian swap now instead of billions of times later */
		realcipher[i ^ 3] =
			atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void *)realcipher;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i;
	unsigned int b = ((unsigned int*)binary)[0];

	for(i = 0; i < count; i++)
		if (b == output[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	unsigned int *t = (unsigned int*) binary;

	return (t[0] == output[index]);
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD_32 *binary;
	int i;

	if (partial_output) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, BINARY_SIZE * global_work_size, output, 0, NULL, NULL), "failed reading results back");
		partial_output = 0;
	}
	binary = (ARCH_WORD_32*)get_binary(source);

	for(i = 0; i < BINARY_SIZE / 4; i++)
		if (output[i * global_work_size + index] != binary[i])
			return 0;
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	/* Self-test cludge */
	if (idx_offset > 4 * (global_work_size + 1))
		idx_offset = 0;

	if (key_idx > key_offset)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, multi_profilingEvent[0]), "Failed transferring keys");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, sizeof(cl_uint) * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL, multi_profilingEvent[1]), "Failed transferring index");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, output, 0, NULL, multi_profilingEvent[3]), "failed in reading data back");
	partial_output = 1;

	return count;
}

static int get_hash_0(int index) { return output[index] & PH_MASK_0; }
static int get_hash_1(int index) { return output[index] & PH_MASK_1; }
static int get_hash_2(int index) { return output[index] & PH_MASK_2; }
static int get_hash_3(int index) { return output[index] & PH_MASK_3; }
static int get_hash_4(int index) { return output[index] & PH_MASK_4; }
static int get_hash_5(int index) { return output[index] & PH_MASK_5; }
static int get_hash_6(int index) { return output[index] & PH_MASK_6; }

struct fmt_main fmt_opencl_mysqlsha1 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{ NULL },
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL },
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
		NULL,
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
