/*
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * samu at linuxasylum dot net
 * This program comes with ABSOLUTELY NO WARRANTY; express or
 * implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_NSLDAPS;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_NSLDAPS);
#else

#include <string.h>

#include "path.h"
#include "misc.h"
#include "params.h"
#include "formats.h"
#include "common.h"
#include "stdint.h"
#include "config.h"
#include "options.h"
#include "sha.h"
#include "base64.h"
#include "common-opencl.h"

#define FORMAT_LABEL			"ssha-opencl"
#define FORMAT_NAME			"Netscape LDAP {SSHA}"
#define ALGORITHM_NAME			"SHA1 OpenCL (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define CIPHERTEXT_LENGTH		40

#define DIGEST_SIZE			20
#define BINARY_SIZE			4
#define BINARY_ALIGN			1
#define SALT_SIZE			8
#define SALT_ALIGN			4

#define PLAINTEXT_LENGTH		32

#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT		1

typedef struct {
	uint32_t h0, h1, h2, h3, h4;
} SHA_DEV_CTX;


#define NSLDAP_MAGIC "{ssha}"
#define NSLDAP_MAGIC_LENGTH 6
#define BASE64_ALPHABET	  \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static cl_mem pinned_saved_keys, pinned_partial_hashes;
static cl_mem buffer_out, buffer_keys, mysalt;
static cl_uint *outbuffer;
static cl_uint *outbuffer2;
static char *saved_plain;
static char saved_salt[SALT_SIZE];
static int have_full_hashes;
static struct fmt_main *self;

static struct fmt_tests tests[] = {
	{"{SSHA}8VKmzf3SqceSL8/CJ0bGz7ij+L0SQCxcHHYzBw==", "mabelove"},
	{"{SSHA}91PzTv0Wjs/QVzbQ9douCG3HK8gpV1ocqgbZUg==", "12345678"},
	{"{SSHA}DNPSSyXT0wzh4JiiX1D8RnltILQzUlFBuhKFcA==", "wildstar"},
	{"{SSHA}yVEfRVwCJqVUBgLvgM89ExKgcfZ9QEFQgmobJg==", "zanzibar"},
	{"{SSHA}WTT3B9Jjr8gOt0Q7WMs9/XvukyhTQj0Ns0jMKQ==", "Password9"},
	{"{SSHA}cKFVqtf358j0FGpPsEIK1xh3T0mtDNV1kAaBNg==", "salles"},
	{"{SSHA}y9Nc5vOnK12ppTjHo35lxM1pMFnLZMwqqwH6Eg==", "00000000"},
	{"{SSHA}W3ipFGmzS3+j6/FhT7ZC39MIfqFcct9Ep0KEGA==", "asddsa123"},



#if 0
/*
 * These two were found in john-1.6-nsldaps4.diff.gz and apparently they were
 * supported by that version of they code, but they are not anymore.
 */
	{"{SSHA}/EExmSfmhQSPHDJaTxwQSdb/uPpzYWx0ZXI=", "secret"},
	{"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0", "secret"},
#endif
	{NULL}
};

#define STEP                   0
#define SEED                   1024

static int have_full_hashes;

//This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: "  ,  ", crypt: "    ,  ", result xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = kpc;
	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");

	saved_plain = (char*)clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ,
			 0, PLAINTEXT_LENGTH * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");
	memset(saved_plain, 0, PLAINTEXT_LENGTH * kpc);

	outbuffer2 = mem_alloc(sizeof(cl_uint) * 4 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
	    sizeof(cl_uint) * kpc, NULL, &ret_code);

	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");

	outbuffer = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id],
	    pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
	    sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory outbuffer");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	    PLAINTEXT_LENGTH * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");

	buffer_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
	    sizeof(cl_uint) * 5 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");

	mysalt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, SALT_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating mysalt out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mysalt),
		(void *) &mysalt), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1,
		sizeof(buffer_keys), (void *) &buffer_keys),
	    "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out),
		(void *) &buffer_out), "Error setting argument 2");
}

static void release_clobj(void){
	if (outbuffer2) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
		                                       outbuffer, 0,NULL,NULL),
		               "Error Unmapping outbuffer");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
		                                       saved_plain, 0, NULL, NULL),
		               "Error Unmapping saved_plain");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(buffer_keys),
		               "Error Releasing buffer_keys");
		HANDLE_CLERROR(clReleaseMemObject(buffer_out),
		               "Error Releasing buffer_out");
		HANDLE_CLERROR(clReleaseMemObject(mysalt),
		               "Error Releasing mysalt");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys),
		               "Error Releasing pinned_saved_keys");
		HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes),
		               "Error Releasing pinned_partial_hashes");

		MEM_FREE(outbuffer2);
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

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d", PLAINTEXT_LENGTH);
		opencl_init("$JOHN/kernels/ssha_kernel.cl", gpu_id, build_opts);

		// create kernel to execute
		crypt_kernel = clCreateKernel(program[gpu_id], "sha1_crypt_kernel", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 1, NULL, warn,
		                       1, self, create_clobj, release_clobj,
		                       2 * PLAINTEXT_LENGTH, 0);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static void *get_binary(char *ciphertext) {
	static char realcipher[DIGEST_SIZE + 1 + SALT_SIZE + 9];

	memset(realcipher, 0, sizeof(realcipher));
	base64_decode(NSLDAP_MAGIC_LENGTH + ciphertext, CIPHERTEXT_LENGTH,
	    realcipher);
	return (void *) realcipher;
}

static void *get_salt(char *ciphertext){
	static char *realcipher;

	// Cludge to be sure to satisfy the salt aligment test of 1.7.9.3 on 64-bit
	if (!realcipher) realcipher = mem_alloc_tiny(DIGEST_SIZE + 1 + SALT_SIZE + 9 + 4, MEM_ALIGN_WORD) + 4;

	memset(realcipher, 0, DIGEST_SIZE + SALT_SIZE + 9 + 4);

	base64_decode(NSLDAP_MAGIC_LENGTH + ciphertext, CIPHERTEXT_LENGTH,
	    realcipher);
	return (void *) &realcipher[DIGEST_SIZE];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH))
		return 0;
	ciphertext += NSLDAP_MAGIC_LENGTH;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	if (strncmp(ciphertext + CIPHERTEXT_LENGTH - 2, "==", 2))
		return 0;
	if (strspn(ciphertext, BASE64_ALPHABET) != CIPHERTEXT_LENGTH - 2)
		return 0;

	return 1;
}

static int get_hash_0(int index) { return outbuffer[index] & PH_MASK_0; }
static int get_hash_1(int index) { return outbuffer[index] & PH_MASK_1; }
static int get_hash_2(int index) { return outbuffer[index] & PH_MASK_2; }
static int get_hash_3(int index) { return outbuffer[index] & PH_MASK_3; }
static int get_hash_4(int index) { return outbuffer[index] & PH_MASK_4; }
static int get_hash_5(int index) { return outbuffer[index] & PH_MASK_5; }
static int get_hash_6(int index) { return outbuffer[index] & PH_MASK_6; }

static int salt_hash(void *salt){
	return *((ARCH_WORD_32 *) salt) & (SALT_HASH_SIZE - 1);
}

static void set_key(char *key, int index){
	memcpy(&(saved_plain[index*PLAINTEXT_LENGTH]), key, PLAINTEXT_LENGTH);
}

static void set_salt(void *salt){
	memcpy(saved_salt, salt, SALT_SIZE);

	/* Used to be in crypt_all() - bad for single salt */
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mysalt, CL_FALSE, 0, SALT_SIZE,
	    saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer mysalt");
}

static char *get_key(int index) {
	int length = 0;
	static char out[PLAINTEXT_LENGTH + 1];
	char *key = &saved_plain[index * PLAINTEXT_LENGTH];

	while (length < PLAINTEXT_LENGTH && *key)
		out[length++] = *key++;
	out[length] = 0;
	return out;
}

static int cmp_all(void *binary, int count) {
	unsigned int i = 0;
	unsigned int b = ((unsigned int *) binary)[0];
	for (; i < count; i++) {
		if (b == outbuffer[i])
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	unsigned int *t = (unsigned int *) binary;

	if (t[0] == outbuffer[index])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) get_binary(source);

	if (!have_full_hashes){
		clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE,
			    sizeof(cl_uint) * global_work_size,
			    sizeof(cl_uint) * 4 * global_work_size, outbuffer2,
			     0, NULL, NULL);
		have_full_hashes = 1;
	}
	if (t[1]!=outbuffer2[index])
		return 0;
	if (t[2]!=outbuffer2[1*global_work_size+index])
		return 0;
	if (t[3]!=outbuffer2[2*global_work_size+index])
		return 0;
	if (t[4]!=outbuffer2[3*global_work_size+index])
		return 0;
	return 1;
}



static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_FALSE, 0, PLAINTEXT_LENGTH * global_work_size, saved_plain, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer saved_plain");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueNDRangeKernel");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	// read back partial hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, outbuffer, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueReadBuffer -reading partial hashes");
	have_full_hashes = 0;

	return count;
}

struct fmt_main fmt_opencl_NSLDAPS = {
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
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
		salt_hash,
		NULL,
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
