/*
 * Java KeyStore password cracker for JtR.
 * (will NOT address password(s) for alias(es) within keystore).
 *
 * OpenCL plugin by Terry West.
 * Derived from keystore_fmt_plug.c,
 * written by Dhiru Kholia <dhiru at openwall.com> and
 * Narendra Kangralkar <narendrakangralkar at gmail.com>.
 *
 * Input Format: $keystore$target$salt_length$salt$hash$nkeys$keylength$keydata$keylength$keydata...
 *
 * This software is Copyright (c) 2015, Terry West <terrybwest at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Fixes/enhancements JimF, Feb, 2016.
 *  corrected bug where binary passwords failed.
 *  reduced max size of password (performance improvement)
 *  don't convert password to BE shorts on CPU (reduced size and perf gain)
 *  reduced binary returned from GPU from full sized, to 4 bytes. (perf gain)
 *  compute full hash in CPU during cmp_exact()
 *  made a common code module (for sharing code with CPU)
 *  added 2 additional test vectors, and benmark_length changed from -1 to 0
 *  Performance about 2.5x for multi-salts on my Tahiti
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_keystore;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_keystore);
#else

#include <string.h>

#include "arch.h"
#include "sha.h"
#include "misc.h"
#include "common-opencl.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "keystore_common.h"
#include "memdbg.h"

#define FORMAT_LABEL            "keystore-opencl"
#define FORMAT_NAME             "Java KeyStore"
#define ALGORITHM_NAME          "SHA1 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
// reduced PLAIN_LEN from 125 bytes, and speed went from 12.2k to 16.4k
#define PLAINTEXT_LENGTH        32
// reduced BIN_SIZE from 20 bytes to 4 for the GPU, and speed went from
// 16.4k to 17.8k.  cmp_exact does a CPU hash check on possible matches.
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

// these to pass to kernel
typedef struct {
	uint32_t length;
	uint8_t  pass[PLAINTEXT_LENGTH];
} keystore_password;

typedef struct {
	uint32_t gpu_out; // GPU only returns first 4 bytes.
} keystore_hash;

typedef struct {
	uint32_t length;
	uint8_t  salt[SALT_LENGTH_GPU];
} keystore_salt;

// this for use here
static struct custom_salt {
	int length;
	unsigned char salt[SALT_LENGTH_GPU];
} *cur_salt;

static struct fmt_main   *self;

static size_t insize, outsize, saltsize;

static keystore_password *inbuffer;
static keystore_hash     *outbuffer;
static keystore_salt      saltbuffer;
static cl_mem mem_in, mem_out, mem_salt;

static cl_int cl_err;

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(keystore_password) * gws;
	outsize = sizeof(keystore_hash) * gws;
	saltsize = sizeof(keystore_salt);

	inbuffer  = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);

	/// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize,
	    NULL, &cl_err);
	HANDLE_CLERROR(cl_err, "Error allocating mem_in");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_err);
	HANDLE_CLERROR(cl_err, "Error allocating mem_salt");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize,
	    NULL, &cl_err);
	HANDLE_CLERROR(cl_err, "Error allocating mem_out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (mem_in) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem_in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		mem_in   = NULL;
		mem_salt = NULL;
		mem_out  = NULL;
	}
}


static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	// TODO
	if (!autotuned) {

		char build_opts[64];
		snprintf(build_opts, sizeof(build_opts),
				"-DPASSLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
				PLAINTEXT_LENGTH,
				SALT_LENGTH_GPU,
				4);
		opencl_init("$JOHN/kernels/keystore_kernel.cl",
				    gpu_id, build_opts);
		crypt_kernel = clCreateKernel(program[gpu_id], "keystore", &cl_err);
		HANDLE_CLERROR(cl_err, "Error creating keystore kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(0, 0, NULL, warn, 1, self,
				               create_clobj, release_clobj,
							   sizeof(keystore_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 2, (cpu(device_info[gpu_id]) ?
	              1000000000 : 10000000000ULL));//2000);

	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		--autotuned;
	}
}

static void *get_salt(char *ciphertext)
{
	/* NOTE: do we need dynamic allocation because of underlying large object size? */
	static struct custom_salt *cs;

	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	if (!cs) cs = mem_alloc_tiny(sizeof(struct custom_salt),16);
	memset(cs, 0, sizeof(struct custom_salt));

	ctcopy += FORMAT_TAG_LEN; 				// skip over "$keystore$"
	p = strtokm(ctcopy, "$");   // skip target
	p = strtokm(NULL, "$");
	cs->length = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs->length; ++i)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			        + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	/* we've got the salt, we can skip all the rest
	p = strtokm(NULL, "$"); // skip hash
	p = strtokm(NULL, "$");
	cs->count = atoi(p);
	p = strtokm(NULL, "$");
	cs->keysize = atoi(p);
	for (i = 0; i < cs->keysize; i++)
		cs->keydata[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			           + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	*/
	MEM_FREE(keeptr);
	return (void *)cs;
}

static void set_salt(void *salt)
{
	// Before the salt from the ciphertext, prepend
	// "Mighty Aphrodite":
	const char *magic  = "Mighty Aphrodite";
	int         maglen = 16;
	int			i, j;

	cur_salt = (struct custom_salt*)salt;
	saltbuffer.length = maglen + cur_salt->length;
	for (i = 0; i < maglen; ++i) {
		saltbuffer.salt[i] = (uint8_t)magic[i];
	}
	for (j = 0; j < cur_salt->length; ++i, ++j) {
		saltbuffer.salt[i] = cur_salt->salt[j];
	}

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
			                            CL_FALSE, 0, saltsize,
										&saltbuffer, 0, NULL, NULL),
										"Copy salt to gpu");
}

static void keystore_set_key(char *key, int index)
{
	uint32_t len = strlen(key);

	memcpy(inbuffer[index].pass, key, len);
	inbuffer[index].length = len;
}

static char *get_key(int index)
{
	static char key[PLAINTEXT_LENGTH + 1];

	memcpy(key, inbuffer[index].pass, inbuffer[index].length);
	key[inbuffer[index].length] = 0;

	return key;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	/// Copy password buffer to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
	        "Copy data to gpu");

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
	        multi_profilingEvent[1]), "Run kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]), "Copy result back");

	///Await completion of all the above
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	return count;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i, b = ((uint32_t *)binary)[0];

	for (i = 0; i < count; ++i) {
		if (b == outbuffer[i].gpu_out) {
			return 1;
		}
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (((uint32_t*)binary)[0] != outbuffer[index].gpu_out) {
		return 0;
	}

	return 1;
}

static int cmp_exact(char *source, int index)
{
	// we do a CPU check here.
	unsigned char *binary = (unsigned char *)keystore_common_get_binary(source);
	unsigned char out[20];
	SHA_CTX ctx;
	unsigned char Pass[PLAINTEXT_LENGTH*2];
	int i;

	for (i = 0; i < inbuffer[index].length; ++i) {
		Pass[i<<1] = 0;
		Pass[(i<<1)+1] = inbuffer[index].pass[i];
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, Pass, inbuffer[index].length<<1);
	SHA1_Update(&ctx, "Mighty Aphrodite", 16);
	SHA1_Update(&ctx, cur_salt->salt, cur_salt->length);
	SHA1_Final(out, &ctx);
	return !memcmp(binary, out, 20);
}

struct fmt_main fmt_opencl_keystore = {
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
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
		/* FIXME: report cur_salt->length as tunable cost? */
		{ NULL },
		{ FORMAT_TAG },
		keystore_common_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		keystore_common_valid_cpu,
		fmt_default_split,
		keystore_common_get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		keystore_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* ifdef HAVE_OPENCL */
