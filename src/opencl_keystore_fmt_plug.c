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
#include "opencl_common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "keystore_common.h"

#define FORMAT_LABEL            "keystore-opencl"
#define FORMAT_NAME             "Java KeyStore"
#define ALGORITHM_NAME          "SHA1 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define BUFSIZE                 ((PLAINTEXT_LENGTH + 3) / 4 * 4)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

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

static keystore_hash *outbuffer;
static keystore_salt saltbuffer;

static int new_keys;
static struct fmt_main *self;

static size_t outsize, saltsize;
static unsigned int key_idx;

static cl_uint *saved_plain, *saved_idx;
static cl_mem pinned_saved_keys, pinned_saved_idx;

static cl_mem buffer_keys, buffer_idx;
static cl_mem mem_out, mem_salt;

static cl_int cl_err;

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char *warn[] = {
	"key xfer: ",  ", idx xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	outsize = sizeof(keystore_hash) * gws;
	saltsize = sizeof(keystore_salt);

	outbuffer = mem_alloc(outsize);

	// Allocate memory
	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * gws, NULL, &ret_code);
	if (ret_code != CL_SUCCESS) {
		saved_plain = mem_calloc(gws, BUFSIZE);
		if (saved_plain == NULL)
			HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys.");
	}
	else {
		saved_plain = clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * gws, 0, NULL, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain.");
		memset(saved_plain, 0, BUFSIZE * gws);
	}

	pinned_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx.");
	saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx.");
	memset(saved_idx, 0, sizeof(cl_uint) * gws);

	buffer_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BUFSIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys.");

	buffer_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx.");

	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_err);
	HANDLE_CLERROR(cl_err, "Error allocating mem_salt");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize,
	    NULL, &cl_err);
	HANDLE_CLERROR(cl_err, "Error allocating mem_out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys),
		&buffer_keys), "Error setting kernel arg");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx),
		&buffer_idx), "Error setting kernel arg");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_out),
		&mem_out), "Error setting kernel arg");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(mem_salt),
		&mem_salt), "Error setting kernel arg");
}

static void release_clobj(void)
{
	if (outbuffer) {
		if (pinned_saved_keys) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id],
				pinned_saved_keys, saved_plain, 0, NULL, NULL),
			               "Unmap saved_plain.");
			HANDLE_CLERROR(clFinish(queue[gpu_id]),
			               "Release mappings.");
			HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys),
			               "Release pinned_saved_keys.");
		}
		else
			MEM_FREE(saved_plain);

		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx,
			saved_idx, 0, NULL, NULL), "Unmap saved_idx.");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Release mappings.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Release buffer pinned_saved_idx.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Release buffer_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Release buffer_idx.");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");

		MEM_FREE(outbuffer);
	}
}


static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
				"-DPASSLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
				PLAINTEXT_LENGTH, SALT_LENGTH_GPU, 4);

		opencl_init("$JOHN/opencl/keystore_kernel.cl", gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "keystore", &cl_err);
		HANDLE_CLERROR(cl_err, "Error creating keystore kernel");
	}

	// Current key_idx can only hold 25 bits of offset so
	// we can't reliably use a GWS higher than 1M or so.
	size_t gws_limit = MIN((1 << 25) / (BUFSIZE / 4),
	                       get_max_mem_alloc_size(gpu_id) / BUFSIZE);

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(0, 0, NULL, warn, 2, self,
	                       create_clobj, release_clobj,
	                       BUFSIZE, gws_limit, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 200);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void *get_salt(char *ciphertext)
{
	/* NOTE: do we need dynamic allocation because of underlying large object size? */
	static struct custom_salt *cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	const char *magic  = "Mighty Aphrodite";
	int         maglen = 16;

	if (!cs) cs = mem_alloc_tiny(sizeof(struct custom_salt),16);
	memset(cs, 0, sizeof(struct custom_salt));

	ctcopy += FORMAT_TAG_LEN; 				// skip over "$keystore$"
	p = strtokm(ctcopy, "$");   // skip target
	p = strtokm(NULL, "$");
	cs->length = atoi(p);
	p = strtokm(NULL, "$");
	// Before each salt from the ciphertext, prepend "Mighty Aphrodite":
	memcpy(cs->salt, magic, maglen);
	for (i = 0; i < cs->length; ++i)
		cs->salt[maglen + i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			        + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs->length += maglen;
	MEM_FREE(keeptr);
	return (void*)cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	saltbuffer.length = cur_salt->length;
	memcpy(saltbuffer.salt, cur_salt->salt, cur_salt->length);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
	                                    CL_FALSE, 0, cur_salt->length + 4,
	                                    &saltbuffer, 0, NULL, NULL),
	               "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *_key, int index)
{
	const uint32_t *key = (uint32_t*)_key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 7) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));
	new_keys = 1;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len;
	char *key;

	len = saved_idx[index] & 127;
	key = (char*)&saved_plain[saved_idx[index] >> 7];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	if (new_keys) {
		if (key_idx)
			BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys,
				CL_FALSE, 0, 4 * key_idx, saved_plain, 0, NULL,
				multi_profilingEvent[0]),
				"failed in clEnqueueWriteBuffer buffer_keys.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_FALSE,
			0, 4 * gws, saved_idx, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueWriteBuffer buffer_idx.");
		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &gws, lws, 0, NULL,
	        multi_profilingEvent[2]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[3]),
	              "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i, b = ((uint32_t*)binary)[0];

	for (i = 0; i < count; ++i)
		if (b == outbuffer[i].gpu_out)
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (((uint32_t*)binary)[0] != outbuffer[index].gpu_out)
		return 0;

	return 1;
}

static int cmp_exact(char *source, int index)
{
	// we do a CPU check here.
	unsigned char *binary = (unsigned char*)keystore_common_get_binary(source);
	unsigned char out[20];
	SHA_CTX ctx;
	unsigned char Pass[PLAINTEXT_LENGTH * 2];
	int i;
	int len = saved_idx[index] & 127;
	char *key = (char*)&saved_plain[saved_idx[index] >> 7];

	// This is NOT a crappy UTF-16 conversion although it look like it
	for (i = 0; i < len; ++i) {
		Pass[i << 1] = 0;
		Pass[(i << 1) + 1] = key[i];
	}
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, Pass, len << 1);
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
		set_key,
		get_key,
		clear_keys,
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
