/*
 * This software is Copyright (c) 2018 magnum
 * Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com>
 * Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_keychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_keychain);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "options.h"
#include "jumbo.h"
#include "opencl_common.h"

#define FORMAT_LABEL		"keychain-opencl"
#define FORMAT_NAME			"Mac OS X Keychain"
#define FORMAT_TAG			"$keychain$*"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"PBKDF2-SHA1 3DES OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BINARY_SIZE			0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE			sizeof(*salt_struct)
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_ALIGN			4
#define SALTLEN				20
#define IVLEN 				8
#define CTLEN				48

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pbkdf2_password;

typedef struct {
	uint32_t v[24/4];
} pbkdf2_hash;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  length;
	uint8_t  salt[64];
} pbkdf2_salt;

typedef struct {
	pbkdf2_salt pbkdf2;
	unsigned char iv[8];
	unsigned char ct[CTLEN];
} keychain_salt;

typedef struct {
	uint32_t cracked;
} keychain_out;

static struct fmt_main *self;

static struct fmt_tests keychain_tests[] = {
	{"$keychain$*10f7445c8510fa40d9ef6b4e0f8c772a9d37e449*f3d19b2a45cdcccb*8c3c3b1c7d48a24dad4ccbd4fd794ca9b0b3f1386a0a4527f3548bfe6e2f1001804b082076641bbedbc9f3a7c33c084b", "password"},
	// these were generated with pass_gen.pl.  NOTE, they ALL have the data (which gets encrypted) which was decrypted from the above hash.
	{"$keychain$*a88cd6fbaaf40bc5437eee015a0f95ab8ab70545*b12372b1b7cb5c1f*1f5c596bcdd015afc126bc86f42dd092cb9d531d14a0aafaa89283f1bebace60562d497332afbd952fd329cc864144ec", "password"},
	{"$keychain$*23328e264557b93204dc825c46a25f7fb1e17d4a*19a9efde2ca98d30*6ac89184134758a95c61bd274087ae0cffcf49f433c7f91edea98bd4fd60094e2936d99e4d985dec98284379f23259c0", "hhh"},
	{"$keychain$*927717d8509db73aa47c5e820e3a381928b5e048*eef33a4a1483ae45*a52691580f17e295b8c2320947968503c605b2784bfe4851077782139f0de46f71889835190c361870baa56e2f4e9e43", "JtR-Jumbo"},
	{"$keychain$*1fab88d0b8ea1a3d303e0aef519796eb29e46299*3358b0e77d60892f*286f975dcd191024227514ed9939d0fa94034294ba1eca6d5c767559e75e944b5a2fcb54fd696be64c64f9d069ce628a", "really long password -----------------------------"},
	{NULL}
};

static struct custom_salt {
	unsigned char salt[SALTLEN];
	unsigned char iv[IVLEN];
	unsigned char ct[CTLEN];
} *salt_struct;

static cl_int cl_error;
static pbkdf2_password *inbuffer;
static keychain_out *outbuffer;
static keychain_salt currentsalt;
static cl_mem mem_in, mem_dk, mem_salt, mem_out;

size_t insize, dksize, saltsize, outsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

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
	insize = sizeof(pbkdf2_password) * gws;
	dksize = sizeof(pbkdf2_hash) * gws;
	saltsize = sizeof(keychain_salt);
	outsize = sizeof(keychain_out) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);

	/// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_dk =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, dksize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_dk),
		&mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (outbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_dk), "Release mem dk");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
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
		char build_opts[96];

		snprintf(build_opts, sizeof(build_opts),
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d -DCTLEN=%d",
		         PLAINTEXT_LENGTH,
		         (int)sizeof(currentsalt.pbkdf2.salt),
		         (int)sizeof(pbkdf2_hash), CTLEN);
		opencl_init("$JOHN/kernels/keychain_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "keychain", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(pbkdf2_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) != IVLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if (hexlenl(p, &extra) != CTLEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt *salt_struct;

	if (!salt_struct)
		salt_struct = mem_calloc_tiny(sizeof(struct custom_salt),
	                              MEM_ALIGN_WORD);
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$keychain$*" */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		salt_struct->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < IVLEN; i++)
		salt_struct->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < CTLEN; i++)
		salt_struct->ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)salt_struct;
}

static void set_salt(void *salt)
{
	salt_struct = (struct custom_salt *)salt;
	memcpy(currentsalt.pbkdf2.salt, salt_struct->salt, 20);
	currentsalt.pbkdf2.length = 20;
	currentsalt.pbkdf2.iterations = 1000;
	currentsalt.pbkdf2.outlen = 24;
	currentsalt.pbkdf2.skip_bytes = 0;
	memcpy(currentsalt.iv, salt_struct->iv, 8);
	memcpy(currentsalt.ct, salt_struct->ct, CTLEN);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
	    "Copy salt to gpu");
}

static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);

	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t gws = count;
	size_t *lws = (local_work_size && !(gws % local_work_size)) ?
		&local_work_size : NULL;

	/// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
	        "Copy data to gpu");

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &gws, lws, 0, NULL,
	        multi_profilingEvent[1]), "Run kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (outbuffer[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return outbuffer[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_keychain = {
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
		FMT_CASE | FMT_8_BIT | FMT_NOT_EXACT,
		{ NULL },
		{ FORMAT_TAG },
		keychain_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
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

#endif /* HAVE_OPENCL */
