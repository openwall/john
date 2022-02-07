/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>,
 * Copyright (c) 2012 Dhiru Kholia <dhiru at openwall.com> and
 * Copyright (c) 2012-2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_keyring;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_keyring);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "opencl_common.h"
#include "options.h"
#include "aes.h"
#include "sha2.h"
#include "md5.h"

#define FORMAT_LABEL		"keyring-opencl"
#define FORMAT_NAME		"GNOME Keyring"
#define FORMAT_TAG			"$keyring$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"SHA256 AES OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define PLAINTEXT_LENGTH	(55-8)
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4

#define SALTLEN 8

typedef unsigned char guchar; /* How many aliases do we need?! */
typedef unsigned int guint;
typedef int gint;

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} keyring_password;

typedef struct {
	uint32_t cracked;
} keyring_hash;

typedef struct {
	uint32_t length;
	uint32_t iterations;
	uint8_t salt[SALTLEN];
	uint32_t crypto_size;
	uint8_t ct[LINE_BUFFER_SIZE / 2]; /* after hex conversion */
} keyring_salt;

static int *cracked;

static struct custom_salt {
	unsigned int iterations;
	unsigned char salt[SALTLEN];
	unsigned int crypto_size;
	unsigned int inlined;
	unsigned char ct[LINE_BUFFER_SIZE / 2]; /* after hex conversion */
} *cur_salt;

static struct fmt_tests keyring_tests[] = {
	{"$keyring$db1b562e453a0764*3221*16*0*02b5c084e4802369c42507300f2e5e56", "openwall"},
	{"$keyring$4f3f1557a7da17f5*2439*144*0*12215fabcff6782aa23605ab2cd843f7be9477b172b615eaa9130836f189d32ffda2e666747378f09c6e76ad817154daae83a36c0a0a35f991d40bcfcba3b7807ef57a0ce4c7f835bf34c6e358f0d66aa048d73dacaaaf6d7fa4b3510add6b88cc237000ff13cb4dbd132db33be3ea113bedeba80606f86662cc226af0dad789c703a7df5ad8700542e0f7a5e1f10cf0", "password"},
	{NULL}
};

static keyring_password *inbuffer;
static keyring_hash *outbuffer;
static keyring_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static struct fmt_main *self;
static int new_keys;

#define insize (sizeof(keyring_password) * global_work_size)
#define outsize (sizeof(keyring_hash) * global_work_size)
#define settingsize (sizeof(keyring_salt))
#define cracked_size (sizeof(*cracked) * global_work_size)

#define STEP                    0
#define SEED                    256

static const char * warn[] = {
	"xfer: "  ,  ", crypt: "    ,  ", xfer: "
};

// This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t global_work_size, struct fmt_main *self)
{
	cl_int cl_error;

	release_clobj();

	inbuffer = (keyring_password*) mem_calloc(1, insize);
	outbuffer = (keyring_hash*) mem_alloc(outsize);

	cracked = mem_calloc(1, cracked_size);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
	}
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

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[128];
		cl_int cl_error;

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%d -DSALTLEN=%d -DLINE_BUFFER_SIZE=%d",
		         PLAINTEXT_LENGTH, SALTLEN, LINE_BUFFER_SIZE);
		opencl_init("$JOHN/opencl/keyring_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "keyring", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	int iter = MIN(db->max_cost[0], options.loader.max_cost[0]);

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       sizeof(keyring_password), 0, db);

	//Auto tune execution from shared/included code.
	autotune_run(self, iter, 0, 200);
}

static int looks_like_nice_int(char *p)
{
	// reasonability check + avoids atoi's UB
	if (strlen(p) > 9)
		return 0;
	for (; *p; p++)
		if (*p < '0' || *p > '9')
			return 0;
	return 1;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int ctlen, extra;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	if (keeptr == NULL)
		goto err;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	while (*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
			goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* crypto size */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	ctlen = atoi(p);
	if (ctlen > sizeof(cur_salt->ct))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* inlined - unused? TODO */
		goto err;
	if (!looks_like_nice_int(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if (ctlen > LINE_BUFFER_SIZE)
		goto err;
	if (hexlenl(p, &extra) != ctlen * 2 || extra)
		goto err;
	if (strlen(p) < 32)	/* this shouldn't happen for valid hashes */
		goto err;
	while (*p)
		if (atoi16l[ARCH_INDEX(*p++)] == 0x7f)
			goto err;

	MEM_FREE(keeptr);
	return 1;

      err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));

	if (!cur_salt)
		cur_salt = mem_alloc_tiny(sizeof(struct custom_salt),
		                          MEM_ALIGN_WORD);
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$keyring$" */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.crypto_size = atoi(p);
	p = strtokm(NULL, "*");
	cs.inlined = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.crypto_size; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy(currentsalt.salt, cur_salt->salt, SALTLEN);
	currentsalt.length = SALTLEN;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.crypto_size = cur_salt->crypto_size;
	memcpy(currentsalt.ct, cur_salt->ct, cur_salt->crypto_size);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
	                                    CL_FALSE, 0, settingsize,
	                                    &currentsalt, 0, NULL, NULL),
	               "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);

	new_keys = 1;
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
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");

		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]),
	    "Run kernel");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]), "Copy result back");

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

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int)my_salt->iterations;
}

struct fmt_main fmt_opencl_keyring = {
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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		keyring_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
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
