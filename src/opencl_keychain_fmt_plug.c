/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for Keychain format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_keychain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_keychain);
#else

#include <string.h>
#include <openssl/des.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "stdint.h"
#include "misc.h"
#include "options.h"
#include "jumbo.h"
#include "common-opencl.h"

#define FORMAT_LABEL		"keychain-opencl"
#define FORMAT_NAME		"Mac OS X Keychain"
#define ALGORITHM_NAME		"PBKDF2-SHA1 OpenCL 3DES"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(*salt_struct)
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_ALIGN		4
#define SALTLEN 20
#define IVLEN 8
#define CTLEN 48

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} keychain_password;

typedef struct {
	uint32_t v[32/4];
} keychain_hash;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint8_t  length;
	uint8_t  salt[SALTLEN];
} keychain_salt;

static int *cracked;
static int any_cracked;
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
static keychain_password *inbuffer;
static keychain_hash *outbuffer;
static keychain_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;

size_t insize, outsize, settingsize, cracked_size;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
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
	insize = sizeof(keychain_password) * gws;
	outsize = sizeof(keychain_hash) * gws;
	settingsize = sizeof(keychain_salt);
	cracked_size = sizeof(*cracked) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);
	cracked = mem_calloc(1, cracked_size);

	/// Allocate memory
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
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
		         PLAINTEXT_LENGTH,
		         (int)sizeof(currentsalt.salt),
		         (int)sizeof(outbuffer->v));
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_unsplit_kernel.cl",
		            gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "derive_key", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(keychain_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	if (strncmp(ciphertext,  "$keychain$*", 11) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 11;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if(hexlenl(p) != SALTLEN * 2)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if(hexlenl(p) != IVLEN * 2)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if(hexlenl(p) != CTLEN * 2)
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
	ctcopy += 11;	/* skip over "$keychain$*" */
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
	memcpy((char*)currentsalt.salt, salt_struct->salt, 20);
	currentsalt.length = 20;
	currentsalt.iterations = 1000;
	currentsalt.outlen = 24;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy salt to gpu");
}

#undef set_key
static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
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

static int kcdecrypt(unsigned char *key, unsigned char *iv, unsigned char *data)
{
	unsigned char out[CTLEN];
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;
	memset(out, 0, sizeof(out));
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, CTLEN, &ks1, &ks2, &ks3, &ivec,  DES_DECRYPT);

	/* possible bug here, is this assumption (pad of 4) always valid? */
	if (out[47] != 4 || check_pkcs_pad(out, CTLEN, 8) < 0)
		return -1;

	return 0;
}

#if 0
//#ifdef DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	/// Copy data to gpu
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

	if (ocl_autotune_running)
		return count;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	if (!kcdecrypt((unsigned char*)outbuffer[index].v,
	               salt_struct->iv, salt_struct->ct))
	{
		cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
		any_cracked |= 1;
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
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
