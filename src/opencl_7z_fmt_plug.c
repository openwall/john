/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for 7z format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_sevenzip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_sevenzip);
#else

#include <string.h>
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "common-opencl.h"
#include "options.h"
#include "crc32.h"
#include "stdint.h"
#include "unicode.h"
#include "memdbg.h"

#define FORMAT_LABEL		"7z-opencl"
#define FORMAT_NAME		"7-Zip"
#define FORMAT_TAG		"$7z$"
#define TAG_LENGTH		4
#define ALGORITHM_NAME		"SHA256 OPENCL AES"
#define BENCHMARK_COMMENT	" (512K iterations)"
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define PLAINTEXT_LENGTH	((55-8)/2)
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4

#define BIG_ENOUGH 		(8192 * 32)

typedef struct {
	uint32_t length;
	uint16_t v[PLAINTEXT_LENGTH];
} sevenzip_password;

typedef struct {
	uint8_t key[32];
} sevenzip_hash;

typedef struct {
	uint32_t length;
	uint32_t iterations;
	uint8_t salt[16];
} sevenzip_salt;

typedef struct {
	cl_uint total[2];
	cl_uint state[8];
	cl_uchar buffer[64];
} SHA256_CTX;

typedef struct {
	cl_ulong t;
	SHA256_CTX ctx;
	cl_uint len;
	cl_ushort buffer[PLAINTEXT_LENGTH];
} sevenzip_state;

static int *cracked;
static int any_cracked;

static struct custom_salt {
	int NumCyclesPower;
	int SaltSize;
	int ivSize;
	int type;
	unsigned char data[BIG_ENOUGH];
	unsigned char iv[16];
	unsigned char salt[16];
	unsigned int crc;
	int length;     /* used in decryption */
	int unpacksize; /* used in CRC calculation */
} *cur_salt;

static struct fmt_tests sevenzip_tests[] = {
	/* CRC checks passes for these hashes */
	{"$7z$0$19$0$1122$8$d1f50227759415890000000000000000$1412385885$112$112$5e5b8b734adf52a64c541a5a5369023d7cccb78bd910c0092535dfb013a5df84ac692c5311d2e7bbdc580f5b867f7b5dd43830f7b4f37e41c7277e228fb92a6dd854a31646ad117654182253706dae0c069d3f4ce46121d52b6f20741a0bb39fc61113ce14d22f9184adafd6b5333fb1", "password"},
	{"$7z$0$19$0$1122$8$a264c94f2cd72bec0000000000000000$725883103$112$108$64749c0963e20c74602379ca740165b9511204619859d1914819bc427b7e5f0f8fc67f53a0b53c114f6fcf4542a28e4a9d3914b4bc76baaa616d6a7ec9efc3f051cb330b682691193e6fa48159208329460c3025fb273232b82450645f2c12a9ea38b53a2331a1d0858813c8bf25a831", "openwall"},
	/* padding check passes for these hashes */
	{"$7z$0$19$0$1122$8$732b59fd26896e410000000000000000$2955316379$192$183$7544a3a7ec3eb99a33d80e57907e28fb8d0e140ec85123cf90740900429136dcc8ba0692b7e356a4d4e30062da546a66b92ec04c64c0e85b22e3c9a823abef0b57e8d7b8564760611442ecceb2ca723033766d9f7c848e5d234ca6c7863a2683f38d4605322320765938049305655f7fb0ad44d8781fec1bf7a2cb3843f269c6aca757e509577b5592b60b8977577c20aef4f990d2cb665de948004f16da9bf5507bf27b60805f16a9fcc4983208297d3affc4455ca44f9947221216f58c337f", "password"},
	/* not supported hashes, will require validFolder check */
	// {"$7z$0$19$0$1122$8$5fdbec1569ff58060000000000000000$2465353234$112$112$58ba7606aafc7918e3db7f6e0920f410f61f01e9c1533c40850992fee4c5e5215bc6b4ea145313d0ac065b8ec5b47d9fb895bb7f97609be46107d71e219544cfd24b52c2ecd65477f72c466915dcd71b80782b1ac46678ab7f437fd9f7b8e9d9fad54281d252de2a7ae386a65fc69eda", "password"},
	{NULL}
};

static sevenzip_password *inbuffer;
static sevenzip_hash *outbuffer;
static sevenzip_salt currentsalt;
static cl_mem mem_in, mem_out, mem_state, mem_salt;
static cl_kernel sevenzip_init;

#define insize (sizeof(sevenzip_password) * global_work_size)
#define outsize (sizeof(sevenzip_hash) * global_work_size)
#define statesize (sizeof(sevenzip_state) * global_work_size)
#define saltsize (sizeof(sevenzip_salt))
#define cracked_size (sizeof(*cracked) * global_work_size)
static struct fmt_main *self;

#define HASH_LOOPS	4096
#define LOOP_COUNT	((1 << currentsalt.iterations) + HASH_LOOPS - 1) / HASH_LOOPS
#define STEP		0
#define SEED		16

static int split_events[] = { 2, -1, -1 };

static const char *warn[] = {
	"xfer: "  ,  ", init: ",  ", crypt: ",  ", xfer: "
};

// This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, sevenzip_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64;
}

static void create_clobj(size_t global_work_size, struct fmt_main *self)
{
	cl_int cl_error;

	inbuffer = (sevenzip_password*) mem_calloc(1, insize);
	outbuffer = (sevenzip_hash*) mem_alloc(outsize);

	cracked = mem_calloc(1, cracked_size);

	// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_state =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, statesize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem state");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(sevenzip_init, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_init, 1, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(sevenzip_init, 2, sizeof(mem_state),
		&mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_state),
		&mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
		MEM_FREE(cracked);
	}
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(sevenzip_init), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

static int crypt_all(int *pcount, struct db_salt *salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *salt);

static void init(struct fmt_main *_self)
{
	CRC32_t crc;
	char build_opts[64];
	cl_int cl_error;

	self = _self;

	CRC32_Init(&crc);
	snprintf(build_opts, sizeof(build_opts),
	         "-DPLAINTEXT_LENGTH=%d -DHASH_LOOPS=%d",
	         PLAINTEXT_LENGTH, HASH_LOOPS);
	opencl_init("$JOHN/kernels/7z_kernel.cl",
	                gpu_id, build_opts);

	sevenzip_init = clCreateKernel(program[gpu_id], "sevenzip_init",
	                               &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");

	crypt_kernel = clCreateKernel(program[gpu_id], "sevenzip_crypt",
	                              &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");

	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static void reset(struct db_main *db)
{
	if (!db) {
		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
		                       warn, 2, self,
		                       create_clobj, release_clobj,
		                       sizeof(sevenzip_salt), 0);

		//  Auto tune execution from shared/included code.
		self->methods.crypt_all = crypt_all_benchmark;
		autotune_run(self, 1 << 19, 0, 15000000000ULL);
		self->methods.crypt_all = crypt_all;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, type, NumCyclesPower;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (strlen(p) > 1)
		goto err;
	type = atoi(p);
	if (type != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* NumCyclesPower */
		goto err;
	if (strlen(p) > 2)
		goto err;
	NumCyclesPower = atoi(p);
	if (NumCyclesPower > 24 || NumCyclesPower < 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt length */
		goto err;
	len = atoi(p);
	if(len > 16 || len < 0) /* salt length */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv length */
		goto err;
	if (strlen(p) > 2)
		goto err;
	len = atoi(p);
	if(len < 0 || len > 16) /* iv length */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv */
		goto err;
	if (!ishex(p))
		goto err;
	if (strlen(p) > len*2 && strcmp(p+len*2, "0000000000000000"))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* crc */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* data length */
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* unpacksize */
		goto err;
	if (!isdec(p))	/* no way to validate, other than atoi() works for it */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* data */
		goto err;
	if (strlen(p) != len * 2)	/* validates data_len atoi() */
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

	static union {
		struct custom_salt _cs;
		ARCH_WORD_32 dummy;
	} un;
	struct custom_salt *cs = &(un._cs);

	ctcopy += 4;
	p = strtokm(ctcopy, "$");
	cs->type = atoi(p);
	p = strtokm(NULL, "$");
	cs->NumCyclesPower = atoi(p);
	p = strtokm(NULL, "$");
	cs->SaltSize = atoi(p);
	p = strtokm(NULL, "$"); /* salt */
	p = strtokm(NULL, "$");
	cs->ivSize = atoi(p);
	p = strtokm(NULL, "$"); /* iv */
	for (i = 0; i < cs->ivSize; i++)
		cs->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); /* crc */
	cs->crc = atou(p);
	p = strtokm(NULL, "$");
	cs->length = atoi(p);
	p = strtokm(NULL, "$");
	cs->unpacksize = atoi(p);
	p = strtokm(NULL, "$"); /* crc */
	for (i = 0; i < cs->length; i++)
		cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->SaltSize);
	currentsalt.length = cur_salt->SaltSize;
	currentsalt.iterations = cur_salt->NumCyclesPower;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
		"Transfer salt to gpu");
}

static void clear_keys(void)
{
	memset(inbuffer, 0, insize);
}

static void sevenzip_set_key(char *key, int index)
{
	UTF16 c_key[PLAINTEXT_LENGTH + 1];
	int length = strlen(key);

	/* Convert password to utf-16-le format (--encoding aware) */
	length = enc_to_utf16(c_key, PLAINTEXT_LENGTH,
	                      (UTF8*)key, length);
	if (length <= 0)
		length = strlen16(c_key);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, c_key, 2 * length);
}

static char *get_key(int index)
{
	UTF16 c_key[PLAINTEXT_LENGTH + 1];
	int length = inbuffer[index].length;

	memcpy(c_key, inbuffer[index].v, 2 * length);
	c_key[length] = 0;

	return (char*)utf16_to_enc(c_key);
}

// XXX port Python code to C *OR* use code from LZMA SDK
static int validFolder(unsigned char *data)
{
	// int numcoders = self._read64Bit(file)
	return 0;
}

static int sevenzip_decrypt(unsigned char *derived_key, unsigned char *data)
{
	unsigned char out[cur_salt->length];
	AES_KEY akey;
	unsigned char iv[16];
	union {
		unsigned char crcc[4];
		unsigned int crci;
	} _crc_out;
	unsigned char *crc_out = _crc_out.crcc;
	unsigned int ccrc;
	CRC32_t crc;
	int i;
	int nbytes, margin;
	memcpy(iv, cur_salt->iv, 16);

	if(AES_set_decrypt_key(derived_key, 256, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");
	}
	AES_cbc_encrypt(cur_salt->data, out, cur_salt->length, &akey, iv, AES_DECRYPT);

	/* various verifications tests */

	// test 0, padding check, bad hack :-(
	margin = nbytes = cur_salt->length - cur_salt->unpacksize;
	i = cur_salt->length - 1;
	while (nbytes > 0) {
		if (out[i] != 0)
			return -1;
		nbytes--;
		i--;
	}
	if (margin > 7) {
		// printf("valid padding test ;-)\n");
		// print_hex(out, cur_salt->length);
		return 0;
	}

	// test 1, CRC test
	CRC32_Init(&crc);
	CRC32_Update(&crc, out, cur_salt->unpacksize);
	CRC32_Final(crc_out, crc);
	ccrc =  _crc_out.crci; // computed CRC
	if (ccrc == cur_salt->crc)
		return 0;  // XXX don't be too eager!

	// XXX test 2, "well-formed folder" test
	if (validFolder(out)) {
		printf("validFolder check ;-)\n");
		return 0;
	}

	return -1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, index;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL),
	        "Copy data to gpu");

	// Run 1st kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_init, 1,
		NULL, &global_work_size, lws, 0, NULL, NULL),
		"Run init kernel");

	// Run loop kernel
	for (i = 0; i < LOOP_COUNT; i++) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
			crypt_kernel, 1, NULL, &global_work_size, lws, 0,
		        NULL, NULL),
		        "Run loop kernel");
		HANDLE_CLERROR(clFinish(queue[gpu_id]),
		               "Error running loop kernel");
		opencl_process_event();
	}

	// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, NULL),
	        "Copy result back");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		/* decrypt and check */
		if(sevenzip_decrypt(outbuffer[index].key, cur_salt->data) == 0)
		{
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}
	return count;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;

	// Copy data to gpu
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
	        "Copy data to gpu");

	// Run 1st kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], sevenzip_init, 1,
		NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]),
		"Run init kernel");

	// Warm-up run
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		crypt_kernel, 1, NULL, &global_work_size, lws, 0,
	        NULL, NULL),
	        "Run loop kernel");

	// Loop kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		crypt_kernel, 1, NULL, &global_work_size, lws, 0,
	        NULL, multi_profilingEvent[2]),
	        "Run loop kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[3]),
	        "Copy result back");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");

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

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)(1 << my_salt->NumCyclesPower);
}
#endif

struct fmt_main fmt_opencl_sevenzip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT | FMT_UNICODE | FMT_UTF8,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		sevenzip_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		sevenzip_set_key,
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

#endif /* HAVE_OPENCL */
