/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for 7z format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

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
#include "sha2.h"
#include "md5.h"
#include "crc32.h"
#include "stdint.h"

#define FORMAT_LABEL		"7z-opencl"
#define FORMAT_NAME		"7-Zip"
#define ALGORITHM_NAME		"SHA256 AES OPENCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	8*1024
#define MAX_KEYS_PER_CRYPT	MIN_KEYS_PER_CRYPT
#define PLAINTEXT_LENGTH	12
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4

#define BIG_ENOUGH 		(8192 * 32)

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} sevenzip_password;

typedef struct {
	uint8_t key[32];
} sevenzip_hash;

typedef struct {
	uint32_t length;
	uint32_t iterations;
	uint8_t salt[16];
} sevenzip_salt;

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
static cl_mem mem_in, mem_out, mem_setting;

#define insize (sizeof(sevenzip_password) * global_work_size)
#define outsize (sizeof(sevenzip_hash) * global_work_size)
#define settingsize (sizeof(sevenzip_salt))
#define cracked_size (sizeof(*cracked) * global_work_size)

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
	MEM_FREE(cracked);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

static void init(struct fmt_main *self)
{
	CRC32_t crc;
	char build_opts[64];
	cl_int cl_error;
	char *temp;
	cl_ulong maxsize;

	CRC32_Init(&crc);
	snprintf(build_opts, sizeof(build_opts),
	         "-DPLAINTEXT_LENGTH=%d",
	         PLAINTEXT_LENGTH);
	opencl_init("$JOHN/kernels/7z_kernel.cl",
	                gpu_id, build_opts);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);
	else
		local_work_size = cpu(device_info[gpu_id]) ? 1 : 64;

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);
	else
		global_work_size = MAX_KEYS_PER_CRYPT;

	crypt_kernel = clCreateKernel(program[gpu_id], "sevenzip", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max workgroup size");

	while (local_work_size > maxsize)
		local_work_size >>= 1;

	inbuffer = (sevenzip_password *) mem_calloc(insize);
	outbuffer = (sevenzip_hash *) mem_alloc(outsize);

	cracked = mem_calloc(cracked_size);

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

	self->params.max_keys_per_crypt = global_work_size;
	if (!local_work_size)
		opencl_find_best_workgroup(self);

	self->params.min_keys_per_crypt = local_work_size;

	if (options.verbosity > 2)
		fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
}

// XXX implement valid
static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext,  "$7z$", 4) != 0)
		return 0;

	return 1;
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
	p = strtok(ctcopy, "$");
	cs->type = atoi(p);
	p = strtok(NULL, "$");
	cs->NumCyclesPower = atoi(p);
	p = strtok(NULL, "$");
	cs->SaltSize = atoi(p);
	p = strtok(NULL, "$"); /* salt */
	p = strtok(NULL, "$");
	cs->ivSize = atoi(p);
	p = strtok(NULL, "$"); /* iv */
	for (i = 0; i < cs->ivSize; i++)
		cs->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$"); /* crc */
	cs->crc = atoi(p);
	p = strtok(NULL, "$");
	cs->length = atoi(p);
	p = strtok(NULL, "$");
	cs->unpacksize = atoi(p);
	p = strtok(NULL, "$"); /* crc */
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
}

static void sevenzip_set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	inbuffer[index].length = length;
	inbuffer[index].v[length]= 0;
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
	int count = *pcount;
	int index;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent),
	    "Run kernel");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, outbuffer, 0, NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		/* do decryptiion and checks */
		if(sevenzip_decrypt(outbuffer[index].key, cur_salt->data) == 0)
			any_cracked = cracked[index] = 1;
		else
			cracked[index] = 0;
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

struct fmt_main fmt_opencl_sevenzip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT | FMT_UNICODE,
#if FMT_MAIN_VERSION > 11
		{
		}
#endif
		sevenzip_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
		}
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		sevenzip_set_key,
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
