/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for Keychain format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include <openssl/des.h>
#include "common-opencl.h"
#include "gladman_fileenc.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"zip-opencl"
#define FORMAT_NAME		"ZIP-AES PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define	KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(zip_cpu_salt)

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
	uint8_t length;
	uint8_t v[24];
} zip_password;

typedef struct {
	uint32_t v[17];
} zip_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
} zip_salt;

static int *cracked;

typedef struct {
	uint8_t length;
	uint8_t salt[20];
	int type;		/* type of zip file */
	int mode;
	unsigned char passverify[2];
} zip_cpu_salt;

zip_cpu_salt *cur_salt;

static struct fmt_tests zip_tests[] = {
	{"$zip$*0*1*8005b1b7d077708d*dee4", "testpassword#"},
	{"$zip$*0*3*e3bd6c1a4c4950d0c35c1b0ca2bd5e84*061f", "testpassword#"},
	{NULL}
};

static zip_password *inbuffer;
static zip_hash *outbuffer;
static zip_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(zip_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(zip_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(zip_salt);

#ifdef DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static void release_all(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release Kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
}
static void init(struct fmt_main *self)
{
	cl_int cl_error;

	global_work_size = MAX_KEYS_PER_CRYPT;

	inbuffer =
	    (zip_password *) malloc(sizeof(zip_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (zip_hash *) malloc(sizeof(zip_hash) * MAX_KEYS_PER_CRYPT);

	/* Zeroize the lengths in case crypt_all() is called with some keys still
	 * not set.  This may happen during self-tests. */
	{
		int i;
		for (i = 0; i < MAX_KEYS_PER_CRYPT; i++)
			inbuffer[i].length = 0;
	}

	cracked = mem_calloc_tiny(sizeof(*cracked) *
			KEYS_PER_CRYPT, MEM_ALIGN_WORD);

	//listOpenCLdevices();
	opencl_init("$JOHN/zip_kernel.cl", ocl_gpu_id, platform_id);
	/// Alocate memory
	mem_in =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem in");
	mem_setting =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem setting");
	mem_out =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem out");

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "zip", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_salt kernel argument");
	opencl_find_best_workgroup(self);

	atexit(release_all);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$zip$", 5);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	char *encoded_salt;
	static zip_cpu_salt cs;
	int strength, n;

	ctcopy += 6;	/* skip over "$zip$*" */
	cs.type = atoi(strtok(ctcopy, "*"));
	strength = atoi(strtok(NULL, "*"));
	cs.mode = strength;
	switch (strength) {
	case 1:
		n = 8;
		break;
	case 2:
		n = 12;
		break;
	case 3:
		n = 16;
		break;
	default:
		fprintf(stderr, "ZIP: Unsupported strength %d\n", strength);
		error();
		n = 0; /* Not reached */
	}
	cs.length = n;
	encoded_salt = strtok(NULL, "*");
	for (i = 0; i < n; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(encoded_salt[i * 2])] * 16
		    + atoi16[ARCH_INDEX(encoded_salt[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 2; i++)
		cs.passverify[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (zip_cpu_salt*)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->length);
	currentsalt.length = cur_salt->length;
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

static void crypt_all(int count)
{
	int index;
	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	    "Copy setting to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent),
	    "Run kernel");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0,
		outsize, outbuffer, 0, NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

	for (index = 0; index < count; index++)
	{
		unsigned char pwd_ver[2] = { 0 };
		unsigned char *p;
		p = (unsigned char*)outbuffer[index].v;
		memcpy(pwd_ver, p + 2 * KEY_LENGTH(cur_salt->mode), 2);
		if(!memcmp(pwd_ver, cur_salt->passverify, 2))
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}

}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_zip = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		zip_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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
