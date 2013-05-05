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
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"keychain-opencl"
#define FORMAT_NAME		"Mac OS X Keychain PBKDF2-HMAC-SHA-1 3DES"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1024*9
#define MAX_KEYS_PER_CRYPT	MIN_KEYS_PER_CRYPT
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(*salt_struct)
#define SALTLEN 20
#define IVLEN 8
#define CTLEN 48

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		ARCH_WORD_32

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} keychain_password;

typedef struct {
	uint32_t v[32/4];
} keychain_hash;

typedef struct {
	uint8_t  length;
	uint8_t  salt[SALTLEN];
	uint32_t iterations;
	uint32_t outlen;
} keychain_salt;

static int *cracked;
static int any_cracked;

static struct fmt_tests keychain_tests[] = {
	{"$keychain$*10f7445c8510fa40d9ef6b4e0f8c772a9d37e449*f3d19b2a45cdcccb*8c3c3b1c7d48a24dad4ccbd4fd794ca9b0b3f1386a0a4527f3548bfe6e2f1001804b082076641bbedbc9f3a7c33c084b", "password"},
	{NULL}
};

static struct custom_salt {
	unsigned char salt[SALTLEN];
	unsigned char iv[IVLEN];
	unsigned char ct[CTLEN];
} *salt_struct;

static keychain_password *inbuffer;
static keychain_hash *outbuffer;
static keychain_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;

#define insize (sizeof(keychain_password) * global_work_size)
#define outsize (sizeof(keychain_hash) * global_work_size)
#define settingsize (sizeof(keychain_salt))
#define cracked_size (sizeof(*cracked) * global_work_size)

/*
static void done(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release Kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");

	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
	MEM_FREE(cracked);
}
*/

static void init(struct fmt_main *self)
{
	cl_int cl_error;
	char build_opts[64];
	char *temp;
	cl_ulong maxsize;

	snprintf(build_opts, sizeof(build_opts),
	         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
	         PLAINTEXT_LENGTH,
	         (int)sizeof(currentsalt.salt),
	         (int)sizeof(outbuffer->v));
	opencl_init_opt("$JOHN/kernels/pbkdf2_hmac_sha1_unsplit_kernel.cl",
	                ocl_gpu_id, platform_id, build_opts);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);
	else
		local_work_size = cpu(device_info[ocl_gpu_id]) ? 1 : 64;

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);
	else
		global_work_size = MAX_KEYS_PER_CRYPT;

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "derive_key", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max workgroup size");

	while (local_work_size > maxsize)
		local_work_size >>= 1;

	inbuffer =
		(keychain_password *) mem_calloc(sizeof(keychain_password) *
		                             global_work_size);
	outbuffer =
	    (keychain_hash *) mem_alloc(sizeof(keychain_hash) * global_work_size);

	cracked = mem_calloc(sizeof(*cracked) * global_work_size);

	/// Allocate memory
	mem_in =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_setting =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");
	mem_out =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
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

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);

	//atexit(done);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	if (strncmp(ciphertext,  "$keychain$*", 11) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 11;
	if ((p = strtok(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if(strlen(p) != SALTLEN * 2)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iv */
		goto err;
	if(strlen(p) != IVLEN * 2)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if(strlen(p) != CTLEN * 2)
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
	ctcopy += 11;	/* skip over "$keychain$*" */
	salt_struct = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtok(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		salt_struct->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < IVLEN; i++)
		salt_struct->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
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
	int pad, n, i;
	DES_cblock key1, key2, key3;
	DES_cblock ivec;
	DES_key_schedule ks1, ks2, ks3;
	memset(out, 0, sizeof(out));
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	DES_set_key((C_Block *) key1, &ks1);
	DES_set_key((C_Block *) key2, &ks2);
	DES_set_key((C_Block *) key3, &ks3);
	memcpy(ivec, iv, 8);
	DES_ede3_cbc_encrypt(data, out, CTLEN, &ks1, &ks2, &ks3, &ivec,  DES_DECRYPT);

	// now check padding
	pad = out[47];
	if(pad > 8)
		// "Bad padding byte. You probably have a wrong password"
		return -1;
	if(pad != 4) /* possible bug here, is this assumption always valid? */
		return -1;
	n = CTLEN - pad;
	for(i = n; i < CTLEN; i++)
		if(out[i] != pad)
			// "Bad padding. You probably have a wrong password"
			return -1;
	return 0;
}

#ifdef DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static void crypt_all(int count)
{
	int index;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

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

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	if (!kcdecrypt((unsigned char*)outbuffer[index].v,
	               salt_struct->iv, salt_struct->ct))
		any_cracked = cracked[index] = 1;
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
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		keychain_tests
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
