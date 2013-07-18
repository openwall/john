/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for Keyring format.
 *
 * Lots of fixes were done by magnum which made the format work!
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

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
#include "stdint.h"

#define FORMAT_LABEL		"keyring-opencl"
#define FORMAT_NAME		"GNOME Keyring"
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

#define SALTLEN 8
typedef unsigned char guchar; /* How many aliases do we need?! */
typedef unsigned int guint;
typedef int gint;


typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} keyring_password;

typedef struct {
	uint8_t key[16];
	uint8_t iv[16];
} keyring_hash;

typedef struct {
	uint32_t length;
	uint32_t iterations;
	uint8_t salt[8];
} keyring_salt;

static int *cracked;
static int any_cracked;

static struct custom_salt {
	unsigned int iterations;
	unsigned char salt[SALTLEN];
	unsigned int crypto_size;
	unsigned int inlined;
	unsigned char ct[LINE_BUFFER_SIZE / 2]; /* after hex conversion */
} *cur_salt;

static struct fmt_tests keyring_tests[] = {
	{"$keyring$db1b562e453a0764*3221*16*0*02b5c084e4802369c42507300f2e5e56", "openwall"},
	//{"$keyring$4f3f1557a7da17f5*2439*144*0*12215fabcff6782aa23605ab2cd843f7be9477b172b615eaa9130836f189d32ffda2e666747378f09c6e76ad817154daae83a36c0a0a35f991d40bcfcba3b7807ef57a0ce4c7f835bf34c6e358f0d66aa048d73dacaaaf6d7fa4b3510add6b88cc237000ff13cb4dbd132db33be3ea113bedeba80606f86662cc226af0dad789c703a7df5ad8700542e0f7a5e1f10cf0", "password"},
	{NULL}
};

static keyring_password *inbuffer;
static keyring_hash *outbuffer;
static keyring_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;

#define insize (sizeof(keyring_password) * global_work_size)
#define outsize (sizeof(keyring_hash) * global_work_size)
#define settingsize (sizeof(keyring_salt))
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
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

static void init(struct fmt_main *self)
{
	char build_opts[64];
	cl_int cl_error;
	char *temp;
	cl_ulong maxsize;

	snprintf(build_opts, sizeof(build_opts),
	         "-DPLAINTEXT_LENGTH=%d",
	         PLAINTEXT_LENGTH);
	opencl_init("$JOHN/kernels/keyring_kernel.cl",
	                ocl_gpu_id, build_opts);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);
	else
		local_work_size = cpu(device_info[ocl_gpu_id]) ? 1 : 64;

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);
	else
		global_work_size = MAX_KEYS_PER_CRYPT;

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "keyring", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max workgroup size");

	while (local_work_size > maxsize)
		local_work_size >>= 1;

	inbuffer = (keyring_password *) mem_calloc(insize);
	outbuffer = (keyring_hash *) mem_alloc(outsize);

	cracked = mem_calloc(cracked_size);

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

	if (options.verbosity > 2)
		fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int ctlen;
	if (strncmp(ciphertext, "$keyring$", 9) != 0)
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;
	if ((p = strtok(ctcopy, "*")) == NULL)	/* salt */
		goto err;
	if(strlen(p) != SALTLEN * 2)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* crypto size */
		goto err;
	ctlen = atoi(p);
	if ((p = strtok(NULL, "*")) == NULL)	/* inlined */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* ciphertext */
		goto err;
	if (ctlen > LINE_BUFFER_SIZE)
		goto err;
	if(strlen(p) != ctlen * 2)
		goto err;
	if (strlen(p) < 32) /* this shouldn't happen for valid hashes */
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
	static struct custom_salt cs;
	ctcopy += 9;	/* skip over "$keyring$" */
	cur_salt = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtok(ctcopy, "*");
	for (i = 0; i < SALTLEN; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.crypto_size = atoi(p);
	p = strtok(NULL, "*");
	cs.inlined = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.crypto_size; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, SALTLEN);
	currentsalt.length = SALTLEN;
	currentsalt.iterations = cur_salt->iterations;
}

static void keyring_set_key(char *key, int index)
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

static int verify_decrypted_buffer(unsigned char *buffer, int len)
{
	guchar digest[16];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, buffer + 16, len - 16);
	MD5_Final(digest, &ctx);
	return memcmp(buffer, digest, 16) == 0;
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
	for (index = 0; index < count; index++) {
		unsigned char buffer[32];
		unsigned char iv[16];
		AES_KEY akey;
		unsigned char *p = outbuffer[index].iv;

		//dump_stuff_msg(inbuffer[index].length, outbuffer[index].key, 16);

		// on GPU now!
		// symkey_generate_simple(password, n_password, salt, 8, iterations, key, iv);

		memcpy(iv, p, 16);
		memcpy(buffer, cur_salt->ct, cur_salt->crypto_size);
		memset(&akey, 0, sizeof(AES_KEY));
		if (AES_set_decrypt_key(outbuffer[index].key, 128, &akey) < 0) {
			fprintf(stderr, "AES_set_decrypt_key failed!\n");
		}

		AES_cbc_encrypt(buffer, buffer, cur_salt->crypto_size, &akey, iv, AES_DECRYPT);
		if (verify_decrypted_buffer(buffer, cur_salt->crypto_size))
			any_cracked = cracked[index] = 1;
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

struct fmt_main fmt_opencl_keyring = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		keyring_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		keyring_set_key,
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
