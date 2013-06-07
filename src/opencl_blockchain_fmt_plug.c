/* blockchain "My Wallet" cracker patch for JtR. Hacked together during June of
 * 2013 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * See https://blockchain.info/wallet/wallet-format

 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall.com>
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation. */

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
#define FORMAT_LABEL		"blockchain-opencl"
#define FORMAT_NAME		"blockchain My Wallet PBKDF2-HMAC-SHA-1 AES"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define KEYS_PER_CRYPT		40960*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(struct custom_salt)
#define BIG_ENOUGH 		(8192 * 32)
// increase me (in multiples of 16) to increase the decrypted and search area
#define SAFETY_FACTOR 		64

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		ARCH_WORD_32

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} blockchain_password;

typedef struct {
	uint32_t v[32/4];
} blockchain_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[16];
	int iterations;
	int outlen;
} blockchain_salt;

static int *cracked;
static int any_cracked;

static struct fmt_tests blockchain_tests[] = {
	{"$blockchain$400$53741f25a90ef521c90bb2fd73673e64089ff2cca6ba3cbf6f34e0f80f960b2f60b9ac48df009dc30c288dcf1ade5f16c70a3536403fc11a68f242ba5ad3fcceae3ca5ecd23905997474260aa1357fc322b1434ffa026ba6ad33707c9ad5260e7230b87d8888a45ddc27513adb30af8755ec0737963ae6bb281318c48f224e9c748f6697f75f63f718bebb3401d6d5f02cf62b1701c205762c2f43119b68771ed10ddab79b5f74f56d611f61f77b8b65b5b5669756017429633118b8e5b8b638667e44154de4cc76468c4200eeebda2711a65333a7e3c423c8241e219cdca5ac47c0d4479444241fa27da20dba1a1d81e778a037d40d33ddea7c39e6d02461d97185f66a73deedff39bc53af0e9b04a3d7bf43648303c9f652d99630cd0789819376d68443c85f0eeb7af7c83eecddf25ea912f7721e3fb73ccaedf860f0f033ffc990ed73db441220d0cbe6e029676fef264dc2dc497f39bedf4041ba355d086134744d5a36e09515d230cd499eb20e0c574fb1bd9d994ce26f53f21d06dd58db4f8e0efbcaee7038df793bbb3daa96", "strongpassword"},
	{"$blockchain$384$ece598c58b22a3b245a02039ce36bdf589a86b6344e802b4a3ac9b727cc0b6977e9509bc1ac4d1b7b9cbf9089ecdc89706f0a469325f7ee218b2212b6cd3e32677be20eee91e267fe13ebded02946d4ae1163ef22b3dca327d7390091247ac770288a0c7be181b21a48a8f945d9913cdfdc4cfd739ee3a41ced11cacde22e3233250e36f8b8fb4d81de5298a84374af75b88afda3438eed232e52aa0eb29e0d475456c86ae9d1aaadca14bc25f273c93fd4d7fd8316ed5306733bca77e8214277edd3155342abe0710985dc20b4f80e6620e386aa7658f92df25c7c932f0eb1beca25253662bd558647a3ba741f89450bfdba59a0c016477450fbcecd62226626e06ed2e3f5a4180e32d534c7769bcd1160aad840cfd3b7b13a90d34fedb3408fe74379a9e8a840fe3bfee8e0ee01f77ee389613fa750c3d2771b83eeb4e16598f76c15c311c325bd5d54543571aa20934060e332f451e58d67ad0f4635c0c021fa76821a68d64f1a5fb6fd70365eef4442cedcc91eb8696d52d078807edd89d", "qwertyuiop1"},
	{NULL}
};

static struct custom_salt {
	unsigned char data[BIG_ENOUGH];
	int length;
} *cur_salt;

static blockchain_password *inbuffer;
static blockchain_hash *outbuffer;
static blockchain_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;

#define insize (sizeof(blockchain_password) * global_work_size)
#define outsize (sizeof(blockchain_hash) * global_work_size)
#define settingsize sizeof(blockchain_salt)
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
	                ocl_gpu_id, build_opts);

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
		(blockchain_password *) mem_calloc(sizeof(blockchain_password) *
		                             global_work_size);
	outbuffer =
	    (blockchain_hash *) mem_alloc(sizeof(blockchain_hash) * global_work_size);

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

	if (options.verbosity > 2)
		fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
}

// XXX implement valid
static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext,  "$blockchain$", 12) != 0)
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

	ctcopy += 12;
	p = strtok(ctcopy, "$");
	cs->length = atoi(p);
	p = strtok(NULL, "$");
	for (i = 0; i < cs->length; i++)
		cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cs;
}


static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.salt, cur_salt->data, 16);
	currentsalt.length = 16;
	currentsalt.iterations = 10;
	currentsalt.outlen = 32;
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

static int blockchain_decrypt(unsigned char *derived_key, unsigned char *data)
{
	unsigned char out[SAFETY_FACTOR];
	AES_KEY akey;
	unsigned char iv[16];
	memcpy(iv, cur_salt->data, 16);

	if(AES_set_decrypt_key(derived_key, 256, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");
	}
	AES_cbc_encrypt(data + 16, out, SAFETY_FACTOR, &akey, iv, AES_DECRYPT);

	/* various tests */
	if (out[0] != '{') // fast test
		return -1;
	if (jtr_memmem(out, SAFETY_FACTOR, "\"guid\"", 6))
		return 0;
	if (jtr_memmem(out, SAFETY_FACTOR, "sharedKey", 9))
		return 0;

	/* XXX more tests required?
	 *  if (jtr_memmem(out, cur_salt->length, "pbkdf2_iterations", 17))
	 *  	return 0;
	 */

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
	if (!blockchain_decrypt((unsigned char*)outbuffer[index].v, cur_salt->data))
		any_cracked = cracked[index] = 1;

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

struct fmt_main fmt_opencl_blockchain = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		blockchain_tests
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
