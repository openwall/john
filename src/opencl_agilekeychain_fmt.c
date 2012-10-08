/* 1Password Agile Keychain cracker patch for JtR. Hacked together during
 * July of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and is based on agilekeychain (https://bitbucket.org/gwik/agilekeychain)
 *
 * Copyright (c) 2009 Antonin Amand <antonin.amand@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation. */

#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include <openssl/aes.h>
#include "common-opencl.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"agilekeychain-opencl"
#define FORMAT_NAME		"1Password Agile Keychain PBKDF2-HMAC-SHA-1 AES"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALTLEN 8
#define CTLEN 1040

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		ARCH_WORD_32

typedef struct {
	uint8_t length;
	uint8_t v[15];
} keychain_password;

typedef struct {
	uint32_t v[8];
} keychain_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[20];
	int iterations;
} keychain_salt;

static int *cracked;

static struct fmt_tests keychain_tests[] = {
	{"$agilekeychain$2*1000*8*7146eaa1cca395e5*1040*e7eb81496717d35f12b83024bb055dec00ea82843886cbb8d0d77302a85d89b1d2c0b5b8275dca44c168cba310344be6eea3a79d559d0846a9501f4a012d32b655047673ef66215fc2eb4e944a9856130ee7cd44523017bbbe2957e6a81d1fd128434e7b83b49b8a014a3e413a1d76b109746468070f03f19d361a21c712ef88e05b04f8359f6dd96c1c4487ea2c9df22ea9029e9bc8406d37850a5ead03062283a42218c134d05ba40cddfe46799c931291ec238ee4c11dc71d2b7e018617d4a2bf95a0c3c1f98ea14f886d94ee2a65871418c7c237f1fe52d3e176f8ddab6dfd4bc039b6af36ab1bc9981689c391e71703e31979f732110b84d5fccccf59c918dfcf848fcd80c6da62ced6e231497b9cbef22d5edca439888556bae5e7b05571ac34ea54fafc03fb93e4bc17264e50a1d04b688fcc8bc715dd237086c2537c32de34bbb8a29de0208800af2a9b561551ae6561099beb61045f22dbe871fab5350e40577dd58b4c8fb1232f3f85b8d2e028e5535fd131988a5df4c0408929b8eac6d751dcc698aa1d79603251d90a216ae5e28bffc0610f61fefe0a23148dcc65ab88b117dd3b8d311157424867eb0261b8b8c5b11def85d434dd4c6dc7036822a279a77ec640b28da164bea7abf8b634ba0e4a13d9a31fdcfebbdbe53adcdf2564d656e64923f76bc2619428abdb0056ce20f47f3ece7d4d11dc55d2969684ca336725561cb27ce0504d57c88a2782daccefb7862b385d494ce70fef93d68e673b12a68ba5b8c93702be832d588ac935dbf0a7b332e42d1b6da5f87aed03498a37bb41fc78fcdbe8fe1f999fe756edf3a375beb54dd508ec45af07985f1430a105e552d9817106ae12d09906c4c28af575d270308a950d05c07da348f59571184088d46bbef3e7a2ad03713e90b435547b23f340f0f5d00149838d9919d40dac9b337920c7e577647fe4e2811f05b8e888e3211d9987cf922883aa6e53a756e579f7dff91c297fcc5cda7d10344545f64099cfd2f8fd59ee5c580ca97cf8b17e0222b764df25a2a52b81ee9db41b3c296fcea1203b367e55d321c3504aeda8913b0cae106ccf736991030088d581468264b8486968e868a44172ad904d97e3e52e8370aaf52732e6ee6cc46eb33a901afc6b7c687b8f6ce0b2b4cdfe19c7139615195a052051becf39383ab83699a383a26f8a36c78887fe27ea7588c0ea21a27357ff9923a3d23ca2fb04ad671b63f8a8ec9b7fc969d3bece0f5ff19a40bc327b9905a6de2193ffe3aa1997e9266205d083776e3b94869164abcdb88d64b8ee5465f7165b75e1632abd364a24bb1426889955b8f0354f75c6fb40e254f7de53d8ef7fee9644bf2ebccd934a72bb1cc9c19d354d66996acbddd60d1241657359d9074a4b313b21af2ee4f10cf20f4122a5fad4ee4f37a682ffb7234bea61985d1ad130bfb9f4714461fb574dbf851c*1000*8*c05f3bc3e7f3cad7*1040*f3e3d091b64da1529b04b2795898b717faad59f7dae4bda25e6e267c28a56a7702e51991b2a3fb034cdda2d9bfd531dfd2c3af00f39fdfe8bcbdde02ab790415bcf071d133b15f647f55ff512730ae4914ce20b72184c827f6350ac768b00c9eab0e3322e084bb3e9e9439a10030950f5504dcc4f7ba614b27fde99bd0d743a58341e90ec313395486eb8068df205b7bdf25134ed97dd2e2883d7eb3e63b659602ada765084a69d7ed8fc55b60aa67718cc9e5bf31ab8f3029b32a4b001071848d2b76b5f4b921d2169ca287e9e78ecd904d040c817c7c7cde4ba8510b462e139c16519962ca0adb7d5f89d431cd4541a9a7aaec8d799697f4d3947d87884bed32ada13db725c72ab6450ac8fe989a94917cca784bcf6ffbe756f19d4e8897e0f80d8c318e13e5b30fc356646aaf038a952b0781f12dfef1f4bd6922ae05a573eeff4dbb064cfbb0fd62962a6a53a8de308da2b8e83baebfe261cb127f874a5eff3f05cda123ab2ba559cf444ce33b6845f4c902733b8982044151a8aa1859769082ade5928f2d4f616ce972ae8dde1f2be37d496ad16057008dfe678c75cbdc53db25ed311edbcf8b2a73bcd2809f6bd1d389aaeed82a75fa15676d08aa5390efdc189c180be6a52ec5a7371304d26e477039197671377d1ea3d6ee41e68a42348a4fe9a1d2400eaeba8ed0a7419b9694d780456d96378c00318a5be0f41afa887476b3bebb7cf30d61ca8fc77de35671a3053a517aa39444e01e1752da3146dc97eec5849d6f025c3d4bc6e0499b901f629d8a081ad35ed33602cbef5e9a68f090170fcc1f285eb094e3dc619740a067fd2aeeb20abbb17926c3ad097f3f0bad4de540d1829a985cd7e700100622ec47da046071c11a1597e5f093268b4ed79ffcf2450b9ba2b649b932fbce912bdb4da010581bd9c731be792c8f75177f6c8c4e1756d63a1491a8aae4bb11beeca118e7d08073b500dd82b81e4bdbeb15625afca8f1c8e06b2360da972587516ef62e91d1d9aad90e62226d53363bff318f5af21f69c234731ac22b09506a1b807d2366e88905668d960c7963daa93046e9a56db1d7a437e9a37aa7a2945197265478b264ec14d383030ef73504fd26d4be9e72ebddb14a00bf6bd66a3adaa1d17cada378a2b0bc852f961af52333f7966f8a60738dfd47e79ce537082f187117ffd31f54f53356b671154dfa245671c4cd054c1a8d303a202fccfae6d3f9e3646838cef38703b5e660b5ce7679f5898d801908f90092dbec335c98e4002041287fe9bfa7d7828a29ab240ec2cedc9fa12cfd7c3ef7b61dad4fbf2ef9c0a904dbde1b3792fb5178607608dc9fc2fbc85addf89fa3df94317e729810b508356b5bb176cdb022afb0ec5eeff4d5081b66733d1be1b54cc4f080bfc33187663b5ab185472b35dc8812e201472e6af376c43ee23aa2db6cd04bddd79b99b0c28c48a5ae", "openwall"},
	{NULL}
};

static struct custom_salt {
	unsigned int nkeys;
	unsigned int iterations[2];
	unsigned int saltlen[2];
	unsigned char salt[2][SALTLEN];
	unsigned int ctlen[2];
	unsigned char ct[2][CTLEN];
} *cur_salt;

static keychain_password *inbuffer;
static keychain_hash *outbuffer;
static keychain_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(keychain_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(keychain_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(keychain_salt);

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
	    (keychain_password *) malloc(sizeof(keychain_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (keychain_hash *) malloc(sizeof(keychain_hash) * MAX_KEYS_PER_CRYPT);

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
	opencl_init("$JOHN/keychain_kernel.cl", ocl_gpu_id, platform_id);
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

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "keychain", &cl_error);
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
	return !strncmp(ciphertext, "$agilekeychain$", 15);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 15;	/* skip over "$agilekeychain$" */
	p = strtok(ctcopy, "*");
	cs.nkeys = atoi(p);
	p = strtok(NULL, "*");
	cs.iterations[0] = atoi(p);
	p = strtok(NULL, "*");
	cs.saltlen[0] = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.saltlen[0]; i++)
		cs.salt[0][i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.ctlen[0] = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.ctlen[0]; i++)
		cs.ct[0][i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->saltlen[0]);
	currentsalt.length = cur_salt->saltlen[0];
	currentsalt.iterations = cur_salt->iterations[0];
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

static int akcdecrypt(unsigned char *derived_key, unsigned char *data)
{
	unsigned char key[16];
	unsigned char iv[16];
	unsigned char out[CTLEN];
	int pad, n, i, key_size;
	AES_KEY akey;
	memcpy(key, derived_key, 16);
	memcpy(iv, derived_key + 16, 16);
	memset(out, 0, sizeof(out));
	memset(&akey, 0, sizeof(AES_KEY));

	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_derypt_key failed in crypt!\n");
	}
	AES_cbc_encrypt(data, out, CTLEN, &akey, iv, AES_DECRYPT);

	// now check padding
	pad = out[CTLEN - 1];
	if(pad < 1 || pad > 16) /* AES block size is 128 bits = 16 bytes */
		// "Bad padding byte. You probably have a wrong password"
		return -1;
	n = CTLEN - pad;
	key_size = n / 8;
	if(key_size != 128 && key_size != 192 && key_size != 256)
		// "invalid key size"
		return -1;
	for(i = n; i < CTLEN; i++)
		if(out[i] != pad)
			// "Bad padding. You probably have a wrong password"
			return -1;
	return 0;
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

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#else
	for (index = 0; index < count; index++)
#endif
	{
		if(akcdecrypt((unsigned char*)outbuffer[index].v, cur_salt->ct[0]) == 0) {
			cracked[index] = 1;
		}
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

struct fmt_main fmt_opencl_agilekeychain = {
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
