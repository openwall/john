/*  Modified by Dhiru Kholia <dhiru at openwall.com> for ODF AES format.
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
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include "sha2.h"
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define FORMAT_LABEL		"odf-aes-opencl"
#define FORMAT_NAME		"ODF SHA-256 AES"
#define ALGORITHM_NAME		"OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1024*9
#define MAX_KEYS_PER_CRYPT	MIN_KEYS_PER_CRYPT
#define BINARY_SIZE		20
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(odf_cpu_salt)

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
	uint32_t length;
	uint8_t v[32];	// hash of password
} odf_password;

typedef struct {
	uint32_t v[32/4];
} odf_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	uint32_t iterations;
	uint32_t outlen;
} odf_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[32 / sizeof(ARCH_WORD_32)];

typedef struct {
	int cipher_type;
	int checksum_type;
	int iterations;
	int key_size;
	int iv_length;
	int salt_length;
	int content_length;
	unsigned char iv[16];
	unsigned char salt[32];
	unsigned char content[1024];
} odf_cpu_salt;

static odf_cpu_salt *cur_salt;

static struct fmt_tests tests[] = {
	{"$odf$*1*1*1024*32*61802eba18eab842de1d053809ba40927fd40b26c69ddeca6a8a652ed9c16a28*16*c5c0815b931f313627100d592a9c972f*16*e9a48b7daff738deaabe442007fb2ec4*0*be3b65ea09642c2b4fdc23e553e1f5304bc5df222b624c6373d53e674f5df01fdb8873cdab7a5a685fa45ad5441a9d8869401b7fa076c488ad53fd9971e97244ecc9416484450d4fb2ee4ec08af4044d7def937e6545dea2ce36bd5c57b1f46b11b9cf90c8fb3accff149ce2d54820b181b9124db9aac131f6436d77cf716423f04d42438eed6f9ca14bd24b9b17d3478176addd5fa0254bf986fccd879e326485790e28b94ad5306868734b5ac1b1ddb3f876382dee6e9428e8230e84bf11b7e85ccbae8b4b424cd73160c380f874b37fbe3c7e88c13ef4bde74b56507d17095c2c32bb8bcded0637e4403107bb33252f72f5886a91b7720fe32a8659a09c217717e4c74a7c2e09fc40b46aa288309a36e86b9f1856e1bce176bc9690555431e05c7b67ff95df64f8f40053079bfc9dda021ab2714fecf74398b867ebef675958f29eaa15eb631845e358a0c5caff0b824a2a69a6eabee069d3d6236d77709fd60438c9e3ad9e42b26810375e1e587eff105ac295327ef8bf66f6462388b7727ec32d6abde2f8d6126b185124bb437753663f6ab1f321ddfdb36d9f1f528729492e0b1bb8d3b9eda3c86c1997c92b902f5160f77587c37e45b5c133b5d9709fea910a2e9b54c0960b0ebc870cdbb858aabe07ed27cba86d29a7e64c6e3863131859314a14e64c1168d4a2d5ca0697853fb1fe969ba968e31359881d51edce287eff415de8e60cec2068bb82157fbcf0cf9a95e92cb23f32e6156daced4bee6ba8c8b41174d01fcd7662911bcc10d5b4478f8209ce3b91075d10529780be4f17e841a1f1833d432c3dc854908643e58b03c8860dfbc710a29f79f75ea262cfcef9cd67fb67d73f55b300d42f4577445af2b9f224620204cfb88de2cbf57931ac0e0f8d98259a41d744cad6a58abc7761c266f4e93aca19356b07073c09ae9d1976f4f2e1a76c350cc7764c27ae257eb69ba4213dd0a7794fa83d220439a398efd988b6dbf0de4c08bc3e4830c9e482b9e0fd1679f14e6f132cf06bae1d763dde7ce6f525ff9a0ebad28aeca16496194f2a6263a20e7afeb43d83c8c936130d6508f2bf68b5ca50375948424193a7fb1106fdf63ff72896e1b2633907f01a693218e3303436542bcf2af24cc4a41621c36768ce9a84d32cc9f3c2b108bfc78c25b1c2ea94e6e0d65406f78bdb8bc33c94a9550e5cc3e995cfbd31da03afb929418acdc89b099415f9bdb7dab7a75d44a696e14b031d601ad8d907e14a28044706c0c2955df2cb34ffea82af367e487b6cc928dc87a33fc7555173e7faa5cfd1af6d3d6f496f23a9579db22dd4a2c16e950fdc90696d95a81183765a4fbddb42c488d40ac1de28483cf1cdddf821d3f859c57b13cb7f21a916bd0d89438a17634c68637f23e2544589e8ae5ee5bced91680c087cb3105cd74a09e88d3aae17d75e", "test"},
	{NULL}
};

static odf_password *inbuffer;
static odf_hash *outbuffer;
static odf_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;

#define insize (sizeof(odf_password) * global_work_size)
#define outsize (sizeof(odf_hash) * global_work_size)
#define settingsize sizeof(odf_salt)

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
	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);
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
	         (int)sizeof(inbuffer->v),
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
		(odf_password *) mem_calloc(sizeof(odf_password) *
		                        global_work_size);
	outbuffer =
	    (odf_hash *) mem_alloc(sizeof(odf_hash) * global_work_size);

	saved_key = mem_calloc(sizeof(*saved_key) * global_work_size);

	crypt_out = mem_calloc(sizeof(*crypt_out) * global_work_size);

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

static int ishex(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res;
	if (strncmp(ciphertext, "$odf$*", 6))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 6;
	if ((p = strtok(ctcopy, "*")) == NULL)	/* cipher type */
		goto err;
	res = atoi(p);
	if (res != 1) {
		goto err;
	}
	if ((p = strtok(NULL, "*")) == NULL)	/* checksum type */
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* key size */
		goto err;
	res = atoi(p);
	if (res != 16 && res != 32)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* checksum field (skipped) */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iv length */
		goto err;
	res = atoi(p);
	if (res > 16)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt length */
		goto err;
	res = atoi(p);
	if (res > 32)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* something */
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)	/* content */
		goto err;
	res = strlen(p);
	if (res > 2048 || res & 1)
		goto err;
	if (!ishex(p))
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
	static odf_cpu_salt cs;
	ctcopy += 6;	/* skip over "$odf$*" */
	p = strtok(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtok(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtok(NULL, "*");
	cs.iterations = atoi(p);
	p = strtok(NULL, "*");
	cs.key_size = atoi(p);
	p = strtok(NULL, "*");
	/* skip checksum field */
	p = strtok(NULL, "*");
	cs.iv_length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.salt_length = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	memset(cs.content, 0, sizeof(cs.content));
	for (i = 0; p[i * 2] && i < 1024; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs.content_length = i;
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	ctcopy += 6;	/* skip over "$odf$*" */
	p = strtok(ctcopy, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	p = strtok(NULL, "*");
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(keeptr);
	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (odf_cpu_salt*)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->salt_length);
	currentsalt.length = cur_salt->salt_length;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.outlen = cur_salt->key_size;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

#undef set_key
static void set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static void crypt_all(int count)
{
	int index;

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for(index = 0; index < count; index++)
	{
		unsigned char hash[32];
		SHA256_CTX ctx;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (unsigned char *)saved_key[index], strlen(saved_key[index]));
		SHA256_Final((unsigned char *)hash, &ctx);
		memcpy(inbuffer[index].v, hash, 32);
		inbuffer[index].length = 32;
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
	for(index = 0; index < count; index++)
	{
		AES_KEY akey;
		unsigned char iv[32];
		SHA256_CTX ctx;
		unsigned char pt[1024];
		memcpy(iv, cur_salt->iv, 32);
		memset(&akey, 0, sizeof(AES_KEY));
		AES_set_decrypt_key((unsigned char*)outbuffer[index].v, 256, &akey);
		AES_cbc_encrypt(cur_salt->content, pt, cur_salt->content_length, &akey, iv, AES_DECRYPT);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, pt, cur_salt->content_length);
		SHA256_Final((unsigned char*)crypt_out[index], &ctx);
	 }
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_odf_aes = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		4,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		1,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
