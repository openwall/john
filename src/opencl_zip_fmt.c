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
#define MIN_KEYS_PER_CRYPT	1024*9
#define MAX_KEYS_PER_CRYPT	MIN_KEYS_PER_CRYPT
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(zip_cpu_salt)

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} zip_password;

typedef struct {
	uint32_t v[(2 * PLAINTEXT_LENGTH + PWD_VER_LENGTH + 3) / 4];
} zip_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	int     iterations;
	int     outlen;
} zip_salt;

static int *cracked;
static int any_cracked;

typedef struct {
	uint8_t length;
	uint8_t salt[20];
	int type;		/* type of zip file */
	int mode;
	unsigned char passverify[2];
} zip_cpu_salt;

/* From gladman_fileenc.h */
#define PWD_VER_LENGTH		2
#define KEYING_ITERATIONS	1000
#define KEY_LENGTH(mode)	(8 * ((mode) & 3) + 8)
#define SALT_LENGTH(mode)	(4 * ((mode) & 3) + 4)

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

#define insize (sizeof(zip_password) * global_work_size)
#define outsize (sizeof(zip_hash) * global_work_size)
#define settingsize (sizeof(zip_salt))
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
	char *temp;
	char build_opts[64];
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

	/// Allocate memory
	inbuffer =
		(zip_password *) mem_calloc(sizeof(zip_password) *
		                            global_work_size);
	outbuffer =
	    (zip_hash *) mem_alloc(sizeof(zip_hash) * global_work_size);

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

static int ishex(char *q)
{
       while (atoi16[ARCH_INDEX(*q)] != 0x7F)
               q++;
       return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;

	if (strncmp(ciphertext, "$zip$*", 6))
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += 6;	/* skip leading '$zip$*' */
	if (!(ptr = strtok(ctcopy, "*")))
		goto error;
	if (*ptr != '0')
		goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (strlen(ptr) != 1)
		goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (!ishex(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
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
	currentsalt.iterations = KEYING_ITERATIONS;
	currentsalt.outlen = 2 * KEY_LENGTH(cur_salt->mode) + PWD_VER_LENGTH;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_setting,
	               CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
	               "Copy setting to gpu");
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

	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");

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
	if (!memcmp(&((unsigned char*)outbuffer[index].v)[2 * KEY_LENGTH(cur_salt->mode)], cur_salt->passverify, 2))
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
