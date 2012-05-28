/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include <assert.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"

#include "common-opencl.h"

#define uint32_t		unsigned int
#define uint8_t			unsigned char

#define PHPASS_TYPE		"PORTABLE-MD5"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define CIPHERTEXT_LENGTH	34	/// header = 3 | loopcnt = 1 | salt = 8 | ciphertext = 22
#define BINARY_SIZE		16
#define SALT_SIZE		8

#define KEYS_PER_CRYPT		1024*9*4
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define FORMAT_LABEL		"phpass-opencl"
#define FORMAT_NAME		"PHPASS-OPENCL"

//#define _PHPASS_DEBUG

typedef struct {
	unsigned char v[PLAINTEXT_LENGTH];
	unsigned char length;
} phpass_password;

typedef struct {
	uint32_t v[4];		///128bits for hash
} phpass_hash;

static phpass_password inbuffer[MAX_KEYS_PER_CRYPT];			/** plaintext ciphertexts **/
static phpass_hash outbuffer[MAX_KEYS_PER_CRYPT];			/** calculated hashes **/
static const char phpass_prefix[] = "$P$";
static char currentsalt[SALT_SIZE + 1];

extern void mem_init(unsigned char *, uint32_t *, char *, char *, int);
extern void mem_clear(void);
extern void gpu_phpass(void);

// OpenCL variables:
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(phpass_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(phpass_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(uint8_t) * SALT_SIZE + 4;
static size_t global_work_size = KEYS_PER_CRYPT/4;


static struct fmt_tests tests[] = {
	/*{"$P$900000000jPBDh/JWJIyrF0.DmP7kT.", "ala"},
	   {"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	   {"$P$900000001ahWiA6cMRZxkgUxj4x/In0", "john"},
	   {"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"},
	   {"$P$900000000zgzuX4Dc2091D8kak8RdR0", "h3ll00"},
	   {"$P$900000000qZTL5A0XQUX9hq0t8SoKE0", "1234567890"},
	   {"$P$900112200B9LMtPy2FSq910c1a6BrH0", "1234567890"},
	   {"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	   {"$P$9sadli2.wzQIuzsR2nYVhUSlHNKgG/0", "john"},
	   {"$P$90000000000tbNYOc9TwXvLEI62rPt1", ""}, */

	/*{"$P$9saltstriAcRMGl.91RgbAD6WSq64z.", "a"},
	   {"$P$9saltstriMljTzvdluiefEfDeGGQEl/", "ab"},
	   {"$P$9saltstrikCftjZCE7EY2Kg/pjbl8S.", "abc"},
	   {"$P$9saltstriV/GXRIRi9UVeMLMph9BxF0", "abcd"},
	   {"$P$9saltstri3JPgLni16rBZtI03oeqT.0", "abcde"},
	   {"$P$9saltstri0D3A6JyITCuY72ZoXdejV.", "abcdef"},
	   {"$P$9saltstriXeNc.xV8N.K9cTs/XEn13.", "abcdefg"}, */
	{"$P$9saltstrinwvfzVRP3u1gxG2gTLWqv.", "abcdefgh"},
	/*
	   {"$P$9saltstriSUQTD.yC2WigjF8RU0Q.Z.", "abcdefghi"},
	   {"$P$9saltstriWPpGLG.jwJkwGRwdKNEsg.", "abcdefghij"},
	   {"$P$9saltstrizjDEWUMXTlQHQ3/jhpR4C.", "abcdefghijk"},
	   {"$P$9saltstriGLUwnE6bl91BPJP6sxyka.", "abcdefghijkl"},
	   {"$P$9saltstriq7s97e2m7dXnTEx2mtPzx.", "abcdefghijklm"},
	   {"$P$9saltstriTWMzWKsEeiE7CKOVVU.rS0", "abcdefghijklmn"},
	   {"$P$9saltstriXt7EDPKtkyRVOqcqEW5UU.", "abcdefghijklmno"}, 
	 */
	{NULL}
};

static void release_all(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release Kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[gpu_id]), "Release Queue");
}

static void set_key(char *key, int index)
{
#ifdef _PHPASS_DEBUG
	printf("set_key(%d) = %s\n", index, key);
#endif
	int length = strlen(key);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, inbuffer[index].length);
	ret[inbuffer[index].length] = 0;
	return ret;
}

static void find_best_workgroup()
{
	cl_event myEvent;
	cl_ulong startTime, endTime, kernelExecTimeNs = CL_ULONG_MAX;
	size_t my_work_group = 1;
	cl_int ret_code;
	int i;
	size_t max_group_size;
	clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_WORK_GROUP_SIZE,
	    sizeof(max_group_size), &max_group_size, NULL);
	cl_command_queue queue_prof =
	    clCreateCommandQueue(context[gpu_id], devices[gpu_id],
	    CL_QUEUE_PROFILING_ENABLE,
	    &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating command queue");
	local_work_size = 1;
	/// Set keys
	char *pass = "aaaaaaaa";
	for (i = 0; i < KEYS_PER_CRYPT; i++) {
		set_key(pass, i);
	}
	///Set salt
	memcpy(currentsalt, "saltstri9", 9);
	char setting[SALT_SIZE + 3 + 1] = { 0 };
	strcpy(setting, currentsalt);
	strcpy(setting + SALT_SIZE, phpass_prefix);
	setting[SALT_SIZE + 3] = atoi64[ARCH_INDEX(currentsalt[8])];

	///Copy data to GPU
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_setting, CL_FALSE,
		0, settingsize, setting, 0, NULL, NULL),
	    "Copy setting to gpu");

	///Find best local work size
	for (my_work_group = 1; (int) my_work_group <= (int) max_group_size;
	    my_work_group *= 2) {

		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, crypt_kernel,
			1, NULL, &global_work_size, &my_work_group, 0, NULL,
			&myEvent), "Run kernel");

		HANDLE_CLERROR(clFinish(queue_prof), "clFinish error");
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT,
		    sizeof(cl_ulong), &startTime, NULL);
		clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END,
		    sizeof(cl_ulong), &endTime, NULL);

		if ((endTime - startTime) < kernelExecTimeNs) {
			kernelExecTimeNs = endTime - startTime;
			local_work_size = my_work_group;
		}
		//printf("%d time=%lld\n",(int) my_work_group, endTime-startTime);
	}
	printf("Optimal Group work Size = %d\n", (int) local_work_size);
	clReleaseCommandQueue(queue_prof);
}

static void init(struct fmt_main *pFmt)
{
	atexit(release_all);
	opencl_init("$JOHN/phpass_kernel.cl", gpu_id,platform_id);

	/// Alocate memory
	cl_int cl_error;
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem in");
	mem_setting =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem setting");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem out");

	/// Setup kernel parameters
	crypt_kernel = clCreateKernel(program[gpu_id], "phpass", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");
	clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(crypt_kernel, 1, sizeof(mem_out), &mem_out);
	clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting), &mem_setting);

	find_best_workgroup();
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	uint32_t i, j, count_log2, found;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	if (strncmp(ciphertext, phpass_prefix, 3) != 0)
		return 0;

	for (i = 3; i < CIPHERTEXT_LENGTH; i++) {
		found = 0;
		for (j = 0; j < 64; j++)
			if (itoa64[j] == ARCH_INDEX(ciphertext[i])) {
				found = 1;
				break;
			}
		if (!found)
			return 0;
	}
	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
};

//code from historical JtR phpass patch
static void *binary(char *ciphertext)
{
	static unsigned char b[BINARY_SIZE];
	memset(b, 0, BINARY_SIZE);
	int i, bidx = 0;
	unsigned sixbits;
	char *pos = &ciphertext[3 + 1 + 8];

	for (i = 0; i < 5; i++) {
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 6);
		sixbits >>= 2;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 4);
		sixbits >>= 4;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] |= (sixbits << 6);
	return (void *) b;
}

static void *salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE + 1];
	memcpy(salt, &ciphertext[4], 8);
	salt[8] = ciphertext[3];
	return salt;
}


static void set_salt(void *salt)
{
	memcpy(currentsalt, salt, SALT_SIZE + 1);
}

static void crypt_all(int count)
{
#ifdef _PHPASS_DEBUG
	printf("crypt_all(%d)\n", count);
#endif
	///Prepare setting format: salt+prefix+count_log2
	char setting[SALT_SIZE + 3 + 1] = { 0 };
	strcpy(setting, currentsalt);
	strcpy(setting + SALT_SIZE, phpass_prefix);
	setting[SALT_SIZE + 3] = atoi64[ARCH_INDEX(currentsalt[8])];
	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, setting, 0, NULL, NULL),
	    "Copy setting to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL, NULL),
	    "Run kernel");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0,
		outsize, outbuffer, 0, NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");
}

static int binary_hash_0(void *binary)
{
#ifdef _PHPASS_DEBUG
	printf("binary_hash_0 ");
	int i;
	uint32_t *b = binary;
	for (i = 0; i < 4; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	return (((ARCH_WORD_32 *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0x7ffffff;
}

static int get_hash_0(int index)
{
#ifdef _PHPASS_DEBUG
	printf("get_hash_0:   ");
	int i;
	for (i = 0; i < 4; i++)
		printf("%08x ", outbuffer[index].v[i]);
	puts("");
#endif
	return outbuffer[index].v[0] & 0xf;
}

static int get_hash_1(int index)
{
	return outbuffer[index].v[0] & 0xff;
}

static int get_hash_2(int index)
{
	return outbuffer[index].v[0] & 0xfff;
}

static int get_hash_3(int index)
{
	return outbuffer[index].v[0] & 0xffff;
}

static int get_hash_4(int index)
{
	return outbuffer[index].v[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	return outbuffer[index].v[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	return outbuffer[index].v[0] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{

	uint32_t b = ((uint32_t *) binary)[0];
	uint32_t i;
	for (i = 0; i < count; i++) {
		if (b == outbuffer[i].v[0]) {
#ifdef _PHPASS_DEBUG
			puts("cmp_all = 1");
#endif
			return 1;
		}
	}
#ifdef _PHPASS_DEBUG
	puts("cmp_all = 0");
#endif	/* _PHPASS_DEBUG */
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (t[i] != outbuffer[index].v[i]) {
#ifdef _PHPASS_DEBUG
			puts("cmp_one = 0");
#endif
			return 0;
		}
#ifdef _PHPASS_DEBUG
	puts("cmp_one = 1");
#endif
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_opencl_phpass = {
	{
		    FORMAT_LABEL,
		    FORMAT_NAME,
		    PHPASS_TYPE,
		    BENCHMARK_COMMENT,
		    BENCHMARK_LENGTH,
		    PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    SALT_SIZE + 1,
		    MIN_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
		    FMT_CASE | FMT_8_BIT,
	    tests},
	{
		    init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    binary,
		    salt,
		    {
				binary_hash_0,
				binary_hash_1,
				binary_hash_2,
				binary_hash_3,
				binary_hash_4,
				binary_hash_5,
			binary_hash_6},
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
			get_hash_6},
		    cmp_all,
		    cmp_one,
	    cmp_exact}
};
