/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"

#include "common-opencl.h"

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

#define FORMAT_LABEL		"wpapsk-opencl"
#define FORMAT_NAME		FORMAT_LABEL
#define ALGORITHM_NAME		"pbkdf2-sha1"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1


#define	KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	15
#define SALT_SIZE		sizeof(wpapsk_salt)
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
static const char wpapsk_prefix[] = "$WPAPSK$";

typedef struct {
	uint8_t length;
	uint8_t v[15];
} wpapsk_password;

typedef struct {
	uint32_t v[8];
} wpapsk_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[15];
} wpapsk_salt;


//#define _WPAPSK_DEBUG

static wpapsk_password *inbuffer;
static wpapsk_hash *outbuffer;
static wpapsk_salt currentsalt;
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(wpapsk_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(wpapsk_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(wpapsk_salt);
static size_t global_work_size = KEYS_PER_CRYPT;

static struct fmt_tests tests[] = {
	{"$WPAPSK$administrator#77c05884d12743449e72d75797430053ccb7e5256b9b2a709cf8ee00e71317fc", "a"},
	{NULL}
};

extern void wpapsk_gpu(wpapsk_password *, wpapsk_hash *, wpapsk_salt *);

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
	uint8_t length = strlen(key);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
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
	static char *pass = "dupa";
	for (i = 0; i < KEYS_PER_CRYPT; i++) {
		set_key(pass, i);
	}
	///Set salt
	memcpy(currentsalt.salt, "saltstring", 10);
	currentsalt.length = 10;
	///Copy data to GPU
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_setting, CL_FALSE,
		0, settingsize, &currentsalt, 0, NULL, NULL),
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

	inbuffer =
	    (wpapsk_password *) malloc(sizeof(wpapsk_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (wpapsk_hash *) malloc(sizeof(wpapsk_hash) * MAX_KEYS_PER_CRYPT);

	//listOpenCLdevices();
	opencl_init("$JOHN/wpapsk_kernel.cl", gpu_id, platform_id);
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

	crypt_kernel = clCreateKernel(program[gpu_id], "wpapsk", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");
	clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(crypt_kernel, 1, sizeof(mem_out), &mem_out);
	clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting), &mem_setting);
	find_best_workgroup();


	atexit(release_all);

}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	if (strncmp(ciphertext, wpapsk_prefix, strlen(wpapsk_prefix)) != 0)
		return 0;
	char *hash = strrchr(ciphertext, '#') + 1;
	int hashlength = 0;
	if (hash == NULL)
		return 0;
	while (hash < ciphertext + strlen(ciphertext)) {
		if (atoi16[ARCH_INDEX(*hash++)] == 0x7f)
			return 0;
		hashlength++;
	}
	if (hashlength != 64)
		return 0;
	return 1;
}

static void *binary(char *ciphertext)
{
	static uint32_t binary[8];
	char *hash = strrchr(ciphertext, '#') + 1;
	if (hash == NULL)
		return binary;
	int i;
	for (i = 0; i < 8; i++) {
		sscanf(hash + (8 * i), "%08x", &binary[i]);
		binary[i] = SWAP(binary[i]);
	}
	return binary;

}

static void *salt(char *ciphertext)
{
	static wpapsk_salt salt;
	char *pos = ciphertext + strlen(wpapsk_prefix);
	int length = 0;
	while (*pos != '#')
		salt.salt[length++] = *pos++;
	salt.length = length;
	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, sizeof(wpapsk_salt));
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
	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, &currentsalt, 0, NULL, NULL),
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
#ifdef _WPAPSK_DEBUG
	puts("binary");
	uint32_t i, *b = binary;
	for (i = 0; i < 8; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	return (((uint32_t *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((uint32_t *) binary)[0] & 0x7ffffff;
}

static int get_hash_0(int index)
{
#ifdef _WPAPSK_DEBUG
	int i;
	puts("get_hash");
	for (i = 0; i < 8; i++)
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
	uint32_t i, b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	uint32_t i, *b = (uint32_t *) binary;
	for (i = 0; i < 8; i++)
		if (b[i] != outbuffer[index].v[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_opencl_wpapsk = {
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
