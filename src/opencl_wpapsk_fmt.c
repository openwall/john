/*
* This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*
* Code is based on  Aircrack-ng source
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"

#include "common-opencl.h"
#include "wpapsk.h"

#define FORMAT_LABEL		"wpapsk-opencl"
#define FORMAT_NAME		"WPA-PSK PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME		"OpenCL"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1


#define	KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

//#define _WPAPSK_DEBUG

extern wpapsk_password *inbuffer;
extern wpapsk_hash *outbuffer;
extern wpapsk_salt currentsalt;
extern mic_t *mic;
extern hccap_t hccap;
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(wpapsk_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(wpapsk_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(wpapsk_salt);

static struct fmt_tests tests[] = {
/// testcase from http://wiki.wireshark.org/SampleCaptures = wpa-Induction.pcap
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "Induction"},
	{NULL}
};

extern void wpapsk_gpu(wpapsk_password *, wpapsk_hash *, wpapsk_salt *);

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

	assert(sizeof(hccap_t) == HCCAP_SIZE);

	inbuffer =
	    (wpapsk_password *) malloc(sizeof(wpapsk_password) *
	    MAX_KEYS_PER_CRYPT);
	outbuffer =
	    (wpapsk_hash *) malloc(sizeof(wpapsk_hash) * MAX_KEYS_PER_CRYPT);
	mic = (mic_t *) malloc(sizeof(mic_t) * MAX_KEYS_PER_CRYPT);

/*
 * Zeroize the lengths in case crypt_all() is called with some keys still
 * not set.  This may happen during self-tests.
 */
	{
		int i;
		for (i = 0; i < self->params.max_keys_per_crypt; i++)
			inbuffer[i].length = 0;
	}

	//listOpenCLdevices();
	opencl_init("$JOHN/wpapsk_kernel.cl", ocl_gpu_id, platform_id);
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

	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "wpapsk", &cl_error);
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

static void crypt_all(int count)
{
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

	///Make last computations on CPU
	wpapsk_postprocess(KEYS_PER_CRYPT);

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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
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
