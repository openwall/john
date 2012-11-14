/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>
 * and Copyright (c) 2012 magnum, and it is hereby released to the general
 * public under the following terms: Redistribution and use in source and
 * binary forms, with or without modification, are permitted.
 *
 * Code is based on  Aircrack-ng source
 */
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "config.h"

#include "common-opencl.h"

static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel wpapsk_init, wpapsk_loop, wpapsk_pass2, wpapsk_final_md5, wpapsk_final_sha1;
static int VF = 1;	/* Will be set to 4 when we run vectorized */

#define JOHN_OCL_WPAPSK
#include "wpapsk.h"

#define FORMAT_LABEL		"wpapsk-opencl"
#define FORMAT_NAME		"WPA-PSK PBKDF2-HMAC-SHA-1"
#define ALGORITHM_NAME		"OpenCL"

#define BENCHMARK_LENGTH	-1

#define ITERATIONS		4095
#define HASH_LOOPS		105 /* Must be made from factors 3, 3, 5, 7, 13 */

#define	KEYS_PER_CRYPT		1024*9
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define LWS_CONFIG		"wpapsk_LWS"
#define GWS_CONFIG		"wpapsk_GWS"

#define MIN(a, b)		(a > b) ? (b) : (a)
#define MAX(a, b)		(a > b) ? (a) : (b)

extern wpapsk_password *inbuffer;
extern wpapsk_salt currentsalt;
extern mic_t *mic;
extern hccap_t hccap;

typedef struct {
	cl_uint W[5];
	cl_uint ipad[5];
	cl_uint opad[5];
	cl_uint out[5];
	cl_uint partial[5];
} wpapsk_state;

static struct fmt_tests tests[] = {
/// testcase from http://wiki.wireshark.org/SampleCaptures = wpa-Induction.pcap. This is SHA-1 post-process.
	{"$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI", "Induction"},
	{NULL}
};

static void create_clobj(int gws, struct fmt_main *self)
{
	int i;

	global_work_size = gws;
	gws *= VF;
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	/// Allocate memory
	mem_in = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(wpapsk_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	inbuffer = clEnqueueMapBuffer(queue[ocl_gpu_id], mem_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(wpapsk_password) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	mem_state = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, sizeof(wpapsk_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	mem_salt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(wpapsk_salt), &currentsalt, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");

	mem_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(mic_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");
	mic = clEnqueueMapBuffer(queue[ocl_gpu_id], mem_out, CL_TRUE, CL_MAP_READ, 0, sizeof(mic_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	/*
	 * Zeroize the lengths in case crypt_all() is called with some keys still
	 * not set.  This may happen during self-tests.
	 */
	for (i = 0; i < gws; i++)
		inbuffer[i].length = strlen(tests[0].plaintext);

	HANDLE_CLERROR(clSetKernelArg(wpapsk_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_pass2, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_pass2, 1, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_md5, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(wpapsk_final_sha1, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], mem_in, inbuffer, 0, NULL, NULL), "Error Unmapping mem in");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], mem_out, mic, 0, NULL, NULL), "Error Unmapping mem in");

	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem_in");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");
	HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
	HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
}

static void release_all(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");

	HANDLE_CLERROR(clReleaseKernel(wpapsk_init), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_loop), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_pass2), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_final_md5), "Release Kernel");
	HANDLE_CLERROR(clReleaseKernel(wpapsk_final_sha1), "Release Kernel");
}

static void set_key(char *key, int index);
static void *salt(char *ciphertext);
static void set_salt(void *salt);

static cl_ulong gws_test(int gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_command_queue queue_prof;
	cl_event Event[7];
	cl_int ret_code;
	int i;
	size_t scalar_gws = VF * gws;

	create_clobj(gws, self);
	queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i = 0; i < scalar_gws; i++)
		set_key(tests[0].plaintext, i);
	set_salt(salt(tests[0].ciphertext));

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_in, CL_FALSE, 0, sizeof(wpapsk_password) * global_work_size, inbuffer, 0, NULL, &Event[0]), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_salt, CL_FALSE, 0, sizeof(wpapsk_salt), &currentsalt, 0, NULL, &Event[1]), "Copy setting to gpu");

	/// Run kernels
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, wpapsk_init, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[2]), "Run initial kernel");

	for (i = 0; i < ITERATIONS / HASH_LOOPS - 1; i++)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, wpapsk_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel");
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, wpapsk_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[3]), "Run loop kernel");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, wpapsk_pass2, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[4]), "Run intermediate kernel");

	for (i = 0; i < ITERATIONS / HASH_LOOPS; i++)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, wpapsk_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel (2nd)");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, wpapsk_final_sha1, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[5]), "Run final kernel");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, mem_out, CL_TRUE, 0, sizeof(mic_t) * global_work_size, mic, 0, NULL, &Event[6]), "Copy result back");

#if 0
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "wpapsk_init kernel duration: %llu us, ", (endTime-startTime)/1000ULL);
#endif

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "%.2f ms x %u = %.2f s,\t", (float)((endTime - startTime)/1000000.), 2 * ITERATIONS / HASH_LOOPS, (float)(2 * ITERATIONS / HASH_LOOPS) * (endTime - startTime) / 1000000000.);

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "- exceeds 200 ms\n");
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

#if 0
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[4], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[4], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "wpapsk_pass2 kernel duration: %llu us, ", (endTime-startTime)/1000ULL);

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[5], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[5], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "wpapsk_final kernel duration: %llu us\n", (endTime-startTime)/1000ULL);
#endif

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0], CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[6], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");

	clReleaseCommandQueue(queue_prof);
	release_clobj();

	return (endTime - startTime);
}

static void find_best_gws(int do_benchmark, struct fmt_main *self)
{
	int num;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	unsigned int SHAspeed, bestSHAspeed = 0;
	int optimal_gws = local_work_size;
	const int sha1perkey = 2 * ITERATIONS * 2 + 6 + 10;
	unsigned long long int MaxRunTime = cpu(device_info[ocl_gpu_id]) ? 1000000000ULL : 5000000000ULL;

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size; num; num *= 2) {
		if (!do_benchmark)
			advance_cursor();
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		SHAspeed = sha1perkey * (1000000000UL * VF * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d%8llu c/s%14u sha1/s%8.3f sec per crypt_all()", num, (1000000000ULL * VF * num / run_time), SHAspeed, (float)run_time / 1000000000.);

		if (((float)run_time / (float)min_time) < ((float)SHAspeed / (float)bestSHAspeed)) {
			if (do_benchmark)
				fprintf(stderr, "!\n");
			bestSHAspeed = SHAspeed;
			optimal_gws = num;
		} else {
			if (run_time < MaxRunTime && SHAspeed > (bestSHAspeed * 1.01)) {
				if (do_benchmark)
					fprintf(stderr, "+\n");
				bestSHAspeed = SHAspeed;
				optimal_gws = num;
				continue;
			}
			if (do_benchmark)
				fprintf(stderr, "\n");
			if (run_time >= MaxRunTime)
				break;
		}
	}
	global_work_size = optimal_gws;
}

static void init(struct fmt_main *self)
{
	char *temp, build_opts[128];
	cl_ulong maxsize, maxsize2;

	global_work_size = 0;
	assert(sizeof(hccap_t) == HCCAP_SIZE);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(temp);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, GWS_CONFIG)))
		global_work_size = atoi(temp);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);

	snprintf(build_opts, sizeof(build_opts), "-DHASH_LOOPS=%u -DITERATIONS=%u -DPLAINTEXT_LENGTH=%u", HASH_LOOPS, ITERATIONS, PLAINTEXT_LENGTH);
	opencl_init_opt("$JOHN/wpapsk_kernel.cl", ocl_gpu_id, platform_id, build_opts);

	crypt_kernel = wpapsk_init = clCreateKernel(program[ocl_gpu_id], "wpapsk_init", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_loop = clCreateKernel(program[ocl_gpu_id], "wpapsk_loop", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_pass2 = clCreateKernel(program[ocl_gpu_id], "wpapsk_pass2", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_final_md5 = clCreateKernel(program[ocl_gpu_id], "wpapsk_final_md5", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");
	wpapsk_final_sha1 = clCreateKernel(program[ocl_gpu_id], "wpapsk_final_sha1", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(wpapsk_init, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(wpapsk_loop, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(wpapsk_pass2, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(wpapsk_final_md5, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(wpapsk_final_sha1, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;

	//fprintf(stderr, "Max LWS %lu\n", maxsize);

	if (local_work_size > maxsize)
		local_work_size = maxsize;

	if (!local_work_size) {
		int temp = global_work_size;

		local_work_size = maxsize;
		global_work_size = global_work_size ? global_work_size : KEYS_PER_CRYPT;
		create_clobj(global_work_size, self);
		opencl_find_best_workgroup_limit(self, maxsize);
		release_clobj();
		global_work_size = temp;
	}

	if (!global_work_size)
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
	create_clobj(global_work_size, self);
	atexit(release_all);
}

static void crypt_all(int count)
{
	int i;

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0, sizeof(wpapsk_password) * global_work_size, inbuffer, 0, NULL, NULL), "Copy data to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], wpapsk_init, 1, NULL, &global_work_size, &local_work_size, 0, NULL, firstEvent), "Run initial kernel");

	for (i = 0; i < ITERATIONS / HASH_LOOPS; i++)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], wpapsk_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], wpapsk_pass2, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run intermediate kernel");

	for (i = 0; i < ITERATIONS / HASH_LOOPS; i++)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], wpapsk_loop, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "Run loop kernel (2nd pass)");

	if (hccap.keyver == 1)
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], wpapsk_final_md5, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "Run final kernel (MD5)");
	else
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], wpapsk_final_sha1, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "Run final kernel (SHA1)");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Failed running final kernel");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_TRUE, 0, sizeof(mic_t) * global_work_size, mic, 0, NULL, NULL), "Copy result back");
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
