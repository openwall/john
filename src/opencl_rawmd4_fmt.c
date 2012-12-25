/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2010 by Solar Designer
 *
 * MD5 OpenCL code is based on Alain Espinosa's OpenCL patches.
 *
 */

#include <string.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include "config.h"
#include "options.h"

#define PLAINTEXT_LENGTH    31
#define FORMAT_LABEL        "raw-md4-opencl"
#define FORMAT_NAME         "Raw MD4"
#define ALGORITHM_NAME      "OpenCL (inefficient, development use only)"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define CIPHERTEXT_LENGTH   32
#define BINARY_SIZE         16
#define SALT_SIZE           0

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys;
static cl_uint *partial_hashes;
static cl_uint *res_hashes;
static char *saved_plain;
static int keybuf_size = (PLAINTEXT_LENGTH + 1);

#define MIN(a, b)		(a > b) ? (b) : (a)
#define MAX(a, b)		(a > b) ? (a) : (b)

#define MIN_KEYS_PER_CRYPT      2048
#define MAX_KEYS_PER_CRYPT      (1024 * 2048)

#define LWS_CONFIG		"rawmd4_LWS"
#define GWS_CONFIG		"rawmd4_GWS"
#define DUR_CONFIG		"rawmd4_MaxDuration"

static int have_full_hashes;

static int max_keys_per_crypt = MAX_KEYS_PER_CRYPT;
static int saved_keys_per_crypt;

static struct fmt_tests tests[] = {
	{"$MD4$6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"$MD4$31d6cfe0d16ae931b73c59d7e0c089c0", "" },
	{"$MD4$cafbb81fb64d9dd286bc851c4c6e0d21", "lolcode" },
	{"$MD4$585028aa0f794af812ee3be8804eb14a", "123456" },
	{"$MD4$23580e2a459f7ea40f9efa148b63cafb", "12345" },
	{"$MD4$bf75555ca19051f694224f2f5e0b219d", "1234567" },
	{"$MD4$41f92cf74e3d2c3ba79183629a929915", "rockyou" },
	{"$MD4$0ceb1fd260c35bd50005341532748de6", "abc123" },
	{NULL}
};

static void create_clobj(int kpc){
	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, keybuf_size * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");
	saved_plain = (char *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, keybuf_size * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	res_hashes = malloc(sizeof(cl_uint) * 3 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, keybuf_size * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, BINARY_SIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 2");
}

static void release_clobj(void){
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Ummapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Ummapping saved_plain");

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
	HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes), "Error Releasing pinned_partial_hashes");
	MEM_FREE(res_hashes);
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
	HANDLE_CLERROR(clReleaseContext(context[ocl_gpu_id]), "Release Context");
}

static cl_ulong gws_test(int gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_command_queue queue_prof;
	cl_event Event[4];
	cl_int ret_code;
	int i;

	create_clobj(gws);
	queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);

        for (i=0; i < gws; i++){
		strncpy(&(saved_plain[i * keybuf_size]), tests[0].plaintext, keybuf_size);
		saved_plain[i * keybuf_size + strlen(tests[0].plaintext)] = 0x80;
	}
	///Copy data to GPU memory
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_FALSE, 0, keybuf_size * gws, saved_plain, 0, NULL, &Event[0]), "Copy memin");

	///Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 1, NULL, (size_t *) &gws, &local_work_size, 0, NULL, &Event[1]), "Set ND range");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, buffer_out, CL_TRUE, 0, sizeof(cl_uint) * gws, res_hashes, 0, NULL, &Event[2]), "Copy data back");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, buffer_out, CL_TRUE, 0, sizeof(cl_uint) * gws * 3, res_hashes, 0, NULL, &Event[3]), "Copy data back");

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "input xfer: %llu us, ", (endTime-startTime)/1000ULL);

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[1], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[1], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "kernel %.2f ms, ", (float)((endTime - startTime)/1000000.));

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "- exceeds 200 ms\n");
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "results xfer: %llu us\n", (endTime-startTime)/1000ULL);

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0], CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");

	clReleaseCommandQueue(queue_prof);
	release_clobj();

	return (endTime - startTime);
}

static void find_best_gws(int do_benchmark, struct fmt_main *self)
{
	int num;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	unsigned int cryptspeed, bestspeed = 0;
	int optimal_gws = local_work_size;
	unsigned long long int MaxRunTime = cpu(device_info[ocl_gpu_id]) ? 500000000ULL : 1000000000ULL;
	char *tmp_value;

	if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, DUR_CONFIG)))
		MaxRunTime = atoi(tmp_value) * 1000000000ULL;

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size; num; num *= 2) {
		//Check if hardware can handle the size we are going to try now.
		if (keybuf_size * num * 1.2 > get_max_mem_alloc_size(ocl_gpu_id))
			break;

		if (!do_benchmark)
			advance_cursor();
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		cryptspeed = (1000000000UL * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d\t %14u c/s%8.3f sec per crypt_all()", num, cryptspeed, (float)run_time / 1000000000.);

		if (((float)run_time / (float)min_time) < ((float)cryptspeed / (float)bestspeed)) {
			if (do_benchmark)
				fprintf(stderr, "!\n");
			bestspeed = cryptspeed;
			optimal_gws = num;
		} else {
			if (run_time < MaxRunTime && cryptspeed > (bestspeed * 1.01)) {
				if (do_benchmark)
					fprintf(stderr, "+\n");
				bestspeed = cryptspeed;
				optimal_gws = num;
				continue;
			}
			if (do_benchmark)
				fprintf(stderr, "\n");
			if (run_time >= MaxRunTime)
				break;
		}
	}
	fprintf(stderr, "Optimal global work size %d\n", optimal_gws);
	fprintf(stderr, "(to avoid this test on next run, put \""
		GWS_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
		SUBSECTION_OPENCL "])\n", optimal_gws);

	max_keys_per_crypt = optimal_gws;

}

static void init(struct fmt_main *self) {
	char build_opts[64];
	char *kpc;

	/* Reduced length can give a significant boost.
	   This kernel need a multiple of 4 - 1 (eg. 31, 15 or 11). */
	if (options.force_maxlength && options.force_maxlength < PLAINTEXT_LENGTH - 3) {
		keybuf_size = MAX((options.force_maxlength + 4) / 4 * 4, 8);
		self->params.benchmark_comment = mem_alloc_tiny(20, MEM_ALIGN_NONE);
		sprintf(self->params.benchmark_comment, " (max length %d)",
		        keybuf_size - 1);
	}
	snprintf(build_opts, sizeof(build_opts),
	         "-DKEY_LENGTH=%d", keybuf_size);
	opencl_init_opt("$JOHN/kernels/md4_kernel.cl", ocl_gpu_id, platform_id, build_opts);
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "md4", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	max_keys_per_crypt = MAX_KEYS_PER_CRYPT;
	local_work_size = 0;

	if ((kpc = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(kpc);

	if ((kpc = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, GWS_CONFIG)))
		max_keys_per_crypt = atoi(kpc);

	if ((kpc = getenv("LWS")))
		local_work_size = atoi(kpc);

	if ((kpc = getenv("GWS")))
		max_keys_per_crypt = atoi(kpc);

	if (local_work_size > get_current_work_group_size(ocl_gpu_id, crypt_kernel))
		local_work_size = get_current_work_group_size(ocl_gpu_id, crypt_kernel);

	if (!local_work_size) {
		create_clobj(MAX_KEYS_PER_CRYPT);
		opencl_find_best_workgroup(self);
		release_clobj();
	}

	if (max_keys_per_crypt == 0){
		//user chose to die of boredom
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);
	}
	fprintf(stderr, "Local work size (LWS) %d, Global work size (GWS) %d\n",(int)local_work_size, max_keys_per_crypt);
	atexit(done);
	create_clobj(max_keys_per_crypt);

	self->params.max_keys_per_crypt = max_keys_per_crypt;
	self->params.min_keys_per_crypt = local_work_size;
}

static int valid(char *ciphertext, struct fmt_main *self) {
	char *p, *q;
	p = ciphertext;
	if (!strncmp(p, "$MD4$", 5))
		p += 5;
	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index) {
	static char out[5 + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, "$MD4$", 5))
		return ciphertext;

	memcpy(out, "$MD4$", 5);
	memcpy(out + 5, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext) {
	static unsigned char out[BINARY_SIZE];
	char *p;
	int i;
	p = ciphertext + 5;
	for (i = 0; i < sizeof(out); i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}
static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *) binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *) binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *) binary & 0x7FFFFFF; }

static int get_hash_0(int index) { return partial_hashes[index] & 0x0F; }
static int get_hash_1(int index) { return partial_hashes[index] & 0xFF; }
static int get_hash_2(int index) { return partial_hashes[index] & 0xFFF; }
static int get_hash_3(int index) { return partial_hashes[index] & 0xFFFF; }
static int get_hash_4(int index) { return partial_hashes[index] & 0xFFFFF; }
static int get_hash_5(int index) { return partial_hashes[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return partial_hashes[index] & 0x7FFFFFF; }

static void set_salt(void *salt) { }

static void set_key(char *key, int index) {
	int length = -1;
	int base = index * keybuf_size;

	do {
		length++;
		saved_plain[base + length] = key[length];
	}
	while (key[length]);
	memset(&saved_plain[base + length + 1], 0, 7);	// ugly hack which "should" work!
}

static char *get_key(int index) {
	int length = -1;
	int base = index * keybuf_size;
	static char out[PLAINTEXT_LENGTH + 1];

	do {
		length++;
		out[length] = saved_plain[base + length];
	}
	while (out[length] && length < keybuf_size);
	out[length] = 0;
	return out;
}

static void crypt_all(int count)
{
	size_t gws;

	gws = (((count + local_work_size - 1) / local_work_size) * local_work_size);
	saved_keys_per_crypt = gws;

#ifdef DEBUGVERBOSE
	int i, j;
	unsigned char *p = (unsigned char *) saved_plain;
	count--;
	for (i = 0; i < count + 1; i++) {
		fprintf(stderr, "\npassword : ");
		for (j = 0; j < 64; j++) {
			fprintf(stderr, "%02x ", p[i * 64 + j]);
		}
	}
	fprintf(stderr, "\n");
#endif
	// copy keys to the device
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
	    keybuf_size * gws, saved_plain, 0, NULL, NULL),
	    "failed in clEnqueueWriteBuffer buffer_keys");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
	    &gws, &local_work_size, 0, NULL, profilingEvent),
	    "failed in clEnqueueNDRangeKernel");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]),"failed in clFinish");
	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0,
	    sizeof(cl_uint) * gws, partial_hashes, 0, NULL, NULL),
	    "failed in reading data back");
	have_full_hashes = 0;

#ifdef DEBUGVERBOSE
	p = (unsigned char *) partial_hashes;
	for (i = 0; i < 2; i++) {
		fprintf(stderr, "\n\npartial_hashes : ");
		for (j = 0; j < 16; j++)
			fprintf(stderr, "%02x ", p[i * 16 + j]);
	}
	fprintf(stderr, "\n");;
#endif
}

static int cmp_one(void *binary, int index){
	unsigned int *t = (unsigned int *) binary;

	if (t[0] == partial_hashes[index])
		return 1;
	return 0;
}

static int cmp_all(void *binary, int count) {
	unsigned int i = 0;
	unsigned int b = ((unsigned int *) binary)[0];
	for (; i < count; i++)
		if (b == partial_hashes[i])
			return 1;
	return 0;
}

static int cmp_exact(char *source, int count){
	unsigned int *t = (unsigned int *) get_binary(source);

	if (!have_full_hashes){
	clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
		sizeof(cl_uint) * (saved_keys_per_crypt),
		sizeof(cl_uint) * 3 * saved_keys_per_crypt, res_hashes, 0,
		NULL, NULL);
		have_full_hashes = 1;
	}

	if (t[1]!=res_hashes[count])
		return 0;
	if (t[2]!=res_hashes[1*saved_keys_per_crypt+count])
		return 0;
	if (t[3]!=res_hashes[2*saved_keys_per_crypt+count])
		return 0;
	return 1;
}

struct fmt_main fmt_opencl_rawMD4 = {
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
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
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
