/*
 * Copyright (c) 2012 Samuele Giovanni Tonon
 * samu at linuxasylum dot net, and
 * Copyright (c) 2012, 2013 magnum
 * This program comes with ABSOLUTELY NO WARRANTY; express or
 * implied.
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "options.h"
#include "formats.h"
#include "sha.h"
#include "common-opencl.h"

#define FORMAT_LABEL            "mysql-sha1-opencl"
#define FORMAT_NAME             "MySQL 4.1+"
#define ALGORITHM_NAME          "SHA1 OpenCL (inefficient, development use only)"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1

#define PLAINTEXT_LENGTH        55
#define CIPHERTEXT_LENGTH       41

#define BINARY_SIZE             20
#define BINARY_ALIGN            1
#define SALT_SIZE               0
#define SALT_ALIGN              1

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      (1024 * 2048)

#define OCL_CONFIG              "mysql-sha1"

typedef struct {
	unsigned int h0,h1,h2,h3,h4;
} SHA_DEV_CTX;


static char *saved_key;
static unsigned int *output, *saved_idx, key_idx;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_result;
static cl_mem pinned_key, pinned_idx, pinned_result;
static int partial_output;

static struct fmt_tests tests[] = {
	{"*5AD8F88516BD021DD43F171E2C785C69F8E54ADB", "tere"},
	{"*2c905879f74f28f8570989947d06a8429fb943e6", "verysecretpassword"},
	{"*A8A397146B1A5F8C8CF26404668EFD762A1B7B82", "________________________________"},
	{"*F9F1470004E888963FB466A5452C9CBD9DF6239C", "12345678123456781234567812345678"},
	{"*97CF7A3ACBE0CA58D5391AC8377B5D9AC11D46D9", "' OR 1 /*'"},
	{"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "password"},
	{"*7534F9EAEE5B69A586D1E9C1ACE3E3F9F6FCC446", "5"},
	{"*be1bdec0aa74b4dcb079943e70528096cca985f8", ""},
	{"*0D3CED9BEC10A777AEC23CCC353A8C08A633045E", "abc"},
	{"*18E70DF2758EE4C0BD954910E5808A686BC38C6A", "VAwJsrUcrchdG9"},
	{"*440F91919FD39C01A9BC5EDB6E1FE626D2BFBA2F", "lMUXgJFc2rNnn"},
	{"*171A78FB2E228A08B74A70FE7401C807B234D6C9", "TkUDsVJC"},
	{"*F7D70FD3341C2D268E98119ED2799185F9106F5C", "tVDZsHSG"},
	{NULL}
};

static void create_clobj(size_t gws, struct fmt_main *self)
{
	global_work_size = gws;
	self->params.max_keys_per_crypt = gws;

	pinned_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, PLAINTEXT_LENGTH * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, PLAINTEXT_LENGTH * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_idx = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * (gws + 1), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_idx");

	pinned_result = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BINARY_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key),"Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 1");
}

static void release_clobj(void){
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

static cl_ulong gws_test(size_t gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_event Event[4];
	int i, tidx = 0;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	create_clobj(gws, self);

	// Set keys - all keys from tests will be benchmarked and some
	// will be permuted to force them unique
	self->methods.clear_keys();
	for (i = 0; i < gws; i++) {
		union {
			char c[PLAINTEXT_BUFFER_SIZE];
			unsigned int w;
		} uniq;
		int len;
		if (self->params.tests[tidx].plaintext == NULL)
			tidx = 0;
		len = strlen(self->params.tests[tidx].plaintext);
		strncpy(uniq.c, self->params.tests[tidx++].plaintext,
		        sizeof(uniq.c));
		uniq.w ^= i;
		uniq.c[len] = 0;
		self->methods.set_key(uniq.c, i);
	}

	/* Emulate crypt_all() */
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, &Event[0]), "Failed transferring keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, sizeof(cl_uint) * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL, &Event[1]), "Failed transferring index");
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, &Event[2]), "running kernel");

	/* Only benchmark partial transfer - that is what we optimize for */
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, sizeof(cl_uint) * gws, output, 0, NULL, &Event[3]), "failed in reading output back");

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
            CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
            NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[1],
            CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
            NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "key xfer %.2f ms, ", (double)(endTime-startTime)/1000000.);

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
            CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
            NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
            CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
            NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "crypt kernel %.2f ms, ", (double)((endTime - startTime)/1000000.));

	/* 200 ms duration limit */
	if (endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "- exceeds 200 ms\n");
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	    CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	    NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	    CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	    NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "results xfer %.2f ms", (double)(endTime-startTime)/1000000.);

	if (do_benchmark)
		fprintf(stderr, "\n");

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
	    CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
	    NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	    CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	    NULL), "Failed to get profiling info");

	release_clobj();

	return (endTime - startTime);
}

static void find_best_gws(int do_benchmark, struct fmt_main *self)
{
	int num, max_gws;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	double SHA1speed, bestSHA1speed = 0.0;
	int optimal_gws = get_kernel_preferred_multiple(ocl_gpu_id,
	                                                crypt_kernel);
	const int sha1perkey = 2;
	unsigned long long int MaxRunTime = 1000000000ULL;

	/* Enable profiling */
#ifndef CL_VERSION_1_1
	HANDLE_CLERROR(clSetCommandQueueProperty(queue[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, CL_TRUE, NULL), "Failed enabling profiling");
#else /* clSetCommandQueueProperty() is deprecated */
	cl_command_queue origQueue = queue[ocl_gpu_id];
	queue[ocl_gpu_id] = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed enabling profiling");
#endif

	/* Beware of device limits */
	max_gws = get_max_mem_alloc_size(ocl_gpu_id) / PLAINTEXT_LENGTH;

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = optimal_gws; num <= max_gws; num *= 2) {
		if (!do_benchmark)
			advance_cursor();
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		SHA1speed = sha1perkey * (1000000000. * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d %9.0f c/s %13.0f sha1/s%8.2f sec per crypt_all()", num, (1000000000. * num / run_time), SHA1speed, (double)run_time / 1000000000.);

		if (((double)run_time / (double)min_time) < (SHA1speed / bestSHA1speed)) {
			if (do_benchmark)
				fprintf(stderr, "!\n");
			bestSHA1speed = SHA1speed;
			optimal_gws = num;
		} else {
			if (run_time < MaxRunTime && SHA1speed > bestSHA1speed) {
				if (do_benchmark)
					fprintf(stderr, "+\n");
				bestSHA1speed = SHA1speed;
				optimal_gws = num;
				continue;
			}
			if (do_benchmark)
				fprintf(stderr, "\n");
			if (run_time >= MaxRunTime)
				break;
		}
	}

	/* Disable profiling */
#ifndef CL_VERSION_1_1
	HANDLE_CLERROR(clSetCommandQueueProperty(queue[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, CL_FALSE, NULL), "Failed disabling profiling");
#else /* clSetCommandQueueProperty() is deprecated */
	clReleaseCommandQueue(queue[ocl_gpu_id]);
	queue[ocl_gpu_id] = origQueue;
#endif

	global_work_size = optimal_gws;
}

static int valid(char *ciphertext, struct fmt_main *self){
	int i;

	if (ciphertext[0] != '*')
		return 0;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 1; i < CIPHERTEXT_LENGTH; i++) {
		if (!( (('0' <= ciphertext[i])&&(ciphertext[i] <= '9'))
		       || (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		       || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
		{
			return 0;
		}
	}
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, sizeof(out));
	strupr(out);
	return out;
}

static void init(struct fmt_main *self)
{
	cl_ulong maxsize, max_mem;
	char build_opts[64];

	local_work_size = global_work_size = 0;

	snprintf(build_opts, sizeof(build_opts),
	        "-DPLAINTEXT_LENGTH=%u", PLAINTEXT_LENGTH);
	opencl_init("$JOHN/kernels/msha_kernel.cl", ocl_gpu_id, build_opts);

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(OCL_CONFIG);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "mysqlsha1_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	/* Enumerate GWS using *LWS=NULL (unless it was set explicitly) */
	if (!global_work_size)
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);

	/* Note: we ask for the kernel's max size, not the device's! */
	maxsize = get_kernel_max_lws(ocl_gpu_id, crypt_kernel);

	// Obey device limits
	max_mem = get_max_mem_alloc_size(ocl_gpu_id);
	while (global_work_size > max_mem / ((PLAINTEXT_LENGTH + 63) / 64 * 64))
		global_work_size -= get_kernel_preferred_multiple(ocl_gpu_id,
		                                                  crypt_kernel);

	if (!local_work_size) {
		create_clobj(global_work_size, self);
		opencl_find_best_workgroup_limit(self, maxsize, ocl_gpu_id, crypt_kernel);
		release_clobj();
	}

	if (local_work_size > maxsize)
		local_work_size = maxsize;

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	// Ensure GWS is multiple of LWS
	global_work_size = global_work_size / local_work_size * local_work_size;

	if (options.verbosity > 2)
		fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n",(int)local_work_size, (int)global_work_size);

	create_clobj(global_work_size, self);
	self->params.min_keys_per_crypt = local_work_size;
}

static void clear_keys(void)
{
	key_idx = 0;
	saved_idx[0] = 0;
	key_offset = 0;
	idx_offset = 0;
}

static void set_key(char *key, int index)
{
	while (*key)
		saved_key[key_idx++] = *key++;

	saved_idx[index + 1] = key_idx;

	/* Early partial transfer to GPU every 256K keys */
	if (index && !(index & (256 * 1024 - 1))) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		key_offset = key_idx;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, sizeof(cl_uint) * index - idx_offset, saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL, NULL), "Failed transferring index");
		idx_offset = sizeof(cl_uint) * index;
		HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "failed in clFlush");
	}
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index + 1] - saved_idx[index];
	char *key = (char*)&saved_key[saved_idx[index]];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	return out;
}

static void *get_binary(char *ciphertext)
{
	static char realcipher[BINARY_SIZE];
	int i;

	ciphertext += 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		/* endian swap now instead of billions of times later */
		realcipher[i ^ 3] =
			atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void *)realcipher;
}

static int cmp_all(void *binary, int index)
{
	unsigned int i;
	unsigned int b = ((unsigned int*)binary)[0];

	for(i = 0; i < index; i++)
		if (b == output[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	unsigned int *t = (unsigned int*) binary;

	return (t[0] == output[index]);
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD_32 *binary;
	int i;

	if (partial_output) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, BINARY_SIZE * global_work_size, output, 0, NULL, NULL), "failed reading results back");
		partial_output = 0;
	}
	binary = (ARCH_WORD_32*)get_binary(source);

	for(i = 0; i < BINARY_SIZE / 4; i++)
		if (output[i * global_work_size + index] != binary[i])
			return 0;
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	/* Don't do more than requested */
	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	/* Self-test cludge */
	if (idx_offset > 4 * (global_work_size + 1))
		idx_offset = 0;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, sizeof(cl_uint) * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / sizeof(cl_uint)), 0, NULL, NULL), "Failed transferring index");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent), "failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, sizeof(cl_uint) * global_work_size, output, 0, NULL, NULL), "failed in reading data back");
	partial_output = 1;

	return count;
}

static int get_hash_0(int index) { return output[index] & 0xf; }
static int get_hash_1(int index) { return output[index] & 0xff; }
static int get_hash_2(int index) { return output[index] & 0xfff; }
static int get_hash_3(int index) { return output[index] & 0xffff; }
static int get_hash_4(int index) { return output[index] & 0xfffff; }
static int get_hash_5(int index) { return output[index] & 0xffffff; }
static int get_hash_6(int index) { return output[index] & 0x7ffffff; }

struct fmt_main fmt_opencl_mysqlsha1 = {
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
		0,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		clear_keys,
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
