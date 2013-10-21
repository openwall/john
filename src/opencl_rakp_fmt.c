/*
 * Code based on:
 * - Assorted OpenCL JtR plugins
 * - RAKP JtR plugin, (C) 2012 magnum, (C) 2013 Dhiru Kholia
 *
 * OpenCL RAKP JtR plugin (C) 2013 by Harrison Neal
 * Vectorizing, packed key buffer and other optimizations (c) magnum 2013
 *
 * Licensed under GPLv2
 * This program comes with ABSOLUTELY NO WARRANTY, neither expressed nor
 * implied. See the following for more information on the GPLv2 license:
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include "common-opencl.h"
#include "options.h"

#define FORMAT_LABEL            "RAKP-opencl"
#define FORMAT_NAME             ""
#define ALGORITHM_NAME          "IPMI 2.0 RAKP (RMCP+) OpenCL"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1000

#define BLOCK_SIZE              64
#define PAD_SIZE                BLOCK_SIZE
#define SALT_STORAGE_SIZE       (BLOCK_SIZE*2)
#define SALT_SIZE               (SALT_STORAGE_SIZE - 9)
#define SALT_MIN_SIZE           (SALT_SIZE - BLOCK_SIZE + 1)

#define PLAINTEXT_LENGTH        (PAD_SIZE - 1) /* idx & 63 */

#define BINARY_SIZE             20

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      (3 * 1024 * 1024)

#define FORMAT_TAG              "$rakp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define BINARY_ALIGN            1
#define SALT_ALIGN              1

#define OCL_CONFIG              "rakp"
#define HEXCHARS                "0123456789abcdef"

#ifndef uint32_t
#define uint32_t unsigned int
#endif

static unsigned char salt_storage[SALT_STORAGE_SIZE];

cl_command_queue queue_prof;
cl_int ret_code;
cl_kernel crypt_kernel;
cl_mem salt_buffer, keys_buffer, idx_buffer, digest_buffer;

static unsigned int *keys;
static unsigned int *idx;
static ARCH_WORD_32 (*digest);
static unsigned int key_idx = 0;
static unsigned int v_width = 1;	/* Vector width of kernel */
static int partial_output;

#define MIN(a, b)               (((a) > (b)) ? (b) : (a))
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))

static struct fmt_tests tests[] = {
	{"$rakp$a4a3a2a03f0b000094272eb1ba576450b0d98ad10727a9fb0ab83616e099e8bf5f7366c9c03d36a3000000000000000000000000000000001404726f6f74$0ea27d6d5effaa996e5edc855b944e179a2f2434", "calvin"},
	{"$rakp$c358d2a72f0c00001135f9b254c274629208b22f1166d94d2eba47f21093e9734355a33593da16f2000000000000000000000000000000001404726f6f74$41fce60acf2885f87fcafdf658d6f97db12639a9", "calvin"},
	{"$rakp$b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174$472bdabe2d5d4bffd6add7b3ba79a291d104a9ef", "hashcat"},
	{NULL}
};

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q = NULL;
	int len;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = strrchr(ciphertext, '$');
	if (!q)
		return 0;
	q = q + 1;
	if ((q - p - 1) > SALT_SIZE * 2)
		return 0;

	if ((q - p - 1) < SALT_MIN_SIZE * 2)
		return 0;

	len = strspn(q, HEXCHARS);
	if (len != BINARY_SIZE * 2 || len != strlen(q))
		return 0;

	if (strspn(p, HEXCHARS) != q - p - 1)
		return 0;

	return 1;
}

static void clear_keys(void);
static void set_key(char *key, int index);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	global_work_size = kpc;
	kpc *= v_width;

	keys = mem_alloc((PLAINTEXT_LENGTH + 1) * kpc);
	idx = mem_alloc(sizeof(*idx) * kpc);
	digest = mem_alloc(kpc * BINARY_SIZE);

	salt_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, SALT_STORAGE_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	keys_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, (PLAINTEXT_LENGTH + 1) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating keys_buffer out argument");

	idx_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating idx_buffer out argument");

	digest_buffer = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, BINARY_SIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating digest_buffer in argument");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 0, sizeof(salt_buffer), (void *) &salt_buffer),
		"Error attaching salt_buffer to kernel");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 1, sizeof(keys_buffer), (void *) &keys_buffer),
		"Error attaching keys_buffer to kernel");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 2, sizeof(idx_buffer), (void *) &idx_buffer),
		"Error attaching idx_buffer to kernel");

	HANDLE_CLERROR(
		clSetKernelArg(crypt_kernel, 3, sizeof(digest_buffer), (void *) &digest_buffer),
		"Error attaching digest_buffer to kernel");

	self->params.min_keys_per_crypt = local_work_size * v_width;
	self->params.max_keys_per_crypt = global_work_size * v_width;
}

static void release_clobj(void)
{
	MEM_FREE(keys);
	MEM_FREE(idx);
	MEM_FREE(digest);

	HANDLE_CLERROR(clReleaseMemObject(salt_buffer), "Error releasing salt_buffer");
	HANDLE_CLERROR(clReleaseMemObject(keys_buffer), "Error releasing keys_buffer");
	HANDLE_CLERROR(clReleaseMemObject(idx_buffer), "Error releasing idx_buffer");
	HANDLE_CLERROR(clReleaseMemObject(digest_buffer), "Error releasing digest_buffer");
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Error releasing kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Error releasing program");
}

static cl_ulong gws_test(size_t gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_event Event[4];
	int i, tidx = 0;
	size_t scalar_gws = v_width * gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	create_clobj(gws, self);

	// Set keys - all keys from tests will be benchmarked and some
	// will be permuted to force them unique
	self->methods.clear_keys();
	for (i = 0; i < scalar_gws; i++) {
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

	self->methods.set_salt(self->methods.salt(tests[0].ciphertext));

	/* Emulate crypt_all() */
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], keys_buffer, CL_FALSE, 0, 4 * key_idx, keys, 0, NULL, &Event[0]), "Error updating contents of keys_buffer");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], idx_buffer, CL_FALSE, 0, 4 * scalar_gws, idx, 0, NULL, &Event[1]), "Error updating contents of idx_buffer");
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, &Event[2]), "running kernel");

	/* Only benchmark partial transfer - that is what we optimize for */
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], digest_buffer, CL_TRUE, 0, sizeof(cl_uint) * scalar_gws, digest, 0, NULL, &Event[3]), "Error reading results from digest_buffer");

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
		fprintf(stderr, "crypt %.2f ms, ", (double)(endTime-startTime)/1000000.);

	/* 200 ms duration limit */
	if (endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "exceeds 200 ms\n");
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
	int optimal_gws = get_kernel_preferred_multiple(ocl_gpu_id, crypt_kernel);
	const int sha1perkey = 5;
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
	max_gws = MIN(get_max_mem_alloc_size(ocl_gpu_id) / PAD_SIZE, get_global_memory_size(ocl_gpu_id) / (PAD_SIZE + 4 + 20 + SALT_STORAGE_SIZE)) / v_width;

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = optimal_gws; num <= max_gws; num *= 2) {
		if (!do_benchmark)
			advance_cursor();
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		SHA1speed = sha1perkey * (1000000000. * num * v_width / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d %9.0f c/s %13.0f sha1/s%8.2f sec per crypt_all()", num, (1000000000. * num * v_width / run_time), SHA1speed, (double)run_time / 1000000000.);

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

static void init(struct fmt_main *self)
{
	cl_ulong maxsize, max_mem;
	char build_opts[64];
	static char valgo[48] = "";

	if ((v_width = opencl_get_vector_width(ocl_gpu_id,
	                                       sizeof(cl_int))) > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", v_width);
		self->params.algorithm_name = valgo;
	}

	local_work_size = global_work_size = 0;

	snprintf(build_opts, sizeof(build_opts), "-DV_WIDTH=%u", v_width);
	opencl_init("$JOHN/kernels/rakp_kernel.cl", ocl_gpu_id, build_opts);

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(OCL_CONFIG);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "rakp_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel");

	/* Enumerate GWS using *LWS=NULL (unless it was set explicitly) */
	if (!global_work_size)
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);

	/* Note: we ask for the kernel's max size, not the device's! */
	maxsize = get_current_work_group_size(ocl_gpu_id, crypt_kernel);

	// Obey device limits
	max_mem = get_max_mem_alloc_size(ocl_gpu_id);
	while (global_work_size > max_mem /
	       (v_width * (PLAINTEXT_LENGTH + 63) / 64 * 64))
		global_work_size -= get_kernel_preferred_multiple(ocl_gpu_id,
		                                                  crypt_kernel);

	if (local_work_size > maxsize)
		local_work_size = maxsize;

	if (!local_work_size) {
		create_clobj(global_work_size, self);
		opencl_find_best_workgroup_limit(self, maxsize, ocl_gpu_id, crypt_kernel);
		release_clobj();
	}

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	// Current key_idx can only hold 26 bits of offset so
	// we can't reliably use a GWS higher than 4.7M or so.
	if (global_work_size * v_width > (1 << 26) * 4 / PAD_SIZE)
		global_work_size = (1 << 26) * 4 / PAD_SIZE / v_width;

	// Ensure GWS is multiple of LWS
	global_work_size = global_work_size / local_work_size * local_work_size;

	if (options.verbosity > 2)
		fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n",(int)local_work_size, (int)global_work_size);

	create_clobj(global_work_size, self);
}

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *key, int index)
{
	const unsigned int *key32 = (unsigned int*)key;
	int len = strlen(key);

	idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		keys[key_idx++] = *key32++;
		len -= 4;
	}
	if (len)
		keys[key_idx++] = *key32 & (0xffffffffU >> (32 - (len << 3)));
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = idx[index] & 63;
	char *key = (char*)&keys[idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = key[i];

	out[i] = 0;

	return out;
}

static void *binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	/* Endian swap once now instead of billions of times later */
	alter_endianity(out, BINARY_SIZE);

	return out;
}

static void *salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	unsigned int i, len;

	if (!strncmp(ctcopy, FORMAT_TAG, TAG_LENGTH))
		ctcopy += TAG_LENGTH;

	p = strtok(ctcopy, "$");
	len = strlen(p) / 2;
	for (i = 0; i < len; i++) {
		salt_storage[i ^ 3] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	salt_storage[len ^ 3] = 0x80;
	for (i = len + 1; i < SALT_STORAGE_SIZE - 2; i++) {
		salt_storage[i ^ 3] = 0;
	}
	len += 64;
	len *= 8;
	salt_storage[(SALT_STORAGE_SIZE - 1) ^ 3] = len & 0xffU;
	salt_storage[(SALT_STORAGE_SIZE - 2) ^ 3] = (len >> 8) & 0xffU;
	MEM_FREE(keeptr);
	return (void *)&salt_storage;
}

static void set_salt(void *salt)
{
	HANDLE_CLERROR(
		clEnqueueWriteBuffer(queue[ocl_gpu_id], salt_buffer, CL_FALSE, 0, sizeof(salt_storage), (void*) salt, 0, NULL, NULL),
		"Error updating contents of salt_buffer");
	HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "failed in clFlush");
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (digest[index] == ((unsigned int*)binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (digest[index] == ((unsigned int*)binary)[0]);
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD_32 *b;
	int i;

	if (partial_output) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], digest_buffer, CL_TRUE, 0, BINARY_SIZE * global_work_size * v_width, digest, 0, NULL, NULL), "failed reading results back");
		partial_output = 0;
	}
	b = (ARCH_WORD_32*)binary(source);

	for(i = 0; i < BINARY_SIZE / 4; i++)
		if (digest[i * global_work_size * v_width + index] != b[i])
			return 0;
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t scalar_gws;

	global_work_size = ((count + v_width * local_work_size - 1) / (v_width * local_work_size)) * local_work_size;
	scalar_gws = global_work_size * v_width;

	if (key_idx) {
		HANDLE_CLERROR(
			clEnqueueWriteBuffer(queue[ocl_gpu_id], keys_buffer, CL_FALSE, 0, 4 * key_idx, keys, 0, NULL, NULL),
			"Error updating contents of keys_buffer");

		HANDLE_CLERROR(
			clEnqueueWriteBuffer(queue[ocl_gpu_id], idx_buffer, CL_FALSE, 0, 4 * scalar_gws, idx, 0, NULL, NULL),
			"Error updating contents of idx_buffer");
	}

	HANDLE_CLERROR(
		clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent),
		"Error beginning execution of the kernel");

	HANDLE_CLERROR(
		clFinish(queue[ocl_gpu_id]),
		"Error waiting for kernel to finish executing");

	HANDLE_CLERROR(
		clEnqueueReadBuffer(queue[ocl_gpu_id], digest_buffer, CL_TRUE, 0, sizeof(cl_uint) * scalar_gws, digest, 0, NULL, NULL),
		"Error reading results from digest_buffer");
	partial_output = 1;

	return count;
}

static int get_hash_0(int index) { return digest[index] & 0xf; }
static int get_hash_1(int index) { return digest[index] & 0xff; }
static int get_hash_2(int index) { return digest[index] & 0xfff; }
static int get_hash_3(int index) { return digest[index] & 0xffff; }
static int get_hash_4(int index) { return digest[index] & 0xfffff; }
static int get_hash_5(int index) { return digest[index] & 0xffffff; }
static int get_hash_6(int index) { return digest[index] & 0x7ffffff; }

struct fmt_main fmt_opencl_rakp = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_STORAGE_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		0,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
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
		set_salt,
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
