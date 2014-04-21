/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-256
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>

#include "common-opencl.h"
#include "config.h"
#include "options.h"
#include "opencl_cryptsha256.h"
#include "cryptsha256_common.h"
#include "memdbg.h"

#define FORMAT_LABEL			"sha256crypt-opencl"
#define ALGORITHM_NAME			"SHA256 OpenCL"
#define OCL_CONFIG			"sha256crypt"

//Checks for source code to pick (parameters, sizes, kernels to execute, etc.)
#define _USE_CPU_SOURCE			(cpu(source_in_use))
#define _USE_GPU_SOURCE			(gpu(source_in_use) || platform_apple(platform_id))
#define _USE_LOCAL_SOURCE		(use_local(source_in_use) || amd_vliw5(source_in_use))
#define _SPLIT_KERNEL_IN_USE		(_USE_GPU_SOURCE || _USE_LOCAL_SOURCE)

static sha256_salt			* salt;
static sha256_password			* plaintext;			// plaintext ciphertexts
static sha256_hash			* calculated_hash;		// calculated hashes

static cl_mem salt_buffer;		//Salt information.
static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem hash_buffer;		//Hash keys (output).
static cl_mem work_buffer;		//Temporary buffer
static cl_mem pinned_saved_keys, pinned_partial_hashes;

static cl_kernel prepare_kernel, final_kernel;

static int new_keys, source_in_use;
static int split_events[3] = { 1, 4, 5 };

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). Have to included after formats definitions.
#include "opencl_autotune.h"

static struct fmt_tests tests[] = {
	{"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
	{"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
	{"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
	{"$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0", "password"},
	{NULL}
};

/*********
static struct fmt_tests tests[] = {
	{"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
	{"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.", "U*U***U"},
	{"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
	{"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
	{"$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43", ""},
#ifdef DEBUG //Special test cases.
	{"$5$EKt.VLXiPjwyv.xe$52wdOp9ixFXMsHDI1JcCw8KJ83IakDP6J7MIEV2OUk0", "1234567"},
	{"$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0", "password"},
#endif
	{NULL}
};
****/

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size(){

	return common_get_task_max_work_group_size(_USE_LOCAL_SOURCE,
		(sizeof(sha256_ctx) + sizeof(sha256_buffers) + 1),
		crypt_kernel);
}

static size_t get_task_max_size(){

	return common_get_task_max_size((amd_gcn(device_info[gpu_id]) ? 10 : 4),
		KEYS_PER_CORE_CPU, KEYS_PER_CORE_GPU, crypt_kernel);
}

static size_t get_default_workgroup(){

	if (cpu(device_info[gpu_id]))
		return 1;
	else
		return 128;
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main * self)
{
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	pinned_saved_keys = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(sha256_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	plaintext = (sha256_password *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_keys, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(sha256_password) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id],
			CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(sha256_hash) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (sha256_hash *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
			sizeof(sha256_hash) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

	// create arguments (buffers)
	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha256_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha256_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
			sizeof(sha256_hash) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	work_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
			sizeof(sha256_buffers) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area");

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
			(void *) &salt_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 2");

	if (_SPLIT_KERNEL_IN_USE) {
		size_t temp_size = local_work_size;

		if (!local_work_size)
			temp_size = get_task_max_work_group_size();

		//Set prepare kernel arguments
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 0, sizeof(cl_mem),
			(void *) &salt_buffer), "Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem),
			(void *) &work_buffer), "Error setting argument 2");

		if (_USE_LOCAL_SOURCE) {

			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 3,
				sizeof(sha256_buffers) * temp_size,
				NULL), "Error setting argument 3");
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 4,
				sizeof(sha256_ctx) * temp_size,
				NULL), "Error setting argument 4");
		}
		//Set crypt kernel arguments
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
			(void *) &work_buffer), "Error setting argument crypt_kernel (3)");

		if (_USE_LOCAL_SOURCE) {
			//Fast working memory.
			HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4,
				sizeof(sha256_buffers) * temp_size,
				NULL), "Error setting argument 4");
			HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5,
				sizeof(sha256_ctx) * temp_size,
				NULL), "Error setting argument 5");
		}
		//Set final kernel arguments
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(cl_mem),
				(void *) &salt_buffer), "Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(cl_mem),
				(void *) &pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(cl_mem),
				(void *) &hash_buffer), "Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_mem),
			(void *) &work_buffer), "Error setting argument crypt_kernel (3)");

		if (_USE_LOCAL_SOURCE) {
			//Fast working memory.
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 4,
				sizeof(sha256_buffers) * temp_size,
				NULL), "Error setting argument 4");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 5,
				sizeof(sha256_ctx) * temp_size,
				NULL), "Error setting argument 5");
		}
	}
	memset(plaintext, '\0', sizeof(sha256_password) * gws);
}

static void release_clobj(void) {
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
			calculated_hash, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping out_hashes");

	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
			plaintext, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping saved_plain");

	ret_code = clReleaseMemObject(salt_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing data_info");
	ret_code = clReleaseMemObject(pass_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
	ret_code = clReleaseMemObject(hash_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");
	ret_code = clReleaseMemObject(work_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing work_out");

	ret_code = clReleaseMemObject(pinned_saved_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");

	ret_code = clReleaseMemObject(pinned_partial_hashes);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Salt functions ------- */
static void * get_salt(char *ciphertext) {
	static sha256_salt out;
	int len;

	out.rounds = ROUNDS_DEFAULT;
	ciphertext += 3;
	if (!strncmp(ciphertext, ROUNDS_PREFIX,
			sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			ciphertext = endp + 1;
			srounds = srounds < ROUNDS_MIN ?
					ROUNDS_MIN : srounds;
			out.rounds = srounds > ROUNDS_MAX ?
					ROUNDS_MAX : srounds;
		}
	}
	for (len = 0; ciphertext[len] != '$'; len++);
	//Assure buffer has no "trash data".
	memset(out.salt, '\0', SALT_LENGTH);
	len = (len > SALT_LENGTH ? SALT_LENGTH : len);

	//Put the tranfered salt on salt buffer.
	memcpy(out.salt, ciphertext, len);
	out.length = len;
	out.final = out.rounds - GET_MULTIPLE(out.rounds, HASH_LOOPS);

	return &out;
}

static void set_salt(void * salt_info) {

	salt = salt_info;

	//Send salt information to GPU.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0,
		sizeof(sha256_salt), (void * ) salt, 0, NULL, NULL),
		"failed in clEnqueueWriteBuffer salt_buffer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static int salt_hash(void * salt) {

	return common_salt_hash(salt, SALT_SIZE, SALT_HASH_SIZE);
}

/* ------- Key functions ------- */
static void set_key(char * key, int index) {
	int len;

	//Assure buffer has no "trash data".
	memset(plaintext[index].pass, '\0', PLAINTEXT_LENGTH);
	len = strlen(key);
	len = (len > PLAINTEXT_LENGTH ? PLAINTEXT_LENGTH : len);

	//Put the tranfered key on password buffer.
	memcpy(plaintext[index].pass, key, len);
	plaintext[index].length = len ;
	new_keys = 1;
}

static char * get_key(int index) {
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, plaintext[index].pass, PLAINTEXT_LENGTH);
	ret[plaintext[index].length] = '\0';
	return ret;
}

/* ------- Initialization  ------- */
static void build_kernel(char * task) {

	opencl_build_kernel(task, gpu_id, NULL, 1);

	// create kernel(s) to execute
	crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	if (_SPLIT_KERNEL_IN_USE) {
		prepare_kernel = clCreateKernel(program[gpu_id], "kernel_prepare", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel_prepare. Double-check kernel name?");
		final_kernel = clCreateKernel(program[gpu_id], "kernel_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel_final. Double-check kernel name?");
	}
}

static void init(struct fmt_main * self) {
	char * tmp_value;
	char * task = "$JOHN/kernels/cryptsha256_kernel_DEFAULT.cl";

	opencl_prepare_dev(gpu_id);
	source_in_use = device_info[gpu_id];

	if ((tmp_value = getenv("_TYPE")))
		source_in_use = atoi(tmp_value);

	if (_USE_LOCAL_SOURCE)
		task = "$JOHN/kernels/cryptsha256_kernel_LOCAL.cl";

	else if (_USE_GPU_SOURCE)
		task = "$JOHN/kernels/cryptsha256_kernel_GPU.cl";

	build_kernel(task);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(STEP, HASH_LOOPS, ((_SPLIT_KERNEL_IN_USE) ? 7 : 3),
		((_SPLIT_KERNEL_IN_USE) ? split_events : NULL),
		warn, 1, self, create_clobj, release_clobj,
		sizeof(sha256_password), 0);

	if (source_in_use != device_info[gpu_id])
		fprintf(stderr, "Selected runtime id %d, source (%s)\n", source_in_use, task);

	//Auto tune execution from shared/included code.
	self->methods.crypt_all = crypt_all_benchmark;
	common_run_auto_tune(self, ROUNDS_DEFAULT, 0,
		(cpu(device_info[gpu_id]) ? 2000000000ULL : 7000000000ULL));
	self->methods.crypt_all = crypt_all;
}

static void done(void) {
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");

	if (_SPLIT_KERNEL_IN_USE) {
		HANDLE_CLERROR(clReleaseKernel(prepare_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
	}
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
	uint32_t i;
	uint32_t b = ((uint32_t *) binary)[0];

	for (i = 0; i < count; i++)
		if (b == calculated_hash[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void * binary, int index) {
	return !memcmp(binary, (void *) &calculated_hash[index], BINARY_SIZE);
}

static int cmp_exact(char * source, int count) {
	return 1;
}

/* ------- Crypt function ------- */
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt)
{
	int count = *pcount;
	int i;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
			sizeof(sha256_password) * gws, plaintext, 0, NULL, multi_profilingEvent[0]),
			"failed in clEnqueueWriteBuffer pass_buffer");

	//Enqueue the kernel
	if (_SPLIT_KERNEL_IN_USE) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[3]),
			"failed in clEnqueueNDRangeKernel I");

		for (i = 0; i < 3; i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
				&gws, lws, 0, NULL,
				multi_profilingEvent[split_events[i]]),  //1 ,4 ,5
				"failed in clEnqueueNDRangeKernel");
		}
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[6]),
			"failed in clEnqueueNDRangeKernel II");
	} else
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(sha256_hash) * gws, calculated_hash, 0, NULL, multi_profilingEvent[2]),
			"failed in reading data back");

	//Do the work
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

	return count;
}

static int crypt_all(int *pcount, struct db_salt *_salt)
{
	int count = *pcount;
	int i;
	size_t gws;

	gws = GET_MULTIPLE_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
				sizeof(sha256_password) * gws, plaintext, 0, NULL, NULL),
				"failed in clEnqueueWriteBuffer pass_buffer");

	//Enqueue the kernel
	if (_SPLIT_KERNEL_IN_USE) {
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel I");

		for (i = 0; i < (salt->rounds / HASH_LOOPS); i++) {
			HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
				&gws, &local_work_size, 0, NULL, NULL),
				"failed in clEnqueueNDRangeKernel");
			HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel II");
	} else
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(sha256_hash) * gws, calculated_hash, 0, NULL, NULL),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

	return count;
}

/* ------- Binary Hash functions group ------- */
static int get_hash_0(int index) { return calculated_hash[index].v[0] & 0xf; }
static int get_hash_1(int index) { return calculated_hash[index].v[0] & 0xff; }
static int get_hash_2(int index) { return calculated_hash[index].v[0] & 0xfff; }
static int get_hash_3(int index) { return calculated_hash[index].v[0] & 0xffff; }
static int get_hash_4(int index) { return calculated_hash[index].v[0] & 0xfffff; }
static int get_hash_5(int index) { return calculated_hash[index].v[0] & 0xffffff; }
static int get_hash_6(int index) { return calculated_hash[index].v[0] & 0x7ffffff; }

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	sha256_salt *sha256crypt_salt;
	sha256crypt_salt = salt;
	return (unsigned int)sha256crypt_salt->rounds;
}
#endif


/* ------- Format structure ------- */
struct fmt_main fmt_opencl_cryptsha256 = {
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
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
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
		salt_hash,
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
