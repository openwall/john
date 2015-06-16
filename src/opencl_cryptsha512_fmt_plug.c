/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-SHA-512
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_cryptsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_cryptsha512);
#else

#include <string.h>

#include "common-opencl.h"
#include "config.h"
#include "options.h"
#include "opencl_cryptsha512.h"
#define __CRYPTSHA512_CREATE_PROPER_TESTS_ARRAY__
#include "cryptsha512_common.h"

#define FORMAT_LABEL			"sha512crypt-opencl"
#define ALGORITHM_NAME			"SHA512 OpenCL"
#define OCL_CONFIG			"sha512crypt"

//Checks for source code to pick (parameters, sizes, kernels to execute, etc.)
#define _USE_CPU_SOURCE			(cpu(source_in_use))
#define _USE_GPU_SOURCE			(gpu(source_in_use))
#define _SPLIT_KERNEL_IN_USE		(gpu(source_in_use))

static sha512_salt			* salt;
static sha512_password	 		* plaintext;			// plaintext ciphertexts
static sha512_hash			* calculated_hash;		// calculated hashes

static cl_mem salt_buffer;		//Salt information.
static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem hash_buffer;		//Hash keys (output).
static cl_mem work_buffer, tmp_buffer;	//Temporary buffers
static cl_mem pinned_saved_keys, pinned_partial_hashes;
static struct fmt_main *self;

static cl_kernel prepare_kernel, final_kernel;

static int new_keys, source_in_use;
static int split_events[3] = { 1, 5, 6 };

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	if (_SPLIT_KERNEL_IN_USE) {
		s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, prepare_kernel));
		s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
	}
	return s;

}

static size_t get_task_max_size(){

	return 0;
}

static size_t get_default_workgroup(){

    	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 0;
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main * self)
{
	pinned_saved_keys = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(sha512_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	plaintext = (sha512_password *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_keys, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(sha512_password) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id],
			CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(sha512_hash) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (sha512_hash *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
			sizeof(sha512_hash) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

	// create arguments (buffers)
	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha512_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(sha512_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
			sizeof(sha512_hash) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	tmp_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
			sizeof(buffer_64) * 8 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area 1");

	if (! amd_gcn(source_in_use)) {
		work_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
			sizeof(uint64_t) * (9 * 8) * gws, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area 2");
	} else {
		work_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
		    sizeof(sha512_buffers) * gws, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area");
	}

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
			(void *) &salt_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 2");

	if (_SPLIT_KERNEL_IN_USE) {

		if (! amd_gcn(source_in_use)) {
			//Set prepare kernel arguments
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 0, sizeof(cl_mem),
				(void *) &salt_buffer), "Error setting argument 0");
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem),
				(void *) &pass_buffer), "Error setting argument 1");
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem),
				(void *) &tmp_buffer), "Error setting argument 2");
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 3, sizeof(cl_mem),
				(void *) &work_buffer), "Error setting argument 3");

			//Set crypt kernel arguments
			HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
				(void *) &tmp_buffer), "Error setting argument crypt_kernel (3)");
			HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem),
				(void *) &work_buffer), "Error setting argument crypt_kernel (4)");

			//Set final kernel arguments
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(cl_mem),
				(void *) &salt_buffer), "Error setting argument 0");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(cl_mem),
				(void *) &pass_buffer), "Error setting argument 1");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(cl_mem),
				(void *) &hash_buffer), "Error setting argument 2");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_mem),
				(void *) &tmp_buffer), "Error setting argument 3");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 4, sizeof(cl_mem),
				(void *) &work_buffer), "Error setting argument crypt_kernel (4)");
		} else {
			//Set prepare kernel arguments
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 0, sizeof(cl_mem),
				(void *) &salt_buffer), "Error setting argument 0");
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem),
				(void *) &pass_buffer), "Error setting argument 1");
			HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem),
				(void *) &work_buffer), "Error setting argument 2");

			//Set crypt kernel arguments
			HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem),
				(void *) &work_buffer), "Error setting argument crypt_kernel (3)");

			//Set final kernel arguments
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(cl_mem),
					(void *) &salt_buffer), "Error setting argument 0");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(cl_mem),
					(void *) &pass_buffer), "Error setting argument 1");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(cl_mem),
					(void *) &hash_buffer), "Error setting argument 2");
			HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_mem),
					(void *) &work_buffer), "Error setting argument 3");
		}
	}
	memset(plaintext, '\0', sizeof(sha512_password) * gws);
}

static void release_clobj(void) {
	cl_int ret_code;

	if (work_buffer) {
		ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
		                                   calculated_hash, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Error Unmapping out_hashes");

		ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
		                                   plaintext, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Error Unmapping saved_plain");
		HANDLE_CLERROR(clFinish(queue[gpu_id]),
		               "Error releasing memory mappings");

		ret_code = clReleaseMemObject(salt_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing data_info");
		ret_code = clReleaseMemObject(pass_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
		ret_code = clReleaseMemObject(hash_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");
		ret_code = clReleaseMemObject(tmp_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing tmp_buffer");
		ret_code = clReleaseMemObject(work_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing work_out");

		ret_code = clReleaseMemObject(pinned_saved_keys);
		HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");

		ret_code = clReleaseMemObject(pinned_partial_hashes);
		HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");

		work_buffer = NULL;
	}
}

/* ------- Salt functions ------- */
static void * get_salt(char *ciphertext) {
	static sha512_salt out;
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
	out.final = out.rounds % HASH_LOOPS;

	return &out;
}

static void set_salt(void * salt_info) {

	salt = salt_info;

	//Send salt information to GPU.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0,
		sizeof(sha512_salt), salt, 0, NULL, NULL),
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
	char *custom_opts;
	int major, minor;

	if (!(custom_opts = getenv(OCL_CONFIG "_BuildOpts")))
		custom_opts = cfg_get_param(SECTION_OPTIONS,
		                            SUBSECTION_OPENCL,
		                            OCL_CONFIG "_BuildOpts");

	opencl_build_kernel(task, gpu_id, custom_opts, 1);
	opencl_driver_value(gpu_id, &major, &minor);

	if (major == 1311 && minor == 2) {
		fprintf(stderr,
			"The OpenCL driver in use cannot run this kernel. Please, update your driver!\n");
		error();
	}

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

static void init(struct fmt_main *_self) {
	char * tmp_value;
	char * task = "$JOHN/kernels/cryptsha512_kernel_DEFAULT.cl";

	self = _self;

	opencl_prepare_dev(gpu_id);
	source_in_use = device_info[gpu_id];

	if ((tmp_value = getenv("_TYPE")))
		source_in_use = atoi(tmp_value);

	if (amd_gcn(source_in_use))
		task = "$JOHN/kernels/cryptsha512_kernel_GCN.cl";
	else if (_USE_GPU_SOURCE)
		task = "$JOHN/kernels/cryptsha512_kernel_GPU.cl";

	build_kernel(task);

	if (source_in_use != device_info[gpu_id])
		fprintf(stderr, "Selected runtime id %d, source (%s)\n",
		        source_in_use, task);
}

static void reset(struct db_main *db)
{
	if (!db) {
		int default_value = 0;

		if (gpu_amd(source_in_use))
			default_value = get_processors_count(gpu_id);
		else if (gpu_intel(source_in_use))
			default_value = 1024;
		else
			default_value = autotune_get_task_max_size(
				1, KEYS_PER_CORE_CPU, KEYS_PER_CORE_GPU,
				crypt_kernel);

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(default_value, HASH_LOOPS,
		                       ((_SPLIT_KERNEL_IN_USE) ?
		                        split_events : NULL),
		                       warn, 1, self, create_clobj,
		                       release_clobj,
		                       sizeof(uint64_t) * 9 * 8 , 0);

		//Auto tune execution from shared/included code.
		self->methods.crypt_all = crypt_all_benchmark;
		autotune_run(self, ROUNDS_DEFAULT, 0,
		             (cpu(device_info[gpu_id]) ?
		              2000000000ULL : 7000000000ULL));
		self->methods.crypt_all = crypt_all;
		memset(plaintext, '\0', sizeof(sha512_password) * global_work_size);
	}
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
	uint64_t b = ((uint64_t *) binary)[0];

	for (i = 0; i < count; i++)
		if (b == calculated_hash[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void * binary, int index)
{
	return !memcmp(binary, (void *) &calculated_hash[index], BINARY_SIZE);
}

static int cmp_exact(char * source, int count) {
	return 1;
}

/* ------- Crypt function ------- */
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt) {
	int count = *pcount;
	int i;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
			sizeof(sha512_password) * gws, plaintext, 0, NULL, multi_profilingEvent[0]),
			"failed in clEnqueueWriteBuffer pass_buffer");

	//Enqueue the kernel
	if (_SPLIT_KERNEL_IN_USE) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[3]),
			"failed in clEnqueueNDRangeKernel I");

		for (i = 0; i < 3; i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
				&gws, lws, 0, NULL,
				multi_profilingEvent[split_events[i]]),  //1, 5, 6
				"failed in clEnqueueNDRangeKernel");
		}
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[4]),
			"failed in clEnqueueNDRangeKernel II");
	} else
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(sha512_hash) * gws, calculated_hash, 0, NULL, multi_profilingEvent[2]),
			"failed in reading data back");

	//Do the work
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

	return count;
}

static int crypt_all(int *pcount, struct db_salt *_salt)
{
	const int count = *pcount;
	int i;
	size_t gws;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	//Send data to device.
	if (new_keys)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE, 0,
			sizeof(sha512_password) * gws, plaintext, 0, NULL, NULL),
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
			sizeof(sha512_hash) * gws, calculated_hash, 0, NULL, NULL),
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
	sha512_salt *sha512crypt_salt;
	sha512crypt_salt = salt;
	return (unsigned int)sha512crypt_salt->rounds;
}
#endif

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_cryptsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			iteration_count,
		},
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
		NULL,
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
