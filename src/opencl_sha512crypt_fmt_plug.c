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

#include "opencl_common.h"
#include "config.h"
#include "options.h"
#include "../run/opencl/opencl_sha512crypt.h"
#define __CRYPTSHA512_CREATE_PROPER_TESTS_ARRAY__
#include "sha512crypt_common.h"

#define FORMAT_LABEL            "sha512crypt-opencl"
#define ALGORITHM_NAME          "SHA512 OpenCL"
#define OCL_CONFIG              "sha512crypt"

//Checks for source code to pick (parameters, sizes, kernels to execute, etc.)
#define _USE_CPU_SOURCE         (cpu(source_in_use))
#define _USE_GPU_SOURCE         (gpu(source_in_use))
#define _SPLIT_KERNEL_IN_USE    (gpu(source_in_use))

static sha512_salt *salt;
static sha512_password *plaintext;  // plaintext ciphertexts
static sha512_password *plain_sorted;   // sorted list (by plaintext len)
static sha512_hash *calculated_hash;    // calculated hashes
static sha512_hash *computed_hash;  // calculated hashes (from plain_sorted)

//To connect the sorted and unsorted plaintext lists
static unsigned int *indices;
static size_t indices_size;
static uint32_t bitmap_of_lens; // what plaintext sizes do we have?

static cl_mem salt_buffer;      //Salt information.
static cl_mem pass_buffer;      //Plaintext buffer.
static cl_mem hash_buffer;      //Hash keys (output).
static cl_mem work_buffer, tmp_buffer;  //Temporary buffers
static cl_mem pinned_saved_keys, pinned_partial_hashes;
static struct fmt_main *self;

static cl_kernel prepare_kernel, preproc_kernel, final_kernel;
static cl_kernel crypt_full_kernel, crypt_fast_kernel;

static int new_keys, source_in_use;
static int split_events[3] = { 1, 6, 7 };

//This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl_autotune.h"

static void release_kernel();

#if (PLAINTEXT_LENGTH > 31) //Can't use sizeof(uint32_t)
#error "Review bitmap_of_lens size"
#endif

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	if (_SPLIT_KERNEL_IN_USE) {
		s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0,
		        prepare_kernel));
		s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0,
		        preproc_kernel));
		s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0,
		        final_kernel));
	}
	return s;

}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	pinned_saved_keys = clCreateBuffer(context[gpu_id],
	                                   CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
	                                   sizeof(sha512_password) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
	               "Error creating page-locked memory pinned_saved_keys");

	plaintext = (sha512_password *) mem_alloc(sizeof(sha512_password) * gws);

	plain_sorted = (sha512_password *) clEnqueueMapBuffer(queue[gpu_id],
	               pinned_saved_keys, CL_TRUE, CL_MAP_WRITE, 0,
	               sizeof(sha512_password) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id],
	                                       CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
	                                       sizeof(sha512_hash) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
	               "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (sha512_hash *) mem_alloc(sizeof(sha512_hash) * gws);

	computed_hash = (sha512_hash *) clEnqueueMapBuffer(queue[gpu_id],
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
	                            sizeof(sha512_buffers) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area 1");
	work_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
	                             sizeof(uint64_t) * (9 * 8) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument work_area 2");

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_full_kernel, 0, sizeof(cl_mem),
	                              (void *)&salt_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_fast_kernel, 0, sizeof(cl_mem),
	                              (void *)&salt_buffer), "Error setting argument 0");

	if (!(_SPLIT_KERNEL_IN_USE)) {
		HANDLE_CLERROR(clSetKernelArg(crypt_full_kernel, 1, sizeof(cl_mem),
		                              (void *)&pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(crypt_full_kernel, 2, sizeof(cl_mem),
		                              (void *)&hash_buffer), "Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(crypt_fast_kernel, 1, sizeof(cl_mem),
		                              (void *)&pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(crypt_fast_kernel, 2, sizeof(cl_mem),
		                              (void *)&hash_buffer), "Error setting argument 2");

	} else {
		//Set prepare kernel arguments
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 0, sizeof(cl_mem),
		                              (void *)&salt_buffer), "Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 1, sizeof(cl_mem),
		                              (void *)&pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 2, sizeof(cl_mem),
		                              (void *)&tmp_buffer), "Error setting argument 2");

		//Set preprocess kernel arguments
		HANDLE_CLERROR(clSetKernelArg(preproc_kernel, 0, sizeof(cl_mem),
		                              (void *)&salt_buffer), "Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(preproc_kernel, 1, sizeof(cl_mem),
		                              (void *)&pass_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(preproc_kernel, 2, sizeof(cl_mem),
		                              (void *)&tmp_buffer), "Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(preproc_kernel, 3, sizeof(cl_mem),
		                              (void *)&work_buffer), "Error setting argument 3");

		//Set crypt kernel arguments
		HANDLE_CLERROR(clSetKernelArg(crypt_full_kernel, 1, sizeof(cl_mem),
		                              (void *)&hash_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(crypt_full_kernel, 2, sizeof(cl_mem),
		                              (void *)&tmp_buffer), "Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(crypt_full_kernel, 3, sizeof(cl_mem),
		                              (void *)&work_buffer), "Error setting argument 3");
		HANDLE_CLERROR(clSetKernelArg(crypt_fast_kernel, 1, sizeof(cl_mem),
		                              (void *)&hash_buffer), "Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(crypt_fast_kernel, 2, sizeof(cl_mem),
		                              (void *)&tmp_buffer), "Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(crypt_fast_kernel, 3, sizeof(cl_mem),
		                              (void *)&work_buffer), "Error setting argument 3");

		//Set final kernel arguments
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(cl_mem),
		                              (void *)&salt_buffer), "Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(cl_mem),
		                              (void *)&hash_buffer), "Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(cl_mem),
		                              (void *)&tmp_buffer), "Error setting argument 3");
		HANDLE_CLERROR(clSetKernelArg(final_kernel, 3, sizeof(cl_mem),
		                              (void *)&work_buffer), "Error setting argument 3");
	}
	memset(plaintext, '\0', sizeof(sha512_password) * gws);
	memset(plain_sorted, '\0', sizeof(sha512_password) * gws);
}

static void release_clobj(void)
{
	cl_int ret_code;

	if (work_buffer) {
		ret_code =
		    clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
		                            computed_hash, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Error Unmapping out_hashes");

		ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
		                                   plain_sorted, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Error Unmapping saved_plain");

		MEM_FREE(plaintext);
		MEM_FREE(calculated_hash);

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
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory");
	}
}

/* ------- Salt functions ------- */
static void *get_salt(char *ciphertext)
{
	static sha512_salt out;
	int len;

	out.rounds = ROUNDS_DEFAULT;
	ciphertext += FORMAT_TAG_LEN;
	if (!strncmp(ciphertext, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			ciphertext = endp + 1;
			srounds = srounds < ROUNDS_MIN ? ROUNDS_MIN : srounds;
			out.rounds = srounds > ROUNDS_MAX ? ROUNDS_MAX : srounds;
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

static void set_salt(void *salt_info)
{

	salt = salt_info;

	//Send salt information to GPU.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE,
	                                    0, sizeof(sha512_salt), salt, 0, NULL, NULL),
	               "failed in clEnqueueWriteBuffer salt_buffer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static int salt_hash(void *salt)
{

	return common_salt_hash(salt, SALT_SIZE, SALT_HASH_SIZE);
}

/* ------- Key functions ------- */
static void clear_keys(void)
{
	crypt_kernel = crypt_fast_kernel;

	/* When a new group of keys begins to be sent to the OpenCL device
	 * clear the information about previously sent keys data.
	 */
	bitmap_of_lens = 0;
}

static void set_key(char *key, int index)
{
	unsigned int len = strnlen(key, PLAINTEXT_LENGTH);

	strncpy((char *)plaintext[index].pass, key, PLAINTEXT_LENGTH); /* NUL padding is required */
	plaintext[index].length = len;

	new_keys = 1;
	bitmap_of_lens |= (1 << len);

	if (len > 15)
		crypt_kernel = crypt_full_kernel;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];

	memcpy(ret, plaintext[index].pass, PLAINTEXT_LENGTH);
	ret[plaintext[index].length] = '\0';
	return ret;
}

/* ------- Initialization  ------- */
static void build_kernel(const char *task, const char *custom_opts)
{
	int major, minor;

	release_kernel();

	if (!strlen(custom_opts)) {
		char opt[MAX_OCLINFO_STRING_LEN];
		int i;

		snprintf(opt, sizeof(opt), "%s_%s", OCL_CONFIG, get_device_name_(gpu_id));

		//Remove spaces.
		for (i = 0; opt[i]; i++)
			if (opt[i] == ' ')
				opt[i] = '_';

		if (!(custom_opts = getenv(opt)))
			custom_opts = cfg_get_param(SECTION_OPTIONS,
		                                    SUBSECTION_OPENCL, opt);

		if (!(custom_opts) && !(custom_opts = getenv(OCL_CONFIG "_BuildOpts")))
			custom_opts = cfg_get_param(SECTION_OPTIONS,
		                                    SUBSECTION_OPENCL, OCL_CONFIG "_BuildOpts");
	}
	opencl_build_kernel(task, gpu_id, custom_opts, 1);
	opencl_driver_value(gpu_id, &major, &minor);

	if (major == 1311 && minor == 2) {
		fprintf(stderr,
		        "The OpenCL driver in use cannot run this kernel. Please, update your driver!\n");
		error();
	}
	// create kernel(s) to execute
	crypt_full_kernel = clCreateKernel(program[gpu_id], "kernel_crypt_full", &ret_code);
	HANDLE_CLERROR(ret_code,
	               "Error creating kernel. Double-check kernel name?");
	crypt_fast_kernel = clCreateKernel(program[gpu_id], "kernel_crypt_fast", &ret_code);
	HANDLE_CLERROR(ret_code,
	               "Error creating kernel. Double-check kernel name?");
	crypt_kernel = crypt_fast_kernel;

	if (_SPLIT_KERNEL_IN_USE) {
		prepare_kernel =
		    clCreateKernel(program[gpu_id], "kernel_prepare", &ret_code);
		HANDLE_CLERROR(ret_code,
		               "Error creating kernel_prepare. Double-check kernel name?");
		final_kernel =
		    clCreateKernel(program[gpu_id], "kernel_final", &ret_code);
		HANDLE_CLERROR(ret_code,
		               "Error creating kernel_final. Double-check kernel name?");
		preproc_kernel =
		    clCreateKernel(program[gpu_id], "kernel_preprocess",
			                   &ret_code);
		HANDLE_CLERROR(ret_code,
		               "Error creating kernel_preprocess. Double-check kernel name?");
	}
}

static void release_kernel()
{
	if (program[gpu_id]) {
		HANDLE_CLERROR(clReleaseKernel(crypt_full_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_fast_kernel), "Release kernel");

		if (_SPLIT_KERNEL_IN_USE) {
			HANDLE_CLERROR(clReleaseKernel(prepare_kernel), "Release kernel");
			HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
			HANDLE_CLERROR(clReleaseKernel(preproc_kernel), "Release kernel");
		}
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static int calibrate()
{
	char opt[MAX_OCLINFO_STRING_LEN];
	char *task = "$JOHN/opencl/cryptsha512_kernel_GPU.cl";
	int i, j, k, l, kernel_opt, best_opt = 0;
	unsigned long long best_speed = 0;
	size_t best_lws = 0, best_gws = 0;
	int loop_set[][5] = {
		{1, 2, 3, -1, 0},   //Fist loop inside block()
		{9, 10, 11, 0, 0},  //Second loop inside block()
		{17, 18, 19, 0, 0}, //Main loop inside kernel crypt()
		{1, 1, 0, 0, 0},    //Use vector operations.
		{0, 0, 0, 0, 0}
	};

	fprintf(stderr, "\nCalibration is trying to figure out the best "
		        "configuration to use at runtime. Please, wait...\n");

	i = j = k = l = 0;
	while (loop_set[0][i]) {

		if (loop_set[0][i] > 0) {
			kernel_opt = (1 << loop_set[0][i]);
			kernel_opt += (1 << loop_set[1][j]);
			kernel_opt += (1 << loop_set[2][k]);
			kernel_opt += ((l & 1) << 25); // vector operations
		} else {
			i++;
			kernel_opt = 0;
		}
		snprintf(opt, sizeof(opt), "-DUNROLL_LOOP=%i", kernel_opt);

		//Build the tuned kernel
		build_kernel(task, opt);
		local_work_size = 0; global_work_size = 0;
		autotune_run(self, ROUNDS_DEFAULT, 0, 200);
		release_clobj();
		release_kernel();

#ifdef OCL_DEBUG
		fprintf(stderr, "Configuration is LWS="Zu" GWS="Zu", UNROLL_LOOP=%i, "
	                "c/s: %llu\n", local_work_size, global_work_size,
			kernel_opt, global_speed);
#endif
		if (global_speed > (1.01 * best_speed)) {
			best_speed = global_speed;
			best_lws = local_work_size;
			best_gws = global_work_size;
			best_opt = kernel_opt;

			if (options.verbosity > VERB_LEGACY)
				fprintf(stderr, "- Good configuration found: LWS="Zu" GWS="Zu", "
				                "UNROLL_LOOP=%i, c/s: %llu\n", local_work_size,
				                global_work_size, kernel_opt, global_speed);
		}
		l++;

		if (!loop_set[3][l]) {
		    l = 0; k++;
		}

		if (!loop_set[2][k]) {
		    k = 0; j++;
		}

		if (!loop_set[1][j]) {
		    j = 0; i++;
		}
	}
	//Keep discoverd values.
	snprintf(opt, sizeof(opt), ""Zu"", best_gws);
	setenv("GWS", opt, 1);
	snprintf(opt, sizeof(opt), ""Zu"", best_lws);
	setenv("LWS", opt, 1);

	fprintf(stderr, "The best configuration is: LWS="Zu" GWS="Zu", UNROLL_LOOP=%i, "
	                "c/s: %llu\n", best_lws, best_gws, best_opt, best_speed);

	return best_opt;
}

static void reset(struct db_main *db)
{
	char *tmp_value;
	char *task = "$JOHN/opencl/cryptsha512_kernel_GPU.cl";
	char opt[24] = "";

	int major, minor;

	new_keys = 0;
	bitmap_of_lens = 0;

	source_in_use = device_info[gpu_id];

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS,
	                       ((_SPLIT_KERNEL_IN_USE) ? split_events : NULL),
	                        warn, 1, self, create_clobj,
	                        release_clobj, sizeof(uint64_t) * 9 * 8, 0, db);

	//Calibrate or a regular run.
	if ((tmp_value = getenv("_CALIBRATE"))) {
		int kernel_opt;

		kernel_opt = calibrate();
		snprintf(opt, sizeof(opt), "-DUNROLL_LOOP=%i", kernel_opt);

	} else {
		if ((tmp_value = getenv("_TYPE")))
			source_in_use = atoi(tmp_value);

		opencl_driver_value(gpu_id, &major, &minor);

		if (!(_USE_GPU_SOURCE))
			task = "$JOHN/opencl/cryptsha512_kernel_DEFAULT.cl";

		if (source_in_use != device_info[gpu_id])
			fprintf(stderr, "Selected runtime id %d, source (%s)\n",
				source_in_use, task);
	}
	build_kernel(task, opt);

	//Auto tune execution from shared/included code.
	autotune_run(self, ROUNDS_DEFAULT, 0, 200);

	//Clear work buffers.
	memset(plaintext, '\0', sizeof(sha512_password) * global_work_size);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		release_kernel();
		MEM_FREE(indices);
		indices_size = 0;
	}
}

/* ------- Compare functins ------- */
static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint64_t b = ((uint64_t *) binary)[0];

	for (i = 0; i < count; i++)
		if (b == calculated_hash[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, (void *)&calculated_hash[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

/* ------- Crypt function ------- */
static int crypt_all(int *pcount, struct db_salt *_salt)
{
	int count = *pcount;
	int index;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	sha512_password *input_candidates;
	sha512_hash *output_hashes;

	gws = GET_NEXT_MULTIPLE(count, local_work_size);

	if (bitmap_of_lens & (bitmap_of_lens - 1)) {
		input_candidates = plain_sorted;
		output_hashes = computed_hash;
	} else {
		input_candidates = plaintext;
		output_hashes = calculated_hash;
	}

	if (new_keys) {
		// sort passwords by length
		if (bitmap_of_lens & (bitmap_of_lens - 1)) {
			if (count > indices_size) {
				MEM_FREE(indices);
				indices = mem_alloc(count * sizeof(*indices));
				indices_size = count;
			}

			unsigned int new_index = 0, len;
			for (len = 0; bitmap_of_lens >> len; len++)
				if ((bitmap_of_lens >> len) & 1)
					for (index = 0; index < count; index++)
						if (plaintext[index].length == len)
							indices[new_index++] = index;

			while (new_index < count) /* at least self-test may have skipped some indices */
				indices[new_index++] = 0;

			//Create a sorted by length candidates list.
			for (index = 0; index < count; index++) {
				memcpy(plain_sorted[index].pass, plaintext[indices[index]].pass, PLAINTEXT_LENGTH);
				plain_sorted[index].length = plaintext[indices[index]].length;
			}

			while (index < gws) /* in case GWS got rounded up to multiple of LWS */
				plain_sorted[index++].length = 0;
		}

		//Transfer plaintext buffer to device.
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer,
		                                   CL_FALSE, 0, sizeof(sha512_password) * gws, input_candidates, 0,
		                                   NULL, multi_profilingEvent[0]),
		              "failed in clEnqueueWriteBuffer pass_buffer");
		WAIT_INIT(gws)
		HANDLE_CLERROR(clFlush(queue[gpu_id]), "Error running clFlush");
		WAIT_SLEEP
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running clFinish");
		WAIT_UPDATE
		WAIT_DONE
	}

	//Enqueue the kernel
	if (_SPLIT_KERNEL_IN_USE) {
		WAIT_INIT(gws)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1,
		                                     NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]),
		              "failed in clEnqueueNDRangeKernel I");

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], preproc_kernel, 1,
		                                     NULL, &gws, lws, 0, NULL, multi_profilingEvent[4]),
		              "failed in clEnqueueNDRangeKernel II");
		WAIT_SLEEP
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running prep kernels");
		WAIT_UPDATE
		WAIT_DONE

		unsigned int i, iterations;
		iterations = ocl_autotune_running ? 3 : (salt->rounds / HASH_LOOPS);

		WAIT_INIT(gws)
		for (i = 0; i < iterations; i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			                                     &gws, lws, 0, NULL, (ocl_autotune_running ?
			                                             multi_profilingEvent[split_events[i]] : NULL)),  //1, 5, 6
			              "failed in clEnqueueNDRangeKernel");

			WAIT_SLEEP
			HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			WAIT_UPDATE
			opencl_process_event();
		}
		WAIT_DONE

		WAIT_INIT(gws)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1,
		                                     NULL, &gws, lws, 0, NULL, multi_profilingEvent[5]),
		              "failed in clEnqueueNDRangeKernel III");
		WAIT_SLEEP
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running final kernel");
		WAIT_UPDATE
		WAIT_DONE
	} else {
		WAIT_INIT(gws)
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		                                     NULL, &gws, lws, 0, NULL, multi_profilingEvent[1]),
		              "failed in clEnqueueNDRangeKernel");
		WAIT_SLEEP
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error running crypt kernel");
		WAIT_UPDATE
		WAIT_DONE
	}

	//Read back hashes
	WAIT_INIT(gws)
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
	                                  sizeof(sha512_hash) * gws, output_hashes, 0, NULL,
	                                  multi_profilingEvent[2]), "failed in reading data back");

	//Do the work
	BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	WAIT_UPDATE
	WAIT_DONE

	if (bitmap_of_lens & (bitmap_of_lens - 1))
		//Build calculated hash list according to original plaintext list order.
		for (index = 0; index < count; index++)
			memcpy(calculated_hash[indices[index]].v, computed_hash[index].v,
			    BINARY_SIZE);

	new_keys = 0;

	return count;
}

/* ------- Binary Hash functions group ------- */
static int get_hash_0(int index)
{
	return calculated_hash[index].v[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return calculated_hash[index].v[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return calculated_hash[index].v[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return calculated_hash[index].v[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return calculated_hash[index].v[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return calculated_hash[index].v[0] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return calculated_hash[index].v[0] & PH_MASK_6;
}

static unsigned int iteration_count(void *salt)
{
	sha512_salt *sha512crypt_salt;

	sha512crypt_salt = salt;
	return (unsigned int)sha512crypt_salt->rounds;
}

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
		{ FORMAT_TAG },
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

#endif                          /* plugin stanza */

#endif                          /* HAVE_OPENCL */
