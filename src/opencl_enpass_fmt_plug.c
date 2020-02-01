/*
 * JtR OpenCL format to crack Enpass Password Manager databases
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * The OpenCL boilerplate code is borrowed from other OpenCL formats.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_enpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_enpass);
#else

#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "enpass_common.h"
#include "options.h"
#include "jumbo.h"
#include "opencl_common.h"
#include "misc.h"
#define OUTLEN                  32
#define PLAINTEXT_LENGTH        28
#include "../run/opencl/opencl_pbkdf2_hmac_sha256.h"

#define FORMAT_LABEL            "enpass-opencl"
#define OCL_ALGORITHM_NAME      "PBKDF2-SHA512 AES OpenCL"
#define ALGORITHM_NAME          OCL_ALGORITHM_NAME
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               sizeof(*cur_salt)
#define SALT_ALIGN              MEM_ALIGN_WORD

/* This handles all widths */
#define GETPOS(i, index)        (((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static struct custom_salt *cur_salt;

static struct fmt_tests enpass_tests[] = {
	{"$enpass$1$100000$73a0f3720c04e61c26a4062e4066a31143a8dd07540518981106cf7b9ec8c9b62d91803f0319c916056727309f4ac9adc9177a3c5e9c6873635e2512af9481443cc85362b67af2a14e32bdd063bd815276669ec17d4d23e1cd8859024eaeac1de36138fabfd001335be3b98b4404259c40a5797bca8763fd72a0cb5ba8ad06ab94677eaa9b4c7d2753b52c2caba82207a0e2b0213ecad22c4249ce6c708d0163d988d0cb2569b975b07ad7d7b773967f05a8a9392526e0b465f4e60c3a8021b346390f654384b58dda041b90bd1e6e3843ad62073e02bab8eba7d8ef9e1dac338890666fca758d46f4a45291b65e360c739c576742d6a12c2ebf2f70886a241424f75c33025aae6ff00245056a622d4f16df7df944a6bbdea8823c5d3640d82c3c939e1668962033863d51accfb6dd02b443b2078e68aa5e9e5b4fe226c2ab670713e214530a4c1c73989760cf8ba08a87c20f0a03e9fbc22c8be718d4af14b1a729d7494aa067bf9a9cb42e578bef9fea60e332c2a18e9de54188a083b997ae70b1f4a88f7d2f5e201c33e138b0b79e33c3c099873ec02acfa9da57712ea6115ee553bad7ca4ee775eeb1319c95a02c687060b0b47bd8d004e6b8f6b5a7095dd210c108d9800be471acac750ad33d332138e0fecac173dcc6b1b1aa4fd55d374f22db4f59fde21dfc2de77a2db12a8f1681180428483b2ac134078faf056ad511a515e0824d40dfd63f602d3dabe2be33c3bc5d8408519dbba5478195eb23095b79d7bb705bd0868899e0a12d06cc2d052f5c01c71937082662f6209697a5e6908aeafba6465897fae1b9fbbe42fadc52a823ce2aa191375ad2b93462c84fb74a9eb02b9391a34a3a8ad2c83d646bffa641e78245568fca9f35a07dad31baa7814de590ac63ed4182034bf4ff68be4b428ce1ea679ad146d378cf5de1049b5abe542684cb49183281d68596059691ded3e65913c84c63d49000a927bb6af9d3e2577ee992c9c5a0f952a84e3006a283fd02907421edd90bd5da21386b533a68b933914e0a7b7fa27535008310e0d40d1d6911573cd1d1900d085c509854c415c244aa3a9a937ca29d3f809ec12fc677c1fb70762c4e0e0c463702bdad82e2a6b6bcd2d83c7710a9013497c0a639e5f379e668eea4f4222f9f0f2d00a1ce438c8305d7b04cdb2380f50ee7d774149762d8f40061b743bf9dc7f8411f766e75e9b1c6fba94a1cae6171c27821fcf9b4b9bd3278066aa900f111cdd97cbffe9fad3aa7b5096457677cc544091727d6dfd738e9e2669288182620e3e0d161a0f2f58336f14def91d826be5623970860f0e847d894701e130ccbc822c1c550a4ad6a3be48e905f2fe8d1e837d246f767b0c8454827228c82103a612f405bf7f867ac69a28f880f843e26054012f33273b36870b9b6a82353457cdce1f49301051219", "openwall"},
	{NULL}
};

typedef struct {
	unsigned int cracked;
	unsigned int key[((OUTLEN + 19) / 20) * 20 / sizeof(uint32_t)];
} enpass_out;

typedef struct {
	unsigned int  length;
	unsigned int  outlen;
	unsigned int  iterations;
	unsigned char salt[115];
	union {
		uint8_t  c[16];
		uint32_t w[16 / 4];
	} iv;
	unsigned char data[16];
} enpass_salt;

static size_t key_buf_size, outsize;
static unsigned int *inbuffer;
static enpass_out *output;
static enpass_salt currentsalt;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static size_t key_buf_size;
static int new_keys;
static struct fmt_main *self;

static cl_kernel pbkdf2_init, pbkdf2_state, pbkdf2_loop, enpass_final;

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS              (3 * 271)
#define ITERATIONS              100000 /* Just for auto tune */
#define LOOP_COUNT              (((currentsalt.iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define STEP                    0
#define SEED                    128

static const char * warn[] = {
	"P xfer: "  ,  ", init: "   , ", loop: " , ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, enpass_final));

	return s;
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	key_buf_size = 64 * gws;
	outsize = sizeof(enpass_out) * gws;

	// Allocate memory
	inbuffer = mem_calloc(1, key_buf_size);
	output = mem_alloc(outsize);

	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(enpass_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(enpass_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(enpass_final, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(enpass_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
}

static void release_clobj(void)
{
	if (output) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(output);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(enpass_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DOUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u",
		         HASH_LOOPS, OUTLEN, PLAINTEXT_LENGTH);
		opencl_init("$JOHN/opencl/enpass_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		enpass_final = clCreateKernel(program[gpu_id], "enpass_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 2*HASH_LOOPS, split_events,
	                       warn, 2, self, create_clobj,
	                       release_clobj,
	                       sizeof(pbkdf2_state), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 2 * (ITERATIONS - 1) + 4, 0, 200);
}

static void set_salt(void *salt)
{
	int size = page_sz - reserve_sz;

	cur_salt = (struct custom_salt*)salt;

	/* PBKDF2 */
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->salt_length);
	currentsalt.length = cur_salt->salt_length;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.outlen = 32; // AES 256-bit key only

	/* AES */
	memcpy(currentsalt.iv.c, &cur_salt->data[16 + size], 16);
	memcpy(currentsalt.data, &cur_salt->data[16], 16);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0,
		sizeof(enpass_salt), &currentsalt, 0, NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void clear_keys(void)
{
	memset(inbuffer, 0, key_buf_size);
}

static void enpass_set_key(char *key, int index)
{
	int i;
	int length = strlen(key);

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];

	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	int i = 0;

	while (i < PLAINTEXT_LENGTH &&
	       (ret[i] = ((char*)inbuffer)[GETPOS(i, index)]))
		i++;
	ret[i] = 0;

	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, j;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (ocl_autotune_running || new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (j = 0; j < (ocl_autotune_running ? 1 : (currentsalt.outlen + 19) / 20); j++) {
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], enpass_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");
	}

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, outsize, output, 0, NULL, multi_profilingEvent[4]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (output[i].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (output[index].cracked);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_enpass = {
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
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		enpass_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		enpass_common_valid,
		fmt_default_split,
		fmt_default_binary,
		enpass_common_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		enpass_set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
