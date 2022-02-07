/*
 * JtR OpenCL format to crack Telegram Desktop passcodes.
 *
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * The OpenCL boilerplate code is borrowed from other OpenCL formats.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_OPENCL

#include "arch.h"

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_telegram;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_telegram);
#else

#include <string.h>
#include <stdint.h>

#include "formats.h"
#include "common.h"
#include "telegram_common.h"
#include "options.h"
#include "jumbo.h"
#include "opencl_common.h"
#include "misc.h"
#define MAX_OUTLEN (136)
#include "../run/opencl/opencl_pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL            "telegram-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define PLAINTEXT_LENGTH        64
#define SALT_SIZE               sizeof(*cur_salt)
#define SALT_ALIGN              MEM_ALIGN_WORD

static struct fmt_tests tests[] = {
	// Telegram Desktop 1.3.9 on Ubuntu 18.04 LTS
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*d6fb7ebda06a23a9c42fc57c39e2c3128da4ee1ff394f17c2fc4290229e13d1c9e45c42ef1aee64903e5904c28cffd49498358fee96eb01888f2251715b7a5e71fa130918f46da5a2117e742ad7727700e924411138bb8d4359662da0ebd4f4357d96d1aa62955e44d4acf2e2ac6e0ce057f48fe24209090fd35eeac8a905aca649cafb2aade1ef7a96a7ab44a22bd7961e79a9291b7fea8749dd415f2fcd73d0293cdb533554f396625f669315c2400ebf6f1f30e08063e88b59b2d5832a197b165cdc6b0dc9d5bfa6d5e278a79fa101e10a98c6662cc3d623aa64daada76f340a657c2cbaddfa46e35c60ecb49e8f1f57bc170b8064b70aa2b22bb326915a8121922e06e7839e62075ee045b8c82751defcba0e8fb75c32f8bbbdb8b673258", "openwall123"},
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*7c04a5becb2564fe4400c124f5bb5f1896117327d8a21f610bd431171f606fa6e064c088aacc59d8eae4e6dce539abdba5ea552f5855412c26284bc851465d6b31949b276f4890fc212d63d73e2ba132d6098688f2a6408b9d9d69c3db4bcd13dcc3a5f80a7926bb11eb2c99c7f02b5d9fd1ced974d18ed9d667deae4be8df6a4a97ed8fae1da90d5131a7536535a9bfa8094ca7f7465deabef00ab4c715f151d016a879197b328c74dfad5b1f854217c741cf3e0297c63c3fb4d5d672d1e31d797b2c01cb8a254f80a37b6c9a011d864c21c4145091f22839a52b6daf23ed2f350f1deb275f1b0b4146285ada0f0b168ce54234854b19ec6657ad0a92ffb0f3b86547c8b8cc3655a29797c398721e740ed606a71018d16545c78ee240ff3635", "öye"},
	{NULL}
};

typedef struct {
	unsigned int cracked;
} telegram_out;

typedef struct {
	pbkdf2_salt pbkdf2;
	uint32_t encrypted_blob_length;
	unsigned char encrypted_blob[ENCRYPTED_BLOB_LEN];
} telegram_salt;


/* This handles all widths */
#define GETPOS(i, index)        (((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static struct custom_salt *cur_salt;
static size_t key_buf_size;
static unsigned int *inbuffer;
static telegram_out *output;
static telegram_salt currentsalt;
static cl_mem mem_in, mem_dk, mem_salt, mem_state, mem_out;
static size_t key_buf_size;
static int new_keys;
static struct fmt_main *self;

static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final, telegram_final;

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS              4000
#define ITERATIONS              10000 /* Just for auto tune */
#define LOOP_COUNT              (((currentsalt.pbkdf2.iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define STEP                    0
#define SEED                    128

static const char * warn[] = {
	"P xfer: ",  ", init: ", ", loop: ", ", pbkdf2: ", ", telegram: ", ", res xfer: "
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
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_final));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, telegram_final));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	gws *= ocl_v_width;

	key_buf_size = 64 * gws;

	// Allocate memory
	inbuffer = mem_calloc(1, key_buf_size);
	output = mem_alloc(sizeof(telegram_out) * gws);

	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(telegram_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");
	mem_dk = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem dk");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(telegram_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 1, sizeof(mem_dk), &mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(telegram_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(telegram_final, 1, sizeof(mem_dk), &mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(telegram_final, 2, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (output) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_dk), "Release mem dk");
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
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(telegram_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	static char valgo[sizeof(ALGORITHM_NAME) + 12] = "";

	self = _self;

	opencl_prepare_dev(gpu_id);
	/* VLIW5 does better with just 2x vectors due to GPR pressure */
	if (!options.v_width && amd_vliw5(device_info[gpu_id]))
		ocl_v_width = 2;
	else
		ocl_v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	if (ocl_v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DMAX_OUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u -DENCRYPTED_BLOB_LEN=%d",
		         HASH_LOOPS, MAX_OUTLEN, PLAINTEXT_LENGTH, ocl_v_width, ENCRYPTED_BLOB_LEN);
		opencl_init("$JOHN/opencl/telegram_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		telegram_final = clCreateKernel(program[gpu_id], "telegram_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	// Initialize OpenCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
	                       warn, 2, self, create_clobj,
	                       release_clobj,
	                       ocl_v_width * sizeof(pbkdf2_state), 0, db);

	// Auto tune execution from shared/included code, max 200ms duration.
	autotune_run(self, 2 * (ITERATIONS - 1) + 4, 0, 200);
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p); /* must be 1 for now; 2 is rejected in valid() */
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.salt_length = strlen(p) / 2;
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.encrypted_blob_length = strlen(p) / 2;
	for (i = 0; i < cs.encrypted_blob_length; i++)
		cs.encrypted_blob[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt*)salt;
	memcpy(currentsalt.pbkdf2.salt, cur_salt->salt, cur_salt->salt_length);
	memcpy(currentsalt.encrypted_blob, cur_salt->encrypted_blob,
	       cur_salt->encrypted_blob_length);
	currentsalt.pbkdf2.length = cur_salt->salt_length;
	currentsalt.pbkdf2.iterations = cur_salt->iterations;
	currentsalt.pbkdf2.outlen = MAX_OUTLEN;
	currentsalt.encrypted_blob_length = cur_salt->encrypted_blob_length;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(telegram_salt), &currentsalt, 0, NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static void clear_keys(void)
{
	memset(inbuffer, 0, key_buf_size);
}

static void telegram_set_key(char *key, int index)
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
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_KPC_MULTIPLE(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (j = 0; j < (ocl_autotune_running ? 1 : (currentsalt.pbkdf2.outlen + 19) / 20); j++) {
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");
	}
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], telegram_final, 1, NULL, &scalar_gws, lws, 0, NULL, multi_profilingEvent[4]), "Run Telegram kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(telegram_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[5]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++) {
		if (output[index].cracked)
			return 1;
	}

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return output[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_telegram = {
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
		telegram_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			telegram_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		telegram_set_key,
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
