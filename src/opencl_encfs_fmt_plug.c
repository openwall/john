/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for Keychain format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_encfs;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_encfs);
#else

#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include "common-opencl.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "stdint.h"
#include "encfs_common.h"
#include "options.h"
#include "misc.h"
#define OUTLEN (32 + 16)
#include "opencl_pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL		"encfs-opencl"
#define FORMAT_NAME		"EncFS"
#define OCL_ALGORITHM_NAME	"PBKDF2-SHA1 OpenCL"
#define CPU_ALGORITHM_NAME	" AES/Blowfish"
#define ALGORITHM_NAME		OCL_ALGORITHM_NAME CPU_ALGORITHM_NAME
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define BINARY_SIZE		0
#define PLAINTEXT_LENGTH	64
#define SALT_SIZE		sizeof(*cur_salt)
#define BINARY_ALIGN		MEM_ALIGN_WORD
#define SALT_ALIGN			MEM_ALIGN_WORD

/* This handles all widths */
#define GETPOS(i, index)	(((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static int *cracked;
static int any_cracked;

static const int KEY_CHECKSUM_BYTES = 4;

static encfs_common_custom_salt *cur_salt;

static struct fmt_tests tests[] = {
	{"$encfs$192*181474*0*20*f1c413d9a20f7fdbc068c5a41524137a6e3fb231*44*9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f", "openwall"},
	{"$encfs$128*181317*0*20*e9a6d328b4c75293d07b093e8ec9846d04e22798*36*b9e83adb462ac8904695a60de2f3e6d57018ccac2227251d3f8fc6a8dd0cd7178ce7dc3f", "Jupiter"},
	{"$encfs$256*714949*0*20*472a967d35760775baca6aefd1278f026c0e520b*52*ac3b7ee4f774b4db17336058186ab78d209504f8a58a4272b5ebb25e868a50eaf73bcbc5e3ffd50846071c882feebf87b5a231b6", "Valient Gough"},
	{"$encfs$256*120918*0*20*e6eb9a85ee1c348bc2b507b07680f4f220caa763*52*9f75473ade3887bca7a7bb113fbc518ffffba631326a19c1e7823b4564ae5c0d1e4c7e4aec66d16924fa4c341cd52903cc75eec4", "Alo3San1t@nats"},
	{NULL}
};

static size_t key_buf_size;
static unsigned int *inbuffer;
static pbkdf2_out *output;
static pbkdf2_salt currentsalt;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static size_t key_buf_size;
static int new_keys;
static struct fmt_main *self;

static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final;

#define cracked_size (sizeof(*cracked) * global_work_size * ocl_v_width)

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS		(3 * 251)
#define ITERATIONS		181474 /* Just for auto tune */
#define LOOP_COUNT		(((currentsalt.iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"P xfer: "  ,  ", init: "   , ", loop: " , ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_final));
	return s;
}

#if 0
struct fmt_main *me;
#endif

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= ocl_v_width;

	key_buf_size = 64 * gws;

	/// Allocate memory
	inbuffer = mem_calloc(1, key_buf_size);
	output = mem_alloc(sizeof(pbkdf2_out) * gws);
	cracked = mem_calloc(1, cracked_size);

	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(pbkdf2_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");
}

static void release_clobj(void)
{
	if (cracked) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem setting");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(output);
		MEM_FREE(cracked);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	static char valgo[sizeof(ALGORITHM_NAME) + 8] = "";

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
		         OCL_ALGORITHM_NAME " %ux" CPU_ALGORITHM_NAME, ocl_v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DOUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
		         HASH_LOOPS, OUTLEN, PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/kernels/pbkdf2_hmac_sha1_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 2*HASH_LOOPS, split_events,
		                       warn, 2, self, create_clobj,
		                       release_clobj,
		                       ocl_v_width * sizeof(pbkdf2_state), 0, db);

		//Auto tune execution from shared/included code.
		autotune_run(self, 2 * (ITERATIONS - 1) + 4, 0,
		             (cpu(device_info[gpu_id]) ?
		              1000000000 : 10000000000ULL));
	}
}

static void set_salt(void *salt)
{
	cur_salt = (encfs_common_custom_salt*)salt;
	memcpy((char*)currentsalt.salt, cur_salt->salt, cur_salt->saltLen);
	currentsalt.length = cur_salt->saltLen;
	currentsalt.iterations = cur_salt->iterations;
	currentsalt.outlen = cur_salt->keySize + cur_salt->ivLength;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(pbkdf2_salt), &currentsalt, 0, NULL, NULL), "Copy salt to gpu");
}

static void clear_keys(void) {
	memset(inbuffer, 0, key_buf_size);
}

static void set_key(char *key, int index)
{
	int i;
	int length = strlen(key);

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];

	new_keys = 1;
}

static char* get_key(int index)
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
	int i, j, index;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER_VW(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

	/// Copy data to gpu
	if (ocl_autotune_running || new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	/// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (j = 0; j < (ocl_autotune_running ? 1 : (currentsalt.outlen + 19) / 20); j++) {
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run intermediate kernel");
	}

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(pbkdf2_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[4]), "Copy result back");

	if (!ocl_autotune_running) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (index = 0; index < count; index++)
		{
			int i;
			unsigned char master[MAX_KEYLENGTH + MAX_IVLENGTH];
			unsigned char tmpBuf[cur_salt->dataLen];
			unsigned int checksum = 0;
			unsigned int checksum2 = 0;

			memcpy(master, output[index].dk, cur_salt->keySize + cur_salt->ivLength);

			// First N bytes are checksum bytes.
			for (i = 0; i < KEY_CHECKSUM_BYTES; ++i)
				checksum = (checksum << 8) | (unsigned int)cur_salt->data[i];
			memcpy(tmpBuf, cur_salt->data + KEY_CHECKSUM_BYTES, cur_salt->keySize + cur_salt->ivLength);
			encfs_common_streamDecode(cur_salt, tmpBuf, cur_salt->keySize + cur_salt->ivLength ,checksum, master);
			checksum2 = encfs_common_MAC_32(cur_salt, tmpBuf, cur_salt->keySize + cur_salt->ivLength, master);
			if (checksum2 == checksum)
			{
				cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_encfs = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"iteration count",
		},
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		encfs_common_valid,
		fmt_default_split,
		fmt_default_binary,
		encfs_common_get_salt,
		{
			encfs_common_iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
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
