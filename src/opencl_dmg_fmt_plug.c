/*
 * This software is Copyright (c) 2017-2018, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_dmg;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_dmg);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "options.h"
#include "jumbo.h"
#include "loader.h"
#include "dmg_common.h"
#include "opencl_common.h"
#include "sha.h"
#define OUTLEN 32
#define PLAINTEXT_LENGTH	125
#include "../run/opencl/opencl_pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL		"dmg-opencl"
#define FORMAT_NAME		"Apple DMG"
#define FORMAT_TAG           "$dmg$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME		"PBKDF2-SHA1 3DES/AES OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_SIZE		sizeof(dmg_salt)
#define SALT_ALIGN		sizeof(uint32_t)

/* This handles all widths */
#define GETPOS(i, index)	(((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

typedef struct {
	pbkdf2_salt pbkdf2;
	uint32_t headerver;
	unsigned int ivlen;
	unsigned char iv[32];
	uint32_t encrypted_keyblob_size;
	uint8_t encrypted_keyblob[32];
	unsigned int len_wrapped_aes_key;
	unsigned char wrapped_aes_key[296];
	unsigned int len_hmac_sha1_key;
	unsigned char wrapped_hmac_sha1_key[300];
	int cno;
	int data_size;
	unsigned char chunk[8192];
	uint32_t scp; /* start chunk present */
	unsigned char zchunk[4096]; /* chunk #0 */
} dmg_salt;

typedef struct {
	unsigned int dk[((OUTLEN + 19) / 20) * 20 / sizeof(unsigned int)];
	unsigned int cracked;
} dmg_out;

static size_t key_buf_size;
static unsigned int *inbuffer;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static dmg_out *output;
static dmg_salt *cur_salt;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static int new_keys;
static struct fmt_main *self;

static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final, dmg_final[3];

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS		500
#define LOOP_COUNT		(((cur_salt->pbkdf2.iterations - 1 + HASH_LOOPS - 1)) / HASH_LOOPS)
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"P xfer: "  ,  ", init: "   , ", loop: " , ", final: ", ", dmg final: ", ", res xfer: "
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
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, dmg_final[1]));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, dmg_final[2]));
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
	output = mem_calloc(gws, sizeof(dmg_out));
	saved_key = mem_calloc(gws, PLAINTEXT_LENGTH + 1);

	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(dmg_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(dmg_out) * gws, NULL, &ret_code);
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

	HANDLE_CLERROR(clSetKernelArg(dmg_final[1], 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(dmg_final[1], 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");

	HANDLE_CLERROR(clSetKernelArg(dmg_final[2], 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(dmg_final[2], 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
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
		MEM_FREE(saved_key);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(dmg_final[1]), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(dmg_final[2]), "Release kernel");
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
		snprintf(valgo, sizeof(valgo), ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DHASH_LOOPS=%u -DOUTLEN=%u -DV_WIDTH=%u",
		         HASH_LOOPS, OUTLEN, ocl_v_width);
		opencl_init("$JOHN/opencl/dmg_kernel.cl", gpu_id, build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		dmg_final[1] = clCreateKernel(program[gpu_id], "dmg_final_v1", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		dmg_final[2] = clCreateKernel(program[gpu_id], "dmg_final_v2", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	// FIXME: Share in opencl_autotune.h
	int iter = MIN(db->max_cost[0], options.loader.max_cost[0]);

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events,
	                       warn, 2, self, create_clobj,
	                       release_clobj,
	                       ocl_v_width * sizeof(pbkdf2_state), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ((2 * iter - 1) + HASH_LOOPS - 1), 0, 200);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	char *p;
	int headerver;
	int res, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$dmg$" marker */
	if ((p = strtokm(ctcopy, "*")) == NULL)
		goto err;
	headerver = atoi(p);
	if (headerver == 2) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt len */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 20)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* ivlen */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (atoi(p) > sizeof(cur_salt->iv))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* encrypted_keyblob_size */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 128) /* This is truncated to 32 anyway, in get_salt */
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* encrypted keyblob */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* chunk number */
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* data_size */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if ((p = strtokm(NULL, "*")) == NULL)	/* chunk */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if (res > sizeof(cur_salt->chunk))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* scp */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res == 1) {
			if ((p = strtokm(NULL, "*")) == NULL)	/* zchunk */
				goto err;
			if (strlen(p) != 4096 * 2)
				goto err;
		} else if (res != 0)
			goto err;
	}
	else if (headerver == 1) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt len */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 20)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* len_wrapped_aes_key */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > sizeof(cur_salt->wrapped_aes_key))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* wrapped_aes_key  */
			goto err;
		if (hexlenl(p, &extra) != res*2 || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* len_hmac_sha1_key */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > sizeof(cur_salt->wrapped_hmac_sha1_key))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* hmac_sha1_key */
			goto err;
		if (strlen(p) / 2 != res)
			goto err;
	}
	else
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static dmg_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*");
	cs.headerver = atoi(p);
	if (cs.headerver == 2) {
		p = strtokm(NULL, "*");
		cs.pbkdf2.length = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.pbkdf2.length; i++)
			cs.pbkdf2.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.ivlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.ivlen; i++)
			cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.encrypted_keyblob_size = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < MIN(cs.encrypted_keyblob_size, sizeof(cs.encrypted_keyblob)); i++)
			cs.encrypted_keyblob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.cno = atoi(p);
		p = strtokm(NULL, "*");
		cs.data_size = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.data_size; i++)
			cs.chunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.scp = atoi(p);
		if (cs.scp == 1) {
			p = strtokm(NULL, "*");
			for (i = 0; i < 4096; i++)
				cs.zchunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
		if ((p = strtokm(NULL, "*")))
			cs.pbkdf2.iterations = atoi(p);
		else
			cs.pbkdf2.iterations = 1000;
	}
	else {
		p = strtokm(NULL, "*");
		cs.pbkdf2.length = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.pbkdf2.length; i++)
			cs.pbkdf2.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.len_wrapped_aes_key = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.len_wrapped_aes_key; i++)
			cs.wrapped_aes_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.len_hmac_sha1_key = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.len_hmac_sha1_key; i++)
			cs.wrapped_hmac_sha1_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		if ((p = strtokm(NULL, "*")))
			cs.pbkdf2.iterations = atoi(p);
		else
			cs.pbkdf2.iterations = 1000;
	}
	if (cs.pbkdf2.iterations == 0)
		cs.pbkdf2.iterations = 1000;
	cs.pbkdf2.outlen = 32;
	MEM_FREE(keeptr);
	return (void*)&cs;
}


static void set_salt(void *salt)
{
	cur_salt = (dmg_salt*)salt;
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0,
	                                    sizeof(dmg_salt), cur_salt, 0,
	                                    NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void clear_keys(void) {
	memset(inbuffer, 0, key_buf_size);
}

#undef set_key
static void set_key(char *cand, int index)
{
	int i;
	char *key = cand;
	int length = strlen(cand);
	unsigned char hash[20];

	strcpy(saved_key[index], key);

	if (length > 64) {
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cand, length);
		SHA1_Final(hash, &ctx);

		key = (char*)hash;
		length = 20;
	}

	for (i = 0; i < length; i++)
		((char*)inbuffer)[GETPOS(i, index)] = key[i];

	new_keys = 1;
}

static char* get_key(int index)
{
	return saved_key[index];
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
		WAIT_INIT(global_work_size)

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");

		BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
		WAIT_UPDATE
		WAIT_DONE

		new_keys = 0;
	}

	// Run kernels
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running init kernel");

	WAIT_INIT(global_work_size)
	for (j = 0; j < (ocl_autotune_running ? 1 : ((cur_salt->pbkdf2.outlen + 19) / 20)); j++) {
		for (i = 0; i < (ocl_autotune_running ? 1 : LOOP_COUNT); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");

			WAIT_SLEEP
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			WAIT_UPDATE

			opencl_process_event();
		}

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Run final pbkdf2 kernel");
	}
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running final pbkdf2 kernel");
	WAIT_DONE

	WAIT_INIT(global_work_size)

	// DMG post-processing
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], dmg_final[cur_salt->headerver], 1, NULL, &scalar_gws, lws, 0, NULL, multi_profilingEvent[4]), "Run final dmg kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE, 0, sizeof(dmg_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[5]), "Copy result back");

	BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	WAIT_UPDATE
	WAIT_DONE

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (output[index].cracked)
			return 1;
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

static unsigned int iteration_count(void *salt)
{
	return ((dmg_salt*)salt)->pbkdf2.iterations;
}

static unsigned int headerver(void *salt)
{
	return ((dmg_salt*)salt)->headerver;
}

struct fmt_main fmt_opencl_dmg = {
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
			"version",
		},
		{ FORMAT_TAG },
		dmg_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
			headerver,
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
