/*
 * This software is Copyright (c) 2022 magnum,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_cryptgost94;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_cryptgost94);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "opencl_common.h"
#include "opencl_helper_macros.h"

#define FORMAT_LABEL        "gost94crypt-opencl"
#define FORMAT_NAME         "Astra Linux $gost94hash$"
#define ALGORITHM_NAME      "GOST R 34.11-94 OpenCL"

#define PLAINTEXT_LENGTH    60

#define BINARY_SIZE         (256/8) // 32
#define BINARY_ALIGN        4
#define SALT_SIZE           sizeof(saltstruct)
#define SALT_ALIGN          4

#define SALT_LENGTH         16

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#define CIPHERTEXT_LENGTH   43

/* ------ Contains (at least) prepare(), valid() and split() ------ */
/* Prefix for optional rounds specification.  */
#define ROUNDS_PREFIX       "rounds="
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT      5000
/* Minimum number of rounds. Libs usually have it as 1000 but we accept any */
#define ROUNDS_MIN          1
/* Maximum number of rounds.  */
#define ROUNDS_MAX          999999999

#define BENCHMARK_COMMENT   " (rounds=5000)"
#define BENCHMARK_LENGTH    0x107
#define FORMAT_TAG          "$gost94hash$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

static struct fmt_tests tests[] = {
	{"$gost94hash$salt$sG.6rfU0vKHX4eL00bUDqjXxaAcQHqpJQlM3ctfj013", "magnum"},
	{"$gost94hash$longersalt$KthJlkmGINf53PizXq8phMfeIC0deIsfafswsC3UN74", "password"},
	{"$gost94hash$longersalt$EtAWEGKZQGtZeHXaSDpQJP5tLhZnOi1NC2M/7PCmHZ6", "longerpassword"},
	{NULL}
};

typedef struct {
	unsigned int len;
	char key[PLAINTEXT_LENGTH];
} inbuf;

typedef struct {
	unsigned int v[BINARY_SIZE / sizeof(unsigned int)];
} outbuf;
static outbuf *crypt_out;

typedef struct {
	unsigned int rounds;
	unsigned int len;
	unsigned char salt[SALT_LENGTH];
} saltstruct;
static saltstruct cur_salt;

typedef struct {
	unsigned char p_bytes[PLAINTEXT_LENGTH];
	unsigned char s_bytes[SALT_LENGTH];
} statebuf;

typedef struct {
	unsigned int sbox[4][256];
} localbuf;

#define STEP			0
#define SEED			128
#define HASH_LOOPS		(21 * 8)
#define ITERATIONS		5004

static inbuf *inbuffer;
static cl_mem mem_in, mem_out, mem_salt, mem_state;
static cl_kernel init_kernel, final_kernel;
static int new_keys;
static struct fmt_main *self;

static const char *warn[] = {
	"key xfer: ", ", init: ", ", loop: ", ", final: ", ", result xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	inbuffer = mem_calloc(gws, sizeof(inbuf));
	crypt_out = mem_calloc(gws, sizeof(outbuf));

	CLCREATEBUFFER(mem_in, CL_RO, gws * sizeof(inbuf));
	CLCREATEBUFFER(mem_out, CL_WO, gws * sizeof(outbuf));
	CLCREATEBUFFER(mem_state, CL_RW, gws * sizeof(statebuf));
	CLCREATEBUFFER(mem_salt, CL_RO, sizeof(saltstruct));

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_TRUE, 0, gws * sizeof(inbuf), inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_TRUE, 0, sizeof(saltstruct), &cur_salt, 0, NULL, NULL), "Salt transfer");

	CLKERNELARG(init_kernel, 0, mem_in);
	CLKERNELARG(init_kernel, 1, mem_salt);
	CLKERNELARG(init_kernel, 2, mem_state);
	CLKRNARGLOC(init_kernel, 3, localbuf);
	CLKERNELARG(init_kernel, 4, mem_out);

	CLKERNELARG(crypt_kernel, 0, mem_in);
	CLKERNELARG(crypt_kernel, 1, mem_salt);
	CLKERNELARG(crypt_kernel, 2, mem_state);
	CLKRNARGLOC(crypt_kernel, 3, localbuf);
	CLKERNELARG(crypt_kernel, 4, mem_out);

	CLKERNELARG(final_kernel, 0, mem_in);
	CLKERNELARG(final_kernel, 1, mem_salt);
	CLKERNELARG(final_kernel, 2, mem_state);
	CLKRNARGLOC(final_kernel, 3, localbuf);
	CLKERNELARG(final_kernel, 4, mem_out);

	global_work_size = gws;
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s = autotune_get_task_max_work_group_size(FALSE, 0, init_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	return MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
}

static void release_clobj(void)
{
	if (crypt_out) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(crypt_out);
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

		snprintf(build_opts, sizeof(build_opts), "-DPLAINTEXT_LENGTH=%u -DHASH_LOOPS=%u",
		         PLAINTEXT_LENGTH, HASH_LOOPS);
		opencl_init("$JOHN/opencl/gost94hash_kernel.cl", gpu_id, build_opts);

		init_kernel = clCreateKernel(program[gpu_id], "gost94init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		crypt_kernel = clCreateKernel(program[gpu_id], "gost94loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");

		final_kernel = clCreateKernel(program[gpu_id], "gost94final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn,
	                       2, self, create_clobj, release_clobj,
	                       sizeof(mem_state), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ITERATIONS, 0, 200);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(init_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

/* ------- Check if the ciphertext if a valid gost94hash crypt ------- */
static int valid(char * ciphertext, struct fmt_main * self) {
	char *pos, *start;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
			return 0;

	ciphertext += FORMAT_TAG_LEN;

	if (!strncmp(ciphertext, ROUNDS_PREFIX, sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		if (!strtoul(num, &endp, 10))
					return 0;
		if (*endp == '$')
			ciphertext = endp + 1;
	}
	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext || pos > &ciphertext[SALT_LENGTH]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;
	return 1;
}

/* ------- To binary functions ------- */
#define TO_BINARY(b1, b2, b3) \
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void * get_binary(char * ciphertext) {
	static uint32_t outbuf[BINARY_SIZE/4];
	uint32_t value;
	char *pos = strrchr(ciphertext, '$') + 1;
	unsigned char *out = (unsigned char*)outbuf;
	int i=0;

	do {
		TO_BINARY(i, (i+10)%30, (i+20)%30);
		i = (i+21)%30;
	} while (i != 0);
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) |
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12);
	out[31] = value >> 8;
	out[30] = value;
	return (void *)out;
}

static void set_salt(void *salt)
{
	memcpy(&cur_salt, salt, sizeof(saltstruct));

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(saltstruct), &cur_salt, 0, NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_KPC_MULTIPLE(count, local_work_size);
	int index;

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, gws * sizeof(inbuf), inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");

		new_keys = 0;
	}

	// Run kernel
	CLRUNKERNEL(init_kernel, &gws, lws, multi_profilingEvent[1]);

	uint loops = (ocl_autotune_running ? 1 : cur_salt.rounds / HASH_LOOPS);
	WAIT_INIT(gws)
	for (index = 0; index < loops; index++) {
		CLRUNKERNEL(crypt_kernel, &gws, lws, multi_profilingEvent[2]);
		WAIT_SLEEP
		CLFINISH();
		WAIT_UPDATE
		opencl_process_event();
	}
	WAIT_DONE

	CLRUNKERNEL(final_kernel, &gws, lws, multi_profilingEvent[3]);

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, gws * sizeof(outbuf), crypt_out, 0, NULL, multi_profilingEvent[4]), "Copy result back");

	return count;
}

static void *get_salt(char *ciphertext)
{
	int len;

	memset(&cur_salt, 0, sizeof(cur_salt));
	cur_salt.rounds = ROUNDS_DEFAULT;
	ciphertext += FORMAT_TAG_LEN;
	if (!strncmp(ciphertext, ROUNDS_PREFIX,
	             sizeof(ROUNDS_PREFIX) - 1)) {
		const char *num = ciphertext + sizeof(ROUNDS_PREFIX) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			ciphertext = endp + 1;
			srounds = srounds < ROUNDS_MIN ?
				ROUNDS_MIN : srounds;
			cur_salt.rounds = srounds > ROUNDS_MAX ?
				ROUNDS_MAX : srounds;
		}
	}

	for (len = 0; ciphertext[len] != '$'; len++);

	if (len > SALT_LENGTH)
		len = SALT_LENGTH;

	memcpy(cur_salt.salt, ciphertext, len);
	cur_salt.len = len;
	return &cur_salt;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index].v, ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index].v, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	inbuffer[index].len = strlen(key);

	memcpy(inbuffer[index].key, key, inbuffer[index].len);

	new_keys = 1;
}

static char* get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];

	memcpy(out, inbuffer[index].key, inbuffer[index].len);
	out[inbuffer[index].len] = 0;

	return out;
}

// Public domain hash function by DJ Bernstein
// We are hashing the entire struct, so rounds get included
static int salt_hash(void *salt)
{
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < SALT_SIZE; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

static unsigned int iteration_count(void *salt)
{
	saltstruct *p = salt;
	return p->rounds;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

struct fmt_main fmt_opencl_cryptgost94 = {
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
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
#endif /* HAVE_OPENCL */
