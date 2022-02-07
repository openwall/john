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

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rakp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rakp);
#else

#include <string.h>
#include <stdint.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "johnswap.h"
#include "opencl_common.h"
#include "options.h"

#define FORMAT_LABEL            "RAKP-opencl"
#define FORMAT_NAME             "IPMI 2.0 RAKP (RMCP+)"
#define ALGORITHM_NAME          "HMAC-SHA1 OpenCL"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7

#define BLOCK_SIZE              64
#define PAD_SIZE                BLOCK_SIZE
#define SALT_STORAGE_SIZE       (BLOCK_SIZE*2)
#define SALT_SIZE               (SALT_STORAGE_SIZE - 9)
#define SALT_MIN_SIZE           (SALT_SIZE - BLOCK_SIZE + 1)

#define PLAINTEXT_LENGTH        (PAD_SIZE - 1) /* idx & 63 */
#define BUFFER_SIZE		((PLAINTEXT_LENGTH + 63) / 64 * 64)

#define BINARY_SIZE             20

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define FORMAT_TAG              "$rakp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              1

#define STEP                    0
#define SEED                    65536
#define ROUNDS			5

static const char * warn[] = {
        "pass xfer: ",  ", index xfer: ",  ", crypt: ",  ", result xfer: "
};

static unsigned char salt_storage[SALT_STORAGE_SIZE];

static cl_mem salt_buffer, keys_buffer, idx_buffer, digest_buffer;

static int new_keys;
static unsigned int *keys;
static uint32_t *idx;
static uint32_t (*digest);
static unsigned int key_idx = 0;
static int partial_output;
static struct fmt_main *self;

//This file contains auto-tuning routine(s). Have to included after other definitions.
#include "opencl_autotune.h"

static struct fmt_tests tests[] = {
	{"$rakp$a4a3a2a03f0b000094272eb1ba576450b0d98ad10727a9fb0ab83616e099e8bf5f7366c9c03d36a3000000000000000000000000000000001404726f6f74$0ea27d6d5effaa996e5edc855b944e179a2f2434", "calvin"},
	{"$rakp$c358d2a72f0c00001135f9b254c274629208b22f1166d94d2eba47f21093e9734355a33593da16f2000000000000000000000000000000001404726f6f74$41fce60acf2885f87fcafdf658d6f97db12639a9", "calvin"},
	{"$rakp$b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174$472bdabe2d5d4bffd6add7b3ba79a291d104a9ef", "hashcat"},
	/* dummy hash for testing long salts */
	{"$rakp$787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878$ba4ecc30a0b36a6ba0db862fc95201a81b9252ee", ""},
	{NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

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

	len = strspn(q, HEXCHARS_lc);
	if (len != BINARY_SIZE * 2 || len != strlen(q))
		return 0;

	if (strspn(p, HEXCHARS_lc) != q - p - 1)
		return 0;

	return 1;
}

static void clear_keys(void);
static void set_key(char *key, int index);
static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	gws *= ocl_v_width;

	keys = mem_alloc((PLAINTEXT_LENGTH + 1) * gws);
	idx = mem_calloc(gws, sizeof(*idx));
	digest = mem_alloc(gws * BINARY_SIZE);

	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, SALT_STORAGE_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	keys_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, (PLAINTEXT_LENGTH + 1) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating keys_buffer out argument");

	idx_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating idx_buffer out argument");

	digest_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, BINARY_SIZE * gws, NULL, &ret_code);
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
}

static void release_clobj(void)
{
	if (keys) {
		HANDLE_CLERROR(clReleaseMemObject(digest_buffer), "Error releasing digest_buffer");
		HANDLE_CLERROR(clReleaseMemObject(idx_buffer), "Error releasing idx_buffer");
		HANDLE_CLERROR(clReleaseMemObject(keys_buffer), "Error releasing keys_buffer");
		HANDLE_CLERROR(clReleaseMemObject(salt_buffer), "Error releasing salt_buffer");

		MEM_FREE(digest);
		MEM_FREE(idx);
		MEM_FREE(keys);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Error releasing kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Error releasing program");

		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	static char valgo[48] = "";

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
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts), "-DV_WIDTH=%u", ocl_v_width);
		opencl_init("$JOHN/opencl/rakp_kernel.cl", gpu_id, build_opts);

		// create kernel to execute
		crypt_kernel = clCreateKernel(program[gpu_id], "rakp_kernel", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	// Current key_idx can only hold 26 bits of offset so
	// we can't reliably use a GWS higher than 4M or so.
	size_t gws_limit = MIN((1 << 26) * 4 / (ocl_v_width * BUFFER_SIZE),
	                       get_max_mem_alloc_size(gpu_id) /
	                       (ocl_v_width * BUFFER_SIZE));

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 2,
	                       self, create_clobj, release_clobj,
	                       ocl_v_width * BUFFER_SIZE, gws_limit, db);

	//Auto tune execution from shared/included code.
	autotune_run(self, ROUNDS, gws_limit, 200);
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

	new_keys = 1;
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

static void *get_binary(char *ciphertext)
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

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	unsigned int i, len;

	if (!strncmp(ctcopy, FORMAT_TAG, TAG_LENGTH))
		ctcopy += TAG_LENGTH;

	p = strtokm(ctcopy, "$");
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
		clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0, sizeof(salt_storage), (void*) salt, 0, NULL, NULL),
		"Error updating contents of salt_buffer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
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
	uint32_t *b;
	int i;

	if (partial_output) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], digest_buffer, CL_TRUE, 0, BINARY_SIZE * global_work_size * ocl_v_width, digest, 0, NULL, NULL), "failed reading results back");
		partial_output = 0;
	}
	b = (uint32_t*)get_binary(source);

	for (i = 0; i < BINARY_SIZE / 4; i++)
		if (digest[i * global_work_size * ocl_v_width + index] != b[i])
			return 0;
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_KPC_MULTIPLE(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	if (new_keys && key_idx) {
		BENCH_CLERROR(
			clEnqueueWriteBuffer(queue[gpu_id], keys_buffer, CL_FALSE, 0, 4 * key_idx, keys, 0, NULL, multi_profilingEvent[0]),
			"Error updating contents of keys_buffer");

		BENCH_CLERROR(
			clEnqueueWriteBuffer(queue[gpu_id], idx_buffer, CL_FALSE, 0, 4 * scalar_gws, idx, 0, NULL, multi_profilingEvent[1]),
			"Error updating contents of idx_buffer");

		new_keys = 0;
	}

	BENCH_CLERROR(
		clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]),
		"Error beginning execution of the kernel");

	BENCH_CLERROR(
		clEnqueueReadBuffer(queue[gpu_id], digest_buffer, CL_TRUE, 0, sizeof(cl_uint) * scalar_gws, digest, 0, NULL, multi_profilingEvent[3]),
		"Error reading results from digest_buffer");
	partial_output = 1;

	return count;
}

struct fmt_main fmt_opencl_rakp = {
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
		SALT_STORAGE_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
		{ NULL },
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
		{ NULL },
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
