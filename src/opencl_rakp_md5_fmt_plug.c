/*
 * OpenCL IPMI 2.0 RAKP (RMCP+) HMAC-MD5 (RAKP auth algorithm 2).
 *
 * Host based on opencl_rakp_fmt_plug.c (HMAC-SHA1 RAKP, (C) 2013 Harrison Neal,
 * magnum, Dhiru Kholia). Copyright (c) 2026 HD Moore. Released under GPLv2 like
 * the original. Scalar one-work-item-per-candidate kernel that calls the shared
 * hmac_md5 helper; the raw RAKP salt (binary) + length are passed to the GPU.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rakp_md5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rakp_md5);
#else

#include <string.h>
#include <stdint.h>

#include "path.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "opencl_common.h"
#include "options.h"

#define FORMAT_LABEL            "RAKP-MD5-opencl"
#define FORMAT_NAME             "IPMI 2.0 RAKP (RMCP+)"
#define ALGORITHM_NAME          "HMAC-MD5 OpenCL"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7

#define BLOCK_SIZE              64
#define SALT_STORAGE_SIZE       (BLOCK_SIZE * 2)
#define SALT_SIZE               (SALT_STORAGE_SIZE - 9)
#define SALT_MIN_SIZE           (SALT_SIZE - BLOCK_SIZE + 1)

#define PLAINTEXT_LENGTH        (BLOCK_SIZE - 1) /* idx & 63 */
#define BUFFER_SIZE             ((PLAINTEXT_LENGTH + 63) / 64 * 64)

#define BINARY_SIZE             16

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define FORMAT_TAG              "$rakp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(uint32_t)

#define STEP                    0
#define SEED                    65536
#define ROUNDS                  5

static const char * warn[] = {
	"pass xfer: ", ", index xfer: ", ", crypt: ", ", result xfer: "
};

typedef struct {
	uint32_t length;
	unsigned char salt[SALT_STORAGE_SIZE];
} rakp_salt_t;

static cl_uint salt_len_arg;

static cl_mem salt_buffer, keys_buffer, idx_buffer, digest_buffer;

static int new_keys;
static unsigned int *keys;
static uint32_t *idx;
static unsigned char *digest;
static unsigned int key_idx = 0;
static struct fmt_main *self;

#include "opencl_autotune.h"

static struct fmt_tests tests[] = {
	{"$rakp$000476044b237ebb4f2a415ce488ebc91996043c8011e26079633b706424119e09dcaad4acf21b10535000000000000000000000000000001404726f6f74$102546a8888f78d420fc48ba84108ee2", "superuser"},
	{"$rakp$000aae1770480e004b31afa4a6e13297b09fc5d60b4a018b4fc50ecf9a8963745bf6a56a6873f50f000000000000000000000000000000001400$ef1f3c6c029975343a4d1195dee130da", "admin"},
	{"$rakp$001108876d5e010001e176e46f686d5e296145b5d6454181da9a9e2f0e9eba82b7c6c1c83dcf3a5a000000000000000000000000000000001400$3ea2e6b997bc34959ef1617fd4be1348", "admin"},
	{NULL}
};

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

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	keys = mem_alloc((PLAINTEXT_LENGTH + 1) * gws);
	idx = mem_calloc(gws, sizeof(*idx));
	digest = mem_alloc(gws * BINARY_SIZE);

	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, SALT_STORAGE_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer");
	keys_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, (PLAINTEXT_LENGTH + 1) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating keys_buffer");
	idx_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating idx_buffer");
	digest_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating digest_buffer");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(salt_buffer), &salt_buffer), "Error arg 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_uint), &salt_len_arg), "Error arg 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(keys_buffer), &keys_buffer), "Error arg 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(idx_buffer), &idx_buffer), "Error arg 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(digest_buffer), &digest_buffer), "Error arg 4");
}

static void release_clobj(void)
{
	if (keys) {
		HANDLE_CLERROR(clReleaseMemObject(digest_buffer), "Release digest_buffer");
		HANDLE_CLERROR(clReleaseMemObject(idx_buffer), "Release idx_buffer");
		HANDLE_CLERROR(clReleaseMemObject(keys_buffer), "Release keys_buffer");
		HANDLE_CLERROR(clReleaseMemObject(salt_buffer), "Release salt_buffer");
		MEM_FREE(digest);
		MEM_FREE(idx);
		MEM_FREE(keys);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release program");
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
		opencl_init("$JOHN/opencl/rakp_md5_kernel.cl", gpu_id, NULL);
		crypt_kernel = clCreateKernel(program[gpu_id], "rakp_md5_kernel", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	size_t gws_limit = MIN((1 << 26) * 4 / BUFFER_SIZE,
	                       get_max_mem_alloc_size(gpu_id) / BUFFER_SIZE);

	opencl_init_auto_setup(SEED, 0, NULL, warn, 2, self,
	                       create_clobj, release_clobj, BUFFER_SIZE, gws_limit, db);
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
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

static void *get_salt(char *ciphertext)
{
	static rakp_salt_t out;
	char *p;
	unsigned int i, len;

	memset(&out, 0, sizeof(out));
	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;
	len = (strrchr(p, '$') - p) / 2;
	for (i = 0; i < len; i++)
		out.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	out.length = len;
	return &out;
}

static void set_salt(void *salt)
{
	rakp_salt_t *s = salt;

	salt_len_arg = s->length;
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_uint), &salt_len_arg), "Error setting salt_len");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE, 0, s->length, s->salt, 0, NULL, NULL),
	               "Error updating salt_buffer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == ((uint32_t*)(digest + index * BINARY_SIZE))[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, digest + index * BINARY_SIZE, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_KPC_MULTIPLE(count, local_work_size);

	if (new_keys && key_idx) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], keys_buffer, CL_FALSE, 0, 4 * key_idx, keys, 0, NULL, multi_profilingEvent[0]),
		              "Error updating keys_buffer");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer, CL_FALSE, 0, 4 * global_work_size, idx, 0, NULL, multi_profilingEvent[1]),
		              "Error updating idx_buffer");
		new_keys = 0;
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[2]),
	              "Error running kernel");
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], digest_buffer, CL_TRUE, 0, BINARY_SIZE * global_work_size, digest, 0, NULL, multi_profilingEvent[3]),
	              "Error reading digest_buffer");

	return count;
}

#define OCL_GET_HASH(index) (((uint32_t*)(digest + (index) * BINARY_SIZE))[0])
static int get_hash_0(int index) { return OCL_GET_HASH(index) & PH_MASK_0; }
static int get_hash_1(int index) { return OCL_GET_HASH(index) & PH_MASK_1; }
static int get_hash_2(int index) { return OCL_GET_HASH(index) & PH_MASK_2; }
static int get_hash_3(int index) { return OCL_GET_HASH(index) & PH_MASK_3; }
static int get_hash_4(int index) { return OCL_GET_HASH(index) & PH_MASK_4; }
static int get_hash_5(int index) { return OCL_GET_HASH(index) & PH_MASK_5; }
static int get_hash_6(int index) { return OCL_GET_HASH(index) & PH_MASK_6; }

struct fmt_main fmt_opencl_rakp_md5 = {
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
		sizeof(rakp_salt_t),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
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
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
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

#endif /* plugin stanza */
#endif /* HAVE_OPENCL */
