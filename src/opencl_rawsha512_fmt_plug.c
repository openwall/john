/*
 * SHA-512 hashing, OpenCL interface.
 * Please note that in current comparison function, we use computed a77
 * compares with ciphertext d80. For more details, refer to:
 * http://www.openwall.com/lists/john-dev/2012/04/11/13
 *
 * Copyright (c) 2012 myrice
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rawsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rawsha512);
#else

#include <string.h>

#include "arch.h"
#include "common-opencl.h"
#include "params.h"
#include "options.h"
#include "common.h"
#include "formats.h"
#include "sha2.h"

#define FORMAT_LABEL			"Raw-SHA512-opencl"
#define FORMAT_NAME			""
#define ALGORITHM_NAME			"SHA512 OpenCL (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define KERNEL_NAME "kernel_sha512"
#define CMP_KERNEL_NAME "kernel_cmp"

#define MIN_KEYS_PER_CRYPT	(1024*512)
#define MAX_KEYS_PER_CRYPT	(MIN_KEYS_PER_CRYPT)
#define hash_addr(j,idx) (((j)*(global_work_size))+(idx))

#define SWAP64(n) \
  (((n) << 56)					\
   | (((n) & 0xff00) << 40)			\
   | (((n) & 0xff0000) << 24)			\
   | (((n) & 0xff000000) << 8)			\
   | (((n) >> 8) & 0xff000000)			\
   | (((n) >> 24) & 0xff0000)			\
   | (((n) >> 40) & 0xff00)			\
   | ((n) >> 56))


#define SALT_SIZE 0
#define SALT_ALIGN 1

#define BINARY_SIZE 8
#define FULL_BINARY_SIZE 64
#define BINARY_ALIGN sizeof(uint64_t)

#define PLAINTEXT_LENGTH 20
#define CIPHERTEXT_LENGTH 128

typedef struct { // notice memory align problem
	uint32_t buffer[32];	//1024 bits
	uint32_t buflen;
} sha512_ctx;

#define OCL_CONFIG		"rawsha512"

typedef struct {
    uint8_t length;
    char v[PLAINTEXT_LENGTH+1];
} sha512_key;

typedef struct {
    uint64_t v[BINARY_SIZE / 8]; // up to 512 bits
} sha512_hash;


static struct fmt_tests tests[] = {
	{"b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", "password"},
	{"2c80f4c2b3db6b677d328775be4d38c8d8cd9a4464c3b6273644fb148f855e3db51bc33b54f3f6fa1f5f52060509f0e4d350bb0c7f51947728303999c6eff446", "john-user"},
	{NULL}
};


static sha512_key *gkey;
static sha512_hash *ghash;
static uint8_t sha512_key_changed;
static uint8_t hash_copy_back;

static uint64_t H[8] = {
	0x6a09e667f3bcc908LL,
	0xbb67ae8584caa73bLL,
	0x3c6ef372fe94f82bLL,
	0xa54ff53a5f1d36f1LL,
	0x510e527fade682d1LL,
	0x9b05688c2b3e6c1fLL,
	0x1f83d9abfb41bd6bLL,
	0x5be0cd19137e2179LL
};

//OpenCL variables:
static cl_mem mem_in, mem_out, mem_binary, mem_cmp;
static cl_kernel cmp_kernel;
static struct fmt_main *self;

#define insize (sizeof(sha512_key) * global_work_size)
#define outsize (sizeof(sha512_hash) * global_work_size)

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return MIN(autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel),
			   autotune_get_task_max_work_group_size(FALSE, 0, cmp_kernel));
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gkey = mem_calloc(gws, sizeof(sha512_key));
	ghash = mem_calloc(gws, sizeof(sha512_hash));

	///Allocate memory on the GPU
	mem_in =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while allocating memory for passwords");
	mem_out =
		clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while allocating memory for hashes");
	mem_binary =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(uint64_t), NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while allocating memory for binary");
	mem_cmp =
		clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(uint32_t), NULL,
		&ret_code);
	HANDLE_CLERROR(ret_code,"Error while allocating memory for cmp_all result");

	///Assign crypt kernel parameters
	clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in);
	clSetKernelArg(crypt_kernel, 1, sizeof(mem_out), &mem_out);

	///Assign cmp kernel parameters
	clSetKernelArg(cmp_kernel, 0, sizeof(mem_binary), &mem_binary);
	clSetKernelArg(cmp_kernel, 1, sizeof(mem_out), &mem_out);
	clSetKernelArg(cmp_kernel, 2, sizeof(mem_cmp), &mem_cmp);
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

	MEM_FREE(ghash);
	MEM_FREE(gkey);
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		char build_opts[64];

		snprintf(build_opts, sizeof(build_opts),
		         "-DPLAINTEXT_LENGTH=%u", PLAINTEXT_LENGTH);

		opencl_init("$JOHN/kernels/sha512_kernel.cl", gpu_id, build_opts);

		/* create kernels to execute */
		crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &ret_code);
		HANDLE_CLERROR(ret_code,"Error while creating crypt_kernel");
		cmp_kernel = clCreateKernel(program[gpu_id], CMP_KERNEL_NAME, &ret_code);
		HANDLE_CLERROR(ret_code,"Error while creating cmp_kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(sha512_key), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 500);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(cmp_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
		autotuned--;
	}
}

static inline void copy_hash_back()
{
    if (!hash_copy_back) {
        HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,outsize, ghash, 0, NULL, NULL), "Copy data back");
        hash_copy_back = 1;
    }
}

static void set_key(char *key, int index)
{
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	gkey[index].length = length;
	memcpy(gkey[index].v, key, length);
	sha512_key_changed = 1;
}

static char *get_key(int index)
{
	gkey[index].v[gkey[index].length] = 0;
	return gkey[index].v;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	/* Require lowercase hex digits (assume ASCII) */
	pos = ciphertext;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && (*pos <= '9' || *pos >= 'a'))
		pos++;
	return !*pos && pos - ciphertext == CIPHERTEXT_LENGTH;

}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[FULL_BINARY_SIZE];
	char *p;
	int i;
	uint64_t *b;

	p = ciphertext;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint64_t*)out;
	for (i = 0; i < 8; i++) {
		uint64_t t = SWAP64(b[i])-H[i];
		b[i] = SWAP64(t);
	}
	return out;

}

static int binary_hash_0(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_0;
}

static int binary_hash_1(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_1;
}

static int binary_hash_2(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_2;
}

static int binary_hash_3(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_3;
}

static int binary_hash_4(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return *((ARCH_WORD_32 *)binary+6) & PH_MASK_6;
}

static int get_hash_0(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[index] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	copy_hash_back();
	return ((uint64_t*)ghash)[index] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	copy_hash_back();

	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	copy_hash_back();

	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	copy_hash_back();

	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	copy_hash_back();

	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	copy_hash_back();

	return ((uint64_t*)ghash)[hash_addr(0, index)] & PH_MASK_6;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	///Copy data to GPU memory
	if (sha512_key_changed || ocl_autotune_running) {
		BENCH_CLERROR(clEnqueueWriteBuffer
		    (queue[gpu_id], mem_in, CL_FALSE, 0, insize, gkey, 0, NULL,
			multi_profilingEvent[0]), "Copy memin");
	}

	///Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel
	    (queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws,
		0, NULL, multi_profilingEvent[1]), "Set ND range");

	/// Reset key to unchanged and hashes uncopy to host
	sha512_key_changed = 0;
    hash_copy_back = 0;

	return count;
}

static int cmp_all(void *binary, int count)
{
	uint32_t result;
	///Copy binary to GPU memory
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_binary, CL_FALSE,
		0, sizeof(uint64_t), ((uint64_t*)binary)+3, 0, NULL, NULL), "Copy mem_binary");

	///Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel
	    (queue[gpu_id], cmp_kernel, 1, NULL, &global_work_size, &local_work_size,
		0, NULL, NULL), "Set ND range");

	/// Copy result out
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_cmp, CL_TRUE, 0,
		sizeof(uint32_t), &result, 0, NULL, NULL), "Copy data back");

	return result;
}

static int cmp_one(void *binary, int index)
{
	uint64_t *b = (uint64_t *) binary;
	uint64_t *t = (uint64_t *)ghash;

	copy_hash_back();
	if (b[3] != t[hash_addr(0, index)])
		return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	SHA512_CTX ctx;
	uint64_t *b,*c,crypt_out[8];
	int i;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, gkey[index].v, gkey[index].length);
	SHA512_Final((unsigned char *)(crypt_out), &ctx);

	b = (uint64_t *)get_binary(source);
	c = (uint64_t *)crypt_out;

	for (i = 0; i < 8; i++) {
		uint64_t t = SWAP64(c[i])-H[i];
		c[i] = SWAP64(t);
	}


	for (i = 0; i < FULL_BINARY_SIZE / 8; i++) { //examin 512bits
		if (b[i] != c[i])
			return 0;
	}
	return 1;

}

struct fmt_main fmt_opencl_rawsha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		FULL_BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
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
