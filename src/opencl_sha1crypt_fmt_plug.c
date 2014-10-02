/*
 * This software is Copyright (c) 2014 Dhiru Kholia
 * and Copyright (c) 2014 magnum,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ocl_cryptsha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ocl_cryptsha1);
#else

#include <string.h>

#include "arch.h"
#include "base64.h"
#include "sha.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "common-opencl.h"

//#define DEBUG
#define SHA1_MAGIC "$sha1$"
#define SHA1_SIZE 20

#define FORMAT_LABEL                "sha1crypt-opencl"
#define FORMAT_NAME                 "(NetBSD)"
#define ALGORITHM_NAME              "PBKDF1-SHA1 OpenCL"
#define BENCHMARK_COMMENT           ""
#define BENCHMARK_LENGTH            -1001

#define BINARY_SIZE                 20
// max valid salt len in hash is shorter than this (by length of "$sha1$" and length of base10 string of rounds)
#define SALT_LENGTH                 64

#define PLAINTEXT_LENGTH            55
#define CHECKSUM_LENGTH             28

#define BINARY_ALIGN                4
#define SALT_SIZE                   sizeof(salt_t)
#define SALT_ALIGN                  4

#define MIN_KEYS_PER_CRYPT          1
#define MAX_KEYS_PER_CRYPT          1

/* An example hash (of password) is $sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq.
 * An sha1-crypt hash string has the format $sha1$rounds$salt$checksum, where:
 *
 * $sha1$ is the prefix used to identify sha1-crypt hashes, following the Modular Crypt Format
 * rounds is the decimal number of rounds to use (40000 in the example).
 * salt is 0-64 characters drawn from [./0-9A-Za-z] (jtNX3nZ2 in the example).
 * checksum is 28 characters drawn from the same set, encoding a 168-bit checksum.
 */

static struct fmt_tests tests[] = {
	{"$sha1$64000$wnUR8T1U$vt1TFQ50tBMFgkflAFAOer2CwdYZ", "password"},
	{"$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq", "password"},
	{"$sha1$64000$wnUR8T1U$wmwnhQ4lpo/5isi5iewkrHN7DjrT", "123456"},
	{"$sha1$64000$wnUR8T1U$azjCegpOIk0FjE61qzGWhdkpuMRL", "complexlongpassword@123456"},
	{NULL}
};

#define STEP			0
#define SEED			64

#define OCL_CONFIG		"sha1crypt"

#define MIN(a, b)		(((a) < (b)) ? (a) : (b))
#define MAX(a, b)		(((a) > (b)) ? (a) : (b))
#define ITERATIONS		(64000*2+2)

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[BINARY_SIZE / sizeof(uint32_t)];
} crack_t;

typedef struct {
	uint8_t length;
	uint8_t salt[32]; // FIXME
	uint32_t iterations;
	uint32_t outlen;
} salt_t;

static pass_t *host_pass;
static crack_t *host_crack;
static salt_t *host_salt;
static cl_int cl_error;
static cl_mem mem_in, mem_out, mem_salt;

static const char * warn[] = {
        "data xfer: "  ,  ", salt xfer: "   , ", crypt: " , ", result xfer: "
};

static int split_events[] = { 2, -1, -1 };

static int crypt_all(int *pcount, struct db_salt *_salt);
static int crypt_all_benchmark(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	//fprintf(stderr, "%s(%zu)\n", __FUNCTION__, kpc);
#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)\
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);\
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)\
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	host_pass = mem_calloc(kpc * sizeof(pass_t));
	host_crack = mem_calloc(kpc * sizeof(crack_t));

	mem_in =
		CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
		"Cannot allocate mem in");
	mem_salt =
		CLCREATEBUFFER(CL_RO, sizeof(salt_t),
		"Cannot allocate mem salt");
	mem_out =
		CLCREATEBUFFER(CL_WO, kpc * sizeof(crack_t),
		"Cannot allocate mem out");

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_out, "Error while setting mem_out");
	CLKERNELARG(crypt_kernel, 2, mem_salt, "Error while setting mem_salt");
}

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return common_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return 1;
	else
		return 128;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

	MEM_FREE(host_pass);
	MEM_FREE(host_crack);
}

static void init(struct fmt_main *self)
{
	char build_opts[64];
	size_t gws_limit;

	snprintf(build_opts, sizeof(build_opts),
	         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
	         PLAINTEXT_LENGTH,
	         (int)sizeof(host_salt->salt),
	         (int)sizeof(host_crack->hash));
        opencl_init("$JOHN/kernels/pbkdf1_hmac_sha1_kernel.cl",
                    gpu_id, build_opts);

	crypt_kernel =
	    clCreateKernel(program[gpu_id], "derive_key", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating crypt kernel");

	gws_limit = get_max_mem_alloc_size(gpu_id) /
		(sizeof(pass_t) + sizeof(crack_t));

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, ITERATIONS, split_events,
		warn, 1, self, create_clobj, release_clobj,
	        sizeof(pass_t) + sizeof(crack_t), gws_limit);

	//Auto tune execution from shared/included code.
	self->methods.crypt_all = crypt_all_benchmark;
	common_run_auto_tune(self, ITERATIONS, gws_limit, 5000000000ULL);
	self->methods.crypt_all = crypt_all;
}

static void done(void)
{
	release_clobj();
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel 1");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]),
	    "Release Program");
}

static void set_salt(void *salt)
{
	host_salt = salt;
	//fprintf(stderr, "%s() len %u iter %u\n", __FUNCTION__, host_salt->length, host_salt->iterations);
}

static int binary_hash_0(void *binary)
{
#ifdef DEBUG
	dump_stuff_msg("binary_hash[0]", (uint32_t*)binary, 20);
#endif
	return (((uint32_t *) binary)[0] & 0xf);
}

static int get_hash_0(int index)
{
#ifdef DEBUG
	dump_stuff_msg("\nget_hash", host_crack[index].hash, 20);
#endif
	return host_crack[index].hash[0] & 0xf;
}
static int get_hash_1(int index) { return host_crack[index].hash[0] & 0xff; }
static int get_hash_2(int index) { return host_crack[index].hash[0] & 0xfff; }
static int get_hash_3(int index) { return host_crack[index].hash[0] & 0xffff; }
static int get_hash_4(int index) { return host_crack[index].hash[0] & 0xfffff; }
static int get_hash_5(int index) { return host_crack[index].hash[0] & 0xffffff; }
static int get_hash_6(int index) { return host_crack[index].hash[0] & 0x7ffffff; }

static int valid(char *ciphertext, struct fmt_main *self) {
	char *pos, *start, *endp;
	if (strncmp(ciphertext, SHA1_MAGIC, sizeof(SHA1_MAGIC) - 1))
		return 0;

	// validate checksum
        pos = start = strrchr(ciphertext, '$') + 1;
	if (strlen(pos) != CHECKSUM_LENGTH)
		return 0;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CHECKSUM_LENGTH)
		return 0;

	// validate "rounds"
	start = ciphertext + sizeof(SHA1_MAGIC) - 1;
	if (!strtoul(start, &endp, 10))
		return 0;

	// validate salt
	start = pos = strchr(start, '$') + 1;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F && *pos != '$') pos++;
	if (pos - start != 8)
		return 0;

	return 1;
}

#define TO_BINARY(b1, b2, b3) \
	value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void *get_binary(char * ciphertext)
{       static union {
                unsigned char c[BINARY_SIZE + 16];
                ARCH_WORD dummy;
        } buf;
        unsigned char *out = buf.c;
	ARCH_WORD_32 value;

	char *pos = strrchr(ciphertext, '$') + 1;
	int i = 0;

	// XXX is this even correct?
	do {
		TO_BINARY(i, i + 1, i + 2);
		i = i + 3;
	} while (i <= 18);

	return (void *)out;
}

static int crypt_all_benchmark(int *pcount, struct db_salt *salt)
{
	int ev = 0, count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_EXACT_MULTIPLE(count, local_work_size);
	//fprintf(stderr, "%s(%d) lws %zu gws %zu\n", __FUNCTION__, count, local_work_size, gws);
	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in,
		CL_FALSE, 0, gws * sizeof(pass_t), host_pass, 0,
		NULL, multi_profilingEvent[ev++]), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(salt_t), host_salt, 0, NULL, multi_profilingEvent[ev++]),
	    "Copy salt to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
		1, NULL, &gws, lws, 0, NULL,
		multi_profilingEvent[ev++]), "Run kernel");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out,
		CL_FALSE, 0, gws * sizeof(crack_t), host_crack, 0,
		NULL, multi_profilingEvent[ev++]), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	return count;
}

static void opencl_limit_gws(int count)
{
	global_work_size =
	    (count + local_work_size - 1) / local_work_size * local_work_size;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_EXACT_MULTIPLE(count, local_work_size);
	opencl_limit_gws(count);
	//fprintf(stderr, "%s(%d) lws %zu gws %zu\n", __FUNCTION__, count, local_work_size, gws);

	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in,
		CL_FALSE, 0, gws * sizeof(pass_t), host_pass, 0,
		NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, sizeof(salt_t), host_salt, 0, NULL, NULL),
	    "Copy salt to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel,
		1, NULL, &gws, lws, 0, NULL,
		NULL), "Run kernel");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out,
		CL_FALSE, 0, gws * sizeof(crack_t), host_crack, 0,
		NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	return count;
}

static void *get_salt(char *ciphertext)
{
	static salt_t out;
	char tmp[256];
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	strncpy(tmp, ciphertext, p - ciphertext -1);
	tmp[p-ciphertext-1] = 0;
	out.iterations = strtoul(&ciphertext[sizeof(SHA1_MAGIC)-1], NULL, 10);
	// point p to the salt value, BUT we have to decorate the salt for this hash.
	p = strrchr(tmp, '$') + 1;
	// real salt used is: <salt><magic><iterations>
	out.length = snprintf((char*)out.salt, sizeof(out.salt), "%.*s%s%u", (int)strlen(p), p, SHA1_MAGIC, out.iterations);
	out.outlen = BINARY_SIZE;
	return &out;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (host_crack[i].hash[0] == ((uint32_t *) binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;

	for (i = 0; i < BINARY_SIZE / 4; i++)
		if (host_crack[index].hash[i] != ((uint32_t *) binary)[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	int saved_key_length = MIN(strlen(key), PLAINTEXT_LENGTH);

	memcpy(host_pass[index].v, key, saved_key_length);
	host_pass[index].length = saved_key_length;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
	return ret;
}

// Public domain hash function by DJ Bernstein
// We are hashing the entire struct
static int salt_hash(void *salt)
{
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < SALT_SIZE; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	salt_t *p = salt;
	return p->iterations;
}
#endif

struct fmt_main fmt_ocl_cryptsha1 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
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
