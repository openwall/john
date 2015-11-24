/*
 * MS Office 97-2003 cracker for JtR.
 *
 * This software is Copyright (c) 2014, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define FORMAT_STRUCT fmt_ocl_oldoff

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main FORMAT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FORMAT_STRUCT);
#else

#include <string.h>
#include <errno.h>

#include "common-opencl.h"
#include "stdint.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "dyna_salt.h"

#define FORMAT_LABEL		"oldoffice-opencl"
#define FORMAT_NAME		"MS Office <= 2003"
#define ALGORITHM_NAME		"MD5/SHA1 RC4 OpenCL"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1000 /* Use 0 for benchmarking w/ mitm */
#define PLAINTEXT_LENGTH	19 //* 19 is leanest, 24, 28, 31, max. 51 */
#define BINARY_SIZE		0
#define BINARY_ALIGN		MEM_ALIGN_NONE
#define SALT_SIZE		sizeof(dyna_salt*)
#define SALT_ALIGN		MEM_ALIGN_WORD

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define CIPHERTEXT_LENGTH	(TAG_LEN + 120)
#define FORMAT_TAG		"$oldoffice$"
#define TAG_LEN			(sizeof(FORMAT_TAG) - 1)

static struct fmt_tests oo_tests[] = {
	{"$oldoffice$1*de17a7f3c3ff03a39937ba9666d6e952*2374d5b6ce7449f57c9f252f9f9b53d2*e60e1185f7aecedba262f869c0236f81", "test"},
	{"$oldoffice$0*e40b4fdade5be6be329c4238e2099b8a*259590322b55f7a3c38cb96b5864e72d*2e6516bfaf981770fe6819a34998295d", "123456789012345"},
	{"$oldoffice$4*163ae8c43577b94902f58d0106b29205*87deff24175c2414cb1b2abdd30855a3*4182446a527fe4648dffa792d55ae7a15edfc4fb", "Google123"},
	/* Meet-in-the-middle candidate produced with oclHashcat -m9710 */
	/* Real pw is "hashcat", one collision is "zvDtu!" */
	{"", "zvDtu!", {"", "$oldoffice$1*d6aabb63363188b9b73a88efb9c9152e*afbbb9254764273f8f4fad9a5d82981f*6f09fd2eafc4ade522b5f2bee0eaf66d","f2ab1219ae"} },
#if PLAINTEXT_LENGTH >= 24
	/* 2003-RC4-40bit-MS-Base-Crypto-1.0_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*9f32522fe9bcb69b12f39d3c24b39b2f*fac8b91a8a578468ae7001df4947558f*f2e267a5bea45736b52d6d1051eca1b935eabf3a", "myhovercraftisfullofeels"},
	/* Test-RC4-40bit-MS-Base-DSS_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*095b777a73a10fb6bcd3e48d50f8f8c5*36902daab0d0f38f587a84b24bd40dce*25db453f79e8cbe4da1844822b88f6ce18a5edd2", "myhovercraftisfullofeels"},
	/* 2003-RC4-40bit-MS-Base-DH-SChan_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*284bc91cb64bc847a7a44bc7bf34fb69*1f8c589c6fcbd43c42b2bc6fff4fd12b*2bc7d8e866c9ea40526d3c0a59e2d37d8ded3550", "myhovercraftisfullofeels"},
	/* Test-RC4-128bit-MS-Strong-Crypto_myhovercraftisfullofeels_.doc */
	{"$oldoffice$4*a58b39c30a06832ee664c1db48d17304*986a45cc9e17e062f05ceec37ec0db17*fe0c130ef374088f3fec1979aed4d67459a6eb9a", "myhovercraftisfullofeels"},
	/* 2003-RC4-40bit-MS-Base-1.0_myhovercraftisfullofeels_.xls */
	{"$oldoffice$3*f426041b2eba9745d30c7949801f7d3a*888b34927e5f31e2703cc4ce86a6fd78*ff66200812fd06c1ba43ec2be9f3390addb20096", "myhovercraftisfullofeels"},
#endif
	/* the following hash was extracted from Proc2356.ppt (manually + by oldoffice2john.py */
	{"$oldoffice$3*DB575DDA2E450AB3DFDF77A2E9B3D4C7*AB183C4C8B5E5DD7B9F3AF8AE5FFF31A*B63594447FAE7D4945D2DAFD113FD8C9F6191BF5", "crypto"},
	{"$oldoffice$3*3fbf56a18b026e25815cbea85a16036c*216562ea03b4165b54cfaabe89d36596*91308b40297b7ce31af2e8c57c6407994b205590", "openwall"},
	{NULL}
};

extern volatile int bench_running;

typedef struct {
	dyna_salt dsalt;
	int type;
	unsigned char salt[16];
	unsigned char verifier[16]; /* or encryptedVerifier */
	unsigned char verifierHash[20];  /* or encryptedVerifierHash */
	unsigned int has_mitm;
	unsigned char mitm[8]; /* Meet-in-the-middle hint, if we have one */
} custom_salt;

static struct {
	int ct_hash;
	unsigned char mitm[10];
} mitm_catcher;

static custom_salt cs;
static custom_salt *cur_salt = &cs;

typedef struct {
	uint len;
	ushort password[PLAINTEXT_LENGTH + 1];
} mid_t;

static char *saved_key;
static int any_cracked;
static int new_keys;

static int max_len = PLAINTEXT_LENGTH;

static unsigned int *saved_idx, key_idx;
static unsigned int *cracked;
static size_t key_offset, idx_offset;
static cl_mem cl_saved_key, cl_saved_idx, cl_salt, cl_mid_key, cl_result;
static cl_mem pinned_key, pinned_idx, pinned_result, cl_benchmark;
static cl_kernel oldoffice_utf16, oldoffice_md5, oldoffice_sha1;
static struct fmt_main *self;

#define STEP			0
#define SEED			1024

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xP: ",  ", xI: ",  ", enc: ",  ", md5+rc4: ",  ", xR: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, oldoffice_utf16);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0,
	                                                 oldoffice_md5));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0,
	                                                 oldoffice_sha1));
	s = MIN(s, 64);
	return s;
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, max_len * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, max_len * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, max_len * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * (gws + 1), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_idx");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(unsigned int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(unsigned int) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	cracked = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(unsigned int) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping cracked");

	cl_benchmark = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(bench_running), NULL, &ret_code);

	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(cs), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");

	cl_mid_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(mid_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device-only buffer");

	HANDLE_CLERROR(clSetKernelArg(oldoffice_utf16, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_utf16, 1, sizeof(cl_mem), (void*)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_utf16, 2, sizeof(cl_mem), (void*)&cl_mid_key), "Error setting argument 2");

	HANDLE_CLERROR(clSetKernelArg(oldoffice_md5, 0, sizeof(cl_mem), (void*)&cl_mid_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_md5, 1, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_md5, 2, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_md5, 3, sizeof(cl_mem), (void*)&cl_benchmark), "Error setting argument 3");

	HANDLE_CLERROR(clSetKernelArg(oldoffice_sha1, 0, sizeof(cl_mem), (void*)&cl_mid_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_sha1, 1, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_sha1, 2, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(oldoffice_sha1, 3, sizeof(cl_mem), (void*)&cl_benchmark), "Error setting argument 3");
}

static void release_clobj(void)
{
	if (cl_mid_key) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, cracked, 0, NULL, NULL), "Error Unmapping cracked");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_salt), "Release salt buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_mid_key), "Release state buffer");

		cl_mid_key = NULL;
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(oldoffice_utf16), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(oldoffice_md5), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(oldoffice_sha1), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;

	opencl_prepare_dev(gpu_id);

	if (options.target_enc == UTF_8)
		max_len = self->params.plaintext_length =
			MIN(125, 3 * PLAINTEXT_LENGTH);
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		size_t gws_limit = 4 << 20;
		char build_opts[96];

		snprintf(build_opts, sizeof(build_opts),
#if !NT_FULL_UNICODE
		         "-DUCS_2 "
#endif
		         "-D%s -DPLAINTEXT_LENGTH=%u",
		         cp_id2macro(options.target_enc), PLAINTEXT_LENGTH);
		opencl_init("$JOHN/kernels/oldoffice_kernel.cl", gpu_id, build_opts);

		/* create kernels to execute */
		oldoffice_utf16 = clCreateKernel(program[gpu_id], "oldoffice_utf16", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		crypt_kernel = oldoffice_md5 =
			clCreateKernel(program[gpu_id], "oldoffice_md5", &ret_code);
		oldoffice_sha1 =
			clCreateKernel(program[gpu_id], "oldoffice_sha1", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 3,
		                       self, create_clobj, release_clobj,
		                       2 * sizeof(mid_t), gws_limit);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, gws_limit, 1000000000);
	}
}

/* Based on ldr_cracked_hash from loader.c */
#define HASH_LOG 30
#define HASH_SIZE (1 << HASH_LOG)
static int hex_hash(char *ciphertext)
{
	unsigned int hash, extra;
	unsigned char *p = (unsigned char *)ciphertext;

	hash = p[0] | 0x20; /* ASCII case insensitive */
	if (!hash)
		goto out;
	extra = p[1] | 0x20;
	if (!extra)
		goto out;

	p += 2;
	while (*p) {
		hash <<= 1; extra <<= 1;
		hash += p[0] | 0x20;
		if (!p[1]) break;
		extra += p[1] | 0x20;
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> HASH_LOG;
			extra ^= extra >> (HASH_LOG - 1);
			hash &= HASH_SIZE - 1;
		}
	}

	hash -= extra;
	hash ^= extra << (HASH_LOG / 2);
	hash ^= hash >> HASH_LOG;
	hash &= HASH_SIZE - 1;
out:
	return hash;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int type;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		return 0;
	if (strlen(ciphertext) > CIPHERTEXT_LENGTH)
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += TAG_LEN;
	if (!(ptr = strtokm(ctcopy, "*"))) /* type */
		goto error;
	type = atoi(ptr);
	if (type < 0 || type > 4)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (hexlen(ptr) != 32)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier */
		goto error;
	if (hexlen(ptr) != 32)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier hash */
		goto error;
	if (type < 3 && hexlen(ptr) != 32)
		goto error;
	else if (type >= 3 && hexlen(ptr) != 40)
		goto error;
/*
 * Deprecated field: mitm hash (40-bit RC4). The new way to put it is in the
 * uid field, like hashcat's example hash.
 */
	if (type <= 3 && (ptr = strtokm(NULL, "*"))) {
		if (hexlen(ptr) != 10)
			goto error;
	}
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

/* uid field may contain a meet-in-the-middle hash */
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	if (split_fields[0] && valid(split_fields[0], self) && split_fields[1] &&
	    hexlen(split_fields[1]) == 10) {
		mitm_catcher.ct_hash = hex_hash(split_fields[0]);
		memcpy(mitm_catcher.mitm, split_fields[1], 10);
		return split_fields[0];
	}
	else if (valid(split_fields[1], self) && split_fields[2] &&
	         hexlen(split_fields[2]) == 10) {
		mitm_catcher.ct_hash = hex_hash(split_fields[1]);
		memcpy(mitm_catcher.mitm, split_fields[2], 10);
	}
	return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH];

	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);

	return out;
}

static void *get_salt(char *ciphertext)
{
	static void *ptr;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LEN;	/* skip over "$oldoffice$" */
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.verifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	if(cs.type < 3) {
		for (i = 0; i < 16; i++)
			cs.verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	else {
		for (i = 0; i < 20; i++)
			cs.verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if ((p = strtokm(NULL, "*"))) { /* Deprecated field */
		cs.has_mitm = 1;
		for (i = 0; i < 5; i++)
			cs.mitm[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	} else
	if (hex_hash(ciphertext) == mitm_catcher.ct_hash) {
		cs.has_mitm = 1;
		for (i = 0; i < 5; i++)
			cs.mitm[i] = atoi16[ARCH_INDEX(mitm_catcher.mitm[i * 2])] * 16
				+ atoi16[ARCH_INDEX(mitm_catcher.mitm[i * 2 + 1])];
	} else
		cs.has_mitm = 0;

	MEM_FREE(keeptr);

	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(custom_salt, type);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(custom_salt, type, has_mitm, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_copy(&cs, sizeof(custom_salt), MEM_ALIGN_WORD);
	return &ptr;
}

static char *source(char *source, void *binary)
{
	static char Buf[CIPHERTEXT_LENGTH];
	unsigned char *cpi, *cp = (unsigned char*)Buf;
	int i, len;

	cp += sprintf(Buf, "%s%d*", FORMAT_TAG, cur_salt->type);

	cpi = cur_salt->salt;
	for (i = 0; i < 16; i++) {
		*cp++ = itoa16[*cpi >> 4];
		*cp++ = itoa16[*cpi & 0xf];
		cpi++;
	}
	*cp++ = '*';

	cpi = cur_salt->verifier;
	for (i = 0; i < 16; i++) {
		*cp++ = itoa16[*cpi >> 4];
		*cp++ = itoa16[*cpi & 0xf];
		cpi++;
	}
	*cp++ = '*';

	len = (cur_salt->type < 3) ? 16 : 20;
	cpi = cur_salt->verifierHash;
	for (i = 0; i < len; i++) {
		*cp++ = itoa16[*cpi >> 4];
		*cp++ = itoa16[*cpi & 0xf];
		cpi++;
	}
	*cp = 0;

	if (cur_salt->has_mitm && !bench_running) {
		static int last;
		char out[11];

		if (last != hex_hash(Buf)) {
			last = hex_hash(Buf);
			cpi = cur_salt->mitm;
			for (i = 0; i < 5; i++) {
				out[2 * i + 0] = itoa16[*cpi >> 4];
				out[2 * i + 1] = itoa16[*cpi & 0xf];
				cpi++;
			}
			out[10] = 0;
			fprintf(stderr, "MITM key: %s\n", out);
		}
	}

	return Buf;
}

static void set_salt(void *salt)
{
	cur_salt = *(custom_salt**)salt;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_benchmark, CL_FALSE, 0, sizeof(bench_running), (void*)&bench_running, 0, NULL, NULL), "Failed transferring salt");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, CL_FALSE, 0, sizeof(cs), cur_salt, 0, NULL, NULL), "Failed transferring salt");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int index;
	const int count = *pcount;
	size_t lws;

	/* kernel is made for lws 64, using local memory */
	lws = local_work_size ? local_work_size : 64;

	/* Don't do more than requested */
	global_work_size = (count + lws - 1) / lws * lws;

	//fprintf(stderr, "%s(%d) lws "Zu" gws "Zu" kidx %u m %d k %d\n", __FUNCTION__, count, lws, global_work_size, key_idx, m, new_keys);

	if (new_keys || ocl_autotune_running) {
		/* Self-test kludge */
		if (idx_offset > 4 * (global_work_size + 1))
			idx_offset = 0;

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, multi_profilingEvent[0]), "Failed transferring keys");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, multi_profilingEvent[1]), "Failed transferring index");
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], oldoffice_utf16, 1, NULL, &global_work_size, &lws, 0, NULL, multi_profilingEvent[2]), "Failed running first kernel");

		new_keys = 0;
	}

	if (cur_salt->type < 3) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], oldoffice_md5, 1, NULL, &global_work_size, &lws, 0, NULL, multi_profilingEvent[3]), "Failed running md5 kernel");
	} else {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], oldoffice_sha1, 1, NULL, &global_work_size, &lws, 0, NULL, multi_profilingEvent[3]), "Failed running sha1 kernel");
	}

	if (cur_salt->has_mitm || cur_salt->type > 3 || bench_running) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, sizeof(unsigned int) * global_work_size, cracked, 0, NULL, multi_profilingEvent[4]), "failed reading results back");

		any_cracked = 0;

		for (index = 0; index < count; index++)
		if (cracked[index]) {
			any_cracked = 1;
			break;
		}
	} else {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_salt, CL_TRUE, 0, sizeof(cs), cur_salt, 0, NULL, NULL), "Failed transferring salt");
		if ((any_cracked = cur_salt->has_mitm))
			BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, sizeof(unsigned int) * global_work_size, cracked, 0, NULL, multi_profilingEvent[4]), "failed reading results back");
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

static void clear_keys(void)
{
	key_idx = 0;
	saved_idx[0] = 0;
	key_offset = 0;
	idx_offset = 0;
}

static void set_key(char *key, int index)
{
	while (*key)
		saved_key[key_idx++] = *key++;

	saved_idx[index + 1] = key_idx;
	new_keys = 1;

	/* Early partial transfer to GPU */
	if (index && !(index & (256*1024 - 1))) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		key_offset = key_idx;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * index - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, NULL), "Failed transferring index");
		idx_offset = 4 * index;
		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		new_keys = 0;
	}
}

static char *get_key(int index)
{
	static UTF16 u16[PLAINTEXT_LENGTH + 1];
	static UTF8 out[3 * PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index + 1] - saved_idx[index];
	UTF8 *key = (UTF8*)&saved_key[saved_idx[index]];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	/* Ensure we truncate just like the GPU conversion does */
	enc_to_utf16(u16, PLAINTEXT_LENGTH, (UTF8*)out, len);
	return (char*)utf16_to_enc(u16);
}

static unsigned int oo_hash_type(void *salt)
{
	custom_salt *my_salt;

	my_salt = *(custom_salt**)salt;
	return (unsigned int) my_salt->type;
}

struct fmt_main FORMAT_STRUCT = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_SPLIT_UNIFIES_CASE | FMT_DYNA_SALT,
		{
			"hash type",
		},
		oo_tests
	}, {
		init,
		done,
		reset,
		prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
		{
			oo_hash_type,
		},
		source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
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
