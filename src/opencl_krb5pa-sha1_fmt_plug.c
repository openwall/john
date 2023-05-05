/*
 * Kerberos 5 "PA ENC TIMESTAMP" by magnum & Dhiru
 *
 * Pcap file -> input file:
 * 1. tshark -r capture.pcapng -T pdml  > ~/capture.pdml
 * 2. krbng2john.py ~/capture.pdml > krb5.in
 * 3. Run john on krb5.in
 *
 * http://www.ietf.org/rfc/rfc4757.txt
 * http://www.securiteam.com/windowsntfocus/5BP0H0A6KM.html
 *
 * Input format is 'user:$krb5pa$etype$user$realm$salt$timestamp+checksum'
 *
 * NOTE: Checksum implies last 12 bytes of PA_ENC_TIMESTAMP value in AS-REQ
 * packet.
 *
 * Default Salt: realm + user
 *
 * AES-256 encryption & decryption of AS-REQ timestamp in Kerberos v5
 * See the following RFC for more details about the crypto & algorithms used:
 *
 * RFC3961 - Encryption and Checksum Specifications for Kerberos 5
 * RFC3962 - Advanced Encryption Standard (AES) Encryption for Kerberos 5
 *
 * march 09 / kevin devine <wyse101 0x40 gmail.com>
 *
 * This software is
 * Copyright (c) 2012-2018 magnum
 * Copyright (c) 2012 Dhiru Kholia (dhiru at openwall.com)
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_krb5pa_sha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_krb5pa_sha1);
#else

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "common.h"
#include "unicode.h"
#include "config.h"
#include "loader.h"
#include "opencl_common.h"
#define MAX_OUTLEN 32
#include "../run/opencl/opencl_pbkdf2_hmac_sha1.h"

#define FORMAT_LABEL            "krb5pa-sha1-opencl"
#define FORMAT_NAME             "Kerberos 5 AS-REQ Pre-Auth etype 17/18" /* aes-cts-hmac-sha1-96 */
#define FORMAT_TAG              "$krb5pa$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "PBKDF2-SHA1 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define BINARY_SIZE             12
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#define MAX_SALTLEN             52
#define MAX_REALMLEN            MAX_SALTLEN
#define MAX_USERLEN             MAX_SALTLEN
#define TIMESTAMP_SIZE          44
#define CHECKSUM_SIZE           BINARY_SIZE
#define TOTAL_LENGTH            (14 + 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) + MAX_REALMLEN + MAX_USERLEN + MAX_SALTLEN)

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

/* This handles all sizes */
#define GETPOS(i, index)        (((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)
/* This is faster but can't handle size 3 */
//#define GETPOS(i, index)      (((index) & (ocl_v_width - 1)) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static struct fmt_tests tests[] = {
	/* etype 17 hash obtained using MiTM etype downgrade attack */
	{"$krb5pa$17$user1$EXAMPLE.COM$$c5461873dc13665771b98ba80be53939e906d90ae1ba79cf2e21f0395e50ee56379fbef4d0298cfccfd6cf8f907329120048fd05e8ae5df4", "openwall"},
	{"$krb5pa$18$user1$EXAMPLE.COM$$2a0e68168d1eac344da458599c3a2b33ff326a061449fcbc242b212504e484d45903c6a16e2d593912f56c93883bf697b325193d62a8be9c", "openwall"},
	{"$krb5pa$18$user1$EXAMPLE.COM$$a3918bd0381107feedec8db0022bdf3ac56e534ed54d13c62a7013a47713cfc31ef4e7e572f912fa4164f76b335e588bf29c2d17b11c5caa", "openwall"},
	{"$krb5pa$18$l33t$EXAMPLE.COM$$98f732b309a1d7ef2355a974842a32894d911e97150f5d57f248e1c2632fbd3735c5f156532ccae0341e6a2d779ca83a06021fe57dafa464", "openwall"},
	{"$krb5pa$18$aduser$AD.EXAMPLE.COM$$64dfeee04be2b2e0423814e0df4d0f960885aca4efffe6cb5694c4d34690406071c4968abd2c153ee42d258c5e09a41269bbcd7799f478d3", "password@123"},
	{"$krb5pa$18$aduser$AD.EXAMPLE.COM$$f94f755a8b4493d925094a4eb1cec630ac40411a14c9733a853516fe426637d9daefdedc0567e2bb5a83d4f89a0ad1a4b178662b6106c0ff", "password@12345678"},
	{"$krb5pa$18$aduser$AD.EXAMPLE.COM$AD.EXAMPLE.COMaduser$f94f755a8b4493d925094a4eb1cec630ac40411a14c9733a853516fe426637d9daefdedc0567e2bb5a83d4f89a0ad1a4b178662b6106c0ff", "password@12345678"},
	{NULL},
};

static cl_mem mem_in, mem_dk, mem_out, mem_salt, mem_state, mem_cleartext;
static cl_mem pinned_in, pinned_out;
static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final, pa_sha1_final;
static struct fmt_main *self;

static struct custom_salt {
	int type;
	int etype;
	unsigned char realm[64];
	unsigned char user[64];
	unsigned char salt[64]; /* realm + user */
	unsigned char ct[TIMESTAMP_SIZE];
} *cur_salt;

typedef struct {
	pbkdf2_salt pbkdf2;
	uint32_t etype;
	unsigned char ct[(TIMESTAMP_SIZE + 63) / 64 * 64];
} pa_sha1_salt;

typedef struct {
	uint32_t hash[BINARY_SIZE / sizeof(uint32_t)];
} krb5pa_out;

static size_t key_buf_size;
static unsigned int *inbuffer;
static pa_sha1_salt currentsalt;
static krb5pa_out *output;

static int new_keys;

#define ITERATIONS		(4096 - 1)
#define HASH_LOOPS		105 // Must be made from factors 3, 3, 5, 7, 13
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"xfer: ",  ", init: ",  ", loop: ",  ", final: ",  ", pa_sha1: ",  ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_init);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_loop));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pbkdf2_final));
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, pa_sha1_final));
	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	gws *= ocl_v_width;

	key_buf_size = PLAINTEXT_LENGTH * gws;

	// Allocate memory
	pinned_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned in");
	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	inbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, key_buf_size, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	pinned_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(krb5pa_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned out");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(krb5pa_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_out, CL_TRUE, CL_MAP_READ, 0, sizeof(krb5pa_out) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	mem_dk = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem dk");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(pa_sha1_salt), &currentsalt, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");

	mem_cleartext = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (TIMESTAMP_SIZE + 63) / 64 * 64 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem cleartext");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 1, sizeof(mem_dk), &mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pa_sha1_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pa_sha1_final, 1, sizeof(mem_dk), &mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pa_sha1_final, 2, sizeof(mem_cleartext), &mem_cleartext), "Error while setting mem_cleartext kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pa_sha1_final, 3, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (mem_state) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_in, inbuffer, 0, NULL, NULL), "Error Unmapping mem in");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_out, output, 0, NULL, NULL), "Error Unmapping mem out");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_in), "Release pinned_in");
		HANDLE_CLERROR(clReleaseMemObject(pinned_out), "Release pinned_out");
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem_in");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");
		HANDLE_CLERROR(clReleaseMemObject(mem_dk), "Release mem_dk");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_cleartext), "Release mem_cleartext");
		mem_state = NULL;
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(pa_sha1_final), "Release Kernel");

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
		         "-DHASH_LOOPS=%u -DITERATIONS=%u -DMAX_OUTLEN=%u "
		         "-DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
		         HASH_LOOPS, ITERATIONS, MAX_OUTLEN,
		         PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/opencl/krb5_kernel.cl", gpu_id,
		            build_opts);

		pbkdf2_init = clCreateKernel(program[gpu_id], "pbkdf2_init", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		crypt_kernel = pbkdf2_loop = clCreateKernel(program[gpu_id], "pbkdf2_loop", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pbkdf2_final = clCreateKernel(program[gpu_id], "pbkdf2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
		pa_sha1_final = clCreateKernel(program[gpu_id], "pa_sha1_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 2 * HASH_LOOPS, split_events,
	                       warn, 2, self, create_clobj,
	                       release_clobj,
	                       ocl_v_width * sizeof(pbkdf2_state), 0, db);

	//Auto tune execution from shared/included code.
	autotune_run(self, 4 * ITERATIONS + 4, 0, 200);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *data = ciphertext;
	int type, saltlen = 0;

	// tag is mandatory
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	data += FORMAT_TAG_LEN;

	// etype field, 17 or 18
	p = strchr(data, '$');
	if (!p || p - data != 2)
		return 0;
	type = atoi(data);
	if (type < 17 || type > 18)
		return 0;
	data = p + 1;

	// user field
	p = strchr(data, '$');
	if (!p || p - data > MAX_USERLEN)
		return 0;
	saltlen += p - data;
	data = p + 1;

	// realm field
	p = strchr(data, '$');
	if (!p || p - data > MAX_REALMLEN)
		return 0;
	saltlen += p - data;
	data = p + 1;

	// salt field
	p = strchr(data, '$');
	if (!p)
		return 0;
	// if salt is empty, realm.user is used instead
	if (p - data)
		saltlen = p - data;
	data = p + 1;

	// We support a max. total salt length of 52.
	// We could opt to emit a warning if rejected here.
	if (saltlen > MAX_SALTLEN) {
		static int warned = 0;

		if (!ldr_in_pot)
		if (!warned++)
			fprintf(stderr, "%s: One or more hashes rejected due to salt length limitation\n", FORMAT_LABEL);

		return 0;
	}


	// 56 bytes (112 hex chars) encrypted timestamp + checksum
	if (strlen(data) != 2 * (TIMESTAMP_SIZE + CHECKSUM_SIZE) ||
	    strspn(data, HEXCHARS_all) != strlen(data))
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "$");
	cs.etype = atoi(p);
	p = strtokm(NULL, "$");
	if (p[-1] == '$')
		cs.user[0] = 0;
	else {
		strcpy((char*)cs.user, p);
		p = strtokm(NULL, "$");
	}
	if (p[-1] == '$')
		cs.realm[0] = 0;
	else {
		strcpy((char*)cs.realm, p);
		p = strtokm(NULL, "$");
	}
	if (p[-1] == '$') {
		strcpy((char*)cs.salt, (char*)cs.realm);
		strcat((char*)cs.salt, (char*)cs.user);
	} else {
		strcpy((char*)cs.salt, p);
		p = strtokm(NULL, "$");
	}
	for (i = 0; i < TIMESTAMP_SIZE; i++)
		cs.ct[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
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

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[TOTAL_LENGTH + 1];
	char in[TOTAL_LENGTH + 1];
	char salt[MAX_SALTLEN + 1];
	char *data;
	char *e, *u, *r, *s, *tc;

	strnzcpy(in, ciphertext, sizeof(in));

	tc = strrchr(in, '$'); *tc++ = 0;
	s = strrchr(in, '$'); *s++ = 0;
	r = strrchr(in, '$'); *r++ = 0;
	u = strrchr(in, '$'); *u++ = 0;
	e = in + 8;

	/* Default salt is user.realm */
	if (!*s) {
		snprintf(salt, sizeof(salt), "%s%s", r, u);
		s = salt;
	}
	snprintf(out, sizeof(out), "%s%s$%s$%s$%s$%s", FORMAT_TAG, e, u, r, s, tc);

	data = out + strlen(out) - 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) - 1;
	strlwr(data);

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

	p = strrchr(ciphertext, '$') + 1 + TIMESTAMP_SIZE * 2; /* skip to checksum field */
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return output[index].hash[0] & PH_MASK_0; }
static int get_hash_1(int index) { return output[index].hash[0] & PH_MASK_1; }
static int get_hash_2(int index) { return output[index].hash[0] & PH_MASK_2; }
static int get_hash_3(int index) { return output[index].hash[0] & PH_MASK_3; }
static int get_hash_4(int index) { return output[index].hash[0] & PH_MASK_4; }
static int get_hash_5(int index) { return output[index].hash[0] & PH_MASK_5; }
static int get_hash_6(int index) { return output[index].hash[0] & PH_MASK_6; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	currentsalt.pbkdf2.length = strlen((char*)cur_salt->salt);
	currentsalt.pbkdf2.iterations = 4096;
	currentsalt.pbkdf2.outlen = (cur_salt->etype == 17) ? 16 : 32;

	currentsalt.etype = cur_salt->etype;
	memcpy(currentsalt.ct, cur_salt->ct, TIMESTAMP_SIZE);
	memcpy(currentsalt.pbkdf2.salt, cur_salt->salt, currentsalt.pbkdf2.length);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(pa_sha1_salt), &currentsalt, 0, NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, j;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_KPC_MULTIPLE(count, local_work_size);

	scalar_gws = gws * ocl_v_width;

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0, key_buf_size, inbuffer, 0, NULL, multi_profilingEvent[0]), "Copy data to gpu");
		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_init, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[1]), "Run initial kernel");

	for (j = 0; j < (ocl_autotune_running ? 1 : ((currentsalt.pbkdf2.outlen + 19) / 20)); j++) {
		for (i = 0; i < (ocl_autotune_running ? 1 : ITERATIONS / HASH_LOOPS); i++) {
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_loop, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "Run loop kernel");
			BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
			opencl_process_event();
		}

		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pbkdf2_final, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[3]), "Run final pbkdf2 kernel");
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pa_sha1_final, 1, NULL, &scalar_gws, lws, 0, NULL, multi_profilingEvent[4]), "Run final kernel (SHA1)");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(krb5pa_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[5]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == output[index].hash[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, output[index].hash, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static unsigned int etype(void *salt)
{
	return ((struct custom_salt *)salt)->etype;
}

struct fmt_main fmt_opencl_krb5pa_sha1 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		{
			"etype"
		},
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
		{
			etype
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
