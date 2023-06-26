/*
 * JtR format to crack "AS-REP" messages.
 *
 * This software is
 * Copyright (c) 2017 Dhiru Kholia (dhiru at openwall.com),
 * Copyright (c) 2018 magnum,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is based on krb5_asrep_fmt_plug.c and opencl_krb5pa-sha1_fmt_plug.c
 * files.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_krb5_asrep_aes;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_krb5_asrep_aes);
#else

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "common.h"
#include "config.h"
#include "aes.h"
#include "krb5_common.h"
#include "krb5_asrep_common.h"
#include "opencl_common.h"
#define MAX_OUTLEN 32
#include "../run/opencl/opencl_pbkdf2_hmac_sha1.h"
#include "hmac_sha.h"

#define FORMAT_LABEL            "krb5asrep-aes-opencl"
#define FORMAT_NAME             "Kerberos 5 AS-REP etype 17/18"
#define ALGORITHM_NAME          "PBKDF2-SHA1 OpenCL"

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define GETPOS(i, index)        (((index) % ocl_v_width) * 4 + ((i) & ~3U) * ocl_v_width + (((i) & 3) ^ 3) + ((index) / ocl_v_width) * 64 * ocl_v_width)

static struct fmt_tests tests[] = {
	// hero-17-abcd.pcap
	{"$krb5asrep$17$EXAMPLE.COMhero$4e7c79214fd330b2e505a4c75e257e4686029136d54f92ce91bb69d5ffc064e64e925b3ae8bc1df431c74ccaf2075cb4a1a32151b0848964e147bf6f8e4a50caa7931faad50433991e016e312c70ad9007e38166f8df39eda3edd2445cce757e062d0919e663a67eb9fdb472b2a840cf521f18bd794947bcc0c0c6394cc5a60b860c963640867e623732206e7bf904d3b066a17b6f4ea3fd6d74f110ee80052e5297f7a19aaec22e22d582d183d43d6ca1792da187a3a182d1f479c5b4692841ccd701a63735d64584c4f8d199d67876dae5181f4eadfe75e454d0587d0953d7e16cb1b63265da6188b10c1746a2e83c41707bd03fcb2d460d1c6802826a0347b5ee7cdbe5384acad139b4395928bd$7ed0277ba9b853008cc62abe", "abcd"},
	// AS-REP-with-PA-unsupported-openwall.pcap
	{"$krb5asrep$18$EXAMPLE.COMlulu$b49aa3de9314e2d8daafe323f2e84b9a4ddc361d99bf3bf3a99102f8bff5368bdefc9d7ae090532fdad2a508ac1271bfbd17363b3a1da23bf9db324a24c238634e3ab28d7f4eca009b4c3953c882f5a4206458a0b4238f3e538308d7339382f38412bbfe7b71e269274526edf7b802ea1ecdf7b8c17f9502b7a6750313329a68b8f8a2d039c8dfe74b9ead98684cfc86e5d0f77c18ba05718b01c33831db17191a0e77f9cef998bbb66a794915b03c94725aceabe9e2b5e25b665a37b5dd3a59a5552bd779dd5f0ae7295d232194eec1ca1ba0324bdc836ba623117e59fcfedab45a86d76d2c768341d327c035a1f5c756cfc06d76b6f7ea31c7a8e782eb48de0aab2fb373ffc2352c4192838323f8$a5245c7f39480a840da0e4c6", "openwall"},
	// luser-18-12345678.pcap
	{"$krb5asrep$18$EXAMPLE.COMluser$42e34732112be6cec1532177a6c93af5ec3b2fc7da106c004d6d89ddcb4131092aecbead3e9f30d07b593f4c7adc6478ab50b80fee07db3531471f5f1986c8882c45fef784258f9d43195108b83a74f6dcae1beed179c356c0da4e2d69f122efc579fd207d2b2b241a6c275997f2ec6fec95573a7518cb8b8528d932cc14186e4c5d46cef1eed4f2924ea316d80a62b0bcd98592a11eb69c04ef43b63aeae35e9f8bd8f842d0c9c33d768cd33c55914c2a1fb2f7c640b7270cf2274993c0ce4f413aac8e9d7a231c70dd0c6f8b9c16b47a90fae8d68982a66aa58e2eb8dde93d3504e87b5d4e33827c2aa501ed63544c0578032f395205c63b030cccc699aafb9132692c79a154d645fe83927b0eda$420973360c2e907b9053f1db", "12345678"},
	{NULL}
};

static cl_mem mem_in, mem_dk, mem_out, mem_salt, mem_state, mem_plaintext, mem_edata2;
static cl_mem pinned_in, pinned_out;
static cl_kernel pbkdf2_init, pbkdf2_loop, pbkdf2_final, asrep_final;
static struct fmt_main *self;

static struct custom_salt *cur_salt;

typedef struct {
	pbkdf2_salt pbkdf2;
	uint32_t etype;
	uint32_t edata2len;
	uint8_t  edata1[16];
	// edata2 is a separate __global buffer of variable size
} asrep_salt;

typedef struct {
	unsigned int cracked;
} asrep_out;

static size_t key_buf_size;
static unsigned int *inbuffer;
static asrep_salt currentsalt;
static asrep_out *output;
static int edata_size = 4096;
static int new_keys;

#define ITERATIONS		(4096 - 1)
#define HASH_LOOPS		105 // Must be made from factors 3, 3, 5, 7, 13
#define STEP			0
#define SEED			128

static const char * warn[] = {
	"xfer: ",  ", init: ",  ", loop: ",  ", final: ",  ", asrep: ",  ", res xfer: "
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
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, asrep_final));
	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	gws *= ocl_v_width;

	key_buf_size = 64 * gws;

	// Allocate memory
	pinned_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned in");
	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, key_buf_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem in");
	inbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, key_buf_size, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	pinned_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(asrep_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating pinned out");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, sizeof(asrep_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem out");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_out, CL_TRUE, CL_MAP_READ, 0, sizeof(asrep_out) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory");

	mem_dk = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_out) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem dk");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, sizeof(pbkdf2_state) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem_state");

	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(asrep_salt), &currentsalt, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem setting");

	mem_edata2 = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, edata_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem edata2");

	mem_plaintext = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, edata_size * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error allocating mem plaintext");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 1, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_init, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_loop, 0, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 1, sizeof(mem_dk), &mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pbkdf2_final, 2, sizeof(mem_state), &mem_state), "Error while setting mem_state kernel argument");

	HANDLE_CLERROR(clSetKernelArg(asrep_final, 0, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(asrep_final, 1, sizeof(mem_dk), &mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(asrep_final, 2, sizeof(mem_edata2), &mem_edata2), "Error while setting mem_edata2 kernel argument");
	HANDLE_CLERROR(clSetKernelArg(asrep_final, 3, sizeof(mem_plaintext), &mem_plaintext), "Error while setting mem_plaintext kernel argument");
	HANDLE_CLERROR(clSetKernelArg(asrep_final, 4, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (mem_edata2) {
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
		HANDLE_CLERROR(clReleaseMemObject(mem_edata2), "Release mem_edata2");
		HANDLE_CLERROR(clReleaseMemObject(mem_plaintext), "Release mem_plaintext");
		mem_edata2 = NULL;
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(pbkdf2_init), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_loop), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(pbkdf2_final), "Release Kernel");
		HANDLE_CLERROR(clReleaseKernel(asrep_final), "Release Kernel");

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
		asrep_final = clCreateKernel(program[gpu_id], "asrep_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel");
	}

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 2 * HASH_LOOPS, split_events,
	                       warn, 2, self, create_clobj,
	                       release_clobj,
	                       edata_size, 0, db);

	//Auto tune execution from shared/included code.
	autotune_run(self, 4 * ITERATIONS + 4, 0, 200);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return krb5_asrep_valid(ciphertext, self, 0);
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

static void set_salt(void *salt)
{
	size_t buf_size;

	cur_salt = *((struct custom_salt **)salt);
	buf_size = (cur_salt->edata2len + 31) / 32 * 32;

	if (buf_size > edata_size) {
		edata_size = buf_size;
		HANDLE_CLERROR(clReleaseMemObject(mem_plaintext), "Release mem_plaintext");
		HANDLE_CLERROR(clReleaseMemObject(mem_edata2), "Release mem_edata2");
		mem_plaintext = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, edata_size * global_work_size, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error allocating mem plaintext");

		mem_edata2 = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, edata_size, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error allocating mem edata2");

		HANDLE_CLERROR(clSetKernelArg(asrep_final, 2, sizeof(mem_edata2), &mem_edata2), "Error while setting mem_edata2 kernel argument");
		HANDLE_CLERROR(clSetKernelArg(asrep_final, 3, sizeof(mem_plaintext), &mem_plaintext), "Error while setting mem_plaintext kernel argument");
	}
	currentsalt.pbkdf2.length = strlen((char*)cur_salt->salt);
	currentsalt.pbkdf2.iterations = 4096;
	currentsalt.pbkdf2.outlen = (cur_salt->etype == 17) ? 16 : 32;
	currentsalt.etype = cur_salt->etype;
	currentsalt.edata2len = cur_salt->edata2len;

	memcpy(currentsalt.pbkdf2.salt, cur_salt->salt, currentsalt.pbkdf2.length);
	memcpy(currentsalt.edata1, cur_salt->edata1, sizeof(currentsalt.edata1));
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, sizeof(asrep_salt), &currentsalt, 0, NULL, NULL), "Salt transfer");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_edata2, CL_FALSE, 0, currentsalt.edata2len, cur_salt->edata2, 0, NULL, NULL), "Copy edata2 to gpu");
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

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], asrep_final, 1, NULL, &scalar_gws, lws, 0, NULL, multi_profilingEvent[4]), "Run final kernel (SHA1)");
	BENCH_CLERROR(clFinish(queue[gpu_id]), "Failed running final kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0, sizeof(asrep_out) * scalar_gws, output, 0, NULL, multi_profilingEvent[5]), "Copy result back");

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

struct fmt_main fmt_opencl_krb5_asrep_aes = {
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
		FMT_CASE | FMT_8_BIT | FMT_DYNA_SALT | FMT_HUGE_INPUT,
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
		krb5_asrep_split,
		fmt_default_binary,
		krb5_asrep_get_salt,
		{
			krb5_asrep_etype
		},
		fmt_default_source,
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
