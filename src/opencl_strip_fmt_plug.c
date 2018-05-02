/* STRIP Password Manager cracker patch for JtR. Hacked together during
 * September of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com> */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_strip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_strip);
#else

#include <string.h>
#include <stdint.h>

#include "arch.h"
#include "formats.h"
#include "options.h"
#include "common.h"
#include "misc.h"
#include "opencl_common.h"

#define FORMAT_LABEL         "strip-opencl"
#define FORMAT_NAME          "STRIP Password Manager"
#define FORMAT_TAG           "$strip$*"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME       "PBKDF2-SHA1 AES OpenCL"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     -1
#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1
#define BINARY_SIZE          0
#define PLAINTEXT_LENGTH     64
#define SALT_SIZE            sizeof(struct custom_salt)
#define BINARY_ALIGN         1
#define SALT_ALIGN           4

#define ITERATIONS           4000
#define FILE_HEADER_SZ       16
#define SQLITE_FILE_HEADER   "SQLite format 3"
#define HMAC_SALT_MASK       0x3a
#define FAST_PBKDF2_ITER     2
#define SQLITE_MAX_PAGE_SIZE 65536

static struct fmt_tests strip_tests[] = {
	/* test vector created by STRIP for Windows */
	{"$strip$*66cd7a4ff7716f7b86cf587ce18eb39518e096eb152615ada8d007d9f035c20c711e62cbde96d8c3aad2a4658497a6119addc97ed3c970580cd666f301c63ce041a1748ee5c3861ada3cd6ee75b5d68891f731b3c2e3294b08e10ce3c23c2bfac158f8c45d0332791f64d1e3ad55e936d17a42fef5228e713b8188050c9a61c7f026af6203172cf2fc54c8b439e2260d7a00a4156713f92f8466de5c05cd8701e0d3d9cb3f392ae918e6900d5363886d4e1ed7e90da76b180ef9555c1cd358f6d1ee3755a208fee4d5aa1c776a0888200b21a3da6614d5fe2303e78c09563d862d19deecdc9f0ec7fbc015689a74f4eb477d9f22298b1b3f866ca4cb772d74821a1f8d03fd5fd0d020ffd41dd449b431ddf3bbfba3399311d9827be428202ee56e2c2a4e91f3415b4282c691f16cd447cf877b576ab963ea4ea3dc7d8c433febdc36607fd2372c4165abb59e3e75c28142f1f2575ecca6d97a9f782c3410151f8bbcbc65a42fdc59fdc4ecd8214a2bbd3a4562fac21c48f7fc69a4ecbcf664b4e435d7734fde5494e4d80019a0302e22565ed6a49b29cecf81077fd92f0105d18a421e04ee0deaca6389214abc7182db7003da7e267816531010b236eadfea20509718ff743ed5ad2828b6501dd84a371feed26f0514bbda69118a69048ebb71e3e2c54fb918422f1320724a353fe8d81a562197454d2c67443be8a4008a756aec0998386a5fd48e379befe966b42dfa6684ff049a61b51de5f874a12ab7d9ab33dc84738e036e294c22a07bebcc95be9999ab988a1fa1c944ab95be970045accb661249be8cc34fcc0680cb1aff8dfee21f586c571b1d09bf370c6fc131418201e0414acb2e4005b0b6fda1f3d73b7865823a008d1d3f45492a960dbdd6331d78d9e2e6a368f08ee3456b6d78df1d5630f825c536fff60bad23fb164d151d80a03b0c78edbfdee5c7183d7527e289428cf554ad05c9d75011f6b233744f12cd85fbb62f5d1ae22f43946f24a483a64377bf3fa16bf32cea1ab4363ef36206a5989e97ff847e5d645791571b9ecd1db194119b7663897b9175dd9cc123bcc7192eaf56d4a2779c502700e88c5c20b962943084bcdf024dc4f19ca649a860bdbd8f8f9b4a9d03027ae80f4a3168fc030859acb08a871950b024d27306cdc1a408b2b3799bb8c1f4b6ac3593aab42c962c979cd9e6f59d029f8d392315830cfcf4066bf03e0fc5c0f3630e9c796ddb38f51a2992b0a61d6ef115cb34d36c7d94b6c9d49dfe8d064d92b483f12c14fa10bf1170a575e4571836cef0a1fbf9f8b6968abda5e964bb16fd62fde1d1df0f5ee9c68ce568014f46f1717b6cd948b0da9a6f4128da338960dbbcbc9c9c3b486859c06e5e2338db3458646054ccd59bb940c7fc60cda34f633c26dde83bb717b75fefcbd09163f147d59a6524752a47cd94", "openwall"},
	/* test vector created by STRIP Password Manager (for Android) */
	{"$strip$*78adb0052203efa1bd1b02cac098cc9af1bf7e84ee2eaebaaba156bdcfe729ab12ee7ba8a84e79d11dbd67eee82bcb24be99dbd5db7f4c3a62f188ce4b48edf4ebf6cbf5a5869a61f83fbdb3cb4bf79b3c2c898f422d71eab31afdf3a8d4e97204dedbe7bd8b5e4c891f4880ca917c8b2f67ca06035e7f8db1fae91c45db6a08adf96ec5ddcb9e60b648acf883a7550ea5b67e2d27623e8de315f29cba48b8b1d1bde62283615ab88293b29ad73ae404a42b13e35a95770a504d81e335c00328a6290e411fa2708a697fab7c2d17ff5d0a3fe508118bb43c3d5e72ef563e0ffd337f559085a1373651ca2b8444f4437d8ac0c19aa0a24b248d1d283062afbc3b4ccc9b1861f59518eba771f1d9707affe0222ff946da7c014265ab4ba1f6417dd22d92e4adf5b7e462588f0a42e061a3dad041cbb312d8862aed3cf490df50b710a695517b0c8771a01f82db09231d392d825f5667012e349d2ed787edf8448bbb1ff548bee3a33392cd209e8b6c1de8202f6527d354c3858b5e93790c4807a8967b4c0321ed3a1d09280921650ac33308bd04f35fb72d12ff64a05300053358c5d018a62841290f600f7df0a7371b6fac9b41133e2509cb90f774d02e7202185b9641d063ed38535afb81590bfd5ad9a90107e4ff6d097ac8f35435f307a727f5021f190fc157956414bfce4818a1e5c6af187485683498dcc1d56c074c534a99125c6cfbf5242087c6b0ae10971b0ff6114a93616e1a346a22fcac4c8f6e5c4a19f049bbc7a02d2a31d39548f12440c36dbb253299a11b630e8fd88e7bfe58545d60dce5e8566a0a190d816cb775bd859b8623a7b076bce82c52e9cff6a2d221f9d3fd888ac30c7e3000ba8ed326881ffe911e27bb8982b56caa9a12065721269976517d2862e4a486b7ed143ee42c6566bba04c41c3371220f4843f26e328c33a5fb8450dadc466202ffc5c49cc95827916771e49e0602c3f8468537a81cf2fa1db34c090fccab6254436c05657cf29c3c415bb22a42adeac7870858bf96039b81c42c3d772509fdbe9a94eaf99ee9c59bac3ea97da31e9feac14ed53a0af5c5ebd2e81e40a5140da4f8a44048d5f414b0ba9bfb8024c7abaf5346fde6368162a045d1196f81d55ed746cc6cbd7a7c9cdbfa392279169626437da15a62730c2990772e106a5b84a60edaa6c5b8030e1840aa6361f39a12121a1e33b9e63fb2867d6241de1fb6e2cd1bd9a78c7122258d052ea53a4bff4e097ed49fc17b9ec196780f4c6506e74a5abb10c2545e6f7608d2eefad179d54ad31034576be517affeb3964c65562538dd6ea7566a52c75e4df593895539609a44097cb6d31f438e8f7717ce2bf777c76c22d60b15affeb89f08084e8f316be3f4aefa4fba8ec2cc1dc845c7affbc0ce5ebccdbfde5ebab080a285f02bdfb76c6dbd243e5ee1e5d", "p@$$w0rD"},
	{NULL}
};

#define KEYLEN  PLAINTEXT_LENGTH
#define SALTLEN 16
#define OUTLEN  32

typedef struct {
	uint32_t length;
	uint8_t v[KEYLEN];
} pbkdf2_password;

typedef struct {
	uint32_t v[(OUTLEN+3)/4];
} pbkdf2_hash;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  length;
	uint8_t  salt[SALTLEN];
	uint8_t  pad[3];
} pbkdf2_salt;

typedef struct {
	pbkdf2_salt pbkdf2;
	unsigned char data[1024];
} strip_salt;

typedef struct {
	uint32_t cracked;
} strip_out;

static struct custom_salt {
	unsigned char salt[SALTLEN];
	unsigned char data[1024];
} *cur_salt;

static int new_keys;
static cl_int cl_error;
static pbkdf2_password *inbuffer;
static strip_out *outbuffer;
static strip_salt currentsalt;
static cl_mem mem_in, mem_dk, mem_salt, mem_out;
static struct fmt_main *self;

static size_t insize, dksize, saltsize, outsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	insize = sizeof(pbkdf2_password) * gws;
	dksize = sizeof(pbkdf2_hash) * gws;
	saltsize = sizeof(strip_salt);
	outsize = sizeof(strip_out) * gws;

	inbuffer = mem_calloc(1, insize);
	outbuffer = mem_alloc(outsize);

	/// Allocate memory
	mem_in =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_dk =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, dksize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem dk");
	mem_salt =
	    clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_out =
	    clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_dk),
		&mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (outbuffer) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_dk), "Release mem dk");

		MEM_FREE(inbuffer);
		MEM_FREE(outbuffer);
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
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
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d",
		         KEYLEN, SALTLEN, OUTLEN);
		opencl_init("$JOHN/kernels/strip_kernel.cl", gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "strip", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		// Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
		                       create_clobj, release_clobj,
		                       sizeof(pbkdf2_password), 0, db);

		// Auto tune execution from shared/included code.
		autotune_run(self, 1, 0, 1000);
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$strip$" and first '*' */
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* salt + data */
		goto err;
	if (hexlenl(p, &extra) != 2048 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt *cs;

	if (!cs)
		cs = mem_alloc_tiny(sizeof(struct custom_salt), 4);

	memset(cs, 0, sizeof(struct custom_salt));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$strip$" and first '*' */
	p = strtokm(ctcopy, "*");
	for (i = 0; i < 16; i++)
			cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		for (; i < 1024; i++)
			cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	memcpy((char*)currentsalt.pbkdf2.salt, cur_salt->salt, 16);
	currentsalt.pbkdf2.length = 16;
	currentsalt.pbkdf2.iterations = ITERATIONS;
	currentsalt.pbkdf2.outlen = 32;
	currentsalt.pbkdf2.skip_bytes = 0;
	memcpy(currentsalt.data, cur_salt->data, sizeof(currentsalt.data));

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
	    "Copy salt to gpu");
}

static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);

	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;

	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	if (new_keys || ocl_autotune_running) {
		/// Copy data to gpu
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
		        "Copy data to gpu");
		new_keys = 0;
	}

	/// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
	        multi_profilingEvent[1]), "Run kernel");

	/// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, outbuffer, 0, NULL, multi_profilingEvent[2]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (outbuffer[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return outbuffer[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_strip = {
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
		FMT_CASE | FMT_8_BIT | FMT_NOT_EXACT | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		strip_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
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
		fmt_default_clear_keys,
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
