/*
 * This software is Copyright (c) 2018, Ivan Freed <ivan.freed at protonmail.com>,
 * Copyright (c) 2012-2013 Lukas Odzioba, Copyright (c) 2014 JimF, Copyright
 * (c) 2014 magnum, and it is hereby released to the general public under the
 * following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on opencl_pbkdf2_hmac_sha512_fmt_plug.c file.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_diskcryptor_aes;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_diskcryptor_aes);
#else

#include <stdint.h>
#include <string.h>

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "opencl_common.h"
#include "diskcryptor_common.h"
#include "pbkdf2_hmac_common.h"

#define FORMAT_NAME             "DiskCryptor AES XTS (only)"
#define FORMAT_LABEL            "diskcryptor-aes-opencl"
#define ALGORITHM_NAME          "PBKDF2-SHA512 AES OpenCL"
#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define PLAINTEXT_LENGTH        110
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define KERNEL_NAME             "pbkdf2_sha512_kernel"
#define SPLIT_KERNEL_NAME       "pbkdf2_sha512_loop"
#define FINAL_KERNEL_NAME       "diskcryptor_final"

#define HASH_LOOPS              250
#define ITERATIONS              1000

typedef struct {
	// for plaintext, we must make sure it is a full uint64_t width.
	uint64_t v[(PLAINTEXT_LENGTH + 7) / 8]; // v must be kept aligned(8)
	uint64_t length; // keep 64 bit aligned, length is overkill, but easiest way to stay aligned.
} pass_t;

typedef struct {
	uint64_t hash[8];
} crack_t;

typedef struct {
	// for salt, we append \x00\x00\x00\x01\x80 and must make sure it is a full uint64 width
	uint64_t salt[(PBKDF2_64_MAX_SALT_SIZE + 1 + 4 + 7) / 8]; // salt must be kept aligned(8)
	uint32_t length;
	uint32_t rounds;
} salt_t;

typedef struct {
	uint64_t ipad[8];
	uint64_t opad[8];
	uint64_t hash[8];
	uint64_t W[8];
	cl_uint rounds;
} state_t;

typedef struct {
	salt_t pbkdf2;
	uint8_t header[96];
} diskcryptor_salt_t;

typedef struct {
	uint32_t cracked;
} out_t;

static struct custom_salt *cur_salt;
static int new_keys;

/* Original password */
static char (*orig_key)[PLAINTEXT_LENGTH + 1];

static pass_t *host_pass;
static diskcryptor_salt_t *host_salt;
static out_t *host_crack;
static cl_mem mem_in, mem_salt, mem_state, mem_dk, mem_out;
static cl_kernel split_kernel, final_kernel;
static cl_int cl_error;
static struct fmt_main *self;

#define STEP                    0
#define SEED                    256

static const char *warn[] = {
	"xfer: ",  ", init: " , ", crypt: ", ", final: ", ", res xfer: "
};

static int split_events[] = { 2, -1, -1 };

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

struct fmt_tests diskcryptor_aes_tests[] = {
	/* AES XTS test vectors */
	{"$diskcryptor$0*e710cb6585ba412d9b4ce8587b8faa311d9a7d8f3dea46232b83b98ac6fd17d6026173cf1096355bf33768b5a9856486af0e9300f92dee6067228662f53598d250a789cb449617f44c05411b4fdb018ba3d11cdc328efd06c3123b1fa8dc52273480d905e4fd7023a8cbe807a52245c877f963feb5b80363680d94cdfb2d8e1cd019e16734890f856441ca1f38a7809699c871454a487f6262a9b732db35c76e902f732a9505597b3df8e00653cf77662072341420e6482d28d12db5e97c9e5b66a7bce4d2c6b1ffe5105e9461deb9fdda805a502dd78fcc5044514e8f4a1552753082d9294abc4cd4873d365d317e4a720cdaef3182d9fa963e50a888e9451824108f6ae837f2cdd25223426a817c23d913205b7e373ee8403b87c830ec95f5dd501662ae9b6228cd692fa4632a5a25ccec970359e18cf85b93f64de226d20aa7ed19f99f665c9ab5a19412669653e6e0db855fef9f0623b68680567373d20ce64031c95b6f9b897fc8905ee1571f0b18aab078048d39502e8644515f8e4dfdaba368b7c1ca0403e7827292b7319a0dfcc1b8f090cc782474f68e117b573259466860577c6459e5cccdf8e5e49ab38b87c29e87cb3d113896ed13ba0ad4d8e51d39d3bde3ef3f78d8e85b86ae52b16c27f9701f7bebb01c49e067452b711d6311550b6927014ef56ed5fa29ff6ada6586942997c1384dc3c5331418bcd676d7ddea7ee1c27aabcf49e9c56fb74ad42b6f43f1193e59c9b807e27c562251a483fcf480653b21d2769f48d15f31b1432c0079c78fedbbf98e4d43c43c1a6ce6cb85ff2776c227cd4291e8cf8e05bb1d9a6e0164913cd0336ed01dc5ffab1463f18cdb82723dfd6d038987d6067f3d341fb5ea087ecde8ddd4dd74b52a617a26658f07ca778b161ef25c45bacc60125ac9fd2117345126faf83937173d196e9b0edbb6fe573958bd3a31ea9ea4593c1b21822835f6c65be0cae0157ff59bb316bd39c6d276d9cc4e77a4ad1f6f8280307b1a3a7cbfef7243aab6aa437da633047dbb4e0dd7eae299290b4d45f8928cd359e2547ccf773884a590e14feed71062bda2b241ec67de77ef7a96d5f01a0d132086f6f0915bfda1f7907787f3fea20865f7f1a9557d5a4572c8e21003e993262e7c328700aba0b0f9335a030bb2c5fdd89f01130030d791a6be95e5c19e3b0a20fe80588c5463ad8f7915af340e2ba3917cfbb716a9557f3a24702cec53e23448d97e25e6aca074e16ac2f293a2a2631da23458fb19d09f1dc1a233642687469caaf2c64694ec03e8c2b16a4f80103a82454504ba6c1b95b82ce904c8400c0faaac69eff773c20988d5a57cb08420680a9ab38cd5ef4749c54cb95917a79076d032504f2f70ad2ed75e9f3d07fa8a50303eb2a27e3581e3129e577317868f203847bb8ed05d0d57bb9e1126ffb582f7f3a454b23d7a0bd18d840470360ebfd3fa0128c4853843e514e066c4173ea58a5fd84d3ebc574efb7a6e60cd8cfeba513ce9e5877c00095eefa9312a605cf21a43550cdfe94bbeaa1b83fa6a0cbebd7cbd25916ba2a8acec1d66578127ab0c045cad0ebef6e8eaa2f88b117d7d2d0abdd3b323ae03e9b9c7d29c5aa4056bcb27c51cea69640a45db8d483b04ba4f8bc426370f656251c8584dd3efdfad048087eb20010a0e29c3bbcdebee8ea77477e5fa2031215342a03c113e3138b53b3e3743bbd922c89433a98e94712208f801e93a263e55310c08e8722e28e7d49dabd4b3cb24c0d742371606f9db44ecfbdc7587fd4918a0bbed2af951b727b49b8f146459ba2d8dfcb9ca050f455a5f140b8810704c5e8a94f979ab818b3ff8bdc8bd32e143f28d0db91c00c3c0a0e35c647aeab2669bd272d28e6ffc4ca1ebec628c04e0dbeca5fd44aa5330318099043b232f3b9089fff382c94ffabcc2d6896370b4b149068e0a8a93deb09d003942c121fa9ec4856cb8e9d999a47a49ab5a1af3b18570cea699a0568748bf7ca03399318338b57682f97044b3a5a8eb9a56aaf11b7165ae2a797a5db08ae55bfe0b142eb8a54bdb77a47bff3dadd72b012cca7707dd20eda5ea3e426e7c8bf8b8bed57062ca53d2c962bc96e54d971ac5e68f68726ffbabf35ec32c417748d018644029decea8c6b511573ebfa325c331ab21aef16f8968ec2262dad36e49ce6a8ff3ce672a0674ed29054567775249812c4fb15e53916209d37e7ebd90e213203344095699ad5cf06d63887aad8623b107b135610663ae85c54f69b6491128338efae3f60ebc9d1c26b32dc6b0bee7ee3cb9e7a8de26c82b3bf056e83119ca88beb2f5a835092e98d87a4d6eeddc3957ffaf7671b20227a7b6923464a68c4bf94a885c8a9bd29b04a141e049e5b60db40a89d0eb4cc08c0b38974d1012d6fb75be58c5c849f35bb38cc887d7fb8615bb28a84197f695f89fbf9adacdbf49c1a205af8ae312021f217f2af644d203189665622b98c9338663a5d524de4864ff12318e544fe06b851cc723503613217972882300c43032a0d00d9ff11e941ee1def5425e78dd312676cd0bfb36a6848f92cc936e2ea19f4002f8c98a3c37e23389c0c428d97d2152cf5050b2f8422b4730c9047b57bb6e911a3e05486e099148a9e84cef9ed1c6643e949643dd6a122e9b6bf058aab88bf1993f70ffd5306dac7e0066363fb57068fb4cfaabea157071b105f4dd5484968def1ec4139cf66c5bbbc5fcdbd29fa0308eabcc84b61c01e26234115714596ad7ad67676c7a6c6acc4549619f74d828a1f1181826733cd9283e0bb2f0a010cd1765d3cb68825b7d210e486339d0deeee5d7893eb8e04761c3ed0261959717f26ac3802215b9f32e24d574764e10fdc5d19508ac309e1912600709735c1a", "openwall"},
	{NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, split_kernel));
	return MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));
}

static void release_clobj(void);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	release_clobj();

	host_pass = mem_calloc(kpc, sizeof(pass_t));
	orig_key = mem_calloc(kpc, sizeof(*orig_key));
	host_crack = mem_calloc(kpc, sizeof(out_t));
	host_salt = mem_calloc(1, sizeof(diskcryptor_salt_t));

#define CL_RO CL_MEM_READ_ONLY
#define CL_WO CL_MEM_WRITE_ONLY
#define CL_RW CL_MEM_READ_WRITE

#define CLCREATEBUFFER(_flags, _size, _string)  \
	clCreateBuffer(context[gpu_id], _flags, _size, NULL, &cl_error);  \
	HANDLE_CLERROR(cl_error, _string);

#define CLKERNELARG(kernel, id, arg, msg)  \
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), msg);

	mem_salt = CLCREATEBUFFER(CL_RO, sizeof(diskcryptor_salt_t),
			"Cannot allocate mem salt");
	mem_in = CLCREATEBUFFER(CL_RO, kpc * sizeof(pass_t),
			"Cannot allocate mem in");
	mem_state = CLCREATEBUFFER(CL_RW, kpc * sizeof(state_t),
			"Cannot allocate mem state");
	mem_dk = CLCREATEBUFFER(CL_RW, kpc * sizeof(crack_t),
			"Cannot allocate mem dk");
	mem_out = CLCREATEBUFFER(CL_WO, kpc * sizeof(out_t),
			"Cannot allocate mem out");

	CLKERNELARG(crypt_kernel, 0, mem_in, "Error while setting mem_in");
	CLKERNELARG(crypt_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(crypt_kernel, 2, mem_state, "Error while setting mem_state");

	CLKERNELARG(split_kernel, 0, mem_state, "Error while setting mem_state");
	CLKERNELARG(split_kernel, 1, mem_dk, "Error while setting mem_dk");

	CLKERNELARG(final_kernel, 0, mem_dk, "Error while setting mem_dk");
	CLKERNELARG(final_kernel, 1, mem_salt, "Error while setting mem_salt");
	CLKERNELARG(final_kernel, 2, mem_out, "Error while setting mem_out");
}

static void init(struct fmt_main *_self)
{
	static int warned = 0;

	self = _self;
	opencl_prepare_dev(gpu_id);

	if (!warned++ && !(options.flags & FLG_TEST_CHK) && !options.listconf) {
		fprintf(stderr, "[ATTENTION] This format (%s) can only crack AES XTS DiskCryptor hashes.\n", FORMAT_LABEL);
	}
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
				"-DHASH_LOOPS=%u -DPLAINTEXT_LENGTH=%d -DPBKDF2_64_MAX_SALT_SIZE=%d",
				HASH_LOOPS, PLAINTEXT_LENGTH, PBKDF2_64_MAX_SALT_SIZE);

		opencl_init("$JOHN/opencl/diskcryptor_aes_kernel.cl", gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");

		split_kernel =
			clCreateKernel(program[gpu_id], SPLIT_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating split kernel");

		final_kernel =
			clCreateKernel(program[gpu_id], FINAL_KERNEL_NAME, &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating final kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn, 2,
	                       self, create_clobj, release_clobj,
	                       sizeof(state_t), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, ITERATIONS, 0, 200);
}

static void release_clobj(void)
{
	if (host_pass) {
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_dk), "Release mem out");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(host_pass);
		MEM_FREE(host_salt);
		MEM_FREE(host_crack);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		HANDLE_CLERROR(clReleaseKernel(final_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(split_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 2048; i++)
		cs.header[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	memcpy(cs.salt, cs.header, 64);
	cs.iterations = 1000; // fixed as of version 1.1.846.118 (09.07.2014)

	// we append the count and EOM here, one time.
	memcpy(cs.salt + 64, "\x0\x0\x0\x1\x80", 5);
	cs.saltlen = 64 + 5; // we include the x80 byte in our saltlen, but the .cl kernel knows to reduce saltlen by 1

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	memcpy(host_salt->pbkdf2.salt, cur_salt->salt, cur_salt->saltlen);
	host_salt->pbkdf2.length = cur_salt->saltlen;
	host_salt->pbkdf2.rounds = cur_salt->iterations;

	memcpy(host_salt->header, cur_salt->header, 96);

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
				CL_FALSE, 0, sizeof(diskcryptor_salt_t), host_salt, 0, NULL, NULL),
			"Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i, loops = (host_salt->pbkdf2.rounds + HASH_LOOPS - 1) / HASH_LOOPS;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			gws * sizeof(pass_t), host_pass,
			0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	// Run standard PBKDF2 kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
				NULL, &gws, lws, 0, NULL,
				multi_profilingEvent[1]), "Run kernel");

	for (i = 0; i < (ocl_autotune_running ? 1 : loops); i++) {
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
					split_kernel, 1, NULL,
					&gws, lws, 0, NULL,
					multi_profilingEvent[2]), "Run split kernel");
		BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
		opencl_process_event();
	}

	// Run GELI post-processing kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], final_kernel, 1,
				NULL, &gws, lws, 0, NULL,
				multi_profilingEvent[3]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
				gws * sizeof(out_t), host_crack,
				0, NULL, multi_profilingEvent[4]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (host_crack[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return host_crack[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	int len;

	/* store original */
	len = strnzcpyn(orig_key[index], key, sizeof(orig_key[index]));

	/* convert key to UTF-16LE and fill with nulls */
	memset((char*)host_pass[index].v, 0, PLAINTEXT_LENGTH);
	len = enc_to_utf16((UTF16 *)host_pass[index].v, PLAINTEXT_LENGTH / 2, (unsigned char*)key, len);
	if (len < 0)
		len = strlen16((UTF16 *)host_pass[index].v);
	host_pass[index].length = len << 1;

	new_keys = 1;
}

static char *get_key(int index)
{
	/* Ensure truncation due to over-length or invalid UTF-8 is made like how the GPU got it. */
	if (options.target_enc == UTF_8)
		truncate_utf8((UTF8*)orig_key[index], PLAINTEXT_LENGTH);

	return orig_key[index];
}

struct fmt_main fmt_opencl_diskcryptor_aes = {
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
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT | FMT_UNICODE | FMT_ENC,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		diskcryptor_aes_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		diskcryptor_valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			diskcryptor_iteration_count,
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
