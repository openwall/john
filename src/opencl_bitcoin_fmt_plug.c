/*
 * Copyright notices inherited/copied from the CPU format:
 *
 * Cracker for bitcoin-qt (bitcoin) wallet hashes. Hacked together during April
 * of 2013 by Dhiru Kholia <dhiru at openwall dot com>.
 *
 * Also works for Litecoin-Qt (litecoin) wallet files!
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall dot com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This cracks password protected bitcoin (bitcoin-qt) "wallet" files.
 *
 * bitcoin => https://github.com/bitcoin/bitcoin
 *
 * Thanks to Solar for asking to add support for bitcoin wallet files.
 *
 * Works fine with bitcoin-core-0.14.0 from March, 2017.
 *
 * OpenCL format (dirty hack of the CPU format):
 *
 * Copyright (c) 2021 Solar Designer
 * Copyright (c) 2021 magnum
 * Same cut-down BSD license as above
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_bitcoin;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_bitcoin);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "aes.h"
#include "johnswap.h"
#include "opencl_common.h"

#define FORMAT_LABEL            "Bitcoin-opencl"
#define FORMAT_NAME             "Bitcoin Core"
#define FORMAT_TAG              "$bitcoin$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#define ALGORITHM_NAME          "SHA512 AES OpenCL"

#if !defined (SHA512_DIGEST_LENGTH)
#define SHA512_DIGEST_LENGTH    64
#endif

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#define SALT_SIZE               sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define SZ                      128

static struct fmt_tests bitcoin_tests[] = {
	/* retroactively added hashcat's test vector for benchmark compatibility */
	{"$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$96$480008005625057442352316337722323437108374245623701184230273883222762730232857701607167815448714$66$014754433300175043011633205413774877455616682000536368706315333388", "hashcat"},
	/* bitcoin wallet hashes */
	{"$bitcoin$96$169ce74743c260678fbbba92e926198702fd84e46ba555190f6f3d82f6852e4adeaa340d2ac065288e8605f13d1d7c86$16$26049c64dda292d5$177864$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "openwall"},
	{"$bitcoin$96$bd97a08e00e38910550e76848949285b9702fe64460f70d464feb2b63f83e1194c745e58fa4a0f09ac35e5777c507839$16$26049c64dda292d5$258507$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "password"},
	{"$bitcoin$96$4eca412eeb04971428efec70c9e18fb9375be0aa105e7eec55e528d0ba33a07eb6302add36da86736054dee9140ec9b8$16$26049c64dda292d5$265155$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "strongpassword"},
	/* litecoin wallet hash */
	{"$bitcoin$96$54401984b32448917b6d18b7a11debe91d62aaa343ab62ed98e1d3063f30817832c744360331df94cbf1dcececf6d00e$16$bfbc8ee2c07bbb4b$194787$96$07a206d5422640cfa65a8482298ad8e8598b94d99e2c4ce09c9d015b734632778cb46541b8c10284b9e14e5468b654b9$66$03fe6587bf580ee38b719f0b8689c80d300840bbc378707dce51e6f1fe20f49c20", "isyourpasswordstronger"},
	/* bitcoin-core-0.14.0 wallet */
	{"$bitcoin$96$8e7be42551c822c7e55a384e15b4fbfec69ceaed000925870dfb262d3381ed4405507f6c94defbae174a218eed0b5ce8$16$b469e6dbd76926cf$244139$96$ec03604094ada8a5d76bbdb455d260ac8b202ec475d5362d334314c4e7012a2f4b8f9cf8761c9862cd20892e138cd29e$66$03fdd0341a72d1a119ea1de51e477f0687a2bf601c07c032cc87ef82e0f8f49b19", "password@12345"},
	/* bitcoin-core-0.14.0 wallet */
	{"$bitcoin$96$2559c50151aeec013a9820c571fbee02e5892a3ead07607ee8de9d0ff55798cff6fe60dbd71d7873cb794a03e0d63b70$16$672204f8ab168ff6$136157$96$a437e8bd884c928603ee00cf85eaaf9245a071efa763db03ab485cb757f155976edc7294a6a731734f383850fcac4316$66$03ff84bb48f454662b91a6e588af8752da0674efa5dae82e7340152afcc38f4ba4", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	/* bitcoin-core-0.15.1 wallet, 2017-12-26 */
	{"$bitcoin$96$a05caebc15448da36badbfca2f17624fdf0aa606627213288ca282919b4347580cb161e9d15cb56f8df550c382d8da0a$16$2da7b13a38ef4fb1$148503$96$9d6d027ce45c3fb7a6d4f68c56577fb3b78c9b2d0686e76480cd17df82c88ee3b8616374895fb6edd2257dece6c1a6a6$66$03ffc099d1b6dc18b063fe4c4abc51ef0647d03296104288dc13a5a05d5d018fe1", "openwall123"},
	/* bitcoin-0.7.0-win32-setup.exe from year 2012 */
	{"$bitcoin$96$23582816ecc192d621e22069f5849583684301882a0128aeebd34c208e200db5dfc8feba73d9284156887223ea288b02$16$3052e5cd17a35872$83181$96$c10fd1099feefaff326bc5437bd9be9afc4eee67d8965abe6b191a750c787287a96dc5afcad3a887ce0848cdcfe15516$66$03ff11e4003e96d7b8a028e12aed4f0a041848f58e4c41eebe6cb862f758da6cb7", "openwall123"},
	/* bitcoin-0.5.2-win32-setup.exe from January 2012 */
	{"$bitcoin$96$a8d2a30b9a5419934cbb7cb0727ddc16c4bebdbf30d7e099ca35f2b1b7ba04cc42eb5b865bff8f65fc6ba9e15428d84f$16$872581181d72f577$128205$96$0a8d43558ed2b55f4a53491df66e6a71003db4588d11dc0a88b976122c2849a74c2bfaace36424cf029795db6fd2c78f$130$04ff53a6f68eab1c52e5b561b4616edb5bed4d7510cdb4931c8da68732a86d86f3a3f7de266f17c8d03e02ebe8e2c86e2f5de0007217fd4aaf5742ca7373113060", "openwall"},
	/* PRiVCY-qt.exe <- privcy-1.1.1.0.tar.gz */
	{"$bitcoin$96$d98326490616ef9f59767c5bf148061565fe1b21078445725ef31629e8ee430bf4d04896d5064b6651ab4c19021e2d7c$16$51ee8c9ab318da9e$46008$96$819f6c8e618869c7933b85f6c59d15ca6786876edc435ba3f400e272c2999b43e0e3cda27acd928d1adbccd01b613e66$66$03feefa49b8cbbdbb327b7c477586e4a3275132cf6778f05bc11c517dc2e9107cb", "openwall"},
	// Truncated PRiVCY hash
	{"$bitcoin$64$65fe1b21078445725ef31629e8ee430bf4d04896d5064b6651ab4c19021e2d7c$16$51ee8c9ab318da9e$46008$96$819f6c8e618869c7933b85f6c59d15ca6786876edc435ba3f400e272c2999b43e0e3cda27acd928d1adbccd01b613e66$66$03feefa49b8cbbdbb327b7c477586e4a3275132cf6778f05bc11c517dc2e9107cb", "openwall"},
	/* Nexus legacy wallet */
	{"$bitcoin$64$6b0fbcd048e791edbab30408e14ee24cc51493b810afb61a1e59bc633993a093$36$74fc96a47606814567f02c7df532f6079cbd$169021$2$00$2$00", "openwall"},
	{NULL}
};

static int *cracked;

typedef struct {
	int len;
	char c[PLAINTEXT_LENGTH + 1];
} password_t;

typedef struct custom_salt {
	unsigned char cry_master[SZ];
	int cry_master_length;
	unsigned char cry_salt[SZ];
	int cry_salt_length;
	int cry_rounds;
	int final_block_fill;
} salt_t;

typedef union {
	uint8_t  b[SHA512_DIGEST_LENGTH];
	uint32_t w[SHA512_DIGEST_LENGTH / sizeof(uint32_t)];
	uint64_t W[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
} hash512_t;

static int new_keys;
static password_t *saved_key;
static salt_t *cur_salt;
static cl_int cl_error;
static cl_mem mem_in, mem_salt, mem_state, mem_cracked;
static struct fmt_main *self;
static cl_kernel init_kernel, final_kernel;
static size_t init_kernel_max_lws;

static size_t in_size, salt_size, state_size, cracked_size;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/*
 * HASH_LOOPS is ideally made by factors of (iteration count - 1) and should
 * be chosen for a kernel duration of not more than 200 ms
 */
#define HASH_LOOPS		2000

static int split_events[] = { 2, -1, -1 };

static const char *warn[] = {
	"xfer: ",  ", init: ",  ", loop: ",  ", final: ", ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	init_kernel_max_lws = autotune_get_task_max_work_group_size(FALSE, 0, init_kernel);

	size_t s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, final_kernel));

	return s;
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	in_size = sizeof(password_t) * gws;
	salt_size = sizeof(salt_t);
	state_size = sizeof(hash512_t) * gws;
	cracked_size = sizeof(*cracked) * gws;

	// Allocate memory
	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, in_size, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	saved_key = mem_calloc_align(sizeof(password_t), gws, MEM_ALIGN_WORD);

	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, salt_size, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem setting");

	mem_state = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, state_size, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	mem_cracked = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, cracked_size, NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem cracked");
	cracked = mem_calloc_align(sizeof(*cracked), gws, MEM_ALIGN_WORD);

	HANDLE_CLERROR(clSetKernelArg(init_kernel, 0, sizeof(mem_in), &mem_in), "Error setting kernel argument");
	HANDLE_CLERROR(clSetKernelArg(init_kernel, 1, sizeof(mem_salt), &mem_salt), "Error setting kernel argument");
	HANDLE_CLERROR(clSetKernelArg(init_kernel, 2, sizeof(mem_state), &mem_state), "Error setting kernel argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_state), &mem_state), "Error setting kernel argument");

	HANDLE_CLERROR(clSetKernelArg(final_kernel, 0, sizeof(mem_salt), &mem_salt), "Error setting kernel argument");
	HANDLE_CLERROR(clSetKernelArg(final_kernel, 1, sizeof(mem_state), &mem_state), "Error setting kernel argument");
	HANDLE_CLERROR(clSetKernelArg(final_kernel, 2, sizeof(mem_cracked), &mem_cracked), "Error setting kernel argument");
}

static void release_clobj(void)
{
	if (saved_key) {
		HANDLE_CLERROR(clReleaseMemObject(mem_cracked), "Release mem cracked");
		HANDLE_CLERROR(clReleaseMemObject(mem_state), "Release mem state");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");

		MEM_FREE(cracked);
		MEM_FREE(saved_key);
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

		snprintf(build_opts, sizeof(build_opts), "-DSZ=%u -DPLAINTEXT_LENGTH=%u", SZ, PLAINTEXT_LENGTH);

		opencl_init("$JOHN/opencl/bitcoin_kernel.cl", gpu_id, build_opts);

		init_kernel = clCreateKernel(program[gpu_id], "bitcoin_init", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating init kernel");
		crypt_kernel = clCreateKernel(program[gpu_id], "loop_sha512", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating loop kernel");
		final_kernel = clCreateKernel(program[gpu_id], "bitcoin_final", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating final kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, HASH_LOOPS, split_events, warn, 2, self,
	                       create_clobj, release_clobj,
	                       sizeof(hash512_t), 0, db);

	// Auto tune execution from shared/included code, 200ms crypt_all() max.
	autotune_run(self, 200460 /* first test vector's iteration count */, 0, 200);
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

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p = NULL;
	int res;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;

	if ((p = strtokm(ctcopy, "$")) == NULL) /* cry_master_length (of the hex string) */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_master */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and cry_master */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_salt_length (length of hex string) */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_salt */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and cry_salt */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_rounds */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* ckey_length (of hex) */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* ckey */
		goto err;
	if (strlen(p) != res) /* validates atoi() and ckey */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* public_key_length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* public_key */
		goto err;
	if (strlen(p) != res) /* validates atoi() and public_key */
		goto err;
	if (!ishexlc(p))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	int i;
	char *p;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "$");
	cs.cry_master_length = atoi(p) / 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.cry_master_length; i++)
		cs.cry_master[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.cry_salt_length = atoi(p);
	cs.final_block_fill = 0;
	if (cs.cry_salt_length == 36) { /* Nexus legacy wallet */
		cs.cry_salt_length = 16;
		cs.final_block_fill = 8; /* for mkey size 72 */
	}
	cs.cry_salt_length /= 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.cry_salt_length; i++)
		cs.cry_salt[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "$");
	cs.cry_rounds = atoi(p);

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0,
		salt_size, cur_salt, 0, NULL, multi_profilingEvent[0]),
		"Copy salt to gpu");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	in_size = sizeof(password_t) * global_work_size;
	cracked_size = sizeof(*cracked) * global_work_size;

	if (new_keys) {
		// Copy data to gpu
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			in_size, saved_key, 0, NULL, multi_profilingEvent[0]),
			"Copy data to gpu");

		new_keys = 0;
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		init_kernel, 1, NULL,
		&global_work_size, (local_work_size <= init_kernel_max_lws) ? lws : NULL, 0, NULL,
		multi_profilingEvent[1]), "Run init kernel");

	// Better precision for WAIT_ macros
	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");

	// Run loop kernel
	cl_uint left = cur_salt->cry_rounds - 1;
	cl_uint batch = HASH_LOOPS;
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_uint),
		(void *)&batch), "Error setting kernel argument 1");
	WAIT_INIT(global_work_size)
	do {
		if (batch > left) {
			batch = left;
			HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_uint),
				(void *)&batch), "Error setting kernel argument 1");
		}
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
			crypt_kernel, 1, NULL,
			&global_work_size, lws, 0, NULL,
			multi_profilingEvent[2]), "Run loop kernel");
		if (batch == HASH_LOOPS)
			WAIT_SLEEP
		BENCH_CLERROR(clFinish(queue[gpu_id]), "Error running loop kernel");
		if (batch == HASH_LOOPS)
			WAIT_UPDATE
		opencl_process_event();
		left -= batch;
	} while (left && !ocl_autotune_running);
	WAIT_DONE

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id],
		final_kernel, 1, NULL,
		&global_work_size, lws, 0, NULL,
		multi_profilingEvent[3]), "Run final kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_cracked, CL_TRUE, 0,
		cracked_size, cracked, 0, NULL, multi_profilingEvent[4]),
		"Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (cracked[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	saved_key[index].len = strnzcpyn(saved_key[index].c, key, sizeof(saved_key[index].c));

	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index].c;
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->cry_rounds;
}

struct fmt_main fmt_opencl_bitcoin = {
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
		bitcoin_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
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
