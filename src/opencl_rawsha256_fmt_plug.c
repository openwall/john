/*
 * Developed by Claudio André <claudio.andre at correios.net.br> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-256
 * More information at http://openwall.info/wiki/john/OpenCL-CISCO4
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012 Claudio André <claudio.andre at correios.net.br>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rawsha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rawsha256);
#else

#include <string.h>

#include "sha.h"
#include "sha2.h"
#include "common-opencl.h"
#include "config.h"
#include "options.h"
#include "opencl_rawsha256.h"
#include "rawSHA256_common.h"

#define FORMAT_LABEL			"Raw-SHA256-opencl"
#define FORMAT_NAME			""

#define ALGORITHM_NAME			"SHA256 OpenCL (inefficient, development use mostly)"

#define OCL_CONFIG			"raw-sha256"

static uint32_t				* plaintext, * saved_idx;	// plaintext ciphertexts
static uint32_t				* calculated_hash;		// calculated (partial) hashes

static cl_mem pass_buffer;		//Plaintext buffer.
static cl_mem hash_buffer;		//Partial hash keys (output).
static cl_mem idx_buffer;		//Sizes and offsets buffer.
static cl_mem p_binary_buffer;		//To compare partial binary ([3]).
static cl_mem result_buffer;		//To get the if a hash was found.
static cl_mem pinned_saved_keys, pinned_saved_idx, pinned_partial_hashes;

static cl_kernel cmp_kernel;

static int hash_found;
static uint32_t key_idx = 0;
static size_t offset = 0, offset_idx = 0;

static int crypt_all(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static struct fmt_tests tests[] = {
	{"71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{HEX_TAG "71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
	{"25b64f637b373d33a8aa2b7579784e99a20e6b7dfea99a71af124394b8958f27", "doesthiswork"},
	{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
	{"27c6794c8aa2f70f5f6dc93d3bfb25ca6de9b0752c8318614cbd4ad203bea24c", "ALLCAPS"},
	{"04cdd6c523673bf448efe055711a9b184817d7843b0a76c2046f5398b5854152", "TestTESTt3st"},
	{HEX_TAG "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
	{HEX_TAG "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
	{HEX_TAG "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", ""},
	{"LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{CISCO_TAG "LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU", "password"},
	{"a49c2c9d0c006c8cb55a9a7a38822b83e0cd442614cb416af952fa50156761dc", "openwall"},
#ifdef DEBUG //Special test cases.
	{"c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", "1234567890"},
	{"6ed645ef0e1abea1bf1e4e935ff04f9e18d39812387f63cda3415b46240f0405", "12345678901234567890"},
	{"f54e5c8f810648e7638d25eb7ed6d24b7e5999d588e88826f2aa837d2ee52ecd", "123456789012345678901234567890"},
	{"a4ebdd541454b84cc670c9f1f5508baf67ffd3fe59b883267808781f992a0b1d", "1234567890123456789012345678901234567890"},
	{"f58fffba129aa67ec63bf12571a42977c0b785d3b2a93cc0538557c91da2115d", "12345678901234567890123456789012345678901234567890"},
	{"3874d5c9cc5ab726e6bbebadee22c680ce530004d4f0bb32f765d42a0a6c6dc1", "123456789012345678901234567890123456789012345678901"},
	{"03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9", "1234567890123456789012345678901234567890123456789012345"},
	{"9e7d3e56996c5a06a6a378567e62f5aa7138ebb0f55c0bdaf73666bf77f73380", "mot\xf6rhead"},
	{"0f46e4b0802fee6fed599682a16287d0397699cfd742025482c086a70979e56a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 31
	{"c62e4615bd39e222572f3a1bf7c2132ea1e65b17ec805047bd6b2842c593493f", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 32
	{"d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 55
	{CISCO_TAG "OsOmQzwozC4ROs/CzpczJoShdCeW9lp7k/tGrPS5Kog", "1"},
	{CISCO_TAG "d7kgbEk.P6mpKdduC66fUy1BF0MImo3eyJ9uI/JbMRk", "openwall"},
	{CISCO_TAG "p5BSCWNS3ivUDpZlWthR.k4Q/xWqlFyEqXdaPikHenI", "2"},
	{CISCO_TAG "HwUf7ev9Fx84X2vvspULAeDbmwlg9jgm/Wk63kc3vfU", "11"},
	{CISCO_TAG "bsPEUMVATKKO9yeUlJfE3OCzHlgf0s6goJpg3P1k0UU", "test"},
	{CISCO_TAG "hUsuWZSE8dZERUBYNwRK8Aa8VxEGIHsuZFUCjNj2.Ac", "verylongbutweakpassword"},
	{CISCO_TAG "fLUL1VG98zYDf9Q.M40nZ5blVT3M6UBex74Blw.UDCc", "thismaximumpasswordlength"},
	{CISCO_TAG "Xq81UiuCj7bz9B..EX2BZumsU/d8pF5gs2NlRMW6sTk", "applesucks"},
	{CISCO_TAG "O/D/cn1nawcByQoJfBxrNnUx6jjfWV.FNFx5TzmzihU", "AppleSucks"},
#endif
	{NULL}
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, cmp_kernel));
	return s;
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	return 0;
}

static void crypt_one(int index, sha256_hash * hash) {
	SHA256_CTX ctx;

	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, key, len);
	SHA256_Final((unsigned char *) (hash), &ctx);
}

/* ------- Create and destroy necessary objects ------- */
static void create_clobj(size_t gws, struct fmt_main * self)
{
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	pinned_saved_keys = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");

	plaintext = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_keys, CL_TRUE, CL_MAP_WRITE, 0,
			BUFFER_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory plaintext");

	pinned_saved_idx = clCreateBuffer(context[gpu_id],
			CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");

	saved_idx = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_saved_idx, CL_TRUE, CL_MAP_WRITE, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id],
			CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");

	calculated_hash = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
			sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory out_hashes");

	// create arguments (buffers)
	pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument pass_buffer");

	idx_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument idx_buffer");

	hash_buffer = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
			sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument hash_buffer");

	p_binary_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
			sizeof(uint32_t), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument p_binary_buffer");

	result_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
			sizeof(int), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument result_buffer");

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
			(void *) &pass_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
			(void *) &idx_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 2");

	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 0, sizeof(cl_mem),
			(void *) &hash_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 1, sizeof(cl_mem),
			(void *) &p_binary_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(cmp_kernel, 2, sizeof(cl_mem),
			(void *) &result_buffer), "Error setting argument 2");

	//Assure buffers have no "trash data".
	memset(plaintext, '\0', BUFFER_SIZE * gws);
	memset(saved_idx, '\0', sizeof(uint32_t) * gws);
}

static void release_clobj(void) {
	cl_int ret_code;

	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys,
			plaintext, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping keys");
	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx,
			saved_idx, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping indexes");
	ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes,
			calculated_hash, 0, NULL, NULL);
	HANDLE_CLERROR(ret_code, "Error Unmapping partial hashes");
	HANDLE_CLERROR(clFinish(queue[gpu_id]),
	               "Error releasing memory mappings");

	ret_code = clReleaseMemObject(pass_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
	ret_code = clReleaseMemObject(hash_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing hash_buffer");
	ret_code = clReleaseMemObject(idx_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing idx_buffer");

	ret_code = clReleaseMemObject(p_binary_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing p_binary_buffer");
	ret_code = clReleaseMemObject(result_buffer);
	HANDLE_CLERROR(ret_code, "Error Releasing result_buffer");

	ret_code = clReleaseMemObject(pinned_saved_keys);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
	ret_code = clReleaseMemObject(pinned_saved_idx);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_idx");
	ret_code = clReleaseMemObject(pinned_partial_hashes);
	HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
}

/* ------- Key functions ------- */
static void clear_keys(void) {
	offset = 0;
	offset_idx = 0;
	key_idx = 0;
}

static void set_key(char * _key, int index) {
	int len = 0;

	const uint32_t * key = (uint32_t *) _key;

	while (*(_key++))
		len++;

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		plaintext[key_idx++] = *key++;
		len -= 4;
	}

	if (len)
		plaintext[key_idx++] = *key;

	//Batch transfers to GPU.
	if ((index % TRANSFER_SIZE) == 0 && (index > 0)) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			plaintext + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer pass_buffer");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer,
			CL_FALSE, sizeof(uint32_t) * offset,
			sizeof(uint32_t) * TRANSFER_SIZE,
			saved_idx + offset, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer idx_buffer");

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		offset += TRANSFER_SIZE;
		offset_idx = key_idx;
	}
}

static char * get_key(int index) {
	static char ret[RAW_PLAINTEXT_LENGTH + 1];
	int len = saved_idx[index] & 63;
	char * key = (char *) &plaintext[saved_idx[index] >> 6];

	memcpy(ret, key, RAW_PLAINTEXT_LENGTH);
	ret[len] = '\0';

	return ret;
}

/* ------- Initialization  ------- */
static void init(struct fmt_main * self) {
	char * task = "$JOHN/kernels/sha256_kernel.cl";
	size_t gws_limit;

	opencl_prepare_dev(gpu_id);
	opencl_build_kernel(task, gpu_id, NULL, 1);

	// create kernel(s) to execute
	crypt_kernel = clCreateKernel(program[gpu_id], "kernel_crypt", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	cmp_kernel = clCreateKernel(program[gpu_id], "kernel_cmp", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel_cmp. Double-check kernel name?");

	gws_limit = MIN((0xf << 22) * 4 / BUFFER_SIZE,
			get_max_mem_alloc_size(gpu_id) / BUFFER_SIZE);

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
		warn, 1, self, create_clobj, release_clobj,
		BUFFER_SIZE, gws_limit);

	//Limit worksize using index limitation.
	while (global_work_size > gws_limit)
		global_work_size -= local_work_size;

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, gws_limit,
		(cpu(device_info[gpu_id]) ? 500000000ULL : 1000000000ULL));
}

static void done(void) {
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(cmp_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

/* ------- To binary functions ------- */
static void * get_binary(char *ciphertext) {
	static unsigned char *out;
	uint32_t * b;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < (FULL_BINARY_SIZE / 2); i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	b = (uint32_t *) out;
	b[0] = SWAP32(b[3]) - H3;

	return out;
}

static void * get_full_binary(char *ciphertext) {
	static unsigned char *out;
	char *p;
	int i;

	if (!out) out = mem_alloc_tiny(FULL_BINARY_SIZE, MEM_ALIGN_WORD);

	p = ciphertext + 8;
	for (i = 0; i < FULL_BINARY_SIZE; i++) {
		out[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				 atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

/* ------- Crypt function ------- */
static int crypt_all(int *pcount, struct db_salt *_salt) {
	int count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);

	/* Self-test cludge */
	if (offset > key_idx || offset > gws)
		offset = 0;

	//Send data to device.
	if (key_idx > offset)
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer, CL_FALSE,
		sizeof(uint32_t) * offset,
		sizeof(uint32_t) * (key_idx - offset),
		plaintext + offset, 0, NULL, multi_profilingEvent[0]),
		"failed in clEnqueueWriteBuffer pass_buffer");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer, CL_FALSE,
		sizeof(uint32_t) * offset,
		sizeof(uint32_t) * (gws - offset),
		saved_idx + offset, 0, NULL, multi_profilingEvent[3]),
		"failed in clEnqueueWriteBuffer idx_buffer");

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
			&gws, lws, 0, NULL, multi_profilingEvent[1]),
			"failed in clEnqueueNDRangeKernel");

	//Read back hashes
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], hash_buffer, CL_FALSE, 0,
			sizeof(uint32_t) * gws, calculated_hash, 0,
			NULL, multi_profilingEvent[2]),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");

	return count;
}

/* ------- Compare functins ------- */
static int cmp_all(void * binary, int count) {
	uint32_t partial_binary;
	size_t gws;

	gws = GET_MULTIPLE_OR_BIGGER(count, local_work_size);
	partial_binary = ((uint32_t *) binary)[0];
	hash_found = 0;

	//Send data to device.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], p_binary_buffer, CL_FALSE, 0,
			sizeof(uint32_t), &partial_binary, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer p_binary_buffer");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], result_buffer, CL_FALSE, 0,
			sizeof(int), &hash_found, 0, NULL, NULL),
			"failed in clEnqueueWriteBuffer p_binary_buffer");

	//Enqueue the kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], cmp_kernel, 1, NULL,
			&gws, &local_work_size, 0, NULL, NULL),
			"failed in clEnqueueNDRangeKernel");

	//Read results back.
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], result_buffer, CL_FALSE, 0,
			sizeof(int), &hash_found, 0, NULL, NULL),
			"failed in reading data back");

	//Do the work
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");

	return hash_found;
}

static int cmp_one(void *binary, int index) {
	return (calculated_hash[index] == ((uint32_t *) binary)[0]);
}

static int cmp_exact(char *source, int index) {
	//I don't know why, but this is called and i have to recheck.
	//If i skip this final test i get:
	//form=raw-sha512-ng-opencl	 guesses: 1468 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]
	//.pot CHK:raw-sha512-ng-opencl	 guesses: 1452 time: 0:00:00:02 : Expected count(s) (1500)  [!!!FAILED!!!]

	uint32_t * binary;
	sha256_hash full_hash;

	crypt_one(index, &full_hash);

	binary = (uint32_t *) get_full_binary(source);
	return !memcmp(binary, (void *) &full_hash, FULL_BINARY_SIZE);
}

/* ------- Binary Hash functions group ------- */
#if 0
static void print_binary(void * binary) {
	uint32_t *bin = binary;
	int i;

	for (i = 0; i < 8; i++)
		fprintf(stderr, "%08x ", bin[i]);
	puts("(Ok)");
}

static void print_hash(int index) {
	fprintf(stderr, "\n");
	fprintf(stderr, "%08x ", calculated_hash[index]);
	puts("");
}
#endif

static int binary_hash_0(void * binary) {
#if 0
	print_binary(binary);
#endif
	return *(ARCH_WORD_32 *) binary & 0xF;
}

//Get Hash functions group.
static int get_hash_0(int index) {
#if 0
	print_hash(index);
#endif
	return calculated_hash[index] & 0xF;
}
static int get_hash_1(int index) { return calculated_hash[index] & 0xff; }
static int get_hash_2(int index) { return calculated_hash[index] & 0xfff; }
static int get_hash_3(int index) { return calculated_hash[index] & 0xffff; }
static int get_hash_4(int index) { return calculated_hash[index] & 0xfffff; }
static int get_hash_5(int index) { return calculated_hash[index] & 0xffffff; }
static int get_hash_6(int index) { return calculated_hash[index] & 0x7ffffff; }

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_rawsha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		RAW_PLAINTEXT_LENGTH - 1,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
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
		fmt_default_salt_hash,
		fmt_default_set_salt,
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
