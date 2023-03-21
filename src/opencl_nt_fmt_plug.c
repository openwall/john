/*
 * NTLM patch for john (performance improvement and OpenCL 1.0 conformant)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2010 and modified
 * by Samuele Giovanni Tonon in 2011.  No copyright is claimed, and
 * the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2010 Alain Espinosa
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * Copyright (c) 2015 Sayantan Datta <sdatta at openwall.com>
 * Copyright (c) 2015-2023 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_NT;
extern struct fmt_main fmt_opencl_NT_long;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_NT);
john_register_one(&fmt_opencl_NT_long);
#else

#include <string.h>
#include <assert.h>
#include <sys/time.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "config.h"
#include "options.h"
#include "unicode.h"
#include "md4.h" // for cmp_exact()
#include "simd-intrinsics.h" // for md4_reverse()
#include "johnswap.h" // for printing of false positives
#include "mask_ext.h"
#include "opencl_hash_check.h"

#define FORMAT_LABEL        "NT-opencl"
#define FORMAT_LABEL_LONG   "NT-long-opencl"
#define FORMAT_NAME         ""
#define FORMAT_TAG          "$NT$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME      "MD4 OpenCL"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define PLAINTEXT_LENGTH    27
#define PLAINTEXT_LEN_LONG  125 /* 59, 91, 123, 125 are supported */
/* At most 3 bytes of UTF-8 needed per character */
#define UTF8_MAX_LENGTH     MIN(125, 3 * utf16len)
#define BUFSIZE             ((UTF8_MAX_LENGTH + 3) / 4 * 4)
#define AUTOTUNE_LENGTH     8
#define CIPHERTEXT_LENGTH   32
#define BINARY_SIZE         8
#define BINARY_ALIGN        sizeof(cl_uint)
#define SALT_SIZE           0
#define SALT_ALIGN          1

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

/* Note: Some plaintexts will be replaced in init() depending on codepage */
static struct fmt_tests tests[] = {
	{"8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$7a21990fcd3d759941e45c490f143d5f", "12345"},
	{"$NT$f9e37e83b83c47a93c2f09f66408631b", "abc123"},
	{"$NT$b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"$NT$2b2ac2d1c7c8fda6cea80b5fad7563aa", "computer"},
	{"$NT$32ed87bdb5fdc5e9cba88547376818d4", "123456"},
	{"$NT$b7e0ea9fbffcf6dd83086e905089effd", "tigger"},
	{"$NT$7ce21f17c0aee7fb9ceba532d0546ad6", "1234"},
	{"$NT$b23a90d0aad9da3615fafc27a1b8baeb", "a1b2c3"},
	{"$NT$2d20d252a479f485cdf5e171d93985bf", "qwerty"},
	{"$NT$3dbde697d71690a769204beb12283678", "123"},
	{"$NT$c889c75b7c1aae1f7150c5681136e70e", "xxx"},
	{"$NT$d5173c778e0f56d9fc47e3b3c829aca7", "money"},
	{"$NT$0cb6948805f797bf2a82807973b89537", "test"},
	{"$NT$0569fcf2b14b9c7f3d3b5f080cbd85e5", "carmen"},
	{"$NT$f09ab1733a528f430353834152c8a90e", "mickey"},
	{"$NT$878d8014606cda29677a44efa1353fc7", "secret"},
	{"$NT$85ac333bbfcbaa62ba9f8afb76f06268", "summer"},
	{"$NT$5962cc080506d90be8943118f968e164", "internet"},
	{"$NT$f07206c3869bda5acd38a3d923a95d2a", "service"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$d0dfc65e8f286ef82f6b172789a0ae1c", "canada"},
	{"$NT$066ddfd4ef0e9cd7c256fe77191ef43c", "hello"},
	{"$NT$39b8620e745b8aa4d1108e22f74f29e2", "ranger"},
	{"$NT$8d4ef8654a9adc66d4f628e94f66e31b", "shadow"},
	{"$NT$320a78179516c385e35a93ffa0b1c4ac", "baseball"},
	{"$NT$e533d171ac592a4e70498a58b854717c", "donald"},
	{"$NT$5eee54ce19b97c11fd02e531dd268b4c", "harley"},
	{"$NT$6241f038703cbfb7cc837e3ee04f0f6b", "hockey"},
	{"$NT$becedb42ec3c5c7f965255338be4453c", "letmein"},
	{"$NT$ec2c9f3346af1fb8e4ee94f286bac5ad", "maggie"},
	{"$NT$f5794cbd75cf43d1eb21fad565c7e21c", "mike"},
	{"$NT$74ed32086b1317b742c3a92148df1019", "mustang"},
	{"$NT$63af6e1f1dd9ecd82f17d37881cb92e6", "snoopy"},
	{"$NT$58def5844fe58e8f26a65fff9deb3827", "buster"},
	{"$NT$f7eb9c06fafaa23c4bcf22ba6781c1e2", "dragon"},
	{"$NT$dd555241a4321657e8b827a40b67dd4a", "jordan"},
	{"$NT$bb53a477af18526ada697ce2e51f76b3", "michael"},
	{"$NT$92b7b06bb313bf666640c5a1e75e0c18", "michelle"},
	{"$NT$0ae2ac07ba42fb76e0d9e5852d00e83f", "xxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{NULL}
};

static struct fmt_tests tests_long[] = {
	{"8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$7a21990fcd3d759941e45c490f143d5f", "12345"},
	{"$NT$0ae2ac07ba42fb76e0d9e5852d00e83f", "xxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$f9e37e83b83c47a93c2f09f66408631b", "abc123"},
	{"$NT$b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"$NT$2b2ac2d1c7c8fda6cea80b5fad7563aa", "computer"},
	{"$NT$32ed87bdb5fdc5e9cba88547376818d4", "123456"},
	{"$NT$b7e0ea9fbffcf6dd83086e905089effd", "tigger"},
	{"$NT$7ce21f17c0aee7fb9ceba532d0546ad6", "1234"},
	{"$NT$b23a90d0aad9da3615fafc27a1b8baeb", "a1b2c3"},
	{"$NT$2d20d252a479f485cdf5e171d93985bf", "qwerty"},
	{"$NT$3dbde697d71690a769204beb12283678", "123"},
	{"$NT$c889c75b7c1aae1f7150c5681136e70e", "xxx"},
	{"$NT$d5173c778e0f56d9fc47e3b3c829aca7", "money"},
	{"$NT$0cb6948805f797bf2a82807973b89537", "test"},
	{"$NT$0569fcf2b14b9c7f3d3b5f080cbd85e5", "carmen"},
	{"$NT$f09ab1733a528f430353834152c8a90e", "mickey"},
	{"$NT$878d8014606cda29677a44efa1353fc7", "secret"},
	{"$NT$85ac333bbfcbaa62ba9f8afb76f06268", "summer"},
	{"$NT$5962cc080506d90be8943118f968e164", "internet"},
#if PLAINTEXT_LEN_LONG > 27
	{"$NT$e4e10a22597efd64ad85ec18c948cbf2", "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$ea1be9a74e6a7ca800ba932293aa2d6d", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$ec1814e21f7f5bed537fbab2e357bb60", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$59c7fe1adebc59dcb0f513cbed87eb92", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$59c1f6430d9d1aea6d9212f4cb6ea3ea", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$ce4e33c64e8fa0084ef3974a8c8ece59", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$4ccdaf5b8534ffc158b96e55669314a3", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
#endif /* 28..59 */
#if PLAINTEXT_LEN_LONG > 59
	{"$NT$889359447c0a6a784f8736e76326ce51", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$9774270d26d6ff5539326a7a39ae4b7a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$15f9da1d28df9e7088bba11c0977a201", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$f99dddb5d218f258fe041d3a9079ff2a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$b1b3356e5e05046ffe6d3f87ae2f8c12", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$5a4880f7cfcaa3bbfc7c6b4ca920970d", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$6c68a921eba1cce568cbe543ecf106ad", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
#endif /* 60..91 */
#if PLAINTEXT_LEN_LONG > 91
	{"$NT$2e99a04f4626ca16d1e40879ece1977e", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$8f83db5a44550b592b7de15b16939a30", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$d756304967ef98371509fa3150b018aa", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$6a66155ad4ebaab10267ddffca3cf2d3", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$01d3b7a7958e26e914ea851a2a3e882c", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$8924aa73dd0ce16a37bdec6edb3c8802", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$afb0648a73bd1e9662ff672251f80f63", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
#endif /* 92..123 */
#if PLAINTEXT_LEN_LONG > 123
	{"$NT$8f637d62e1d14cb97ca150c89222937a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
	{"$NT$9d10efd08eb95db46f9a2badb2a71fcb", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
#endif /* 124..125 */
	{NULL}
};

static int utf16len;    /* We mess with plaintext_length in case of UTF-8 so have to keep track of the original */

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

static cl_mem pinned_saved_keys, pinned_saved_idx, pinned_int_key_loc;
static cl_mem buffer_keys, buffer_idx, buffer_int_keys, buffer_int_key_loc;
static cl_uint *saved_plain, *saved_idx, *saved_int_key_loc;
static int static_gpu_locations[MASK_FMT_INT_PLHDR];

static size_t key_idx;
static size_t key_offset, idx_offset;

static struct fmt_main *self;

#define STEP			0
#define SEED			1024

static const char * warn[] = {
	"key xfer: ",  ", idx xfer: ",  ", crypt: ",  ", res xfer: "
};

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

struct fmt_main fmt_opencl_NT;

static void set_kernel_args_kpc()
{
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 2.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_int_key_loc), (void *) &buffer_int_key_loc), "Error setting argument 3.");
}

static void set_kernel_args()
{
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_int_keys), (void *) &buffer_int_keys), "Error setting argument 4.");
}

static void release_clobj(void);

static void create_clobj(size_t kpc, struct fmt_main *self)
{
	release_clobj();

	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * kpc, NULL, &ret_code);
	if (ret_code != CL_SUCCESS) {
		saved_plain = (cl_uint *) mem_alloc(BUFSIZE * kpc);
		if (saved_plain == NULL)
			HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys.");
	}
	else {
		saved_plain = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * kpc, 0, NULL, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain.");
	}

	pinned_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx.");
	saved_idx = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx.");

	pinned_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_int_key_loc.");
	saved_int_key_loc = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_int_key_loc, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_int_key_loc.");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys.");

	buffer_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx.");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_key_loc.");

	set_kernel_args_kpc();
}

static void create_base_clobj(void)
{
	cl_uint dummy = 0;

	//dummy is used as dummy parameter
	buffer_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 4 * mask_int_cand.num_int_cand, mask_int_cand.int_cand ? mask_int_cand.int_cand : (void *)&dummy, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_keys.");

	ocl_hc_64_crobj(crypt_kernel);

	set_kernel_args();
}

static void release_clobj(void)
{
	if (buffer_idx) {
		if (pinned_saved_keys) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain.");
			HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys.");
		}
		else
			MEM_FREE(saved_plain);
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx.");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc, saved_int_key_loc, 0, NULL, NULL), "Error Unmapping saved_int_key_loc.");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing mappings.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_key_loc), "Error Releasing buffer_int_key_loc.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Error Releasing pinned_saved_idx.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_int_key_loc), "Error Releasing pinned_int_key_loc.");
		buffer_idx = 0;
	}
}

static void release_base_clobj(void)
{
	if (buffer_int_keys) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_keys), "Error Releasing buffer_int_keys.");
		buffer_int_keys = 0;
	}
	ocl_hc_64_rlobj();
}

static void done(void)
{
	release_clobj();
	release_base_clobj();

	if (crypt_kernel) {
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel.");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program.");

		crypt_kernel = NULL;
	}
}

static void init_kernel(unsigned int num_ld_hashes, char *bitmap_para)
{
	char build_opts[5000];
	int i;
	cl_ulong const_cache_size;

	if (crypt_kernel) {
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel.");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program.");

		crypt_kernel = NULL;
	}

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof(cl_ulong), &const_cache_size, 0), "failed to get CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE.");

	sprintf(build_opts, "-D OFFSET_TABLE_SIZE=%u -D HASH_TABLE_SIZE=%u"
#if !NT_FULL_UNICODE
		" -DUCS_2"
#endif
		" -D NUM_LOADED_HASHES=%u -D NUM_INT_KEYS=%u %s -D IS_STATIC_GPU_MASK=%d"
		" -D CONST_CACHE_SIZE=%llu -D%s -D%s -DPLAINTEXT_LENGTH=%d -D LOC_0=%d"
#if MASK_FMT_INT_PLHDR > 1
	" -D LOC_1=%d "
#endif
#if MASK_FMT_INT_PLHDR > 2
	"-D LOC_2=%d "
#endif
#if MASK_FMT_INT_PLHDR > 3
	"-D LOC_3=%d"
#endif
	,ocl_hc_offset_table_size, ocl_hc_hash_table_size,
	num_ld_hashes, mask_int_cand.num_int_cand, bitmap_para, mask_gpu_is_static,
	(unsigned long long)const_cache_size, cp_id2macro(options.target_enc),
	options.internal_cp == UTF_8 ? cp_id2macro(ENC_RAW) :
	cp_id2macro(options.internal_cp), utf16len,
	static_gpu_locations[0]
#if MASK_FMT_INT_PLHDR > 1
	, static_gpu_locations[1]
#endif
#if MASK_FMT_INT_PLHDR > 2
	, static_gpu_locations[2]
#endif
#if MASK_FMT_INT_PLHDR > 3
	, static_gpu_locations[3]
#endif
	);

	opencl_build_kernel("$JOHN/opencl/nt_kernel.cl", gpu_id, build_opts, 0);
	crypt_kernel = clCreateKernel(program[gpu_id], "nt", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
}

static void init(struct fmt_main *_self)
{
	if (!utf16len || _self != self)
		utf16len = _self->params.plaintext_length;

	self = _self;
	ocl_hc_num_loaded_hashes = 0;

	ocl_hc_64_init(_self);

	struct fmt_tests *tests = self->params.tests;

	opencl_prepare_dev(gpu_id);
	mask_int_cand_target = opencl_speed_index(gpu_id) / 300;
	if (options.target_enc == UTF_8) {
		self->params.plaintext_length = UTF8_MAX_LENGTH;
		tests[1].plaintext = "\xC3\xBC";	// German u-umlaut in UTF-8
		tests[1].ciphertext = "$NT$8bd6e4fb88e01009818749c5443ea712";
		tests[2].plaintext = "\xC3\xBC\xC3\xBC"; // two of them
		tests[2].ciphertext = "$NT$cc1260adb6985ca749f150c7e0b22063";
		tests[3].plaintext = "\xE2\x82\xAC";	// euro sign
		tests[3].ciphertext = "$NT$030926b781938db4365d46adc7cfbcb8";
		tests[4].plaintext = "\xE2\x82\xAC\xE2\x82\xAC";
		tests[4].ciphertext = "$NT$682467b963bb4e61943e170a04f7db46";
	} else if (CP_to_Unicode[0xfc] == 0x00fc) {
		tests[1].plaintext = "\xFC";	// u-umlaut in many Latin codepages
		tests[1].ciphertext = "$NT$8bd6e4fb88e01009818749c5443ea712";
		tests[2].plaintext = "\xFC\xFC"; // two of them
		tests[2].ciphertext = "$NT$cc1260adb6985ca749f150c7e0b22063";
		tests[3].plaintext = "\xFC\xFC\xFC";	// 3 of them
		tests[3].ciphertext = "$NT$2e583e8c210fb101994c19877ac53b89";
		tests[4].plaintext = "\xFC\xFC\xFC\xFC";
		tests[4].ciphertext = "$NT$243bb98e7704797f92b1dd7ded6da0d0";
	}
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + FORMAT_TAG_LEN + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		ciphertext += FORMAT_TAG_LEN;

	out[0] = '$';
	out[1] = 'N';
	out[2] = 'T';
	out[3] = '$';

	memcpylwr(&out[FORMAT_TAG_LEN], ciphertext, 32);
	out[36] = 0;

	return out;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
        char *pos;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		ciphertext += FORMAT_TAG_LEN;

        for (pos = ciphertext; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

        if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
        else
	return 0;

}

// here to 'handle' the pwdump files:  user:uid:lmhash:ntlmhash:::
// Note, we address the user id inside loader.
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[33+FORMAT_TAG_LEN+1];

	if (!valid(split_fields[1], self) && split_fields[1][0] != '$') {
		if (split_fields[3] && strlen(split_fields[3]) == 32) {
			sprintf(out, "%s%s", FORMAT_TAG, split_fields[3]);
			if (valid(out,self))
				return out;
		}
	}
	return split_fields[1];
}

static void *get_binary(char *ciphertext)
{
	static unsigned int out[4];
	unsigned int i=0;
	unsigned int temp;

	ciphertext+=4;
	for (; i<4; i++){
		temp  = (atoi16[ARCH_INDEX(ciphertext[i*8+0])])<<4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+1])]);

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+2])])<<12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+3])])<<8;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+4])])<<20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+5])])<<16;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+6])])<<28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+7])])<<24;

		out[i]=temp;
	}

	/* Reverse MD4 steps */
	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;

	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3;

	return out;
}

static int binary_hash_0(void *binary) { return ((unsigned int *)binary)[0] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((unsigned int *)binary)[0] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((unsigned int *)binary)[0] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((unsigned int *)binary)[0] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((unsigned int *)binary)[0] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((unsigned int *)binary)[0] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((unsigned int *)binary)[0] & PH_MASK_6; }

static int get_hash_0(int index) { return bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] & PH_MASK_0; }
static int get_hash_1(int index) { return bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] & PH_MASK_1; }
static int get_hash_2(int index) { return bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] & PH_MASK_2; }
static int get_hash_3(int index) { return bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] & PH_MASK_3; }
static int get_hash_4(int index) { return bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] & PH_MASK_4; }
static int get_hash_5(int index) { return bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] & PH_MASK_5; }
static int get_hash_6(int index) { return bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] & PH_MASK_6; }

static void clear_keys(void)
{
	key_idx = 0;
	key_offset = 0;
	idx_offset = 0;
}

static void set_key(char *_key, int index)
{
	const uint32_t *key = (uint32_t*)_key;
	int len = strlen(_key);

	if (mask_int_cand.num_int_cand > 1 && !mask_gpu_is_static) {
		int i;
		saved_int_key_loc[index] = 0;
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
			if (mask_skip_ranges[i] != -1)  {
				saved_int_key_loc[index] |= ((mask_int_cand.
				int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset +
				mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos) & 0xff) << (i << 3);
			}
			else
				saved_int_key_loc[index] |= 0x80 << (i << 3);
		}
	}

	saved_idx[index] = (key_idx << 7) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));

	/* Early partial transfer to GPU every 2 MB */
	if (4 * key_idx - key_offset > (2 << 20)) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_FALSE, key_offset, 4 * key_idx - key_offset, saved_plain + key_offset / 4, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_keys.");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_FALSE, idx_offset, 4 * (index + 1) - idx_offset, saved_idx + idx_offset / 4, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_idx.");

		if (!mask_gpu_is_static)
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_FALSE, idx_offset, 4 * (index + 1) - idx_offset, saved_int_key_loc + idx_offset / 4, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_int_key_loc.");

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");

		key_offset = 4 * key_idx;
		idx_offset = 4 * (index + 1);
	}
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_BUFFER_SIZE];
	int i, len, int_index, t;
	char *key;

	if (ocl_hc_hash_ids == NULL || ocl_hc_hash_ids[0] == 0 ||
	    index >= ocl_hc_hash_ids[0] || ocl_hc_hash_ids[0] > ocl_hc_num_loaded_hashes) {
		t = index;
		int_index = 0;
	}
	else  {
		t = ocl_hc_hash_ids[1 + 3 * index];
		int_index = ocl_hc_hash_ids[2 + 3 * index];

	}

	if (t >= global_work_size) {
		//fprintf(stderr, "Get key error! %d %d\n", t, index);
		t = 0;
	}

	len = saved_idx[t] & 127;
	key = (char*)&saved_plain[saved_idx[t] >> 7];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	if (len && mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			if (mask_gpu_is_static)
				out[static_gpu_locations[i]] =
				mask_int_cand.int_cand[int_index].x[i];
			else
				out[(saved_int_key_loc[t]& (0xff << (i * 8))) >> (i * 8)] =
				mask_int_cand.int_cand[int_index].x[i];
	}

	/* Ensure truncation due to over-length or invalid UTF-8 is made like in GPU code. */
	if (options.target_enc == UTF_8)
		truncate_utf8((UTF8*)out, utf16len);

	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	//fprintf(stderr, "%s(%d) lws "Zu" gws "Zu" idx %u int_cand %d\n", __FUNCTION__, count, local_work_size, gws, key_idx, mask_int_cand.num_int_cand);

	// copy keys to the device
	if (key_idx)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_FALSE, key_offset, 4 * key_idx - key_offset, saved_plain + key_offset / 4, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer buffer_keys.");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_FALSE, idx_offset, 4 * gws - idx_offset, saved_idx + idx_offset / 4, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer buffer_idx.");

	if (!mask_gpu_is_static)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_FALSE, idx_offset, 4 * gws - idx_offset, saved_int_key_loc + idx_offset / 4, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_int_key_loc.");

	return ocl_hc_64_extract_info(salt, set_kernel_args, set_kernel_args_kpc, init_kernel, gws, lws, pcount);
}

static void reset(struct db_main *db)
{
	release_base_clobj();
	release_clobj();

	ocl_hc_num_loaded_hashes = db->salts->count;
	ocl_hc_64_prepare_table(db->salts);
	init_kernel(ocl_hc_num_loaded_hashes, ocl_hc_64_select_bitmap(ocl_hc_num_loaded_hashes));

	create_base_clobj();

	size_t gws_limit = MIN((0xf << 21) * 4 / BUFSIZE,
	                       get_max_mem_alloc_size(gpu_id) / BUFSIZE);
	get_power_of_two(gws_limit);
	if (gws_limit > MIN((0xf << 21) * 4 / BUFSIZE,
	                    get_max_mem_alloc_size(gpu_id) / BUFSIZE))
		gws_limit >>= 1;

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 1, NULL, warn, 2, self,
	                       create_clobj, release_clobj,
	                       2 * BUFSIZE, gws_limit, db);

	// Auto tune execution from shared/included code.
	autotune_run_extra(self, 1, gws_limit, 200, CL_TRUE);
}

static int cmp_exact(char *source, int index)
{
	unsigned int *binary = self->methods.binary(source);
	unsigned int hash[4];
	char *password = self->methods.get_key(index);
	UTF16 key[PLAINTEXT_BUFFER_SIZE];
	int len = enc_to_utf16(key, PLAINTEXT_BUFFER_SIZE, (UTF8*)password, (unsigned int)strlen(password));
	MD4_CTX ctx;

	MD4_Init(&ctx);
	MD4_Update(&ctx, key, 2 * len);
	MD4_Final((unsigned char*)hash, &ctx);
	md4_reverse(hash);
	int result = !memcmp(hash, binary, 16);
#if DEBUG
	if (!result) {
		fprintf(stderr, "\n64-bit collision detected by kernel and %s(%d)\n", __FUNCTION__, index);
		dump_stderr_msg("             expected", binary, 16);
		dump_stderr_msg("           calculated", hash, 16);
		md4_unreverse(hash);
		md4_unreverse(binary);
		dump_stderr_msg("unreversed   expected", binary, 16);
		dump_stderr_msg("unreversed calculated", hash, 16);
		fprintf(stderr, "Plaintext  : %s\n\n", self->methods.get_key(index));
	}
#endif
	return result;
}

struct fmt_main fmt_opencl_NT = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC | FMT_REMOVE | FMT_MASK,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		reset,
		prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL },
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
		ocl_hc_64_cmp_all,
		ocl_hc_64_cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_opencl_NT_long = {
	{
		FORMAT_LABEL_LONG,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LEN_LONG,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC | FMT_REMOVE | FMT_MASK,
		{ NULL },
		{ FORMAT_TAG },
		tests_long
	}, {
		init,
		done,
		reset,
		prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
		{ NULL },
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
		ocl_hc_64_cmp_all,
		ocl_hc_64_cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
