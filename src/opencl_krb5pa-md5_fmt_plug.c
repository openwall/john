/*
 * Kerberos 5 etype 23 "PA ENC TIMESTAMP" by magnum
 *
 * Previously called mskrb5 because I had the idea it was Micro$oft specific.
 *
 * Pcap file -> input file:
 * 1. tshark -r capture.pcapng -T pdml  > ~/capture.pdml
 * 2. krbng2john.py ~/capture.pdml > krb5.in
 * 3. Run john on krb5.in
 *
 * Legacy input format:
 * user:$mskrb5$user$realm$checksum$timestamp
 *
 * New input format from krb2john.py (the above is still supported)
 * user:$krb5pa$etype$user$realm$salt$timestamp+checksum
 *
 * user, realm and salt are unused in this format.
 *
 * This software is Copyright (c) 2013 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 *
 */

#ifdef HAVE_OPENCL
#define FMT_STRUCT fmt_opencl_krb5pa_md5

#if FMT_EXTERNS_H
extern struct fmt_main FMT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FMT_STRUCT);
#else

#include <string.h>

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "opencl_common.h"
#include "config.h"
#include "unicode.h"
#include "loader.h"

#include "md4.h"
#include "hmacmd5.h"
#include "rc4.h"
#include "mask_ext.h"
#include "bt_interface.h"

#define FORMAT_LABEL            "krb5pa-md5-opencl"
#define FORMAT_NAME             "Kerberos 5 AS-REQ Pre-Auth etype 23"
#define FORMAT_TAG              "$krb5pa$23$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG2             "$mskrb5$"
#define FORMAT_TAG2_LEN         (sizeof(FORMAT_TAG2)-1)
#define ALGORITHM_NAME          "MD4 HMAC-MD5 RC4 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        27
#define UTF8_MAX_LENGTH         (3 * PLAINTEXT_LENGTH)
#define BUFSIZE                 ((UTF8_MAX_LENGTH + 3) / 4 * 4)
#define AUTOTUNE_LENGTH         8
#define MAX_REALMLEN            64
#define MAX_USERLEN             64
#define MAX_SALTLEN             128
#define TIMESTAMP_SIZE          36
#define CHECKSUM_SIZE           16
#define KEY_SIZE                16
#define BINARY_SIZE             CHECKSUM_SIZE
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(salt_t)
#define SALT_ALIGN              4
#define SALT_PARAM_BASE         ((int)SALT_SIZE / 4)
#define TOTAL_LENGTH            (14 + 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) + MAX_REALMLEN + MAX_USERLEN + MAX_SALTLEN)

/* these will be altered in init() depending on GPU */
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

// Second and third plaintext will be replaced in init() under come encodings
static struct fmt_tests tests[] = {
	{"$krb5pa$23$user$realm$salt$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7daeb03b6fbcfe91f8346f3c0ae7e8abfe5", "John"},
	{"$mskrb5$john$JOHN.DOE.MS.COM$02E837D06B2AC76891F388D9CC36C67A$2A9785BF5036C45D3843490BF9C228E8C18653E10CE58D7F8EF119D2EF4F92B1803B1451", "fr2beesgr"},
	{"$mskrb5$user1$EXAMPLE.COM$08b5adda3ab0add14291014f1d69d145$a28da154fa777a53e23059647682eee2eb6c1ada7fb5cad54e8255114270676a459bfe4a", "openwall"},
	{"$mskrb5$hackme$EXAMPLE.NET$e3cdf70485f81a85f7b59a4c1d6910a3$6e2f6705551a76f84ec2c92a9dd0fef7b2c1d4ca35bf1b02423359a3ecaa19bdf07ed0da", "openwall@123"},
	{"$mskrb5$$$98cd00b6f222d1d34e08fe0823196e0b$5937503ec29e3ce4e94a051632d0fff7b6781f93e3decf7dca707340239300d602932154", ""},
	{"$mskrb5$$$F4085BA458B733D8092E6B348E3E3990$034ACFC70AFBA542690B8BC912FCD7FED6A848493A3FF0D7AF641A263B71DCC72902995D", "frank"},
	{"$mskrb5$user$realm$eb03b6fbcfe91f8346f3c0ae7e8abfe5$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7da", "John"},
	{"$mskrb5$$$881c257ce5df7b11715a6a60436e075a$c80f4a5ec18e7c5f765fb9f00eda744a57483db500271369cf4752a67ca0e67f37c68402", "the"},
	{"$mskrb5$$$ef012e13c8b32448241091f4e1fdc805$354931c919580d4939421075bcd50f2527d092d2abdbc0e739ea72929be087de644cef8a", "Ripper"},
#if PLAINTEXT_LENGTH >= 31
	{"$mskrb5$$$334ef74dad191b71c43efaa16aa79d88$34ebbad639b2b5a230b7ec1d821594ed6739303ae6798994e72bd13d5e0e32fdafb65413", "VeryveryveryloooooooongPassword"},
#endif
	// repeat first hash in exactly the same form that is used in john.pot
	{"$krb5pa$23$$$$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7daeb03b6fbcfe91f8346f3c0ae7e8abfe5", "John"},
	// http://www.exumbraops.com/layerone2016/party (sample.krb.pcap, hash extracted by krb2john.py)
	{"$krb5pa$23$$$$4b8396107e9e4ec963c7c2c5827a4f978ad6ef943f87637614c0f31b2030ad1115d636e1081340c5d6612a3e093bd40ce8232431", "P@$$w0rd123"},
	{NULL}
};

typedef struct {
	uint32_t checksum[CHECKSUM_SIZE / sizeof(uint32_t)];
	unsigned char timestamp[TIMESTAMP_SIZE];
} salt_t;

static cl_mem pinned_saved_keys, pinned_saved_idx, pinned_int_key_loc;
static cl_mem buffer_keys, buffer_idx, buffer_int_keys, buffer_int_key_loc;
static cl_uint *saved_plain, *saved_idx, *saved_int_key_loc;
static int static_gpu_locations[MASK_FMT_INT_PLHDR];

static cl_mem buffer_return_hashes, buffer_hash_ids, buffer_bitmap_dupe;
static cl_mem *buffer_offset_tables, *buffer_hash_tables, *buffer_bitmaps, *buffer_salts;
static OFFSET_TABLE_WORD *offset_table;
static unsigned int **hash_tables;
static unsigned int current_salt;
static cl_uint *loaded_hashes, max_num_loaded_hashes, *hash_ids, *bitmaps, max_hash_table_size;
static cl_ulong bitmap_size_bits;

static unsigned int key_idx;
static unsigned int new_keys;
static struct fmt_main *self;
static cl_uint *zero_buffer;

#define STEP                    0
#define SEED                    1024

static const char *warn[] = {
	"key xfer: ",  ", idx xfer: ",  ", crypt: ",  ", res xfer: "
};

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return MIN(autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel), 32);
}

struct fmt_main FMT_STRUCT;

static void set_kernel_args_kpc()
{
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 2.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_int_key_loc), (void *) &buffer_int_key_loc), "Error setting argument 4.");
}

static void set_kernel_args()
{
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(buffer_int_keys), (void *) &buffer_int_keys), "Error setting argument 5.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 8, sizeof(buffer_return_hashes), (void *) &buffer_return_hashes), "Error setting argument 9.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 9, sizeof(buffer_hash_ids), (void *) &buffer_hash_ids), "Error setting argument 10.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 10, sizeof(buffer_bitmap_dupe), (void *) &buffer_bitmap_dupe), "Error setting argument 11.");
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

static void create_base_clobj()
{
	unsigned int dummy = 0;

	zero_buffer = (cl_uint *) mem_calloc(max_hash_table_size/32 + 1, sizeof(cl_uint));

	buffer_return_hashes = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 2 * sizeof(cl_uint) * max_num_loaded_hashes, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_return_hashes.");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (3 * max_num_loaded_hashes + 1) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_buffer_hash_ids.");

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, (max_hash_table_size/32 + 1) * sizeof(cl_uint), zero_buffer, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap_dupe.");

	//ref_ctr is used as dummy parameter
	buffer_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 4 * mask_int_cand.num_int_cand, mask_int_cand.int_cand ? mask_int_cand.int_cand : (void *)&dummy, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_keys.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");

	set_kernel_args();
}

static void release_clobj(void)
{
	if (buffer_keys) {
		if (pinned_saved_keys) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain.");
			HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys.");
		}
		else
			MEM_FREE(saved_plain);

		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx.");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc, saved_int_key_loc, 0, NULL, NULL), "Error Unmapping saved_int_key_loc.");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing mappings.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Error Releasing pinned_saved_idx.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_int_key_loc), "Error Releasing pinned_int_key_loc.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_key_loc), "Error Releasing buffer_int_key_loc.");
		buffer_keys = 0;
	}
}

static void release_base_clobj(void)
{
	if (buffer_int_keys) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_keys), "Error Releasing buffer_int_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_return_hashes), "Error Releasing buffer_return_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error Releasing buffer_bitmap_dupe.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Error Releasing buffer_hash_ids.");
		MEM_FREE(zero_buffer);
		buffer_int_keys = 0;
	}
}

static void release_salt_buffers()
{
	unsigned int k;
	if (hash_tables) {
		k = 0;
		while (hash_tables[k]) {
			MEM_FREE(hash_tables[k]);
			k++;
		}
		MEM_FREE(hash_tables);
	}
	if (buffer_offset_tables) {
		k = 0;
		while (buffer_offset_tables[k]) {
			clReleaseMemObject(buffer_offset_tables[k]);
			buffer_offset_tables[k] = 0;
			k++;
		}
		MEM_FREE(buffer_offset_tables);
	}
	if (buffer_hash_tables) {
		k = 0;
		while (buffer_hash_tables[k]) {
			clReleaseMemObject(buffer_hash_tables[k]);
			buffer_hash_tables[k] = 0;
			k++;
		}
		MEM_FREE(buffer_hash_tables);
	}
	if (buffer_bitmaps) {
		k = 0;
		while (buffer_bitmaps[k]) {
			clReleaseMemObject(buffer_bitmaps[k]);
			buffer_bitmaps[k] = 0;
			k++;
		}
		MEM_FREE(buffer_bitmaps);
	}
	if (buffer_salts) {
		k = 0;
		while (buffer_salts[k]) {
			clReleaseMemObject(buffer_salts[k]);
			buffer_salts[k] = 0;
			k++;
		}
		MEM_FREE(buffer_salts);
	}
}

static void done(void)
{
	release_clobj();
	release_base_clobj();

	if (crypt_kernel) {
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel.");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program.");
		crypt_kernel = NULL;
		program[gpu_id] = NULL;
	}

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (hash_ids)
		MEM_FREE(hash_ids);
	release_salt_buffers();
}

static void init_kernel(void)
{
	char build_opts[5000];
	int i;
	cl_ulong const_cache_size;

	clReleaseKernel(crypt_kernel);
	crypt_kernel = NULL;

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof(cl_ulong), &const_cache_size, 0), "failed to get CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE.");

	sprintf(build_opts, "-DNUM_INT_KEYS=%u -DIS_STATIC_GPU_MASK=%d -DSALT_PARAM_BASE=%u"
#if !NT_FULL_UNICODE
		" -DUCS_2"
#endif
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
    , mask_int_cand.num_int_cand, mask_gpu_is_static, SALT_PARAM_BASE,
	(unsigned long long)const_cache_size, cp_id2macro(options.target_enc),
	options.internal_cp == UTF_8 ? cp_id2macro(ENC_RAW) :
	cp_id2macro(options.internal_cp), PLAINTEXT_LENGTH,
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

	if (!program[gpu_id])
		opencl_build_kernel("$JOHN/opencl/krb5pa-md5_kernel.cl", gpu_id, build_opts, 0);
	if (!crypt_kernel) {
		crypt_kernel = clCreateKernel(program[gpu_id], "krb5pa_md5", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	}
}

static void set_key(char *_key, int index);

static void init(struct fmt_main *_self)
{
	self = _self;
	max_num_loaded_hashes = 0;

	opencl_prepare_dev(gpu_id);
	mask_int_cand_target = opencl_speed_index(gpu_id) >> 16;

	if (options.target_enc == UTF_8) {
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;

		tests[1].plaintext = "\xC3\xBC"; // German u-umlaut in UTF-8
		tests[1].ciphertext = "$mskrb5$$$958db4ddb514a6cc8be1b1ccf82b0191$090408357a6f41852d17f3b4bb4634adfd388db1be64d3fe1a1d75ee4338d2a4aea387e5";
		tests[2].plaintext = "\xC3\x9C\xC3\x9C"; // 2x uppercase of them
		tests[2].ciphertext = "$mskrb5$$$057cd5cb706b3de18e059912b1f057e3$fe2e561bd4e42767e972835ea99f08582ba526e62a6a2b6f61364e30aca7c6631929d427";
	} else {
		if (CP_to_Unicode[0xfc] == 0x00fc) {
			tests[1].plaintext = "\xFC";     // German u-umlaut in many ISO-8859-x
			tests[1].ciphertext = "$mskrb5$$$958db4ddb514a6cc8be1b1ccf82b0191$090408357a6f41852d17f3b4bb4634adfd388db1be64d3fe1a1d75ee4338d2a4aea387e5";
		}
		if (CP_to_Unicode[0xdc] == 0x00dc) {
			tests[2].plaintext = "\xDC\xDC"; // 2x uppercase of them
			tests[2].ciphertext = "$mskrb5$$$057cd5cb706b3de18e059912b1f057e3$fe2e561bd4e42767e972835ea99f08582ba526e62a6a2b6f61364e30aca7c6631929d427";
		}
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *data = ciphertext, *p;

	if (!strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG2_LEN)) {
		data += FORMAT_TAG2_LEN;

		// user field
		p = strchr(data, '$');
		if (!p || p - data > MAX_USERLEN)
			return 0;
		data = p + 1;

		// realm field
		p = strchr(data, '$');
		if (!p || p - data > MAX_REALMLEN)
			return 0;
		data = p + 1;

		// checksum
		p = strchr(data, '$');
		if (!p || p - data != 2 * CHECKSUM_SIZE ||
		    strspn(data, HEXCHARS_all) != p - data)
			return 0;
		data = p + 1;

		// encrypted timestamp
		p += strlen(data) + 1;
		if (*p || p - data != TIMESTAMP_SIZE * 2 ||
		    strspn(data, HEXCHARS_all) != p - data)
			return 0;

		return 1;
	} else if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		data += FORMAT_TAG_LEN;

		// user field
		p = strchr(data, '$');
		if (!p || p - data > MAX_USERLEN)
			return 0;
		data = p + 1;

		// realm field
		p = strchr(data, '$');
		if (!p || p - data > MAX_REALMLEN)
			return 0;
		data = p + 1;

		// salt field
		p = strchr(data, '$');
		if (!p || p - data > MAX_SALTLEN)
			return 0;
		data = p + 1;

		// timestamp+checksum
		p += strlen(data) + 1;
		if (*p || p - data != (TIMESTAMP_SIZE + CHECKSUM_SIZE) * 2 ||
		    strspn(data, HEXCHARS_all) != p - data)
			return 0;

		return 1;
	}
	return 0;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TOTAL_LENGTH + 1];
	char *data;

	if (!strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG2_LEN)) {
		char in[TOTAL_LENGTH + 1];
		char *c, *t;

		strnzcpy(in, ciphertext, sizeof(in));

		t = strrchr(in, '$'); *t++ = 0;
		c = strrchr(in, '$'); *c++ = 0;

		snprintf(out, sizeof(out), "%s$$$%s%s", FORMAT_TAG, t, c);
	} else {
		char *tc;

		tc = strrchr(ciphertext, '$');

		snprintf(out, sizeof(out), "%s$$$%s", FORMAT_TAG, ++tc);
	}

	data = out + strlen(out) - 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) - 1;
	strlwr(data);

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *binary;
	char *p;
	int i;

	if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = strrchr(ciphertext, '$') + 1;
		p += 2 * TIMESTAMP_SIZE;

	for (i = 0; i < CHECKSUM_SIZE; i++) {
		binary[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return (void*)binary;
}

static void *get_salt(char *ciphertext)
{
	static salt_t salt;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
		for (i = 0; i < TIMESTAMP_SIZE; i++) {
			salt.timestamp[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
			p += 2;
		}
		for (i = 0; i < CHECKSUM_SIZE; i++) {
			((unsigned char*)salt.checksum)[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
			p += 2;
	}
	return (void*)&salt;
}

static int get_hash_0(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & PH_MASK_0; }
static int get_hash_1(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & PH_MASK_1; }
static int get_hash_2(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & PH_MASK_2; }
static int get_hash_3(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & PH_MASK_3; }
static int get_hash_4(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & PH_MASK_4; }
static int get_hash_5(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & PH_MASK_5; }
static int get_hash_6(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & PH_MASK_6; }

static void clear_keys(void)
{
	key_idx = 0;
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
	new_keys = 1;
}

static char *get_key(int index)
{
	static char out[UTF8_MAX_LENGTH + 1];
	int i, len, int_index, t;
	char *key;

	if (hash_ids == NULL || hash_ids[0] == 0 ||
	    index >= hash_ids[0] || hash_ids[0] > max_num_loaded_hashes) {
		t = index;
		int_index = 0;
	}
	else  {
		t = hash_ids[1 + 3 * index];
		int_index = hash_ids[2 + 3 * index];

	}

	if (t >= global_work_size) {
		t = 0;
		int_index = 0;
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
		truncate_utf8((UTF8*)out, PLAINTEXT_LENGTH);

	return out;
}

/* Use only for smaller bitmaps < 16MB */
static void prepare_bitmap_4(cl_ulong bmp_sz, cl_uint **bitmap_ptr, uint32_t num_loaded_hashes)
{
	unsigned int i;
	MEM_FREE(*bitmap_ptr);
	*bitmap_ptr = (cl_uint*) mem_calloc((bmp_sz >> 3), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[4 * i + 3] & (bmp_sz - 1);
		(*bitmap_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[4 * i + 2] & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[4 * i + 1] & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 4) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[4 * i] & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) * 3 + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));
	}
}
/*
static void prepare_bitmap_1(cl_ulong bmp_sz, cl_uint **bitmap_ptr, uint32_t num_loaded_hashes)
{
	unsigned int i;
	MEM_FREE(*bitmap_ptr);
	*bitmap_ptr = (cl_uint*) mem_calloc((bmp_sz >> 5), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[4 * i + 3] & (bmp_sz - 1);
		(*bitmap_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));
	}
}*/

static void select_bitmap(unsigned int num_loaded_hashes)
{
	cl_ulong max_local_mem_sz_bytes = 0;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_LOCAL_MEM_SIZE,
		sizeof(cl_ulong), &max_local_mem_sz_bytes, 0),
		"failed to get CL_DEVICE_LOCAL_MEM_SIZE.");

	if (num_loaded_hashes <= 5100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;

		else
			bitmap_size_bits = 256 * 1024;
	}

	else if (num_loaded_hashes <= 10100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;

		else
			bitmap_size_bits = 256 * 1024;

	}

	else if (num_loaded_hashes <= 20100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 1024 * 1024;

		else
			bitmap_size_bits = 512 * 1024;

	}

	else if (num_loaded_hashes <= 250100)
		bitmap_size_bits = 2048 * 1024;

	else if (num_loaded_hashes <= 1100100) {
		if (!amd_gcn_11(device_info[gpu_id]))
			bitmap_size_bits = 4096 * 1024;

		else
			bitmap_size_bits = 2048 * 1024;
	}
	else {
		fprintf(stderr, "Too many hashes (%d), max is 1100100\n",
		        num_loaded_hashes);
		error();
	}

	prepare_bitmap_4(bitmap_size_bits, &bitmaps, num_loaded_hashes);
}

static void prepare_table(struct db_main *db)
{
	struct db_salt *salt;
	int seq_ids = 0;

	max_num_loaded_hashes = 0;
	max_hash_table_size = 1;

	salt = db->salts;
	do {
		if (salt->count > max_num_loaded_hashes)
			max_num_loaded_hashes = salt->count;
	} while ((salt = salt->next));

	MEM_FREE(loaded_hashes);
	MEM_FREE(hash_ids);
	release_salt_buffers();

	loaded_hashes = (cl_uint*) mem_alloc(4 * max_num_loaded_hashes * sizeof(cl_uint));
	hash_ids = (cl_uint*) mem_calloc((3 * max_num_loaded_hashes + 1), sizeof(cl_uint));

	hash_tables = (unsigned int **)mem_calloc(sizeof(unsigned int*), db->salt_count + 1);
	buffer_offset_tables = (cl_mem *)mem_calloc(sizeof(cl_mem), db->salt_count + 1);
	buffer_hash_tables = (cl_mem *)mem_calloc(sizeof(cl_mem), db->salt_count + 1);
	buffer_bitmaps = (cl_mem *)mem_calloc(sizeof(cl_mem), db->salt_count + 1);
	buffer_salts = (cl_mem *)mem_calloc(sizeof(cl_mem), db->salt_count + 1);

	hash_tables[db->salt_count] = NULL;
	buffer_offset_tables[db->salt_count] = NULL;
	buffer_hash_tables[db->salt_count] = NULL;
	buffer_bitmaps[db->salt_count] = NULL;
	buffer_salts[db->salt_count] = NULL;

	salt = db->salts;
	do {
		unsigned int i = 0;
		unsigned int num_loaded_hashes, salt_params[SALT_SIZE / sizeof(unsigned int) + 5];
		unsigned int hash_table_size, offset_table_size, shift64_ht_sz, shift64_ot_sz;
		struct db_password *pw, *last;

		last = pw = salt->list;
		do {
			unsigned int *bin = (unsigned int *)pw->binary;
			if (bin == NULL) {
				if (last == pw)
					salt->list = pw->next;
				else
					last->next = pw->next;
			} else {
				last = pw;
				loaded_hashes[4 * i] = bin[0];
				loaded_hashes[4 * i + 1] = bin[1];
				loaded_hashes[4 * i + 2] = bin[2];
				loaded_hashes[4 * i + 3] = bin[3];
				i++;
			}
		} while ((pw = pw->next));

		if (i != salt->count) {
			fprintf(stderr,
				"Something went wrong while preparing hashes..Exiting..\n");
			error();
		}
		num_loaded_hashes = salt->count;
		salt->sequential_id = seq_ids++;

		num_loaded_hashes = bt_create_perfect_hash_table(128, (void*)loaded_hashes,
		                                              num_loaded_hashes,
		                                              &offset_table,
		                                              &offset_table_size,
		                                              &hash_table_size, 0);

		if (!num_loaded_hashes) {
			MEM_FREE(bt_hash_table_128);
			fprintf(stderr, "Failed to create Hash Table for cracking.\n");
			error();
		}

		hash_tables[salt->sequential_id] = bt_hash_table_128;

		buffer_offset_tables[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, offset_table_size * sizeof(OFFSET_TABLE_WORD), offset_table, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_offset_tables[].");

		buffer_hash_tables[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, hash_table_size * sizeof(unsigned int) * 2, bt_hash_table_128, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_hash_tables[].");

		if (max_hash_table_size < hash_table_size)
			max_hash_table_size = hash_table_size;

		shift64_ht_sz = (((1ULL << 63) % hash_table_size) * 2) % hash_table_size;
		shift64_ot_sz = (((1ULL << 63) % offset_table_size) * 2) % offset_table_size;

		select_bitmap(num_loaded_hashes);

		memcpy(salt_params, salt->salt, SALT_SIZE);
		salt_params[SALT_PARAM_BASE + 0] = bitmap_size_bits - 1;
		salt_params[SALT_PARAM_BASE + 1] = offset_table_size;
		salt_params[SALT_PARAM_BASE + 2] = hash_table_size;
		salt_params[SALT_PARAM_BASE + 3] = shift64_ot_sz;
		salt_params[SALT_PARAM_BASE + 4] = shift64_ht_sz;

		buffer_bitmaps[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)(bitmap_size_bits >> 3) * 2, bitmaps, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmaps[].");

		buffer_salts[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, SALT_SIZE + 5 * sizeof(unsigned int), salt_params, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_salts[].");

		MEM_FREE(bitmaps);
		MEM_FREE(offset_table);

	} while ((salt = salt->next));
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	/* kernel is made for lws 32, using local memory */
	size_t lws = local_work_size ? local_work_size : 32;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	//fprintf(stderr, "%s(%d) lws "Zu" gws "Zu" idx %u int_cand %d\n", __FUNCTION__, count, local_work_size, gws, key_idx, mask_int_cand.num_int_cand);

	// copy keys to the device
	if (new_keys) {
		if (key_idx)
			BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_FALSE, 0, 4 * key_idx, saved_plain, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer buffer_keys.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_FALSE, 0, 4 * gws, saved_idx, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer buffer_idx.");
		if (!mask_gpu_is_static)
			BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_FALSE, 0, 4 * gws, saved_int_key_loc, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_int_key_loc.");
		new_keys = 0;
	}

	current_salt = salt->sequential_id;
	BENCH_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_salts[current_salt]), (void *) &buffer_salts[current_salt]), "Error setting argument 3.");
	BENCH_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(buffer_bitmaps[current_salt]), (void *) &buffer_bitmaps[current_salt]), "Error setting argument 6.");
	BENCH_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_offset_tables[current_salt]), (void *) &buffer_offset_tables[current_salt]), "Error setting argument 7.");
	BENCH_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(buffer_hash_tables[current_salt]), (void *) &buffer_hash_tables[current_salt]), "Error setting argument 8.");

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, &lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), hash_ids, 0, NULL, multi_profilingEvent[3]), "failed in reading back num cracked hashes.");

	if (hash_ids[0] > max_num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_return_hashes, CL_FALSE, 0, 2 * sizeof(cl_uint) * hash_ids[0], loaded_hashes, 0, NULL, NULL), "failed in reading back return_hashes.");
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (3 * hash_ids[0] + 1) * sizeof(cl_uint), hash_ids, 0, NULL, NULL), "failed in reading data back hash_ids.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_FALSE, 0, (max_hash_table_size/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmap_dupe.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
	}

	*pcount *= mask_int_cand.num_int_cand;
	return hash_ids[0];
}

static int cmp_all(void *binary, int count)
{
	if (count) return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (((unsigned int*)binary)[0] ==
		hash_tables[current_salt][hash_ids[3 + 3 * index]]);
}

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) get_binary(source);

	if (t[2] != loaded_hashes[2 * index])
		return 0;
	if (t[3] != loaded_hashes[2 * index + 1])
		return 0;
	return 1;
}

static void reset(struct db_main *db)
{
	if (crypt_kernel)
		done();

	release_base_clobj();
	release_clobj();

	prepare_table(db);
	init_kernel();

	create_base_clobj();

	current_salt = 0;
	hash_ids[0] = 0;

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
	autotune_run_extra(self, 11, gws_limit, 200, CL_TRUE);
}

struct fmt_main FMT_STRUCT = {
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
		{ FORMAT_TAG, FORMAT_TAG2 },
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
		{ NULL },
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
