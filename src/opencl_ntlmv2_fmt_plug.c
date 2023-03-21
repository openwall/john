/*
 * OpenCL NTLMv2 -- NTLMv2 Challenge/Response
 *
 * Based on code written by JoMo-Kun <jmk at foofus.net> in 2009
 *
 * This software is
 * Copyright (c) 2016, magnum
 * Copyright (c) 2015, Sayantan Datta <std2048@gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This algorithm is designed for performing brute-force cracking of the NTLMv2
 * challenge/response sets exchanged during network-based authentication
 * attempts. The captured challenge/response set from these attempts
 * should be stored using the following format:
 *
 * USERNAME::DOMAIN:SERVER CHALLENGE:NTLMv2 RESPONSE:CLIENT CHALLENGE
 *
 * For example:
 * ntlmv2test::WORKGROUP:1122334455667788:07659A550D5E9D02996DFD95C87EC1D5:0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000
 *
 */

#ifdef HAVE_OPENCL
#define FMT_STRUCT fmt_opencl_NTLMv2

#if FMT_EXTERNS_H
extern struct fmt_main FMT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FMT_STRUCT);
#else

#include <string.h>
#include <sys/time.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "opencl_common.h"
#include "config.h"
#include "options.h"
#include "unicode.h"
#include "mask_ext.h"
#include "bt_interface.h"

#define PLAINTEXT_LENGTH        27
#define UTF8_MAX_LENGTH         (3 * PLAINTEXT_LENGTH)
#define BUFSIZE                 ((UTF8_MAX_LENGTH + 3) / 4 * 4)
#define AUTOTUNE_LENGTH         8
#define FORMAT_LABEL            "ntlmv2-opencl"
#define FORMAT_NAME             "NTLMv2 C/R"
#define FORMAT_TAG              "$NETNTLMv2$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "MD4 HMAC-MD5 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define SALT_MAX_LENGTH         59 /* Username + Domainname len in characters */
#define BINARY_SIZE             16 /* octets */
#define BINARY_ALIGN            4
#define SERVER_CHALL_LENGTH     16 /* hex chars */
#define CLIENT_CHALL_LENGTH_MAX (1024 - SERVER_CHALL_LENGTH - 128) /* hex */
#define SALT_SIZE_MAX           584 /* octets of salt blob */
#define SALT_PARAM_BASE         (SALT_SIZE_MAX / 4)
#define SALT_ALIGN              4
#define CIPHERTEXT_LENGTH       32 /* hex chars */
#define TOTAL_LENGTH            (12 + 3 * SALT_MAX_LENGTH + 1 + SERVER_CHALL_LENGTH + 1 + CLIENT_CHALL_LENGTH_MAX + 1 + CIPHERTEXT_LENGTH + 1)

/* these will be altered in init() depending on GPU */
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests tests[] = {
	{"", "password",                  {"TESTWORKGROUP\\NTlmv2", "", "",              "1122334455667788","07659A550D5E9D02996DFD95C87EC1D5","0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"} },
	{"$NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000", "password"},
	{"$NETNTLMv2$TESTUSERW2K3ADWIN7$1122334455667788$989B96DC6EAB529F72FCBA852C0D5719$01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000", "testpass"},
	{"$NETNTLMv2$USERW2K3ADWIN7$1122334455667788$5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9$0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
	{"$NETNTLMv2$USER1Domain$1122334455667788$5E4AB1BF243DCA304A00ADEF78DC38DF$0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
	{"", "password",                  {"NTlmv2",                "", "TESTWORKGROUP", "1122334455667788","07659A550D5E9D02996DFD95C87EC1D5","0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"} },
	{"", "testpass",                  {"TestUser",              "", "W2K3ADWIN7",    "1122334455667788","989B96DC6EAB529F72FCBA852C0D5719","01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{"", "password",                  {"user",                  "", "W2K3ADWIN7",    "1122334455667788","5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9","0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{"", "password",                  {"USER1",                 "", "Domain",        "1122334455667788","5E4AB1BF243DCA304A00ADEF78DC38DF","0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
#ifdef DEBUG
	{"$NETNTLMv2$USER1W2K3ADWIN7$1122334455667788$027EF88334DAA460144BDB678D4F988D$010100000000000092809B1192AACA01E01B519CB0248776000000000200120057004F0052004B00470052004F00550050000000000000000000", "SomeLongPassword1BlahBlah"},
	{"$NETNTLMv2$TEST_USERW2K3ADWIN7$1122334455667788$A06EC5ED9F6DAFDCA90E316AF415BA71$010100000000000036D3A13292AACA01D2CD95757A0836F9000000000200120057004F0052004B00470052004F00550050000000000000000000", "TestUser's Password"},
	{"", "SomeLongPassword1BlahBlah", {"W2K3ADWIN7\\user1",     "", "",              "1122334455667788","027EF88334DAA460144BDB678D4F988D","010100000000000092809B1192AACA01E01B519CB0248776000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{"", "TestUser's Password",       {"W2K3ADWIN7\\TEST_USER", "", "",              "1122334455667788","A06EC5ED9F6DAFDCA90E316AF415BA71","010100000000000036D3A13292AACA01D2CD95757A0836F9000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
#endif
/* Long salt (username.domain > 27 chars) */
	{"", "Newpass8", {"Administrator", "", "WIN-HMH39596ABN", "1122334455667788", "80be64a4282577cf3b80503f4acb0e5a", "0101000000000000f077830c70a4ce0114ddd5c22457143000000000020000000000000000000000"} },
	{NULL}
};

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
static unsigned int new_keys = 1;
static struct fmt_main *self;
static cl_uint *zero_buffer;

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

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
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
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
	if (zero_buffer) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_keys), "Error Releasing buffer_int_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_return_hashes), "Error Releasing buffer_return_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error Releasing buffer_bitmap_dupe.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Error Releasing buffer_hash_ids.");
		MEM_FREE(zero_buffer);
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
	}

	MEM_FREE(loaded_hashes);
	MEM_FREE(hash_ids);
	release_salt_buffers();
}

static void init_kernel(void)
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

	opencl_build_kernel("$JOHN/opencl/ntlmv2_kernel.cl", gpu_id, build_opts, 0);
	crypt_kernel = clCreateKernel(program[gpu_id], "ntlmv2", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
}

static void set_key(char *_key, int index);

static void init(struct fmt_main *_self)
{
	self = _self;
	max_num_loaded_hashes = 0;

	opencl_prepare_dev(gpu_id);
	mask_int_cand_target = opencl_speed_index(gpu_id) / 900;

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *pos2;
	UTF16 utf16temp[SALT_MAX_LENGTH + 2];
	char utf8temp[3 * SALT_MAX_LENGTH + 1];
	int saltlen;

	if (ciphertext == NULL)
		return 0;
	else
		if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)!=0) return 0;

	if (strlen(ciphertext) > TOTAL_LENGTH)
		return 0;

	pos = &ciphertext[FORMAT_TAG_LEN];

	/* Validate Username and Domain Length */
	for (pos2 = pos; *pos2 != '$'; pos2++)
		if ((unsigned char)*pos2 < 0x20)
			return 0;

	if ( !(*pos2 && (pos2 - pos <= 3 * SALT_MAX_LENGTH)) )
		return 0;

	/* This is tricky: Max supported salt length is 59 characters
	   of Unicode, which has no exact correlation to number of octets.
	   The actual rejection is postponed to the bottom of this function. */
	saltlen = enc_to_utf16(utf16temp, SALT_MAX_LENGTH + 1,
	        (UTF8*)strnzcpy(utf8temp, pos, pos2 - pos + 1),
	        pos2 - pos);

	/* Validate Server Challenge Length */
	pos2++; pos = pos2;
	for (; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == SERVER_CHALL_LENGTH)) )
		return 0;

	/* Validate NTLMv2 Response Length */
	pos2++; pos = pos2;
	for (; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
		return 0;

	/* Validate Client Challenge Length */
	pos2++; pos = pos2;
	for (; atoi16[ARCH_INDEX(*pos2)] != 0x7F; pos2++);
	if ((pos2 - pos > CLIENT_CHALL_LENGTH_MAX) || (pos2 - pos < 28))
		return 0;

	if (saltlen < 0 || saltlen > SALT_MAX_LENGTH) {
		static int warned = 0;

		if (!ldr_in_pot)
		if (!warned++)
			fprintf(stderr, "%s: One or more hashes rejected due "
			        "to salt length limitation.\nMax supported sum"
			        " of Username + Domainname lengths is %d"
			         " characters.\nTry the CPU format for "
			        "those.\n", FORMAT_LABEL, SALT_MAX_LENGTH);
		return 0;
	}
	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *login         = split_fields[0];
	char *uid           = split_fields[2];
	char *srv_challenge = split_fields[3];
	char *nethashv2     = split_fields[4];
	char *cli_challenge = split_fields[5];
	char *identity = NULL, *tmp;

	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN))
		return split_fields[1];
	if (!login || !uid || !srv_challenge || !nethashv2 || !cli_challenge)
		return split_fields[1];

	/* DOMAIN\USER: -or- USER::DOMAIN: */
	if ((tmp = strstr(login, "\\")) != NULL) {
		identity = (char *) mem_alloc(strlen(login)*2 + 1);
		strcpy(identity, tmp + 1);

		/* Upper-Case Username - Not Domain */
		enc_strupper(identity);

		strncat(identity, login, tmp - login);
	}
	else {
		identity = (char *) mem_alloc(strlen(login)*2 + strlen(uid) + 1);
		strcpy(identity, login);

		enc_strupper(identity);

		strcat(identity, uid);
	}
	tmp = (char *) mem_alloc(FORMAT_TAG_LEN + strlen(identity) + 1 + strlen(srv_challenge) + 1 + strlen(nethashv2) + 1 + strlen(cli_challenge) + 1);
	sprintf(tmp, "%s%s$%s$%s$%s", FORMAT_TAG, identity, srv_challenge, nethashv2, cli_challenge);
	MEM_FREE(identity);

	if (valid(tmp, self)) {
		char *cp = str_alloc_copy(tmp);
		MEM_FREE(tmp);
		return cp;
	}
	MEM_FREE(tmp);
	return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[TOTAL_LENGTH + 1];
	char *pos = NULL;
	int identity_length = 0;

	if (strnlen(ciphertext, LINE_BUFFER_SIZE) < LINE_BUFFER_SIZE &&
	    strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;

	/* Calculate identity length */
	for (pos = ciphertext + FORMAT_TAG_LEN; *pos != '$'; pos++);
	identity_length = pos - (ciphertext + FORMAT_TAG_LEN);

	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, strlen(ciphertext));
	strlwr(&out[FORMAT_TAG_LEN + identity_length + 1]); /* Exclude: $NETNTLMv2$USERDOMAIN$ */

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *binary;
	char *pos = NULL;
	int i, identity_length;

	if (!binary)
		binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	for (pos = ciphertext + FORMAT_TAG_LEN; *pos != '$'; pos++);
	identity_length = pos - (ciphertext + FORMAT_TAG_LEN);

	ciphertext += FORMAT_TAG_LEN + identity_length + 1 + SERVER_CHALL_LENGTH + 1;
	for (i=0; i < BINARY_SIZE; i++)
	{
		binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
		binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
	}

	return binary;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char *binary_salt;
	int i, identity_length, challenge_size;
	char *pos = NULL;

	/* 2 * 64 + 8 + 8 + 440 == 584 */
	if (!binary_salt)
		binary_salt = mem_alloc_tiny(SALT_SIZE_MAX, MEM_ALIGN_WORD);

	/* Clean slate */
	memset(binary_salt, 0, SALT_SIZE_MAX);

	/* Calculate identity length */
	for (pos = ciphertext + FORMAT_TAG_LEN; *pos != '$'; pos++);

	/* Convert identity (username + domain) string to NT unicode */
	identity_length = enc_to_utf16((UTF16*)binary_salt, SALT_MAX_LENGTH,
	                               (unsigned char *)ciphertext + FORMAT_TAG_LEN,
	                               pos - (ciphertext + FORMAT_TAG_LEN)) * sizeof(UTF16);
	binary_salt[identity_length] = 0x80;

	/* Set length of last MD5 block */
	((int*)binary_salt)[((identity_length + 8) >> 6) * 16 + 14] =
		(64 + identity_length) << 3;

	/* Set server and client challenge size */

	/* Skip: $NETNTLMv2$USER_DOMAIN$ */
	ciphertext = pos + 1;

	/* SERVER_CHALLENGE$NTLMV2_RESPONSE$CLIENT_CHALLENGE --> SERVER_CHALLENGECLIENT_CHALLENGE */
	/* CIPHERTEXT == NTLMV2_RESPONSE (16 bytes / 32 characters) */
	challenge_size = (strlen(ciphertext) - CIPHERTEXT_LENGTH - 2) / 2;

	/* Set challenge size in response, in blocks */
	((int*)binary_salt)[32] = 1 + (challenge_size + 8) / 64;

	/* Set server challenge */
	for (i = 0; i < SERVER_CHALL_LENGTH / 2; i++)
		binary_salt[128 + 4 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	/* Set client challenge */
	ciphertext += SERVER_CHALL_LENGTH + 1 + CIPHERTEXT_LENGTH + 1;
	for (i = 0; i < strlen(ciphertext) / 2; ++i)
		binary_salt[128 + 4 + SERVER_CHALL_LENGTH / 2 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	binary_salt[128 + 4 + SERVER_CHALL_LENGTH / 2 + i] = 0x80;

	/* Set length of last MD5 block */
	((int*)binary_salt)[32 + 1 + 16 * ((challenge_size + 8) / 64) + 14] = (64 + challenge_size) << 3;

	/* Return a concatenation of the identity value and the server and client challenges */
	return (void*)binary_salt;
}

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
		truncate_utf8((UTF8*)out, PLAINTEXT_LENGTH);

	return out;
}

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
		unsigned int num_loaded_hashes, salt_params[SALT_SIZE_MAX / sizeof(unsigned int) + 5];
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

		num_loaded_hashes = bt_create_perfect_hash_table(128, (void *)loaded_hashes,
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

		memcpy(salt_params, salt->salt, SALT_SIZE_MAX);
		salt_params[SALT_PARAM_BASE + 0] = bitmap_size_bits - 1;
		salt_params[SALT_PARAM_BASE + 1] = offset_table_size;
		salt_params[SALT_PARAM_BASE + 2] = hash_table_size;
		salt_params[SALT_PARAM_BASE + 3] = shift64_ot_sz;
		salt_params[SALT_PARAM_BASE + 4] = shift64_ht_sz;

		buffer_bitmaps[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)(bitmap_size_bits >> 3) * 2, bitmaps, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmaps[].");

		buffer_salts[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, SALT_SIZE_MAX + 5 * sizeof(unsigned int), salt_params, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_salts[].");

		MEM_FREE(bitmaps);
		MEM_FREE(offset_table);

	} while((salt = salt->next));
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	size_t *lws = local_work_size ? &local_work_size : NULL;
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

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

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
	if (count)
		return 1;
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
	autotune_run_extra(self, 11, gws_limit, 100, CL_TRUE);
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
		SALT_SIZE_MAX,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC | FMT_REMOVE | FMT_HUGE_INPUT | FMT_MASK,
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
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash,
		},
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
		set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
