/*
 * OpenCL NTLMv2 -- NTLMv2 Challenge/Response
 *
 * Based on code written by JoMo-Kun <jmk at foofus.net> in 2009
 *
 * Copyright (c) 2012, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_NTLMv2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_NTLMv2);
#else

#include <string.h>

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "common-opencl.h"
#include "config.h"
#include "unicode.h"
#include "loader.h"

#define FORMAT_LABEL            "ntlmv2-opencl"
#define FORMAT_NAME             "NTLMv2 C/R"
#define ALGORITHM_NAME          "MD4 HMAC-MD5 OpenCL"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        27 /* Bumped 3x for UTF-8 */
#define SALT_MAX_LENGTH         59 /* Username + Domainname len in characters */
#define DIGEST_SIZE             16 /* octets */
#define BINARY_SIZE             4 /* octets */
#define BINARY_ALIGN            4
#define SERVER_CHALL_LENGTH     16 /* hex chars */
#define CLIENT_CHALL_LENGTH_MAX (1024 - SERVER_CHALL_LENGTH - 128) /* hex */
#define SALT_SIZE_MAX           584 /* octets of salt blob */
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

static char *saved_key;
static unsigned int *output, *saved_idx, key_idx;
static size_t key_offset, idx_offset;
static unsigned char *challenge;
static int new_keys, partial_output;
static int max_len = PLAINTEXT_LENGTH;
static struct fmt_main *self;

static cl_mem cl_saved_key, cl_saved_idx, cl_challenge, cl_nthash, cl_result;
static cl_mem pinned_key, pinned_idx, pinned_result, pinned_salt;
static cl_kernel ntlmv2_nthash;

#define STEP 0
#define SEED 256

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static const char * warn[] = {
	"xfer: ",  ", xfer: ",  ", init: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, ntlmv2_nthash);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel));
	return s;
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	gws *= ocl_v_width;

	pinned_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, max_len * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, max_len * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, max_len * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_idx = clEnqueueMapBuffer(queue[gpu_id], pinned_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 4 * (gws + 1), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_idx");

	pinned_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 16 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	pinned_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, SALT_SIZE_MAX, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_challenge = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, SALT_SIZE_MAX, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	challenge = clEnqueueMapBuffer(queue[gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, SALT_SIZE_MAX, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping challenge");

	cl_nthash = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device-only buffer");

	HANDLE_CLERROR(clSetKernelArg(ntlmv2_nthash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(ntlmv2_nthash, 1, sizeof(cl_mem), (void*)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(ntlmv2_nthash, 2, sizeof(cl_mem), (void*)&cl_nthash), "Error setting argument 2");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_nthash), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_challenge), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 2");
}

static void release_clobj(void)
{
	if (cl_nthash) {
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_salt, challenge, 0, NULL, NULL), "Error Unmapping challenge");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

		HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release pinned salt buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
		HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_challenge), "Release salt buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");
		HANDLE_CLERROR(clReleaseMemObject(cl_nthash), "Release state buffer");

		cl_nthash = NULL;
	}
}

static void done(void)
{
	if (autotuned) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(ntlmv2_nthash), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		autotuned--;
	}
}

/*
  We're essentially using three salts, but we're going to pack it into a single blob for now.

  Input:  $NETNTLMv2$USER_DOMAIN$_SERVER_CHALLENGE_$_NTLMv2_RESP_$_CLIENT_CHALLENGE_
  Username + Domain <= 59 characters (118 octets of UTF-16) - 2 blocks of MD5
  Server Challenge: 8 bytes
  Client Challenge: <= 440 bytes
  Output: (int)salt[16].(int)Challenge Size, Server Challenge . Client Challenge
*/
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
	for (pos = ciphertext + 11; *pos != '$'; pos++);

	/* Convert identity (username + domain) string to NT unicode */
	identity_length = enc_to_utf16((UTF16*)binary_salt, SALT_MAX_LENGTH,
	                               (unsigned char *)ciphertext + 11,
	                               pos - (ciphertext + 11)) * sizeof(UTF16);
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

static void set_salt(void *salt)
{
	memcpy(challenge, salt, SALT_SIZE_MAX);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_challenge, CL_FALSE, 0, SALT_SIZE_MAX, challenge, 0, NULL, NULL), "Failed transferring salt");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static void init(struct fmt_main *_self)
{
	static char valgo[32] = "";

	self = _self;

	opencl_prepare_dev(gpu_id);
	/* Nvidia Kepler benefits from 2x interleaved code */
	if (!options.v_width && nvidia_sm_3x(device_info[gpu_id]))
		ocl_v_width = 2;
	else
		ocl_v_width = opencl_get_vector_width(gpu_id, sizeof(cl_int));

	if (ocl_v_width > 1) {
		/* Run vectorized kernel */
		snprintf(valgo, sizeof(valgo),
		         ALGORITHM_NAME " %ux", ocl_v_width);
		self->params.algorithm_name = valgo;
	}

	if (options.target_enc == UTF_8)
		max_len = self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;
}

static void reset(struct db_main *db)
{
	if (!autotuned) {
		size_t gws_limit;
		char build_opts[96];

		snprintf(build_opts, sizeof(build_opts),
#if !NT_FULL_UNICODE
		         "-DUCS_2 "
#endif
		         "-D%s -DPLAINTEXT_LENGTH=%u -DV_WIDTH=%u",
		         cp_id2macro(options.target_enc), PLAINTEXT_LENGTH, ocl_v_width);
		opencl_init("$JOHN/kernels/ntlmv2_kernel.cl", gpu_id, build_opts);

		/* create kernels to execute */
		ntlmv2_nthash = clCreateKernel(program[gpu_id], "ntlmv2_nthash", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
		crypt_kernel = clCreateKernel(program[gpu_id], "ntlmv2_final", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

		gws_limit = (4 << 20) / ocl_v_width;

		//Initialize openCL tuning (library) for this format.
		opencl_init_auto_setup(SEED, 0, NULL, warn, 3, self,
		                       create_clobj, release_clobj,
		                       2 * ocl_v_width * max_len, gws_limit);

		//Auto tune execution from shared/included code.
		autotune_run(self, 11, gws_limit, 500);
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *pos2;
	UTF16 utf16temp[SALT_MAX_LENGTH + 2];
	char utf8temp[3 * SALT_MAX_LENGTH + 1];
	int saltlen;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, "$NETNTLMv2$", 11)!=0) return 0;

	if (strlen(ciphertext) > TOTAL_LENGTH)
		return 0;

	pos = &ciphertext[11];

	/* Validate Username and Domain Length */
	for (pos2 = pos; *pos2 != '$'; pos2++)
		if ((unsigned char)*pos2 < 0x20)
			return 0;

	if ( !(*pos2 && (pos2 - pos <= 3*SALT_MAX_LENGTH)) )
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
	char *srv_challenge = split_fields[3];
	char *nethashv2     = split_fields[4];
	char *cli_challenge = split_fields[5];
	char *login = split_fields[0];
	char *uid = split_fields[2];
	char *identity = NULL, *tmp;

	if (!strncmp(split_fields[1], "$NETNTLMv2$", 11))
		return split_fields[1];
	if (!split_fields[0]||!split_fields[2]||!split_fields[3]||!split_fields[4]||!split_fields[5])
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
	tmp = (char *) mem_alloc(11 + strlen(identity) + 1 + strlen(srv_challenge) + 1 + strlen(nethashv2) + 1 + strlen(cli_challenge) + 1);
	sprintf(tmp, "$NETNTLMv2$%s$%s$%s$%s", identity, srv_challenge, nethashv2, cli_challenge);
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

	/* Calculate identity length */
	for (pos = ciphertext + 11; *pos != '$'; pos++);
	identity_length = pos - (ciphertext + 11);

	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, strlen(ciphertext));
	strlwr(&out[12 + identity_length]); /* Exclude: $NETNTLMv2$USERDOMAIN$ */

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *binary;
	char *pos = NULL;
	int i, identity_length;

	if (!binary) binary = mem_alloc_tiny(DIGEST_SIZE, MEM_ALIGN_WORD);

	for (pos = ciphertext + 11; *pos != '$'; pos++);
	identity_length = pos - (ciphertext + 11);

	ciphertext += 11 + identity_length + 1 + SERVER_CHALL_LENGTH + 1;
	for (i=0; i<DIGEST_SIZE; i++)
	{
		binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
		binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
	}

	return binary;
}

/* Calculate the NTLMv2 response for the given challenge, using the
   specified authentication identity (username and domain), password
   and client nonce.

   challenge: (int)identity[16].(int)Challenge Size, Server Challenge . Client Challenge
*/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t scalar_gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	/* Don't do more than requested */
	global_work_size = GET_MULTIPLE_OR_BIGGER_VW(count, local_work_size);
	scalar_gws = global_work_size * ocl_v_width;

	/* Self-test cludge */
	if (idx_offset > 4 * (scalar_gws + 1))
		idx_offset = 0;

	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, multi_profilingEvent[0]), "Failed transferring keys");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (scalar_gws + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, multi_profilingEvent[1]), "Failed transferring index");
		BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], ntlmv2_nthash, 1, NULL, &scalar_gws, lws, 0, NULL, multi_profilingEvent[2]), "Failed running first kernel");

		new_keys = 0;
	}
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[3]), "Failed running second kernel");
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, 4 * scalar_gws, output, 0, NULL, multi_profilingEvent[4]), "failed reading results back");

	partial_output = 1;

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for(index = 0; index < count; index++)
		if (output[index] == ((ARCH_WORD_32*)binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (output[index] == ((ARCH_WORD_32*)binary)[0]);
}

static int cmp_exact(char *source, int index)
{
	ARCH_WORD_32 *binary;
	int i;

	if (partial_output) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_result, CL_TRUE, 0, 16 * ocl_v_width * global_work_size, output, 0, NULL, NULL), "failed reading results back");
		partial_output = 0;
	}
	binary = (ARCH_WORD_32*)get_binary(source);

	for(i = 0; i < DIGEST_SIZE / 4; i++)
		if (output[i * ocl_v_width * global_work_size + index] != binary[i])
			return 0;
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

static int salt_hash(void *salt)
{
	/* We pick part of the client nounce */
	return ((ARCH_WORD_32*)salt)[17+2+5] & (SALT_HASH_SIZE - 1);
}

static int get_hash_0(int index) { return output[index] & PH_MASK_0; }
static int get_hash_1(int index) { return output[index] & PH_MASK_1; }
static int get_hash_2(int index) { return output[index] & PH_MASK_2; }
static int get_hash_3(int index) { return output[index] & PH_MASK_3; }
static int get_hash_4(int index) { return output[index] & PH_MASK_4; }
static int get_hash_5(int index) { return output[index] & PH_MASK_5; }
static int get_hash_6(int index) { return output[index] & PH_MASK_6; }

struct fmt_main fmt_opencl_NTLMv2 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		{ NULL },
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
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
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
