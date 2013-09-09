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

#define OCL_CONFIG              "ntlmv2"

#define MIN(a, b)               (((a) > (b)) ? (b) : (a))
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))

/* these will be altered in init() depending on GPU */
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

static struct fmt_tests tests[] = {
	{"$NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000", "password"},
	{"$NETNTLMv2$TESTUSERW2K3ADWIN7$1122334455667788$989B96DC6EAB529F72FCBA852C0D5719$01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000", "testpass"},
	{"$NETNTLMv2$USERW2K3ADWIN7$1122334455667788$5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9$0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
	{"$NETNTLMv2$USER1Domain$1122334455667788$5E4AB1BF243DCA304A00ADEF78DC38DF$0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
	{"", "password",                  {"TESTWORKGROUP\\NTlmv2", "", "",              "1122334455667788","07659A550D5E9D02996DFD95C87EC1D5","0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"} },
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

static cl_mem cl_saved_key, cl_saved_idx, cl_challenge, cl_nthash, cl_result;
static cl_mem pinned_key, pinned_idx, pinned_result, pinned_salt;
static cl_kernel ntlmv2_nthash;

static void create_clobj(int gws, struct fmt_main *self)
{
	global_work_size = gws;
	self->params.max_keys_per_crypt = gws;

	pinned_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, max_len * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, max_len * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_key = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, max_len * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_key");

	pinned_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saved_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, 4 * (gws + 1), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saved_idx = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 4 * (gws + 1), 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saved_idx");

	pinned_result = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 16 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	pinned_salt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, SALT_SIZE_MAX, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_challenge = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, SALT_SIZE_MAX, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	challenge = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, SALT_SIZE_MAX, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping challenge");

	cl_nthash = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
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
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_salt, challenge, 0, NULL, NULL), "Error Unmapping challenge");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release pinned salt buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_challenge), "Release salt buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_nthash), "Release state buffer");
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(ntlmv2_nthash), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
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
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_challenge, CL_FALSE, 0, SALT_SIZE_MAX, challenge, 0, NULL, NULL), "Failed transferring salt");
	HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "failed in clFlush");
}

static cl_ulong gws_test(int gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_event Event[5];
	int i, tidx = 0;

	create_clobj(gws, self);

	/* Use all available test vectors to set keys */
	self->methods.clear_keys();
	for (i = 0; i < gws; i++) {
		if (tests[tidx].plaintext == NULL)
			tidx = 0;
		self->methods.set_key(tests[tidx++].plaintext, i);
	}

	/* Emulate set_salt() */
	memcpy(challenge, get_salt(tests[0].ciphertext), SALT_SIZE_MAX);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_challenge, CL_FALSE, 0, SALT_SIZE_MAX, challenge, 0, NULL, NULL), "Failed transferring salt");

	/* Emulate crypt_all() */
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, &Event[0]), "Failed transferring keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, &Event[1]), "Failed transferring index");
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], ntlmv2_nthash, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[2]), "running kernel");
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[3]), "running kernel");

	/* Only benchmark partial transfer - that is what we optimize for */
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, 4 * gws, output, 0, NULL, &Event[4]), "failed in reading output back");

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
	        CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
	        NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[1],
	        CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	        NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "key xfer %.2f ms, ", (double)(endTime-startTime)/1000000.);

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
	        CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	        NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
	        CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	        NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "ntlmv2_nthash %.2f ms, ", (double)(endTime-startTime)/1000000.);

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "exceeds 200 ms\n");
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	        CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	        NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	        CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	        NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "final kernel %.2f ms, ", (double)((endTime - startTime)/1000000.));

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "- exceeds 200 ms\n");
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[4],
	        CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	        NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[4],
	        CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	        NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "results xfer %.2f ms", (double)(endTime-startTime)/1000000.);

	if (do_benchmark)
		fprintf(stderr, "\n");

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
	        CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
	        NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[4],
	        CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	        NULL), "Failed to get profiling info");

	release_clobj();

	return (endTime - startTime);
}

static void find_best_gws(int do_benchmark, struct fmt_main *self)
{
	int num;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	double MD5speed, bestMD5speed = 0.0;
	int optimal_gws = local_work_size, max_gws;
	const int md5perkey = 11;
	unsigned long long int MaxRunTime = 1000000000ULL;

	/* Enable profiling */
#ifndef CL_VERSION_1_1
	HANDLE_CLERROR(clSetCommandQueueProperty(queue[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, CL_TRUE, NULL), "Failed enabling profiling");
#else /* clSetCommandQueueProperty() is deprecated */
	cl_command_queue origQueue = origQueue = queue[ocl_gpu_id];
	queue[ocl_gpu_id] = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed enabling profiling");
#endif

	/* Beware of device limits */
	max_gws = MIN(get_max_mem_alloc_size(ocl_gpu_id) / max_len, get_global_memory_size(ocl_gpu_id) / (max_len + 16 + 16 + SALT_SIZE_MAX));

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size; num <= max_gws; num *= 2) {
		if (!do_benchmark)
			advance_cursor();
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		MD5speed = md5perkey * (1000000000. * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d %9.0f c/s %13.0f md5/s%8.2f sec per crypt_all()", num, (1000000000. * num / run_time), MD5speed, (double)run_time / 1000000000.);

		if (((double)run_time / (double)min_time) < (MD5speed / bestMD5speed)) {
			if (do_benchmark)
				fprintf(stderr, "!\n");
			bestMD5speed = MD5speed;
			optimal_gws = num;
		} else {
			if (run_time < MaxRunTime && MD5speed > (bestMD5speed * 1.01)) {
				if (do_benchmark)
					fprintf(stderr, "+\n");
				bestMD5speed = MD5speed;
				optimal_gws = num;
				continue;
			}
			if (do_benchmark)
				fprintf(stderr, "\n");
			if (run_time >= MaxRunTime)
				break;
		}
	}

	/* Disable profiling */
#ifndef CL_VERSION_1_1
	HANDLE_CLERROR(clSetCommandQueueProperty(queue[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, CL_FALSE, NULL), "Failed disabling profiling");
#else /* clSetCommandQueueProperty() is deprecated */
	clReleaseCommandQueue(queue[ocl_gpu_id]);
	queue[ocl_gpu_id] = origQueue;
#endif

	global_work_size = optimal_gws;
}

static void init(struct fmt_main *self)
{
	cl_ulong maxsize, maxsize2, max_mem;
	char build_opts[64];
	char *encoding = options.encodingDef ? options.encodingDef : "ISO_8859_1";

	if (options.utf8)
		max_len = self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;

	snprintf(build_opts, sizeof(build_opts),
	        "-DENC_%s -DENCODING=%s", encoding, encoding);
	opencl_init("$JOHN/kernels/ntlmv2_kernel.cl", ocl_gpu_id, build_opts);

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(OCL_CONFIG);

	/* create kernels to execute */
	ntlmv2_nthash = clCreateKernel(program[ocl_gpu_id], "ntlmv2_nthash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "ntlmv2_final", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(ntlmv2_nthash, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;
	clGetDeviceInfo(devices[ocl_gpu_id], CL_DEVICE_MAX_MEM_ALLOC_SIZE,
	        sizeof(max_mem), &max_mem, NULL);

	/* maxsize is the lowest figure from the three different kernels */
	if (!local_work_size) {
		int temp = global_work_size;
		local_work_size = maxsize;
		global_work_size = global_work_size ? global_work_size : 512 * maxsize;
		while (global_work_size > max_mem / ((max_len + 63) / 64 * 64))
			global_work_size -= local_work_size;
		create_clobj(global_work_size, self);
		opencl_find_best_workgroup_limit(self, maxsize, ocl_gpu_id, crypt_kernel);
		release_clobj();
		global_work_size = temp;
	}

	if (local_work_size > maxsize)
		local_work_size = maxsize;

	self->params.min_keys_per_crypt = local_work_size;

	if (!global_work_size)
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	// Obey device limits
	while (global_work_size > max_mem / ((max_len + 63) / 64 * 64))
		global_work_size -= local_work_size;

	// Current key_idx can only hold 26 bits of offset so
	// we can't reliably use a GWS higher than 4.7M or so.
	if (global_work_size > (1 << 26) * 4 / PLAINTEXT_LENGTH)
		global_work_size = (1 << 26) * 4 / PLAINTEXT_LENGTH;

	// Ensure GWS is multiple of LWS
	global_work_size = global_work_size / local_work_size * local_work_size;

	if (options.verbosity > 2)
		fprintf(stderr,
		        "Local worksize (LWS) %d, Global worksize (GWS) %d\n",
		        (int)local_work_size, (int)global_work_size);
	create_clobj(global_work_size, self);
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
		identity = (char *) mem_alloc(strlen(login));
		strcpy(identity, tmp + 1);

		/* Upper-Case Username - Not Domain */
		enc_strupper(identity);

		strncat(identity, login, tmp - login);
	}
	else {
		identity = (char *) mem_alloc(strlen(login) + strlen(uid) + 1);
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
	int count = *pcount;

	/* Don't do more than requested */
	global_work_size = ((count + (local_work_size - 1)) / local_work_size) * local_work_size;

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, NULL), "Failed transferring index");
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], ntlmv2_nthash, 1, NULL, &global_work_size, &local_work_size, 0, NULL, firstEvent), "Failed running first kernel");

		new_keys = 0;
	}
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "Failed running second kernel");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, 4 * global_work_size, output, 0, NULL, NULL), "failed reading results back");

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
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, 16 * global_work_size, output, 0, NULL, NULL), "failed reading results back");
		partial_output = 0;
	}
	binary = (ARCH_WORD_32*)get_binary(source);

	for(i = 0; i < DIGEST_SIZE / 4; i++)
		if (output[i * global_work_size + index] != binary[i])
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
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		key_offset = key_idx;
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * index - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, NULL), "Failed transferring index");
		idx_offset = 4 * index;
		HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "failed in clFlush");
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

static int get_hash_0(int index) { return output[index] & 0xf; }
static int get_hash_1(int index) { return output[index] & 0xff; }
static int get_hash_2(int index) { return output[index] & 0xfff; }
static int get_hash_3(int index) { return output[index] & 0xffff; }
static int get_hash_4(int index) { return output[index] & 0xfffff; }
static int get_hash_5(int index) { return output[index] & 0xffffff; }
static int get_hash_6(int index) { return output[index] & 0x7ffffff; }

struct fmt_main fmt_opencl_NTLMv2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_MAX,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		0,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		get_binary,
		get_salt,
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
