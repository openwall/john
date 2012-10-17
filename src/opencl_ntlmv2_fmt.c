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

#define FORMAT_LABEL		"ntlmv2-opencl"
#define FORMAT_NAME		"NTLMv2 C/R MD4 HMAC-MD5"
#define ALGORITHM_NAME		"OpenCL" /* Will change to "OpenCL 4x" if vectorized */
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	27 /* characters */
#define SALT_MAX_LENGTH		27 /* Username + Domainname length in characters */
#define BINARY_SIZE		16 /* octets */
#define SERVER_CHALL_LENGTH	16 /* hex chars */
#define CLIENT_CHALL_LENGTH_MAX	(1024 - SERVER_CHALL_LENGTH - 128) /* hex chars */
#define SALT_SIZE_MAX		512 /* octets */
#define CIPHERTEXT_LENGTH	32 /* hex chars */
#define TOTAL_LENGTH		(12 + 3 * SALT_MAX_LENGTH + 1 + SERVER_CHALL_LENGTH + 1 + CLIENT_CHALL_LENGTH_MAX + 1 + CIPHERTEXT_LENGTH + 1)

#define LWS_CONFIG		"ntlmv2_LWS"
#define GWS_CONFIG		"ntlmv2_GWS"

#define MIN(a, b)		(a > b) ? (b) : (a)
#define MAX(a, b)		(a > b) ? (a) : (b)

/* these will be altered in init() depending on GPU */
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests tests[] = {
	{"$NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000", "password"},
	{"$NETNTLMv2$TESTUSERW2K3ADWIN7$1122334455667788$989B96DC6EAB529F72FCBA852C0D5719$01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000", "testpass"},
	{"$NETNTLMv2$USERW2K3ADWIN7$1122334455667788$5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9$0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
	{"$NETNTLMv2$USER1W2K3ADWIN7$1122334455667788$027EF88334DAA460144BDB678D4F988D$010100000000000092809B1192AACA01E01B519CB0248776000000000200120057004F0052004B00470052004F00550050000000000000000000", "SomeLongPassword1BlahBlah"},
	{"$NETNTLMv2$TEST_USERW2K3ADWIN7$1122334455667788$A06EC5ED9F6DAFDCA90E316AF415BA71$010100000000000036D3A13292AACA01D2CD95757A0836F9000000000200120057004F0052004B00470052004F00550050000000000000000000", "TestUser's Password"},
	{"$NETNTLMv2$USER1Domain$1122334455667788$5E4AB1BF243DCA304A00ADEF78DC38DF$0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
	{"", "password",                  {"TESTWORKGROUP\\NTlmv2", "", "",              "1122334455667788","07659A550D5E9D02996DFD95C87EC1D5","0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"} },
	{"", "password",                  {"NTlmv2",                "", "TESTWORKGROUP", "1122334455667788","07659A550D5E9D02996DFD95C87EC1D5","0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"} },
	{"", "testpass",                  {"TestUser",              "", "W2K3ADWIN7",    "1122334455667788","989B96DC6EAB529F72FCBA852C0D5719","01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{"", "password",                  {"user",                  "", "W2K3ADWIN7",    "1122334455667788","5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9","0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{"", "SomeLongPassword1BlahBlah", {"W2K3ADWIN7\\user1",     "", "",              "1122334455667788","027EF88334DAA460144BDB678D4F988D","010100000000000092809B1192AACA01E01B519CB0248776000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{"", "TestUser's Password",       {"W2K3ADWIN7\\TEST_USER", "", "",              "1122334455667788","A06EC5ED9F6DAFDCA90E316AF415BA71","010100000000000036D3A13292AACA01D2CD95757A0836F9000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{"", "password",                  {"USER1",                 "", "Domain",        "1122334455667788","5E4AB1BF243DCA304A00ADEF78DC38DF","0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
	{NULL}
};

static unsigned int *saved_key;
static unsigned int *output;
static unsigned char *challenge;
static int new_keys;
static int VF = 1;

static cl_mem cl_saved_key, cl_challenge, cl_nthash, cl_result;
static cl_kernel ntlmv2_nthash;

static void create_clobj(int gws, struct fmt_main *self)
{
	global_work_size = gws;
	gws *= VF;
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;

	cl_saved_key = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 64 * gws, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_key = clEnqueueMapBuffer(queue[ocl_gpu_id], cl_saved_key, CL_TRUE, CL_MAP_READ, 0, 64 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_key");
	memset(saved_key, 0, 64 * gws);

	cl_result = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	output = clEnqueueMapBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 16 * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory output");
	memset(output, 0, 16 * gws);

	cl_challenge = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, SALT_SIZE_MAX, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	challenge = clEnqueueMapBuffer(queue[ocl_gpu_id], cl_challenge, CL_TRUE, CL_MAP_READ, 0, SALT_SIZE_MAX, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory challenge");
	memset(challenge, 0, SALT_SIZE_MAX);

	cl_nthash = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory nthash");

	HANDLE_CLERROR(clSetKernelArg(ntlmv2_nthash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(ntlmv2_nthash, 1, sizeof(cl_mem), (void*)&cl_nthash), "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_nthash), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_challenge), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 2");
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_challenge, challenge, 0, NULL, NULL), "Error Unmapping challenge");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_result, output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], cl_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	output = NULL; saved_key = NULL; challenge = NULL;
}

static void set_key(char *key, int index)
{
	int len;
	unsigned int *utfkey = &saved_key[index * 16];

	/* Clean slate */
	memset(utfkey, 0, 64);

	/* convert key to UTF-16LE */
	len = enc_to_utf16((UTF16*)utfkey, PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	if (len < 0)
		len = strlen16((UTF16*)utfkey);

	/* Prepare for GPU */
	((UTF16*)utfkey)[len] = 0x80;

	utfkey[14] = len << 4;

	new_keys = 1;
}

/*
  We're essentially using three salts, but we're going to pack it into a single blob for now.

  Input:  $NETNTLMv2$USER_DOMAIN$_SERVER_CHALLENGE_$_NTLMv2_RESP_$_CLIENT_CHALLENGE_
  Username + Domain <= 27 characters (54 octets of UTF-16)
  Server Challenge: 8 bytes
  Client Challenge: < ~450 bytes
  Output: (int)salt[16].(int)Challenge Size, Server Challenge . Client Challenge
*/
static void *get_salt(char *ciphertext)
{
	static unsigned char *binary_salt;
	int i, identity_length, challenge_size;
	char *pos = NULL;

	if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE_MAX, MEM_ALIGN_WORD);

	/* Clean slate */
	memset(binary_salt, 0, SALT_SIZE_MAX);

	/* Calculate identity length */
	for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);

	/* Convert identity (username + domain) string to NT unicode */
	identity_length = enc_to_utf16((UTF16*)binary_salt, 64, (unsigned char *)ciphertext + 11, pos - (ciphertext + 11)) * sizeof(UTF16);
	binary_salt[identity_length] = 0x80;

	/* Set length of last MD5 block */
	((int*)binary_salt)[14] = (64 + identity_length) << 3;

	/* Set server and client challenge size */

	/* Skip: $NETNTLMv2$USER_DOMAIN$ */
	ciphertext = pos + 1;

	/* SERVER_CHALLENGE$NTLMV2_RESPONSE$CLIENT_CHALLENGE --> SERVER_CHALLENGECLIENT_CHALLENGE */
	/* CIPHERTEXT == NTLMV2_RESPONSE (16 bytes / 32 characters) */
	challenge_size = (strlen(ciphertext) - CIPHERTEXT_LENGTH - 2) / 2;

	/* Set challenge size in response, in blocks */
	((int*)binary_salt)[16] = 1 + (challenge_size + 8) / 64;

	/* Set server challenge */
	for (i = 0; i < SERVER_CHALL_LENGTH / 2; i++)
		binary_salt[64 + 4 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	/* Set client challenge */
	ciphertext += SERVER_CHALL_LENGTH + 1 + CIPHERTEXT_LENGTH + 1;
	for (i = 0; i < strlen(ciphertext) / 2; ++i)
		binary_salt[64 + 4 + SERVER_CHALL_LENGTH / 2 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	binary_salt[64 + 4 + SERVER_CHALL_LENGTH / 2 + i] = 0x80;

	/* Set length of last MD5 block */
	((int*)binary_salt)[16 + 1 + 16 * ((challenge_size + 8) / 64) + 14] = (64 + challenge_size) << 3;

	/* Return a concatenation of the identity value and the server and client challenges */
	return (void*)binary_salt;
}

static void set_salt(void *salt)
{
	memcpy(challenge, salt, SALT_SIZE_MAX);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_challenge, CL_FALSE, 0, SALT_SIZE_MAX, challenge, 0, NULL, NULL), "Failed transferring salt");
}

static cl_ulong gws_test(int gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_command_queue queue_prof;
	cl_event Event[4];
	cl_int ret_code;
	int i;
	size_t scalar_gws = VF * gws;

	create_clobj(gws, self);
	queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i = 0; i < scalar_gws; i++)
		set_key(tests[0].plaintext, i);
	set_salt(get_salt(tests[0].ciphertext));

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_saved_key, CL_FALSE, 0, 64 * scalar_gws, saved_key, 0, NULL, &Event[0]), "Failed transferring keys");

	ret_code = clEnqueueNDRangeKernel(queue_prof, ntlmv2_nthash, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[1]);
	if (ret_code != CL_SUCCESS) {
		fprintf(stderr, "Error: %s\n", get_error_name(ret_code));
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

	ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[2]);
	if (ret_code != CL_SUCCESS) {
		fprintf(stderr, "Error: %s\n", get_error_name(ret_code));
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, cl_result, CL_FALSE, 0, 16 * scalar_gws, output, 0, NULL, &Event[3]), "failed in reading output back");
	HANDLE_CLERROR(clFinish(queue_prof), "Failed running kernel");

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
	                                       CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	                                       NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
	                                       CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	                                       NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "key transfer %.2f ms, ", (double)(endTime-startTime)/1000000.);

#if 1
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[1],
	                                       CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	                                       NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[1],
	                                       CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	                                       NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "ntlmv2_nthash %.2f ms, ", (double)(endTime-startTime)/1000000.);

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "exceeds 200 ms\n");
		return 0;
	}
#endif

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
	                                       CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	                                       NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2],
	                                       CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	                                       NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "final kernel %.2f ms, ", (double)((endTime - startTime)/1000000.));

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "- exceeds 200 ms\n");
		return 0;
	}
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	                                       CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime,
	                                       NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	                                       CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	                                       NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "results transfer %.2f ms, ", (double)(endTime-startTime)/1000000.);

	if (do_benchmark)
		fprintf(stderr, "\n");

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0],
	                                       CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime,
	                                       NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3],
	                                       CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime,
	                                       NULL), "Failed to get profiling info");
	clReleaseCommandQueue(queue_prof);
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

	/* The real formula would be "amount of FREE memory / 96" or so. */
	max_gws = get_global_memory_size(ocl_gpu_id) / 1024;

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size; num <= max_gws; num *= 2) {
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		MD5speed = md5perkey * (1000000000. * VF * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d %9.0f c/s %13.0f md5/s%8.2f sec per crypt_all()", num, (1000000000. * VF * num / run_time), MD5speed, (double)run_time / 1000000000.);

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
	global_work_size = optimal_gws;
}

static void init(struct fmt_main *self)
{
	char *temp;
	cl_ulong maxsize, maxsize2;

	global_work_size = 0;
	opencl_init("$JOHN/ntlmv2_kernel.cl", ocl_gpu_id, platform_id);

	/* create kernel to execute */
	ntlmv2_nthash = clCreateKernel(program[ocl_gpu_id], "ntlmv2_nthash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "ntlmv2_final", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	if (gpu(device_info[ocl_gpu_id])) {
		/* Run scalar code */
		VF = 1;
	} else {
		/* Run vectorized code */
		VF = 4;
		self->params.algorithm_name = "OpenCL 4x";
	}

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(temp);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, GWS_CONFIG)))
		global_work_size = atoi(temp);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(ntlmv2_nthash, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize2), &maxsize2, NULL), "Query max work group size");
	if (maxsize2 < maxsize) maxsize = maxsize2;

	/* maxsize is the lowest figure from the three different kernels */
	if (!local_work_size) {
		if (getenv("LWS") || cpu(device_info[ocl_gpu_id])) {
			int temp = global_work_size;
			local_work_size = maxsize;
			global_work_size = global_work_size ? global_work_size : 512 * maxsize;
			create_clobj(global_work_size, self);
			opencl_find_best_workgroup_limit(self, maxsize);
			release_clobj();
			global_work_size = temp;
		} else {
			local_work_size = maxsize;
		}
	}

	if (local_work_size > maxsize) {
		fprintf(stderr, "LWS %d is too large for this GPU. Max allowed is %d, using that.\n", (int)local_work_size, (int)maxsize);
		local_work_size = maxsize;
	}

	if (!global_work_size)
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
	create_clobj(global_work_size, self);
	atexit(release_clobj);

	if (options.utf8)
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *pos2;
	UTF16 utf16temp[SALT_MAX_LENGTH + 2];
	char utf8temp[3 * SALT_MAX_LENGTH + 1];
	int saltlen;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, "$NETNTLMv2$", 11)!=0) return 0;

	pos = &ciphertext[11];

	/* Validate Username and Domain Length */
	for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
		if ((unsigned char)*pos2 < 0x20)
			return 0;

	if ( !(*pos2 && (pos2 - pos <= 3*SALT_MAX_LENGTH)) )
		return 0;

	/* This is tricky: Max supported salt length is 27 characters
	   of Unicode, which has no exact correlation to number of octets */
	saltlen = enc_to_utf16(utf16temp, SALT_MAX_LENGTH + 1,
	                       (UTF8*)strnzcpy(utf8temp, pos, pos2 - pos - 2),
	                       pos2 - pos - 3);
	if (saltlen < 0 || saltlen > SALT_MAX_LENGTH) {
		static int warned = 0;
		if (!warned++)
			fprintf(stderr, "NOTE: One or more hashes rejected due to salt length limitation.\nMax supported sum of Username + Domainname lengths is 27 characters.\nTry the CPU format for those.\n");
		return 0;
	}

	/* Validate Server Challenge Length */
	pos2++; pos = pos2;
	for (; strncmp(pos2, "$", 1) != 0; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == SERVER_CHALL_LENGTH)) )
		return 0;

	/* Validate NTLMv2 Response Length */
	pos2++; pos = pos2;
	for (; strncmp(pos2, "$", 1) != 0; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
		return 0;

	/* Validate Client Challenge Length */
	pos2++; pos = pos2;
	for (; atoi16[ARCH_INDEX(*pos2)] != 0x7F; pos2++);
	if ((pos2 - pos > CLIENT_CHALL_LENGTH_MAX) || (pos2 - pos < 28))
		return 0;

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

#if FMT_MAIN_VERSION > 9
static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
#else
static char *split(char *ciphertext, int index)
#endif
{
	static char out[TOTAL_LENGTH + 1];
	char *pos = NULL;
	int identity_length = 0;

	/* Calculate identity length */
	for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);
	identity_length = pos - (ciphertext + 11);

	memset(out, 0, sizeof(out));
	memcpy(&out, ciphertext, strlen(ciphertext));
	strlwr(&out[12 + identity_length]); /* Exclude: $NETNTLMv2$USERDOMAIN$ */

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *binary;
	char *pos = NULL;
	int i, identity_length;

	if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);
	identity_length = pos - (ciphertext + 11);

	ciphertext += 11 + identity_length + 1 + SERVER_CHALL_LENGTH + 1;
	for (i=0; i<BINARY_SIZE; i++)
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
static void crypt_all(int count)
{
	size_t scalar_gws = global_work_size * VF;

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, 0, 64 * scalar_gws, saved_key, 0, NULL, NULL), "Failed transferring keys");
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], ntlmv2_nthash, 1, NULL, &global_work_size, &local_work_size, 0, NULL, firstEvent), "Failed running first kernel");
		new_keys = 0;
	}
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "Failed running second kernel");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, 16 * scalar_gws, output, 0, NULL, NULL), "failed reading results back");
}

static int cmp_all(void *binary, int count)
{
	int index;
	for(index=0; index<count; index++)
		if (output[4 * index] == ((ARCH_WORD_32*)binary)[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(&output[4 * index], binary, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(&output[4 * index], get_binary(source), BINARY_SIZE);
}

static char *get_key(int index)
{
	static UTF8 out[3 * PLAINTEXT_LENGTH + 1];
	unsigned int *utfkey = &saved_key[index * 16];
	int len = utfkey[14] >> 4;

	utf16_to_enc_r(out, len, (UTF16*)utfkey);
	return (char*)out;
}

static int salt_hash(void *salt)
{
	/* We pick part of the client nounce */
	return ((ARCH_WORD_32*)salt)[17+2+5] & (SALT_HASH_SIZE - 1);
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return output[4 * index] & 0xF;
}

static int get_hash_1(int index)
{
	return output[4 * index] & 0xFF;
}

static int get_hash_2(int index)
{
	return output[4 * index] & 0xFFF;
}

static int get_hash_3(int index)
{
	return output[4 * index] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return output[4 * index] & 0xFFFFF;
}

struct fmt_main fmt_opencl_NTLMv2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		4,
#endif
		SALT_SIZE_MAX,
#if FMT_MAIN_VERSION > 9
		4,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		prepare,
		valid,
		split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
