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
 * user:$krb5pa$etype$user$realm$salt$timestamp+checksum
 *
 * user, realm and salt are unused in this format.
 *
 * This software is Copyright (c) 2013 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
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

#include "md5.h"
#include "hmacmd5.h"
#include "md4.h"
#include "rc4.h"

#define FORMAT_LABEL       "krb5pa-md5-opencl"
#define FORMAT_NAME        "Kerberos 5 AS-REQ Pre-Auth etype 23" /* md4, rc4-hmac-md5 */
#define ALGORITHM_NAME     "MD4 HMAC-MD5 RC4 OpenCL"
#define BENCHMARK_COMMENT  ""
#define BENCHMARK_LENGTH   -1000
#define PLAINTEXT_LENGTH   27 /* Bumped 3x for UTF-8 */
#define MAX_REALMLEN       64
#define MAX_USERLEN        64
#define MAX_SALTLEN        128
#define TIMESTAMP_SIZE     36
#define CHECKSUM_SIZE      16
#define KEY_SIZE           16
#define BINARY_SIZE        CHECKSUM_SIZE
#define BINARY_ALIGN       4
#define SALT_SIZE          sizeof(salt_t)
#define SALT_ALIGN         4
#define TOTAL_LENGTH       (14 + 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) + MAX_REALMLEN + MAX_USERLEN + MAX_SALTLEN)

#define OCL_CONFIG              "krb5pa-md5"

#define MIN(a, b)               (((a) > (b)) ? (b) : (a))
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))

// these may be altered in init()
#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 1

#define HEXCHARS           "0123456789abcdefABCDEF"

// Second and third plaintext will be replaced in init() under --encoding=utf8
static struct fmt_tests tests[] = {
	{"$krb5pa$23$user$realm$salt$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7daeb03b6fbcfe91f8346f3c0ae7e8abfe5", "John"},
	{"$mskrb5$john$JOHN.DOE.MS.COM$02E837D06B2AC76891F388D9CC36C67A$2A9785BF5036C45D3843490BF9C228E8C18653E10CE58D7F8EF119D2EF4F92B1803B1451", "fr2beesgr"},
	{"$mskrb5$user1$EXAMPLE.COM$08b5adda3ab0add14291014f1d69d145$a28da154fa777a53e23059647682eee2eb6c1ada7fb5cad54e8255114270676a459bfe4a", "openwall"},
	{"$mskrb5$hackme$EXAMPLE.NET$e3cdf70485f81a85f7b59a4c1d6910a3$6e2f6705551a76f84ec2c92a9dd0fef7b2c1d4ca35bf1b02423359a3ecaa19bdf07ed0da", "openwall@123"},
	{"$mskrb5$$$98cd00b6f222d1d34e08fe0823196e0b$5937503ec29e3ce4e94a051632d0fff7b6781f93e3decf7dca707340239300d602932154", ""},
	{"$mskrb5$$$F4085BA458B733D8092E6B348E3E3990$034ACFC70AFBA542690B8BC912FCD7FED6A848493A3FF0D7AF641A263B71DCC72902995D", "frank"},
	{"$mskrb5$$$eb03b6fbcfe91f8346f3c0ae7e8abfe5$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7da", "John"},
	{"$mskrb5$$$881c257ce5df7b11715a6a60436e075a$c80f4a5ec18e7c5f765fb9f00eda744a57483db500271369cf4752a67ca0e67f37c68402", "the"},
	{"$mskrb5$$$ef012e13c8b32448241091f4e1fdc805$354931c919580d4939421075bcd50f2527d092d2abdbc0e739ea72929be087de644cef8a", "Ripper"},
#if PLAINTEXT_LENGTH >= 31
	{"$mskrb5$$$334ef74dad191b71c43efaa16aa79d88$34ebbad639b2b5a230b7ec1d821594ed6739303ae6798994e72bd13d5e0e32fdafb65413", "VeryveryveryloooooooongPassword"},
#endif
	{NULL}
};

typedef struct {
	ARCH_WORD_32 checksum[CHECKSUM_SIZE / sizeof(ARCH_WORD_32)];
	unsigned char timestamp[TIMESTAMP_SIZE];
} salt_t;

static char *saved_key;
static unsigned int *output, *saved_idx, key_idx;
static size_t key_offset, idx_offset;
static unsigned char *saltblob;
static int new_keys;
static int max_len = PLAINTEXT_LENGTH;

static cl_mem cl_saved_key, cl_saved_idx, cl_saltblob, cl_nthash, cl_result;
static cl_mem pinned_key, pinned_idx, pinned_result, pinned_salt;
static cl_kernel krb5pa_md5_nthash;

static void create_clobj(size_t gws, struct fmt_main *self)
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

	pinned_result = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_result = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, BINARY_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	output = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_result, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BINARY_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping output");

	pinned_salt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, SALT_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked buffer");
	cl_saltblob = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, SALT_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device buffer");
	saltblob = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, SALT_SIZE, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping saltblob");

	cl_nthash = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 16 * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating device-only buffer");

	HANDLE_CLERROR(clSetKernelArg(krb5pa_md5_nthash, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(krb5pa_md5_nthash, 1, sizeof(cl_mem), (void*)&cl_saved_idx), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(krb5pa_md5_nthash, 2, sizeof(cl_mem), (void*)&cl_nthash), "Error setting argument 2");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_nthash), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saltblob), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_result), "Error setting argument 2");
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_salt, saltblob, 0, NULL, NULL), "Error Unmapping saltblob");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_result, output, 0, NULL, NULL), "Error Unmapping output");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_salt), "Release pinned salt buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_result), "Release pinned result buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_key), "Release pinned key buffer");
	HANDLE_CLERROR(clReleaseMemObject(pinned_idx), "Release pinned index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saltblob), "Release salt buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_result), "Release result buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_key), "Release key buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_saved_idx), "Release index buffer");
	HANDLE_CLERROR(clReleaseMemObject(cl_nthash), "Release state buffer");
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(krb5pa_md5_nthash), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
}

static void *salt(char *ciphertext);

static cl_ulong gws_test(size_t gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_event Event[5];
	int i, tidx = 0;

	create_clobj(gws, self);

	// Set keys - all keys from tests will be benchmarked and some
	// will be permuted to force them unique
	self->methods.clear_keys();
	for (i = 0; i < gws; i++) {
		union {
			char c[PLAINTEXT_BUFFER_SIZE];
			unsigned int w;
		} uniq;
		int len;
		if (self->params.tests[tidx].plaintext == NULL)
			tidx = 0;
		len = strlen(self->params.tests[tidx].plaintext);
		strncpy(uniq.c, self->params.tests[tidx++].plaintext,
		    sizeof(uniq.c));
		uniq.w ^= i;
		uniq.c[len] = 0;
		self->methods.set_key(uniq.c, i);
	}

	/* Emulate set_salt() */
	memcpy(saltblob, salt(tests[0].ciphertext), SALT_SIZE);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saltblob, CL_FALSE, 0, SALT_SIZE, saltblob, 0, NULL, NULL), "Failed transferring salt");

	/* Emulate crypt_all() */
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, &Event[0]), "Failed transferring keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, &Event[1]), "Failed transferring index");
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], krb5pa_md5_nthash, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[2]), "running kernel");
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[3]), "running kernel");

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, BINARY_SIZE * gws, output, 0, NULL, &Event[4]), "failed in reading output back");

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
		fprintf(stderr, "krb5pa_md5_nthash %.2f ms, ", (double)(endTime-startTime)/1000000.);

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
	const int md5perkey = 9;
	unsigned long long int MaxRunTime = 1000000000ULL;

	/* Enable profiling */
#ifndef CL_VERSION_1_1
	HANDLE_CLERROR(clSetCommandQueueProperty(queue[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, CL_TRUE, NULL), "Failed enabling profiling");
#else /* clSetCommandQueueProperty() is deprecated */
	cl_command_queue origQueue = queue[ocl_gpu_id];
	queue[ocl_gpu_id] = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "Failed enabling profiling");
#endif

	/* Beware of device limits */
	max_gws = MIN(get_max_mem_alloc_size(ocl_gpu_id) / max_len, get_global_memory_size(ocl_gpu_id) / (max_len + 16 + BINARY_SIZE + SALT_SIZE));

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
	char *encoding = options.encodingDef ?
	    options.encodingDef : "ISO_8859_1";

	if (options.utf8) {
		max_len = self->params.plaintext_length = 3 * PLAINTEXT_LENGTH;

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

	snprintf(build_opts, sizeof(build_opts),
	    "-DENC_%s -DENCODING=%s -DPLAINTEXT_LENGTH=%u",
	         encoding, encoding, PLAINTEXT_LENGTH);
	opencl_init("$JOHN/kernels/krb5pa-md5_kernel.cl", ocl_gpu_id, build_opts);

	/* Read LWS/GWS prefs from config or environment */
	opencl_get_user_preferences(OCL_CONFIG);

	/* create kernels to execute */
	krb5pa_md5_nthash = clCreateKernel(program[ocl_gpu_id], "krb5pa_md5_nthash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "krb5pa_md5_final", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	maxsize = get_current_work_group_size(ocl_gpu_id, krb5pa_md5_nthash);
	maxsize2 = get_current_work_group_size(ocl_gpu_id, crypt_kernel);
	if (maxsize2 < maxsize) maxsize = maxsize2;

	max_mem = get_max_mem_alloc_size(ocl_gpu_id);

	/* maxsize is the lowest figure from the two kernels */
	if (!local_work_size)
#if 0
		local_work_size = 64;
#else
	{
		int temp = global_work_size;
		local_work_size = maxsize;
		global_work_size = global_work_size ? global_work_size : 128 * maxsize;
		while (global_work_size > max_mem / ((max_len + 63) / 64 * 64))
			global_work_size -= local_work_size;
		create_clobj(global_work_size, self);
		opencl_find_best_workgroup_limit(self, maxsize, ocl_gpu_id, crypt_kernel);
		release_clobj();
		global_work_size = temp;
	}
#endif

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

	// Ensure GWS is multiple of LWS
	global_work_size = global_work_size / local_work_size * local_work_size;

	if (options.verbosity > 2)
		fprintf(stderr,
		        "Local worksize (LWS) %d, Global worksize (GWS) %d\n",
		        (int)local_work_size, (int)global_work_size);
	create_clobj(global_work_size, self);
}

static void *salt(char *ciphertext)
{
	static salt_t salt;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	if (strlen(p) == 2 * (TIMESTAMP_SIZE + CHECKSUM_SIZE)) {
		// New input format
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
	} else {
		// Old input format
		p -= (2 * CHECKSUM_SIZE + 1);
		for (i = 0; i < CHECKSUM_SIZE; i++) {
			((unsigned char*)salt.checksum)[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
			p += 2;
		}
		++p;
		for (i = 0; i < TIMESTAMP_SIZE; i++) {
			salt.timestamp[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
			p += 2;
		}
	}
	return (void*)&salt;
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i;

	/* Don't do more than requested */
	global_work_size = (count + local_work_size - 1) / local_work_size * local_work_size;

	if (new_keys) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_key, CL_FALSE, key_offset, key_idx - key_offset, saved_key + key_offset, 0, NULL, NULL), "Failed transferring keys");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saved_idx, CL_FALSE, idx_offset, 4 * (global_work_size + 1) - idx_offset, saved_idx + (idx_offset / 4), 0, NULL, NULL), "Failed transferring index");
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], krb5pa_md5_nthash, 1, NULL, &global_work_size, &local_work_size, 0, NULL, firstEvent), "Failed running first kernel");

		new_keys = 0;
	}
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, lastEvent), "Failed running second kernel");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], cl_result, CL_TRUE, 0, BINARY_SIZE * global_work_size, output, 0, NULL, NULL), "failed reading results back");

	for (i = 0; i < count; i++) {
		unsigned char *binary = &((unsigned char*)output)[BINARY_SIZE * i];

		// Check for known plaintext
		if (binary[14] == '2' && binary[15] == '0') {
			salt_t *salt = (salt_t*)saltblob;
			unsigned char K[KEY_SIZE];
			unsigned char K1[KEY_SIZE];
			unsigned char K3[KEY_SIZE];
			unsigned char plaintext[TIMESTAMP_SIZE];
			const unsigned char one[] = { 1, 0, 0, 0 };
			char *password;

			// K = MD4(UTF-16LE(password))
			// This is not thread safe
			password = get_key(i);
			E_md4hash((unsigned char*)password,
			    strlen(password), K);

			// K1 = HMAC-MD5(K, 1)
			// 1 is encoded as little endian in 4 bytes (0x01000000)
			hmac_md5(K, (unsigned char*)&one, 4, K1);

			// K3 = HMAC-MD5(K1, CHECKSUM)
			hmac_md5(K1, (unsigned char*)salt->checksum,
			         CHECKSUM_SIZE, K3);

			// Decrypt the timestamp
			RC4_single(K3, KEY_SIZE, salt->timestamp,
			           TIMESTAMP_SIZE, plaintext);

			if (plaintext[28] == 'Z') {
				// create checksum K2 = HMAC-MD5(K1, plaintext)
				hmac_md5(K1, plaintext, TIMESTAMP_SIZE, binary);
			}
		}
	}

	return count;
}

static void set_salt(void *salt)
{
	salt_t *salts = (salt_t*)salt;

	memcpy(saltblob, salts->checksum, CHECKSUM_SIZE);
	memcpy(saltblob + CHECKSUM_SIZE, salts->timestamp, TIMESTAMP_SIZE);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], cl_saltblob, CL_FALSE, 0, SALT_SIZE, saltblob, 0, NULL, NULL), "Failed transferring salt");
	HANDLE_CLERROR(clFlush(queue[ocl_gpu_id]), "Error transferring salts");
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TOTAL_LENGTH + 1];
	char *data;

	strnzcpy(out, ciphertext, sizeof(out));
	data = out + strlen(out) - 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) - 1;
	strlwr(data);

	return out;
}

static void *binary(char *ciphertext)
{
	static unsigned char *binary;
	char *p;
	int i;

	if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = strrchr(ciphertext, '$') + 1;
	if (strlen(p) == 2 * (TIMESTAMP_SIZE + CHECKSUM_SIZE))
		// New input format
		p += 2 * TIMESTAMP_SIZE;
	else
		// Old input format
		p -= (2 * CHECKSUM_SIZE + 1);

	for (i = 0; i < CHECKSUM_SIZE; i++) {
		binary[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return (void*)binary;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *data = ciphertext, *p;

	if (!strncmp(ciphertext, "$mskrb5$", 8)) {
		data += 8;

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
		    strspn(data, HEXCHARS) != p - data)
			return 0;
		data = p + 1;

		// encrypted timestamp
		p += strlen(data) + 1;
		if (*p || p - data != TIMESTAMP_SIZE * 2 ||
		    strspn(data, HEXCHARS) != p - data)
			return 0;

		return 1;
	} else if (!strncmp(ciphertext, "$krb5pa$23$", 11)) {
		data += 11;

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
		    strspn(data, HEXCHARS) != p - data)
			return 0;

		return 1;
	}
	return 0;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;

	for (index = 0; index < count; index++)
		if (*(ARCH_WORD_32*)binary == *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, &output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int get_hash_0(int index) { return *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)] & 0xf; }
static int get_hash_1(int index) { return *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)] & 0xff; }
static int get_hash_2(int index) { return *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)] & 0xfff; }
static int get_hash_3(int index) { return *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)] & 0xffff; }
static int get_hash_4(int index) { return *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)] & 0xfffff; }
static int get_hash_5(int index) { return *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)] & 0xffffff; }
static int get_hash_6(int index) { return *(ARCH_WORD_32*)&output[index * BINARY_SIZE / sizeof(ARCH_WORD_32)] & 0x7ffffff; }

static int salt_hash(void *salt)
{
	return (((salt_t*)salt)->checksum[0]) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_opencl_krb5pa_md5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
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
		fmt_default_prepare,
		valid,
		split,
		binary,
		salt,
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
