/* RAR 3.x cracker patch for JtR. Hacked together during
 * April of 2011 by Dhiru Kholia <dhiru.kholia at gmail.com> for GSoC.
 * magnum added -p mode support, using code based on libclamav
 * and OMP, AES-NI and OpenCL support.
 *
 * This software is Copyright © 2011, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright © 2012, magnum and it is hereby released to the general public
 * under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This program uses code present in the public domain unrar utility written by
 * Alexander Roshal (http://www.rarlab.com/rar/unrarsrc-4.0.7.tar.gz).
 * Specifically, lines 240 to 274 from crypt.cpp are used.
 *
 * Huge thanks to Marc Bevand <m.bevand (at) gmail.com> for releasing unrarhp
 * (http://www.zorinaq.com/unrarhp/) and documenting the RAR encryption scheme.
 * This patch is made possible by unrarhp's documentation.
 *
 * http://anrieff.net/ucbench/technical_qna.html is another useful reference
 * for RAR encryption scheme.
 *
 * For type = 0 for files encrypted with "rar -hp ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*0*archive_name*offset-for-ciphertext*method:type::file_name
 *
 * For type = 1 for files encrypted with "rar -p ..." option
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*archive_name*offset-for-ciphertext*method:type::file_name
 *
 * or (inlined binary)
 *
 * archive_name:$RAR3$*type*hex(salt)*hex(crc)*PACK_SIZE*UNP_SIZE*1*hex(full encrypted file)*method:type::file_name
 *
 */

#include "opencl_rar.h"

#ifdef CL_VERSION_1_0
/* Not defining ALWAYS_OPENCL will be very beneficial for Single mode
   and speed up self-tests at startup */
//#define ALWAYS_OPENCL
#ifdef DEBUG
/* Non-blocking requests may postpone errors, causing confusion */
#define BLOCK_IF_DEBUG	CL_TRUE
#else
#define BLOCK_IF_DEBUG	CL_FALSE
#endif
#ifdef RAR_VECTORIZE
#define VF	4
#else
#define VF	1
#endif
#endif

#include "arch.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#if defined(__APPLE__) && defined(__MACH__)
#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif
#else
#include <openssl/sha.h>
#endif
#else
#include <openssl/sha.h>
#endif

#include <openssl/ssl.h>
#undef MEM_FREE

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "johnswap.h"
#include "unrar.h"
#ifdef CL_VERSION_1_0
#include "common-opencl.h"
#endif
#include "config.h"

#define FORMAT_LABEL		"rar"
#define FORMAT_NAME		"RAR3"
#ifdef CL_VERSION_1_0
#define ALGORITHM_NAME		"OpenCL"
#else
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT	" (4 characters)"
#define BENCHMARK_LENGTH	-1

#define UNICODE_LENGTH		(2 * PLAINTEXT_LENGTH)
#define BINARY_SIZE		2
#define SALT_SIZE		sizeof(rarfile)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

/* The reason we want to bump OMP_SCALE in this case is to even out the
   difference in processing time for different length keys. It doesn't
   boost performance in other ways */
#ifdef _OPENMP
#include <omp.h>
#include <pthread.h>
#define OMP_SCALE		4
static pthread_mutex_t *lockarray;
#endif

static int omp_t = 1;
static unsigned char *saved_salt;
static unsigned char *saved_key;
#ifdef CL_VERSION_1_0
static int new_keys;
#endif
static int (*cracked);
static unpack_data_t (*unpack_data);

static unsigned int *saved_len;
static unsigned char *aes_key;
static unsigned char *aes_iv;

typedef struct {
	int type;	/* 0 = -hp, 1 = -p */
	unsigned char salt[8];
	/* for rar -hp mode: */
	unsigned char saved_ct[16];
	/* for rar -p mode: */
	union {
		unsigned int w;
		unsigned char c[4];
	} crc;
	unsigned int pack_size;
	unsigned int unp_size;
	unsigned char *encrypted;
	char *archive_name;
	long pos;
	int method;
} rarfile;

static rarfile *cur_file;

#ifdef CL_VERSION_1_0
/* Determines when to use CPU instead (eg. Single mode, few keys in a call) */
#define CPU_GPU_RATIO		32
static size_t global_work_size = 0;
static cl_mem cl_saved_key, cl_saved_len, cl_salt, cl_aes_key, cl_aes_iv;
#endif

struct fmt_main rar_fmt;
static int *mkpc = &rar_fmt.params.max_keys_per_crypt;

/* cRARk use 4-char passwords for CPU benchmark */
static struct fmt_tests cpu_tests[] = {
	{"$RAR3$*0*b109105f5fe0b899*d4f96690b1a8fe1f120b0290a85a2121", "test"},
	{"$RAR3$*0*42ff7e92f24fb2f8*9d8516c8c847f1b941a0feef064aaf0d", "1234"},
	{"$RAR3$*0*56ce6de6ddee17fb*4c957e533e00b0e18dfad6accc490ad9", "john"},
	/* -p mode tests, -m3 and -m0 */
	{"$RAR3$*1*c47c5bef0bbd1e98*965f1453*48*47*1*c5e987f81d316d9dcfdb6a1b27105ce63fca2c594da5aa2f6fdf2f65f50f0d66314f8a09da875ae19d6c15636b65c815*30", "test"},
	{"$RAR3$*1*b4eee1a48dc95d12*965f1453*64*47*1*0fe529478798c0960dd88a38a05451f9559e15f0cf20b4cac58260b0e5b56699d5871bdcc35bee099cc131eb35b9a116adaedf5ecc26b1c09cadf5185b3092e6*33", "test"},
#ifdef DEBUG
	/* Various lengths, these should be in self-test but not benchmark */
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif
	{NULL}
};

#ifdef CL_VERSION_1_0
/* cRARk use 6-char passwords for GPU benchmark */
static struct fmt_tests gpu_tests[] = {
	{"$RAR3$*0*af24c0c95e9cafc7*e7f207f30dec96a5ad6f917a69d0209e", "magnum"},
	{"$RAR3$*0*2653b9204daa2a8e*39b11a475f486206e2ec6070698d9bbc", "123456"},
	{"$RAR3$*0*63f1649f16c2b687*8a89f6453297bcdb66bd756fa10ddd98", "abc123"},
	/* -p mode tests, -m3 and -m0 */
	{"$RAR3$*1*575b083d78672e85*965f1453*48*47*1*cd3d8756438f43ab70e668792e28053f0ad7449af1c66863e3e55332bfa304b2c082b9f23b36cd4a8ebc0b743618c5b2*30", "magnum"},
	{"$RAR3$*1*6f5954680c87535a*965f1453*64*47*1*c9bb398b9a5d54f035fd22be54bc6dc75822f55833f30eb4fb8cc0b8218e41e6d01824e3467475b90b994a5ddb7fe19366d293c9ee305316c2a60c3a7eb3ce5a*33", "magnum"},
#ifdef DEBUG
	/* Various lengths, these should be in self-test but not benchmark */
	{"$RAR3$*0*c203c4d80a8a09dc*49bbecccc08b5d893f308bce7ad36c0f", "sator"},
	{"$RAR3$*0*672fca155cb74ac3*8d534cd5f47a58f6493012cf76d2a68b", "arepo"},
	{"$RAR3$*0*c203c4d80a8a09dc*c3055efe7ca6587127fd541a5b88e0e4", "tenet"},
	{"$RAR3$*0*672fca155cb74ac3*c760267628f94060cca57be5896003c8", "opera"},
	{"$RAR3$*0*c203c4d80a8a09dc*1f406154556d4c895a8be207fd2b5d0c", "rotas"},
	{"$RAR3$*0*345f5f573a077ad7*638e388817cc7851e313406fd77730b9", "Boustrophedon"},
	{"$RAR3$*0*c9dea41b149b53b4*fcbdb66122d8ebdb32532c22ca7ab9ec", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*f2b26d76424efa351c728b321671d074", "@"},
	{"$RAR3$*0*ea0ea55ce549c8ab*cf89099c620fcc244bdcbae55a616e76", "ow"},
	{"$RAR3$*0*ea0ea55ce549c8ab*6a35a76b1ce9ddc4229b9166d60dc113", "aes"},
	{"$RAR3$*0*ea0ea55ce549c8ab*1830771da109f53e2d6e626be16c2666", "sha1"},
	{"$RAR3$*0*7e52d3eba9bad316*ee8e1edd435cfa9b8ab861d958a4d588", "fiver"},
	{"$RAR3$*0*7e52d3eba9bad316*01987735ab0be7b6538470bd5f5fbf80", "magnum"},
	{"$RAR3$*0*7e52d3eba9bad316*f2fe986ed266c6617c48d04a429cf2e3", "7777777"},
	{"$RAR3$*0*7e52d3eba9bad316*f0ad6e7fdff9f82fff2aa990105fde21", "password"},
	{"$RAR3$*0*7ce241baa2bd521b*3eb0017fa8843017952c53a3ac8332b6", "nine9nine"},
	{"$RAR3$*0*7ce241baa2bd521b*ccbf0c3f8e059274606f33cc388b8a2f", "10tenten10"},
	{"$RAR3$*0*5fa43f823a60da63*af2630863e12046e42c4501c915636c9", "eleven11111"},
	{"$RAR3$*0*5fa43f823a60da63*88c0840d0bd98844173d35f867558ec2", "twelve121212"},
	{"$RAR3$*0*4768100a172fa2b6*48edcb5283ee2e4f0e8edb25d0d85eaa", "subconsciousness"},
#endif
	{NULL}
};
#endif

#if defined (_OPENMP)
static void lock_callback(int mode, int type, char *file, int line)
{
	(void)file;
	(void)line;
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&(lockarray[type]));
	else
		pthread_mutex_unlock(&(lockarray[type]));
}

static unsigned long thread_id(void)
{
	unsigned long ret;
	ret = (unsigned long) pthread_self();
	return (ret);
}

static void init_locks(void)
{
	int i;
	lockarray = (pthread_mutex_t*) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&(lockarray[i]), NULL);
	CRYPTO_set_id_callback((unsigned long (*)()) thread_id);
	CRYPTO_set_locking_callback((void (*)()) lock_callback);
}
#endif	/* _OPENMP */

/* Use AES-NI if available. This is not supported with low-level calls,
   we have to use EVP) */
static void init_aesni(void)
{
	ENGINE *e;
	const char *engine_id = "aesni";

	ENGINE_load_builtin_engines();
	e = ENGINE_by_id(engine_id);
	if (!e) {
		//fprintf(stderr, "AES-NI engine not available\n");
		return;
	}
	if (!ENGINE_init(e)) {
		fprintf(stderr, "AES-NI engine could not init\n");
		ENGINE_free(e);
		return;
	}
	if (!ENGINE_set_default(e, ENGINE_METHOD_ALL & ~ENGINE_METHOD_RAND)) {
		/* This should only happen when 'e' can't initialise, but the
		 * previous statement suggests it did. */
		fprintf(stderr, "AES-NI engine initialized but then failed\n");
		abort();
	}
	ENGINE_finish(e);
	ENGINE_free(e);
}

static void openssl_cleanup(void)
{
	ENGINE_cleanup();
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
}

#ifdef CL_VERSION_1_0
static void create_clobj(int kpc)
{
	int i;
	int bench_len = strlen(rar_fmt.params.tests[0].plaintext) * 2;

#ifdef DEBUG
	fprintf(stderr, "Creating %d bytes of key buffer\n", UNICODE_LENGTH * kpc);
#endif
	cl_saved_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, UNICODE_LENGTH * kpc, NULL , &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_key = (unsigned char*)clEnqueueMapBuffer(queue[gpu_id], cl_saved_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, UNICODE_LENGTH * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_key");
	memset(saved_key, 0, UNICODE_LENGTH * kpc);

#ifdef DEBUG
	fprintf(stderr, "Creating %lu bytes of key_len buffer\n", sizeof(cl_int) * kpc);
#endif
	cl_saved_len = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_int) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_len = (unsigned int*)clEnqueueMapBuffer(queue[gpu_id], cl_saved_len, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_int) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_len");
	for (i = 0; i < kpc; i++)
		saved_len[i] = bench_len;

#ifdef DEBUG
	fprintf(stderr, "Creating 8 bytes of salt buffer\n");
#endif
	cl_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 8, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	saved_salt = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], cl_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 8, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_salt");
	memset(saved_salt, 0, 8);

#ifdef DEBUG
	fprintf(stderr, "Creating %d bytes each of aes_key and aes_iv buffers\n", 16 * kpc);
#endif
	// aes_key is uchar[16] but kernel treats it as uint[4]
	cl_aes_key = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	aes_key = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], cl_aes_key, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory aes_key");
	memset(aes_key, 0, 16 * kpc);

	cl_aes_iv = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, 16 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");
	aes_iv = (unsigned char*) clEnqueueMapBuffer(queue[gpu_id], cl_aes_iv, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 16 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory aes_iv");
	memset(aes_iv, 0, 16 * kpc);

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem), (void*)&cl_saved_key), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem), (void*)&cl_saved_len), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem), (void*)&cl_salt), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(cl_mem), (void*)&cl_aes_key), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(cl_mem), (void*)&cl_aes_iv), "Error setting argument 4");

	global_work_size = (*mkpc = kpc) / VF;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], cl_aes_key, aes_key, 0, NULL, NULL), "Error Unmapping aes_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], cl_aes_iv, aes_iv, 0, NULL, NULL), "Error Unmapping aes_iv");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], cl_saved_key, saved_key, 0, NULL, NULL), "Error Unmapping saved_key");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], cl_saved_len, saved_len, 0, NULL, NULL), "Error Unmapping saved_len");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], cl_salt, saved_salt, 0, NULL, NULL), "Error Unmapping saved_salt");
	aes_key = NULL; aes_iv = NULL; saved_key = NULL; saved_len = NULL; saved_salt = NULL;
}
#endif	/* OpenCL */

static void set_key(char *key, int index)
{
	int plen;
	UTF16 buf[PLAINTEXT_LENGTH + 1];

	/* UTF-16LE encode the password, encoding aware */
	plen = enc_to_utf16(buf, PLAINTEXT_LENGTH, (UTF8*) key, strlen(key));

	if (plen < 0)
		plen = strlen16(buf);

	memcpy(&saved_key[UNICODE_LENGTH * index], buf, UNICODE_LENGTH);

	saved_len[index] = plen << 1;

#ifdef CL_VERSION_1_0
	new_keys = 1;
#endif
}

#ifdef CL_VERSION_1_0
cl_ulong gws_test(int num)
{
	cl_ulong startTime, endTime, run_time;
	cl_command_queue queue_prof;
	cl_event myEvent;
	cl_int ret_code;
	int i;

	create_clobj(num);
	queue_prof = clCreateCommandQueue(context[gpu_id], devices[gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i = 0; i < num; i++)
		set_key(rar_fmt.params.tests[0].plaintext, i);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_salt, BLOCK_IF_DEBUG, 0, 8, saved_salt, 0, NULL, NULL), "Failed transferring salt");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_saved_key, BLOCK_IF_DEBUG, 0, UNICODE_LENGTH * num, saved_key, 0, NULL, NULL), "Failed transferring keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, cl_saved_len, BLOCK_IF_DEBUG, 0, sizeof(int) * num, saved_len, 0, NULL, NULL), "Failed transferring lengths");
	ret_code = clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &myEvent);
	if (ret_code != CL_SUCCESS) {
		fprintf(stderr, "Error: %s\n", get_error_name(ret_code));
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}
	HANDLE_CLERROR(clFinish(queue_prof), "Failed running kernel");
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL);
	run_time = endTime - startTime;
	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, cl_aes_iv, BLOCK_IF_DEBUG, 0, 16 * num, aes_iv, 0, NULL, &myEvent), "Failed reading iv back");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue_prof, cl_aes_key, BLOCK_IF_DEBUG, 0, 16 * num, aes_key, 0, NULL, &myEvent), "Failed reading key back");
	HANDLE_CLERROR(clFinish(queue_prof), "Failed reading results back");
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL);
	clReleaseCommandQueue(queue_prof);
	release_clobj();

	return (run_time + endTime - startTime);
}

static void find_best_kpc(int do_benchmark)
{
	int num;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	unsigned int SHAspeed, bestSHAspeed = 0;
	int optimal_kpc = local_work_size * VF;
	const int sha1perkey = (strlen(rar_fmt.params.tests[0].plaintext) * 2 + 8 + 3) * (0x40000 + 16) / 64;

#ifndef DEBUG
	if (do_benchmark)
#endif
	{
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd\n\n", local_work_size);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size * VF; num; num *= 2) {
		if (!(run_time = gws_test(num)))
			break;

		SHAspeed = sha1perkey * (1000000000UL * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

#ifndef DEBUG
		if (do_benchmark)
#endif
		fprintf(stderr, "kpc %6d\t%4lu c/s%14u sha1/s%8.3f sec per crypt_all()", num, (1000000000UL * num / run_time), SHAspeed, (float)run_time / 1000000000.);

		if (((float)run_time / (float)min_time) < ((float)SHAspeed / (float)bestSHAspeed)) {
#ifndef DEBUG
			if (do_benchmark)
#endif
			fprintf(stderr, "!\n");
			bestSHAspeed = SHAspeed;
			optimal_kpc = num;
		} else {

			if (((float)run_time / (float)min_time) > 1.8 * ((float)SHAspeed / (float)bestSHAspeed) && run_time > 10000000000U) {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "\n");
				break;
			}

			if (SHAspeed > bestSHAspeed) {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "+");
				bestSHAspeed = SHAspeed;
				optimal_kpc = num;
			}
#ifndef DEBUG
			if (do_benchmark)
#endif
			fprintf(stderr, "\n");
		}
	}
	if (do_benchmark) {
		int got_better = 0;

		for (num = optimal_kpc + VF * local_work_size; num; num += VF * local_work_size) {
			if (!(run_time = gws_test(num)))
				break;

			SHAspeed = sha1perkey * (1000000000UL * num / run_time);

			if (run_time < min_time)
				min_time = run_time;

#ifndef DEBUG
			if (do_benchmark)
#endif
			fprintf(stderr, "kpc %6d\t%4lu c/s%14u sha1/s%8.3f sec per crypt_all()", num, (1000000000UL * num / run_time), SHAspeed, (float)run_time / 1000000000.);

			if (((float)run_time / (float)min_time) > ((float)SHAspeed / (float)bestSHAspeed) && run_time > 10000000000U) {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "\n");
				break;
			}

			if (SHAspeed > bestSHAspeed && run_time < 10000000000U) {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "+\n");
				bestSHAspeed = SHAspeed;
				optimal_kpc = num;
				got_better = 1;
			} else {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "\n");
				break;
			}
		}
		if (!got_better)
		for (num = optimal_kpc - VF * local_work_size; num; num -= VF * local_work_size) {
			if (!(run_time = gws_test(num)))
				break;

			SHAspeed = sha1perkey * (1000000000UL * num / run_time);

			if (run_time < min_time)
				min_time = run_time;

#ifndef DEBUG
			if (do_benchmark)
#endif
			fprintf(stderr, "kpc %6d\t%4lu c/s%14u sha1/s%8.3f sec per crypt_all()", num, (1000000000UL * num / run_time), SHAspeed, (float)run_time / 1000000000.);

			if (((float)run_time / (float)min_time) > ((float)SHAspeed / (float)bestSHAspeed) && run_time > 10000000000U) {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "\n");
				break;
			}

			if (SHAspeed > bestSHAspeed && run_time < 10000000000U) {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "+\n");
				bestSHAspeed = SHAspeed;
				optimal_kpc = num;
				got_better = 1;
			} else {
#ifndef DEBUG
				if (do_benchmark)
#endif
				fprintf(stderr, "\n");
				break;
			}
		}
	}
	if (get_device_type(gpu_id) != CL_DEVICE_TYPE_CPU) {
		fprintf(stderr, "Optimal keys per crypt %d\n",(int)optimal_kpc);
		fprintf(stderr, "(to avoid this test on next run, put \""
		        KPC_CONFIG " = %d\" in john.conf, section [" SECTION_OPTIONS
		        SUBSECTION_OPENCL "])\n", (int)optimal_kpc);
	}
	global_work_size = (*mkpc = optimal_kpc) / VF;
}
#endif	/* OpenCL */

static void init(struct fmt_main *pFmt)
{
#ifdef CL_VERSION_1_0
	char *temp;
	cl_ulong maxsize;

	opencl_init("$JOHN/rar_kernel.cl", gpu_id, platform_id);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[gpu_id], "SetCryptKeys", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	/* We mimic the lengths of cRARk for comparisons */
	if (get_device_type(gpu_id) == CL_DEVICE_TYPE_GPU) {
		pFmt->params.benchmark_comment = " (6 characters)";
		pFmt->params.tests = gpu_tests;
#if defined(DEBUG) && !defined(ALWAYS_OPENCL)
		fprintf(stderr, "Note: will use CPU for self-tests and Single mode.\n");
#endif
	} else
		fprintf(stderr, "Note: OpenCL device is CPU. A non-OpenCL build may be faster.\n");
	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(temp);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, KPC_CONFIG)))
		global_work_size = atoi(temp) / VF;

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);

	if ((temp = getenv("KPC")))
		global_work_size = atoi(temp) / VF;

	/* Note: we ask for this kernel's max size, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");

#ifdef DEBUG
	fprintf(stderr, "Max allowed local work size %d\n", (int)maxsize);
#endif

	if (!local_work_size) {
		if (get_device_type(gpu_id) == CL_DEVICE_TYPE_CPU) {
			local_work_size = 8;
		} else {
			local_work_size = 64;
		}
	}

	if (local_work_size > maxsize) {
		fprintf(stderr, "LWS %d is too large for this GPU. Max allowed is %d, using that.\n", (int)local_work_size, (int)maxsize);
		local_work_size = maxsize;
	}

	if (!global_work_size)
		find_best_kpc(temp == NULL ? 0 : 1);

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize %d, KPC %d\n", (int)local_work_size, (int)global_work_size, VF * (int)global_work_size);

	create_clobj(VF * global_work_size);

#ifdef DEBUG
	{
		cl_ulong loc_mem_size;
		HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[gpu_id], CL_KERNEL_LOCAL_MEM_SIZE, sizeof(loc_mem_size), &loc_mem_size, NULL), "Query local memory usage");
		fprintf(stderr, "Kernel using %lu bytes of local memory out of %lu available\n", loc_mem_size, get_local_memory_size(gpu_id));
	}
#endif

	atexit(release_clobj);

	*mkpc = VF * global_work_size;

#endif	/* OpenCL */

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
#ifndef CL_VERSION_1_0	/* OpenCL gets to decide */
	*mkpc = omp_t * OMP_SCALE * MAX_KEYS_PER_CRYPT;
#endif
	init_locks();
#endif /* _OPENMP */

	if (options.utf8)
		pFmt->params.plaintext_length = PLAINTEXT_LENGTH * 3;

	unpack_data = mem_calloc_tiny(sizeof(unpack_data_t) * omp_t, MEM_ALIGN_WORD);
	cracked = mem_calloc_tiny(sizeof(*cracked) * *mkpc, MEM_ALIGN_WORD);
#ifndef CL_VERSION_1_0
	saved_key = mem_calloc_tiny(UNICODE_LENGTH * *mkpc, MEM_ALIGN_NONE);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) * *mkpc, MEM_ALIGN_WORD);
	saved_salt = mem_calloc_tiny(8, MEM_ALIGN_NONE);
	aes_key = mem_calloc_tiny(16 * *mkpc, MEM_ALIGN_NONE);
	aes_iv = mem_calloc_tiny(16 * *mkpc, MEM_ALIGN_NONE);
#endif

	/* OpenSSL init */
	init_aesni();
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	atexit(openssl_cleanup);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$RAR3$*", 7);
}

static void *get_salt(char *ciphertext)
{
	unsigned int i, count;
	/* extract data from "salt" */
	char *encoded_salt;
	char *saltcopy = strdup(ciphertext);
	char *keep_ptr = saltcopy;
	static rarfile rarfile;

	saltcopy += 7;		/* skip over "$RAR3$*" */
	rarfile.type = atoi(strtok(saltcopy, "*"));
	encoded_salt = strtok(NULL, "*");
	for (i = 0; i < 8; i++)
		rarfile.salt[i] = atoi16[ARCH_INDEX(encoded_salt[i * 2])] * 16 + atoi16[ARCH_INDEX(encoded_salt[i * 2 + 1])];
	if (rarfile.type == 0) {	/* rar-hp mode */
		char *encoded_ct = strtok(NULL, "*");
		for (i = 0; i < 16; i++)
			rarfile.saved_ct[i] = atoi16[ARCH_INDEX(encoded_ct[i * 2])] * 16 + atoi16[ARCH_INDEX(encoded_ct[i * 2 + 1])];
	} else {
		char *p = strtok(NULL, "*");
		int inlined;
		for (i = 0; i < 4; i++)
			rarfile.crc.c[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
		rarfile.pack_size = atoi(strtok(NULL, "*"));
		rarfile.unp_size = atoi(strtok(NULL, "*"));
		inlined = atoi(strtok(NULL, "*"));

		/* load ciphertext. We allocate and load all files here, and
		   they don't get unloaded until program ends */
		rarfile.encrypted = (unsigned char*)malloc(rarfile.pack_size);
		if (inlined) {
			unsigned char *d = rarfile.encrypted;
			p = strtok(NULL, "*");
			for (i = 0; i < rarfile.pack_size; i++)
				*d++ = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
		} else {
			FILE *fp;
			rarfile.archive_name = strtok(NULL, "*");
			rarfile.pos = atol(strtok(NULL, "*"));

			if (!(fp = fopen(rarfile.archive_name, "rb"))) {
				fprintf(stderr, "! %s: %s\n", rarfile.archive_name, strerror(errno));
				error();
			}
			fseek(fp, rarfile.pos, SEEK_SET);
			count = fread(rarfile.encrypted, 1, rarfile.pack_size, fp);
			if (count != rarfile.pack_size) {
				fprintf(stderr, "Error loading file from archive '%s', expected %u bytes, got %u. Archive possibly damaged.\n", rarfile.archive_name, rarfile.pack_size, count);
				exit(0);
			}
			fclose(fp);
		}
		p = strtok(NULL, "*");
		rarfile.method = atoi16[ARCH_INDEX(p[0])] * 16 + atoi16[ARCH_INDEX(p[1])];
		if (rarfile.method != 0x30)
			rarfile.crc.w = ~rarfile.crc.w;
	}
	free(keep_ptr);
	return (void*)&rarfile;
}

static void set_salt(void *salt)
{
	cur_file = (rarfile*)salt;
	memcpy(saved_salt, cur_file->salt, 8);

#ifdef CL_VERSION_1_0
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_salt, BLOCK_IF_DEBUG, 0, 8, saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_salt");
#endif
}

static char *get_key(int index)
{
	return (char*) utf16_to_enc(&((UTF16*) saved_key)[index * PLAINTEXT_LENGTH]);
}

static void crypt_all(int count)
{
	int index = 0;

#ifdef CL_VERSION_1_0
#ifndef ALWAYS_OPENCL
	if (count > (*mkpc / CPU_GPU_RATIO))
#endif
	{
		if (new_keys) {
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_key, BLOCK_IF_DEBUG, 0, UNICODE_LENGTH * *mkpc, saved_key, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_key");
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], cl_saved_len, BLOCK_IF_DEBUG, 0, sizeof(int) * *mkpc, saved_len, 0, NULL, NULL), "failed in clEnqueueWriteBuffer saved_len");
			new_keys = 0;
		}
#ifdef DEBUG
		fprintf(stderr, "GPU: lws %d gws %d kpc %d count %d\n", (int)local_work_size, (int)global_work_size, *mkpc, count);
#endif
		HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, NULL), "failed in clEnqueueNDRangeKernel");
#ifdef DEBUG
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Failed running kernel");
#endif
		// read back aes key & iv
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_key, BLOCK_IF_DEBUG, 0, 16 * *mkpc, aes_key, 0, NULL, NULL), "failed in reading key back");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], cl_aes_iv, CL_TRUE, 0, 16 * *mkpc, aes_iv, 0, NULL, NULL), "failed in reading iv back");

	}
#ifndef ALWAYS_OPENCL
	else
#endif
#endif	/* OpenCL */
#if !defined (CL_VERSION_1_0) || !defined(ALWAYS_OPENCL)
	{
#ifdef DEBUG
		fprintf(stderr, "CPU: kpc %d count %d\n", *mkpc, count);
#endif
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (index = 0; index < count; index++) {
			int i16 = index*16;
			unsigned int i, j;
#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
			unsigned char RawPsw[UNICODE_LENGTH + 8 + sizeof(int)];
#else
			unsigned char RawPsw[UNICODE_LENGTH + 8];
#endif
			int RawLength;
			SHA_CTX ctx;
			unsigned int digest[5];
#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
			unsigned int *PswNum;
#endif

#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
			RawLength = saved_len[index] + 8 + 3;
			PswNum = (unsigned int*) &RawPsw[saved_len[index] + 8];
			*PswNum = 0;
#else
			RawLength = saved_len[index] + 8;
#endif
			/* derive IV and key for AES from saved_key and
			   saved_salt, this code block is based on unrarhp's
			   and unrar's sources */
			memcpy(RawPsw, &saved_key[UNICODE_LENGTH * index], saved_len[index]);
			memcpy(RawPsw + saved_len[index], saved_salt, 8);
			SHA1_Init(&ctx);
			for (i = 0; i < ROUNDS; i++) {
#if !(ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED)
				unsigned char PswNum[3];
#endif

				SHA1_Update(&ctx, RawPsw, RawLength);
#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
				*PswNum += 1;
#else
				PswNum[0] = (unsigned char) i;
				PswNum[1] = (unsigned char) (i >> 8);
				PswNum[2] = (unsigned char) (i >> 16);
				SHA1_Update(&ctx, PswNum, 3);
#endif
				if (i % (ROUNDS / 16) == 0) {
					SHA_CTX tempctx = ctx;
					unsigned int tempout[5];

					SHA1_Final((unsigned char*) tempout, &tempctx);
					aes_iv[i16 + i / (ROUNDS / 16)] = (unsigned char)JOHNSWAP(tempout[4]);
				}
			}
			SHA1_Final((unsigned char*)digest, &ctx);
			for (j = 0; j < 5; j++)	/* reverse byte order */
				digest[j] = JOHNSWAP(digest[j]);
			for (i = 0; i < 4; i++)
				for (j = 0; j < 4; j++)
					aes_key[i16 + i * 4 + j] = (unsigned char)(digest[i] >> (j * 8));
		}
	}
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		int i16 = index*16;
		unsigned int inlen = 16;
		int outlen;
		EVP_CIPHER_CTX aes_ctx;

		EVP_CIPHER_CTX_init(&aes_ctx);
		EVP_DecryptInit_ex(&aes_ctx, EVP_aes_128_cbc(), NULL, &aes_key[i16], &aes_iv[i16]);
		EVP_CIPHER_CTX_set_padding(&aes_ctx, 0);

		//fprintf(stderr, "key %s\n", utf16_to_enc((UTF16*)&saved_key[index * UNICODE_LENGTH]));
		/* AES decrypt, uses aes_iv, aes_key and saved_ct */
		if (cur_file->type == 0) {	/* rar-hp mode */
			unsigned char plain[16];

			outlen = 0;

			EVP_DecryptUpdate(&aes_ctx, plain, &outlen, cur_file->saved_ct, inlen);
			EVP_DecryptFinal_ex(&aes_ctx, cur_file->saved_ct + outlen, &outlen);

			cracked[index] = !memcmp(plain, "\xc4\x3d\x7b\x00\x40\x07\x00", 7);

		} else {

			if (cur_file->method == 0x30) {	/* stored, not deflated */
				CRC32_t crc;
				unsigned char crc_out[4];
				unsigned char plain[0x8010];
				unsigned int size = cur_file->unp_size;
				unsigned char *cipher = cur_file->encrypted;

				/* Use full decryption with CRC check.
				   Compute CRC of the decompressed plaintext */
				CRC32_Init(&crc);
				outlen = 0;

				while (size > 0x8000) {
					inlen = 0x8000;

					EVP_DecryptUpdate(&aes_ctx, plain, &outlen, cipher, inlen);
					CRC32_Update(&crc, plain, outlen > size ? size : outlen);
					size -= outlen;
					cipher += inlen;
				}
				EVP_DecryptUpdate(&aes_ctx, plain, &outlen, cipher, (size + 15) & ~0xf);
				EVP_DecryptFinal_ex(&aes_ctx, &plain[outlen], &outlen);
				size += outlen;
				CRC32_Update(&crc, plain, size);
				CRC32_Final(crc_out, crc);

				/* Compare computed CRC with stored CRC */
				cracked[index] = !memcmp(crc_out, &cur_file->crc.c, 4);
			} else {
				const int solid = 0;
				unpack_data_t *unpack_t;

#ifdef _OPENMP
				unpack_t = &unpack_data[omp_get_thread_num()];
#else
				unpack_t = unpack_data;
#endif
				unpack_t->max_size = cur_file->unp_size;
				unpack_t->dest_unp_size = cur_file->unp_size;
				unpack_t->pack_size = cur_file->pack_size;
				unpack_t->iv = &aes_iv[i16];
				unpack_t->ctx = &aes_ctx;
				unpack_t->key = &aes_key[i16];
#if 1
				if (rar_unpack29(cur_file->encrypted, solid, unpack_t))
					cracked[index] = !memcmp(&unpack_t->unp_crc, &cur_file->crc.c, 4);
				else
					cracked[index] = 0;
#else
				int aa;
				if ((aa = rar_unpack29(cur_file->encrypted, solid, unpack_t)))
					cracked[index] = !memcmp(&unpack_t->unp_crc, &cur_file->crc.c, 4);
				else
					cracked[index] = 0;

				if (aa == -1) {
					puts("memcheck fail");
					exit(0);
				}
#endif
			}
		}
		EVP_CIPHER_CTX_cleanup(&aes_ctx);
	}
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (cracked[index])
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

struct fmt_main rar_fmt = {
{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP,
		cpu_tests // Changed in init if GPU
	},{
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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
		cmp_exact,
		fmt_default_get_source
	}
};
