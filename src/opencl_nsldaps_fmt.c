/*
 * Copyright (c) 2011 Samuele Giovanni Tonon
 * samu at linuxasylum dot net
 * This program comes with ABSOLUTELY NO WARRANTY; express or
 * implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#include <string.h>

#ifdef BSD
	 // OSX
	 #include <architecture/byte_order.h>
#else
	 #include <endian.h>
#endif


#include "path.h"
#include "misc.h"
#include "params.h"
#include "formats.h"
#include "common.h"
#include "config.h"

#include "sha.h"
#include "base64.h"
#include "common-opencl.h"

#define FORMAT_LABEL			"ssha-opencl"
#define FORMAT_NAME			"Netscape LDAP salted SHA-1"
#define ALGORITHM_NAME			"OpenCL (inefficient, development use mostly)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define CIPHERTEXT_LENGTH		40

#define BINARY_SIZE			20
#define SALT_SIZE			8

#define PLAINTEXT_LENGTH		32

#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT		1

#define LWS_CONFIG			"ssha_LWS"
#define GWS_CONFIG			"ssha_GWS"

#ifndef uint32_t
#define uint32_t unsigned int
#endif

typedef struct {
	uint32_t h0, h1, h2, h3, h4;
} SHA_DEV_CTX;


#define NSLDAP_MAGIC "{ssha}"
#define NSLDAP_MAGIC_LENGTH 6

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_partial_hashes, buffer_out, buffer_keys,
    len_buffer, data_info, mysalt, mycrypt;
static cl_uint *outbuffer;
static cl_uint *outbuffer2;
static char *saved_plain;
static char saved_salt[SALT_SIZE];
static unsigned int datai[2];
static int have_full_hashes;

static struct fmt_tests tests[] = {
	{"{SSHA}8VKmzf3SqceSL8/CJ0bGz7ij+L0SQCxcHHYzBw==", "mabelove"},
	{"{SSHA}91PzTv0Wjs/QVzbQ9douCG3HK8gpV1ocqgbZUg==", "12345678"},
	{"{SSHA}DNPSSyXT0wzh4JiiX1D8RnltILQzUlFBuhKFcA==", "wildstar"},
	{"{SSHA}yVEfRVwCJqVUBgLvgM89ExKgcfZ9QEFQgmobJg==", "zanzibar"},
	{"{SSHA}WTT3B9Jjr8gOt0Q7WMs9/XvukyhTQj0Ns0jMKQ==", "Password9"},
	{"{SSHA}cKFVqtf358j0FGpPsEIK1xh3T0mtDNV1kAaBNg==", "salles"},
	{"{SSHA}y9Nc5vOnK12ppTjHo35lxM1pMFnLZMwqqwH6Eg==", "00000000"},
	{"{SSHA}W3ipFGmzS3+j6/FhT7ZC39MIfqFcct9Ep0KEGA==", "asddsa123"},



#if 0
/*
 * These two were found in john-1.6-nsldaps4.diff.gz and apparently they were
 * supported by that version of they code, but they are not anymore.
 */
	{"{SSHA}/EExmSfmhQSPHDJaTxwQSdb/uPpzYWx0ZXI=", "secret"},
	{"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0", "secret"},
#endif
	{NULL}
};

static void create_clobj(int kpc, struct fmt_main *self) {
	global_work_size = kpc;
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = kpc;
	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR, (PLAINTEXT_LENGTH) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");

	saved_plain = (char*)clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_WRITE | CL_MAP_READ,
			 0, (PLAINTEXT_LENGTH) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");
	memset(saved_plain, 0, PLAINTEXT_LENGTH * kpc);

	outbuffer2 = malloc(sizeof(cl_uint) * 4 * kpc);

	pinned_partial_hashes = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE | CL_MEM_ALLOC_HOST_PTR,
	    sizeof(cl_uint) * kpc, NULL, &ret_code);

	HANDLE_CLERROR(ret_code, "Error creating page-locked memory");

	outbuffer = (cl_uint *) clEnqueueMapBuffer(queue[ocl_gpu_id],
	    pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0,
	    sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory outbuffer");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
	    (PLAINTEXT_LENGTH) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer keys argument");

	buffer_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY,
	    sizeof(cl_uint) * 5 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer out argument");

	data_info = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY,
	    sizeof(unsigned int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating data_info out argument");

	mysalt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, SALT_SIZE, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating mysalt out argument");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(data_info),
		(void *) &data_info), "Error setting argument 0");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mysalt),
		(void *) &mysalt), "Error setting argument 1");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2,
		sizeof(buffer_keys), (void *) &buffer_keys),
	    "Error setting argument 2");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_out),
		(void *) &buffer_out), "Error setting argument 3");

	datai[0] = PLAINTEXT_LENGTH;
	datai[1] = kpc;
    	global_work_size = kpc;

	/* We set this here and never again. Used to be in crypt_all() */
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], data_info, CL_FALSE, 0,
	    sizeof(unsigned int) * 2, datai, 0, NULL, NULL), "failed in clEnqueueWriteBuffer data_info");
}

static void release_clobj(void){
    cl_int ret_code;

    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_partial_hashes, outbuffer, 0,NULL,NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping outbuffer");
    ret_code = clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL);
    HANDLE_CLERROR(ret_code, "Error Ummapping saved_plain");
    ret_code = clReleaseMemObject(buffer_keys);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_keys");
    ret_code = clReleaseMemObject(buffer_out);
    HANDLE_CLERROR(ret_code, "Error Releasing buffer_out");
    ret_code = clReleaseMemObject(data_info);
    HANDLE_CLERROR(ret_code, "Error Releasing data_info");
    ret_code = clReleaseMemObject(mysalt);
    HANDLE_CLERROR(ret_code, "Error Releasing mysalt");
    ret_code = clReleaseMemObject(pinned_saved_keys);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_keys");
    ret_code = clReleaseMemObject(pinned_partial_hashes);
    HANDLE_CLERROR(ret_code, "Error Releasing pinned_partial_hashes");
    MEM_FREE(outbuffer2);
}

/* this function could be used to calculated the best num
of keys per crypt for the given format
*/

static void find_best_gws(int do_benchmark, struct fmt_main *self)
{
    cl_event myEvent;
    cl_ulong startTime, endTime, tmpTime;
    int kernelExecTimeNs = INT_MAX;
    cl_int ret_code;
    int optimal_kpc=2048;
    int gws, i = 0;
    cl_uint *tmpbuffer;

    for(gws = local_work_size << 2; gws <= 8*1024*1024; gws <<= 1) {
        create_clobj(gws, self);
	advance_cursor();
	queue_prof = clCreateCommandQueue( context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i=0; i < gws; i++){
		memcpy(&(saved_plain[i*PLAINTEXT_LENGTH]),"abacaeaf",PLAINTEXT_LENGTH);
	}
	clEnqueueWriteBuffer(queue_prof, mysalt, CL_TRUE, 0, SALT_SIZE, saved_salt, 0, NULL, NULL);
	clEnqueueWriteBuffer(queue_prof, buffer_keys, CL_TRUE, 0, (PLAINTEXT_LENGTH) * gws, saved_plain, 0, NULL, NULL);
    	ret_code = clEnqueueNDRangeKernel( queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &myEvent);
	if(ret_code != CL_SUCCESS) {
		// We hit some resource limit so we end here.
		release_clobj();
		break;
	}
	clFinish(queue_prof);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);
	tmpTime = endTime-startTime;
	tmpbuffer = malloc(sizeof(cl_uint) * gws);
	clEnqueueReadBuffer(queue_prof, buffer_out, CL_TRUE, 0, sizeof(cl_uint) * gws, tmpbuffer, 0, NULL, &myEvent);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL);
	clGetEventProfilingInfo(myEvent, CL_PROFILING_COMMAND_END  , sizeof(cl_ulong), &endTime  , NULL);
	tmpTime = tmpTime + (endTime-startTime);
	if (do_benchmark)
		fprintf(stderr, "%10d %10llu c/s %-.2f us\n", gws, gws * 1000000000ULL / tmpTime, tmpTime / 1000.0);
	if( ((int)( ((float) (tmpTime) / gws) * 10 )) <= kernelExecTimeNs) {
		kernelExecTimeNs = ((int) (((float) (tmpTime) / gws) * 10) ) ;
		optimal_kpc = gws;
	}
	MEM_FREE(tmpbuffer);
	clReleaseCommandQueue(queue_prof);
	release_clobj();
    }
    global_work_size = optimal_kpc;
}

static void fmt_ssha_init(struct fmt_main *self)
{
	char *temp;
	cl_ulong maxsize;

	global_work_size = 0;

	opencl_init("$JOHN/ssha_kernel.cl", ocl_gpu_id, platform_id);

	// create kernel to execute
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "sha1_crypt_kernel", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(temp);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, GWS_CONFIG)))
		global_work_size = atoi(temp);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);

	if (!local_work_size) {
		int temp = global_work_size;
		local_work_size = maxsize;
		global_work_size = global_work_size ? global_work_size : 4 * maxsize;
		create_clobj(global_work_size, self);
		opencl_find_best_workgroup_limit(self, maxsize);
		release_clobj();
		global_work_size = temp;
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
}


static void *binary(char *ciphertext) {
	static char realcipher[BINARY_SIZE + SALT_SIZE + 9];

	memset(realcipher, 0, sizeof(realcipher));
	base64_decode(NSLDAP_MAGIC_LENGTH + ciphertext, CIPHERTEXT_LENGTH,
	    realcipher);
	return (void *) realcipher;
}

static void *get_salt(char *ciphertext){
	static char *realcipher;

	// Cludge to be sure to satisfy the salt aligment test of 1.7.9.3 on 64-bit
	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + SALT_SIZE + 9 + 4, MEM_ALIGN_WORD) + 4;

	memset(realcipher, 0, BINARY_SIZE + SALT_SIZE + 9 + 4);

	base64_decode(NSLDAP_MAGIC_LENGTH + ciphertext, CIPHERTEXT_LENGTH,
	    realcipher);
	return (void *) &realcipher[BINARY_SIZE];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (ciphertext && strlen(ciphertext) == CIPHERTEXT_LENGTH + NSLDAP_MAGIC_LENGTH)
		return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
	return 0;
}

static int get_hash_0(int index) { return outbuffer[index] & 0xF; }
static int get_hash_1(int index) { return outbuffer[index] & 0xFF; }
static int get_hash_2(int index) { return outbuffer[index] & 0xFFF; }
static int get_hash_3(int index) { return outbuffer[index] & 0xFFFF; }
static int get_hash_4(int index) { return outbuffer[index] & 0xFFFFF; }
static int get_hash_5(int index) { return outbuffer[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return outbuffer[index] & 0x7FFFFFF; }

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32 *) binary)[0] & 0xF; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32 *) binary)[0] & 0xFF; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32 *) binary)[0] & 0xFFF; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32 *) binary)[0] & 0xFFFF; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32 *) binary)[0] & 0xFFFFF; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_32 *) binary)[0] & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_32 *) binary)[0] & 0x7FFFFFF; }

static int salt_hash(void *salt){
	return *((ARCH_WORD_32 *) salt) & (SALT_HASH_SIZE - 1);
}

static void set_key(char *key, int index){
	memcpy(&(saved_plain[index*PLAINTEXT_LENGTH]), key, PLAINTEXT_LENGTH);
}

static void set_salt(void *salt){
	memcpy(saved_salt, salt, SALT_SIZE);

	/* Used to be in crypt_all() - bad for single salt */
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mysalt, CL_FALSE, 0, SALT_SIZE,
	    saved_salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer mysalt");
}

static char *get_key(int index) {
	return &(saved_plain[index*PLAINTEXT_LENGTH]);
}

static int cmp_all(void *binary, int index) {
	unsigned int i = 0;
	unsigned int b = ((unsigned int *) binary)[0];
	for (; i < index; i++) {
		if (b == outbuffer[i])
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index){
	unsigned int *t = (unsigned int *) binary;

	if (t[0] == outbuffer[index])
		return 1;
	return 0;
}

static int cmp_exact(char *source, int count){
	unsigned int *t = (unsigned int *) binary(source);

	if (!have_full_hashes){
		clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE,
			    sizeof(cl_uint) * (global_work_size),
			    sizeof(cl_uint) * 4 * global_work_size, outbuffer2, 0,
			    NULL, NULL);
		have_full_hashes = 1;
	}
	if (t[1]!=outbuffer2[count])
		return 0;
	if (t[2]!=outbuffer2[1*global_work_size+count])
		return 0;
	if (t[3]!=outbuffer2[2*global_work_size+count])
		return 0;
	if (t[4]!=outbuffer2[3*global_work_size+count])
		return 0;
	return 1;
}



static void crypt_all(int count)
{
	cl_int code;

	code = clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
	    (PLAINTEXT_LENGTH) * global_work_size, saved_plain, 0, NULL, NULL);
	HANDLE_CLERROR(code, "failed in clEnqueueWriteBuffer saved_plain");

	code = clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL,
	    &global_work_size, &local_work_size, 0, NULL, profilingEvent);
	HANDLE_CLERROR(code, "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish error");
	// read back partial hashes
	code = clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0,
	    sizeof(cl_uint) * global_work_size, outbuffer, 0, NULL, NULL);
	HANDLE_CLERROR(code, "failed in clEnqueueReadBuffer -reading partial hashes");
	have_full_hashes = 0;
}

struct fmt_main fmt_opencl_NSLDAPS = {
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
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_ssha_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
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
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
