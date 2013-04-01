/*
 * This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright (c) 2012 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "path.h"
#include "config.h"

#include "common-opencl.h"
#define uint32_t unsigned int
#define uint8_t unsigned char

#define KEYS_PER_CRYPT		(64*1024)
#define PLAINTEXT_LENGTH	15 /* max. due to optimizations */

#define FORMAT_LABEL		"md5crypt-opencl"
#define FORMAT_NAME		"md5crypt"
#define KERNEL_NAME		"cryptmd5"

#define ALGORITHM_NAME		"OpenCL"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define BINARY_SIZE		16
#define SALT_SIZE		(8+1)	/** salt + prefix id **/

#define MIN_KEYS_PER_CRYPT	1 /* These will change in init() */
#define MAX_KEYS_PER_CRYPT	1

#define LWS_CONFIG		"md5crypt_LWS"
#define GWS_CONFIG		"md5crypt_GWS"
#define DUR_CONFIG		"md5crypt_MaxDuration"

typedef struct {
	unsigned int saltlen;
	char salt[8];
	char prefix;		/** 'a' when $apr1$ or '1' when $1$ **/
} crypt_md5_salt;

typedef struct {
	unsigned int length;
	unsigned char v[PLAINTEXT_LENGTH];
} crypt_md5_password;

typedef struct {
	uint32_t v[4];		/** 128 bits **/
} crypt_md5_hash;


static crypt_md5_password *inbuffer;		/** plaintext ciphertexts **/
static crypt_md5_hash *outbuffer;		/** calculated hashes **/
static crypt_md5_salt host_salt;		/** salt **/

static const char md5_salt_prefix[] = "$1$";
static const char apr1_salt_prefix[] = "$apr1$";

//OpenCL variables:
static cl_mem mem_in, mem_out, pinned_in, pinned_out, mem_salt;
static size_t insize, outsize;
static size_t saltsize = sizeof(crypt_md5_salt);
static int new_keys;

static struct fmt_tests tests[] = {
#ifdef DEBUG
	{"$1$Btiy90iG$bGn4vzF3g1rIVGZ5odGIp/", "qwerty"},
	{"$1$salt$c813W/s478KCzR0NnHx7j0", "qwerty"},
	{"$1$salt$8LO.EVfsTf.HATV1Bd0ZP/", "john"},
	{"$1$salt$TelRRxWBCxlpXmgAeB82R/", "openwall"},
	{"$1$salt$l9PzDiECW83MOIMFTRL4Y1", "summerofcode"},
	{"$1$salt$wZ2yVsplRoPoD7IfTvRsa0", "IamMD5"},
	{"$1$saltstri$9S4.PyBpUZBRZw6ZsmFQE/", "john"},
	{"$1$saltstring$YmP55hH3qcHg2cCffyxrq/", "ala"},
	{"$1$salt1234$mdji1uBBCWZ5m2mIWKvLW.", "a"},
	{"$1$salt1234$/JUvhIWHD.csWSCPvr7po0", "ab"},
	{"$1$salt1234$GrxHg1bgkN2HB5CRCdrmF.", "abc"},
	{"$1$salt1234$iZuyvTkrucWx8kVn5BN4M/", "abcd"},
	{"$1$salt1234$wn0RbuDtbJlD1Q.X7.9wG/", "abcde"},
	{"$1$salt1234$lzB83HS4FjzbcD4yMcjl01", "abcdef"},
	{"$1$salt1234$bklJHN73KS04Kh6j6qPnr.", "abcdefg"},
#endif
	{"$1$salt1234$u4RMKGXG2b/Ud2rFmhqi70", "abcdefgh"},	//saltlen=8,passlen=8
#ifdef DEBUG
	{"$1$salt1234$QjP48HUerU7aUYc/aJnre1", "abcdefghi"},
	{"$1$salt1234$9jmu9ldi9vNw.XDO3TahR.", "abcdefghij"},
	{"$1$salt1234$d3.LnlDWfkTIej5Ef1sCU/", "abcdefghijk"},
	{"$1$salt1234$pDV0xEgZR14EpQMmhZ6Hg0", "abcdefghijkl"},
	{"$1$salt1234$WumpbolX2y45Dlv0.A1Mj1", "abcdefghijklm"},
	{"$1$salt1234$FXBreA27b7N7diemBGn5I1", "abcdefghijklmn"},
	{"$1$salt1234$8d5IPIbTd7J/WNEG4b4cl.", "abcdefghijklmno"},

	//tests from korelogic2010 contest
	{"$1$bn6UVs3/$S6CQRLhmenR8OmVp3Jm5p0", "sparky"},
	{"$1$qRiPuG5Z$pLLczmBnwEOD75Vb7YZLg1", "walter"},
	{"$1$E.qsK.Hy$.eX0H6arTHaGOIFkf6o.a.", "heaven"},
	{"$1$Hul2mrWs$.NGCgz3fBGDyG7RMGJAdM0", "bananas"},
	{"$1$1l88Y.UV$swt2d0SPMrBPkdAD8RwSj0", "horses"},
	{"$1$DiHrL6V7$fCVDD1GEAKB.BjAgJL1ZX0", "maddie"},
	{"$1$7fpfV7kr$7LgF64DGPtHPktVKdLM490", "bitch1"},
	{"$1$VKjk2PJc$5wbrtc9oa8kdEO/ocyi06/", "crystal"},
	{"$1$S66DxkFm$kG.QfeHNLifEDTDmf4pzJ/", "claudia"},
	{"$1$T2JMeEYj$Y.wDzFvyb9nlH1EiSCI3M/", "august"},

	//tests from MD5_fmt.c
	{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"$apr1$Q6ZYh...$RV6ft2bZ8j.NGrxLYaJt9.", "test"},
#endif
	{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
#ifdef DEBUG
	{"$1$$qRPK7m23GJusamGpoGLby/", ""},
	{"$apr1$a2Jqm...$grFrwEgiQleDr0zR4Jx1b.", "15 chars is max"},
	{"$1$$AuJCr07mI7DSew03TmBIv/", "no salt"},
	{"$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30", "invalid salt"},
	{"$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	{"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{"$apr1$rBXqc...$NlXxN9myBOk95T0AyLAsJ0", "john"},
	{"$apr1$Grpld/..$qp5GyjwM2dnA5Cdej9b411", "the"},
	{"$apr1$GBx.D/..$yfVeeYFCIiEXInfRhBRpy/", "ripper"},
#endif
	{NULL}
};

static void create_clobj(int gws, struct fmt_main *self)
{
	global_work_size = gws;
	self->params.min_keys_per_crypt = self->params.max_keys_per_crypt = gws;
	insize = sizeof(crypt_md5_password) * gws;
	outsize = sizeof(crypt_md5_hash) * gws;

	///Allocate memory on the GPU
	mem_salt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, saltsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for salt");

	pinned_in = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, insize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating pinned memory for passwords");
	mem_in = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, insize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating GPU memory for passwords");
	inbuffer = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, insize, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping password buffer");

	pinned_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating pinned memory for hashes");
	mem_out = clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating GPU memory for hashes");
	outbuffer = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_out, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, outsize, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping results buffer");

	///Assign kernel parameters
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");

	memset(inbuffer, '\0', sizeof(crypt_md5_password) * gws);
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_in, inbuffer, 0, NULL, NULL), "Error Unmapping inbuffer");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_out, outbuffer, 0, NULL, NULL), "Error Unmapping outbuffer");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_in), "Release pinned_in");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem_in");
	HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
	HANDLE_CLERROR(clReleaseMemObject(pinned_out), "Release pinned_out");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");
}

/*
static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
	HANDLE_CLERROR(clReleaseContext(context[ocl_gpu_id]), "Release Context");
}
*/

static int salt_hash(void *salt)
{
	unsigned int i, h, retval;

	retval = 0;
	for (i = 0; i <= 6; i += 2) {
		h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
		h ^= ((unsigned char *)salt)[i + 1];
		h <<= 6;
		h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i + 1])];
		h ^= ((unsigned char *)salt)[i];
		retval += h;
	}

	retval ^= retval >> SALT_HASH_LOG;
	retval &= SALT_HASH_SIZE - 1;

	return retval;
}

static void set_key(char *key, int index)
{
	uint32_t len = strlen(key);
	inbuffer[index].length = len;
	memcpy((char *) inbuffer[index].v, key, len);
        new_keys = 1;
}

static void set_salt(void *salt)
{
	uint8_t *s = salt;
	uint8_t len;
	for (len = 0; len < 8 && s[len]; len++);
	host_salt.saltlen = len;
	memcpy(host_salt.salt, s, host_salt.saltlen);
	host_salt.prefix = s[8];

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_salt, CL_FALSE, 0, saltsize, &host_salt, 0, NULL, NULL), "Copy memsalt");
}

static void *salt(char *ciphertext)
{
	static uint8_t ret[SALT_SIZE];
	uint8_t i, *pos = (uint8_t *) ciphertext, *dest = ret, *end;
	memset(ret, 0, SALT_SIZE);

	if (strncmp(ciphertext, md5_salt_prefix, strlen(md5_salt_prefix)) == 0) {
		pos += strlen(md5_salt_prefix);
		ret[8] = '1';
	}
	if (strncmp(ciphertext, apr1_salt_prefix,
		strlen(apr1_salt_prefix)) == 0) {
		pos += strlen(apr1_salt_prefix);
		ret[8] = 'a';
	}
	end = pos;
	for (i = 0; i < 8 && *end != '$'; i++, end++);
	while (pos != end)
		*dest++ = *pos++;
	return (void *) ret;
}

static cl_ulong gws_test(int gws, int do_benchmark, struct fmt_main *self)
{
	cl_ulong startTime, endTime;
	cl_command_queue queue_prof;
	cl_event Event[4];
	cl_int ret_code;
	int i;

	create_clobj(gws, self);
	queue_prof = clCreateCommandQueue(context[ocl_gpu_id], devices[ocl_gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	for (i = 0; i < gws; i++)
		set_key(tests[0].plaintext, i);
	set_salt(salt(tests[0].ciphertext));

	///Copy data to GPU memory
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_in, CL_FALSE, 0, insize, inbuffer, 0, NULL, &Event[0]), "Copy memin");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue_prof, mem_salt, CL_FALSE, 0, saltsize, &host_salt, 0, NULL, &Event[1]), "Copy memsalt");

	///Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue_prof, crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, &Event[2]), "Set ND range");
	if (clEnqueueReadBuffer(queue_prof, mem_out, CL_TRUE, 0, outsize, outbuffer, 0, NULL, &Event[3]) != CL_SUCCESS) {
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[1], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "input xfer: %llu us, ", (endTime-startTime)/1000ULL);

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[2], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "kernel %.2f ms, ", (float)((endTime - startTime)/1000000.));

	/* 200 ms duration limit for GCN to avoid ASIC hangs */
	if (amd_gcn(device_info[ocl_gpu_id]) && endTime - startTime > 200000000) {
		if (do_benchmark)
			fprintf(stderr, "- exceeds 200 ms\n");
		clReleaseCommandQueue(queue_prof);
		release_clobj();
		return 0;
	}

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");
	if (do_benchmark)
		fprintf(stderr, "results xfer: %llu us\n", (endTime-startTime)/1000ULL);

	HANDLE_CLERROR(clGetEventProfilingInfo(Event[0], CL_PROFILING_COMMAND_SUBMIT, sizeof(cl_ulong), &startTime, NULL), "Failed to get profiling info");
	HANDLE_CLERROR(clGetEventProfilingInfo(Event[3], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &endTime, NULL), "Failed to get profiling info");

	clReleaseCommandQueue(queue_prof);
	release_clobj();

	return (endTime - startTime);
}

static void find_best_gws(int do_benchmark, struct fmt_main *self)
{
	int num;
	cl_ulong run_time, min_time = CL_ULONG_MAX;
	unsigned int MD5speed, bestMD5speed = 0;
	int optimal_gws = local_work_size;
	const int md5perkey = 1002;
	unsigned long long int MaxRunTime = cpu(device_info[ocl_gpu_id]) ? 1000000000ULL : 5000000000ULL;
	char *tmp_value;

	if ((tmp_value = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, DUR_CONFIG)))
		MaxRunTime = atoi(tmp_value) * 1000000000ULL;

	if (do_benchmark) {
		fprintf(stderr, "Calculating best keys per crypt (GWS) for LWS=%zd and max. %llu s duration.\n\n", local_work_size, MaxRunTime / 1000000000UL);
		fprintf(stderr, "Raw GPU speed figures including buffer transfers:\n");
	}

	for (num = local_work_size; num; num *= 2) {
		if (!do_benchmark)
			advance_cursor();
		if (!(run_time = gws_test(num, do_benchmark, self)))
			break;

		MD5speed = md5perkey * (1000000000UL * num / run_time);

		if (run_time < min_time)
			min_time = run_time;

		if (do_benchmark)
			fprintf(stderr, "gws %6d%8llu c/s%14u md5/s%8.3f sec per crypt_all()", num, (1000000000ULL * num / run_time), MD5speed, (float)run_time / 1000000000.);

		if (((float)run_time / (float)min_time) < ((float)MD5speed / (float)bestMD5speed)) {
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
	if (do_benchmark) {
		fprintf(stderr, "Optimal global worksize %d\n", optimal_gws);
		fprintf(stderr, "(to avoid this test on next run, put \""
		        GWS_CONFIG " = %d\" in john.conf, section ["
		        SECTION_OPTIONS SUBSECTION_OPENCL "])\n", optimal_gws);
	}
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	ret[inbuffer[index].length] = '\0';
	return ret;
}

static void init(struct fmt_main *self)
{
	char *temp;
	cl_ulong maxsize;

	local_work_size = global_work_size = 0;
	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, LWS_CONFIG)))
		local_work_size = atoi(temp);

	if ((temp = cfg_get_param(SECTION_OPTIONS, SUBSECTION_OPENCL, GWS_CONFIG)))
		global_work_size = atoi(temp);

	if ((temp = getenv("LWS")))
		local_work_size = atoi(temp);

	if ((temp = getenv("GWS")))
		global_work_size = atoi(temp);

	opencl_init_opt("$JOHN/kernels/cryptmd5_kernel.cl", ocl_gpu_id, platform_id, NULL);

	///Create Kernel
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], KERNEL_NAME, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating kernel");

	/* Note: we ask for the kernels' max sizes, not the device's! */
	HANDLE_CLERROR(clGetKernelWorkGroupInfo(crypt_kernel, devices[ocl_gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(maxsize), &maxsize, NULL), "Query max work group size");

	if (local_work_size > maxsize)
		local_work_size = maxsize;

	if (!local_work_size) {
		int temp = global_work_size;

		local_work_size = maxsize;
		global_work_size = global_work_size ? global_work_size : KEYS_PER_CRYPT;
		create_clobj(global_work_size, self);
		opencl_find_best_workgroup_limit(self, maxsize);
		release_clobj();
		global_work_size = temp;
	}

	if (!global_work_size)
		find_best_gws(getenv("GWS") == NULL ? 0 : 1, self);

	if (global_work_size < local_work_size)
		global_work_size = local_work_size;

	fprintf(stderr, "Local worksize (LWS) %d, Global worksize (GWS) %d\n", (int)local_work_size, (int)global_work_size);
	create_clobj(global_work_size, self);
	//atexit(done);

	self->params.min_keys_per_crypt = local_work_size;
	self->params.max_keys_per_crypt = global_work_size;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	uint8_t i, len = strlen(ciphertext), prefix = 0;
	char *p;
	if (strncmp(ciphertext, md5_salt_prefix, strlen(md5_salt_prefix)) == 0)
		prefix |= 1;
	if (strncmp(ciphertext, apr1_salt_prefix,
		strlen(apr1_salt_prefix)) == 0)
		prefix |= 2;
	if (prefix == 0)
		return 0;

	p = strrchr(ciphertext, '$');
	for (i = p - ciphertext + 1; i < len; i++) {
		uint8_t z = ARCH_INDEX(ciphertext[i]);
		if (ARCH_INDEX(atoi64[z]) == 0x7f)
			return 0;
	}
	if (len - (p - ciphertext + 1) != 22)
		return 0;
	return 1;
};

static int findb64(char c)
{
	int ret = ARCH_INDEX(atoi64[(uint8_t) c]);
	return ret != 0x7f ? ret : 0;
}

static void to_binary(char *crypt, char *alt)
{

#define _24bit_from_b64(I,B2,B1,B0) \
  {\
      uint8_t c1,c2,c3,c4,b0,b1,b2;\
      uint32_t w;\
      c1=findb64(crypt[I+0]);\
      c2=findb64(crypt[I+1]);\
      c3=findb64(crypt[I+2]);\
      c4=findb64(crypt[I+3]);\
      w=c4<<18|c3<<12|c2<<6|c1;\
      b2=w&0xff;w>>=8;\
      b1=w&0xff;w>>=8;\
      b0=w&0xff;w>>=8;\
      alt[B2]=b0;\
      alt[B1]=b1;\
      alt[B0]=b2;\
  }
	uint32_t w;
	_24bit_from_b64(0, 0, 6, 12);
	_24bit_from_b64(4, 1, 7, 13);
	_24bit_from_b64(8, 2, 8, 14);
	_24bit_from_b64(12, 3, 9, 15);
	_24bit_from_b64(16, 4, 10, 5);
	w = findb64(crypt[21]) << 6 | findb64(crypt[20]) << 0;
	alt[11] = (w & 0xff);
}

static void *binary(char *ciphertext)
{
	static char b[BINARY_SIZE];
	char *p = strrchr(ciphertext, '$') + 1;
	memset(b, 0, BINARY_SIZE);
	to_binary(p, b);
	return (void *) b;
}

static int binary_hash_0(void *binary)
{
	return (((ARCH_WORD_32 *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0x7ffffff;
}

static void crypt_all(int count)
{
	size_t in_size, out_size;

	global_work_size = (((count + local_work_size - 1) / local_work_size) * local_work_size);
	in_size = sizeof(crypt_md5_password) * global_work_size;
	out_size = sizeof(crypt_md5_hash) * global_work_size;

	///Copy data to GPU memory
	if (new_keys)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0, in_size, inbuffer, 0, NULL, NULL), "Copy memin");

	///Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1, NULL, &global_work_size, &local_work_size, 0, NULL, profilingEvent), "Set ND range");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0, out_size, outbuffer, 0, NULL, NULL), "Copy data back");

	///Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish error");

	new_keys = 0;
}

static int get_hash_0(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xf;
}

static int get_hash_1(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xff;
}

static int get_hash_2(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xfff;
}

static int get_hash_3(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xffff;
}

static int get_hash_4(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	return ((ARCH_WORD_32 *) outbuffer[index].v)[0] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i, b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	uint32_t i, *t = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (t[i] != outbuffer[index].v[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_opencl_cryptMD5 = {
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
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
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
