/*
 * This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright (c) 2012 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */
#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_cryptMD5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_cryptMD5);
#else

#include <string.h>
#include <assert.h>

#include "arch.h"
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "path.h"
#include "config.h"
#include "common-opencl.h"
#include "options.h"
#include "memdbg.h"

#define uint32_t unsigned int
#define uint8_t unsigned char

#define PLAINTEXT_LENGTH	15 /* max. due to optimizations */

#define FORMAT_LABEL		"md5crypt-opencl"
#define FORMAT_NAME		"crypt(3) $1$"
#define KERNEL_NAME		"cryptmd5"

#define ALGORITHM_NAME		"MD5 OpenCL"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define BINARY_SIZE		16
#define BINARY_ALIGN		4
#define SALT_SIZE		(8+1)	/** salt + prefix id **/
#define SALT_ALIGN		1

#define MIN_KEYS_PER_CRYPT	1 /* These will change in init() */
#define MAX_KEYS_PER_CRYPT	1

#define OCL_CONFIG		"md5crypt"
#define STEP                    0
#define SEED                    1024
#define ROUNDS_DEFAULT          1000

static const char * warn[] = {
        "pass xfer: "  ,  ", crypt: "    ,  ", result xfer: "
};

//This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static size_t get_task_max_size()
{
	return 0;
}

static size_t get_default_workgroup()
{
	if (cpu(device_info[gpu_id]))
		return get_platform_vendor_id(platform_id) == DEV_INTEL ?
			8 : 1;
	else
		return 64;
}

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
static int new_keys;

#define insize (sizeof(crypt_md5_password) * global_work_size)
#define outsize (sizeof(crypt_md5_hash) * global_work_size)
#define saltsize (sizeof(crypt_md5_salt))

static struct fmt_tests tests[] = {
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
	{"$1$salt1234$u4RMKGXG2b/Ud2rFmhqi70", "abcdefgh"},	//saltlen=8,passlen=8
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
	{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	{"$1$$qRPK7m23GJusamGpoGLby/", ""},
	{"$apr1$a2Jqm...$grFrwEgiQleDr0zR4Jx1b.", "15 chars is max"},
	{"$1$$AuJCr07mI7DSew03TmBIv/", "no salt"},
	{"$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30", "invalid salt"},
	{"$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	{"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{"$apr1$rBXqc...$NlXxN9myBOk95T0AyLAsJ0", "john"},
	{"$apr1$Grpld/..$qp5GyjwM2dnA5Cdej9b411", "the"},
	{"$apr1$GBx.D/..$yfVeeYFCIiEXInfRhBRpy/", "ripper"},
	{NULL}
};

static void create_clobj(size_t gws, struct fmt_main *self)
{
	size_t in_size = (sizeof(crypt_md5_password) * gws);
	size_t out_size = (sizeof(crypt_md5_hash) * gws);

	///Allocate memory on the GPU
	mem_salt = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating memory for salt");

	pinned_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, in_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating pinned memory for passwords");
	mem_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, in_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating GPU memory for passwords");
	inbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_in, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, in_size, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping password buffer");

	pinned_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, out_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating pinned memory for hashes");
	mem_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, out_size, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while allocating GPU memory for hashes");
	outbuffer = clEnqueueMapBuffer(queue[gpu_id], pinned_out, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, out_size, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping results buffer");

	///Assign kernel parameters
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in), &mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out), &mem_out), "Error while setting mem_out kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt), &mem_salt), "Error while setting mem_salt kernel argument");

	memset(inbuffer, '\0', sizeof(crypt_md5_password) * gws);
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_in, inbuffer, 0, NULL, NULL), "Error Unmapping inbuffer");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_out, outbuffer, 0, NULL, NULL), "Error Unmapping outbuffer");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mappings");

	HANDLE_CLERROR(clReleaseMemObject(pinned_in), "Release pinned_in");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem_in");
	HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem_salt");
	HANDLE_CLERROR(clReleaseMemObject(pinned_out), "Release pinned_out");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem_out");
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");
}

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

	//Author decision. I just keep this way.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt, CL_FALSE, 0, saltsize, &host_salt, 0, NULL, NULL), "Copy memsalt");
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
	return (void *)ret;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	ret[inbuffer[index].length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt);

static void init(struct fmt_main *self)
{
	opencl_init("$JOHN/kernels/cryptmd5_kernel.cl", gpu_id, NULL);

	///Create Kernel
	crypt_kernel = clCreateKernel(program[gpu_id], KERNEL_NAME, &ret_code);
	HANDLE_CLERROR(ret_code, "Error while creating kernel");

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
		warn, 1, self, create_clobj, release_clobj,
		sizeof(crypt_md5_password), 0);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1000, 0, 500);
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	global_work_size = (((count + local_work_size - 1) / local_work_size) * local_work_size);

	///Copy data to GPU memory
	if (new_keys)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE,
			0, insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
			"Copy memin");

	///Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL, multi_profilingEvent[1]),
		"Set ND range");
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_FALSE,
		0, outsize, outbuffer, 0, NULL, multi_profilingEvent[2]),
		"Copy data back");

	///Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "clFinish error");

	new_keys = 0;
	return count;
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
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
