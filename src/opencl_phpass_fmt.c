/*
* This software is Copyright (c) 2011-2012 Lukas Odzioba <ukasz at openwall.net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include <assert.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"

#include "common-opencl.h"

#define uint32_t                unsigned int
#define uint8_t                 unsigned char

#define FORMAT_LABEL            "phpass-opencl"
#define FORMAT_NAME             "phpass MD5"

#define ALGORITHM_NAME          "OpenCL"

#define BENCHMARK_COMMENT	" ($P$9 lengths 0 to 15)"
#define BENCHMARK_LENGTH        -1

#define PLAINTEXT_LENGTH        15
#define CIPHERTEXT_LENGTH       34	/// header = 3 | loopcnt = 1 | salt = 8 | ciphertext = 22
#define BINARY_SIZE             16
#define ACTUAL_SALT_SIZE        8
#define SALT_SIZE               (ACTUAL_SALT_SIZE + 1) // 1 byte for iterations

//#define KEYS_PER_CRYPT          1024*8*40
#define KEYS_PER_CRYPT          (2048 * 96)
#define MIN_KEYS_PER_CRYPT      KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT      KEYS_PER_CRYPT

//#define _PHPASS_DEBUG

typedef struct {
	unsigned char v[PLAINTEXT_LENGTH];
	unsigned char length;
} phpass_password;

typedef struct {
	uint32_t v[4];		///128bits for hash
} phpass_hash;

static phpass_password *inbuffer;			/** plaintext ciphertexts **/
static phpass_hash *outbuffer;			/** calculated hashes **/
static const char phpassP_prefix[] = "$P$";
static const char phpassH_prefix[] = "$H$";
static char currentsalt[SALT_SIZE];

extern void mem_init(unsigned char *, uint32_t *, char *, char *, int);
extern void mem_clear(void);
extern void gpu_phpass(void);

// OpenCL variables:
static cl_mem mem_in, mem_out, mem_setting;
static size_t insize = sizeof(phpass_password) * KEYS_PER_CRYPT;
static size_t outsize = sizeof(phpass_hash) * KEYS_PER_CRYPT;
static size_t settingsize = sizeof(uint8_t) * ACTUAL_SALT_SIZE + 4;
//static size_t global_work_size = KEYS_PER_CRYPT/8;

static struct fmt_tests tests[] = {
	{"$P$90000000000tbNYOc9TwXvLEI62rPt1", ""},
	{"$P$9saltstriAcRMGl.91RgbAD6WSq64z.", "a"},
	{"$P$9saltstriMljTzvdluiefEfDeGGQEl/", "ab"},
//	{"$P$9saltstrikCftjZCE7EY2Kg/pjbl8S.", "abc"},
	{"$P$900000000jPBDh/JWJIyrF0.DmP7kT.", "ala"},
//	{"$P$9saltstriV/GXRIRi9UVeMLMph9BxF0", "abcd"},
//	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
//	{"$P$900000001ahWiA6cMRZxkgUxj4x/In0", "john"},
//	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	{"$P$9sadli2.wzQIuzsR2nYVhUSlHNKgG/0", "john"},
	{"$P$9saltstri3JPgLni16rBZtI03oeqT.0", "abcde"},
//	{"$P$9saltstri0D3A6JyITCuY72ZoXdejV.", "abcdef"},
	{"$P$900000000zgzuX4Dc2091D8kak8RdR0", "h3ll00"},
	{"$P$9saltstriXeNc.xV8N.K9cTs/XEn13.", "abcdefg"},
//	{"$P$9saltstrinwvfzVRP3u1gxG2gTLWqv.", "abcdefgh"},
	{"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"},
	{"$H$9saltstriSUQTD.yC2WigjF8RU0Q.Z.", "abcdefghi"},
//	{"$P$9saltstriWPpGLG.jwJkwGRwdKNEsg.", "abcdefghij"},
//	{"$P$900000000qZTL5A0XQUX9hq0t8SoKE0", "1234567890"},
	{"$P$900112200B9LMtPy2FSq910c1a6BrH0", "1234567890"},
//	{"$P$9saltstrizjDEWUMXTlQHQ3/jhpR4C.", "abcdefghijk"},
	{"$P$9RjH.g0cuFtd6TnI/A5MRR90TXPc43/", "password__1"},
	{"$P$9saltstriGLUwnE6bl91BPJP6sxyka.", "abcdefghijkl"},
	{"$P$9saltstriq7s97e2m7dXnTEx2mtPzx.", "abcdefghijklm"},
	{"$P$9saltstriTWMzWKsEeiE7CKOVVU.rS0", "abcdefghijklmn"},
	{"$P$9saltstriXt7EDPKtkyRVOqcqEW5UU.", "abcdefghijklmno"},
#if 0
	{"$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00", "test1"},
	{"$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1", "123456"},
	{"$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1", "123456"},
//	{"$P$912345678LIjjb6PhecupozNBmDndU0", "thisisalongertestPW"},
	{"$H$9A5she.OeEiU583vYsRXZ5m2XIpI68/", "123456"},
	{"$P$917UOZtDi6ksoFt.y2wUYvgUI6ZXIK/", "test1"},
//	{"$P$91234567AQwVI09JXzrV1hEC6MSQ8I0", "thisisalongertest"},
	{"$P$9234560A8hN6sXs5ir0NfozijdqT6f0", "test2"},
	{"$P$9234560A86ySwM77n2VA/Ey35fwkfP0", "test3"},
	{"$P$9234560A8RZBZDBzO5ygETHXeUZX5b1", "test4"},
	{"$P$612345678si5M0DDyPpmRCmcltU/YW/", "JohnRipper"}, // 256
	{"$P$6T4Krr44HLrUqGkL8Lu67lzZVbvHLC1", "test12345"}, // 256
	{"$H$712345678WhEyvy1YWzT4647jzeOmo0", "JohnRipper"}, // 512 (phpBB w/older PHP version)
	{"$P$8DkV/nqeaQNTdp4NvWjCkgN48AK69X.", "test12345"}, // 1024
	{"$P$B12345678L6Lpt4BxNotVIMILOa9u81", "JohnRipper"}, // 8192 (WordPress)
//	{"$P$91234567xogA.H64Lkk8Cx8vlWBVzH0", "thisisalongertst"},
#endif
	{NULL}
};

static void release_all(void)
{
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release Kernel");
	HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(mem_setting), "Release mem setting");
	HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");
	HANDLE_CLERROR(clReleaseCommandQueue(queue[ocl_gpu_id]), "Release Queue");
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
}

static void set_key(char *key, int index)
{
#ifdef _PHPASS_DEBUG
	printf("set_key(%d) = %s\n", index, key);
#endif
	int length = strlen(key);
	memset(inbuffer[index].v, 0, 15);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, inbuffer[index].length);
	ret[inbuffer[index].length] = 0;
	return ret;
}

static void init(struct fmt_main *pFmt)
{
	cl_int cl_error;
	global_work_size = KEYS_PER_CRYPT / 8;
	atexit(release_all);
	opencl_init("$JOHN/phpass_kernel.cl", ocl_gpu_id, platform_id);

	/// Alocate memory
	inbuffer =
	    (phpass_password *) calloc(MAX_KEYS_PER_CRYPT,
	    sizeof(phpass_password));
	assert(inbuffer != NULL);
	outbuffer =
	    (phpass_hash *) calloc(MAX_KEYS_PER_CRYPT, sizeof(phpass_hash));
	assert(inbuffer != NULL);

	mem_in =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, insize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem in");
	mem_setting =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY, settingsize,
	    NULL, &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem setting");
	mem_out =
	    clCreateBuffer(context[ocl_gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
	    &cl_error);
	HANDLE_CLERROR(cl_error, "Error alocating mem out");

	/// Setup kernel parameters
	crypt_kernel = clCreateKernel(program[ocl_gpu_id], "phpass", &cl_error);
	HANDLE_CLERROR(cl_error, "Error creating kernel");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_out),
		&mem_out), "Error while setting mem_out");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_setting),
		&mem_setting), "Error while setting mem_setting");

//      opencl_find_best_workgroup(pFmt);

	local_work_size = 64;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	uint32_t i, j, count_log2, found;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	found = 0;
	if (strncmp(ciphertext, phpassP_prefix, 3) == 0)
		found = 1;
	if (strncmp(ciphertext, phpassH_prefix, 3) == 0)
		found = 1;
	if (!found)
		return 0;

	for (i = 3; i < CIPHERTEXT_LENGTH; i++) {
		found = 0;
		for (j = 0; j < 64; j++)
			if (itoa64[j] == ARCH_INDEX(ciphertext[i])) {
				found = 1;
				break;
			}
		if (!found)
			return 0;
	}
	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
};

//code from historical JtR phpass patch
static void *binary(char *ciphertext)
{
	static unsigned char b[BINARY_SIZE];
	int i, bidx = 0;
	unsigned sixbits;
	char *pos = &ciphertext[3 + 1 + 8];
	memset(b, 0, BINARY_SIZE);

	for (i = 0; i < 5; i++) {
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 6);
		sixbits >>= 2;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 4);
		sixbits >>= 4;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] |= (sixbits << 6);
	return (void *) b;
}

static void *salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];
	memcpy(salt, &ciphertext[4], 8);
	salt[8] = ciphertext[3];
	return salt;
}


static void set_salt(void *salt)
{
	memcpy(currentsalt, salt, SALT_SIZE);
}

static void crypt_all(int count)
{
#ifdef _PHPASS_DEBUG
	printf("crypt_all(%d)\n", count);
#endif
	///Prepare setting format: salt+prefix+count_log2
	char setting[SALT_SIZE + 3] = { 0 };
	strcpy(setting, currentsalt);
	strcpy(setting + ACTUAL_SALT_SIZE, phpassP_prefix);
	setting[ACTUAL_SALT_SIZE + 3] = atoi64[ARCH_INDEX(currentsalt[8])];
	/// Copy data to gpu
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_in, CL_FALSE, 0,
		insize, inbuffer, 0, NULL, NULL), "Copy data to gpu");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], mem_setting,
		CL_FALSE, 0, settingsize, setting, 0, NULL, NULL),
	    "Copy setting to gpu");

	/// Run kernel
	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[ocl_gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, &local_work_size, 0, NULL,
		profilingEvent), "Run kernel");
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");

	/// Read the result back
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], mem_out, CL_FALSE, 0,
		outsize, outbuffer, 0, NULL, NULL), "Copy result back");

	/// Await completion of all the above
	HANDLE_CLERROR(clFinish(queue[ocl_gpu_id]), "clFinish");
}

static int binary_hash_0(void *binary)
{
#ifdef _PHPASS_DEBUG
	printf("binary_hash_0 ");
	int i;
	uint32_t *b = binary;
	for (i = 0; i < 4; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
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

static int get_hash_0(int index)
{
#ifdef _PHPASS_DEBUG
	printf("get_hash_0:   ");
	int i;
	for (i = 0; i < 4; i++)
		printf("%08x ", outbuffer[index].v[i]);
	puts("");
#endif
	return outbuffer[index].v[0] & 0xf;
}

static int get_hash_1(int index)
{
	return outbuffer[index].v[0] & 0xff;
}

static int get_hash_2(int index)
{
	return outbuffer[index].v[0] & 0xfff;
}

static int get_hash_3(int index)
{
	return outbuffer[index].v[0] & 0xffff;
}

static int get_hash_4(int index)
{
	return outbuffer[index].v[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	return outbuffer[index].v[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	return outbuffer[index].v[0] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{

	uint32_t b = ((uint32_t *) binary)[0];
	uint32_t i;
	for (i = 0; i < count; i++) {
		if (b == outbuffer[i].v[0]) {
#ifdef _PHPASS_DEBUG
			puts("cmp_all = 1");
#endif
			return 1;
		}
	}
#ifdef _PHPASS_DEBUG
	puts("cmp_all = 0");
#endif				/* _PHPASS_DEBUG */
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (t[i] != outbuffer[index].v[i]) {
#ifdef _PHPASS_DEBUG
			puts("cmp_one = 0");
#endif
			return 0;
		}
#ifdef _PHPASS_DEBUG
	puts("cmp_one = 1");
#endif
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_opencl_phpass = {
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
		fmt_default_salt_hash,
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
