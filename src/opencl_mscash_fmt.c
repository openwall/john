/*
 * This software is Copyright (c) 2013 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * This is a direct port of mscash-cuda format by Lukas Odzioba
 * <lukas dot odzioba at gmail dot com>
 */
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "opencl_mscash.h"
#include "common-opencl.h"
#include "unicode.h"

#define FORMAT_LABEL		"mscash-opencl"
#define FORMAT_NAME		"M$ Cache Hash"
#define ALGORITHM_NAME		"MD4 opencl (inefficient, development use only)"
#define MAX_CIPHERTEXT_LENGTH	(2 + 19*3 + 1 + 32)
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

static mscash_password *inbuffer;
static mscash_hash *outbuffer;
static mscash_salt currentsalt;

cl_mem buffer_out, buffer_keys, buffer_salt;

static struct fmt_tests tests[] = {
	{"M$test2#ab60bdb4493822b175486810ac2abe63", "test2"},
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1"},
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1"},
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1"},
	{"176a4c2bd45ac73687676c2f09045353", "", {"root"}},	// nullstring password
	{"M$test3#14dd041848e12fc48c0aa7a416a4a00c", "test3"},
	{"M$test4#b945d24866af4b01a6d89b9d932a153c", "test4"},

	{"64cd29e36a8431a2b111378564a10631", "test1", {"TEST1"}},	// salt is lowercased before hashing
	{"290efa10307e36a79b3eebf2a6b29455", "okolada", {"nineteen_characters"}},	// max salt length
	{"ab60bdb4493822b175486810ac2abe63", "test2", {"test2"}},
	{"b945d24866af4b01a6d89b9d932a153c", "test4", {"test4"}},
	{NULL}
};

static void done()
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Release mem out");
	HANDLE_CLERROR(clReleaseMemObject(buffer_salt), "Release mem salt");
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");

}

static void init(struct fmt_main *self)
{
	int argIndex;

	//Allocate memory for hashes and passwords
	inbuffer =
	    (mscash_password *) mem_calloc(MAX_KEYS_PER_CRYPT *
	    sizeof(mscash_password));
	outbuffer =
	    (mscash_hash *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(mscash_hash));

	opencl_init("$JOHN/kernels/mscash_kernel.cl", ocl_gpu_id, NULL);

	crypt_kernel = clCreateKernel( program[ocl_gpu_id], "mscash", &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating kernel");

	buffer_keys = clCreateBuffer( context[ocl_gpu_id], CL_MEM_READ_ONLY, sizeof(mscash_password) * MAX_KEYS_PER_CRYPT, NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");
	buffer_salt = clCreateBuffer( context[ocl_gpu_id], CL_MEM_READ_ONLY, sizeof(mscash_salt), NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");
	buffer_out  = clCreateBuffer( context[ocl_gpu_id], CL_MEM_WRITE_ONLY , sizeof(mscash_hash) * MAX_KEYS_PER_CRYPT, NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");

	argIndex = 0;

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_keys), (void*) &buffer_keys),
		"Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_salt), (void*) &buffer_salt),
		"Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_out ), (void*) &buffer_out ),
		"Error setting argument 2");

}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *hash, *p;
	if (strncmp(ciphertext, mscash_prefix, strlen(mscash_prefix)) != 0)
		return 0;
	hash = p = strrchr(ciphertext, '#') + 1;
	while (*p)
		if (atoi16[ARCH_INDEX(*p++)] == 0x7f)
			return 0;
	return p - hash == 32;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i = 0;
	for (; i < MAX_CIPHERTEXT_LENGTH && ciphertext[i]; i++)
		out[i] = ciphertext[i];
	out[i] = 0;
	// lowercase salt as well as hash, encoding-aware
	enc_strlwr(&out[6]);
	return out;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	if (!strncmp(split_fields[1], "M$", 2) && valid(split_fields[1], self))
		return split_fields[1];
	if (!split_fields[0])
		return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 14);
	sprintf(cp, "M$%s#%s", split_fields[0], split_fields[1]);
	if (valid(cp, self)) {
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void *binary(char *ciphertext)
{
	static unsigned int binary[4];
	char *hash = strrchr(ciphertext, '#') + 1;
	int i;
	for (i = 0; i < 4; i++) {
		sscanf(hash + (8 * i), "%08x", &binary[i]);
		binary[i] = SWAP(binary[i]);
	}
	return binary;
}

static void *salt(char *ciphertext)
{
	static mscash_salt salt;
	char *pos = ciphertext + strlen(mscash_prefix);
	int length = 0;
	memset(&salt, 0, sizeof(salt));
	while (*pos != '#') {
		if (length == SALT_LENGTH)
			return NULL;
		salt.salt[length++] = *pos++;
	}
	salt.salt[length] = 0;
	enc_strlwr(salt.salt);
	salt.length = length;
	return &salt;
}

static void set_salt(void *salt)
{
	//fprintf(stderr, "Key:%s\n", (char *)salt);
	memcpy(&currentsalt, salt, sizeof(mscash_salt));
}

static void set_key(char *key, int index)
{
	//if(index == 5000) fprintf(stderr, "Key:%s\n", key);
	unsigned char length = strlen(key);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, MIN(length, PLAINTEXT_LENGTH));
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	unsigned char length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t gws = MAX_KEYS_PER_CRYPT;
	size_t lws = 64;

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
		sizeof(mscash_password) * MAX_KEYS_PER_CRYPT, inbuffer, 0, NULL, NULL),
		"failed in clEnqueWriteBuffer buffer_keys");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_salt, CL_TRUE, 0,
		sizeof(mscash_salt), &currentsalt, 0, NULL, NULL),
		"failed in clEnqueWriteBuffer salt");

	// Execute method
	clEnqueueNDRangeKernel( queue[ocl_gpu_id], crypt_kernel, 1, NULL, &gws, &lws, 0, NULL, NULL);
	clFinish( queue[ocl_gpu_id] );

	// read back compare results
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, sizeof(mscash_hash) * MAX_KEYS_PER_CRYPT, outbuffer, 0, NULL, NULL), "failed in reading cmp data back");

	return count;
}

static int get_hash_0(int index)
{
	//if(index == 0) fprintf(stderr, "out:%d\n", outbuffer[20].v[0]);
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
	unsigned int i, b = ((unsigned int *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	unsigned int i, *b = (unsigned int *) binary;
	for (i = 0; i < 4; i++)
		if (b[i] != outbuffer[index].v[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_opencl_mscash = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE,
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
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
