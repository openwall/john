/*
 * This software is Copyright (c) 2013 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * This is format is based on mscash-cuda by Lukas Odzioba
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
#include "loader.h"

#define FORMAT_LABEL		"mscash-opencl"
#define FORMAT_NAME		"M$ Cache Hash"
#define ALGORITHM_NAME		"MD4 opencl (inefficient, development use only)"
#define MAX_CIPHERTEXT_LENGTH	(2 + 19*3 + 1 + 32)
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define BUFSIZE            	((PLAINTEXT_LENGTH+3)/4*4)

static unsigned int key_idx = 0;

static unsigned int *saved_plain, *saved_idx, *outbuffer, *outKeyIdx, *current_salt;
cl_mem 	pinned_saved_keys, pinned_saved_idx, pinned_saved_salt,
	buffer_keys, buffer_idx, buffer_salt, buffer_out,
	buffer_outKeyIdx;

/* The following variables depends on the number of salts loaded_count
 * during cracking session. */
static unsigned int **loaded_hashes, *loaded_count, sequential_id = 0, max_salts = 0;
static struct bitmap_ctx *bitmaps;
cl_mem *buffer_ld_hashes, *buffer_bitmaps, *buffer_salts;

static unsigned int cmp_out = 0;
static unsigned int benchmark = 1;
static unsigned int keys_changed = 0;

cl_kernel crk_kernel;

static int crypt_all_self_test(int *pcount, struct db_salt *_salt);
static int crypt_all(int *pcount, struct db_salt *_salt);
static char *get_key_self_test(int index);
static char *get_key(int index);

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
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_keys, saved_plain, 0,NULL,NULL), "Error Unmapping saved keys");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_idx, saved_idx, 0,NULL,NULL), "Error Unmapping saved idx");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[ocl_gpu_id], pinned_saved_salt, current_salt, 0,NULL,NULL), "Error Unmapping saved idx");

	MEM_FREE(outbuffer);

	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Release mem in");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Release pinned mem in");
	HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Release key indices");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Release pinned saved key indeces");
	HANDLE_CLERROR(clReleaseMemObject(buffer_salt), "Release mem salt");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_salt), "Release pinned saved salt");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Release mem out");
	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseKernel(crk_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[ocl_gpu_id]), "Release Program");

	if(!benchmark) {
		int i;
		for(i = 0; i < max_salts; i++) {
			HANDLE_CLERROR(clReleaseMemObject(buffer_ld_hashes[i]), "Release loaded hashes");
			HANDLE_CLERROR(clReleaseMemObject(buffer_bitmaps[i]), "Release loaded bimaps");
			HANDLE_CLERROR(clReleaseMemObject(buffer_salts[i]), "Release loaded salts");
			MEM_FREE(loaded_hashes[i]);
		}
		HANDLE_CLERROR(clReleaseMemObject(buffer_outKeyIdx), "Release output key indeces");
		MEM_FREE(loaded_hashes);
		MEM_FREE(bitmaps);
		MEM_FREE(loaded_count);
		MEM_FREE(outKeyIdx);
	}

}

static void init(struct fmt_main *self)
{
	int argIndex;

	//Allocate memory for hashes and passwords
	//saved_plain = (unsigned int *) mem_calloc(MAX_KEYS_PER_CRYPT * BUFSIZE);
	saved_idx = (unsigned int*) mem_calloc(MAX_KEYS_PER_CRYPT * sizeof(unsigned int));
	outbuffer =
	    (unsigned int *) mem_alloc(MAX_KEYS_PER_CRYPT * 4 * sizeof(unsigned int));

	opencl_init("$JOHN/kernels/mscash_kernel.cl", ocl_gpu_id, NULL);

	crypt_kernel = clCreateKernel( program[ocl_gpu_id], "mscash_self_test", &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating kernel");

	crk_kernel = clCreateKernel( program[ocl_gpu_id], "mscash", &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating kernel");

	pinned_saved_keys = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * MAX_KEYS_PER_CRYPT, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");
	saved_plain = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * MAX_KEYS_PER_CRYPT, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");
	buffer_keys = clCreateBuffer( context[ocl_gpu_id], CL_MEM_READ_ONLY, BUFSIZE * MAX_KEYS_PER_CRYPT, NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");

	pinned_saved_idx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(unsigned int) * MAX_KEYS_PER_CRYPT, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	saved_idx = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(unsigned int) * MAX_KEYS_PER_CRYPT, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");
	buffer_idx = clCreateBuffer( context[ocl_gpu_id], CL_MEM_READ_ONLY, sizeof(unsigned int) * MAX_KEYS_PER_CRYPT, NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");

	pinned_saved_salt = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(unsigned int) * 12, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	current_salt = clEnqueueMapBuffer(queue[ocl_gpu_id], pinned_saved_salt, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(unsigned int) * 12, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_salt");
	buffer_salt = clCreateBuffer( context[ocl_gpu_id], CL_MEM_READ_ONLY, sizeof(unsigned int) * 12, NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");

	buffer_out  = clCreateBuffer( context[ocl_gpu_id], CL_MEM_WRITE_ONLY , 4 * MAX_KEYS_PER_CRYPT * sizeof(unsigned int), NULL, &ret_code );
	HANDLE_CLERROR(ret_code,"Error creating buffer argument");

	argIndex = 0;
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_keys), (void*) &buffer_keys),
		"Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_idx), (void*) &buffer_idx),
		"Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_salt), (void*) &buffer_salt),
		"Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, argIndex++, sizeof(buffer_out ), (void*) &buffer_out ),
		"Error setting argument 3");

	self->methods.crypt_all = crypt_all_self_test;
	self->methods.get_key = get_key_self_test;

	global_work_size = MAX_KEYS_PER_CRYPT;

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

void prepare_login(unsigned int * login, int length,
    unsigned int * nt_buffer)
{
	int i = 0, nt_index, keychars;;
	for (i = 0; i < 12; i++)
		nt_buffer[i] = 0;

	nt_index = 0;
	for (i = 0; i < (length + 4)/ 4; i++) {
		keychars = login[i];
		nt_buffer[nt_index++] = (keychars & 0xFF) | (((keychars >> 8) & 0xFF) << 16);
		nt_buffer[nt_index++] = ((keychars >> 16) & 0xFF) | ((keychars >> 24) << 16);
	}
	nt_index = (length >> 1);
	nt_buffer[nt_index] = (nt_buffer[nt_index] & 0xFF) | (0x80 << ((length & 1) << 4));
	nt_buffer[nt_index + 1] = 0;
	nt_buffer[10] = (length << 4) + 128;
}

static void *salt(char *ciphertext)
{
	static union {
		char csalt[SALT_LENGTH + 1];
		unsigned int  isalt[(SALT_LENGTH + 4)/4];
	} salt;
	static unsigned int final_salt[12];
	char *pos = ciphertext + strlen(mscash_prefix);
	int length = 0;
	memset(&salt, 0, sizeof(salt));
	while (*pos != '#') {
		if (length == SALT_LENGTH)
			return NULL;
		salt.csalt[length++] = *pos++;
	}
	salt.csalt[length] = 0;
	enc_strlwr(salt.csalt);
	prepare_login(salt.isalt, length, final_salt);
	return &final_salt;
}

static void set_salt(void *salt)
{
	memcpy(current_salt, salt, sizeof(unsigned int) * 12);
}

static void no_op(void *salt){}

static void reset(struct db_main *db) {

	if(db != NULL) {
		int argIndex, pwcount, ctr = 0;
		struct db_salt *salt = db -> salts;
		max_salts = db->salt_count;

		outKeyIdx     = (unsigned int*)mem_calloc((db->password_count) * sizeof(unsigned int) * 2);
		loaded_hashes = (unsigned int **)mem_calloc(max_salts * sizeof(unsigned int *));
		loaded_count = (unsigned int*)mem_calloc(max_salts * sizeof(unsigned int));
		bitmaps = (struct bitmap_ctx *)mem_alloc(max_salts * sizeof(struct bitmap_ctx));
		buffer_ld_hashes = (cl_mem *)mem_alloc(max_salts * sizeof(cl_mem));
		buffer_bitmaps = (cl_mem *)mem_alloc(max_salts * sizeof(cl_mem));
		buffer_salts = (cl_mem *)mem_alloc(max_salts * sizeof(cl_mem));

		do {
			salt -> sequential_id = ctr++;
			pwcount = salt->count;
			loaded_hashes[salt->sequential_id] = (unsigned int *) mem_calloc((pwcount * 4 + 1) * sizeof(unsigned int));
			buffer_ld_hashes[salt->sequential_id] = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, (pwcount * 4 + 1) * sizeof(unsigned int), NULL, &ret_code);
			HANDLE_CLERROR(ret_code, "Error creating buffer arg loaded_hashes\n");
			buffer_bitmaps[salt->sequential_id] = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, sizeof(struct bitmap_ctx), NULL, &ret_code);
			HANDLE_CLERROR(ret_code, "Error creating buffer arg bitmap\n");
			buffer_salts[salt->sequential_id] = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, 12 * sizeof(unsigned int), NULL, &ret_code);
			HANDLE_CLERROR(ret_code, "Error creating buffer salts\n");
			HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_salts[salt->sequential_id], CL_TRUE, 0,
			sizeof(unsigned int) * 12, salt->salt, 0, NULL, NULL),
			"failed in clEnqueWriteBuffer salt");

		} while((salt = salt->next));

		buffer_outKeyIdx = clCreateBuffer(context[ocl_gpu_id], CL_MEM_READ_WRITE, (db->password_count) * sizeof(unsigned int) * 2, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer cmp_out\n");

		argIndex = 0;
		HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_keys), (void*) &buffer_keys),
		"Error setting argument 0");
		HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_idx), (void*) &buffer_idx),
		"Error setting argument 1");
		HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_out), (void*) &buffer_out ),
		"Error setting argument 2");
		HANDLE_CLERROR(clSetKernelArg(crk_kernel, argIndex++, sizeof(buffer_outKeyIdx), (void*) &buffer_outKeyIdx ),
		"Error setting argument 3");

		benchmark = 0;

		db->max_int_keys = 0;

		db->format->methods.crypt_all = crypt_all;
		db->format->methods.get_key = get_key;
		db->format->methods.set_salt = no_op;
	}
}

static void load_hash(struct db_salt *salt, unsigned int *loaded_hashes, unsigned int *loaded_count) {

	unsigned int *bin, i;
	struct db_password *pw;

	*loaded_count = (salt->count);
	loaded_hashes[0] = *loaded_count;
	pw = salt -> list;
	i = 0;
	do {
		bin = (unsigned int *)pw -> binary;
		// Potential segfault if removed
		if(bin != NULL) {
			loaded_hashes[i*4 + 1] = bin[0];
			loaded_hashes[i*4 + 2] = bin[1];
			loaded_hashes[i*4 + 3] = bin[2];
			loaded_hashes[i*4 + 4] = bin[3];
			i++ ;
		}
	} while ((pw = pw -> next)) ;

	if(i != (salt->count)) {
		fprintf(stderr, "Something went wrong while loading hashes to gpu..Exiting..\n");
		exit(0);
	}
}

static void load_bitmap(unsigned int num_loaded_hashes, unsigned int *loaded_hashes, unsigned int index, unsigned int *bitmap, size_t szBmp) {
	unsigned int i, hash;
	memset(bitmap, 0, szBmp);

	for(i = 0; i < num_loaded_hashes; i++) {
		hash = loaded_hashes[index + i * 4 + 1] & (szBmp * 8 - 1);
		// divide by 32 , harcoded here and correct only for unsigned int
		bitmap[hash >> 5] |= (1U << (hash & 31));
	}
}

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *_key, int index)
{
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));

	keys_changed = 1;
}

static char *get_key_self_test(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len = saved_idx[index] & 63;
	char *key = (char*)&saved_plain[saved_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;
	return out;
}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	char *key;
	int i, len;

	if(index < loaded_count[sequential_id])
		index = outKeyIdx[index];

	len = saved_idx[index] & 63;
	key = (char*)&saved_plain[saved_idx[index] >> 6];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;
	return out;
}

static int crypt_all_self_test(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t gws = global_work_size;
	size_t lws = 64;

	if (keys_changed) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0,
			sizeof(unsigned int) * global_work_size, saved_idx, 0, NULL, NULL),
			"failed in clEnqueWriteBuffer buffer_idx");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
			4 * key_idx, saved_plain, 0, NULL, NULL),
			"failed in clEnqueWriteBuffer buffer_idx");
		keys_changed = 0;
	}
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_salt, CL_TRUE, 0,
		sizeof(unsigned int) * 12, current_salt, 0, NULL, NULL),
		"failed in clEnqueWriteBuffer salt");

	// Execute method
	clEnqueueNDRangeKernel( queue[ocl_gpu_id], crypt_kernel, 1, NULL, &gws, &lws, 0, NULL, NULL);
	clFinish( queue[ocl_gpu_id] );

	// read back compare results
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out, CL_TRUE, 0, 4 * global_work_size * sizeof(unsigned int), outbuffer, 0, NULL, NULL), "failed in reading cmp data back");

	return count;
}

static int crypt_all(int *pcount, struct db_salt *currentsalt) {

	int  i;
	size_t gws = global_work_size;
	size_t lws = LWS;

	sequential_id = currentsalt -> sequential_id;

	if(loaded_count[sequential_id] != (currentsalt->count)) {
		load_hash(currentsalt, loaded_hashes[sequential_id], &loaded_count[sequential_id]);
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id],
						    buffer_ld_hashes[sequential_id],
						    CL_TRUE, 0, ((currentsalt -> count) * 4 + 1) * sizeof(unsigned int),
						    loaded_hashes[sequential_id], 0, NULL, NULL),
						    "failed in clEnqueueWriteBuffer loaded_hashes");
		load_bitmap(loaded_count[sequential_id], loaded_hashes[sequential_id], 0, &(bitmaps[sequential_id].bitmap0[0]), (BITMAP_SIZE_1 / 8));
		load_bitmap(loaded_count[sequential_id], loaded_hashes[sequential_id], 1, &(bitmaps[sequential_id].bitmap1[0]), (BITMAP_SIZE_1 / 8));
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_bitmaps[sequential_id],
						    CL_TRUE, 0, sizeof(struct bitmap_ctx),
						    &bitmaps[sequential_id], 0, NULL, NULL ),
						    "Failed Copy data to gpu");
	}

	HANDLE_CLERROR(clSetKernelArg(crk_kernel, 4, sizeof(buffer_salts[sequential_id]), (void*) &buffer_salts[sequential_id]),
	"Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crk_kernel, 5, sizeof(buffer_ld_hashes[sequential_id]), (void*) &buffer_ld_hashes[sequential_id]),
	"Error setting argument 5");
	HANDLE_CLERROR(clSetKernelArg(crk_kernel, 6, sizeof(buffer_bitmaps[sequential_id]), (void*) &buffer_bitmaps[sequential_id]),
	"Error setting argument 6");

	if(keys_changed) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_idx, CL_TRUE, 0,
			sizeof(unsigned int) * global_work_size, saved_idx, 0, NULL, NULL),
			"failed in clEnqueWriteBuffer buffer_idx");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[ocl_gpu_id], buffer_keys, CL_TRUE, 0,
			4 * key_idx, saved_plain, 0, NULL, NULL),
			"failed in clEnqueWriteBuffer buffer_idx");
		keys_changed = 0;
	}

	// Execute method
	clEnqueueNDRangeKernel( queue[ocl_gpu_id], crk_kernel, 1, NULL, &gws, &lws, 0, NULL, NULL);
	clFinish( queue[ocl_gpu_id] );

	// read back compare results
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_outKeyIdx, CL_TRUE, 0, sizeof(cl_uint) * loaded_count[sequential_id], outKeyIdx, 0, NULL, NULL), "failed in reading cracked key indices back");

	cmp_out = 0;

	// If a positive match is found outKeyIdx contains some positive value else contains 0
	for(i = 0; i < (loaded_count[sequential_id] & (~cmp_out)); i++)
		cmp_out = outKeyIdx[i]?0xffffffff:0;

	if(cmp_out) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_out,
						   CL_TRUE, 0, 4 * loaded_count[sequential_id] * sizeof(unsigned int),
						   outbuffer, 0, NULL, NULL), "failed in reading cmp data back");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[ocl_gpu_id], buffer_outKeyIdx,
						   CL_TRUE, 0, sizeof(cl_uint) * loaded_count[sequential_id] * 2,
						   outKeyIdx, 0, NULL, NULL), "failed in reading cracked key indices back");
		return loaded_count[sequential_id];
	}

	else return 0;
}

static int get_hash_0(int index)
{
	return outbuffer[index] & 0xf;
}

static int get_hash_1(int index)
{
	return outbuffer[index] & 0xff;
}

static int get_hash_2(int index)
{
	return outbuffer[index] & 0xfff;
}

static int get_hash_3(int index)
{
	return outbuffer[index] & 0xffff;
}

static int get_hash_4(int index)
{
	return outbuffer[index] & 0xfffff;
}

static int get_hash_5(int index)
{
	return outbuffer[index] & 0xffffff;
}

static int get_hash_6(int index)
{
	return outbuffer[index] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i, b = ((unsigned int *) binary)[0];

	if(!benchmark) return 1;

	for (i = 0; i < count; i++)
		if (b == outbuffer[i])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	unsigned int *b = (unsigned int *) binary;

	if(!benchmark) return 1;

	if (b[0] != outbuffer[index])
		return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	unsigned int *t = (unsigned int *) binary(source);
	unsigned int num = benchmark ? global_work_size: loaded_count[sequential_id];
	if (t[1]!=outbuffer[count + num])
		return 0;
	if (t[2]!=outbuffer[2 * num + count])
		return 0;
	if (t[3]!=outbuffer[3 * num + count])
		return 0;

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
		BINARY_ALIGN,
		sizeof(unsigned int) * 12,
		sizeof(unsigned int) ,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE,
		tests
	}, {
		init,
		done,
		reset,
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
