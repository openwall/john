/*
 * MD4 OpenCL code is based on Alain Espinosa's OpenCL patches.
 *
 * This software is Copyright (c) 2010, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and Copyright (c) 2012, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rawMD4;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rawMD4);
#else

#include <string.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include "config.h"
#include "options.h"
#include "mask_ext.h"

#define PLAINTEXT_LENGTH    55 /* Max. is 55 with current kernel */
#define BUFSIZE             ((PLAINTEXT_LENGTH+3)/4*4)
#define FORMAT_LABEL        "Raw-MD4-opencl"
#define FORMAT_NAME         ""
#define ALGORITHM_NAME      "MD4 OpenCL (inefficient, development use only)"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define CIPHERTEXT_LENGTH   32
#define DIGEST_SIZE         16
#define BINARY_SIZE         16
#define BINARY_ALIGN        1
#define SALT_SIZE           0
#define SALT_ALIGN          1

#define FORMAT_TAG          "$MD4$"
#define TAG_LENGTH          (sizeof(FORMAT_TAG) - 1)

cl_command_queue queue_prof;
cl_mem pinned_saved_keys, pinned_saved_idx, pinned_partial_hashes, pinned_int_key_loc;
cl_mem buffer_keys, buffer_idx, buffer_out, buffer_int_keys, buffer_int_key_loc, buffer_loaded_hashes, buffer_hash_ids, buffer_bitmap;
static cl_uint *partial_hashes, *saved_plain, *saved_idx, *saved_int_key_loc, *loaded_hashes = NULL, num_loaded_hashes, *hash_ids = NULL;
static unsigned int key_idx = 0;
static unsigned int ref_ctr;

#define MIN(a, b)               (((a) > (b)) ? (b) : (a))
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define STEP                    0
#define SEED                    1024

static int have_full_hashes;

static const char * warn[] = {
	"pass xfer: "  ,  ", crypt: "    ,  ", result xfer: ",  ", index xfer: "
};

static int crypt_all(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl-autotune.h"
#include "memdbg.h"

static struct fmt_tests tests[] = {
	{"8a9d093f14f8701df17732b2bb182c74", "password"},
	{FORMAT_TAG "6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{"6d78785c44ea8dfa178748b245d8c3ae", "magnum" },
	{FORMAT_TAG "31d6cfe0d16ae931b73c59d7e0c089c0", "" },
	{FORMAT_TAG "934eb897904769085af8101ad9dabca2", "John the ripper" },
	{FORMAT_TAG "cafbb81fb64d9dd286bc851c4c6e0d21", "lolcode" },
	{FORMAT_TAG "585028aa0f794af812ee3be8804eb14a", "123456" },
	{FORMAT_TAG "23580e2a459f7ea40f9efa148b63cafb", "12345" },
	{FORMAT_TAG "2ae523785d0caf4d2fb557c12016185c", "123456789" },
	{FORMAT_TAG "f3e80e83b29b778bc092bf8a7c6907fe", "iloveyou" },
	{FORMAT_TAG "4d10a268a303379f224d8852f2d13f11", "princess" },
	{FORMAT_TAG "bf75555ca19051f694224f2f5e0b219d", "1234567" },
	{FORMAT_TAG "41f92cf74e3d2c3ba79183629a929915", "rockyou" },
	{FORMAT_TAG "012d73e0fab8d26e0f4d65e36077511e", "12345678" },
	{FORMAT_TAG "0ceb1fd260c35bd50005341532748de6", "abc123" },
	{NULL}
};

struct fmt_main fmt_opencl_rawMD4;

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
	return 0;
}

static void create_clobj(size_t kpc, struct fmt_main * self)
{
	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys");
	saved_plain = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain");

	pinned_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx");
	saved_idx = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	pinned_partial_hashes = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY | CL_MEM_ALLOC_HOST_PTR, DIGEST_SIZE * kpc * mask_int_cand.num_int_cand, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_partial_hashes");
	partial_hashes = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_partial_hashes, CL_TRUE, CL_MAP_READ, 0, DIGEST_SIZE * kpc * mask_int_cand.num_int_cand, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory partial_hashes");

	pinned_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_int_key_loc");
	saved_int_key_loc = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_int_key_loc, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, 4 * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_int_key_loc");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys");

	buffer_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx");

	buffer_out = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, DIGEST_SIZE * kpc * mask_int_cand.num_int_cand, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_out");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_key_loc");

	buffer_loaded_hashes = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 16 * num_loaded_hashes, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_loaded_hashes");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, 12 * num_loaded_hashes + 4, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_buffer_hash_ids");

	buffer_bitmap = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, num_loaded_hashes/32 + 1, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap");

	//ref_ctr is used as dummy parameter
	buffer_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 4 * mask_int_cand.num_int_cand, mask_int_cand.int_cand ? mask_int_cand.int_cand : (void *)&ref_ctr, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_keys");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_out), (void *) &buffer_out), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_int_key_loc), (void *) &buffer_int_key_loc), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(buffer_int_keys), (void *) &buffer_int_keys), "Error setting argument 5");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_uint), (void *) &(mask_int_cand.num_int_cand)), "Error setting argument 6");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_loaded_hashes), (void *) &buffer_loaded_hashes), "Error setting argument 7");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(cl_uint), (void *) &num_loaded_hashes), "Error setting argument 8");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 8, sizeof(buffer_hash_ids), (void *) &buffer_hash_ids), "Error setting argument 9");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 9, sizeof(buffer_bitmap), (void *) &buffer_bitmap), "Error setting argument 10");

	ref_ctr++;
}

static void release_clobj(void)
{
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_partial_hashes, partial_hashes, 0,NULL,NULL), "Error Unmapping partial_hashes");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx");
	HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc, saved_int_key_loc, 0, NULL, NULL), "Error Unmapping saved_int_key_loc");
	HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing mappings");
	HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx");
	HANDLE_CLERROR(clReleaseMemObject(buffer_out), "Error Releasing buffer_out");
	HANDLE_CLERROR(clReleaseMemObject(buffer_int_key_loc), "Error Releasing buffer_int_key_loc");
	HANDLE_CLERROR(clReleaseMemObject(buffer_int_keys), "Error Releasing buffer_int_keys");
	HANDLE_CLERROR(clReleaseMemObject(buffer_loaded_hashes), "Error Releasing buffer_int_keys");

	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Error Releasing pinned_saved_idx");
	HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys");
	HANDLE_CLERROR(clReleaseMemObject(pinned_partial_hashes), "Error Releasing pinned_partial_hashes");
	HANDLE_CLERROR(clReleaseMemObject(pinned_int_key_loc), "Error Releasing pinned_int_key_loc");

	ref_ctr--;
}

static void done(void)
{
	release_clobj();

	HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
	HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);

	if (hash_ids)
		MEM_FREE(hash_ids);
}

static void init(struct fmt_main *self)
{
	size_t gws_limit;
	num_loaded_hashes = 0;

	opencl_init("$JOHN/kernels/md4_kernel.cl", gpu_id, NULL);
	crypt_kernel = clCreateKernel(program[gpu_id], "md4", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");

	gws_limit = MIN((0xf << 22) * 4 / BUFSIZE,
			get_max_mem_alloc_size(gpu_id) / BUFSIZE);

	while (tests[num_loaded_hashes].ciphertext != NULL) num_loaded_hashes++;
	hash_ids = (cl_uint*) malloc((3 * num_loaded_hashes + 1) * 4);
	fprintf(stderr, "init, num_loaded_hashes:%d\n", num_loaded_hashes);

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn,
	        1, self, create_clobj,
	        release_clobj, 2 * BUFSIZE, gws_limit);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, gws_limit,
		(cpu(device_info[gpu_id]) ? 500000000ULL : 1000000000ULL));

	mask_int_cand_target = 1000;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	p = ciphertext;
	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = p;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F) {
		if (*q >= 'A' && *q <= 'F') /* support lowercase only */
			return 0;
		q++;
	}
	return !*q && q - p == CIPHERTEXT_LENGTH;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;

	memcpy(out, FORMAT_TAG, TAG_LENGTH);
	memcpy(out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[DIGEST_SIZE];
	char *p;
	int i;
	p = ciphertext + TAG_LENGTH;
	for (i = 0; i < sizeof(out); i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

static int get_hash_0(int index) { return loaded_hashes[4 * hash_ids[3 + 3 * index]] & 0xf; }
static int get_hash_1(int index) { return loaded_hashes[4 * hash_ids[3 + 3 * index]] & 0xff; }
static int get_hash_2(int index) { return loaded_hashes[4 * hash_ids[3 + 3 * index]] & 0xfff; }
static int get_hash_3(int index) { return loaded_hashes[4 * hash_ids[3 + 3 * index]] & 0xffff; }
static int get_hash_4(int index) { return loaded_hashes[4 * hash_ids[3 + 3 * index]] & 0xfffff; }
static int get_hash_5(int index) { return loaded_hashes[4 * hash_ids[3 + 3 * index]] & 0xffffff; }
static int get_hash_6(int index) { return loaded_hashes[4 * hash_ids[3 + 3 * index]] & 0x7ffffff; }

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *_key, int index)
{
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	int len = strlen(_key);
	if (_key[0] == '1' && _key[1] == '0' && _key[2] == '0' && _key[3] == '0' && (strlen(_key) == 4))
	  fprintf(stderr, "key:%s %d\n", _key, index);
	if (mask_int_cand.num_int_cand > 1) {
		int i;
		saved_int_key_loc[index] = 0;
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
		if (mask_skip_ranges[i] != -1)  {
			saved_int_key_loc[index] |= ((mask_int_cand.int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset + mask_int_cand.int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].pos) & 0xff) << (i * 8);
		}
		else
			saved_int_key_loc[index] |= 0x80 << (i * 8);
		}
		//fprintf(stderr, "Ofeset:%d\n", mask_int_cand.int_cpu_mask_ctx->ranges[mask_skip_ranges[1]].offset);
	}

	saved_idx[index] = (key_idx << 6) | len;

	while (len > 4) {
		saved_plain[key_idx++] = *key++;
		len -= 4;
	}
	if (len)
		saved_plain[key_idx++] = *key & (0xffffffffU >> (32 - (len << 3)));


}

static char *get_key(int index)
{
	static char out[PLAINTEXT_LENGTH + 1];
	int i, len, int_index, t;
	char *key;
fprintf(stderr, "Get_key_In: %d\n", index);
	if (hash_ids == NULL || hash_ids[0] == 0 || hash_ids[0] > num_loaded_hashes){ t = 0;}
	else if(index > hash_ids[0]) { fprintf(stderr, "Error!\n"); index = hash_ids[0] - 1; t = hash_ids[1 + 3 * index]; t = 0;}
	else t = hash_ids[1 + 3 * index];

	if (t > global_work_size) { fprintf(stderr, "Error!\n"); t = 0; }
fprintf(stderr, "Get_key:%d\n", t);

	len = saved_idx[t] & 63;
	key = (char*)&saved_plain[saved_idx[t] >> 6];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	if (mask_int_cand.num_int_cand > 1) {
		if (hash_ids[0] == 0) hash_ids[2 + 3 * index] = 0;
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			out[(saved_int_key_loc[t]& (0xff << (i * 8))) >> (i * 8)] = mask_int_cand.int_cand[hash_ids[2 + 3*index]].x[i];

		//fprintf(stderr, "Int Index:%x:\n", saved_int_key_loc[0]);

	}
fprintf(stderr, "Get_key_out\n");
	return out;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;

	//fprintf(stderr, "%s(%d) lws %zu gws %zu idx %u int_cand%d\n", __FUNCTION__, count, local_work_size, global_work_size, key_idx, mask_int_cand.num_int_cand);

	// copy keys to the device
	if (key_idx)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer buffer_keys");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueWriteBuffer buffer_idx");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_TRUE, 0, 4 * global_work_size, saved_int_key_loc, 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueWriteBuffer buffer_int_key_loc");

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueNDRangeKernel");

	// read back partial hashes
	//HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE, 0, sizeof(cl_uint) * global_work_size * mask_int_cand.num_int_cand, partial_hashes, 0, NULL, multi_profilingEvent[2]), "failed in reading data back");

	if (hash_ids == NULL) fprintf(stderr, "BINGO:NUM LOADED HASHES CRYPT ALL:%d\n", num_loaded_hashes);
	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (3 * num_loaded_hashes + 1) * 4, hash_ids, 0, NULL, multi_profilingEvent[6]), "failed in reading data back hash_ids");
	have_full_hashes = 0;

	//fprintf(stderr, "No. of Cracked hashes:%d %d\n", hash_ids[0], global_work_size);

	/*if (mask_int_cand.num_int_cand > 1)
	return global_work_size * mask_int_cand.num_int_cand;

	return count;*/

	return hash_ids[0];
}

static int cmp_all(void *binary, int count)
{
	/*unsigned int i;
	unsigned int b = ((unsigned int *) binary)[0];

	for (i = 0; i < count; i++)
		if (b == partial_hashes[i])
			return 1;*/
	if (count) return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	fprintf(stderr, "cmp_one:%d %x %d %x\n", index, ((unsigned int*)binary)[0], hash_ids[3 + 3 * index], loaded_hashes[4 * hash_ids[3 + 3 * index]]);
	return (((unsigned int*)binary)[0] == loaded_hashes[4 * hash_ids[3 + 3 * index]]);
}

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) get_binary(source);
	fprintf(stderr, "Binary Cmp_Exact:%x\n", t[3]);

	/*if (!have_full_hashes) {
		clEnqueueReadBuffer(queue[gpu_id], buffer_out, CL_TRUE,
		        sizeof(cl_uint) * (global_work_size) * mask_int_cand.num_int_cand,
		        sizeof(cl_uint) * 3 * global_work_size * mask_int_cand.num_int_cand,
		        partial_hashes + global_work_size * mask_int_cand.num_int_cand, 0, NULL, NULL);
		have_full_hashes = 1;
	}*/

	if (t[1]!=loaded_hashes[4 * hash_ids[3 + 3 * index] + 1])
		return 0;
	if (t[2]!=loaded_hashes[4 * hash_ids[3 + 3 * index] + 2])
		return 0;
	if (t[3]!=loaded_hashes[4 * hash_ids[3 + 3 * index] + 3])
		return 0;
	return 1;
}

static void load_hash(struct db_salt *salt) {
	unsigned int *bin, i;
	struct db_password *pw;
	num_loaded_hashes = (salt->count);

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (hash_ids)
		 MEM_FREE(hash_ids);

	loaded_hashes = (cl_uint*) malloc(16 * num_loaded_hashes);
	hash_ids = (cl_uint*) malloc((3 * num_loaded_hashes + 1) * 4);

	pw = salt -> list;
	i = 0;
	do {
		bin = (unsigned int *)pw -> binary;
		// Potential segfault if removed
		if(bin != NULL) {
			loaded_hashes[4*i] = bin[0];
			loaded_hashes[4*i + 1] = bin[1];
			loaded_hashes[4*i + 2] = bin[2];
			loaded_hashes[4*i + 3] = bin[3];
			i++ ;
			fprintf(stderr, "Load Bin:%x\n", bin[1]);
		}
	} while ((pw = pw -> next)) ;

	if(i != (salt->count)) {
		fprintf(stderr, "Something went wrong while loading hashes to gpu..Exiting..\n");
		exit(0);
	}

}

static void reset(struct db_main *db) {
	if (db) {
		size_t kpc;
		if (ref_ctr > 0)
			release_clobj();

		kpc = db->format->params.max_keys_per_crypt;
	/*	kpc /= mask_int_cand.num_int_cand;
		kpc = local_work_size ? (kpc + local_work_size - 1) / local_work_size * local_work_size : kpc;*/
	        load_hash(db->salts);
		create_clobj(kpc, NULL);
		/*db->format->params.max_keys_per_crypt = kpc;

		fprintf(stderr, "KPC: %d\n", db->format->params.max_keys_per_crypt);*/
		fprintf(stderr, "num_loaded_hashes:%d\n", num_loaded_hashes);
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_loaded_hashes, CL_TRUE, 0, 16 * num_loaded_hashes, loaded_hashes, 0, NULL, multi_profilingEvent[5]), "failed in clEnqueueWriteBuffer buffer_keys");
	}

	else {
		unsigned int *binary, i = 0;
		char *ciphertext;
		if (loaded_hashes)
			MEM_FREE(loaded_hashes);
		if (hash_ids)
			 MEM_FREE(hash_ids);

		loaded_hashes = (cl_uint*) malloc(16 * num_loaded_hashes);
		hash_ids = (cl_uint*) malloc((3 * num_loaded_hashes + 1) * 4);

		while (tests[i].ciphertext != NULL) {
			ciphertext = split(tests[i].ciphertext, 0, &fmt_opencl_rawMD4);
			binary = (unsigned int*)get_binary(ciphertext);
			loaded_hashes[4 * i] = binary[0];
			loaded_hashes[4 * i + 1] = binary[1];
			loaded_hashes[4 * i + 2] = binary[2];
			loaded_hashes[4 * i + 3] = binary[3];
			fprintf(stderr, "C:%s P:%s CP:%s B:%x\n", tests[i].ciphertext, tests[i].plaintext, ciphertext, loaded_hashes[4*i]);
			i++;
		}

		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_loaded_hashes, CL_TRUE, 0, 16 * num_loaded_hashes, loaded_hashes, 0, NULL, multi_profilingEvent[5]), "failed in clEnqueueWriteBuffer buffer_keys");

	}
}

struct fmt_main fmt_opencl_rawMD4 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
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
		reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_salt_hash,
		NULL,
		fmt_default_set_salt,
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
