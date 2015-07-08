/*
 * This software is Copyright (c) 2015, Sayantan Datta <std2048@gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifdef HAVE_OPENCL
#define FMT_STRUCT fmt_opencl_mscash

#if FMT_EXTERNS_H
extern struct fmt_main FMT_STRUCT;
#elif FMT_REGISTERS_H
john_register_one(&FMT_STRUCT);
#else

#include <string.h>
#include <assert.h>
#include <sys/time.h>

#include "arch.h"
#include "params.h"
#include "path.h"
#include "common.h"
#include "formats.h"
#include "common-opencl.h"
#include "config.h"
#include "options.h"
#include "unicode.h"
#include "mask_ext.h"
#include "interface.h"

#define PLAINTEXT_LENGTH    27 /* Max. is 55 with current kernel */
#define BUFSIZE             ((PLAINTEXT_LENGTH+3)/4*4)
#define FORMAT_LABEL	    "mscash-opencl"
#define FORMAT_NAME	    "M$ Cache Hash"
#define ALGORITHM_NAME      "MD4 OpenCL"
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1
#define CIPHERTEXT_LENGTH   (2 + 19*3 + 1 + 32)
#define DIGEST_SIZE         16
#define BINARY_SIZE         16
#define BINARY_ALIGN        sizeof(unsigned int)
#define SALT_LENGTH	    19
#define SALT_SIZE	    (12 * sizeof(unsigned int))
#define SALT_ALIGN          sizeof(unsigned int)

static cl_mem pinned_saved_keys, pinned_saved_idx, pinned_int_key_loc;
static cl_mem buffer_keys, buffer_idx, buffer_int_keys, buffer_int_key_loc;
static cl_uint *saved_plain, *saved_idx, *saved_int_key_loc;
static int static_gpu_locations[MASK_FMT_INT_PLHDR];

static cl_mem buffer_return_hashes, buffer_hash_ids, buffer_bitmap_dupe;
static cl_mem buffer_offset_table_test, buffer_hash_table_test, buffer_bitmaps_test, buffer_salt_test;
static cl_mem *buffer_offset_tables = NULL, *buffer_hash_tables = NULL, *buffer_bitmaps = NULL, *buffer_salts = NULL;
static OFFSET_TABLE_WORD *offset_table = NULL;
static unsigned int **hash_tables = NULL;
static unsigned int current_salt = 0;
static cl_uint *loaded_hashes = NULL, max_num_loaded_hashes, *hash_ids = NULL, *bitmaps = NULL, max_hash_table_size = 0;
static cl_ulong bitmap_size_bits = 0;

static unsigned int key_idx = 0;
static unsigned int ocl_ver;
static struct fmt_main *self;

static char mscash_prefix[] = "M$";

#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

#define STEP                    0
#define SEED                    1024

#define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define get_power_of_two(v)	\
{				\
	v--;			\
	v |= v >> 1;		\
	v |= v >> 2;		\
	v |= v >> 4;		\
	v |= v >> 8;		\
	v |= v >> 16;		\
	v |= v >> 32;		\
	v++;			\
}

static int crypt_all(int *pcount, struct db_salt *_salt);

//This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "memdbg.h"

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

struct fmt_main FMT_STRUCT;

static void set_kernel_args_kpc()
{
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(buffer_keys), (void *) &buffer_keys), "Error setting argument 1.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(buffer_idx), (void *) &buffer_idx), "Error setting argument 2.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_int_key_loc), (void *) &buffer_int_key_loc), "Error setting argument 4.");
}

static void set_kernel_args()
{
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(buffer_int_keys), (void *) &buffer_int_keys), "Error setting argument 5.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 8, sizeof(buffer_return_hashes), (void *) &buffer_return_hashes), "Error setting argument 9.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 9, sizeof(buffer_hash_ids), (void *) &buffer_hash_ids), "Error setting argument 10.");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 10, sizeof(buffer_bitmap_dupe), (void *) &buffer_bitmap_dupe), "Error setting argument 11.");
}

static void create_clobj_kpc(size_t kpc)
{
	pinned_saved_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFSIZE * kpc, NULL, &ret_code);
	if (ret_code != CL_SUCCESS) {
		saved_plain = (cl_uint *) mem_alloc(BUFSIZE * kpc);
		if (saved_plain == NULL)
			HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_keys.");
	}
	else {
		saved_plain = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_keys, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, BUFSIZE * kpc, 0, NULL, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_plain.");
	}

	pinned_saved_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_saved_idx.");
	saved_idx = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_saved_idx, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx.");

	pinned_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating page-locked memory pinned_int_key_loc.");
	saved_int_key_loc = (cl_uint *) clEnqueueMapBuffer(queue[gpu_id], pinned_int_key_loc, CL_TRUE, CL_MAP_READ | CL_MAP_WRITE, 0, sizeof(cl_uint) * kpc, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_int_key_loc.");

	// create and set arguments
	buffer_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, BUFSIZE * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_keys.");

	buffer_idx = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, 4 * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_idx.");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, sizeof(cl_uint) * kpc, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_key_loc.");
}

static void create_clobj()
{
	unsigned int dummy = 0;
	buffer_return_hashes = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 2 * sizeof(cl_uint) * max_num_loaded_hashes, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_return_hashes.");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (3 * max_num_loaded_hashes + 1) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_buffer_hash_ids.");

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (max_hash_table_size/32 + 1) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap_dupe.");

	//ref_ctr is used as dummy parameter
	buffer_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 4 * mask_int_cand.num_int_cand, mask_int_cand.int_cand ? mask_int_cand.int_cand : (void *)&dummy, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_keys.");
}

static void release_clobj_kpc(void)
{
	if (buffer_keys) {
		if (pinned_saved_keys) {
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_keys, saved_plain, 0, NULL, NULL), "Error Unmapping saved_plain.");
			HANDLE_CLERROR(clReleaseMemObject(pinned_saved_keys), "Error Releasing pinned_saved_keys.");
		}
		else
			MEM_FREE(saved_plain);

		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx, saved_idx, 0, NULL, NULL), "Error Unmapping saved_idx.");
		HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc, saved_int_key_loc, 0, NULL, NULL), "Error Unmapping saved_int_key_loc.");
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing mappings.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_saved_idx), "Error Releasing pinned_saved_idx.");
		HANDLE_CLERROR(clReleaseMemObject(pinned_int_key_loc), "Error Releasing pinned_int_key_loc.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_keys), "Error Releasing buffer_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_idx), "Error Releasing buffer_idx.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_key_loc), "Error Releasing buffer_int_key_loc.");
		buffer_keys = 0;
	}
}

static void release_clobj_test(void)
{
	if (buffer_salt_test) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_salt_test), "Error Releasing buffer_salt_test.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_offset_table_test), "Error Releasing buffer_offset_table_test.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_table_test), "Error Releasing buffer_hash_table_test.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmaps_test), "Error Releasing buffer_bitmap_test.");
		buffer_salt_test = 0;
	}
}

static void release_clobj(void)
{
	if (buffer_int_keys) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_int_keys), "Error Releasing buffer_int_keys.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_return_hashes), "Error Releasing buffer_return_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error Releasing buffer_bitmap_dupe.");
		buffer_int_keys = 0;
	}
}

static void release_salt_buffers()
{
	unsigned int k;
	if (hash_tables) {
		k = 0;
		while (hash_tables[k]) {
			MEM_FREE(hash_tables[k]);
			hash_tables[k] = 0;
			k++;
		}
		MEM_FREE(hash_tables);
		hash_tables = NULL;
	}
	if (buffer_offset_tables) {
		k = 0;
		while (buffer_offset_tables[k]) {
			clReleaseMemObject(buffer_offset_tables[k]);
			buffer_offset_tables[k] = 0;
			k++;
		}
		MEM_FREE(buffer_offset_tables);
		buffer_offset_tables = NULL;
	}
	if (buffer_hash_tables) {
		k = 0;
		while (buffer_hash_tables[k]) {
			clReleaseMemObject(buffer_hash_tables[k]);
			buffer_hash_tables[k] = 0;
			k++;
		}
		MEM_FREE(buffer_hash_tables);
		buffer_hash_tables = NULL;
	}
	if (buffer_bitmaps) {
		k = 0;
		while (buffer_bitmaps[k]) {
			clReleaseMemObject(buffer_bitmaps[k]);
			buffer_bitmaps[k] = 0;
			k++;
		}
		MEM_FREE(buffer_bitmaps);
		buffer_bitmaps = NULL;
	}
	if (buffer_salts) {
		k = 0;
		while (buffer_salts[k]) {
			clReleaseMemObject(buffer_salts[k]);
			buffer_salts[k] = 0;
			k++;
		}
		MEM_FREE(buffer_salts);
		buffer_salts = NULL;
	}
}

static void done(void)
{
	release_clobj_test();
	release_clobj();
	release_clobj_kpc();

	if (crypt_kernel) {
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel.");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program.");
		crypt_kernel = NULL;
	}

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (hash_ids)
		MEM_FREE(hash_ids);
	release_salt_buffers();
}

static void init_kernel(void)
{
	char build_opts[5000];
	int i;
	cl_ulong const_cache_size;

	clReleaseKernel(crypt_kernel);

	for (i = 0; i < MASK_FMT_INT_PLHDR; i++)
		if (mask_skip_ranges!= NULL && mask_skip_ranges[i] != -1)
			static_gpu_locations[i] = mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos;
		else
			static_gpu_locations[i] = -1;

#if CL_VERSION_1_2
	ocl_ver = get_device_version(gpu_id);
#else
	ocl_ver = 110;
#endif

	/* Driver bug workaround for OSX and GT650M, see #1459 */
	if (ocl_ver == 120 && platform_apple(platform_id) && gpu_nvidia(gpu_id))
		ocl_ver = 110;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof(cl_ulong), &const_cache_size, 0), "failed to get CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE.");

	sprintf(build_opts, "-D NUM_INT_KEYS=%u -D IS_STATIC_GPU_MASK=%d"
		" -D CONST_CACHE_SIZE=%llu -D LOC_0=%d"
#if !CL_VERSION_1_2
		" -DFORCE_OCL_110"
#endif
#if 1 < MASK_FMT_INT_PLHDR
	" -D LOC_1=%d "
#endif
#if 2 < MASK_FMT_INT_PLHDR
	"-D LOC_2=%d "
#endif
#if 3 < MASK_FMT_INT_PLHDR
	"-D LOC_3=%d"
#endif
	, mask_int_cand.num_int_cand, is_static_gpu_mask,
	(unsigned long long)const_cache_size, static_gpu_locations[0]
#if 1 < MASK_FMT_INT_PLHDR
	, static_gpu_locations[1]
#endif
#if 2 < MASK_FMT_INT_PLHDR
	, static_gpu_locations[2]
#endif
#if 3 < MASK_FMT_INT_PLHDR
	, static_gpu_locations[3]
#endif
	);

	opencl_build(gpu_id, build_opts, 0, NULL);
	crypt_kernel = clCreateKernel(program[gpu_id], "mscash", &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating kernel. Double-check kernel name?");
}

static void init(struct fmt_main *_self)
{
	self = _self;
	max_num_loaded_hashes = 0;
	mask_int_cand_target = 10000;

	opencl_prepare_dev(gpu_id);
	opencl_read_source("$JOHN/kernels/mscash_kernel.cl");
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
	static char out[CIPHERTEXT_LENGTH + 1];
	int i = 0;
	for (; i < CIPHERTEXT_LENGTH && ciphertext[i]; i++)
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

/* Used during self-test. */
static void set_salt(void *salt)
{
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_salt_test, CL_TRUE, 0, 12 * sizeof(cl_uint), salt, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_salt_test.");
}

static void set_salt_no_op(void *salt){}

static int get_hash_0(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & 0xf; }
static int get_hash_1(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & 0xff; }
static int get_hash_2(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & 0xfff; }
static int get_hash_3(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & 0xffff; }
static int get_hash_4(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & 0xfffff; }
static int get_hash_5(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & 0xffffff; }
static int get_hash_6(int index) { return hash_tables[current_salt][hash_ids[3 + 3 * index]] & 0x7ffffff; }

static void clear_keys(void)
{
	key_idx = 0;
}

static void set_key(char *_key, int index)
{
	const ARCH_WORD_32 *key = (ARCH_WORD_32*)_key;
	int len = strlen(_key);

	if (mask_int_cand.num_int_cand > 1 && !is_static_gpu_mask) {
		int i;
		saved_int_key_loc[index] = 0;
		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {
			if (mask_skip_ranges[i] != -1)  {
				saved_int_key_loc[index] |= ((mask_int_cand.
				int_cpu_mask_ctx->ranges[mask_skip_ranges[i]].offset +
				mask_int_cand.int_cpu_mask_ctx->
				ranges[mask_skip_ranges[i]].pos) & 0xff) << (i << 3);
			}
			else
				saved_int_key_loc[index] |= 0x80 << (i << 3);
		}
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

	if (hash_ids == NULL || hash_ids[0] == 0 ||
	    index >= hash_ids[0] || hash_ids[0] > max_num_loaded_hashes) {
		t = index;
		int_index = 0;
	}
	else  {
		t = hash_ids[1 + 3 * index];
		int_index = hash_ids[2 + 3 * index];

	}

	if (t > global_work_size) {
		fprintf(stderr, "Get key error! %d %d\n", t, index);
		t = 0;
	}

	len = saved_idx[t] & 63;
	key = (char*)&saved_plain[saved_idx[t] >> 6];

	for (i = 0; i < len; i++)
		out[i] = *key++;
	out[i] = 0;

	if (mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			if (is_static_gpu_mask)
				out[static_gpu_locations[i]] =
				mask_int_cand.int_cand[int_index].x[i];
			else
				out[(saved_int_key_loc[t]& (0xff << (i * 8))) >> (i * 8)] =
				mask_int_cand.int_cand[int_index].x[i];
	}

	return out;
}

/* Use only for smaller bitmaps < 16MB */
static void prepare_bitmap_4(cl_ulong bmp_sz, cl_uint **bitmap_ptr, uint num_loaded_hashes)
{
	unsigned int i;
	MEM_FREE(*bitmap_ptr);
	*bitmap_ptr = (cl_uint*) mem_calloc((bmp_sz >> 3), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[4 * i + 3] & (bmp_sz - 1);
		(*bitmap_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[4 * i + 2] & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[4 * i + 1] & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 4) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[4 * i] & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) * 3 + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));
	}
}
/*
static void prepare_bitmap_1(cl_ulong bmp_sz, cl_uint **bitmap_ptr, uint num_loaded_hashes)
{
	unsigned int i;
	MEM_FREE(*bitmap_ptr);
	*bitmap_ptr = (cl_uint*) mem_calloc((bmp_sz >> 5), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[4 * i + 3] & (bmp_sz - 1);
		(*bitmap_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));
	}
}*/

static void select_bitmap(unsigned int num_loaded_hashes)
{
	cl_ulong max_local_mem_sz_bytes = 0;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_LOCAL_MEM_SIZE,
		sizeof(cl_ulong), &max_local_mem_sz_bytes, 0),
		"failed to get CL_DEVICE_LOCAL_MEM_SIZE.");

	if (num_loaded_hashes <= 5100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;

		else
			bitmap_size_bits = 256 * 1024;
	}

	else if (num_loaded_hashes <= 10100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;

		else
			bitmap_size_bits = 256 * 1024;

	}

	else if (num_loaded_hashes <= 20100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 1024 * 1024;

		else
			bitmap_size_bits = 512 * 1024;

	}

	else if (num_loaded_hashes <= 250100)
		bitmap_size_bits = 2048 * 1024;

	else if (num_loaded_hashes <= 1100100) {
		if (!amd_gcn_11(device_info[gpu_id]))
			bitmap_size_bits = 4096 * 1024;

		else
			bitmap_size_bits = 2048 * 1024;
	}
	assert(num_loaded_hashes <= 1100100);

	prepare_bitmap_4(bitmap_size_bits, &bitmaps, num_loaded_hashes);
}

static void prepare_table(struct db_main *db)
{
	struct db_salt *salt;

	max_num_loaded_hashes = 0;
	max_hash_table_size = 1;

	salt = db->salts;
	do {
		if (salt->count > max_num_loaded_hashes)
			max_num_loaded_hashes = salt->count;
	} while((salt = salt->next));

	MEM_FREE(loaded_hashes);
	MEM_FREE(hash_ids);
	release_salt_buffers();

	loaded_hashes = (cl_uint*) mem_alloc(4 * max_num_loaded_hashes * sizeof(cl_uint));
	hash_ids = (cl_uint*) mem_alloc((3 * max_num_loaded_hashes + 1) * sizeof(cl_uint));

	hash_tables = (unsigned int **)mem_alloc(sizeof(unsigned int*) * (db->salt_count + 1));
	buffer_offset_tables = (cl_mem *)mem_alloc(sizeof(cl_mem) * (db->salt_count + 1));
	buffer_hash_tables = (cl_mem *)mem_alloc(sizeof(cl_mem) * (db->salt_count + 1));
	buffer_bitmaps = (cl_mem *)mem_alloc(sizeof(cl_mem) * (db->salt_count + 1));
	buffer_salts = (cl_mem *)mem_alloc(sizeof(cl_mem) * (db->salt_count + 1));

	hash_tables[db->salt_count] = NULL;
	buffer_offset_tables[db->salt_count] = NULL;
	buffer_hash_tables[db->salt_count] = NULL;
	buffer_bitmaps[db->salt_count] = NULL;
	buffer_salts[db->salt_count] = NULL;

	salt = db->salts;
	do {
		unsigned int i = 0;
		unsigned int num_loaded_hashes, salt_params[SALT_SIZE / sizeof(unsigned int) + 5];
		unsigned int hash_table_size, offset_table_size, shift64_ht_sz, shift64_ot_sz;
		struct db_password *pw = salt->list;
		do {
			unsigned int *bin = (unsigned int *)pw->binary;
			// Potential segfault if removed
			if(bin != NULL) {
				loaded_hashes[4 * i] = bin[0];
				loaded_hashes[4 * i + 1] = bin[1];
				loaded_hashes[4 * i + 2] = bin[2];
				loaded_hashes[4 * i + 3] = bin[3];
				i++;
			}
		} while ((pw = pw -> next));

		if(i != salt->count) {
			fprintf(stderr,
				"Something went wrong while preparing hashes..Exiting..\n");
			error();
		}
		num_loaded_hashes = salt->count;

		num_loaded_hashes = create_perfect_hash_table(128, (void *)loaded_hashes,
				num_loaded_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size, 0);

		if (!num_loaded_hashes) {
			MEM_FREE(hash_table_128);
			fprintf(stderr, "Failed to create Hash Table for cracking.\n");
			error();
		}

		hash_tables[salt->sequential_id] = hash_table_128;

		buffer_offset_tables[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, offset_table_size * sizeof(OFFSET_TABLE_WORD), offset_table, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_offset_tables[].");

		buffer_hash_tables[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, hash_table_size * sizeof(unsigned int) * 2, hash_table_128, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_hash_tables[].");

		if (max_hash_table_size < hash_table_size)
			max_hash_table_size = hash_table_size;

		shift64_ht_sz = (((1ULL << 63) % hash_table_size) * 2) % hash_table_size;
		shift64_ot_sz = (((1ULL << 63) % offset_table_size) * 2) % offset_table_size;

		select_bitmap(num_loaded_hashes);

		memcpy(salt_params, salt->salt, SALT_SIZE);
		salt_params[12] = bitmap_size_bits - 1;
		salt_params[13] = offset_table_size;
		salt_params[14] = hash_table_size;
		salt_params[15] = shift64_ot_sz;
		salt_params[16] = shift64_ht_sz;

		buffer_bitmaps[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (size_t)(bitmap_size_bits >> 3) * 2, bitmaps, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmaps[].");

		buffer_salts[salt->sequential_id] = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, (SALT_SIZE / sizeof(unsigned int) + 5) * sizeof(unsigned int), salt_params, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_salts[].");

		MEM_FREE(bitmaps);
		MEM_FREE(offset_table);

	} while((salt = salt->next));
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = local_work_size ? (count + local_work_size - 1) / local_work_size * local_work_size : count;

	//fprintf(stderr, "%s(%d) lws "Zu" gws "Zu" idx %u int_cand%d\n", __FUNCTION__, count, local_work_size, global_work_size, key_idx, mask_int_cand.num_int_cand);

	// copy keys to the device
	if (key_idx)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_keys, CL_TRUE, 0, 4 * key_idx, saved_plain, 0, NULL, multi_profilingEvent[0]), "failed in clEnqueueWriteBuffer buffer_keys.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_idx, CL_TRUE, 0, 4 * global_work_size, saved_idx, 0, NULL, multi_profilingEvent[1]), "failed in clEnqueueWriteBuffer buffer_idx.");

	if (!is_static_gpu_mask)
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc, CL_TRUE, 0, 4 * global_work_size, saved_int_key_loc, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueWriteBuffer buffer_int_key_loc.");

#if CL_VERSION_1_2
	if (ocl_ver >= 120) {
		static int zero = 0;

		HANDLE_CLERROR(clEnqueueFillBuffer(queue[gpu_id], buffer_hash_ids, &zero, sizeof(cl_uint), 0, sizeof(cl_uint), 0, NULL, multi_profilingEvent[3]), "failed in clEnqueueFillBuffer buffer_hash_ids.");
		HANDLE_CLERROR(clEnqueueFillBuffer(queue[gpu_id], buffer_bitmap_dupe, &zero, sizeof(cl_uint), 0, sizeof(cl_uint) * (max_hash_table_size/32 + 1), 0, NULL, multi_profilingEvent[4]), "failed in clEnqueueFillBuffer buffer_bitmap_dupe.");
	}
#endif
	if (salt) {
		current_salt = salt->sequential_id;
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_salts[current_salt]), (void *) &buffer_salts[current_salt]), "Error setting argument 3.");
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(buffer_bitmaps[current_salt]), (void *) &buffer_bitmaps[current_salt]), "Error setting argument 6.");
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_offset_tables[current_salt]), (void *) &buffer_offset_tables[current_salt]), "Error setting argument 7.");
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(buffer_hash_tables[current_salt]), (void *) &buffer_hash_tables[current_salt]), "Error setting argument 8.");
	}

	HANDLE_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &global_work_size, lws, 0, NULL, multi_profilingEvent[5]), "failed in clEnqueueNDRangeKernel");

	HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), hash_ids, 0, NULL, multi_profilingEvent[6]), "failed in reading back num cracked hashes.");

	if (hash_ids[0] > max_num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_return_hashes, CL_TRUE, 0, 2 * sizeof(cl_uint) * hash_ids[0], loaded_hashes, 0, NULL, multi_profilingEvent[7]), "failed in reading back return_hashes.");
		HANDLE_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (3 * hash_ids[0] + 1) * sizeof(cl_uint), hash_ids, 0, NULL, multi_profilingEvent[8]), "failed in reading data back hash_ids.");
	}

	*pcount *=  mask_int_cand.num_int_cand;
	return hash_ids[0];
}

static int cmp_all(void *binary, int count)
{
	if (count) return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (((unsigned int*)binary)[0] ==
		hash_tables[current_salt][hash_ids[3 + 3 * index]]);
}

static int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) binary(source);

	if (t[2] != loaded_hashes[2 * index])
		return 0;
	if (t[3] != loaded_hashes[2 * index + 1])
		return 0;
	return 1;
}

static void auto_tune(struct db_main *db, long double kernel_run_ms)
{
	size_t gws_limit, gws_init;
	size_t lws_limit, lws_init;

	struct timeval startc, endc;
	long double time_ms = 0, old_time_ms = 0;

	size_t pcount, count;
	size_t i;

	int tune_gws, tune_lws;

	char key[PLAINTEXT_LENGTH + 1];
	unsigned int salt[SALT_SIZE/sizeof(unsigned int)];

	memset(key, 0xF5, PLAINTEXT_LENGTH);
	memset(salt, 0x35, (SALT_SIZE));
	key[PLAINTEXT_LENGTH] = 0;

	gws_limit = MIN((0xf << 22) * 4 / BUFSIZE,
			get_max_mem_alloc_size(gpu_id) / BUFSIZE);
	get_power_of_two(gws_limit);
	if (gws_limit > MIN((0xf << 22) * 4 / BUFSIZE,
		get_max_mem_alloc_size(gpu_id) / BUFSIZE))
		gws_limit >>= 1;

	lws_limit = get_kernel_max_lws(gpu_id, crypt_kernel);

	lws_init = get_kernel_preferred_multiple(gpu_id, crypt_kernel);

	if (gpu_amd(device_info[gpu_id]))
		gws_init = gws_limit >> 6;
	else if (gpu_nvidia(device_info[gpu_id]))
		gws_init = gws_limit >> 8;
	else
		gws_init = 1024;

	if (gws_init > gws_limit)
		gws_init = gws_limit;
	if (gws_init < lws_init)
		lws_init = gws_init;

	local_work_size = 0;
	global_work_size = 0;
	tune_gws = 1;
	tune_lws = 1;
	opencl_get_user_preferences(FORMAT_LABEL);
	if (local_work_size) {
		tune_lws = 0;
		if (local_work_size & (local_work_size - 1))
			get_power_of_two(local_work_size);
		if (local_work_size > lws_limit)
			local_work_size = lws_limit;
	}
	if (global_work_size)
		tune_gws = 0;

#if 0
	 fprintf(stderr, "lws_init:%zu lws_limit:%zu"
			 " gws_init:%zu gws_limit:%zu\n",
			  lws_init, lws_limit, gws_init,
			  gws_limit);
#endif
	/* Auto tune start.*/
	pcount = gws_init;
	count = 0;
#define calc_ms(start, end)	\
		((long double)(end.tv_sec - start.tv_sec) * 1000.000 + \
			(long double)(end.tv_usec - start.tv_usec) / 1000.000)
	if (tune_gws) {
		create_clobj_kpc(pcount);
		set_kernel_args_kpc();
		for (i = 0; i < pcount; i++)
			set_key(key, i);
		gettimeofday(&startc, NULL);
		if (db)
			crypt_all((int *)&pcount, db->salts);
		else {
			set_salt(salt);
			crypt_all((int *)&pcount, NULL);
		}
		gettimeofday(&endc, NULL);
		time_ms = calc_ms(startc, endc);
		count = (size_t)((kernel_run_ms / time_ms) * (long double)gws_init);
		get_power_of_two(count);
	}

	if (tune_gws && tune_lws)
		release_clobj_kpc();

	if (tune_lws) {
		count = tune_gws ? count : global_work_size;
		create_clobj_kpc(count);
		set_kernel_args_kpc();
		pcount = count;
		clear_keys();
		for (i = 0; i < pcount; i++)
			set_key(key, i);
		local_work_size = lws_init;
		gettimeofday(&startc, NULL);
		if (db)
			crypt_all((int *)&pcount, db->salts);
		else {
			set_salt(salt);
			crypt_all((int *)&pcount, NULL);
		}
		gettimeofday(&endc, NULL);
		old_time_ms = calc_ms(startc, endc);
		local_work_size = 2 * lws_init;

		while (local_work_size <= lws_limit) {
			gettimeofday(&startc, NULL);
			pcount = count;
			if (db)
				crypt_all((int *)&pcount, db->salts);
			else {
				set_salt(salt);
				crypt_all((int *)&pcount, NULL);
			}
			gettimeofday(&endc, NULL);
			time_ms = calc_ms(startc, endc);
			if (old_time_ms < time_ms) {
				local_work_size /= 2;
				break;
			}
			old_time_ms = time_ms;
			local_work_size *= 2;
		}

		if (local_work_size > lws_limit)
			local_work_size = lws_limit;
	}

	if (tune_gws && tune_lws) {
		if (old_time_ms > kernel_run_ms) {
			count /= 2;
		}
		else {
			count = (size_t)((kernel_run_ms / old_time_ms) * (long double)count);
			get_power_of_two(count);
		}
	}

	if (tune_gws) {
		if (count > gws_limit)
			count = gws_limit;
		release_clobj_kpc();
		create_clobj_kpc(count);
		set_kernel_args_kpc();
		global_work_size = count;
	}

	if (!tune_gws && !tune_lws) {
		create_clobj_kpc(global_work_size);
		set_kernel_args_kpc();
	}
	/* Auto tune finish.*/

	if (global_work_size % local_work_size) {
		global_work_size = GET_MULTIPLE_OR_BIGGER(global_work_size, local_work_size);
		get_power_of_two(global_work_size);
		release_clobj_kpc();
		if (global_work_size > gws_limit)
			global_work_size = gws_limit;
		create_clobj_kpc(global_work_size);
		set_kernel_args_kpc();
	}
	if (global_work_size > gws_limit) {
		release_clobj_kpc();
		global_work_size = gws_limit;
		create_clobj_kpc(global_work_size);
		set_kernel_args_kpc();
	}

	assert(!(local_work_size & (local_work_size -1)));
	assert(!(global_work_size % local_work_size));
	assert(local_work_size <= lws_limit);
	assert(global_work_size <= gws_limit);

	self->params.max_keys_per_crypt = global_work_size;
	if (options.verbosity > 3)
	fprintf(stdout, "%s GWS: %zu, LWS: %zu\n", db ? "Cracking" : "Self test",
			global_work_size, local_work_size);
#undef calc_ms
}

static void reset(struct db_main *db)
{
	static int initialized;

	if (initialized) {
		release_clobj_test();
		release_clobj();
		release_clobj_kpc();

		prepare_table(db);
		init_kernel();

		create_clobj();
		set_kernel_args();

		self->methods.set_salt = set_salt_no_op;
		auto_tune(db, 300);

	}
	else {
		unsigned int *binary_hash, i = 0;
		char *ciphertext;
		unsigned int salt_params[17];
		static unsigned int hash_table_size, offset_table_size, shift64_ht_sz, shift64_ot_sz;

		while (tests[max_num_loaded_hashes].ciphertext != NULL)
			max_num_loaded_hashes++;

		loaded_hashes = (cl_uint*)mem_alloc(16 * max_num_loaded_hashes);

		while (tests[i].ciphertext != NULL) {
			char **fields = tests[i].fields;
			if (!fields[1])
				fields[1] = tests[i].ciphertext;
			ciphertext = split(prepare(fields, &FMT_STRUCT), 0, &FMT_STRUCT);
			binary_hash = (unsigned int*)binary(ciphertext);
			loaded_hashes[4 * i] = binary_hash[0];
			loaded_hashes[4 * i + 1] = binary_hash[1];
			loaded_hashes[4 * i + 2] = binary_hash[2];
			loaded_hashes[4 * i + 3] = binary_hash[3];
			i++;
		}

		max_num_loaded_hashes = create_perfect_hash_table(128, (void *)loaded_hashes,
				max_num_loaded_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size, 0);

		if (!max_num_loaded_hashes) {
			MEM_FREE(hash_table_128);
			MEM_FREE(offset_table);
			fprintf(stderr, "Failed to create Hash Table for self test.\n");
			error();
		}

		hash_ids = (cl_uint*)mem_alloc((3 * max_num_loaded_hashes + 1) * sizeof(cl_uint));
		hash_tables = (unsigned int **)mem_alloc(2 * sizeof(unsigned int*));
		hash_tables[0] = hash_table_128;
		hash_tables[1] = NULL;
		current_salt = 0;

		select_bitmap(max_num_loaded_hashes);

		shift64_ht_sz = (((1ULL << 63) % hash_table_size) * 2) % hash_table_size;
		shift64_ot_sz = (((1ULL << 63) % offset_table_size) * 2) % offset_table_size;
		salt_params[12] = bitmap_size_bits - 1;
		salt_params[13] = offset_table_size;
		salt_params[14] = hash_table_size;
		salt_params[15] = shift64_ot_sz;
		salt_params[16] = shift64_ht_sz;
		max_hash_table_size = hash_table_size;

		init_kernel();

		buffer_salt_test = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, 17 * sizeof(cl_uint), salt_params, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_salt_test.");
		buffer_offset_table_test = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, offset_table_size * sizeof(OFFSET_TABLE_WORD), offset_table, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_offset_table_test.");
		buffer_bitmaps_test = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, (bitmap_size_bits >> 3) * 2, bitmaps, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmaps_test.");
		buffer_hash_table_test = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, hash_table_size * sizeof(unsigned int) * 2, hash_tables[current_salt], &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_hash_table_test.");

		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(buffer_salt_test), (void *) &buffer_salt_test), "Error setting argument 3.");
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(buffer_bitmaps_test), (void *) &buffer_bitmaps_test), "Error setting argument 6.");
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_offset_table_test), (void *) &buffer_offset_table_test), "Error setting argument 7.");
		HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(buffer_hash_table_test), (void *) &buffer_hash_table_test), "Error setting argument 8.");

		create_clobj();
		set_kernel_args();

		hash_ids[0] = 0;
		MEM_FREE(offset_table);
		MEM_FREE(bitmaps);
		auto_tune(NULL, 50);

		initialized++;
	}
}

struct fmt_main FMT_STRUCT = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
