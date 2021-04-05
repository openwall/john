/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012-2016 Claudio André <claudioandre.br at gmail.com>
 * This program comes with ABSOLUTELY NO WARRANTY; express or implied .
 * This is free software, and you are welcome to redistribute it
 * under certain conditions; as expressed here
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_rawsha512_gpl;
extern struct fmt_main fmt_opencl_xsha512_gpl;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_rawsha512_gpl);
john_register_one(&fmt_opencl_xsha512_gpl);
#else

#include <string.h>

#include "sha2.h"
#include "johnswap.h"
#include "opencl_common.h"
#include "config.h"
#include "options.h"
#include "../run/opencl/opencl_rawsha512.h"
#include "rawSHA512_common.h"

#include "mask_ext.h"
#include "../run/opencl/opencl_mask_extras.h"

#define FORMAT_LABEL            "raw-SHA512-opencl"
#define FORMAT_NAME         ""

#define X_FORMAT_LABEL          "XSHA512-opencl"
#define X_FORMAT_NAME           "Mac OS X 10.7 salted"

#define ALGORITHM_NAME          "SHA512 OpenCL"

#define BINARY_SIZE             DIGEST_SIZE

static sha512_salt *salt;

//plaintext: keys to compute the hash function
//saved_idx: offset and length of each plaintext (data is sent using chunks)
static uint32_t *plaintext, *saved_idx;

static cl_mem salt_buffer;      //Salt information.
static cl_mem pass_buffer;      //Plaintext buffer.
static cl_mem idx_buffer;       //Sizes and offsets buffer.
static cl_kernel prepare_kernel;

//Pinned buffers
static cl_mem pinned_plaintext, pinned_saved_idx, pinned_int_key_loc;

//Reference to self
static struct fmt_main *self;

//Reference to the first element in salt list
static struct db_main *main_db;

//Device (GPU) buffers
//int_keys: mask to apply
//hash_ids: information about how recover the cracked password
//bitmap: a bitmap memory space.
//int_key_loc: the position of the mask to apply.
static cl_mem buffer_int_keys, buffer_hash_ids, buffer_bitmap, buffer_int_key_loc;

//Host buffers
//saved_int_key_loc: the position of the mask to apply
//num_loaded_hashes: number of binary hashes transferred/loaded to GPU
//hash_ids: information about how recover the cracked password
static uint32_t *saved_int_key_loc, num_loaded_hashes, *hash_ids, *saved_bitmap;

//ocl_initialized: a reference counter of the openCL objetcts (expect to be 0 or 1)
static unsigned ocl_initialized = 0;

// Keeps track of whether we should tune for this reset() call.
static int should_tune;

//Used to control partial key transfers.
static uint32_t key_idx = 0;
static size_t offset = 0, offset_idx = 0;
static int new_keys, salted_format = 0;

static uint32_t bitmap_size, previous_size;

static void load_hash();
static char *get_key(int index);
static void build_kernel();
static void release_kernel();
static void release_mask_buffers(void);

//This file contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	size_t s;

	s = autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
	s = MIN(s, autotune_get_task_max_work_group_size(FALSE, 0,
	        prepare_kernel));
	return MIN(s, 512);
}

static uint32_t get_num_loaded_hashes()
{
	uint32_t num_hashes;
	struct db_salt *current_salt;

	num_hashes = 0;
	current_salt = main_db->salts;

	do
		num_hashes += current_salt->count;
	while ((current_salt = current_salt->next));

	return num_hashes;
}

static uint64_t *crypt_one(int index) {
	SHA512_CTX ctx;
	static uint64_t hash[DIGEST_SIZE / sizeof(uint64_t)];

	char * key = get_key(index);
	int len = strlen(key);

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, key, len);
	SHA512_Final((unsigned char *) (hash), &ctx);

	alter_endianity_to_BE64(hash, DIGEST_SIZE / sizeof(uint64_t));

	return hash;
}

static uint64_t *crypt_one_x(int index) {
	SHA512_CTX ctx;
	static uint64_t hash[DIGEST_SIZE / sizeof(uint64_t)];

	char * key = get_key(index);
	int len = strlen(key);

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, (char *) &salt->salt, SALT_SIZE_X);
	SHA512_Update(&ctx, key, len);
	SHA512_Final((unsigned char *) (hash), &ctx);

	alter_endianity_to_BE64(hash, DIGEST_SIZE / sizeof(uint64_t));

	return hash;
}

/* ------- Create and destroy necessary objects ------- */
static void create_mask_buffers()
{
	release_mask_buffers();

	saved_bitmap = (uint32_t *)
		mem_alloc((bitmap_size / 32 + 1) * sizeof(uint32_t));
	buffer_bitmap = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY,
		(bitmap_size / 32 + 1) * sizeof(uint32_t), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap");

	//Set crypt kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(buffer_bitmap),
	                              (void *)&buffer_bitmap), "Error setting argument 7");
}

static void release_mask_buffers()
{
	MEM_FREE(saved_bitmap);

	if (buffer_bitmap)
		clReleaseMemObject(buffer_bitmap);
	buffer_bitmap = NULL;
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	uint32_t hash_id_size;
	size_t mask_cand = 1, mask_gws = 1;

	release_clobj();

	if (mask_int_cand.num_int_cand > 1) {
		mask_cand = mask_int_cand.num_int_cand;
		mask_gws = gws;
	}

	pinned_plaintext = clCreateBuffer(context[gpu_id],
	                                  CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
	                                  BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
	               "Error creating page-locked memory pinned_plaintext");

	plaintext = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
	            pinned_plaintext, CL_TRUE, CL_MAP_WRITE, 0,
	            BUFFER_SIZE * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory plaintext");

	pinned_saved_idx = clCreateBuffer(context[gpu_id],
	                                  CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
	                                  sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
	               "Error creating page-locked memory pinned_saved_idx");

	saved_idx = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
	            pinned_saved_idx, CL_TRUE, CL_MAP_WRITE, 0,
	            sizeof(uint32_t) * gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error mapping page-locked memory saved_idx");

	// create arguments (buffers)
	salt_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                             sizeof(sha512_salt), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating salt_buffer out argument");

	pass_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                             BUFFER_SIZE * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument pass_buffer");

	idx_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
	                            sizeof(uint32_t) * gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument idx_buffer");

	hash_id_size = mask_int_cand.num_int_cand * gws;
	hash_ids = (uint32_t *) mem_alloc(
		hash_id_size * 3 * sizeof(uint32_t) + sizeof(uint32_t));
	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE,
		hash_id_size * 3 * sizeof(uint32_t) + sizeof(uint32_t),
		NULL, &ret_code);

	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_buffer_hash_ids");

	//Mask mode
	pinned_int_key_loc = clCreateBuffer(context[gpu_id],
					    CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
					    sizeof(uint32_t) * mask_gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
		       "Error creating page-locked memory pinned_int_key_loc");

	saved_int_key_loc = (uint32_t *) clEnqueueMapBuffer(queue[gpu_id],
			    pinned_int_key_loc, CL_TRUE, CL_MAP_WRITE, 0,
			    sizeof(uint32_t) * mask_gws, 0, NULL, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
		       "Error mapping page-locked memory saved_int_key_loc");

	buffer_int_key_loc = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
					    sizeof(uint32_t) * mask_gws, NULL, &ret_code);
	HANDLE_CLERROR(ret_code,
		       "Error creating buffer argument buffer_int_key_loc");

	buffer_int_keys = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY,
					 4 * mask_cand, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_int_keys");

	//Set prepare kernel arguments
	HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 0, sizeof(cl_uint),
	                              (void *)&mask_int_cand.num_int_cand), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(prepare_kernel, 1, sizeof(buffer_hash_ids),
	                              (void *)&buffer_hash_ids), "Error setting argument 1");

	//Set kernel arguments
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(cl_mem),
	                              (void *)&salt_buffer), "Error setting argument 0");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(cl_mem),
	                              (void *)&pass_buffer), "Error setting argument 1");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(cl_mem),
	                              (void *)&idx_buffer), "Error setting argument 2");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(buffer_int_key_loc),
	                              (void *)&buffer_int_key_loc), "Error setting argument 3");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(buffer_int_keys),
	                              (void *)&buffer_int_keys), "Error setting argument 4");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(cl_uint),
				      (void *)&(mask_int_cand.num_int_cand)),
	               "Error setting argument 5");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_hash_ids),
	                              (void *)&buffer_hash_ids), "Error setting argument 6");

	//Indicates that the OpenCL objetcs are initialized.
	ocl_initialized++;

	//Assure buffers have no "trash data".
	memset(plaintext, '\0', BUFFER_SIZE * gws);
	memset(saved_idx, '\0', sizeof(uint32_t) * gws);
	memset(saved_int_key_loc, '\0', sizeof(uint32_t) * mask_gws);
}

static void release_clobj()
{
	cl_int ret_code;

	if (ocl_initialized) {
		ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_plaintext,
		                                   plaintext, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Error Unmapping keys");
		ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_saved_idx,
		                                   saved_idx, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Error Unmapping indexes");
		ret_code = clEnqueueUnmapMemObject(queue[gpu_id], pinned_int_key_loc,
		                                   saved_int_key_loc, 0, NULL, NULL);
		HANDLE_CLERROR(ret_code, "Error Unmapping key locations");

		ret_code = clReleaseMemObject(salt_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing salt_buffer");
		ret_code = clReleaseMemObject(pass_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing pass_buffer");
		ret_code = clReleaseMemObject(idx_buffer);
		HANDLE_CLERROR(ret_code, "Error Releasing idx_buffer");

		MEM_FREE(hash_ids);
		clReleaseMemObject(buffer_hash_ids);
		HANDLE_CLERROR(ret_code, "Error Releasing buffer_hash_ids");

		ret_code = clReleaseMemObject(buffer_int_key_loc);
		HANDLE_CLERROR(ret_code, "Error Releasing buffer_int_key_loc");
		ret_code = clReleaseMemObject(buffer_int_keys);
		HANDLE_CLERROR(ret_code, "Error Releasing buffer_int_keys");
		ret_code = clReleaseMemObject(pinned_plaintext);
		HANDLE_CLERROR(ret_code, "Error Releasing pinned_plaintext");
		ret_code = clReleaseMemObject(pinned_saved_idx);
		HANDLE_CLERROR(ret_code, "Error Releasing pinned_saved_idx");
		ret_code = clReleaseMemObject(pinned_int_key_loc);
		HANDLE_CLERROR(ret_code, "Error Releasing pinned_int_key_loc");

		ocl_initialized = 0;
		HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory");
	}
}

/* ------- Salt functions ------- */
static void *get_salt(char *ciphertext)
{
	static union {
		unsigned char c[SALT_SIZE_X];
		ARCH_WORD dummy;
	} out;
	char *p;
	int i;
	ciphertext += XSHA512_TAG_LENGTH;
	p = ciphertext;
	for (i = 0; i < sizeof(out.c); i++) {
		out.c[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out.c;
}

static void set_salt(void *salt_info)
{

	salt = salt_info;

	//Send salt information to GPU.
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], salt_buffer, CL_FALSE,
	                                    0, sizeof(sha512_salt), salt, 0, NULL, NULL),
	               "failed in clEnqueueWriteBuffer salt_buffer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
}

static int salt_hash(void *salt)
{

	return common_salt_hash(salt, SALT_SIZE_X, SALT_HASH_SIZE);
}

/* ------- Reset functions ------- */
static void tune(struct db_main *db)
{
	char *tmp_value;
	size_t gws_limit;
	int autotune_limit = 500;

	if ((tmp_value = getenv("_GPU_AUTOTUNE_LIMIT")))
		autotune_limit = atoi(tmp_value);

	// Auto-tune / Benckmark / Self-test.
	gws_limit = MIN((0xf << 22) * 4 / BUFFER_SIZE,
			get_max_mem_alloc_size(gpu_id) / BUFFER_SIZE);

	if (options.flags & FLG_MASK_CHK)
		gws_limit = MIN(gws_limit,
			get_max_mem_alloc_size(gpu_id) /
			(mask_int_cand.num_int_cand  * 3 * sizeof(uint32_t)));

	//Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL,
			       warn, 3, self, create_clobj, release_clobj,
			       2 * BUFFER_SIZE, gws_limit, db);

	//Auto tune execution from shared/included code.
	autotune_run(self, 1, gws_limit, autotune_limit);
}

static void reset(struct db_main *db)
{
	offset = 0;
	offset_idx = 0;
	key_idx = 0;

	main_db = db;
	num_loaded_hashes = get_num_loaded_hashes();

	//Adjust kernel parameters and rebuild (if necessary).
	build_kernel();

	tune(db);

	hash_ids[0] = 0;
	load_hash();
}

/* ------- Key functions ------- */
static void clear_keys(void)
{
	offset = 0;
	offset_idx = 0;
	key_idx = 0;
}

static void set_key(char *_key, int index)
{

	const uint32_t *key = (uint32_t *) _key;
	int len = strlen(_key);

	saved_idx[index] = (key_idx << 6) | len;

	do {
		plaintext[key_idx++] = *key++;
		len -= 4;
	} while (len > 4);

	if (len > 0)
		plaintext[key_idx++] = *key;

	//Mask Mode ranges setup
	if (mask_int_cand.num_int_cand > 1) {
		int i;

		saved_int_key_loc[index] = 0;

		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {

			if (mask_skip_ranges[i] != -1) {
				saved_int_key_loc[index] |=
				    ((mask_int_cand.int_cpu_mask_ctx->
				      ranges[mask_skip_ranges[i]].offset +
				      mask_int_cand.int_cpu_mask_ctx->
				      ranges[mask_skip_ranges[i]].pos) & 0xff)
				    << (i << 3);
			} else
				saved_int_key_loc[index] |= 0x80 << (i << 3);
		}
	}
	//Batch transfers to GPU.
	if ((index % TRANSFER_SIZE) == 0 && (index > 0)) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer,
		                                    CL_FALSE, sizeof(uint32_t) * offset,
		                                    sizeof(uint32_t) * TRANSFER_SIZE,
		                                    plaintext + offset, 0, NULL, NULL),
		               "failed in clEnqueueWriteBuffer pass_buffer");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer,
		                                    CL_FALSE, sizeof(uint32_t) * offset,
		                                    sizeof(uint32_t) * TRANSFER_SIZE,
		                                    saved_idx + offset, 0, NULL, NULL),
		               "failed in clEnqueueWriteBuffer idx_buffer");

		HANDLE_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
		offset += TRANSFER_SIZE;
		offset_idx = key_idx;
	}
	new_keys = 1;
}

static char *get_key(int index)
{
	static char *ret;
	int int_index, t, i;

	if (!ret)
		ret = mem_alloc_tiny(PLAINTEXT_LENGTH + 1, MEM_ALIGN_WORD);

	//Mask Mode plaintext recovery
	if (hash_ids == NULL || hash_ids[0] == 0 || index > hash_ids[0]) {
		t = index;
		int_index = 0;

	} else {
		t = hash_ids[1 + 3 * index];
		int_index = hash_ids[2 + 3 * index];
	}

	//Mask Mode plaintext recovery.
	if (t >= global_work_size)
		t = 0;

	memcpy(ret, ((char *)&plaintext[saved_idx[t] >> 6]), PLAINTEXT_LENGTH);
	ret[saved_idx[t] & 63] = '\0';

	if (saved_idx[t] & 63 &&
	    mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			ret[(saved_int_key_loc[t] & (0xff << (i * 8))) >> (i * 8)] =
			    mask_int_cand.int_cand[int_index].x[i];
	}

	return ret;

}

/* ------- Initialization  ------- */
static void build_kernel()
{
	static int num_int_cand;

	char *task = "$JOHN/opencl/sha512_gpl_kernel.cl";
	char opt[MAX_OCLINFO_STRING_LEN];

	bitmap_size = get_bitmap_size_bits(num_loaded_hashes, gpu_id);

	if (previous_size != bitmap_size || num_int_cand != mask_int_cand.num_int_cand) {
		previous_size = bitmap_size;
		num_int_cand = mask_int_cand.num_int_cand;

		release_kernel();

		snprintf(opt, sizeof(opt), "-DBITMAP_SIZE_MINUS1=%u", bitmap_size - 1U);

		if (mask_int_cand.num_int_cand > 1)
			strncat(opt, " -DGPU_MASK_MODE", 64U);

		opencl_build_kernel(task, gpu_id, opt, 0);

		// create kernel(s) to execute
		prepare_kernel = clCreateKernel(program[gpu_id], "kernel_prepare",
						&ret_code);
		HANDLE_CLERROR(ret_code,
			       "Error creating kernel_prepare. Double-check kernel name?");

		if (salted_format)
			crypt_kernel = clCreateKernel(program[gpu_id],
						      "kernel_crypt_xsha", &ret_code);
		else
			crypt_kernel = clCreateKernel(program[gpu_id],
						      "kernel_crypt_raw", &ret_code);
		HANDLE_CLERROR(ret_code,
			       "Error creating kernel. Double-check kernel name?");
	}
	//Allocate bit array and pass its size to OpenCL.
	create_mask_buffers();
}

static void release_kernel()
{
	if (program[gpu_id]) {
		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseKernel(prepare_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void init_common(struct fmt_main *_self)
{
	char *tmp_value;

	self = _self;
	opencl_prepare_dev(gpu_id);
	mask_int_cand_target = opencl_speed_index(gpu_id) / 300;
	previous_size = 0;

	if ((tmp_value = getenv("_GPU_MASK_CAND")))
		mask_int_cand_target = atoi(tmp_value);
}

static void init_raw(struct fmt_main *_self)
{
	salted_format = 0;
	init_common(_self);
}

static void init_x(struct fmt_main *_self)
{
	salted_format = 1;
	init_common(_self);
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();
		release_kernel();
		release_mask_buffers();
	}
	should_tune = 0;
	ocl_initialized = 0;
}

static void prepare_bit_array()
{
	uint64_t *binary;
	struct db_password *pw;
	struct db_salt *current_salt;

	current_salt = main_db->salts;
#ifdef DEBUG
	fprintf(stderr, "Clear bitmap array\n");
#endif
	memset(saved_bitmap, '\0', (bitmap_size / 8 + 1));

	do {
		pw = current_salt->list;

		do {
			unsigned int bit_mask_x, bit_mask_y;
			binary = (uint64_t *) pw->binary;

			// Skip cracked.
			if (binary) {
				SPREAD_64(binary[0], binary[1], (bitmap_size - 1U),
					bit_mask_x, bit_mask_y)
#ifdef DEBUG
				if (saved_bitmap[bit_mask_x >> 5] & (1U << (bit_mask_x & 31)) &&
				    saved_bitmap[bit_mask_y >> 5] & (1U << (bit_mask_y & 31)))
					fprintf(stderr, "Collision: %u %08x %08x %08x %08x\n",
						num_loaded_hashes, (unsigned int) binary[0],
						bit_mask_x, bit_mask_y,
						saved_bitmap[bit_mask_x >> 5]);
#endif
				saved_bitmap[bit_mask_x >> 5] |= (1U << (bit_mask_x & 31));
				saved_bitmap[bit_mask_y >> 5] |= (1U << (bit_mask_y & 31));
			}
		} while ((pw = pw->next));

	} while ((current_salt = current_salt->next));
}

/* ------- Send hashes to crack (binary) to GPU ------- */
static void load_hash()
{
	num_loaded_hashes = get_num_loaded_hashes();

	prepare_bit_array();

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap, CL_TRUE, 0,
		(bitmap_size / 32 + 1) * sizeof(uint32_t),
	        saved_bitmap, 0, NULL, NULL),
	        "failed in clEnqueueWriteBuffer buffer_bitmap");

	HANDLE_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
}

/* ------- Crypt function ------- */
static int crypt_all(int *pcount, struct db_salt *_salt)
{
	const int count = *pcount;
	size_t gws;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	gws = GET_NEXT_MULTIPLE(count, local_work_size);

	//Check if any password was cracked and reload (if necessary)
	if (num_loaded_hashes != get_num_loaded_hashes())
		load_hash();

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1,
	                                     NULL, &gws, lws, 0, NULL, multi_profilingEvent[0]),
	              "failed in clEnqueueNDRangeKernel I");

	//Send data to device.
	if (new_keys && key_idx > offset)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pass_buffer,
		                                   CL_FALSE, sizeof(uint32_t) * offset,
		                                   sizeof(uint32_t) * (key_idx - offset), plaintext + offset, 0,
		                                   NULL, multi_profilingEvent[1]),
		              "failed in clEnqueueWriteBuffer pass_buffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], idx_buffer, CL_FALSE,
	                                   sizeof(uint32_t) * offset,
	                                   sizeof(uint32_t) * (gws - offset),
	                                   saved_idx + offset, 0, NULL, multi_profilingEvent[2]),
	              "failed in clEnqueueWriteBuffer idx_buffer");

	if (new_keys && mask_int_cand.num_int_cand > 1) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_key_loc,
		                                   CL_FALSE, 0, 4 * gws, saved_int_key_loc, 0, NULL,
		                                   multi_profilingEvent[5]),
		              "failed in clEnqueueWriteBuffer buffer_int_key_loc");

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_int_keys,
		                                   CL_FALSE, 0, 4 * mask_int_cand.num_int_cand,
		                                   mask_int_cand.int_cand, 0, NULL, multi_profilingEvent[6]),
		              "failed in clEnqueueWriteBuffer buffer_int_keys");
	}
	//Enqueue the kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
	                                     &gws, lws, 0, NULL, multi_profilingEvent[3]),
	              "failed in clEnqueueNDRangeKernel");

	//Possible cracked hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_FALSE,
	                                  0, sizeof(uint32_t), hash_ids,
	                                  0, NULL, multi_profilingEvent[4]),
	              "failed in reading data back buffer_hash_ids");

	//Do the work
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

#ifdef DEBUG
	if (hash_ids[0])
		fprintf(stderr, "Some checks are going to be done on CPU: %u: %1.4f%%\n", hash_ids[0],
			((double) hash_ids[0]) / (global_work_size * mask_int_cand.num_int_cand) * 100);
#endif
	if (hash_ids[0] > global_work_size * mask_int_cand.num_int_cand) {
		fprintf(stderr, "Error, crypt_all() kernel: %u.\n", hash_ids[0]);
		error();
	}

	if (hash_ids[0]) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_FALSE,
			0, (hash_ids[0] * 3 * sizeof(uint32_t) + sizeof(uint32_t)), hash_ids,
						  0, NULL, NULL),
			      "failed in reading data back buffer_hash_ids");

		//Do the work
		BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	}
	*pcount *= mask_int_cand.num_int_cand;
	return hash_ids[0];
}

/* ------- Compare functins ------- */
static int cmp_all(void *binary, int count)
{
	return (count > 0);
}

static int cmp_one(void *binary, int index)
{
	return (hash_ids[3 + 3 * index] == ((uint32_t *) binary)[0]);
}

static int cmp_exact_raw(char *source, int index)
{
	uint64_t *binary;
	uint64_t *full_hash;

#ifdef DEBUG
	fprintf(stderr, "Stressing CPU\n");
#endif
	binary = (uint64_t *) sha512_common_binary_BE(source);

	full_hash = crypt_one(index);
	return !memcmp(binary, (void *) full_hash, BINARY_SIZE);
}

static int cmp_exact_x(char *source, int index)
{
	uint64_t *binary;
	uint64_t *full_hash;

#ifdef DEBUG
	fprintf(stderr, "Stressing CPU\n");
#endif
	binary = (uint64_t *) sha512_common_binary_xsha512_BE(source);

	full_hash = crypt_one_x(index);
	return !memcmp(binary, (void *) full_hash, BINARY_SIZE);
}

//Get Hash functions group.
static int get_hash_0(int index)
{
	return hash_ids[3 + 3 * index] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return hash_ids[3 + 3 * index] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return hash_ids[3 + 3 * index] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return hash_ids[3 + 3 * index] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return hash_ids[3 + 3 * index] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return hash_ids[3 + 3 * index] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return hash_ids[3 + 3 * index] & PH_MASK_6;
}

/* ------- Format structure ------- */
struct fmt_main fmt_opencl_rawsha512_gpl = {
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
		SALT_SIZE_RAW,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_MASK,
		{NULL},
		{FORMAT_TAG},
		sha512_common_tests_rawsha512_20
	}, {
		init_raw,
		done,
		reset,
		fmt_default_prepare,
		sha512_common_valid,
		sha512_common_split,
		sha512_common_binary_BE,
		fmt_default_salt,
		{NULL},
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
		cmp_exact_raw
	}
};

struct fmt_main fmt_opencl_xsha512_gpl = {
	{
		X_FORMAT_LABEL,
		X_FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		XSHA512_BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE_X,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_MASK,
		{NULL},
		{
			XSHA512_FORMAT_TAG
		},
		sha512_common_tests_xsha512
	}, {
		init_x,
		done,
		reset,
		sha512_common_prepare_xsha512,
		sha512_common_valid_xsha512,
		sha512_common_split_xsha512,
		sha512_common_binary_xsha512_BE,
		get_salt,
		{NULL},
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
		cmp_exact_x
	}
};

#endif                          /* plugin stanza */

#endif                          /* HAVE_OPENCL */
