/*
 * Developed by Claudio André <claudioandre.br at gmail.com> in 2012
 * Based on source code provided by Samuele Giovanni Tonon
 *
 * More information at http://openwall.info/wiki/john/OpenCL-RAWSHA-512
 * More information at http://openwall.info/wiki/john/OpenCL-XSHA-512
 *
 * Copyright (c) 2011 Samuele Giovanni Tonon <samu at linuxasylum dot net>
 * Copyright (c) 2012-2020 Claudio André <claudioandre.br at gmail.com>
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

#include "sha.h"
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
#define FORMAT_NAME             ""

#define X_FORMAT_LABEL          "XSHA512-opencl"
#define X_FORMAT_NAME           "Mac OS X 10.7 salted"

#define ALGORITHM_NAME          "SHA512 OpenCL"

#define BINARY_SIZE             DIGEST_SIZE
#define CRACK_VAR_SIZE          (3 * sizeof(uint32_t))
#define CRACK_HEAD_SIZE         (sizeof(uint32_t))
#define CRACK_POS               (3 * index + 3)

//Salt struct used only by xSHA512.
static sha512_salt *salt;

//Reference to self.
static struct fmt_main *self;

//Main db. Used here to get the reference of first element in salt list.
static struct db_main *main_db;

/*                     ###    Host vars and buffers   ###
 * num_loaded_hashes: number of binary hashes transferred/loaded to GPU.
 * cracks: information on how to recover (position/location) of the password (maybe) cracked.
 *         - cracks[0]: number of "possible cracks" (partial matches);
 *           - cracks[3 * index + 1]: get_global_id(0);
 *           - cracks[3 * index + 2]: iter (mask from 1 to candidates_number);
 *           - cracks[3 * index + 3]: 32 low bits of the calculated hash.
 *
 *         - cracks[n] => ARRAY-HEAD + (ARRAY-SIZE * index) + pos
 *           - cracks[CRACK_POS] => 1 + 3 * index + 2
 *           - cracks[CRACK_POS] => 3 * index + 3
 * bitmap: bitmap (a buffer) used to speed up searches and disposals.
 */
static uint32_t *cracks, *bitmap, num_loaded_hashes;

/*
 * Variables to set and control partial key transfers.
 * - we are copying to device less than GWS keys/plaintexts.
 */
static uint32_t key_idx;
static size_t offset, offset_idx;

/*
 * Flags to control:
 * - if new keys have to be transfered to device;
 * - if a salted_format is running.
 */
 static int new_keys, salted_format;

// To signal if the bitmap needs to be rebuild.
static uint32_t bitmap_size, bitmap_prev_size;

/*
 * plaintext: the colection of keys (plaintexts) that we will calculate
 *            the hash using the OpenCL device.
 * saved_idx: the offset and the length of each plaintext (note that data
 *            is sent using chunks, to start cracking as soon as possible).
 * mask_int_key_loc: mask information. Some mask information that needs to
 *                   be defined in set_key ().
 */
static uint32_t *plaintext, *saved_idx, *mask_int_key_loc;

/*                         ###   Pinned buffers   ###
 * Pinned memory refers to a memory that in addition to being on a device,
 * exists in the host, so DMA transfers is possible between these 2 memories,
 * increasing copy performance.
 */
static cl_mem pinned_plaintext, pinned_saved_idx, pinned_int_key_loc;

/*                         ###   Device buffers (GPU)   ###
 * cracks: information on how to recover (position/location) of the password (maybe) cracked.
 * bitmap: bitmap (a buffer on device) used to speed up searches and disposals.
 * int_keys: mask internals (information about the mask and its expansion).
 */
static cl_mem dev_cracks, dev_bitmap, dev_int_keys;

/*
 * salt_buffer: on device salt buffer.
 * prepare_kernel: OpenCL kernel used to prepare the device (cleans and
 *                 prepares the device memory).
 */
static cl_mem salt_buffer;
static cl_kernel prepare_kernel;

//ocl_initialized: a reference counter of the openCL objetcts (should be 0 or 1).
static unsigned ocl_initialized;

static char *get_key(int index);
static void build_kernel(void);
static void load_hash(void);
static void release_kernel(void);
static void release_bitmap_buffers(void);

//Contains auto-tuning routine(s). It has to be included after formats definitions.
#include "opencl_autotune.h"

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	//TODO: Refactor autotune and remove me.
	//      move get_task_max_work_group_size to shared code
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

static uint64_t *crypt_one(int index)
{
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

static uint64_t *crypt_one_x(int index)
{
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
static void set_kernel_args()
{
	//Set the preparation kernel arguments (cleans and prepares the device memory)
	CLKERNELARGx(prepare_kernel, 0, mask_int_cand.num_int_cand);
	CLKERNELARGx(prepare_kernel, 1, dev_cracks);

	//Set the crypt kernel arguments (runs sha512_block())
	CLKERNELARGx(crypt_kernel, 0, salt_buffer);
	CLKERNELARGx(crypt_kernel, 1, pinned_plaintext);
	CLKERNELARGx(crypt_kernel, 2, pinned_saved_idx);
	CLKERNELARGx(crypt_kernel, 3, pinned_int_key_loc);
	CLKERNELARGx(crypt_kernel, 4, dev_int_keys);
	CLKERNELARGx(crypt_kernel, 5, mask_int_cand.num_int_cand);
	CLKERNELARGx(crypt_kernel, 6, dev_cracks);
}

static void set_kernel_bitmap()
{
	//Set crypt kernel arguments
	CLKERNELARGx(crypt_kernel, 7, dev_bitmap);
}

static void create_bitmap_buffers()
{
	release_bitmap_buffers();

	opencl_create_buf_pair((void *) &bitmap, &dev_bitmap,
	    CL_MEM_WRITE_ONLY, (bitmap_size / 32 + 1) * sizeof(uint32_t), CL_NO_TRACK);

	set_kernel_bitmap();
}

static void release_bitmap_buffers()
{
	MEM_FREE(bitmap);
	opencl_release_buf(&dev_bitmap);
}

static void create_clobj(size_t gws, struct fmt_main *self)
{
	uint32_t max_cracks;
	size_t mask_cand = 1, mask_gws = 1;

	release_clobj();

	if (mask_int_cand.num_int_cand > 1) {
		mask_cand = mask_int_cand.num_int_cand;
		mask_gws = gws;
	}
	// create pinned buffers
	opencl_create_map(
		CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, BUFFER_SIZE * gws,
		&pinned_plaintext,     /* buffer created on device */
		(void *) &plaintext);  /* mapped buffer created on host */

	opencl_create_map(
		CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(uint32_t) * gws,
		&pinned_saved_idx,    /* buffer created on device */
		(void *) &saved_idx); /* mapped buffer created on host */

	// create arguments buffers: keys, salt and index for batch transfer
	opencl_create_buf(&salt_buffer, CL_MEM_READ_ONLY, sizeof(sha512_salt), CL_TRACK);

	max_cracks = mask_int_cand.num_int_cand * gws;
	{
		uint32_t tmp_value = max_cracks * CRACK_VAR_SIZE + CRACK_HEAD_SIZE;
		opencl_create_buf_pair((void *) &cracks, &dev_cracks, CL_MEM_READ_WRITE, tmp_value, CL_TRACK);
	}
	//Mask mode
	opencl_create_map(
		CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(uint32_t) * mask_gws,
		&pinned_int_key_loc,          /* buffer created on device */
		(void *) &mask_int_key_loc);  /* mapped buffer created on host */

	opencl_create_buf(&dev_int_keys, CL_MEM_READ_ONLY, 4 * mask_cand, CL_TRACK);

	set_kernel_args();
	set_kernel_bitmap();

	//Indicates that the OpenCL objetcs are initialized.
	ocl_initialized++;

	//Assure buffers have no "trash data".
	memset(plaintext, '\0', BUFFER_SIZE * gws);
	memset(saved_idx, '\0', sizeof(uint32_t) * gws);
	memset(mask_int_key_loc, 0x80, sizeof(uint32_t) * mask_gws);
}

static void release_clobj()
{
	if (ocl_initialized) {
		opencl_release_map();
		opencl_release_buf(NULL);
	}
#ifdef DEBUG
	if (ocl_initialized > 1)
		fprintf(stderr, "Leaks were detected in this format\n");
#endif
	ocl_initialized = 0;
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
			(mask_int_cand.num_int_cand  * CRACK_VAR_SIZE));

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

	cracks[0] = 0;
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

		mask_int_key_loc[index] = 0;

		for (i = 0; i < MASK_FMT_INT_PLHDR; i++) {

			if (mask_skip_ranges[i] != -1) {
				mask_int_key_loc[index] |=
				    ((mask_int_cand.int_cpu_mask_ctx->
				      ranges[mask_skip_ranges[i]].offset +
				      mask_int_cand.int_cpu_mask_ctx->
				      ranges[mask_skip_ranges[i]].pos) & 0xff)
				    << (i << 3);
			} else
				mask_int_key_loc[index] |= 0x80 << (i << 3);
		}
	}
	//Batch transfers to GPU.
	if ((index % TRANSFER_SIZE) == 0 && (index > 0)) {
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pinned_plaintext,
		                                    CL_FALSE, sizeof(uint32_t) * offset,
		                                    sizeof(uint32_t) * TRANSFER_SIZE,
		                                    plaintext + offset, 0, NULL, NULL),
		               "failed in clEnqueueWriteBuffer pass_buffer");
		HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pinned_saved_idx,
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
	if (cracks == NULL || cracks[0] == 0 || index > cracks[0]) {
		t = index;
		int_index = 0;

	} else {
		t = cracks[1 + 3 * index];
		int_index = cracks[2 + 3 * index];
	}

	//Mask Mode plaintext recovery.
	if (t >= global_work_size)
		t = 0;

	memcpy(ret, ((char *)&plaintext[saved_idx[t] >> 6]), PLAINTEXT_LENGTH);
	ret[saved_idx[t] & 63] = '\0';

	if (saved_idx[t] & 63 &&
	    mask_skip_ranges && mask_int_cand.num_int_cand > 1) {
		for (i = 0; i < MASK_FMT_INT_PLHDR && mask_skip_ranges[i] != -1; i++)
			ret[(mask_int_key_loc[t] & (0xff << (i * 8))) >> (i * 8)] =
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

	if (bitmap_prev_size != bitmap_size || num_int_cand != mask_int_cand.num_int_cand) {
		num_int_cand = mask_int_cand.num_int_cand;

		release_kernel();

		snprintf(opt, sizeof(opt), "-DBITMAP_SIZE_MINUS1=%u", bitmap_size - 1U);

		if (mask_int_cand.num_int_cand > 1)
			strncat(opt, " -DGPU_MASK_MODE", 64U);

		opencl_build_kernel(task, gpu_id, opt, 0);

		// create kernel(s) to execute
		opencl_create_kernel(&prepare_kernel, "kernel_prepare");

		if (salted_format)
			opencl_create_kernel(&crypt_kernel, "kernel_crypt_xsha");
		else
			opencl_create_kernel(&crypt_kernel, "kernel_crypt_raw");

		// Do we need to (re)create bitmap buffer?
		if (bitmap_prev_size != bitmap_size)
			create_bitmap_buffers();
		bitmap_prev_size = bitmap_size;
	}
}

static void release_kernel()
{
	if (program[gpu_id]) {
		opencl_release_kernel(NULL);
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
	bitmap_prev_size = 0;

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
		release_bitmap_buffers();
	}
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
	memset(bitmap, '\0', (bitmap_size / 8 + 1));

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
				if (bitmap[bit_mask_x >> 5] & (1U << (bit_mask_x & 31)) &&
				    bitmap[bit_mask_y >> 5] & (1U << (bit_mask_y & 31)))
					fprintf(stderr, "Collision: %u %08x %08x %08x %08x\n",
						num_loaded_hashes, (unsigned int) binary[0],
						bit_mask_x, bit_mask_y,
						bitmap[bit_mask_x >> 5]);
#endif
				bitmap[bit_mask_x >> 5] |= (1U << (bit_mask_x & 31));
				bitmap[bit_mask_y >> 5] |= (1U << (bit_mask_y & 31));
			}
		} while ((pw = pw->next));

	} while ((current_salt = current_salt->next));
}

/* ------- Send hashes to crack (a bitmap of pw->binary) to GPU ------- */
static void load_hash()
{
	num_loaded_hashes = get_num_loaded_hashes();

	prepare_bit_array();

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], dev_bitmap, CL_TRUE, 0,
		(bitmap_size / 32 + 1) * sizeof(uint32_t),
	        bitmap, 0, NULL, NULL),
	        "failed in clEnqueueWriteBuffer dev_bitmap");

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
	//TODO: hot code path. Is there another way to figure this out?
	if (num_loaded_hashes != get_num_loaded_hashes())
		load_hash();

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], prepare_kernel, 1,
	                                     NULL, &gws, lws, 0, NULL, multi_profilingEvent[0]),
	              "failed in clEnqueueNDRangeKernel I");

	//Send data to device.
	if (new_keys && key_idx > offset)
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pinned_plaintext,
		                                   CL_FALSE, sizeof(uint32_t) * offset,
		                                   sizeof(uint32_t) * (key_idx - offset), plaintext + offset, 0,
		                                   NULL, multi_profilingEvent[1]),
		              "failed in clEnqueueWriteBuffer pass_buffer");

	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pinned_saved_idx, CL_FALSE,
	                                   sizeof(uint32_t) * offset,
	                                   sizeof(uint32_t) * (gws - offset),
	                                   saved_idx + offset, 0, NULL, multi_profilingEvent[2]),
	              "failed in clEnqueueWriteBuffer idx_buffer");

	if (new_keys && mask_int_cand.num_int_cand > 1) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], pinned_int_key_loc,
		                                   CL_FALSE, 0, 4 * gws, mask_int_key_loc, 0, NULL,
		                                   multi_profilingEvent[5]),
		              "failed in clEnqueueWriteBuffer dev_int_key_loc");

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], dev_int_keys,
		                                   CL_FALSE, 0, 4 * mask_int_cand.num_int_cand,
		                                   mask_int_cand.int_cand, 0, NULL, multi_profilingEvent[6]),
		              "failed in clEnqueueWriteBuffer dev_int_keys");
	}
	//Enqueue the kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL,
	                                     &gws, lws, 0, NULL, multi_profilingEvent[3]),
	              "failed in clEnqueueNDRangeKernel");

	//Possible cracked hashes
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], dev_cracks, CL_FALSE,
	                                  0, sizeof(uint32_t), cracks,
	                                  0, NULL, multi_profilingEvent[4]),
	              "failed in reading data back dev_cracks");

	//Do the work
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	new_keys = 0;

#ifdef DEBUG
	if (cracks[0])
		fprintf(stderr, "Some checks are going to be done on CPU: %u: %1.4f%%\n", cracks[0],
			((double) cracks[0]) / (global_work_size * mask_int_cand.num_int_cand) * 100);
#endif
	if (cracks[0] > global_work_size * mask_int_cand.num_int_cand) {
		fprintf(stderr, "Error, crypt_all() kernel: %u.\n", cracks[0]);
		error();
	}

	if (cracks[0]) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], dev_cracks, CL_FALSE,
			0, (cracks[0] * CRACK_VAR_SIZE + CRACK_HEAD_SIZE), cracks,
						  0, NULL, NULL),
			      "failed in reading data back dev_cracks");

		//Do the work
		BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	}
	*pcount *= mask_int_cand.num_int_cand;
	return cracks[0];
}

/* ------- Compare functins ------- */
static int cmp_all(void *binary, int count)
{
	return (count > 0);
}

static int cmp_one(void *binary, int index)
{
	return (cracks[CRACK_POS] == ((uint32_t *) binary)[0]);
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
	return cracks[CRACK_POS] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return cracks[CRACK_POS] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return cracks[CRACK_POS] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return cracks[CRACK_POS] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return cracks[CRACK_POS] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return cracks[CRACK_POS] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return cracks[CRACK_POS] & PH_MASK_6;
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
