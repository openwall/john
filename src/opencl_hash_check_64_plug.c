#if HAVE_OPENCL

#include "options.h"
#include "opencl_hash_check.h"
#include "mask_ext.h"
#include "md4.h" // for cmp_exact()
#include "unicode.h" // for cmp_exact()
#include "simd-intrinsics.h" // for md4_reverse()
#include "johnswap.h" // for printing of false positives

cl_uint ocl_hc_num_loaded_hashes;
cl_uint *ocl_hc_hash_ids = NULL;
unsigned int ocl_hc_hash_table_size = 0, ocl_hc_offset_table_size = 0;

static cl_uint *loaded_hashes = NULL;
static OFFSET_TABLE_WORD *offset_table = NULL;
static cl_ulong bitmap_size_bits = 0;
static cl_uint *bitmaps = NULL;
static cl_uint *zero_buffer = NULL;
static cl_mem buffer_offset_table, buffer_hash_table, buffer_hash_ids_64, buffer_bitmap_dupe, buffer_bitmaps;
static struct fmt_main *self;

void ocl_hc_64_init(struct fmt_main *_self)
{
	self = _self;
	bt_hash_table_64 = NULL;
}

void ocl_hc_64_prepare_table(struct db_salt *salt)
{
	unsigned int *bin, i;
	struct db_password *pw, *last;

	ocl_hc_num_loaded_hashes = (salt->count);

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (ocl_hc_hash_ids)
		MEM_FREE(ocl_hc_hash_ids);
	if (offset_table)
		MEM_FREE(offset_table);
	if (bt_hash_table_64)
		MEM_FREE(bt_hash_table_64);

	loaded_hashes = (cl_uint*) mem_alloc(2 * ocl_hc_num_loaded_hashes * sizeof(cl_uint));
	ocl_hc_hash_ids = (cl_uint*) mem_calloc((3 * ocl_hc_num_loaded_hashes + 1), sizeof(cl_uint));

	last = pw = salt->list;
	i = 0;
	do {
		bin = (unsigned int*)pw->binary;
		if (bin == NULL) {
			if (last == pw)
				salt->list = pw->next;
			else
				last->next = pw->next;
		} else {
			last = pw;
			loaded_hashes[2 * i] = bin[0];
			loaded_hashes[2 * i + 1] = bin[1];
			i++;
		}
	} while ((pw = pw->next)) ;

	if (i != (salt->count)) {
		fprintf(stderr,
			"Something went wrong while preparing hashes..Exiting..\n");
		error();
	}

	ocl_hc_num_loaded_hashes =
		bt_create_perfect_hash_table(64, (void*)loaded_hashes,
		                          ocl_hc_num_loaded_hashes,
		                          &offset_table,
		                          &ocl_hc_offset_table_size,
		                          &ocl_hc_hash_table_size, 0);

	if (!ocl_hc_num_loaded_hashes) {
		MEM_FREE(bt_hash_table_64);
		MEM_FREE(offset_table);
		fprintf(stderr, "Failed to create Hash Table for cracking.\n");
		error();
	}
}

/* Use only for smaller bitmaps < 16MB */
static void prepare_bitmap_2(cl_ulong bmp_sz_bits, cl_uint **bitmaps_ptr)
{
	unsigned int i;
	MEM_FREE(*bitmaps_ptr);
	*bitmaps_ptr = (cl_uint*) mem_calloc((bmp_sz_bits >> 4), sizeof(cl_uint));

	for (i = 0; i < ocl_hc_num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[2 * i + 1] & (bmp_sz_bits - 1);
		(*bitmaps_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));

		bmp_idx = loaded_hashes[2 * i] & (bmp_sz_bits - 1);
		(*bitmaps_ptr)[(bmp_sz_bits >> 5) + (bmp_idx >> 5)] |= (1U << (bmp_idx & 31));
	}
}

static void prepare_bitmap_1(cl_ulong bmp_sz_bits, cl_uint **bitmaps_ptr)
{
	unsigned int i;
	MEM_FREE(*bitmaps_ptr);
	*bitmaps_ptr = (cl_uint*) mem_calloc((bmp_sz_bits >> 5), sizeof(cl_uint));

	for (i = 0; i < ocl_hc_num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[2 * i + 1] & (bmp_sz_bits - 1);
		(*bitmaps_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));
	}
}

char* ocl_hc_64_select_bitmap(unsigned int num_ld_hashes)
{
	static char kernel_params[200];
	cl_ulong max_local_mem_sz_bytes = 0;
	unsigned int cmp_steps = 2, use_local = 0;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_LOCAL_MEM_SIZE,
	                               sizeof(cl_ulong), &max_local_mem_sz_bytes, 0),
	               "failed to get CL_DEVICE_LOCAL_MEM_SIZE.");

	if (num_ld_hashes <= 5100) {
		if (amd_gcn_10(device_info[gpu_id]) || amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;
		else if (amd_gcn_11(device_info[gpu_id]) || max_local_mem_sz_bytes < 16384 || cpu(device_info[gpu_id]))
			bitmap_size_bits = 256 * 1024;
		else {
			bitmap_size_bits = 32 * 1024;
			use_local = 1;
		}
	}
	else if (num_ld_hashes <= 10100) {
		if (amd_gcn_10(device_info[gpu_id]) || amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;
		else if (amd_gcn_11(device_info[gpu_id]) || max_local_mem_sz_bytes < 32768 || cpu(device_info[gpu_id]))
			bitmap_size_bits = 256 * 1024;
		else {
			bitmap_size_bits = 64 * 1024;
			use_local = 1;
		}
	}
	else if (num_ld_hashes <= 20100) {
		if (amd_gcn_10(device_info[gpu_id]))
			bitmap_size_bits = 1024 * 1024;
		else if (amd_gcn_11(device_info[gpu_id]) || max_local_mem_sz_bytes < 32768)
			bitmap_size_bits = 512 * 1024;
		else if (amd_vliw4(device_info[gpu_id]) || cpu(device_info[gpu_id]))
			bitmap_size_bits = 256 * 1024;
		else {
			bitmap_size_bits = 32 * 1024;
			use_local = 1;
		}
	}
	else if (num_ld_hashes <= 250100)
		bitmap_size_bits = 2048 * 1024;
	else if (num_ld_hashes <= 1100100) {
		if (!amd_gcn_11(device_info[gpu_id]))
			bitmap_size_bits = 4096 * 1024;
		else
			bitmap_size_bits = 2048 * 1024;
	}
	else if (num_ld_hashes <= 1500100) {
		bitmap_size_bits = 4096 * 1024 * 2;
		cmp_steps = 1;
	}
	else if (num_ld_hashes <= 2700100) {
		bitmap_size_bits = 4096 * 1024 * 2 * 2;
		cmp_steps = 1;
	}
	else {
		cl_ulong mult = num_ld_hashes / 2700100;
		cl_ulong buf_sz;
		bitmap_size_bits = 4096 * 4096;
		get_power_of_two(mult);
		bitmap_size_bits *= mult;
		buf_sz = get_max_mem_alloc_size(gpu_id);
		if (buf_sz & (buf_sz - 1)) {
			get_power_of_two(buf_sz);
			buf_sz >>= 1;
		}
		if (buf_sz >= 536870912)
			buf_sz = 536870912;
		if ((bitmap_size_bits >> 3) > buf_sz)
			bitmap_size_bits = buf_sz << 3;
		cmp_steps = 1;
	}

	if (cmp_steps == 1)
		prepare_bitmap_1(bitmap_size_bits, &bitmaps);
	else
		prepare_bitmap_2(bitmap_size_bits, &bitmaps);

	/*
	 * Much better speed seen on Macbook Pro with GT 650M. Not sure why -
	 * or what we should actually test for.
	 */
	if (platform_apple(platform_id) && gpu_nvidia(device_info[gpu_id]))
		use_local = 0;

	sprintf(kernel_params,
		"-D SELECT_CMP_STEPS=%u"
		" -D BITMAP_SIZE_BITS_LESS_ONE="LLu" -D USE_LOCAL_BITMAPS=%u",
		cmp_steps, (unsigned long long)bitmap_size_bits - 1, use_local);

	bitmap_size_bits *= cmp_steps;

	return kernel_params;
}

void ocl_hc_64_crobj(cl_kernel kernel)
{
	cl_ulong max_alloc_size_bytes = 0;
	cl_ulong cache_size_bytes = 0;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(cl_ulong), &max_alloc_size_bytes, 0), "failed to get CL_DEVICE_MAX_MEM_ALLOC_SIZE.");
	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, sizeof(cl_ulong), &cache_size_bytes, 0), "failed to get CL_DEVICE_GLOBAL_MEM_CACHE_SIZE.");

	if (max_alloc_size_bytes & (max_alloc_size_bytes - 1)) {
		get_power_of_two(max_alloc_size_bytes);
		max_alloc_size_bytes >>= 1;
	}
	if (max_alloc_size_bytes >= 536870912) max_alloc_size_bytes = 536870912;

	if (!cache_size_bytes) cache_size_bytes = 1024;

	zero_buffer = (cl_uint*) mem_calloc(ocl_hc_hash_table_size/32 + 1, sizeof(cl_uint));

	buffer_hash_ids_64 = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (3 * ocl_hc_num_loaded_hashes + 1) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_buffer_hash_ids_64.");

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, (ocl_hc_hash_table_size/32 + 1) * sizeof(cl_uint), zero_buffer, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap_dupe.");

	buffer_bitmaps = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, max_alloc_size_bytes, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmaps.");

	buffer_offset_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, ocl_hc_offset_table_size * sizeof(OFFSET_TABLE_WORD), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_offset_table.");

	buffer_hash_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, ocl_hc_hash_table_size * sizeof(unsigned int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_hash_table.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids_64, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids_64.");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmaps, CL_TRUE, 0, (size_t)(bitmap_size_bits >> 3), bitmaps, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmaps.");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_offset_table, CL_TRUE, 0, sizeof(OFFSET_TABLE_WORD) * ocl_hc_offset_table_size, offset_table, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_offset_table.");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_table, CL_TRUE, 0, sizeof(cl_uint) * ocl_hc_hash_table_size * 2, bt_hash_table_64, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_table.");

	HANDLE_CLERROR(clSetKernelArg(kernel, 4, sizeof(buffer_bitmaps), (void*) &buffer_bitmaps), "Error setting argument 5.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 5, sizeof(buffer_offset_table), (void*) &buffer_offset_table), "Error setting argument 6.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 6, sizeof(buffer_hash_table), (void*) &buffer_hash_table), "Error setting argument 7.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 7, sizeof(buffer_hash_ids_64), (void*) &buffer_hash_ids_64), "Error setting argument 8.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 8, sizeof(buffer_bitmap_dupe), (void*) &buffer_bitmap_dupe), "Error setting argument 9.");
}

int ocl_hc_64_extract_info(struct db_salt *salt, void (*set_kernel_args)(void), void (*set_kernel_args_kpc)(void), void (*init_kernel)(unsigned int, char*), size_t gws, size_t *lws, int *pcount)
{
	if (salt != NULL && salt->count > 4500 &&
		(ocl_hc_num_loaded_hashes - ocl_hc_num_loaded_hashes / 10) > salt->count) {
		size_t old_ot_sz_bytes, old_ht_sz_bytes;

		ocl_hc_64_prepare_table(salt);
		init_kernel(salt->count, ocl_hc_64_select_bitmap(salt->count));

		BENCH_CLERROR(clGetMemObjectInfo(buffer_offset_table, CL_MEM_SIZE, sizeof(size_t), &old_ot_sz_bytes, NULL), "failed to query buffer_offset_table.");

		if (old_ot_sz_bytes < ocl_hc_offset_table_size * sizeof(OFFSET_TABLE_WORD)) {
			BENCH_CLERROR(clReleaseMemObject(buffer_offset_table), "Error Releasing buffer_offset_table.");

			buffer_offset_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, ocl_hc_offset_table_size * sizeof(OFFSET_TABLE_WORD), NULL, &ret_code);
			BENCH_CLERROR(ret_code, "Error creating buffer argument buffer_offset_table.");
		}

		BENCH_CLERROR(clGetMemObjectInfo(buffer_hash_table, CL_MEM_SIZE, sizeof(size_t), &old_ht_sz_bytes, NULL), "failed to query buffer_hash_table.");

		if (old_ht_sz_bytes < ocl_hc_hash_table_size * sizeof(cl_uint) * 2) {
			BENCH_CLERROR(clReleaseMemObject(buffer_hash_table), "Error Releasing buffer_hash_table.");
			BENCH_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error Releasing buffer_bitmap_dupe.");
			MEM_FREE(zero_buffer);

			zero_buffer = (cl_uint*) mem_calloc(ocl_hc_hash_table_size/32 + 1, sizeof(cl_uint));
			buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, ((ocl_hc_hash_table_size - 1) / 32 + 1) * sizeof(cl_uint), zero_buffer, &ret_code);
			BENCH_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap_dupe.");
			buffer_hash_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, ocl_hc_hash_table_size * sizeof(cl_uint) * 2, NULL, &ret_code);
			BENCH_CLERROR(ret_code, "Error creating buffer argument buffer_hash_table.");
		}

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmaps, CL_TRUE, 0, (bitmap_size_bits >> 3), bitmaps, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmaps.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_offset_table, CL_TRUE, 0, sizeof(OFFSET_TABLE_WORD) * ocl_hc_offset_table_size, offset_table, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_offset_table.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_table, CL_TRUE, 0, sizeof(cl_uint) * ocl_hc_hash_table_size * 2, bt_hash_table_64, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_table.");

		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(buffer_bitmaps), (void*) &buffer_bitmaps), "Error setting argument 5.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(buffer_offset_table), (void*) &buffer_offset_table), "Error setting argument 6.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_hash_table), (void*) &buffer_hash_table), "Error setting argument 7.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(buffer_hash_ids_64), (void*) &buffer_hash_ids_64), "Error setting argument 8.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 8, sizeof(buffer_bitmap_dupe), (void*) &buffer_bitmap_dupe), "Error setting argument 9.");
		set_kernel_args();
		set_kernel_args_kpc();
	}

	BENCH_CLERROR(clFinish(queue[gpu_id]), "clFinish");
	WAIT_INIT(gws)

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids_64, CL_FALSE, 0, sizeof(cl_uint), ocl_hc_hash_ids, 0, NULL, multi_profilingEvent[3]), "failed in reading back num cracked hashes.");

	BENCH_CLERROR(clFlush(queue[gpu_id]), "failed in clFlush");
	WAIT_SLEEP
	BENCH_CLERROR(clFinish(queue[gpu_id]), "failed in clFinish");
	WAIT_UPDATE
	WAIT_DONE

	if (ocl_hc_hash_ids[0] > ocl_hc_num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (ocl_hc_hash_ids[0]) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids_64, CL_TRUE, 0, (3 * ocl_hc_hash_ids[0] + 1) * sizeof(cl_uint), ocl_hc_hash_ids, 0, NULL, NULL), "failed in reading data back ocl_hc_hash_ids.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_FALSE, 0, ((ocl_hc_hash_table_size - 1) / 32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmap_dupe.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids_64, CL_FALSE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids_64.");
	}

	*pcount *= mask_int_cand.num_int_cand;
	return ocl_hc_hash_ids[0];
}

void ocl_hc_64_rlobj(void)
{
	if (buffer_bitmaps) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_offset_table), "Error Releasing buffer_offset_table.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_table), "Error Releasing buffer_hash_table.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error Releasing buffer_bitmap_dupe.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids_64), "Error Releasing buffer_hash_ids_64.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmaps), "Error Releasing buffer_bitmap.");
		MEM_FREE(zero_buffer);
		buffer_bitmaps = NULL;
	}

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (ocl_hc_hash_ids)
		MEM_FREE(ocl_hc_hash_ids);
	if (bitmaps)
		MEM_FREE(bitmaps);
	if (offset_table)
		MEM_FREE(offset_table);
	if (bt_hash_table_64)
		MEM_FREE(bt_hash_table_64);
}

int ocl_hc_64_cmp_all(void *binary, int count)
{
	return count;
}

int ocl_hc_64_cmp_one(void *binary, int index)
{
	int result = (((unsigned int*)binary)[0] == bt_hash_table_64[ocl_hc_hash_ids[3 + 3 * index]] &&
	              ((unsigned int*)binary)[1] == bt_hash_table_64[ocl_hc_hash_table_size + ocl_hc_hash_ids[3 + 3 * index]]);
	return result;
}

int ocl_hc_64_cmp_exact(char *source, int index)
{
	unsigned int *binary = self->methods.binary(source);
	unsigned int hash[4];
	char *password = self->methods.get_key(index);
	UTF16 key[PLAINTEXT_BUFFER_SIZE];
	int len = enc_to_utf16(key, PLAINTEXT_BUFFER_SIZE, (UTF8*)password, (unsigned int)strlen(password));
	MD4_CTX ctx;

	MD4_Init(&ctx);
	MD4_Update(&ctx, key, 2 * len);
	MD4_Final((unsigned char*)hash, &ctx);
	md4_reverse(hash);
	int result = !memcmp(hash, binary, 16);
	if (!result) {
		fprintf(stderr, "\nFalse positive or 64-bit collision detected in %s(%d)\n", __FUNCTION__, index);
		dump_stderr_msg("  expected", binary, 16);
		dump_stderr_msg("calculated", hash, 16);
		md4_unreverse(binary);
		dump_stderr_msg("unreversed", binary, 16);
		fprintf(stderr, "Plaintext  : %s\n\n", self->methods.get_key(index));
	}
	return result;
}

#endif /* HAVE_OPENCL */
