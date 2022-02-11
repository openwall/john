#if HAVE_OPENCL

#include "options.h"
#include "opencl_hash_check_128.h"
#include "mask_ext.h"

cl_uint num_loaded_hashes;
cl_uint *hash_ids = NULL;
unsigned int hash_table_size_128 = 0, offset_table_size = 0;

static cl_uint *loaded_hashes = NULL;
static OFFSET_TABLE_WORD *offset_table = NULL;
static cl_ulong bitmap_size_bits = 0;
static cl_uint *bitmaps = NULL;
static cl_uint *zero_buffer = NULL;
static cl_mem buffer_offset_table, buffer_hash_table, buffer_return_hashes, buffer_hash_ids, buffer_bitmap_dupe, buffer_bitmaps;
static struct fmt_main *self;


void ocl_hc_128_init(struct fmt_main *_self)
{
	self = _self;
	hash_table_128 = NULL;
}

void ocl_hc_128_prepare_table(struct db_salt *salt) {
	unsigned int *bin, i;
	struct db_password *pw, *last;

	num_loaded_hashes = (salt->count);

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (hash_ids)
		MEM_FREE(hash_ids);
	if (offset_table)
		MEM_FREE(offset_table);
	if (hash_table_128)
		MEM_FREE(hash_table_128);

	loaded_hashes = (cl_uint*) mem_alloc(4 * num_loaded_hashes * sizeof(cl_uint));
	hash_ids = (cl_uint*) mem_calloc((3 * num_loaded_hashes + 1), sizeof(cl_uint));

	last = pw = salt->list;
	i = 0;
	do {
		bin = (unsigned int *)pw->binary;
		if (bin == NULL) {
			if (last == pw)
				salt->list = pw->next;
			else
				last->next = pw->next;
		} else {
			last = pw;
			loaded_hashes[4 * i] = bin[0];
			loaded_hashes[4 * i + 1] = bin[1];
			loaded_hashes[4 * i + 2] = bin[2];
			loaded_hashes[4 * i + 3] = bin[3];
			i++;
		}
	} while ((pw = pw->next)) ;

	if (i != (salt->count)) {
		fprintf(stderr,
			"Something went wrong while preparing hashes..Exiting..\n");
		error();
	}

	num_loaded_hashes = create_perfect_hash_table(128, (void *)loaded_hashes,
				num_loaded_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size_128, 0);

	if (!num_loaded_hashes) {
		MEM_FREE(hash_table_128);
		MEM_FREE(offset_table);
		fprintf(stderr, "Failed to create Hash Table for cracking.\n");
		error();
	}
}

void ocl_hc_128_prepare_table_test() {
	unsigned int *binary, i;
	char *ciphertext;

	num_loaded_hashes = 0;
	while (self->params.tests[num_loaded_hashes].ciphertext != NULL)
			num_loaded_hashes++;

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (hash_ids)
		MEM_FREE(hash_ids);
	if (offset_table)
		MEM_FREE(offset_table);
	if (hash_table_128)
		MEM_FREE(hash_table_128);

	loaded_hashes = (cl_uint*) mem_alloc(4 * num_loaded_hashes * sizeof(cl_uint));
	hash_ids = (cl_uint*) mem_calloc((3 * num_loaded_hashes + 1), sizeof(cl_uint));

	i = 0;
	while (self->params.tests[i].ciphertext != NULL) {
			ciphertext = self->methods.split(self->params.tests[i].ciphertext, 0, self);
			binary = (unsigned int*)self->methods.binary(ciphertext);
			loaded_hashes[4 * i] = binary[0];
			loaded_hashes[4 * i + 1] = binary[1];
			loaded_hashes[4 * i + 2] = binary[2];
			loaded_hashes[4 * i + 3] = binary[3];
			i++;
	}

	num_loaded_hashes = create_perfect_hash_table(128, (void *)loaded_hashes,
				num_loaded_hashes,
			        &offset_table,
			        &offset_table_size,
			        &hash_table_size_128, 0);

	if (!num_loaded_hashes) {
		MEM_FREE(hash_table_128);
		MEM_FREE(offset_table);
		fprintf(stderr, "Failed to create Hash Table for cracking.\n");
		error();
	}
}

/* Use only for smaller bitmaps < 16MB */
static void prepare_bitmap_8(cl_ulong bmp_sz, cl_uint **bitmap_ptr)
{
	unsigned int i;
	MEM_FREE(*bitmap_ptr);
	*bitmap_ptr = (cl_uint*) mem_calloc((bmp_sz >> 2), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx =
			(loaded_hashes[4 * i] & 0x0000ffff) & (bmp_sz - 1);
		(*bitmap_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));

		bmp_idx = (loaded_hashes[4 * i] >> 16) & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = (loaded_hashes[4 * i + 1] & 0x0000ffff) & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 4) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = (loaded_hashes[4 * i + 1] >> 16) & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) * 3 + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = (loaded_hashes[4 * i + 2] & 0x0000ffff) & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 3) + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = (loaded_hashes[4 * i + 2] >> 16) & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) * 5 + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = (loaded_hashes[4 * i + 3] & 0x0000ffff) & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) * 6 + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));

		bmp_idx = (loaded_hashes[4 * i + 3] >> 16) & (bmp_sz - 1);
		(*bitmap_ptr)[(bmp_sz >> 5) * 7 + (bmp_idx >> 5)] |=
			(1U << (bmp_idx & 31));
	}
}

/* Use only for smaller bitmaps < 16MB */
static void prepare_bitmap_4(cl_ulong bmp_sz, cl_uint **bitmap_ptr)
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

static void prepare_bitmap_1(cl_ulong bmp_sz, cl_uint **bitmap_ptr)
{
	unsigned int i;
	MEM_FREE(*bitmap_ptr);
	*bitmap_ptr = (cl_uint*) mem_calloc((bmp_sz >> 5), sizeof(cl_uint));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int bmp_idx = loaded_hashes[4 * i + 3] & (bmp_sz - 1);
		(*bitmap_ptr)[bmp_idx >> 5] |= (1U << (bmp_idx & 31));
	}
}

char* ocl_hc_128_select_bitmap(unsigned int num_ld_hashes)
{
	static char kernel_params[200];
	cl_ulong max_local_mem_sz_bytes = 0;
	unsigned int cmp_steps = 2, use_local = 0;

	HANDLE_CLERROR(clGetDeviceInfo(devices[gpu_id], CL_DEVICE_LOCAL_MEM_SIZE,
		sizeof(cl_ulong), &max_local_mem_sz_bytes, 0),
		"failed to get CL_DEVICE_LOCAL_MEM_SIZE.");

	if (num_loaded_hashes <= 5100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;

		else if (amd_gcn_11(device_info[gpu_id]) ||
			max_local_mem_sz_bytes < 16384 ||
			cpu(device_info[gpu_id]))
			bitmap_size_bits = 256 * 1024;

		else {
			bitmap_size_bits = 32 * 1024;
			cmp_steps = 4;
			use_local = 1;
		}
	}

	else if (num_loaded_hashes <= 10100) {
		if (amd_gcn_10(device_info[gpu_id]) ||
			amd_vliw4(device_info[gpu_id]))
			bitmap_size_bits = 512 * 1024;

		else if (amd_gcn_11(device_info[gpu_id]) ||
			max_local_mem_sz_bytes < 32768 ||
			cpu(device_info[gpu_id]))
			bitmap_size_bits = 256 * 1024;

		else {
			bitmap_size_bits = 64 * 1024;
			cmp_steps = 4;
			use_local = 1;
		}
	}

	else if (num_loaded_hashes <= 20100) {
		if (amd_gcn_10(device_info[gpu_id]))
			bitmap_size_bits = 1024 * 1024;

		else if (amd_gcn_11(device_info[gpu_id]) ||
			max_local_mem_sz_bytes < 32768)
			bitmap_size_bits = 512 * 1024;

		else if (amd_vliw4(device_info[gpu_id]) ||
			cpu(device_info[gpu_id])) {
			bitmap_size_bits = 256 * 1024;
			cmp_steps = 4;
		}

		else {
			bitmap_size_bits = 32 * 1024;
			cmp_steps = 8;
			use_local = 1;
		}
	}

	else if (num_loaded_hashes <= 250100)
		bitmap_size_bits = 2048 * 1024;

	else if (num_loaded_hashes <= 1100100) {
		if (!amd_gcn_11(device_info[gpu_id]))
			bitmap_size_bits = 4096 * 1024;

		else
			bitmap_size_bits = 2048 * 1024;
	}

	else if (num_loaded_hashes <= 1500100) {
		bitmap_size_bits = 4096 * 1024 * 2;
		cmp_steps = 1;
	}

	else if (num_loaded_hashes <= 2700100) {
		bitmap_size_bits = 4096 * 1024 * 2 * 2;
		cmp_steps = 1;
	}

	else {
		cl_ulong mult = num_loaded_hashes / 2700100;
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

	else if (cmp_steps <= 4)
		prepare_bitmap_4(bitmap_size_bits, &bitmaps);

	else
		prepare_bitmap_8(bitmap_size_bits, &bitmaps);

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

void ocl_hc_128_crobj(cl_kernel kernel)
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

	zero_buffer = (cl_uint *) mem_calloc(hash_table_size_128/32 + 1, sizeof(cl_uint));

	buffer_return_hashes = clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, 2 * sizeof(cl_uint) * num_loaded_hashes, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_return_hashes.");

	buffer_hash_ids = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, (3 * num_loaded_hashes + 1) * sizeof(cl_uint), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_buffer_hash_ids.");

	buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, (hash_table_size_128/32 + 1) * sizeof(cl_uint), zero_buffer, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap_dupe.");

	buffer_bitmaps = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, max_alloc_size_bytes, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_bitmaps.");

	buffer_offset_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, offset_table_size * sizeof(OFFSET_TABLE_WORD), NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_offset_table.");

	buffer_hash_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, hash_table_size_128 * sizeof(unsigned int) * 2, NULL, &ret_code);
	HANDLE_CLERROR(ret_code, "Error creating buffer argument buffer_hash_table.");

	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmaps, CL_TRUE, 0, (size_t)(bitmap_size_bits >> 3), bitmaps, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmaps.");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_offset_table, CL_TRUE, 0, sizeof(OFFSET_TABLE_WORD) * offset_table_size, offset_table, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_offset_table.");
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_table, CL_TRUE, 0, sizeof(cl_uint) * hash_table_size_128 * 2, hash_table_128, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_table.");

	HANDLE_CLERROR(clSetKernelArg(kernel, 4, sizeof(buffer_bitmaps), (void *) &buffer_bitmaps), "Error setting argument 5.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 5, sizeof(buffer_offset_table), (void *) &buffer_offset_table), "Error setting argument 6.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 6, sizeof(buffer_hash_table), (void *) &buffer_hash_table), "Error setting argument 7.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 7, sizeof(buffer_return_hashes), (void *) &buffer_return_hashes), "Error setting argument 8.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 8, sizeof(buffer_hash_ids), (void *) &buffer_hash_ids), "Error setting argument 9.");
	HANDLE_CLERROR(clSetKernelArg(kernel, 9, sizeof(buffer_bitmap_dupe), (void *) &buffer_bitmap_dupe), "Error setting argument 10.");
}

int ocl_hc_128_extract_info(struct db_salt *salt, void (*set_kernel_args)(void), void (*set_kernel_args_kpc)(void), void (*init_kernel)(unsigned int, char *), size_t gws, size_t *lws, int *pcount)
{
	if (salt != NULL && salt->count > 4500 &&
		(num_loaded_hashes - num_loaded_hashes / 10) > salt->count) {
		size_t old_ot_sz_bytes, old_ht_sz_bytes;
		ocl_hc_128_prepare_table(salt);
		init_kernel(salt->count, ocl_hc_128_select_bitmap(salt->count));

		BENCH_CLERROR(clGetMemObjectInfo(buffer_offset_table, CL_MEM_SIZE, sizeof(size_t), &old_ot_sz_bytes, NULL), "failed to query buffer_offset_table.");

		if (old_ot_sz_bytes < offset_table_size *
			sizeof(OFFSET_TABLE_WORD)) {
			BENCH_CLERROR(clReleaseMemObject(buffer_offset_table), "Error Releasing buffer_offset_table.");

			buffer_offset_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, offset_table_size * sizeof(OFFSET_TABLE_WORD), NULL, &ret_code);
			BENCH_CLERROR(ret_code, "Error creating buffer argument buffer_offset_table.");
		}

		BENCH_CLERROR(clGetMemObjectInfo(buffer_hash_table, CL_MEM_SIZE, sizeof(size_t), &old_ht_sz_bytes, NULL), "failed to query buffer_hash_table.");

		if (old_ht_sz_bytes < hash_table_size_128 * sizeof(cl_uint) * 2) {
			BENCH_CLERROR(clReleaseMemObject(buffer_hash_table), "Error Releasing buffer_hash_table.");
			BENCH_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error Releasing buffer_bitmap_dupe.");
			MEM_FREE(zero_buffer);

			zero_buffer = (cl_uint *) mem_calloc(hash_table_size_128/32 + 1, sizeof(cl_uint));
			buffer_bitmap_dupe = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, (hash_table_size_128/32 + 1) * sizeof(cl_uint), zero_buffer, &ret_code);
			BENCH_CLERROR(ret_code, "Error creating buffer argument buffer_bitmap_dupe.");
			buffer_hash_table = clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, hash_table_size_128 * sizeof(cl_uint) * 2, NULL, &ret_code);
			BENCH_CLERROR(ret_code, "Error creating buffer argument buffer_hash_table.");
		}

		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmaps, CL_TRUE, 0, (bitmap_size_bits >> 3), bitmaps, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmaps.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_offset_table, CL_TRUE, 0, sizeof(OFFSET_TABLE_WORD) * offset_table_size, offset_table, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_offset_table.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_table, CL_TRUE, 0, sizeof(cl_uint) * hash_table_size_128 * 2, hash_table_128, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_table.");

		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 4, sizeof(buffer_bitmaps), (void *) &buffer_bitmaps), "Error setting argument 5.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 5, sizeof(buffer_offset_table), (void *) &buffer_offset_table), "Error setting argument 6.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 6, sizeof(buffer_hash_table), (void *) &buffer_hash_table), "Error setting argument 7.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 7, sizeof(buffer_return_hashes), (void *) &buffer_return_hashes), "Error setting argument 8.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 8, sizeof(buffer_hash_ids), (void *) &buffer_hash_ids), "Error setting argument 9.");
		BENCH_CLERROR(clSetKernelArg(crypt_kernel, 9, sizeof(buffer_bitmap_dupe), (void *) &buffer_bitmap_dupe), "Error setting argument 10.");
		set_kernel_args();
		set_kernel_args_kpc();
	}

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1, NULL, &gws, lws, 0, NULL, multi_profilingEvent[2]), "failed in clEnqueueNDRangeKernel");

	WAIT2_INIT(multi_profilingEvent[3]);

	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_FALSE, 0, sizeof(cl_uint), hash_ids, 0, NULL, multi_profilingEvent[3]), "failed in reading back num cracked hashes.");

	WAIT2_FINISH(multi_profilingEvent[3]);

	if (hash_ids[0] > num_loaded_hashes) {
		fprintf(stderr, "Error, crypt_all kernel.\n");
		error();
	}

	if (hash_ids[0]) {
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_return_hashes, CL_FALSE, 0, 2 * sizeof(cl_uint) * hash_ids[0], loaded_hashes, 0, NULL, NULL), "failed in reading back return_hashes.");
		BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, (3 * hash_ids[0] + 1) * sizeof(cl_uint), hash_ids, 0, NULL, NULL), "failed in reading data back hash_ids.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_bitmap_dupe, CL_FALSE, 0, (hash_table_size_128/32 + 1) * sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_bitmap_dupe.");
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], buffer_hash_ids, CL_TRUE, 0, sizeof(cl_uint), zero_buffer, 0, NULL, NULL), "failed in clEnqueueWriteBuffer buffer_hash_ids.");
	}

	*pcount *= mask_int_cand.num_int_cand;
	return hash_ids[0];
}

void ocl_hc_128_rlobj(void)
{
	if (buffer_bitmaps) {
		HANDLE_CLERROR(clReleaseMemObject(buffer_return_hashes), "Error Releasing buffer_return_hashes.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_offset_table), "Error Releasing buffer_offset_table.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_table), "Error Releasing buffer_hash_table.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmap_dupe), "Error Releasing buffer_bitmap_dupe.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_hash_ids), "Error Releasing buffer_hash_ids.");
		HANDLE_CLERROR(clReleaseMemObject(buffer_bitmaps), "Error Releasing buffer_bitmap.");
		MEM_FREE(zero_buffer);
		buffer_bitmaps = NULL;
	}

	if (loaded_hashes)
		MEM_FREE(loaded_hashes);
	if (hash_ids)
		MEM_FREE(hash_ids);
	if (bitmaps)
		MEM_FREE(bitmaps);
	if (offset_table)
		MEM_FREE(offset_table);
	if (hash_table_128)
		MEM_FREE(hash_table_128);
}

int ocl_hc_128_cmp_all(void *binary, int count)
{
	if (count) return 1;
	return 0;
}

int ocl_hc_128_cmp_one(void *binary, int index)
{
	return (((unsigned int*)binary)[0] ==
		hash_table_128[hash_ids[3 + 3 * index]] &&
		((unsigned int*)binary)[1] ==
		hash_table_128[hash_table_size_128+ hash_ids[3 + 3 * index]]);
}

int ocl_hc_128_cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) (self->methods.binary(source));

	if (t[2] != loaded_hashes[2 * index])
		return 0;
	if (t[3] != loaded_hashes[2 * index + 1])
		return 0;
	return 1;
}

#endif /* HAVE_OPENCL */
