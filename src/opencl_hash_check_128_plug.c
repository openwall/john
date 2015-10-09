#include <assert.h>

#include "common-opencl.h"
#include "options.h"
#include "opencl_hash_check_128.h"

cl_uint num_loaded_hashes;
cl_uint *loaded_hashes = NULL;
cl_uint *hash_ids = NULL;
OFFSET_TABLE_WORD *offset_table = NULL;
unsigned int hash_table_size = 0, offset_table_size = 0;
cl_ulong bitmap_size_bits = 0;
cl_uint *bitmaps = NULL;

static struct fmt_main *self;

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

void opencl_hash_check_128_init(struct fmt_main *_self)
{
	self = _self;
}

void prepare_table(struct db_salt *salt) {
	unsigned int *bin, i;
	struct db_password *pw, *last;

	num_loaded_hashes = (salt->count);

	MEM_FREE(loaded_hashes);
	MEM_FREE(hash_ids);
	MEM_FREE(offset_table);
	MEM_FREE(hash_table_128);

	loaded_hashes = (cl_uint*) mem_alloc(4 * num_loaded_hashes * sizeof(cl_uint));
	hash_ids = (cl_uint*) mem_alloc((3 * num_loaded_hashes + 1) * sizeof(cl_uint));

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
			        &hash_table_size, 0);

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

char* select_bitmap(unsigned int num_ld_hashes)
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
		assert(!(buf_sz & (buf_sz - 1)));
		if ((bitmap_size_bits >> 3) > buf_sz)
			bitmap_size_bits = buf_sz << 3;
		assert(!(bitmap_size_bits & (bitmap_size_bits - 1)));
		cmp_steps = 1;
	}

	if (cmp_steps == 1)
		prepare_bitmap_1(bitmap_size_bits, &bitmaps);

	else if (cmp_steps <= 4)
		prepare_bitmap_4(bitmap_size_bits, &bitmaps);

	else
		prepare_bitmap_8(bitmap_size_bits, &bitmaps);

	sprintf(kernel_params,
		"-D SELECT_CMP_STEPS=%u"
		" -D BITMAP_SIZE_BITS_LESS_ONE="LLu" -D USE_LOCAL_BITMAPS=%u",
		cmp_steps, (unsigned long long)bitmap_size_bits - 1, use_local);

	bitmap_size_bits *= cmp_steps;

	return kernel_params;
}


int cmp_all(void *binary, int count)
{
	if (count) return 1;
	return 0;
}

int cmp_one(void *binary, int index)
{
	return (((unsigned int*)binary)[0] ==
		hash_table_128[hash_ids[3 + 3 * index]]);
}

int cmp_exact(char *source, int index)
{
	unsigned int *t = (unsigned int *) (self->methods.binary(source));

	if (t[2] != loaded_hashes[2 * index])
		return 0;
	if (t[3] != loaded_hashes[2 * index + 1])
		return 0;
	return 1;
}
