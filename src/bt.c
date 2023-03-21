/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on paper 'Perfect Spatial Hashing' by Lefebvre & Hoppe
 */

#ifdef HAVE_OPENCL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "status.h"
#include "misc.h" // error()
#include "bt_twister.h"
#include "bt_hash_types.h"

#if _OPENMP > 201107
#define MAYBE_PARALLEL_FOR _Pragma("omp for")
#define MAYBE_ATOMIC_WRITE _Pragma("omp atomic write")
#define MAYBE_ATOMIC_CAPTURE _Pragma("omp atomic capture")
#else
#define MAYBE_PARALLEL_FOR _Pragma("omp single")
#define MAYBE_ATOMIC_WRITE
#define MAYBE_ATOMIC_CAPTURE
#endif

typedef struct {
	/* List of indexes linked to offset_data_idx */
	unsigned int *hash_location_list;
	unsigned short collisions;
	unsigned short iter;
	unsigned int offset_table_idx;
} auxilliary_offset_data;

/* Interface pointers */
static unsigned int (*zero_check_ht)(unsigned int);
static void (*assign_ht)(unsigned int, unsigned int);
static void (*assign0_ht)(unsigned int);
static unsigned int (*calc_ht_idx)(unsigned int, unsigned int);
static unsigned int (*get_offset)(unsigned int, unsigned int);
static void (*allocate_ht)(unsigned int, unsigned int);
static int (*test_tables)(unsigned int, OFFSET_TABLE_WORD *, unsigned int, unsigned int, unsigned int, unsigned int);
static unsigned int (*remove_duplicates)(unsigned int, unsigned int, unsigned int);
static void *loaded_hashes;
static unsigned int hash_type;
static unsigned int binary_size_actual;

static unsigned int num_loaded_hashes;

unsigned int bt_hash_table_size, shift64_ht_sz, shift128_ht_sz;

static OFFSET_TABLE_WORD *offset_table;
static unsigned int offset_table_size, shift64_ot_sz, shift128_ot_sz;
static auxilliary_offset_data *offset_data;

unsigned long long bt_total_memory_in_bytes;

static unsigned int verbosity;

static unsigned int coprime_check(unsigned int m,unsigned int n)
{
	unsigned int rem;

	while (n != 0) {
		rem = m % n;
		m = n;
		n = rem;
	}
	return m;
}

static void release_all_lists()
{
	unsigned int i;

	for (i = 0; i < offset_table_size; i++)
		bt_free((void **)&(offset_data[i].hash_location_list));
}

int bt_malloc(void **ptr, size_t size)
{
	*ptr = mem_alloc(size);
	if (*ptr || !size)
		return 0;
	return 1;
}

int bt_calloc(void **ptr, size_t num, size_t size)
{
	*ptr = mem_calloc(num, size);
	if (*ptr || !num)
		return 0;
	return 1;
}

int bt_memalign_alloc(void **ptr, size_t alignment, size_t size)
{
	*ptr = mem_alloc_align(size, alignment);
	if (*ptr || !size)
		return 0;
	return 1;
}

void bt_free(void **ptr)
{
	MEM_FREE(*ptr);
}

void bt_error_fn(const char *str, char *file, int line)
{
	fprintf(stderr, "%s in file:%s, line:%d.\n", str, file, line);
	error();
}

void bt_warn_fn(const char *str, char *file, int line)
{
	fprintf(stderr, "%s in file:%s, line:%d.\n", str, file, line);
}

static unsigned int modulo_op(void * hash, unsigned int N, uint64_t shift64, uint64_t shift128)
{
	if (hash_type == 64)
		return  modulo64_31b(*(uint64_t *)hash, N);
	else if (hash_type == 128)
		return  modulo128_31b(*(bt_uint128_t *)hash, N, shift64);
	else if (hash_type == 192)
		return  modulo192_31b(*(bt_uint192_t *)hash, N, shift64, shift128);
	else
		fprintf(stderr, "modulo op error\n");
	return 0;
}

/* Exploits the fact that sorting with a bucket is not essential. */
static void in_place_bucket_sort(unsigned int num_buckets)
{
	unsigned int *histogram;
	unsigned int *histogram_empty;
	unsigned int *prefix_sum;
	unsigned int i;

	if (bt_calloc((void **)&histogram, num_buckets + 1, sizeof(unsigned int)))
		bt_error("Failed to allocate memory: histogram.");
	if (bt_calloc((void **)&histogram_empty, num_buckets + 1, sizeof(unsigned int)))
		bt_error("Failed to allocate memory: histogram_empty.");
	if (bt_calloc((void **)&prefix_sum, num_buckets + 10, sizeof(unsigned int)))
		bt_error("Failed to allocate memory: prefix_sum.");

	i = 0;
	while (i < offset_table_size)
		histogram[num_buckets - offset_data[i++].collisions]++;

	for (i = 1; i <= num_buckets; i++)
		prefix_sum[i] = prefix_sum[i - 1] + histogram[i - 1];

	i = 0;
	while (i < prefix_sum[num_buckets]) {
		unsigned int histogram_index = num_buckets - offset_data[i].collisions;
		if (i >= prefix_sum[histogram_index] &&
		    histogram_index < num_buckets &&
		    i < prefix_sum[histogram_index + 1]) {
			histogram_empty[histogram_index]++;
			i++;
		}
		else {
			auxilliary_offset_data tmp;
			unsigned int swap_index = prefix_sum[histogram_index] + histogram_empty[histogram_index];
			histogram_empty[histogram_index]++;
			tmp = offset_data[i];
			offset_data[i] = offset_data[swap_index];
			offset_data[swap_index] = tmp;
		}
	}

	bt_free((void **)&histogram);
	bt_free((void **)&histogram_empty);
	bt_free((void **)&prefix_sum);
}

static void init_tables(unsigned int approx_offset_table_sz, unsigned int approx_hash_table_sz)
{
	unsigned int i, max_collisions, offset_data_idx;
	uint64_t shift128;

	if (verbosity > 1)
		fprintf(stdout, "\nInitialing Tables...");

	bt_total_memory_in_bytes = 0;

	approx_hash_table_sz |= 1;
	/* Repeat until two sizes are coprimes */
	while (coprime_check(approx_offset_table_sz, approx_hash_table_sz) != 1)
		approx_offset_table_sz++;

	offset_table_size = approx_offset_table_sz;
	bt_hash_table_size = approx_hash_table_sz;

	if (bt_hash_table_size > 0x7fffffff || offset_table_size > 0x7fffffff)
		bt_error("Reduce the number of loaded hashes to < 0x7fffffff.");

	shift64_ht_sz = (((1ULL << 63) % bt_hash_table_size) * 2) % bt_hash_table_size;
	shift64_ot_sz = (((1ULL << 63) % offset_table_size) * 2) % offset_table_size;

	shift128 = (uint64_t)shift64_ht_sz * shift64_ht_sz;
	shift128_ht_sz = shift128 % bt_hash_table_size;

	shift128 = (uint64_t)shift64_ot_sz * shift64_ot_sz;
	shift128_ot_sz = shift128 % offset_table_size;

	if (bt_malloc((void **)&offset_table, offset_table_size * sizeof(OFFSET_TABLE_WORD)))
		bt_error("Failed to allocate memory: offset_table.");
	bt_total_memory_in_bytes += offset_table_size * sizeof(OFFSET_TABLE_WORD);

	if (bt_malloc((void **)&offset_data, offset_table_size * sizeof(auxilliary_offset_data)))
		bt_error("Failed to allocate memory: offset_data.");
	bt_total_memory_in_bytes += offset_table_size * sizeof(auxilliary_offset_data);

	max_collisions = 0;
#if _OPENMP
#pragma omp parallel private(i, offset_data_idx)
#endif
	{
#if _OPENMP
#pragma omp for
#endif
		for (i = 0; i < offset_table_size; i++) {
			//memset(&offset_data[i], 0, sizeof(auxilliary_offset_data));
			offset_data[i].offset_table_idx = 0;
			offset_data[i].collisions = 0;
			offset_data[i].hash_location_list = NULL;
			offset_data[i].iter = 0;
			offset_table[i] = 0;
		}
#if _OPENMP
#pragma omp barrier
#endif
		/* Build Auxiliary data structure for offset_table. */
#if _OPENMP
#pragma omp for
#endif
		for (i = 0; i < num_loaded_hashes; i++) {
			offset_data_idx = modulo_op(loaded_hashes + i * binary_size_actual, offset_table_size, shift64_ot_sz, shift128_ot_sz);
#if _OPENMP
#pragma omp atomic
#endif
			offset_data[offset_data_idx].collisions++;
		}
#if _OPENMP
#pragma omp barrier
#pragma omp single
#endif
		for (i = 0; i < offset_table_size; i++)
			if (offset_data[i].collisions) {
				if (bt_malloc((void **)&offset_data[i].hash_location_list, offset_data[i].collisions * sizeof(unsigned int)))
					bt_error("Failed to allocate memory: offset_data[i].hash_location_list.");
				if (offset_data[i].collisions > max_collisions)
					max_collisions = offset_data[i].collisions;
			}
#if _OPENMP
#pragma omp barrier
MAYBE_PARALLEL_FOR
#endif
			for (i = 0; i < num_loaded_hashes; i++) {
				unsigned int iter;
				offset_data_idx = modulo_op(loaded_hashes + i * binary_size_actual, offset_table_size, shift64_ot_sz, shift128_ot_sz);
#if _OPENMP
MAYBE_ATOMIC_WRITE
#endif
					offset_data[offset_data_idx].offset_table_idx = offset_data_idx;
#if _OPENMP
MAYBE_ATOMIC_CAPTURE
#endif
					iter = offset_data[offset_data_idx].iter++;
				offset_data[offset_data_idx].hash_location_list[iter] = i;
			}
#if _OPENMP
#pragma omp barrier
#endif
	}
	bt_total_memory_in_bytes += num_loaded_hashes * sizeof(unsigned int);

	//qsort((void *)offset_data, offset_table_size, sizeof(auxilliary_offset_data), qsort_compare);
	in_place_bucket_sort(max_collisions);

	if (verbosity > 1)
		fprintf(stdout, "Done\n");

	allocate_ht(num_loaded_hashes, verbosity);

	if (verbosity > 2) {
		fprintf(stdout, "Offset Table Size %Lf %% of Number of Loaded Hashes.\n", ((long double)offset_table_size / (long double)num_loaded_hashes) * 100.00);
		fprintf(stdout, "Offset Table Size(in GBs):%Lf\n", ((long double)offset_table_size * sizeof(OFFSET_TABLE_WORD)) / ((long double)1024 * 1024 * 1024));
		fprintf(stdout, "Offset Table Aux Data Size(in GBs):%Lf\n", ((long double)offset_table_size * sizeof(auxilliary_offset_data)) / ((long double)1024 * 1024 * 1024));
		fprintf(stdout, "Offset Table Aux List Size(in GBs):%Lf\n", ((long double)num_loaded_hashes * sizeof(unsigned int)) / ((long double)1024 * 1024 * 1024));

		for (i = 0; i < offset_table_size && offset_data[i].collisions; i++)
			;
		fprintf(stdout, "Unused Slots in Offset Table:%Lf %%\n", 100.00 * (long double)(offset_table_size - i) / (long double)(offset_table_size));

		fprintf(stdout, "Total Memory Use(in GBs):%Lf\n", ((long double)bt_total_memory_in_bytes) / ((long double) 1024 * 1024 * 1024));
	}
}

static unsigned int check_n_insert_into_hash_table(unsigned int offset, auxilliary_offset_data * ptr, unsigned int *hash_table_idxs, unsigned int *store_hash_modulo_table_sz)
{
	unsigned int i;

	i = 0;
	while (i < ptr->collisions) {
		hash_table_idxs[i] = store_hash_modulo_table_sz[i] + offset;
		if (hash_table_idxs[i] >= bt_hash_table_size)
			hash_table_idxs[i] -= bt_hash_table_size;
		if (zero_check_ht(hash_table_idxs[i++]))
			return 0;
	}

	i = 0;
	while (i < ptr->collisions) {
		if (zero_check_ht(hash_table_idxs[i])) {
			unsigned int j = 0;
			while (j < i)
				assign0_ht(hash_table_idxs[j++]);
			return 0;
		}
		assign_ht(hash_table_idxs[i], ptr->hash_location_list[i]);
		i++;
	}
	return 1;
}

static void calc_hash_mdoulo_table_size(unsigned int *store, auxilliary_offset_data * ptr) {
	unsigned int i = 0;

	while (i < ptr->collisions) {
		store[i] =  modulo_op(loaded_hashes + (ptr->hash_location_list[i]) * binary_size_actual, bt_hash_table_size, shift64_ht_sz, shift128_ht_sz);
		i++;
	}
}

static unsigned int create_tables()
{
	unsigned int i;
	unsigned int bitmap = ((1ULL << (sizeof(OFFSET_TABLE_WORD) * 8)) - 1) & 0xFFFFFFFF;
	unsigned int limit = bitmap % bt_hash_table_size + 1;
	unsigned int hash_table_idx;
	unsigned int *store_hash_modulo_table_sz;
	unsigned int *hash_table_idxs;
#ifdef ENABLE_BACKTRACKING
	OFFSET_TABLE_WORD last_offset;
	unsigned int backtracking = 0;
#endif
	unsigned int trigger;
	long double done = 0;
	struct timeval t;

	if (bt_malloc((void **)&store_hash_modulo_table_sz, offset_data[0].collisions * sizeof(unsigned int)))
		bt_error("Failed to allocate memory: store_hash_modulo_table_sz.");
	if (bt_malloc((void **)&hash_table_idxs, offset_data[0].collisions * sizeof(unsigned int)))
		bt_error("Failed to allocate memory: hash_table_idxs.");

	gettimeofday(&t, NULL);

	seedMT(t.tv_sec + t.tv_usec);

	i = 0;
	trigger = 0;

	while (offset_data[i].collisions > 1) {
		OFFSET_TABLE_WORD offset;
		unsigned int num_iter;
		unsigned int start_time;

		done += offset_data[i].collisions;

		calc_hash_mdoulo_table_size(store_hash_modulo_table_sz, &offset_data[i]);

		offset = (OFFSET_TABLE_WORD)(randomMT() & bitmap) % bt_hash_table_size;

#ifdef ENABLE_BACKTRACKING
		if (backtracking) {
			offset = (last_offset + 1) % bt_hash_table_size;
			backtracking = 0;
		}
#endif
		start_time = status_get_time();

		num_iter = 0;
		while (!check_n_insert_into_hash_table((unsigned int)offset, &offset_data[i], hash_table_idxs, store_hash_modulo_table_sz) && num_iter < limit) {
			offset++;
			if (offset >= bt_hash_table_size) offset = 0;
			num_iter++;
		}

		offset_table[offset_data[i].offset_table_idx] = offset;

		if ((trigger & 0xffff) == 0) {
			trigger = 0;
			if (verbosity > 0) {
				fprintf(stdout, "\rProgress:%Lf %%, Number of collisions:%u", done / (long double)num_loaded_hashes * 100.00, offset_data[i].collisions);
				fflush(stdout);
			}
		}

		if (status_get_time() >= start_time + 3) {
			fprintf(stderr, "\nProgress is too slow!! trying next table size.\n");
			bt_free((void **)&hash_table_idxs);
			bt_free((void **)&store_hash_modulo_table_sz);
			return 0;
		}

		trigger++;

		if (num_iter == limit) {
#ifdef ENABLE_BACKTRACKING
			if (num_loaded_hashes > 1000000) {
				unsigned int j, backtrack_steps, iter;

				done -= offset_data[i].collisions;
				offset_table[offset_data[i].offset_table_idx] = 0;

				backtrack_steps = 1;
				j = 1;
				while (j <= backtrack_steps && (int)(i - j) >= 0) {
					last_offset = offset_table[offset_data[i - j].offset_table_idx];
					iter = 0;
					while (iter < offset_data[i - j].collisions) {
						hash_table_idx =
							calc_ht_idx(offset_data[i - j].hash_location_list[iter],
							            last_offset);
						assign0_ht(hash_table_idx);
						iter++;
					}
					offset_table[offset_data[i - j].offset_table_idx] = 0;
					done -= offset_data[i - j].collisions;
					j++;
				}
				i -= (j - 1);
				backtracking = 1;
				continue;
			}
#endif
			bt_free((void **)&hash_table_idxs);
			bt_free((void **)&store_hash_modulo_table_sz);
			return 0;
		}

		i++;
	}

	hash_table_idx = 0;
	while (i < offset_table_size && offset_data[i].collisions > 0) {
		done++;

		while (hash_table_idx < bt_hash_table_size) {
			if (!zero_check_ht(hash_table_idx)) {
				assign_ht(hash_table_idx, offset_data[i].hash_location_list[0]);
				break;
			}
			hash_table_idx++;
		}
		offset_table[offset_data[i].offset_table_idx] = get_offset(hash_table_idx, offset_data[i].hash_location_list[0]);
		if ((trigger & 0xffff) == 0) {
			trigger = 0;
			if (verbosity > 0) {
				fprintf(stdout, "\rProgress:%Lf %%, Number of collisions:%u", done / (long double)num_loaded_hashes * 100.00, offset_data[i].collisions);
				fflush(stdout);
			}
		}
		trigger++;
		i++;
	}

	bt_free((void **)&hash_table_idxs);
	bt_free((void **)&store_hash_modulo_table_sz);

	return 1;
}

static unsigned int next_prime(unsigned int num)
{
	if (num == 1)
		return 2;
	else if (num == 2)
		return 3;
	else if (num == 3 || num == 4)
		return 5;
	else if (num == 5 || num == 6)
		return 7;
	else if (num >= 7 && num <= 9)
		return 1;
/*	else if (num == 11 || num == 12)
		return 13;
	else if (num >= 13 && num < 17)
		return 17;
	else if (num == 17 || num == 18)
		return 19;
	else if (num >= 19 && num < 23)
		return 23;
	else if (num >= 23 && num < 29)
		return 29;
	else if (num == 29 || num == 30 )
		return 31;
	else if (num >= 31 && num < 37)
		return 37;
	else if (num >= 37 && num < 41)
		return 41;
	else if (num == 41 || num == 42 )
		return 43;
	else if (num >= 43 && num < 47)
		return 47;
	else if (num >= 47 && num < 53)
		return 53;
	else if (num >= 53 && num < 59)
		return 59;
	else if (num == 59 || num == 60)
		return 61;
	else if (num >= 61 && num < 67)
		return 67;
	else if (num >= 67 && num < 71)
		return 71;
	else if (num == 71 || num == 72)
		return 73;
	else if (num >= 73 && num < 79)
		return 79;
	else if (num >= 79 && num < 83)
		return 83;
	else if (num >= 83 && num < 89)
		return 89;
	else if (num >= 89 && num < 97)
		return 97;
	else
		return 1;*/
	return 1;
}

unsigned int bt_create_perfect_hash_table(int htype, void *loaded_hashes_ptr,
                                       unsigned int num_ld_hashes,
                                       OFFSET_TABLE_WORD **offset_table_ptr,
                                       unsigned int *offset_table_sz_ptr,
                                       unsigned int *hash_table_sz_ptr,
                                       unsigned int verb)
{
	long double multiplier_ht, multiplier_ot, inc_ht, inc_ot;
	unsigned int approx_hash_table_sz, approx_offset_table_sz, i, dupe_remove_ht_sz;

	bt_total_memory_in_bytes = 0;

	hash_type = htype;
	loaded_hashes = loaded_hashes_ptr;
	verbosity = verb;

	if (hash_type == 64) {
		zero_check_ht = zero_check_ht_64;
		assign_ht = assign_ht_64;
		assign0_ht = assign0_ht_64;
		calc_ht_idx = calc_ht_idx_64;
		get_offset = get_offset_64;
		allocate_ht = allocate_ht_64;
		test_tables = test_tables_64;
		remove_duplicates = remove_duplicates_64;
		bt_loaded_hashes_64 = (uint64_t *)loaded_hashes;
		binary_size_actual = 8;
		if (verbosity > 1)
			fprintf(stdout, "Using Hash type 64.\n");
	}

	else if (hash_type == 128) {
		zero_check_ht = zero_check_ht_128;
		assign_ht = assign_ht_128;
		assign0_ht = assign0_ht_128;
		calc_ht_idx = calc_ht_idx_128;
		get_offset = get_offset_128;
		allocate_ht = allocate_ht_128;
		test_tables = test_tables_128;
		remove_duplicates = remove_duplicates_128;
		bt_loaded_hashes_128 = (bt_uint128_t *)loaded_hashes;
		binary_size_actual = 16;
		if (verbosity > 1)
			fprintf(stdout, "Using Hash type 128.\n");
	}

	else if (hash_type == 192) {
		zero_check_ht = zero_check_ht_192;
		assign_ht = assign_ht_192;
		assign0_ht = assign0_ht_192;
		calc_ht_idx = calc_ht_idx_192;
		get_offset = get_offset_192;
		allocate_ht = allocate_ht_192;
		test_tables = test_tables_192;
		remove_duplicates = remove_duplicates_192;
		bt_loaded_hashes_192 = (bt_uint192_t *)loaded_hashes;
		binary_size_actual = 24;
		if (verbosity > 1)
			fprintf(stdout, "Using Hash type 192.\n");
	}

	inc_ht = 0.005;
	inc_ot = 0.05;

	if (num_ld_hashes <= 100) {
		multiplier_ot = 1.501375173;
		inc_ht = 0.05;
		inc_ot = 0.5;
		dupe_remove_ht_sz = 128;
	}
	else if (num_ld_hashes <= 1000) {
		multiplier_ot = 1.101375173;
		dupe_remove_ht_sz = 1024;
	}
	else if (num_ld_hashes <= 10000) {
		multiplier_ot = 1.151375173;
		dupe_remove_ht_sz = 16384;
	}
	else if (num_ld_hashes <= 100000) {
		multiplier_ot = 1.20375173;
		dupe_remove_ht_sz = 131072;
	}
	else if (num_ld_hashes <= 1000000) {
		multiplier_ot = 1.25375173;
		dupe_remove_ht_sz = 1048576;
	}
	else if (num_ld_hashes <= 10000000) {
		multiplier_ot = 1.31375173;
		dupe_remove_ht_sz = 16777216;
	}
	else if (num_ld_hashes <= 20000000) {
		multiplier_ot = 1.35375173;
		dupe_remove_ht_sz = 33554432;
	}
	else if (num_ld_hashes <= 50000000) {
		multiplier_ot = 1.41375173;
		dupe_remove_ht_sz = 67108864;
	}
	else if (num_ld_hashes <= 110000000) {
		multiplier_ot = 1.51375173;
		dupe_remove_ht_sz = 134217728;
	}
	else if (num_ld_hashes <= 200000000) {
		multiplier_ot = 1.61375173;
		dupe_remove_ht_sz = 134217728 * 2;
	}
	else {
		multiplier_ot = 3.01375173;
		dupe_remove_ht_sz = 134217728 * 4;
	}
	if (num_ld_hashes > 320294464)
		fprintf(stderr, "This many number of hashes have never been tested before and might not succeed!!\n");

	num_loaded_hashes = remove_duplicates(num_ld_hashes, dupe_remove_ht_sz, verbosity);
	if (!num_loaded_hashes)
		bt_error("Failed to remove duplicates.");

	multiplier_ht = 1.001097317;

	approx_offset_table_sz = (((long double)num_loaded_hashes / 4.0) * multiplier_ot + 10.00);
	approx_hash_table_sz = ((long double)num_loaded_hashes * multiplier_ht);

	i = 0;
	do {
		unsigned int temp;

		init_tables(approx_offset_table_sz, approx_hash_table_sz);

		if (create_tables()) {
			if (verbosity > 0)
				fprintf(stdout, "\n");
			break;
		}
		if (verbosity > 0)
			fprintf(stdout, "\n");
		release_all_lists();
		bt_free((void **)&offset_data);
		bt_free((void **)&offset_table);
		if (hash_type == 64)
			bt_free((void **)&bt_hash_table_64);
		else if (hash_type == 128)
			bt_free((void **)&bt_hash_table_128);
		else if (hash_type == 192)
			bt_free((void **)&bt_hash_table_192);

		temp = next_prime(approx_offset_table_sz % 10);
		approx_offset_table_sz /= 10;
		approx_offset_table_sz *= 10;
		approx_offset_table_sz += temp;

		i++;

		if (!(i % 5)) {
			multiplier_ot += inc_ot;
			multiplier_ht += inc_ht;
			approx_offset_table_sz = (((long double)num_loaded_hashes / 4.0) * multiplier_ot + 10.00);
			approx_hash_table_sz = ((long double)num_loaded_hashes * multiplier_ht);
		}

	} while(1);

	release_all_lists();
	bt_free((void **)&offset_data);

	*offset_table_ptr = offset_table;
	*hash_table_sz_ptr = bt_hash_table_size;
	*offset_table_sz_ptr = offset_table_size;

	if (!test_tables(num_loaded_hashes, offset_table, offset_table_size, shift64_ot_sz, shift128_ot_sz, verbosity))
		return 0;

	return num_loaded_hashes;
}

/*static int qsort_compare(const void *p1, const void *p2)
{
	auxilliary_offset_data *a = (auxilliary_offset_data *)p1;
	auxilliary_offset_data *b = (auxilliary_offset_data *)p2;

	if (a[0].collisions > b[0].collisions) return -1;
	if (a[0].collisions == b[0].collisions) return 0;
	return 1;
}*/

#endif
