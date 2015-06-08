/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include <stdlib.h>
#include <stdio.h>
#include "hash_types.h"

uint128_t *loaded_hashes_128 = NULL;
unsigned int *hash_table_128 = NULL;

/* Assuming N < 0x7fffffff */
inline unsigned int modulo128_31b(uint128_t a, unsigned int N, uint64_t shift64)
{
	uint64_t p;
	p = (a.HI64 % N) * shift64;
	p += (a.LO64 % N);
	p %= N;
	return (unsigned int)p;
}

inline uint128_t add128(uint128_t a, unsigned int b)
{
	uint128_t result;
	result.LO64 = a.LO64 + b;
	result.HI64 = a.HI64 + (result.LO64 < a.LO64);
	if (result.HI64 < a.HI64) {
		fprintf(stderr, "128 bit add overflow!!\n");
		exit(0);
	}

	return result;
}

void allocate_ht_128(unsigned int num_loaded_hashes, unsigned int verbosity)
{
	int i;

	if (posix_memalign((void **)&hash_table_128, 16, 4 * hash_table_size * sizeof(unsigned int))) {
		fprintf(stderr, "Couldn't allocate memory!!\n");
		exit(0);
	}

	for (i = 0; i < hash_table_size; i++)
		hash_table_128[i] = hash_table_128[i + hash_table_size]
			= hash_table_128[i + 2 * hash_table_size]
			= hash_table_128[i + 3 * hash_table_size] = 0;

	total_memory_in_bytes += 4 * hash_table_size * sizeof(unsigned int);

	if (verbosity > 2) {
		fprintf(stdout, "Hash Table Size %Lf %% of Number of Loaded Hashes.\n", ((long double)hash_table_size / (long double)num_loaded_hashes) * 100.00);
		fprintf(stdout, "Hash Table Size(in GBs):%Lf\n", ((long double)4.0 * hash_table_size * sizeof(unsigned int)) / ((long double)1024 * 1024 * 1024));
	}
}

inline unsigned int calc_ht_idx_128(unsigned int hash_location, unsigned int offset)
{
	return  modulo128_31b(add128(loaded_hashes_128[hash_location], offset), hash_table_size, shift64_ht_sz);
}

inline unsigned int zero_check_ht_128(unsigned int hash_table_idx)
{
	return ((hash_table_128[hash_table_idx] || hash_table_128[hash_table_idx + hash_table_size] ||
		hash_table_128[hash_table_idx + 2 * hash_table_size] ||
		hash_table_128[hash_table_idx + 3 * hash_table_size]));
}

inline void assign_ht_128(unsigned int hash_table_idx, unsigned int hash_location)
{
	uint128_t hash = loaded_hashes_128[hash_location];
	hash_table_128[hash_table_idx] = (unsigned int)(hash.LO64 & 0xffffffff);
	hash_table_128[hash_table_idx + hash_table_size] = (unsigned int)(hash.LO64 >> 32);
	hash_table_128[hash_table_idx + 2 * hash_table_size] = (unsigned int)(hash.HI64 & 0xffffffff);
	hash_table_128[hash_table_idx + 3 * hash_table_size] = (unsigned int)(hash.HI64 >> 32);
}

inline void assign0_ht_128(unsigned int hash_table_idx)
{
	hash_table_128[hash_table_idx] = hash_table_128[hash_table_idx + hash_table_size]
			= hash_table_128[hash_table_idx + 2 * hash_table_size]
			= hash_table_128[hash_table_idx + 3 * hash_table_size] = 0;
}

unsigned int get_offset_128(unsigned int hash_table_idx, unsigned int hash_location)
{
	unsigned int z = modulo128_31b(loaded_hashes_128[hash_location], hash_table_size, shift64_ht_sz);
	return (hash_table_size - z + hash_table_idx);
}

int test_tables_128(unsigned int num_loaded_hashes, OFFSET_TABLE_WORD *offset_table, unsigned int offset_table_size, unsigned int shift64_ot_sz, unsigned int shift128_ot_sz, unsigned int verbosity)
{
	unsigned char *hash_table_collisions;
	unsigned int i, hash_table_idx, error = 1, count = 0;
	uint128_t hash;

	hash_table_collisions = (unsigned char *) calloc(hash_table_size, sizeof(unsigned char));

	if (verbosity > 1)
		fprintf(stdout, "\nTesting Tables...");

#pragma omp parallel private(i, hash_table_idx, hash)
	{
#pragma omp for
		for (i = 0; i < num_loaded_hashes; i++) {
			hash = loaded_hashes_128[i];
			hash_table_idx =
				calc_ht_idx_128(i,
					(unsigned int)offset_table[
					modulo128_31b(hash,
					offset_table_size, shift64_ot_sz)]);
#pragma omp atomic
			hash_table_collisions[hash_table_idx]++;

			if (error && (hash_table_128[hash_table_idx] != (unsigned int)(hash.LO64 & 0xffffffff)  ||
			    hash_table_128[hash_table_idx + hash_table_size] != (unsigned int)(hash.LO64 >> 32) ||
			    hash_table_128[hash_table_idx + 2 * hash_table_size] != (unsigned int)(hash.HI64 & 0xffffffff) ||
			    hash_table_128[hash_table_idx + 3 * hash_table_size] != (unsigned int)(hash.HI64 >> 32) ||
			    hash_table_collisions[hash_table_idx] > 1)) {
				fprintf(stderr, "Error building tables: Loaded hash Idx:%u, No. of Collosions:%u\n", i, hash_table_collisions[hash_table_idx]);
				error = 0;
			}

		}
#pragma omp single
		for (hash_table_idx = 0; hash_table_idx < hash_table_size; hash_table_idx++)
			if (zero_check_ht_128(hash_table_idx))
				count++;
#pragma omp barrier
	}

	if (count != num_loaded_hashes) {
		error = 0;
		fprintf(stderr, "Error!! Tables contains extra or less entries.\n");
		return 0;
	}

	free(hash_table_collisions);

	if (error && verbosity > 1)
		fprintf(stdout, "OK\n");

	return 1;
}

#define check_equal(p, q) \
	(loaded_hashes_128[p].LO64 == loaded_hashes_128[q].LO64 &&	\
	 loaded_hashes_128[p].HI64 == loaded_hashes_128[q].HI64)

#define check_non_zero(p) \
	(loaded_hashes_128[p].LO64 || loaded_hashes_128[p].HI64)

#define check_zero(p) \
	(loaded_hashes_128[p].LO64 == 0 && loaded_hashes_128[p].HI64 == 0)

#define set_zero(p) \
	loaded_hashes_128[p].LO64 = loaded_hashes_128[p].HI64 = 0

static void remove_duplicates_final(unsigned int num_loaded_hashes, unsigned int hash_table_size, unsigned int *rehash_list)
{
	unsigned int i, **hash_location_list, counter;
#define COLLISION_DTYPE unsigned short
	COLLISION_DTYPE *collisions;
	typedef struct {
		unsigned int store_loc1;
		unsigned int store_loc2;
		unsigned int idx_hash_loc_list;
		COLLISION_DTYPE  collisions;
		COLLISION_DTYPE iter;
	} hash_table_data;

	hash_table_data *hash_table = (hash_table_data *) malloc(hash_table_size * sizeof(hash_table_data));
	collisions = (COLLISION_DTYPE *) calloc(hash_table_size, sizeof(COLLISION_DTYPE));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int idx = loaded_hashes_128[rehash_list[i]].LO64 % hash_table_size;
		collisions[idx]++;
	}

	counter = 0;
	for (i = 0; i < hash_table_size; i++) {
		 hash_table[i].collisions = collisions[i];
		 hash_table[i].iter = 0;
		 hash_table[i].store_loc1 = hash_table[i].store_loc2 =
			hash_table[i].idx_hash_loc_list = 0xffffffff;
		if (hash_table[i].collisions > 3)
			hash_table[i].idx_hash_loc_list = counter++;
	}

	hash_location_list = (unsigned int **) malloc((counter + 1) * sizeof(unsigned int *));

	counter = 0;
	for (i = 0; i < hash_table_size; i++)
	      if (collisions[i] > 3)
			hash_location_list[counter++] = (unsigned int *) malloc((collisions[i] - 1) * sizeof(unsigned int));

	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int k = rehash_list[i];
		unsigned int idx = loaded_hashes_128[k].LO64 % hash_table_size ;

		if (collisions[idx] == 2) {
			if (!hash_table[idx].iter) {
				hash_table[idx].iter++;
				hash_table[idx].store_loc1 = k;
			}
			else if (check_equal(hash_table[idx].store_loc1, k))
				set_zero(k);
		}

		if (collisions[idx] == 3) {
			if (!hash_table[idx].iter) {
				hash_table[idx].iter++;
				hash_table[idx].store_loc1 = k;
			}
			else if (hash_table[idx].iter == 1) {
				if (check_equal(hash_table[idx].store_loc1, k))
					set_zero(k);
				else
					hash_table[idx].store_loc2 = k;
			}
			else if (check_equal(hash_table[idx].store_loc1, k) ||
				 check_equal(hash_table[idx].store_loc2, k))
				set_zero(k);
		}

		else if (collisions[idx] > 3) {
			unsigned int iter = hash_table[idx].iter;
			if (!iter)
				hash_location_list[hash_table[idx].idx_hash_loc_list][iter++] = k;
			else {
				unsigned int j;
				for (j = 0; j < iter; j++)
					if (check_equal(hash_location_list[hash_table[idx].idx_hash_loc_list][j], k)) {
						set_zero(k);
						break;
					}
				if (j == iter && iter < hash_table[idx].collisions - 1)
					hash_location_list[hash_table[idx].idx_hash_loc_list][iter++] = k;
			}
			hash_table[idx].iter = iter;
		}
	}

#undef COLLISION_DTYPE
	for (i = 0; i < counter; i++)
		free(hash_location_list[i]);
	free(hash_location_list);
	free(hash_table);
	free(collisions);
}

unsigned int remove_duplicates_128(unsigned int num_loaded_hashes, unsigned int hash_table_size, unsigned int verbosity)
{
	unsigned int i, num_unique_hashes, *rehash_list, counter;
#define COLLISION_DTYPE unsigned short
	COLLISION_DTYPE *collisions;
	typedef struct {
		unsigned int store_loc1;
		unsigned int store_loc2;
		unsigned int store_loc3;
		COLLISION_DTYPE  collisions;
		COLLISION_DTYPE iter;

	} hash_table_data;

	hash_table_data *hash_table = NULL;

	if (verbosity > 1)
		fprintf(stdout, "Removing duplicate hashes...");

	if (hash_table_size & (hash_table_size - 1)) {
		fprintf(stderr, "Duplicate removal hash table size must power of 2.\n");
		return 0;
	}

	hash_table = (hash_table_data *) malloc(hash_table_size * sizeof(hash_table_data));
	collisions = (COLLISION_DTYPE *) calloc(hash_table_size, sizeof(COLLISION_DTYPE));
#pragma omp parallel private(i)
{
#pragma omp for
	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int idx = loaded_hashes_128[i].LO64 & (hash_table_size - 1);
#pragma omp atomic
		collisions[idx]++;
	}

	counter = 0;
#pragma omp barrier

#pragma omp for
	for (i = 0; i < hash_table_size; i++) {
		 hash_table[i].collisions = collisions[i];
		 hash_table[i].iter = 0;
		 if (hash_table[i].collisions > 4)
#pragma omp atomic
			 counter += (hash_table[i].collisions - 3);
	}
#pragma omp barrier

#pragma omp sections
{
#pragma omp section
{
	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int idx = loaded_hashes_128[i].LO64 & (hash_table_size - 1);

		if (collisions[idx] == 2) {
			if (!hash_table[idx].iter) {
				hash_table[idx].iter++;
				hash_table[idx].store_loc1 = i;
			}
			else if (check_equal(hash_table[idx].store_loc1, i))
				set_zero(i);
		}
	}
}

#pragma omp section
{
	rehash_list = (unsigned int *) malloc(counter * sizeof(unsigned int));
	counter = 0;
	for (i = 0; i < num_loaded_hashes; i++) {
		unsigned int idx = loaded_hashes_128[i].LO64 & (hash_table_size - 1);

		if (collisions[idx] == 3) {
			if (!hash_table[idx].iter) {
				hash_table[idx].iter++;
				hash_table[idx].store_loc1 = i;
			}
			else if (hash_table[idx].iter == 1) {
				if (check_equal(hash_table[idx].store_loc1, i))
					set_zero(i);
				else {
					hash_table[idx].iter++;
					hash_table[idx].store_loc2 = i;
				}
			}
			else if (check_equal(hash_table[idx].store_loc1, i) ||
				 check_equal(hash_table[idx].store_loc2, i))
				set_zero(i);
		}

		else if (collisions[idx] >= 4) {
			if (!hash_table[idx].iter) {
				hash_table[idx].iter++;
				hash_table[idx].store_loc1 = i;
			}
			else if (hash_table[idx].iter == 1) {
				if (check_equal(hash_table[idx].store_loc1, i))
					set_zero(i);
				else {
					hash_table[idx].iter++;
					hash_table[idx].store_loc2 = i;
				}

			}
			else if (hash_table[idx].iter == 2) {
				if (check_equal(hash_table[idx].store_loc1, i) ||
				    check_equal(hash_table[idx].store_loc2, i))
					set_zero(i);
				else {
					hash_table[idx].iter++;
					hash_table[idx].store_loc3 = i;
				}
			}
			else if (hash_table[idx].iter >= 3) {
				if (check_equal(hash_table[idx].store_loc1, i) ||
				    check_equal(hash_table[idx].store_loc2, i) ||
				    check_equal(hash_table[idx].store_loc3, i))
					set_zero(i);
				else {
					if (hash_table[idx].collisions > 4)
						rehash_list[counter++] = i;
				}
			}
		}
	}

	if (counter)
		remove_duplicates_final(counter, counter + (counter >> 1), rehash_list);
	free(rehash_list);
}
}
}

#if 0
	{	unsigned int col1 = 0, col2 = 0, col3 = 0, col4 = 0, col5a = 0;
		for (i = 0; i < hash_table_size; i++) {
			if (collisions[i] == 1)
				col1++;
			else if (collisions[i] == 2)
				col2++;
			else if (collisions[i] == 3)
				col3++;
			else if (collisions[i] == 4)
				col4++;
			else if (collisions[i] > 4)
				col5a += collisions[i];
		}
		col2 *= 2;
		col3 *= 3;
		col4 *= 4;
		fprintf(stderr, "Statistics:%Lf %Lf %Lf %Lf %Lf\n", (long double)col1 / (long double)num_loaded_hashes,
		  (long double)col2 / (long double)num_loaded_hashes, (long double)col3 / (long double)num_loaded_hashes,
			(long double)col4 / (long double)num_loaded_hashes, (long double)col5a / (long double)num_loaded_hashes);

	}
#endif
	for (i = num_loaded_hashes - 1; i >= 0; i--)
		if (check_non_zero(i)) {
			num_unique_hashes = i;
			break;
		}

	for (i = 0; i <= num_unique_hashes; i++)
		if (check_zero(i)) {
			unsigned int j;
			loaded_hashes_128[i] = loaded_hashes_128[num_unique_hashes];
			set_zero(num_unique_hashes);
			num_unique_hashes--;
			for (j = num_unique_hashes; j >= 0; j--)
				if (check_non_zero(j)) {
					num_unique_hashes = j;
					break;
				}
		}
#undef COLLISION_DTYPE
	free(collisions);
	free(hash_table);

	if (verbosity > 1)
		fprintf(stdout, "Done\n");

	return (num_unique_hashes + 1);
}