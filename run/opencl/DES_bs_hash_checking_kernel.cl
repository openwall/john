/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#include "opencl_DES_kernel_params.h"

#define GET_HASH_0(hash, x, k, bits)			\
	for (bit = bits; bit < k; bit++)		\
		hash |= ((((uint)B[bit]) >> x) & 1) << bit;

#define GET_HASH_1(hash, x, k, bits)   			\
	for (bit = bits; bit < k; bit++)		\
		hash |= ((((uint)B[32 + bit]) >> x) & 1) << bit;

#define OFFSET_TABLE_SIZE hash_chk_params.offset_table_size
#define HASH_TABLE_SIZE hash_chk_params.hash_table_size

inline void cmp_final(__private unsigned DES_bs_vector *B,
		      __private unsigned DES_bs_vector *binary,
		      __global unsigned int *offset_table,
		      __global unsigned int *hash_table,
		      DES_hash_check_params hash_chk_params,
		      volatile __global uint *hash_ids,
		      volatile __global uint *bitmap_dupe,
		      unsigned int section,
		      unsigned int depth,
		      unsigned int start_bit)
{
	unsigned long hash;
	unsigned int hash_table_index, t, bit;

	GET_HASH_0(binary[0], depth, 32, start_bit);
	GET_HASH_1(binary[1], depth, 32, start_bit);

	hash = ((unsigned long)binary[1] << 32) | (unsigned long)binary[0];
	hash += (unsigned long)offset_table[hash % OFFSET_TABLE_SIZE];
	hash_table_index = hash % HASH_TABLE_SIZE;

	if (hash_table[hash_table_index + HASH_TABLE_SIZE] == binary[1])
	if (hash_table[hash_table_index] == binary[0])
	if (!(atomic_or(&bitmap_dupe[hash_table_index/32], (1U << (hash_table_index % 32))) & (1U << (hash_table_index % 32)))) {
		t = atomic_inc(&hash_ids[0]);
		hash_ids[1 + 2 * t] = (section * 32) + depth;
		hash_ids[2 + 2 * t] = hash_table_index;
	}
}

#define BITMAP_SIZE_BITS hash_chk_params.bitmap_size_bits
#define BITMAP_SIZE_BITS_LESS_ONE (BITMAP_SIZE_BITS - 1)

__kernel void DES_bs_cmp_high(__global unsigned DES_bs_vector *unchecked_hashes,
	  __global unsigned int *offset_table,
	  __global unsigned int *hash_table,
	  DES_hash_check_params hash_chk_params,
	  volatile __global uint *hash_ids,
	  volatile __global uint *bitmap_dupe,
	  __global uint *bitmaps) {

	int i;
	unsigned DES_bs_vector B[64];
	int section = get_global_id(0);
	int gws = get_global_size(0);
	unsigned int value[2] , bit, bitmap_index;

	for (i = 0; i < 64; i++)
		B[i] = unchecked_hashes[section + i * gws];

	for (i = 0; i < 32; i++) {
		value[0] = 0;
		value[1] = 0;
		GET_HASH_1(value[1], i, hash_chk_params.cmp_bits, 0);
		bitmap_index = value[1] & BITMAP_SIZE_BITS_LESS_ONE;
		bit = (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
		if (bit)
		cmp_final(B, value, offset_table, hash_table, hash_chk_params, hash_ids, bitmap_dupe, section, i, 0);
	}
}

#define num_uncracked_hashes hash_chk_params.num_uncracked_hashes

__kernel void DES_bs_cmp(__global unsigned DES_bs_vector *unchecked_hashes,
	  __global unsigned int *offset_table,
	  __global unsigned int *hash_table,
	  DES_hash_check_params hash_chk_params,
	  volatile __global uint *hash_ids,
	  volatile __global uint *bitmap_dupe,
	  __global int *uncracked_hashes) {

	unsigned DES_bs_vector value[2] , mask, i, bit;
	unsigned DES_bs_vector B[64];
	int section = get_global_id(0);
	int gws = get_global_size(0);

	for (i = 0; i < 64; i++)
		B[i] = unchecked_hashes[section + i * gws];

	for (i = 0; i < num_uncracked_hashes; i++) {

		value[0] = uncracked_hashes[i];
		value[1] = uncracked_hashes[i + num_uncracked_hashes];

		mask = B[0] ^ -(value[0] & 1);

		for (bit = 1; bit < 32; bit++)
			mask |= B[bit] ^ -((value[0] >> bit) & 1);

		for (; bit < 64; bit += 2) {
			mask |= B[bit] ^ -((value[1] >> (bit & 0x1F)) & 1);
			mask |= B[bit + 1] ^ -((value[1] >> ((bit + 1) & 0x1F)) & 1);
		}

		if (mask != ~0U) {
			for (mask = 0; mask < 32; mask++) {
				value[0] = value[1] = 0;
				cmp_final(B, value, offset_table, hash_table, hash_chk_params, hash_ids, bitmap_dupe, section, mask, 0);
			}
		}
	}
}
