/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */
#include "opencl_DES_kernel_params.h"

#if 1
#define MAYBE_GLOBAL __global
#else
#define MAYBE_GLOBAL
#endif

#define kvtype vtype
#define kvand vand
#define kvor vor
#define kvshl1 vshl1
#define kvshl vshl
#define kvshr vshr

#define mask01 0x01010101
#define mask02 0x02020202
#define mask04 0x04040404
#define mask08 0x08080808
#define mask10 0x10101010
#define mask20 0x20202020
#define mask40 0x40404040
#define mask80 0x80808080

#define kvand_shl1_or(dst, src, mask) 			\
	kvand(tmp, src, mask); 				\
	kvshl1(tmp, tmp); 				\
	kvor(dst, dst, tmp)

#define kvand_shl_or(dst, src, mask, shift) 		\
	kvand(tmp, src, mask); 				\
	kvshl(tmp, tmp, shift); 			\
	kvor(dst, dst, tmp)

#define kvand_shl1(dst, src, mask) 			\
	kvand(tmp, src, mask) ;				\
	kvshl1(dst, tmp)

#define kvand_or(dst, src, mask) 			\
	kvand(tmp, src, mask); 				\
	kvor(dst, dst, tmp)

#define kvand_shr_or(dst, src, mask, shift)		\
	kvand(tmp, src, mask); 				\
	kvshr(tmp, tmp, shift); 			\
	kvor(dst, dst, tmp)

#define kvand_shr(dst, src, mask, shift) 		\
	kvand(tmp, src, mask); 				\
	kvshr(dst, tmp, shift)

#define LOAD_V 						\
	kvtype v0 = *(MAYBE_GLOBAL kvtype *)&vp[0]; 	\
	kvtype v1 = *(MAYBE_GLOBAL kvtype *)&vp[1]; 	\
	kvtype v2 = *(MAYBE_GLOBAL kvtype *)&vp[2]; 	\
	kvtype v3 = *(MAYBE_GLOBAL kvtype *)&vp[3]; 	\
	kvtype v4 = *(MAYBE_GLOBAL kvtype *)&vp[4]; 	\
	kvtype v5 = *(MAYBE_GLOBAL kvtype *)&vp[5]; 	\
	kvtype v6 = *(MAYBE_GLOBAL kvtype *)&vp[6]; 	\
	kvtype v7 = *(MAYBE_GLOBAL kvtype *)&vp[7];

#define FINALIZE_NEXT_KEY_BIT_0g { 			\
	kvtype m = mask01, va, vb, tmp; 		\
	kvand(va, v0, m); 				\
	kvand_shl1(vb, v1, m); 				\
	kvand_shl_or(va, v2, m, 2); 			\
	kvand_shl_or(vb, v3, m, 3); 			\
	kvand_shl_or(va, v4, m, 4); 			\
	kvand_shl_or(vb, v5, m, 5); 			\
	kvand_shl_or(va, v6, m, 6); 			\
	kvand_shl_or(vb, v7, m, 7); 			\
	kvor(kp[0], va, vb); 				\
	kp += gws; 						\
}

#define FINALIZE_NEXT_KEY_BIT_1g { 			\
	kvtype m = mask02, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 1); 			\
	kvand(vb, v1, m); 				\
	kvand_shl1_or(va, v2, m); 			\
	kvand_shl_or(vb, v3, m, 2); 			\
	kvand_shl_or(va, v4, m, 3); 			\
	kvand_shl_or(vb, v5, m, 4); 			\
	kvand_shl_or(va, v6, m, 5); 			\
	kvand_shl_or(vb, v7, m, 6); 			\
	kvor(kp[0], va, vb); 				\
	kp += gws; 						\
}

#define FINALIZE_NEXT_KEY_BIT_2g { 			\
	kvtype m = mask04, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 2); 			\
	kvand_shr(vb, v1, m, 1); 			\
	kvand_or(va, v2, m); 				\
	kvand_shl1_or(vb, v3, m); 			\
	kvand_shl_or(va, v4, m, 2); 			\
	kvand_shl_or(vb, v5, m, 3); 			\
	kvand_shl_or(va, v6, m, 4); 			\
	kvand_shl_or(vb, v7, m, 5); 			\
	kvor(kp[0], va, vb); 				\
	kp += gws; 						\
}

#define FINALIZE_NEXT_KEY_BIT_3g { 			\
	kvtype m = mask08, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 3); 			\
	kvand_shr(vb, v1, m, 2); 			\
	kvand_shr_or(va, v2, m, 1); 			\
	kvand_or(vb, v3, m); 				\
	kvand_shl1_or(va, v4, m); 			\
	kvand_shl_or(vb, v5, m, 2); 			\
	kvand_shl_or(va, v6, m, 3); 			\
	kvand_shl_or(vb, v7, m, 4); 			\
	kvor(kp[0], va, vb); 				\
	kp += gws; 						\
}

#define FINALIZE_NEXT_KEY_BIT_4g { 			\
	kvtype m = mask10, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 4); 			\
	kvand_shr(vb, v1, m, 3); 			\
	kvand_shr_or(va, v2, m, 2); 			\
	kvand_shr_or(vb, v3, m, 1); 			\
	kvand_or(va, v4, m); 				\
	kvand_shl1_or(vb, v5, m); 			\
	kvand_shl_or(va, v6, m, 2); 			\
	kvand_shl_or(vb, v7, m, 3); 			\
	kvor(kp[0], va, vb); 				\
	kp += gws; 						\
}

#define FINALIZE_NEXT_KEY_BIT_5g { 			\
	kvtype m = mask20, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 5); 			\
	kvand_shr(vb, v1, m, 4); 			\
	kvand_shr_or(va, v2, m, 3); 			\
	kvand_shr_or(vb, v3, m, 2); 			\
	kvand_shr_or(va, v4, m, 1); 			\
	kvand_or(vb, v5, m); 				\
	kvand_shl1_or(va, v6, m); 			\
	kvand_shl_or(vb, v7, m, 2); 			\
	kvor(kp[0], va, vb); 				\
	kp += gws; 						\
}

#define FINALIZE_NEXT_KEY_BIT_6g { 			\
	kvtype m = mask40, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 6); 			\
	kvand_shr(vb, v1, m, 5); 			\
	kvand_shr_or(va, v2, m, 4); 			\
	kvand_shr_or(vb, v3, m, 3); 			\
	kvand_shr_or(va, v4, m, 2); 			\
	kvand_shr_or(vb, v5, m, 1); 			\
	kvand_or(va, v6, m); 				\
	kvand_shl1_or(vb, v7, m); 			\
	kvor(kp[0], va, vb); 				\
	kp += gws; 						\
}

#define FINALIZE_NEXT_KEY_BIT_7g { 			\
	kvtype m = mask80, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 7); 			\
	kvand_shr(vb, v1, m, 6); 			\
	kvand_shr_or(va, v2, m, 5); 			\
	kvand_shr_or(vb, v3, m, 4); 			\
	kvand_shr_or(va, v4, m, 3); 			\
	kvand_shr_or(vb, v5, m, 2); 			\
	kvand_shr_or(va, v6, m, 1); 			\
	kvand_or(vb, v7, m); 				\
	kvor(kp[0], va, vb); 				\
	kp += gws;				\
}

__kernel void DES_bs_finalize_keys(__global opencl_DES_bs_transfer *des_raw_keys,
				   __global DES_bs_vector *des_bs_keys) {

	int section = get_global_id(0);
	int gws = get_global_size(0);
	__global DES_bs_vector *kp = (__global DES_bs_vector *)&des_bs_keys[section];

	int ic ;
	for (ic = 0; ic < 8; ic++) {
		MAYBE_GLOBAL DES_bs_vector *vp =
		    (MAYBE_GLOBAL DES_bs_vector *)&des_raw_keys[section].xkeys.v[ic][0] ;
		LOAD_V
		FINALIZE_NEXT_KEY_BIT_0g
		FINALIZE_NEXT_KEY_BIT_1g
		FINALIZE_NEXT_KEY_BIT_2g
		FINALIZE_NEXT_KEY_BIT_3g
		FINALIZE_NEXT_KEY_BIT_4g
		FINALIZE_NEXT_KEY_BIT_5g
		FINALIZE_NEXT_KEY_BIT_6g
	}
}

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
		      unsigned int start_bit,
		      unsigned int cmp_steps
 		    )
{
	unsigned long hash;
	unsigned int hash_table_index, t, bit;

	if (cmp_steps > 1) {
		GET_HASH_0(binary[0], depth, 32, start_bit);
		GET_HASH_1(binary[1], depth, 32, start_bit);
	}
	else {
		GET_HASH_0(binary[0], depth, 32, 0);
		GET_HASH_1(binary[1], depth, 32, start_bit);
	}

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

#define BITMAP_SIZE_BITS hash_chk_params.bitmap_size_bits
#define BITMAP_SIZE_BITS_LESS_ONE (BITMAP_SIZE_BITS - 1)

	for (i = 0; i < 64; i++)
		B[i] = unchecked_hashes[section + i * gws];

	value[0] = 0;
	if (hash_chk_params.cmp_steps > 1) {
	for (i = 0; i < 32; i++) {
		value[0] = 0;
		value[1] = 0;
		GET_HASH_0(value[0], i, hash_chk_params.cmp_bits, 0);
		GET_HASH_1(value[1], i, hash_chk_params.cmp_bits, 0);
		bitmap_index = value[1] & (BITMAP_SIZE_BITS - 1);
		bit = (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
		bitmap_index = value[0] & (BITMAP_SIZE_BITS - 1);
		bit &= (bitmaps[(BITMAP_SIZE_BITS >> 5) + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
		if (bit)
		cmp_final(B, value, offset_table, hash_table, hash_chk_params, hash_ids, bitmap_dupe, section, i, hash_chk_params.cmp_bits, hash_chk_params.cmp_steps);
	}
	}

	else {
	for (i = 0; i < 32; i++) {
		value[1] = 0;
		GET_HASH_1(value[1], i, hash_chk_params.cmp_bits, 0);
		bitmap_index = value[1] & BITMAP_SIZE_BITS_LESS_ONE;
		bit = (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
		if (bit)
		cmp_final(B, value, offset_table, hash_table, hash_chk_params, hash_ids, bitmap_dupe, section, i, hash_chk_params.cmp_bits, hash_chk_params.cmp_steps);
	}
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

	int value[2] , mask, i, bit;
	unsigned DES_bs_vector B[64];
	int section = get_global_id(0);
	int gws = get_global_size(0);

	for (i = 0; i < 64; i++)
		B[i] = unchecked_hashes[section + i * gws];

	for(i = 0; i < num_uncracked_hashes; i++) {

		value[0] = uncracked_hashes[i];
		value[1] = uncracked_hashes[i + num_uncracked_hashes];

		mask = B[0] ^ -(value[0] & 1);

		for (bit = 1; bit < 32; bit++)
			mask |= B[bit] ^ -((value[0] >> bit) & 1);

		for (; bit < 64; bit += 2) {
			mask |= B[bit] ^ -((value[1] >> (bit & 0x1F)) & 1);
			mask |= B[bit + 1] ^ -((value[1] >> ((bit + 1) & 0x1F)) & 1);
		}

		if (mask != ~(int)0) {
			for (mask = 0; mask < 32; mask++) {
				value[0] = value[1] = 0;
				cmp_final(B, value, offset_table, hash_table, hash_chk_params, hash_ids, bitmap_dupe, section, mask, 0, 2);
			}
		}
	}
}
