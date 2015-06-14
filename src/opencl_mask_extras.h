/*
 * This file is part of John the Ripper password cracker.
 *
 * Common OpenCL functions go in this file.
 *
 * This software is
 * Copyright (c) 2014 by Sayantan Datta
 * Copyright (c) 2012-2015 Claudio André <claudioandre.br at gmail.com>
 * and is hereby released to the general public under the following terms:
 *    Redistribution and use in source and binary forms, with or without
 *    modifications, are permitted.
 */

#ifndef _JOHN_OPENCL_MASK_H
#define _JOHN_OPENCL_MASK_H

#include "opencl_mask.h"

#ifdef _OPENCL_COMPILER
//To keep Sayantan license, some code was moved to this file.

inline void compare(
	      const uint32_t iter,		//which candidates_number is this one
	      const uint32_t num_loaded_hashes,	//number of password hashes transferred
     __global const uint32_t * loaded_hashes,   //buffer of password hashes transferred
  volatile __global uint32_t * hash_id,		//information about how recover the cracked password
	      const uint32_t * hash,		//the hash calculated by this kernel
  volatile __global uint32_t * bitmap) {

    uint32_t found, j;

    for (j = 0; j < num_loaded_hashes; j++) {
	//It is not really better to handle only part of binary (hash[0]) on GPU.
	found = (loaded_hashes[HASH_PARTS * j] == hash[0]);

	if (found) {
	    	found =
		    (loaded_hashes[HASH_PARTS * j + 1] == hash[1]) &&
		    (loaded_hashes[HASH_PARTS * j + 2] == hash[2]) &&
		    (loaded_hashes[HASH_PARTS * j + 3] == hash[3]) &&
		    (loaded_hashes[HASH_PARTS * j + 4] == hash[4]) &&
		    (loaded_hashes[HASH_PARTS * j + 5] == hash[5]) &&
		    (loaded_hashes[HASH_PARTS * j + 6] == hash[6]) &&
		    (loaded_hashes[HASH_PARTS * j + 7] == hash[7]);

	    if (found) {
		/* Prevent duplicate keys from cracking same hash */
		if (!(atomic_or(&bitmap[j/32], (1U << (j % 32))) &
			(1U << (j % 32)))) {
		    found = atomic_inc(&hash_id[0]);

		    hash_id[1 + 3 * found] = get_global_id(0);
		    hash_id[2 + 3 * found] = iter;
		    hash_id[3 + 3 * found] = j;
		}
	    }
	}
    }
}

inline void compare_64(
	      const uint32_t iter,		//which candidates_number is this one
	      const uint32_t num_loaded_hashes,	//number of password hashes transferred
     __global const uint64_t * loaded_hashes,   //buffer of password hashes transferred
  volatile __global uint32_t * hash_id,		//information about how recover the cracked password
	      const uint64_t * hash,		//the hash calculated by this kernel
  volatile __global uint32_t * bitmap) {

    uint32_t found, j;

    for (j = 0; j < num_loaded_hashes; j++) {
	//It is not really better to handle only part of binary (hash[0]) on GPU.
	found = (loaded_hashes[HASH_PARTS * j] == hash[0]);

	if (found) {
	    	found =
		    (loaded_hashes[HASH_PARTS * j + 1] == hash[1]) &&
		    (loaded_hashes[HASH_PARTS * j + 2] == hash[2]) &&
		    (loaded_hashes[HASH_PARTS * j + 3] == hash[3]) &&
		    (loaded_hashes[HASH_PARTS * j + 4] == hash[4]) &&
		    (loaded_hashes[HASH_PARTS * j + 5] == hash[5]) &&
		    (loaded_hashes[HASH_PARTS * j + 6] == hash[6]) &&
		    (loaded_hashes[HASH_PARTS * j + 7] == hash[7]);

	    if (found) {
		/* Prevent duplicate keys from cracking same hash */
		if (!(atomic_or(&bitmap[j/32], (1U << (j % 32))) &
			(1U << (j % 32)))) {
		    found = atomic_inc(&hash_id[0]);

		    hash_id[1 + 3 * found] = get_global_id(0);
		    hash_id[2 + 3 * found] = iter;
		    hash_id[3 + 3 * found] = j;
		}
	    }
	}
    }
}

#define	MASK_KEYS_GENERATION \
	if (candidates_number > 1) {								\
		uint32_t ikl = int_key_loc[get_global_id(0)];					\
		PUTCHAR(w, (ikl & 0xff) + W_OFFSET, (int_keys[i] & 0xff));					\
												\
		if ((ikl & 0xff00) != 0x8000)							\
		    PUTCHAR(w, ((ikl & 0xff00U) >> 8) + W_OFFSET,				\
						((int_keys[i] & 0xff00U) >> 8));		\
												\
		if ((ikl & 0xff0000) != 0x800000)						\
		    PUTCHAR(w, ((ikl & 0xff0000U) >> 16) + W_OFFSET,				\
							((int_keys[i] & 0xff0000U) >> 16));	\
												\
		if ((ikl & 0xff000000) != 0x80000000)						\
		    PUTCHAR(w, ((ikl & 0xff000000U) >> 24) + W_OFFSET,				\
						    ((int_keys[i] & 0xff000000U) >> 24));	\
	}

#endif

#endif
