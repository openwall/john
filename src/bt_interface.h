/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#ifdef HAVE_OPENCL

#include <inttypes.h>
#define OFFSET_TABLE_WORD unsigned int

typedef struct {
	uint64_t LO64;
	uint64_t HI64;
} bt_uint128_t;

typedef struct {
	uint64_t LO;
	uint64_t MI;
	uint64_t HI;
} bt_uint192_t;

extern unsigned int *bt_hash_table_64; // Hash Table for 64 bit hashes.
extern unsigned int *bt_hash_table_128; // Hash Table for 128 bit hashes.
extern unsigned int *bt_hash_table_192; // Hash Table for 192 bit hashes.

/*
 * Function to build a Perfect Hash Table from an array of hashes.
 * Warning: loaded_hashes_ptr must be of type 'uint64_t *' for hashes <= 64bit
 * 'bt_uint128_t *' for hashes <= 128bit and
 * 'bt_uint192_t *' for hashes <=192bit.
 */
extern unsigned int bt_create_perfect_hash_table(int htype, // Hash type, currently supported upto 192 bit hashes.
			       void *loaded_hashes_ptr, // Pass a pointer to an array containing hashes of type bt_uint128_t or bt_uint192_t.
			       unsigned int num_ld_hashes, // Pass number of hashes in stored in the array.
			       OFFSET_TABLE_WORD **offset_table_ptr, // Returns a pointer to the Offset Table.
			       unsigned int *offset_table_sz_ptr, // Returns the size of Offset Table.
			       unsigned int *hash_table_sz_ptr, // Returns the size of Hash Table.
			       unsigned int verb); // Set verbosity, 0, 1, 2, 3 or greater.

#endif
