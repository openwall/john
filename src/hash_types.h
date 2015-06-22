/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include "interface.h"

extern uint128_t *loaded_hashes_128;
extern uint192_t *loaded_hashes_192;

extern unsigned int hash_table_size;
extern unsigned int shift64_ht_sz, shift128_ht_sz;
extern unsigned long long total_memory_in_bytes;

extern unsigned int modulo128_31b(uint128_t, unsigned int, uint64_t);
extern void allocate_ht_128(unsigned int, unsigned int);
extern unsigned int calc_ht_idx_128(unsigned int, unsigned int);
extern unsigned int zero_check_ht_128(unsigned int);
extern void assign_ht_128(unsigned int, unsigned int);
extern void assign0_ht_128(unsigned int);
extern unsigned int get_offset_128(unsigned int, unsigned int);
extern int test_tables_128(unsigned int, OFFSET_TABLE_WORD *, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int remove_duplicates_128(unsigned int, unsigned int, unsigned int);

extern unsigned int modulo192_31b(uint192_t, unsigned int, uint64_t, uint64_t);
extern void allocate_ht_192(unsigned int, unsigned int);
extern unsigned int calc_ht_idx_192(unsigned int, unsigned int);
extern unsigned int zero_check_ht_192(unsigned int);
extern void assign_ht_192(unsigned int, unsigned int);
extern void assign0_ht_192(unsigned int);
extern unsigned int get_offset_192(unsigned int, unsigned int);
extern int test_tables_192(unsigned int, OFFSET_TABLE_WORD *, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int remove_duplicates_192(unsigned int, unsigned int, unsigned int);