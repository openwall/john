/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#ifdef HAVE_OPENCL

#include "bt_interface.h"

#include "memory.h" // Jtr mem_alloc(), mem_calloc(), MEM_FREE() and mem_alloc_align().
#include "misc.h" // error()

#define bt_error(a) bt_error_fn(a, __FILE__, __LINE__)
#define bt_warn(a) bt_warn_fn(a, __FILE__, __LINE__)

extern uint64_t *bt_loaded_hashes_64;
extern bt_uint128_t *bt_loaded_hashes_128;
extern bt_uint192_t *bt_loaded_hashes_192;

extern unsigned int bt_hash_table_size;
extern unsigned int shift64_ht_sz, shift128_ht_sz;
extern unsigned long long bt_total_memory_in_bytes;

extern int bt_malloc(void **ptr, size_t size);
extern int bt_calloc(void **ptr, size_t num, size_t size);
extern int bt_memalign_alloc(void **ptr, size_t alignment, size_t size);
extern void bt_free(void **ptr);
extern void bt_error_fn(const char *str, char *file, int line);
extern void bt_warn_fn(const char *str, char *file, int line);

extern unsigned int modulo64_31b(uint64_t, unsigned int);
extern void allocate_ht_64(unsigned int, unsigned int);
extern unsigned int calc_ht_idx_64(unsigned int, unsigned int);
extern unsigned int zero_check_ht_64(unsigned int);
extern void assign_ht_64(unsigned int, unsigned int);
extern void assign0_ht_64(unsigned int);
extern unsigned int get_offset_64(unsigned int, unsigned int);
extern int test_tables_64(unsigned int, OFFSET_TABLE_WORD *, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int remove_duplicates_64(unsigned int, unsigned int, unsigned int);

extern unsigned int modulo128_31b(bt_uint128_t, unsigned int, uint64_t);
extern void allocate_ht_128(unsigned int, unsigned int);
extern unsigned int calc_ht_idx_128(unsigned int, unsigned int);
extern unsigned int zero_check_ht_128(unsigned int);
extern void assign_ht_128(unsigned int, unsigned int);
extern void assign0_ht_128(unsigned int);
extern unsigned int get_offset_128(unsigned int, unsigned int);
extern int test_tables_128(unsigned int, OFFSET_TABLE_WORD *, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int remove_duplicates_128(unsigned int, unsigned int, unsigned int);

extern unsigned int modulo192_31b(bt_uint192_t, unsigned int, uint64_t, uint64_t);
extern void allocate_ht_192(unsigned int, unsigned int);
extern unsigned int calc_ht_idx_192(unsigned int, unsigned int);
extern unsigned int zero_check_ht_192(unsigned int);
extern void assign_ht_192(unsigned int, unsigned int);
extern void assign0_ht_192(unsigned int);
extern unsigned int get_offset_192(unsigned int, unsigned int);
extern int test_tables_192(unsigned int, OFFSET_TABLE_WORD *, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int remove_duplicates_192(unsigned int, unsigned int, unsigned int);

#endif
