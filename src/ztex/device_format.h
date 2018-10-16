/*
 * device_format
 *
 * Functions to access remote devices such as ZTEX FPGA board
 * for usage in JtR "formats"
 *
 * This software is Copyright (c) 2016-2018 Denis Burykin
 * [denis_burykin yahoo com], [denis-burykin2014 yandex ru]
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 */

#include "../list.h"

// (re-)initializes hardware.
// Saves pointers to 'struct fmt_params', 'struct device_bitstream'.
void device_format_init(struct fmt_main *fmt_main,
		struct device_bitstream *bitstream, struct list_main *devices_allow,
		int verbosity);

void device_format_done();

void device_format_reset();

void device_format_set_salt(void *salt);

// Copies given key into keys_buffer.
// In case mask is used, copies given template key and mask information.
void device_format_set_key(char *key, int index);

// Performs computation of keys_buffer using given salt
int device_format_crypt_all(int *pcount, struct db_salt *salt);

int device_format_get_hash_0(int index);
int device_format_get_hash_1(int index);
int device_format_get_hash_2(int index);
int device_format_get_hash_3(int index);
int device_format_get_hash_4(int index);
int device_format_get_hash_5(int index);
int device_format_get_hash_6(int index);

int device_format_cmp_all(void *binary, int count);

int device_format_cmp_one(void *binary, int index);

int device_format_cmp_exact(char *source, int index);

// used with FMT_DEVICE_CMP
// Takes index in the range from 0 to crypt_all() return value minus 1.
// Returns 'struct db_password *' that has triggered comparison equality.
struct db_password *device_format_get_password(int index);

// 1. Takes index in the range from 0 to crypt_all() return value minus 1.
// Returns the key (plaintext) that has triggered comparison equality.
// 2. Takes index in the range from 0 to 'pcount-1' value.
// Used for status reporting.
char *device_format_get_key(int index);
