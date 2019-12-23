/*
 * This software is
 * Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2019, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>

#include "formats.h"
#include "arch.h"
#include "memory.h"
#include "common.h"
#include "loader.h"

#define FORMAT_TAG              "$pfxng$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)
#define BINARY_SIZE             20

#define MAX_DATA_LENGTH         8192 // XXX ensure this is large enough

struct custom_salt {
	int mac_algo;
	int key_length;
	int iteration_count;
	int saltlen;
	unsigned char salt[20];
	int data_length;
	unsigned char data[MAX_DATA_LENGTH];
};

extern int pfx_valid(char *ciphertext, struct fmt_main *self);
extern void *pfx_common_get_salt(char *ciphertext);
extern void *pfx_common_get_binary(char *ciphertext);
extern unsigned int pfx_get_mac_type(void *salt);
extern unsigned int pfx_iteration_count(void *salt);
