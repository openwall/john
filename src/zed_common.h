/*
 * This software is Copyright (c) 2019 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>

#include "formats.h"
#include "arch.h"
#include "memory.h"
#include "common.h"
#include "loader.h"

#define salt_len 8
#define key_len 8

#define FORMAT_TAG              "$zed$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)
#define BINARY_SIZE             key_len
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)

struct custom_salt {
	int algo;
	int iteration_count;
	unsigned char salt[salt_len];
};

extern struct fmt_tests zed_tests[];

extern int zed_valid(char *ciphertext, struct fmt_main *self);
extern void *zed_common_get_salt(char *ciphertext);
extern void *zed_common_get_binary(char *ciphertext);
extern unsigned int zed_get_mac_type(void *salt);
extern unsigned int zed_iteration_count(void *salt);
extern int zed_salt_hash(void *salt);
