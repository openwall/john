/*
 * Copyright (c) 2025, magnum
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef ITERATED_SHA1_COMMON_H__
#define ITERATED_SHA1_COMMON_H__

#include "formats.h"

#define FORMAT_NAME         "salted"

#define FORMAT_TAG          "$sisha1$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG) - 1)

#define BINARY_SIZE         20
#define BINARY_ALIGN        4
#define SALT_SIZE           sizeof(salt_t)
#define SALT_ALIGN          4

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x507

#define MAX_SALT_SIZE       16 // 16 bytes, 32 hex chars
#define PLAINTEXT_LENGTH    (55 - MAX_SALT_SIZE)
#define MIN_CIPHERTEXT_LEN  (160 / 4)
#define MAX_CIPHERTEXT_LEN  (160 / 4 + 2 * MAX_SALT_SIZE)

#define MAX_ITER            (1 << 20)

typedef struct {
	uint32_t iter;
	uint32_t len;
	uint32_t salt[MAX_SALT_SIZE / sizeof(uint32_t)];
} salt_t;

extern struct fmt_tests iterated_sha1_tests[];

extern char *iterated_sha1_prepare(char *fields[10], struct fmt_main *self);
extern int iterated_sha1_valid(char *ciphertext, struct fmt_main *self);
extern void* iterated_sha1_get_binary(char* ciphertext);
extern void* iterated_sha1_get_salt(char* ciphertext);
extern int iterated_sha1_salt_hash(void *salt);
extern unsigned int iterated_sha1_iterations(void *salt);

#endif // ITERATED_SHA1_COMMON_H__
