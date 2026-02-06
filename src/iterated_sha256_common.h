/*
 * Copyright (c) 2026, Dhiru Kholia
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef ITERATED_SHA256_COMMON_H__
#define ITERATED_SHA256_COMMON_H__

#include "formats.h"

#define FORMAT_NAME             "salted"

#define FORMAT_TAG              "$sisha256$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG) - 1)

#define BINARY_SIZE             32
#define BINARY_ALIGN            4
#define SALT_ALIGN              4

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7

#define CIPHERTEXT_LENGTH       128
#define SALT_BYTES              32
#define MAX_SALT_BYTES          64
#define MAX_SALT_SIZE           MAX_SALT_BYTES

#ifndef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH        MAX_PLAINTEXT_LENGTH
#endif

#define ISE_ITERATIONS          128
#define ISE_TOTAL_ROUNDS        (ISE_ITERATIONS + 1)
#define MAX_ITERATIONS          (1 << 20)

typedef struct {
	uint32_t iter;
	uint32_t len;
	uint32_t salt[MAX_SALT_BYTES / sizeof(uint32_t)];
} salt_t;

#define SALT_SIZE               sizeof(salt_t)

extern struct fmt_tests iterated_sha256_tests[];

extern int iterated_sha256_valid(char *ciphertext, struct fmt_main *self);
extern void *iterated_sha256_get_binary(char *ciphertext);
extern void *iterated_sha256_get_salt(char *ciphertext);
extern int iterated_sha256_salt_hash(void *salt);
extern unsigned int iterated_sha256_iterations(void *salt);

#endif /* ITERATED_SHA256_COMMON_H__ */
