/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#ifndef _COMMON_RAWSHA384_H
#define _COMMON_RAWSHA384_H

/* ------ Contains (at least) prepare(), valid() and split() ------ */

#define DIGEST_SIZE                     48
#define BINARY_ALIGN                    sizeof(uint64_t)

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH            7

#define FORMAT_TAG          "$SHA384$"

#define TAG_LENGTH            (sizeof(FORMAT_TAG) - 1)

#define CIPHERTEXT_LENGTH             96

int sha384_common_valid(char *ciphertext, struct fmt_main *self);

void * sha384_common_binary(char *ciphertext);
void * sha384_common_binary_BE(char *ciphertext);
void * sha384_common_binary_rev(char *ciphertext);

char * sha384_common_split(char *ciphertext, int index, struct fmt_main *self);

extern struct fmt_tests sha384_common_tests_rawsha384[];

#endif
