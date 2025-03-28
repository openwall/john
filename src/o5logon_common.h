/*
 * This software is Copyright (c) 2025 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#ifndef O5LOGON_COMMON
#define O5LOGON_COMMON

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"

#define FORMAT_NAME         "Oracle O5LOGON protocol"
#define FORMAT_TAG          "$o5logon$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    7
#define PLAINTEXT_LENGTH    32	/* Can't be bumped for OpenCL */
#define CIPHERTEXT_LENGTH   48
#define SALT_LENGTH         10
#define BINARY_SIZE         0
#define BINARY_ALIGN        1
#define SALT_SIZE           sizeof(o5logon_salt)
#define SALT_ALIGN          sizeof(int32_t)

typedef struct {
	unsigned int pw_len;               /* AUTH_PASSWORD length (blocks) */
	unsigned char salt[(SALT_LENGTH + 1 + 3) / 4 * 4]; /* AUTH_VFR_DATA */
	unsigned char ct[CIPHERTEXT_LENGTH];       /* Server's AUTH_SESSKEY */
	unsigned char csk[CIPHERTEXT_LENGTH];      /* Client's AUTH_SESSKEY */
	unsigned char pw[PLAINTEXT_LENGTH + 16];  /* Client's AUTH_PASSWORD */
} o5logon_salt;

extern struct fmt_tests o5logon_tests[];

extern int o5logon_valid(char *ciphertext, struct fmt_main *self);
extern void *o5logon_get_salt(char *ciphertext);

#endif
