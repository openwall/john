/*
 * Common code for cracking Cardano 128-byte length legacy secret Keys (a.k.a XPrv).
 *
 * This software is Copyright (c) 2022, Pal Dorogi <pal dot dorogi at gmail.com>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 *
 * This file is common for its future use, and currently there isn't an OpenCL format
 * implementing this feature.
 *
 */
#include "formats.h"

#define FORMAT_TAG      "$cardano$"
#define FORMAT_TAG_LEN  (sizeof(FORMAT_TAG) - 1)
#define SK_LEN          64
#define PK_LEN          32
#define CC_LEN          32
#define ESK_LEN         (SK_LEN + PK_LEN + CC_LEN)


// Chacha20 parameters
#define KEY_SIZE    32
#define IV_SIZE     8
#define BUF_SIZE    (KEY_SIZE + IV_SIZE)

// Blake2B parameters
#define PWD_HASH_LEN    32

struct custom_salt {
	// The 128-byte length legacy encryted key.
	unsigned char esk[ESK_LEN];
};

extern struct fmt_tests cardano_tests[];
int cardano_valid(char *ciphertext, struct fmt_main *self);
void *cardano_get_salt(char *ciphertext);
