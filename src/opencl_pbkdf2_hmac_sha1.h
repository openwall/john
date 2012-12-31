/*
 * This software is Copyright (c) 2012 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifndef _OPENCL_PBKDF2_HMAC_SHA1_H
#define _OPENCL_PBKDF2_HMAC_SHA1_H

/*
 * The SHA-1 block size used for HMAC dictates (for optimised code) a max.
 * plaintext length of 64 and a max. salt length of 52.
 *
 * These structs do NOT have space for any cstring trailing NULL
 */

#ifndef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH	64
#endif

typedef struct {
	unsigned int  length;
	unsigned char v[PLAINTEXT_LENGTH + 1];
} pbkdf2_password;

typedef struct {
	unsigned int dk[32 / sizeof(unsigned int)];
} pbkdf2_out;

typedef struct {
	unsigned int  length;
	unsigned char salt[52];
} pbkdf2_salt;

typedef struct {
	unsigned int W[5];
	unsigned int ipad[5];
	unsigned int opad[5];
	unsigned int out[5];
} pbkdf2_state;

#endif
