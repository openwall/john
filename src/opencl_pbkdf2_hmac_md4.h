/*
 * This software is Copyright (c) 2015 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#ifndef _OPENCL_PBKDF2_HMAC_MD4_H
#define _OPENCL_PBKDF2_HMAC_MD4_H

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
	unsigned int dk[((OUTLEN + 15) / 16) * 16 / sizeof(unsigned int)];
} pbkdf2_out;

typedef struct {
	unsigned int  length;
	unsigned int  outlen;
	unsigned int  iterations;
	unsigned char salt[52];
} pbkdf2_salt;

#ifndef _OPENCL_COMPILER
#define MAYBE_VECTOR_UINT unsigned int
#endif

typedef struct {
	MAYBE_VECTOR_UINT W[4];
	MAYBE_VECTOR_UINT ipad[4];
	MAYBE_VECTOR_UINT opad[4];
	MAYBE_VECTOR_UINT out[4];
	unsigned int iter_cnt;
	unsigned int pass;
} pbkdf2_state;

#endif
