/*
 * This software is Copyright (c) 2012-2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * JimF.  Increased max salt len to 115 (max that can be handled by 2 limbs)
 */
#ifndef _OPENCL_PBKDF1_HMAC_SHA1_H
#define _OPENCL_PBKDF1_HMAC_SHA1_H

/*
 * The SHA-1 block size used for HMAC dictates (for optimised code) a max.
 * plaintext length of 64 and a max. salt length of 115.
 *
 * These structs do NOT have space for any cstring trailing NULL
 */

#ifndef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH	64
#endif

typedef struct {
	unsigned int dk[((OUTLEN + 19) / 20) * 20 / sizeof(unsigned int)];
} pbkdf1_out;

typedef struct {
	unsigned int  length;
	unsigned int  outlen;
	unsigned int  iterations;
	unsigned char salt[115];
} pbkdf1_salt;

#ifndef _OPENCL_COMPILER
#define MAYBE_VECTOR_UINT unsigned int
#endif

typedef struct {
	MAYBE_VECTOR_UINT W[5];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT out[5];
	unsigned int iter_cnt;
	unsigned int pass;
} pbkdf1_state;

#endif
