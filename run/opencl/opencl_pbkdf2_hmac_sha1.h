/*
 * This software is Copyright (c) 2012-2013 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * increased salt_len from 52 (which was a bug), to 115.  salts [52-115] bytes
 * require 2 sha1 limbs to handle.  Salts [0-51] bytes in length are handled by
 * 1 sha1 limb.  (Feb. 28/16, JimF)
 *
 * increased salt_len from 115 bytes to 179 bytes (kernel can do any length now).
 */
#ifndef _OPENCL_PBKDF2_HMAC_SHA1_H
#define _OPENCL_PBKDF2_HMAC_SHA1_H

/*
 * The SHA-1 block size used for HMAC dictates (for optimized code) a max.
 * plaintext length of 64 and a max. salt length of 179.
 *
 * These structs do NOT have space for any cstring trailing NULL
 */

#ifndef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH	64
#endif

#ifndef MAX_OUTLEN
#define MAX_OUTLEN OUTLEN
#endif

#ifndef pbkdf2_out
typedef struct {
	unsigned int dk[((MAX_OUTLEN + 19) / 20) * 20 / sizeof(unsigned int)];
} pbkdf2_out;
#endif

//#if !defined (OPENCL_PBKDF2_HMAC_SHA1_2_LIMB) && !defined (OPENCL_PBKDF2_HMAC_SHA1_3_LIMB)
//typedef struct {
//	unsigned int  length;
//	unsigned int  outlen;
//	unsigned int  iterations;
//	unsigned char salt[55];
//} pbkdf2_salt;
//#elif defined (OPENCL_PBKDF2_HMAC_SHA1_2_LIMB)
//typedef struct {
//	unsigned int  length;
//	unsigned int  outlen;
//	unsigned int  iterations;
//	unsigned char salt[115];
//} pbkdf2_salt;
//#elif defined (OPENCL_PBKDF2_HMAC_SHA1_3_LIMB)
typedef struct {
	unsigned int  length;
	unsigned int  outlen;
	unsigned int  iterations;
	unsigned char salt[179]; //[243]; is for 4 limb, if we later need it.
} pbkdf2_salt;
//#endif

#ifndef _OPENCL_COMPILER
#define MAYBE_VECTOR_UINT unsigned int
#endif

typedef struct {
	MAYBE_VECTOR_UINT W[5];
	MAYBE_VECTOR_UINT ipad[5];
	MAYBE_VECTOR_UINT opad[5];
	MAYBE_VECTOR_UINT out[5];
#ifndef ITERATIONS
	unsigned int iter_cnt;
#endif
#if !OUTLEN || OUTLEN > 20
	unsigned int pass;
#endif
} pbkdf2_state;

#endif
