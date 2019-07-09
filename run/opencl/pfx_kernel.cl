/*
 * This software is Copyright (c) 2017 Dhiru Kholia <kholia at kth dot se>,
 * Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_pkcs12.h"
#define HMAC_MSG_TYPE __constant
#define HMAC_OUT_TYPE __global
#include "opencl_hmac_sha1.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif
#ifndef MAX_DATA_LENGTH
#error MAX_DATA_LENGTH must be defined
#endif

// input
typedef struct {
	uint32_t length;
	uint32_t v[PLAINTEXT_LENGTH / 4];
} pfx_password;

// output
typedef struct {
	uint32_t v[20 / 4];
} pfx_hash;

// input
typedef struct {
	uint32_t iterations;
	uint32_t keylen;
	uint32_t saltlen;
	uint32_t salt[20 / 4];
	uint32_t datalen;
	uint32_t data[MAX_DATA_LENGTH / 4];
} pfx_salt;

inline void pfx_crypt(__global const uint *password, uint32_t password_length,
                      __constant pfx_salt *salt, __global uint *out)
{
	uint i;
	uint32_t csalt[20 / 4];
	uint32_t cpassword[PLAINTEXT_LENGTH / 4];
	uint32_t ckey[32 / 4];

	for (i = 0; i < (password_length + 3) / 4; i++)
		cpassword[i] = password[i];

	for (i = 0; i < (salt->saltlen + 3) / 4; i++)
		csalt[i] = salt->salt[i];

	pkcs12_pbe_derive_key(salt->iterations, 3, cpassword, password_length,
	                      csalt, salt->saltlen, ckey, salt->keylen);

	hmac_sha1(ckey, salt->keylen, salt->data, salt->datalen, out, 20);
}

__kernel void pfx(__global const pfx_password *inbuffer,
		__global pfx_hash *outbuffer,
		__constant pfx_salt *salt)
{
	uint idx = get_global_id(0);

	pfx_crypt(inbuffer[idx].v, inbuffer[idx].length, salt, outbuffer[idx].v);
}
