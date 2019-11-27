/*
 * This software is Copyright (c) 2019 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_pkcs12.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

#define salt_len 8
#define key_len 8

// input
typedef struct {
	uint32_t length;
	uint32_t v[PLAINTEXT_LENGTH / 4];
} zed_password;

// output
typedef struct {
	uint32_t v[key_len / 4];
} zed_hash;

// input
typedef struct {
	uint32_t algo;
	uint32_t iterations;
	uint32_t salt[salt_len / 4];
} zed_salt;

inline void zed_crypt(__global const uint *password, uint32_t password_length,
                      __constant zed_salt *salt, __global uint *out)
{
	uint i;
	uint32_t csalt[salt_len / 4];
	uint32_t cpassword[PLAINTEXT_LENGTH / 4];
	uint32_t ckey[key_len / 4];

	for (i = 0; i < (password_length + 3) / 4; i++)
		cpassword[i] = password[i];

	for (i = 0; i < (salt_len / 4); i++)
		csalt[i] = salt->salt[i];

	if (salt->algo == 21)
		pkcs12_pbe_derive_key(salt->iterations, 3, cpassword,
		                      password_length, csalt, salt_len, ckey, key_len);
	else
		pkcs12_pbe_derive_key_sha256(salt->iterations, 3, cpassword,
		                             password_length, csalt, salt_len,
		                             ckey, key_len);

	for (i = 0; i < (key_len / 4); i++)
		out[i] = ckey[i];
}

__kernel void zed(__global const zed_password *inbuffer,
		__global zed_hash *outbuffer,
		__constant zed_salt *salt)
{
	uint idx = get_global_id(0);

	zed_crypt(inbuffer[idx].v, inbuffer[idx].length, salt, outbuffer[idx].v);
}
