/*
 * This software is Copyright (c) 2018 Dhiru Kholia <kholia at kth dot se>,
 * Copyright (c) 2017 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_pkcs12.h"
#include "opencl_des.h"

#ifndef PLAINTEXT_LENGTH
#error PLAINTEXT_LENGTH must be defined
#endif

// input
typedef struct {
	uint32_t length;
	uint32_t v[PLAINTEXT_LENGTH / 4];
} sappse_password;

// input
typedef struct {
	uint32_t iterations;
	uint32_t salt_size;
	uint32_t encrypted_pin_size;
	uint32_t salt[32 / 4];
	uchar encrypted_pin[32];
} sappse_salt;

// output
typedef struct {
	uint cracked;
} sappse_out;

inline int sappse_crypt(__global const uint *password, uint32_t password_length,
                      __constant sappse_salt *salt, __global sappse_out *out)
{
	uint i;
	uint32_t csalt[20 / 4];

	union {
		uint32_t chunks[PLAINTEXT_LENGTH / 4];
		uchar bytes[PLAINTEXT_LENGTH];
	} pass;

	union {
		uint32_t chunks[32 / 4];
		uchar bytes[24];
	} key;

	union {
		uint32_t chunks[16 / 4];
		uchar bytes[8];
	} iv;

	for (i = 0; i < (password_length + 3) / 4; i++)
		pass.chunks[i] = password[i];

	for (i = 0; i < (salt->salt_size + 3) / 4; i++)
		csalt[i] = salt->salt[i];

	// derive key
	pkcs12_pbe_derive_key(salt->iterations, 1, pass.chunks, password_length,
	                      csalt, salt->salt_size, key.chunks, 24);

	// derive iv
	for (i = 0; i < (salt->salt_size + 3) / 4; i++)
		csalt[i] = salt->salt[i];

	pkcs12_pbe_derive_key(salt->iterations, 2, pass.chunks, password_length,
	                      csalt, salt->salt_size, iv.chunks, 8);

	// prepare des input
	uint padbyte = 8 - (password_length % 8);
	if (padbyte < 8 && padbyte > 0) {
		for (i = 0; i < padbyte; i++) {
			pass.bytes[password_length + i] = padbyte;
		}
	}

	// encrypt
	uchar temp1[16];
	des3_context ks;
	des3_set3key_enc(&ks, key.bytes);
	des3_crypt_cbc(&ks, DES_ENCRYPT, 8, iv.bytes, const, pass.bytes, temp1);

	for (i = 0; i < 8; i++) {
		if (temp1[i] != salt->encrypted_pin[i]) {
			return 0;
		}
	}

	return 1;
}

__kernel void sappse(__global const sappse_password *inbuffer,
		__global sappse_out *out,
		__constant sappse_salt *salt)
{
	uint idx = get_global_id(0);

	out[idx].cracked = sappse_crypt(inbuffer[idx].v, inbuffer[idx].length, salt, out);
}
