/*
 * This software is Copyright (c) 2018 Dhiru Kholia, Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pbkdf2_hmac_sha512_kernel.cl"
#include "opencl_hmac_sha256.h"

// Sync. with cloudkeychain_common.h
#define CTLEN                   2048

typedef struct {
	salt_t pbkdf2;
	uint32_t hmacdatalen;
	uint8_t hmacdata[CTLEN];
	uint8_t expectedhmac[16];
} cloudkeychain_salt_t;

typedef struct {
	uint cracked;
} out_t;

__kernel void cloudkeychain_final(__global crack_t *pbkdf2,
                                  __constant cloudkeychain_salt_t *salt,
                                  __global out_t *out)
{
	uint gid = get_global_id(0);

	uchar chmac[32];
	union {
		ulong u[8];
		uchar c[64];
	} key;
	int i;

	uchar hmacdata[CTLEN];
	uchar expectedhmac[16];
	memcpy_macro(hmacdata, salt->hmacdata, salt->hmacdatalen);
	memcpy_macro(expectedhmac, salt->expectedhmac, 16);

	// Final swap and copy the PBKDF2 result
	for (i = 0; i < 8; i++)
		key.u[i] = SWAP64(pbkdf2[gid].hash[i]);

	hmac_sha256(key.c + 32, 32, hmacdata, salt->hmacdatalen, chmac, 16);

	if (!memcmp_pp(expectedhmac, chmac, 16)) {
		out[gid].cracked = 1;
		return;
	}

	out[gid].cracked = 0;
}
