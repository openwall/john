/*
 * This software is Copyright (c) 2018 Ivan Freed and it is hereby released
 * to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define AES_SRC_TYPE MAYBE_CONSTANT

#include "pbkdf2_hmac_sha512_kernel.cl"
#include "opencl_aes.h"

typedef struct {
	salt_t pbkdf2;
	uint8_t	header[96];
} diskcryptor_salt_t;

typedef struct {
	uint cracked;
} out_t;

__kernel void diskcryptor_final(__global crack_t *pbkdf2,
                         __constant diskcryptor_salt_t *salt,
                         __global out_t *out)
{
	uint gid = get_global_id(0);

	uchar output[96];

	union {
		ulong u[8];
		uchar c[64];
	} key;
	int i;

	union {
		short value;
		uchar c[2];
	} version;

	union {
		int value;
		uchar c[4];
	} algorithm;

	// Final swap and copy the PBKDF2 result
	for (i = 0; i < 8; i++)
		key.u[i] = SWAP64(pbkdf2[gid].hash[i]);

	AES_256_XTS_DiskCryptor(salt->header, output, key.c, 96);
	memcpy_pp(version.c, output + 72, 2);
	memcpy_pp(algorithm.c, output + 82, 4);
	if ((!memcmp_pc(output + 64, "DCRP", 4)) && (version.value == 2 || version.value == 1) && (algorithm.value >= 0 && algorithm.value <= 7)) {
		out[gid].cracked = 1;
		return;
	}

	out[gid].cracked = 0;
}
