/*
 * Truecrypt implementation. Copyright (c) 2015-2025, magnum
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 */

#include "opencl_misc.h"
#define AES_SRC_TYPE __constant
#define AES_DST_TYPE __global
#include "opencl_aes_xts.h"
#include "pbkdf2_ripemd160.h"

typedef struct {
	uint v[16 / 4];
} tc_hash;

typedef struct {
	uint salt[SALTLEN / 4];
	uint bin[(512 - 64) / 4];
} tc_salt;

__kernel void tc_ripemd_aesxts(__global const pbkdf2_password *inbuffer,
                               __global tc_hash *outbuffer,
                               __constant tc_salt *salt)
{
	__local aes_local_t lt1;
	__local aes_local_t lt2;
	uint idx = get_global_id(0);
	union {
		uint u32[64 / 4];
		uchar uc[64];
	} key;

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length, salt->salt, key.u32);

	AES_256_XTS_first_sector(salt->bin, outbuffer[idx].v, key.uc, &lt1, &lt2);
}
