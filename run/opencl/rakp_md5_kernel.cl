/*
 * OpenCL kernel for IPMI 2.0 RAKP (RMCP+) HMAC-MD5 (RAKP auth algorithm 2).
 *
 * Copyright (c) 2026 HD Moore, released to the general public under the
 * following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * One work-item per candidate. Keys are packed (key_array + index[gid]); the
 * RAKP salt (raw bytes + length) is the HMAC message. Uses the shared
 * opencl_hmac_md5 helper so the HMAC construction stays correct and simple.
 */

#include "opencl_misc.h"
#define HMAC_KEY_TYPE __global const
#include "opencl_hmac_md5.h"

__kernel void rakp_md5_kernel(__global const uchar *salt,
                              const uint salt_len,
                              __global const uint *key_array,
                              __global const uint *index,
                              __global uint *digest)
{
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint key_len = base & 63;
	__global const uchar *key = (__global const uchar *)(key_array + (base >> 6));
	uchar saltbuf[128];
	uint out[4];
	uint i;

	for (i = 0; i < salt_len; i++)
		saltbuf[i] = salt[i];

	hmac_md5(key, key_len, saltbuf, salt_len, out, 16);

	for (i = 0; i < 4; i++)
		digest[gid * 4 + i] = out[i];
}
