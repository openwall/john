/*
 * OpenCL kernel for cracking Bitcoin wallet.dat hashes.
 *
 * This software is
 * Copyright (c) 2021 Solar Designer
 * Copyright (c) 2018 Dhiru Kholia
 * Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * This file is loosely based on parts of the sspr_kernel.cl file.
 */

#include "opencl_sha2_ctx.h"

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

typedef union hash512_u {
	uchar b[SHA512_DIGEST_LENGTH];
	uint w[SHA512_DIGEST_LENGTH / sizeof(uint)];
	uint64_t W[SHA512_DIGEST_LENGTH / sizeof(uint64_t)];
} hash512_t;

__kernel void loop_sha512(__global hash512_t *inoutbuffer, uint count)
{
	uint gid = get_global_id(0);
	hash512_t buf;
	uint i;

	for (i = 0; i < 8; i++)
		buf.W[i] = inoutbuffer[gid].W[i];

	for (i = 0; i < count; i++) {
		uint j;
		ulong W[16];

		for (j = 0; j < 8; j++)
			W[j] = buf.W[j];
		W[8] = 0x8000000000000000;
		W[15] = 64 << 3;
		sha512_single_zeros(W, buf.W);
	}

	for (i = 0; i < 8; i++)
		inoutbuffer[gid].W[i] = buf.W[i];
}
