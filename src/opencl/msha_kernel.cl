/*
 * This code is copyright (c) 2013 magnum
 * and hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_macro.h"

__kernel void mysqlsha1_crypt_kernel(__global const uchar *key,
                                     __global const uint *index,
                                     __global uint *digest)
{
	uint gid = get_global_id(0);
	uint gws = get_global_size(0);
	uint W[16] = { 0 };
	uint output[5];
	uint A, B, C, D, E, temp;
	uint i;
	uint base = index[gid];
	uint len = index[gid + 1] - base;

	key += base;

	/* Work-around for self-tests not always calling set_key() like IRL */
	len = (len > PLAINTEXT_LENGTH) ? 0 : len;

	for (i = 0; i < len; i++)
		PUTCHAR_BE(W, i, key[i]);
	PUTCHAR_BE(W, i, 0x80);
	W[15] = i << 3;
	sha1_single(W, output);

	W[0] = output[0];
	W[1] = output[1];
	W[2] = output[2];
	W[3] = output[3];
	W[4] = output[4];
	W[5] = 0x80000000;
#if USE_SHA1SHORT
	W[15] = 20 << 3;
	sha1_single_short(W, output);
#else
	for (i = 6; i < 16; i++)
		W[i] = 0;
	W[15] = 20 << 3;
	sha1_single(W, output);
#endif
	for (i = 0; i < 5; i++)
		digest[i * gws + gid] = output[i];
}
