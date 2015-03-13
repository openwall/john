/*
   This code was largely inspired by
   pyrit opencl kernel sha1 routines, royger's sha1 sample,
   and md5_opencl_kernel.cl inside jtr.
   Copyright 2011 by Samuele Giovanni Tonon
   samu at linuxasylum dot net
   and Copyright (c) 2012, magnum
   This program comes with ABSOLUTELY NO WARRANTY; express or
   implied .
   This is free software, and you are welcome to redistribute it
   under certain conditions; as expressed here
   http://www.gnu.org/licenses/gpl-2.0.html
*/

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1_macro.h"

__kernel void sha1_crypt_kernel(__global uint* keys, __global const uint *index, __global uint* digest)
{
	uint W[16] = { 0 }, output[5];
	uint temp, A, B, C, D, E;
	uint gid = get_global_id(0);
	uint num_keys = get_global_size(0);
	uint base = index[gid];
	uint len = base & 63;
	uint i;

	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = SWAP32(*keys++);

	PUTCHAR_BE(W, len, 0x80);
	W[15] = len << 3;

	sha1_init(output);
	sha1_block(W, output);

	digest[gid + 0 * num_keys] = SWAP32(output[0]);
	digest[gid + 1 * num_keys] = SWAP32(output[1]);
	digest[gid + 2 * num_keys] = SWAP32(output[2]);
	digest[gid + 3 * num_keys] = SWAP32(output[3]);
	digest[gid + 4 * num_keys] = SWAP32(output[4]);
}
