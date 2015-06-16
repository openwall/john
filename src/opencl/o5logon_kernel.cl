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

/*
 * Modifications (c) 2014 Harrison Neal.
 * Licensed GPLv2
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

__kernel void o5logon_kernel(__global uint* keys, __constant uint* salt, __global const uint *index, __global uint* digest)
{
	uint W[16] = { 0 }, salt_s[3], output[5];
	uint temp, A, B, C, D, E;
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = base & 63;
	uint i;
	uint shift = len % 4;
	uint sr = 8 * shift;
	uint sl = 32 - sr;
	uint sra = (0xffffffff - (1 << sr)) + 1;
	uint sla = 0xffffffff - sra;

	keys += base >> 6;

	for (i = 0; i < (len+3)/4; i++)
		W[i] = SWAP32(*keys++);

	// Do the typical byte swapping...
	salt_s[0] = SWAP32(*salt++);
	salt_s[1] = SWAP32(*salt++);
	salt_s[2] = SWAP32(*salt);

	// Shift the salt bytes into place after the given key.
	W[len/4] |= (salt_s[0] & sra) >> sr;
	W[len/4+1] = ((salt_s[0] & sla) << sl) | ((salt_s[1] & sra) >> sr);
	W[len/4+2] = ((salt_s[1] & sla) << sl) | ((salt_s[2] & sra) >> sr);
	W[len/4+3] = (salt_s[2] & sla) << sl;

	// The 0x80 ending character is added to the salt before we receive it

	W[15] = (len+10) << 3;

	sha1_single(W, output);

	// Because the receiving program will need the entire hash immediately
	// (as opposed to receiving part of it, and only receiving the rest if
	// the first part appears to be a match), arranging the output like so
	// prevents the receiving program from having to jump around to get the
	// entire hash (one memcpy as opposed to five).
	digest[gid * 5] = SWAP32(output[0]);
	digest[gid * 5 + 1] = SWAP32(output[1]);
	digest[gid * 5 + 2] = SWAP32(output[2]);
	digest[gid * 5 + 3] = SWAP32(output[3]);
	digest[gid * 5 + 4] = SWAP32(output[4]);
}
