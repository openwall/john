/*
   This code was largely inspired by
   pyrit opencl kernel sha1 routines, royger's sha1 sample,
   and md5_opencl_kernel.cl inside jtr.
   Copyright 2011 by Samuele Giovanni Tonon
   samu at linuxasylum dot net
   and Copyright (c) 2012-2017, magnum
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
#define AES_SRC_TYPE __constant
#include "opencl_aes.h"

typedef struct {
	uint salt[3]; // ((SALT_LENGTH + 3)/4)
	uchar ct[48]; // CIPHERTEXT_LENGTH
} salt_t;

__kernel void
o5logon_kernel(__global const uint *keys, __constant salt_t *salt,
               __global const uint *index, __global uint *result)
{
	uint W[16] = { 0 }, salt_s[3], output[5];
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint len = base & 63;
	uint i;
	uint shift = len % 4;
	uint sr = 8 * shift;
	uint sl = 32 - sr;
	uint sra = (0xffffffff - (1 << sr)) + 1;
	uint sla = 0xffffffff - sra;
	union {
		uchar c[24];
		uint w[24 / 4];
	} aes_key;
	union {
		uchar c[16];
		ulong l[16 / 8];
	} pt;
	uchar iv[16];
	AES_KEY akey;

	keys += base >> 6;

	for (i = 0; i < (len + 3) / 4; i++)
		W[i] = SWAP32(*keys++);

	// Do the typical byte swapping...
	for (i = 0; i < 3; i++)
		salt_s[i] = SWAP32(salt->salt[i]);

	// Shift the salt bytes into place after the given key.
	W[len / 4] |= (salt_s[0] & sra) >> sr;
	W[len / 4 + 1] = ((salt_s[0] & sla) << sl) | ((salt_s[1] & sra) >> sr);
	W[len / 4 + 2] = ((salt_s[1] & sla) << sl) | ((salt_s[2] & sra) >> sr);
	W[len / 4 + 3] = (salt_s[2] & sla) << sl;

	// The 0x80 ending character was added to the salt before we receive it

	W[15] = (len + 10) << 3;

	sha1_single(uint, W, output);

	for (i = 0; i < 5; i++)
		aes_key.w[i] = SWAP32(output[i]);
	aes_key.w[5] = 0;

	for (i = 0; i < 16; i++)
		iv[i] = salt->ct[16 + i];

	AES_set_decrypt_key(aes_key.c, 192, &akey);
	AES_cbc_decrypt(&salt->ct[32], pt.c, 16, &akey, iv);

	result[gid] = (pt.l[1] == 0x0808080808080808UL);
}
