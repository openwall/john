/*
 *  OpenCL kernel for SHA-1 hashing using long salts in JtR
 *  - specifically written for cracking of Java Keystore 'outer'
 *    passwords in conjunction with opencl_keystore_fmt_plug.c
 *    (format: 'keystore-opencl').
 *
 *  This software is Copyright (c) 2015 Terry West <terrybwest at gmail dot com>,
 *  and it is hereby released to the general public under the following terms:
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

typedef struct {
	uint  length;
	uchar pass[PASSLEN];
} keystore_password;

typedef struct {
	uint key[OUTLEN/4];
//	uint iv[OUTLEN/4];
} keystore_hash;

typedef struct {
	uint length;
	uchar salt[SALTLEN];
} keystore_salt;

__kernel void keystore(__global const keystore_password *inbuffer,
                       __global keystore_hash *outbuffer,
                       __global const keystore_salt *salt)
{
	uint A, B, C, D, E, temp;

	uint gid = get_global_id(0);
	uint W[16] = { 0 };
	uint o[5];
	uint block,	// block index
	     wbi,	// W index in each block
		 i;
	uint pwd_len = inbuffer[gid].length;
	uint salt_len = salt->length;
	// message length is password length + salt length
	uint msg_len = pwd_len + salt_len;
	// --> number of bits - as ulong for later convenience
	ulong msg_bits = msg_len << 3;//SWAP64((ulong)msg_len << 3);
	// But the bytes we actually need to accomodate in
	// each exactly 64-byte block must also include:
	// 	- sizeof(uchar) for salt-terminating bit 1, set as uchar 0x80
	// 	- sizeof(ulong) for final 64-bit message length
	uint ext_len = (uint)msg_len +  sizeof(uchar) + sizeof(ulong);
	uint nblockbytes = 64;

	uint nblocks = ext_len/nblockbytes;

	uint pbi = 0;	// password index
	uint sbi = 0;	// salt index

	// If overflow in nblocks, we need one more + padding
	if ((ext_len - nblocks*nblockbytes) > 0) { // ext_len % nblockbytes
		++nblocks;
	}

	sha1_init(o);

	for (block = 0; block < nblocks; ++block) {
		// for each block, wbi = 0 initially
		wbi = 0;
		// - if we're not done with the password,
		//   put it in W
		for ( ; pbi < pwd_len && wbi < nblockbytes; ++wbi, ++pbi) {
			PUTCHAR_BE(W, wbi, inbuffer[gid].pass[pbi]);
		}
		// if we're done with the password and this block's not yet full ...
		if (pbi == pwd_len && wbi < nblockbytes) {
			// if we're not done with the salt,
			// put it in W
			for ( ; sbi < salt_len && wbi < nblockbytes; ++wbi, ++sbi) {
				PUTCHAR_BE(W, wbi, salt->salt[sbi]);
			}
			// if we're (just) done with the salt and this block's not full ...
			if (sbi == salt_len && wbi < nblockbytes) {
				// put the terminating 1 bit in W as a byte (10000000)
				// and increment sbi so that we don't get here again
				// (eg in a subsequent block)
				PUTCHAR_BE(W, wbi, 0x80);
				++sbi;
				++wbi;
			}
			// if we're done with the salt and added the terminating byte
			// and this block's not full ...
			if (sbi > salt_len && wbi < nblockbytes) {

				if (block < nblocks - 1) {
					// if it's not the last block,
					// pad to the end of the block
					for ( ; wbi < nblockbytes; ++wbi) {
						PUTCHAR_BE(W, wbi, 0x00);
					}
				}
				else {
					// but if it is the last block,
					// pad up to the last 8 bytes of the block
					for ( ; wbi < nblockbytes - 8; ++wbi) {
						PUTCHAR_BE(W, wbi, 0x00);
					}
					// ... and put the message length (password + salt)
					// in bits into W[14] & W[15] as "64-bit big-endian"
					// Not sure if this is correct way to do it though!
					// But this seems to be correct (on CPU only, not GPU - so far!)
					W[14] = (uint)(msg_bits >> 32);          // big-endian low-order word
					W[15] = (uint)(msg_bits & 0xFFFFFFFF);	// big-endian high-order word
/* won't work in GPU, but keep for reference:
					printf("kernel - pwd_len: %i, block: %i, msg_bits: %016x W: ", pwd_len, block, msg_bits);
					for (wbi = 0; wbi < 16; ++wbi) {
						printf("%x ",W[wbi]);
					}
					printf("\n");
*/

				}
			}
		}
		sha1_block(W, o);
	}

#pragma unroll 5
	for (i = 0; i < 5; ++i)
		outbuffer[gid].key[i] = SWAP32(o[i]);

}
