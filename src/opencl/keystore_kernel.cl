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
 *
 *  Updated Feb 2016, JimF. Reduced password to just password. Upconvert
 *  to 16 bit BE done here (less data xfer, improved speed 20%). Changed
 *  computatation of total block counts (to reduce variables). Also, GPU
 *  only returns 4 bytes. If there is a 'hit', CPU will be used to fully
 *  validate. This also improves speed (less data xfer from GPU back).
 */

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

#define nblockbytes 64

typedef struct {
	uint  length;
	uchar pass[PASSLEN];
} keystore_password;

typedef struct {
	uint key;
} keystore_hash;

typedef struct {
	uint length;
	uchar salt[SALTLEN];
} keystore_salt;

__kernel void keystore(const __global uint *keys,
                       __global const uint *index,
                       __global keystore_hash *outbuffer,
                       __constant keystore_salt *salt)
{
	uint gid = get_global_id(0);
	uint base = index[gid];
	uint pwd_len = base & 127;
	uint W[16], o[5];
	uint block;		// block index
	uint nblocks;	// total number of blocks we need to hash.
	uint pbi = 0;	// password index
	uint sbi = 0;	// salt index
	uint salt_len = salt->length;
	// message length is password length * 2 + salt length
	uint msg_len = (pwd_len << 1) + salt_len;
	__global uchar *inbuffer =
		(__global uchar*)(keys + (base >> 7)); // Packed key xfer

	// But the bytes we actually need to accommodate in
	// each exactly 64-byte block must also include:
	// 	- sizeof(uchar) for salt-terminating bit 1, set as uchar 0x80
	//	- 0 or more '\0' byte padding, so that bit length is at proper location.
	// 	- sizeof(ulong) for final 64-bit message length (at very end of last block)
	nblocks = msg_len / nblockbytes + 1;
	if ((msg_len & 63) > 55)
		++nblocks; // the 0x80 and 8 bytes of bit_length do NOT fit into last buffer.

	sha1_init(o);

	for (block = 0; block < nblocks; ++block) {
		// wbi is byte offset within this block we are working on.
		uint wbi = 0;

		// - if we're not done with the password,
		//   put it in W
		for ( ; pbi < pwd_len && wbi < nblockbytes; ++wbi, ++pbi) {
			// password is used as BE uint16 upcast. NOTE, not UTF16 encoded!
			PUTCHAR_BE(W, wbi, 0);
			++wbi;
			PUTCHAR_BE(W, wbi, inbuffer[pbi]);
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
					//W[14] = msg_len >> 29;	// big-endian low-order word
					W[14] = 0;				// our hash will NEVER be this large!
					W[15] = msg_len << 3;	// big-endian high-order word
				}
			}
		}
		sha1_block(uint, W, o);
	}
	outbuffer[gid].key = SWAP32(o[0]);
}
