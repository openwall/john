/*
   This code was largely inspired by
   pyrit opencl kernel sha1 routines, royger's sha1 sample,
   and md5_opencl_kernel.cl inside jtr.
   Copyright 2011 by Samuele Giovanni Tonon
   samu at linuxasylum dot net
   and Copyright (c) 2012 magnum
   This program comes with ABSOLUTELY NO WARRANTY; express or
   implied .
   This is free software, and you are welcome to redistribute it
   under certain conditions; as expressed here
   http://www.gnu.org/licenses/gpl-2.0.html
*/

#include "opencl_device_info.h"
#include "opencl_misc.h"
#include "opencl_sha1.h"

__kernel void sha1_crypt_kernel(__global uchar *salt,
                                __global char *plain_key,
                                __global uint *digest)
{
	int t, gid, msg_pad;
	int stop, mmod;
	uint i, ulen;
	uint W[16], temp, A,B,C,D,E;
	uint num_keys = get_global_size(0);

	gid = get_global_id(0);
	msg_pad = gid * PLAINTEXT_LENGTH;

#pragma unroll
	for (t = 3; t < 15; t++)
		W[t] = 0x00000000;

	for (i = 0; i < PLAINTEXT_LENGTH && ((uchar)plain_key[msg_pad + i]) != 0x0; i++)
		;

	stop = i / 4 ;
	for (t = 0 ; t < stop ; t++){
		W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
		W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
		W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
		W[t] |= (uchar)  plain_key[msg_pad + t * 4 + 3];
	}

	mmod = i % 4;
	if ( mmod == 3){
		W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
		W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
		W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 2]) << 8;
		W[t] |= (uchar)  salt[0];
		W[t+2] = ((uchar) salt[5]) << 24;
		W[t+2] |=  ((uchar)  salt[6]) << 16;
		W[t+2] |=  ((uchar)  salt[7]) << 8;
		W[t+2] |=  ((uchar) 0x80) ;
		mmod = 4 - mmod;
	} else if (mmod == 2) {
		W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
		W[t] |= ((uchar) plain_key[msg_pad + t * 4 + 1]) << 16;
		W[t] |= ((uchar)  salt[0]) << 8;
		W[t] |= (uchar)  salt[1];
		W[t+2] =  ((uchar)  salt[6]) << 24;
		W[t+2] |=  ((uchar)  salt[7]) << 16;
		W[t+2] |=  0x8000 ;
		mmod = 4 - mmod;
	} else if (mmod == 1) {
		W[t] = ((uchar)  plain_key[msg_pad + t * 4]) << 24;
		W[t] |= ((uchar)  salt[0]) << 16;
		W[t] |= ((uchar)  salt[1]) << 8;
		W[t] |= (uchar)  salt[2];
		W[t+2] =  ((uchar)  salt[7]) << 24;
		W[t+2] |=  0x800000 ;
		mmod = 4 - mmod;
	} else /*if (mmod == 0)*/ {
		W[t+2] =  0x80000000 ;
		t = t-1;
	}

	t = t+1;
	for(; t < (stop + 2) && mmod < 8 ; t++ ){
		W[t] = ((uchar)  salt[mmod]) << 24;
		W[t] |= ((uchar)  salt[mmod + 1]) << 16;
		W[t] |= ((uchar)  salt[mmod + 2]) << 8;
		W[t] |= ((uchar)  salt[mmod + 3]);
		mmod = mmod + 4;
	}

	i = i+8;
	ulen = (i * 8) & 0xFFFFFFFF;
	W[15] =  ulen ;

	A = INIT_A;
	B = INIT_B;
	C = INIT_C;
	D = INIT_D;
	E = INIT_E;

	SHA1(A, B, C, D, E, W);

	digest[gid] = SWAP32(A + INIT_A);
	digest[gid+1*num_keys] = SWAP32(B + INIT_B);
	digest[gid+2*num_keys] = SWAP32(C + INIT_C);
	digest[gid+3*num_keys] = SWAP32(D + INIT_D);
	digest[gid+4*num_keys] = SWAP32(E + INIT_E);
}
