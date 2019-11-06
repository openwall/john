/*
 * This software is Copyright (c) 2014 Sayantan Datta <std2048 at gmail dot com>
 * and Copyright (c) 2014-2016 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on CPU version by Jeff Fay, bartavelle and Solar Designer.
 */

#include "opencl_lotus5_fmt.h"
#include "opencl_misc.h"

#if cpu(DEVICE_INFO)
#define MAYBE_LOCAL __constant
#else
#define USE_LOCAL      1
#define MAYBE_LOCAL __local const
#endif

__constant uint magic_table[256] = {
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
  0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
  0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
  0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
  0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
  0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
  0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
  0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
  0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
  0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
  0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
  0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
  0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
  0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
  0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
  0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
  0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
  0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
  0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
  0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
  0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
  0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
};

inline void
lotus_transform_password (unsigned int *i1, unsigned int *o1,
                          MAYBE_LOCAL unsigned int *lotus_magic_table)
{
	unsigned int p1;
	int i;

	p1 = 0x00;
	for (i = 0; i < 4; i++) {
		p1 = o1[i] = lotus_magic_table[((i1[i] & 0xff) ^ p1) & 0xff];
		p1 = lotus_magic_table[(((i1[i] & 0x0000ff00) >> 8) ^ p1) & 0xff];
		o1[i] |= p1 << 8;
		p1 = lotus_magic_table[(((i1[i] & 0x00ff0000) >> 16) ^ p1) & 0xff];
		o1[i] |= p1 << 16;
		p1 = lotus_magic_table[(((i1[i] & 0xff000000) >> 24) ^ p1) & 0xff];
		o1[i] |= p1 << 24;
	}
}

/* The mixing function: perturbs the first three rows of the matrix */
inline void
lotus_mix (unsigned int *m1, MAYBE_LOCAL unsigned int *lotus_magic_table)
{
	int i, j, k;
	unsigned int p1;

	p1 = 0;

	for (i = 18; i > 0; i--) {
		k = 0;
		for (j = 48; j > 0; ) {
			p1 = (m1[k] & 0xff) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffffff00) | p1;
			p1 =  ((m1[k] & 0x0000ff00) >> 8) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffff00ff) | (p1 << 8);
			p1 =  ((m1[k] & 0x00ff0000) >> 16) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xff00ffff) | (p1 << 16);
			p1 =  ((m1[k] & 0xff000000) >> 24) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0x00ffffff) | (p1 << 24);
			k++;
			p1 = (m1[k] & 0xff) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffffff00) | p1;
			p1 =  ((m1[k] & 0x0000ff00) >> 8) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffff00ff) | (p1 << 8);
			p1 =  ((m1[k] & 0x00ff0000) >> 16) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xff00ffff) | (p1 << 16);
			p1 =  ((m1[k] & 0xff000000) >> 24) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0x00ffffff) | (p1 << 24);
			k++;
			p1 = (m1[k] & 0xff) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffffff00) | p1;
			p1 =  ((m1[k] & 0x0000ff00) >> 8) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffff00ff) | (p1 << 8);
			p1 =  ((m1[k] & 0x00ff0000) >> 16) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xff00ffff) | (p1 << 16);
			p1 =  ((m1[k] & 0xff000000) >> 24) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0x00ffffff) | (p1 << 24);
			k++;
			p1 = (m1[k] & 0xff) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffffff00) | p1;
			p1 =  ((m1[k] & 0x0000ff00) >> 8) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xffff00ff) | (p1 << 8);
			p1 =  ((m1[k] & 0x00ff0000) >> 16) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0xff00ffff) | (p1 << 16);
			p1 =  ((m1[k] & 0xff000000) >> 24) ^ lotus_magic_table[((j-- + p1) & 0xff) & 0xff];
			m1[k] = (m1[k] & 0x00ffffff) | (p1 << 24);
			k++;
		}
	}
}

__kernel void
lotus5(__global lotus5_key *i_saved_key,
       __global unsigned int *crypt_key)
{
	unsigned int index = get_global_id(0);
	unsigned int m32[16];
	int password_length;
#if USE_LOCAL
	__local unsigned int s_magic_table[256];

	{
		size_t local_work_dim = get_local_size(0);
		unsigned int lid = get_local_id(0);
		size_t offset;

		for (offset = lid; offset < 256; offset += local_work_dim)
			s_magic_table[offset & 255] = magic_table[offset & 255];

		barrier(CLK_LOCAL_MEM_FENCE);
	}
#endif

	m32[0] = m32[1] = m32[2] = m32[3] = 0;
	m32[4] = m32[5] = m32[6] = m32[7] = 0;

	password_length = i_saved_key[index].l;

	{
		int i, j;

		j = password_length % 4;
		i = password_length / 4;

		for (;j < 4; j++)
			m32[4 + i] |= (PLAINTEXT_LENGTH - password_length) << (j * 8);

		for (j = i + 1; j < 4; j++)
			m32[4 + j] = (PLAINTEXT_LENGTH - password_length) |
	                             (PLAINTEXT_LENGTH - password_length) << 8 |
	                             (PLAINTEXT_LENGTH - password_length) << 16 |
	                             (PLAINTEXT_LENGTH - password_length) << 24;
		}

	m32[8] = m32[4] ^= i_saved_key[index].v.w[0];
	m32[9] = m32[5] ^= i_saved_key[index].v.w[1];
	m32[10] = m32[6] ^= i_saved_key[index].v.w[2];
	m32[11] = m32[7] ^= i_saved_key[index].v.w[3];

	lotus_transform_password(m32 + 4, m32 + 12,
#if USE_LOCAL
		s_magic_table
#else
		magic_table
#endif
	);

	lotus_mix(m32,
#if USE_LOCAL
		s_magic_table
#else
		magic_table
#endif
	);

	m32[4] = m32[12];
	m32[5] = m32[13];
	m32[6] = m32[14];
	m32[7] = m32[15];

	m32[8] = m32[0] ^ m32[4];
	m32[9] = m32[1] ^ m32[5];
	m32[10] = m32[2]^ m32[6];
	m32[11] = m32[3] ^ m32[7];

	lotus_mix(m32,
#if USE_LOCAL
		s_magic_table
#else
		magic_table
#endif
	);

	crypt_key[index * BINARY_SIZE_IN_uint32_t] = m32[0];
	crypt_key[index * BINARY_SIZE_IN_uint32_t + 1] = m32[1];
	crypt_key[index * BINARY_SIZE_IN_uint32_t + 2] = m32[2];
	crypt_key[index * BINARY_SIZE_IN_uint32_t + 3] = m32[3];
}
