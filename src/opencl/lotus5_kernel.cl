/*
 * This software is Copyright (c) 2014 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on CPU version by Jeff Fay, bartavelle and Solar Designer.
 */

#include "opencl_lotus5_fmt.h"
#include "opencl_device_info.h"

#if cpu(DEVICE_INFO)
#define MAYBE_CONSTANT constant
#define CPU_DEVICE
#else
#define MAYBE_CONSTANT __local
#endif

inline void
lotus_transform_password (__private unsigned int *i1,
			  __private unsigned int *o1,
			  MAYBE_CONSTANT unsigned int *lotus_magic_table) {
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

/* The mixing function: perturbs the first three rows of the matrix*/
inline void
lotus_mix (__private unsigned int *m1, MAYBE_CONSTANT unsigned int *lotus_magic_table) {
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
       constant unsigned int *magic_table
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
	__attribute__((max_constant_size(256 * sizeof(unsigned int))))
#endif
       , __global unsigned int *crypt_key) {

	unsigned int index = get_global_id(0);
	unsigned int m32[16];
	int password_length;

#if !cpu(DEVICE_INFO)
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
#if cpu(DEVICE_INFO)
		magic_table
#else
		s_magic_table
#endif
	);

	lotus_mix(m32,
#if cpu(DEVICE_INFO)
		magic_table
#else
		s_magic_table
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
#if cpu(DEVICE_INFO)
		magic_table
#else
		s_magic_table
#endif
	);

	crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32] = m32[0];
	crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32 + 1] = m32[1];
	crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32 + 2] = m32[2];
	crypt_key[index * BINARY_SIZE_IN_ARCH_WORD_32 + 3] = m32[3];
}
