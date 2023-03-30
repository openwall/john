/*
 * This software is Copyright (c) 2012-2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#include "opencl_DES_kernel_params.h"

#if WORK_GROUP_SIZE > 0
#define y48(p, q) vxorf(B[p], s_des_bs_key[q + s_key_offset])
#define z(p, q) vxorf(B[p], s_des_bs_key[key_map[q + k] + s_key_offset])
#else
#define y48(p, q) vxorf(B[p], des_bs_key[section + q * gws])
#define z(p, q) vxorf(B[p], des_bs_key[section + key_map[q + k] * gws])
#endif

#define H1_s()\
	s1(z(index0, 0), z(index1, 1), z(index2, 2), z(index3, 3), z(index4, 4), z(index5, 5),\
		B,40, 48, 54, 62);\
	s2(z(index6, 6), z(index7, 7), z(index8, 8), z(index9, 9), z(index10, 10), z(index11, 11),\
		B,44, 59, 33, 49);\
	s3(z(7, 12), z(8, 13), z(9, 14),\
		z(10, 15), z(11, 16), z(12, 17),\
		B,55, 47, 61, 37);\
	s4(z(11, 18), z(12, 19), z(13, 20),\
		z(14, 21), z(15, 22), z(16, 23),\
		B,57, 51, 41, 32);\
	s5(z(index24, 24), z(index25, 25), z(index26, 26), z(index27, 27), z(index28, 28), z(index29, 29),\
		B,39, 45, 56, 34);\
	s6(z(index30, 30), z(index31, 31), z(index32, 32), z(index33, 33), z(index34, 34), z(index35, 35),\
		B,35, 60, 42, 50);\
	s7(z(23, 36), z(24, 37), z(25, 38),\
		z(26, 39), z(27, 40), z(28, 41),\
		B,63, 43, 53, 38);\
	s8(z(27, 42), z(28, 43), z(29, 44),\
		z(30, 45), z(31, 46), z(0, 47),\
		B,36, 58, 46, 52);

#define H2_s()\
	s1(z(index48, 48), z(index49, 49), z(index50, 50), z(index51, 51), z(index52, 52), z(index53, 53),\
		B,8, 16, 22, 30);\
	s2(z(index54, 54), z(index55, 55), z(index56, 56), z(index57, 57), z(index58, 58), z(index59, 59),\
		B,12, 27, 1, 17);\
	s3(z(39, 60), z(40, 61), z(41, 62),\
		z(42, 63), z(43, 64), z(44, 65),\
		B,23, 15, 29, 5);\
	s4(z(43, 66), z(44, 67), z(45, 68),\
		z(46, 69), z(47, 70), z(48, 71),\
		B,25, 19, 9, 0);\
	s5(z(index72, 72), z(index73, 73), z(index74, 74), z(index75, 75), z(index76, 76), z(index77, 77),\
		B,7, 13, 24, 2);\
	s6(z(index78, 78), z(index79, 79), z(index80, 80), z(index81, 81), z(index82, 82), z(index83, 83),\
		B,3, 28, 10, 18);\
	s7(z(55, 84), z(56, 85), z(57, 86),\
		z(58, 87), z(59, 88), z(60, 89),\
		B,31, 11, 21, 6);\
	s8(z(59, 90), z(60, 91), z(61, 92),\
		z(62, 93), z(63, 94), z(32, 95),\
		B,4, 26, 14, 20);

#define H2_k48()\
	s1(y48(index48, 12), y48(index49, 46), y48(index50, 33), y48(index51, 52), y48(index52, 48), y48(index53, 20),\
		B,8, 16, 22, 30);\
	s2(y48(index54, 34), y48(index55, 55), y48(index56, 5), y48(index57, 13), y48(index58, 18), y48(index59, 40),\
		B,12, 27, 1, 17);\
	s3(y48(39, 4), y48(40, 32), y48(41, 26),\
		y48(42, 27), y48(43, 38), y48(44, 54),\
		B,23, 15, 29, 5);\
	s4(y48(43, 53), y48(44, 6), y48(45, 31),\
		y48(46, 25), y48(47, 19), y48(48, 41),\
		B,25, 19, 9, 0);\
	s5(y48(index72, 15), y48(index73, 24), y48(index74, 28), y48(index75, 43), y48(index76, 30), y48(index77, 3),\
		B,7, 13, 24, 2);\
	s6(y48(index78, 35), y48(index79, 22), y48(index80, 2), y48(index81, 44), y48(index82, 14), y48(index83, 23),\
		B,3, 28, 10, 18);\
	s7(y48(55, 51), y48(56, 16), y48(57, 29),\
		y48(58, 49), y48(59, 7), y48(60, 17),\
		B,31, 11, 21, 6);\
	s8(y48(59, 37), y48(60, 8), y48(61, 9),\
		y48(62, 50), y48(63, 42), y48(32, 21),\
		B,4, 26, 14, 20);

#define SWAP(a, b) {	\
	tmp = B[a];	\
	B[a] = B[b];	\
	B[b] = tmp;	\
}

#define BIG_SWAP() { 	\
	SWAP(0, 32);	\
	SWAP(1, 33);	\
	SWAP(2, 34);	\
	SWAP(3, 35);	\
	SWAP(4, 36);	\
	SWAP(5, 37);	\
	SWAP(6, 38);	\
	SWAP(7, 39);	\
	SWAP(8, 40);	\
	SWAP(9, 41);	\
	SWAP(10, 42);	\
	SWAP(11, 43);	\
	SWAP(12, 44);	\
	SWAP(13, 45);	\
	SWAP(14, 46);	\
	SWAP(15, 47);	\
	SWAP(16, 48);	\
	SWAP(17, 49);	\
	SWAP(18, 50);	\
	SWAP(19, 51);	\
	SWAP(20, 52);	\
	SWAP(21, 53);	\
	SWAP(22, 54);	\
	SWAP(23, 55);	\
	SWAP(24, 56);	\
	SWAP(25, 57);	\
	SWAP(26, 58);	\
	SWAP(27, 59);	\
	SWAP(28, 60);	\
	SWAP(29, 61);	\
	SWAP(30, 62);	\
	SWAP(31, 63);  	\
}

__kernel void DES_bs_25( constant uint *key_map
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
                         __attribute__((max_constant_size(3072)))
#endif
                         , __global DES_bs_vector *des_bs_key,
                         __global vtype *unchecked_hashes) {

		int section = get_global_id(0);
		int gws = get_global_size(0);

		vtype B[64];

		int iterations;
		int k, i;

#if WORK_GROUP_SIZE > 0
		__local DES_bs_vector s_des_bs_key[56 * WORK_GROUP_SIZE];
		int lid = get_local_id(0);
		int s_key_offset = 56 * lid;
		for (i = 0; i < 56; i++)
			s_des_bs_key[s_key_offset + i] = des_bs_key[section + i * gws];

		barrier(CLK_LOCAL_MEM_FENCE);
#endif
		{
			vtype zero = 0;
			DES_bs_clear_block
		}

#ifdef SAFE_GOTO
		vtype tmp;

		for (iterations = 24; iterations >= 0; iterations--) {
			for (k = 0; k < 768; k += 96) {
				H1_s();
				H2_s();
			}
			BIG_SWAP();
		}

		BIG_SWAP();
		for (i = 0; i < 64; i++)
			unchecked_hashes[i * gws + section] = B[i];

#else
		int rounds_and_swapped;
		rounds_and_swapped = 8;
		iterations = 25;
		k = 0;

start:
		H1_s();
		if (rounds_and_swapped == 0x100) goto next;
		H2_s();
		k += 96;
		rounds_and_swapped--;

		if (rounds_and_swapped > 0) goto start;
		k -= (0x300 + 48);
		rounds_and_swapped = 0x108;
		if (--iterations) goto swap;

		for (i = 0; i < 64; i++)
			unchecked_hashes[i * gws + section] = B[i];

		return;

swap:
		H2_k48();
		k += 96;
		if (--rounds_and_swapped) goto start;
next:
		k -= (0x300 - 48);
		rounds_and_swapped = 8;
		iterations--;
		goto start;
#endif
}
