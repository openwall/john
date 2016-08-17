/*
 * This software is Copyright (c) 2012-2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#include "opencl_DES_kernel_params.h"

#if USE_LOCAL_MEM
#define KEY_MAP		s_key_map
#else
#define KEY_MAP		key_map
#endif

#if WORK_GROUP_SIZE > 0
#define y(p, q) vxorf(B[p], s_des_bs_key[KEY_MAP[q + k] + s_key_offset])
#else
#define y(p, q) vxorf(B[p], des_bs_key[section + KEY_MAP[q + k] * gws])
#endif

#define H1()\
	s1(y(processed_salt[0], 0), y(processed_salt[1], 1), y(processed_salt[2], 2), y(processed_salt[3], 3), y(processed_salt[4], 4), y(processed_salt[5], 5),\
		B,40, 48, 54, 62);\
	s2(y(processed_salt[6], 6), y(processed_salt[7], 7), y(processed_salt[8], 8), y(processed_salt[9], 9), y(processed_salt[10], 10), y(processed_salt[11], 11),\
		B,44, 59, 33, 49);\
	s3(y(7, 12), y(8, 13), y(9, 14),\
		y(10, 15), y(11, 16), y(12, 17),\
		B,55, 47, 61, 37);\
	s4(y(11, 18), y(12, 19), y(13, 20),\
		y(14, 21), y(15, 22), y(16, 23),\
		B,57, 51, 41, 32);\
	s5(y(processed_salt[12], 24), y(processed_salt[13], 25), y(processed_salt[14], 26), y(processed_salt[15], 27), y(processed_salt[16], 28), y(processed_salt[17], 29),\
		B,39, 45, 56, 34);\
	s6(y(processed_salt[18], 30), y(processed_salt[19], 31), y(processed_salt[20], 32), y(processed_salt[21], 33), y(processed_salt[22], 34), y(processed_salt[23], 35),\
		B,35, 60, 42, 50);\
	s7(y(23, 36), y(24, 37), y(25, 38),\
		y(26, 39), y(27, 40), y(28, 41),\
		B,63, 43, 53, 38);\
	s8(y(27, 42), y(28, 43), y(29, 44),\
		y(30, 45), y(31, 46), y(0, 47),\
		B,36, 58, 46, 52);

#define H2()\
	s1(y(processed_salt[24], 48), y(processed_salt[25], 49), y(processed_salt[26], 50), y(processed_salt[27], 51), y(processed_salt[28], 52), y(processed_salt[29], 53),\
		B,8, 16, 22, 30);\
	s2(y(processed_salt[30], 54), y(processed_salt[31], 55), y(processed_salt[32], 56), y(processed_salt[33], 57), y(processed_salt[34], 58), y(processed_salt[35], 59),\
		B,12, 27, 1, 17);\
	s3(y(39, 60), y(40, 61), y(41, 62),\
		y(42, 63), y(43, 64), y(44, 65),\
		B,23, 15, 29, 5);\
	s4(y(43, 66), y(44, 67), y(45, 68),\
		y(46, 69), y(47, 70), y(48, 71),\
		B,25, 19, 9, 0);\
	s5(y(processed_salt[36], 72), y(processed_salt[37], 73), y(processed_salt[38], 74), y(processed_salt[39], 75), y(processed_salt[40], 76), y(processed_salt[41], 77),\
		B,7, 13, 24, 2);\
	s6(y(processed_salt[42], 78), y(processed_salt[43], 79), y(processed_salt[44], 80), y(processed_salt[45], 81), y(processed_salt[46], 82), y(processed_salt[47], 83),\
		B,3, 28, 10, 18);\
	s7(y(55, 84), y(56, 85), y(57, 86),\
		y(58, 87), y(59, 88), y(60, 89),\
		B,31, 11, 21, 6);\
	s8(y(59, 90), y(60, 91), y(61, 92),\
		y(62, 93), y(63, 94), y(32, 95),\
		B,4, 26, 14, 20);

#ifdef _CPU
#define loop_body()\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k += 96;\
		rounds_and_swapped--;\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k += 96;\
		rounds_and_swapped--;
#else
#define loop_body()\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k += 96;\
		rounds_and_swapped--;
#endif

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

__kernel void DES_bs_25_b(constant uint *key_map
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
                          __attribute__((max_constant_size(3072)))
#endif
                          , constant int *processed_salt
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
                          __attribute__((max_constant_size(192)))
#endif
			  , __global DES_bs_vector *des_bs_key,
                          __global vtype *unchecked_hashes)
{
	int section = get_global_id(0);
#if WORK_GROUP_SIZE || USE_LOCAL_MEM
	int lid = get_local_id(0);
#endif
	int gws = get_global_size(0);
	vtype B[64];
	int iterations;
	int k, i;

#if WORK_GROUP_SIZE > 0
	__local DES_bs_vector s_des_bs_key[56 * WORK_GROUP_SIZE];
	int s_key_offset = lid * 56;
	for (i = 0; i < 56; i++)
		s_des_bs_key[lid * 56 + i] = des_bs_key[section + i * gws];
#endif

#if USE_LOCAL_MEM
	__local ushort s_key_map[768];
	int lws = get_local_size(0);

	for (i = 0; i < 768; i += lws)
		s_key_map[(lid + i) % 768] = key_map[(lid + i) % 768];
#endif

#if USE_LOCAL_MEM || WORK_GROUP_SIZE > 0
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
			H1();
			H2();
		}
		BIG_SWAP();
	}

	BIG_SWAP();
	for (i = 0; i < 64; i++)
		unchecked_hashes[i * gws + section] = B[i];

#else
	int rounds_and_swapped;
	k = 0;
	rounds_and_swapped = 8;
	iterations = 25;
start:
	loop_body();

	if (rounds_and_swapped > 0) goto start;
	k -= (0x300 + 48);
	rounds_and_swapped = 0x108;

	if (--iterations) goto swap;

	for (i = 0; i < 64; i++)
		unchecked_hashes[i * gws + section] = B[i];

	return;
swap:
	H2();
	k += 96;
	if (--rounds_and_swapped) goto start;
next:
	k -= (0x300 - 48);
	rounds_and_swapped = 8;
	iterations--;
	goto start;
#endif
}
