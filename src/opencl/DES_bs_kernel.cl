/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#include "opencl_DES_kernel_params.h"

#if !HARDCODE_SALT

#ifndef RV7xx
#define x(p) vxorf(B[ index96[p]], _local_K[_local_index768[p + k] + local_offset_K])
#define y(p, q) vxorf(B[p]       , _local_K[_local_index768[q + k] + local_offset_K])
#else
#define x(p) vxorf(B[index96[p] ], _local_K[index768[p + k] + local_offset_K])
#define y(p, q) vxorf(B[p]       , _local_K[index768[q + k] + local_offset_K])
#endif

#define H1()\
	s1(x(0), x(1), x(2), x(3), x(4), x(5),\
		B,40, 48, 54, 62);\
	s2(x(6), x(7), x(8), x(9), x(10), x(11),\
		B,44, 59, 33, 49);\
	s3(y(7, 12), y(8, 13), y(9, 14),\
		y(10, 15), y(11, 16), y(12, 17),\
		B,55, 47, 61, 37);\
	s4(y(11, 18), y(12, 19), y(13, 20),\
		y(14, 21), y(15, 22), y(16, 23),\
		B,57, 51, 41, 32);\
	s5(x(24), x(25), x(26), x(27), x(28), x(29),\
		B,39, 45, 56, 34);\
	s6(x(30), x(31), x(32), x(33), x(34), x(35),\
		B,35, 60, 42, 50);\
	s7(y(23, 36), y(24, 37), y(25, 38),\
		y(26, 39), y(27, 40), y(28, 41),\
		B,63, 43, 53, 38);\
	s8(y(27, 42), y(28, 43), y(29, 44),\
		y(30, 45), y(31, 46), y(0, 47),\
		B,36, 58, 46, 52);

#define H2()\
	s1(x(48), x(49), x(50), x(51), x(52), x(53),\
		B,8, 16, 22, 30);\
	s2(x(54), x(55), x(56), x(57), x(58), x(59),\
		B,12, 27, 1, 17);\
	s3(y(39, 60), y(40, 61), y(41, 62),\
		y(42, 63), y(43, 64), y(44, 65),\
		B,23, 15, 29, 5);\
	s4(y(43, 66), y(44, 67), y(45, 68),\
		y(46, 69), y(47, 70), y(48, 71),\
		B,25, 19, 9, 0);\
	s5(x(72), x(73), x(74), x(75), x(76), x(77),\
		B,7, 13, 24, 2);\
	s6(x(78), x(79), x(80), x(81), x(82), x(83),\
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
		rounds_and_swapped--;\
                barrier(CLK_LOCAL_MEM_FENCE);
#elif defined(_NV)
#define loop_body()\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k += 96;\
		rounds_and_swapped--;\
		barrier(CLK_LOCAL_MEM_FENCE);
#else
#define loop_body()\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k += 96;\
		rounds_and_swapped--;
#endif

__kernel void DES_bs_25_b( constant uint *index768
#if gpu_amd(DEVICE_INFO)
                           __attribute__((max_constant_size(3072)))
#endif
                           ,constant int *index96
#if gpu_amd(DEVICE_INFO)
                           __attribute__((max_constant_size(384)))
#endif
			   ,__global DES_bs_vector *K,
                           __global DES_bs_vector *B_global,
                           __global int *binary,
                           int num_loaded_hashes,
                           volatile __global uint *hash_ids,
			   volatile __global uint *bitmap)
{

		unsigned int section = get_global_id(0), local_offset_K;
		unsigned int local_id = get_local_id(0);
		unsigned int global_work_size = get_global_size(0);
		unsigned int local_work_size = get_local_size(0);

		local_offset_K  = 56 * local_id;

		vtype B[64];

		__local DES_bs_vector _local_K[56 * WORK_GROUP_SIZE] ;
#ifndef RV7xx
		__local ushort _local_index768[768] ;
#endif
		int iterations;
#ifndef SAFE_GOTO
		int rounds_and_swapped;
#else
		vtype tmp;
#endif
		int k = 0, i;

		if (!section) {
			hash_ids[0] = 0;
			for (i = 0; i < (num_loaded_hashes - 1)/32 + 1; i++)
				bitmap[i] = 0;
		}
		barrier(CLK_GLOBAL_MEM_FENCE);

		for (i = 0; i < 56; i++)
			_local_K[local_id * 56 + i] = K[section + i * global_work_size];

#ifndef RV7xx
		for (i = 0; i < 768; i += local_work_size)
			_local_index768[local_id + i] = index768[local_id + i];
#endif
		barrier(CLK_LOCAL_MEM_FENCE);

		{
			vtype zero = 0;
			DES_bs_clear_block
		}

		k = 0;
#ifndef SAFE_GOTO
		rounds_and_swapped = 8;
#endif
		iterations = 25;


#ifdef SAFE_GOTO
	for (iterations = 24; iterations >= 0; iterations--) {
		for (k = 0; k < 768; k += 96) {
			H1();
			H2();
		}
		for (i = 0; i < 32 && iterations; i++) {
			tmp = B[i];
			B[i] = B[i + 32];
			B[i + 32] = tmp;
		}
	}
#else
start:
		loop_body();

		if (rounds_and_swapped > 0) goto start;
		k -= (0x300 + 48);
		rounds_and_swapped = 0x108;

		if (--iterations) goto swap;
#endif
		cmp(B, binary, num_loaded_hashes, hash_ids, bitmap, B_global, section);

		return;
#ifndef SAFE_GOTO
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
#endif
