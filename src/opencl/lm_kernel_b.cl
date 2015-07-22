/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#include "opencl_lm_kernel_params.h"

#if WORK_GROUP_SIZE
#define y(p, q) vxorf(B[p], lm_key[lm_key_idx[q + k] + s_key_offset])
#else
#define y(p, q) vxorf(B[p], lm_key[lm_key_idx[q + k] * gws + section])
#endif

#define H1()\
	s1(y(31, 0), y(0, 1), y(1, 2),\
	y(2, 3), y(3, 4), y(4, 5),\
	B, 40, 48, 54, 62);\
	s2(y(3, 6), y(4, 7), y(5, 8),\
	y(6, 9), y(7, 10), y(8, 11),\
	B, 44, 59, 33, 49);\
	s3(y(7, 12), y(8, 13), y(9, 14),\
	y(10, 15), y(11, 16), y(12, 17),\
	B, 55, 47, 61, 37);\
	s4(y(11, 18), y(12, 19), y(13, 20),\
	y(14, 21), y(15, 22), y(16, 23),\
	B, 57, 51, 41, 32);\
	s5(y(15, 24), y(16, 25), y(17, 26),\
	y(18, 27), y(19, 28), y(20, 29),\
	B, 39, 45, 56, 34);\
	s6(y(19, 30), y(20, 31), y(21, 32),\
	y(22, 33), y(23, 34), y(24, 35),\
	B, 35, 60, 42, 50);\
	s7(y(23, 36), y(24, 37), y(25, 38),\
	y(26, 39), y(27, 40), y(28, 41),\
	B, 63, 43, 53, 38);\
	s8(y(27, 42), y(28, 43), y(29, 44),\
	y(30, 45), y(31, 46), y(0, 47),\
	B, 36, 58, 46, 52);

#define H2()\
	s1(y(63, 48), y(32, 49), y(33, 50),\
	y(34, 51), y(35, 52), y(36, 53),\
	B, 8, 16, 22, 30);\
	s2(y(35, 54), y(36, 55), y(37, 56),\
	y(38, 57), y(39, 58), y(40, 59),\
	B, 12, 27, 1, 17);\
	s3(y(39, 60), y(40, 61), y(41, 62),\
	y(42, 63), y(43, 64), y(44, 65),\
	B, 23, 15, 29, 5);\
	s4(y(43, 66), y(44, 67), y(45, 68),\
	y(46, 69), y(47, 70), y(48, 71),\
	B, 25, 19, 9, 0);\
	s5(y(47, 72), y(48, 73), y(49, 74),\
	y(50, 75), y(51, 76), y(52, 77),\
	B, 7, 13, 24, 2);\
	s6(y(51, 78), y(52, 79), y(53, 80),\
	y(54, 81), y(55, 82), y(56, 83),\
	B, 3, 28, 10, 18);\
	s7(y(55, 84), y(56, 85), y(57, 86),\
	y(58, 87), y(59, 88), y(60, 89),\
	B, 31, 11, 21, 6);\
	s8(y(59, 90), y(60, 91), y(61, 92),\
	y(62, 93), y(63, 94), y(32, 95),\
	B, 4, 26, 14, 20);

#define lm_set_block_8(b, i, v0, v1, v2, v3, v4, v5, v6, v7) \
	{ \
		b[i] = v0; \
		b[i + 1] = v1; \
		b[i + 2] = v2; \
		b[i + 3] = v3; \
		b[i + 4] = v4; \
		b[i + 5] = v5; \
		b[i + 6] = v6; \
		b[i + 7] = v7; \
	}

#define vzero 0

#define vones (~(vtype)0)

inline void lm_loop(__private vtype *B,
#if WORK_GROUP_SIZE
		__local lm_vector *lm_key,
#else
		__global lm_vector *lm_key,
#endif
#if USE_LOCAL_MEM
		__local ushort *lm_key_idx,
#else
		constant uint *lm_key_idx,
#endif
#if WORK_GROUP_SIZE
		unsigned int s_key_offset
#else
		unsigned int gws,
		unsigned int section
#endif
		) {

		int k = 0, rounds = 8;

		do {
			H1();
			H2();
			k += 96;
		} while(--rounds);
}

__kernel void lm_bs(constant uint *lm_key_idx
#if gpu_amd(DEVICE_INFO)
                   __attribute__((max_constant_size(3072)))
#endif
		  ,__global lm_vector *lm_key,
		   __global unsigned int *offset_table,
		   __global unsigned int *hash_table,
		   __global unsigned int *bitmaps,
                   volatile __global uint *hash_ids,
		   volatile __global uint *bitmap_dupe)
{
		unsigned int section = get_global_id(0);
		unsigned int gws = get_global_size(0);

		vtype B[64];

#if USE_LOCAL_MEM || WORK_GROUP_SIZE
		int i;
		unsigned int lid = get_local_id(0);
#endif

#if WORK_GROUP_SIZE
		unsigned int s_key_offset  = 56 * lid;
		__local lm_vector s_lm_key[56 * WORK_GROUP_SIZE];
		for (i = 0; i < 56; i++)
			s_lm_key[lid * 56 + i] = lm_key[section + i * gws];
#endif
#if USE_LOCAL_MEM
		__local ushort s_key_idx[768];
		unsigned int lws= get_local_size(0);
		for (i = 0; i < 768; i += lws)
			s_key_idx[(lid + i) % 768] = lm_key_idx[(lid + i) % 768];
#endif
#if USE_LOCAL_MEM || WORK_GROUP_SIZE
		barrier(CLK_LOCAL_MEM_FENCE);
#endif
		vtype z = vzero, o = vones;
		lm_set_block_8(B, 0, z, z, z, z, z, z, z, z);
		lm_set_block_8(B, 8, o, o, o, z, o, z, z, z);
		lm_set_block_8(B, 16, z, z, z, z, z, z, z, o);
		lm_set_block_8(B, 24, z, z, o, z, z, o, o, o);
		lm_set_block_8(B, 32, z, z, z, o, z, o, o, o);
		lm_set_block_8(B, 40, z, z, z, z, z, o, z, z);
		lm_set_block_8(B, 48, o, o, z, z, z, z, o, z);
		lm_set_block_8(B, 56, o, z, o, z, o, o, o, o);

		lm_loop(B,
#if WORK_GROUP_SIZE
		s_lm_key,
#else
		lm_key,
#endif
#if USE_LOCAL_MEM
		s_key_idx,
#else
		lm_key_idx,
#endif
#if WORK_GROUP_SIZE
		s_key_offset
#else
		gws,
		section
#endif
		);

		cmp(B, offset_table, hash_table, bitmaps, hash_ids, bitmap_dupe, section);
}
