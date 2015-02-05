/* CAUTION:Do not change or move the next 48 lines */
#define index00 31
#define index01  0
#define index02  1
#define index03  2
#define index04  3
#define index05  4
#define index06  3
#define index07  4
#define index08  5
#define index09  6
#define index10  7
#define index11  8
#define index24 15
#define index25 16
#define index26 17
#define index27 18
#define index28 19
#define index29 20
#define index30 19
#define index31 20
#define index32 21
#define index33 22
#define index34 23
#define index35 24
#define index48 63
#define index49 32
#define index50 33
#define index51 34
#define index52 35
#define index53 36
#define index54 35
#define index55 36
#define index56 37
#define index57 38
#define index58 39
#define index59 40
#define index72 47
#define index73 48
#define index74 49
#define index75 50
#define index76 51
#define index77 52
#define index78 51
#define index79 52
#define index80 53
#define index81 54
#define index82 55
#define index83 56

/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#include "opencl_DES_WGS.h"
#include "opencl_device_info.h"

/*
 * Some devices/drivers has problems with the optimized 'goto' program flow.
 * Some AMD driver versions can't build the "fast goto" version but those who
 * can runs faster. Hawaii on 14.9 fails, Tahiti on 14.9 does not (!?).
 *
 * Nvidia can build either kernel but GTX980 is significantly faster with the
 * "safe goto" version (7% faster for one salt, 16% for many salts).
 *
 * OSX' Intel HD4000 driver [1.2(Sep25 2014 22:26:04)] fails building the
 * "fast goto" version.
 */
#if nvidia_sm_5x(DEVICE_INFO) || gpu_intel(DEVICE_INFO) ||	  \
	(gpu_amd(DEVICE_INFO) && DEV_VER_MAJOR >= 1573 && !defined(__Tahiti__))
//#warning Using 'safe goto' kernel
#define SAFE_GOTO
#else
//#warning Using 'fast goto' kernel
#endif

#define ARCH_WORD     			int
#define DES_BS_DEPTH                    32
#define DES_bs_vector                   ARCH_WORD

typedef unsigned ARCH_WORD vtype ;

#if no_byte_addressable(DEVICE_INFO)
#define RV7xx
#endif

#if gpu_nvidia(DEVICE_INFO)
#define _NV
#endif

#if cpu(DEVICE_INFO)
#define _CPU
#endif

#if 1
#define MAYBE_GLOBAL __global
#else
#define MAYBE_GLOBAL
#endif

typedef struct{
	union {
		unsigned char c[8][8][sizeof(DES_bs_vector)] ;
		DES_bs_vector v[8][8] ;
	} xkeys ;
} DES_bs_transfer ;

#define vxorf(a, b) 					\
	((a) ^ (b))

#define vnot(dst, a) 					\
	(dst) = ~(a)
#define vand(dst, a, b) 				\
	(dst) = (a) & (b)
#define vor(dst, a, b) 					\
	(dst) = (a) | (b)
#define vandn(dst, a, b) 				\
	(dst) = (a) & ~(b)

#if defined(_NV)||defined(_CPU)
#define vsel(dst, a, b, c) 				\
	(dst) = (((a) & ~(c)) ^ ((b) & (c)))
#else
#define vsel(dst, a, b, c) 				\
	(dst) = bitselect((a),(b),(c))
#endif

#define vshl(dst, src, shift) 				\
	(dst) = (src) << (shift)
#define vshr(dst, src, shift) 				\
	(dst) = (src) >> (shift)

#define vzero 0

#define vones (~(vtype)0)

#define vst(dst, ofs, src) 				\
	*((MAYBE_GLOBAL vtype *)((MAYBE_GLOBAL DES_bs_vector *)&(dst) + (ofs))) = (src)

#define vst_private(dst, ofs, src) 			\
	*((__private vtype *)((__private DES_bs_vector *)&(dst) + (ofs))) = (src)

#define vxor(dst, a, b) 				\
	(dst) = vxorf((a), (b))

#define vshl1(dst, src) 				\
	vshl((dst), (src), 1)

#define kvtype vtype
#define kvand vand
#define kvor vor
#define kvshl1 vshl1
#define kvshl vshl
#define kvshr vshr


#define mask01 0x01010101
#define mask02 0x02020202
#define mask04 0x04040404
#define mask08 0x08080808
#define mask10 0x10101010
#define mask20 0x20202020
#define mask40 0x40404040
#define mask80 0x80808080


#define LOAD_V 						\
	kvtype v0 = *(MAYBE_GLOBAL kvtype *)&vp[0]; 	\
	kvtype v1 = *(MAYBE_GLOBAL kvtype *)&vp[1]; 	\
	kvtype v2 = *(MAYBE_GLOBAL kvtype *)&vp[2]; 	\
	kvtype v3 = *(MAYBE_GLOBAL kvtype *)&vp[3]; 	\
	kvtype v4 = *(MAYBE_GLOBAL kvtype *)&vp[4]; 	\
	kvtype v5 = *(MAYBE_GLOBAL kvtype *)&vp[5]; 	\
	kvtype v6 = *(MAYBE_GLOBAL kvtype *)&vp[6]; 	\
	kvtype v7 = *(MAYBE_GLOBAL kvtype *)&vp[7];

#define kvand_shl1_or(dst, src, mask) 			\
	kvand(tmp, src, mask); 				\
	kvshl1(tmp, tmp); 				\
	kvor(dst, dst, tmp)

#define kvand_shl_or(dst, src, mask, shift) 		\
	kvand(tmp, src, mask); 				\
	kvshl(tmp, tmp, shift); 			\
	kvor(dst, dst, tmp)

#define kvand_shl1(dst, src, mask) 			\
	kvand(tmp, src, mask) ;				\
	kvshl1(dst, tmp)

#define kvand_or(dst, src, mask) 			\
	kvand(tmp, src, mask); 				\
	kvor(dst, dst, tmp)

#define kvand_shr_or(dst, src, mask, shift)		\
	kvand(tmp, src, mask); 				\
	kvshr(tmp, tmp, shift); 			\
	kvor(dst, dst, tmp)

#define kvand_shr(dst, src, mask, shift) 		\
	kvand(tmp, src, mask); 				\
	kvshr(dst, tmp, shift)

#define FINALIZE_NEXT_KEY_BIT_0 { 			\
	kvtype m = mask01, va, vb, tmp; 		\
	kvand(va, v0, m); 				\
	kvand_shl1(vb, v1, m); 				\
	kvand_shl_or(va, v2, m, 2); 			\
	kvand_shl_or(vb, v3, m, 3); 			\
	kvand_shl_or(va, v4, m, 4); 			\
	kvand_shl_or(vb, v5, m, 5); 			\
	kvand_shl_or(va, v6, m, 6); 			\
	kvand_shl_or(vb, v7, m, 7); 			\
	kvor(kp[0], va, vb); 				\
	kp++; 						\
}

#define FINALIZE_NEXT_KEY_BIT_1 { 			\
	kvtype m = mask02, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 1); 			\
	kvand(vb, v1, m); 				\
	kvand_shl1_or(va, v2, m); 			\
	kvand_shl_or(vb, v3, m, 2); 			\
	kvand_shl_or(va, v4, m, 3); 			\
	kvand_shl_or(vb, v5, m, 4); 			\
	kvand_shl_or(va, v6, m, 5); 			\
	kvand_shl_or(vb, v7, m, 6); 			\
	kvor(kp[0], va, vb); 				\
	kp++; 						\
}

#define FINALIZE_NEXT_KEY_BIT_2 { 			\
	kvtype m = mask04, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 2); 			\
	kvand_shr(vb, v1, m, 1); 			\
	kvand_or(va, v2, m); 				\
	kvand_shl1_or(vb, v3, m); 			\
	kvand_shl_or(va, v4, m, 2); 			\
	kvand_shl_or(vb, v5, m, 3); 			\
	kvand_shl_or(va, v6, m, 4); 			\
	kvand_shl_or(vb, v7, m, 5); 			\
	kvor(kp[0], va, vb); 				\
	kp++; 						\
}

#define FINALIZE_NEXT_KEY_BIT_3 { 			\
	kvtype m = mask08, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 3); 			\
	kvand_shr(vb, v1, m, 2); 			\
	kvand_shr_or(va, v2, m, 1); 			\
	kvand_or(vb, v3, m); 				\
	kvand_shl1_or(va, v4, m); 			\
	kvand_shl_or(vb, v5, m, 2); 			\
	kvand_shl_or(va, v6, m, 3); 			\
	kvand_shl_or(vb, v7, m, 4); 			\
	kvor(kp[0], va, vb); 				\
	kp++; 						\
}

#define FINALIZE_NEXT_KEY_BIT_4 { 			\
	kvtype m = mask10, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 4); 			\
	kvand_shr(vb, v1, m, 3); 			\
	kvand_shr_or(va, v2, m, 2); 			\
	kvand_shr_or(vb, v3, m, 1); 			\
	kvand_or(va, v4, m); 				\
	kvand_shl1_or(vb, v5, m); 			\
	kvand_shl_or(va, v6, m, 2); 			\
	kvand_shl_or(vb, v7, m, 3); 			\
	kvor(kp[0], va, vb); 				\
	kp++; 						\
}

#define FINALIZE_NEXT_KEY_BIT_5 { 			\
	kvtype m = mask20, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 5); 			\
	kvand_shr(vb, v1, m, 4); 			\
	kvand_shr_or(va, v2, m, 3); 			\
	kvand_shr_or(vb, v3, m, 2); 			\
	kvand_shr_or(va, v4, m, 1); 			\
	kvand_or(vb, v5, m); 				\
	kvand_shl1_or(va, v6, m); 			\
	kvand_shl_or(vb, v7, m, 2); 			\
	kvor(kp[0], va, vb); 				\
	kp++; 						\
}

#define FINALIZE_NEXT_KEY_BIT_6 { 			\
	kvtype m = mask40, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 6); 			\
	kvand_shr(vb, v1, m, 5); 			\
	kvand_shr_or(va, v2, m, 4); 			\
	kvand_shr_or(vb, v3, m, 3); 			\
	kvand_shr_or(va, v4, m, 2); 			\
	kvand_shr_or(vb, v5, m, 1); 			\
	kvand_or(va, v6, m); 				\
	kvand_shl1_or(vb, v7, m); 			\
	kvor(kp[0], va, vb); 				\
	kp++; 						\
}

#define FINALIZE_NEXT_KEY_BIT_7 { 			\
	kvtype m = mask80, va, vb, tmp; 		\
	kvand_shr(va, v0, m, 7); 			\
	kvand_shr(vb, v1, m, 6); 			\
	kvand_shr_or(va, v2, m, 5); 			\
	kvand_shr_or(vb, v3, m, 4); 			\
	kvand_shr_or(va, v4, m, 3); 			\
	kvand_shr_or(vb, v5, m, 2); 			\
	kvand_shr_or(va, v6, m, 1); 			\
	kvand_or(vb, v7, m); 				\
	kvor(kp[0], va, vb); 				\
	kp++;

#define GET_BIT \
	(unsigned int)*(unsigned char *)&b[0] >> idx


inline void cmp( __private unsigned DES_bs_vector *B,
	  __global int *binary,
	  int num_loaded_hash,
	  volatile __global uint *output,
	  volatile __global uint *bitmap,
	  __global DES_bs_vector *B_global,
	  int section) {

	int value[2] , mask, i, bit;

	for(i = 0; i < num_loaded_hash; i++) {

		value[0] = binary[i];
		value[1] = binary[i + num_loaded_hash];

		mask = B[0] ^ -(value[0] & 1);

		for (bit = 1; bit < 32; bit++)
			mask |= B[bit] ^ -((value[0] >> bit) & 1);

		for (; bit < 64; bit += 2) {
			mask |= B[bit] ^ -((value[1] >> (bit & 0x1F)) & 1);
			mask |= B[bit + 1] ^ -((value[1] >> ((bit + 1) & 0x1F)) & 1);
		}

		if (mask != ~(int)0) {
			if (!(atomic_or(&bitmap[i/32], (1U << (i % 32))) & (1U << (i % 32)))) {
				mask = atomic_inc(&output[0]);
				output[1 + 2 * mask] = section;
				output[2 + 2 * mask] = 0;
				for (bit = 0; bit < 64; bit++)
					B_global[mask * 64 + bit] = (DES_bs_vector)B[bit];

			}
		}
	}
}
#undef GET_BIT

inline void DES_bs_finalize_keys(unsigned int section,
				__global DES_bs_transfer *DES_bs_all,
				int local_offset_K,
				__local DES_bs_vector *K ) {

	__local DES_bs_vector *kp = (__local DES_bs_vector *)&K[local_offset_K] ;

	int ic ;
	for (ic = 0; ic < 8; ic++) {
		MAYBE_GLOBAL DES_bs_vector *vp =
		    (MAYBE_GLOBAL DES_bs_vector *)&DES_bs_all[section].xkeys.v[ic][0] ;
		LOAD_V
		FINALIZE_NEXT_KEY_BIT_0
		FINALIZE_NEXT_KEY_BIT_1
		FINALIZE_NEXT_KEY_BIT_2
		FINALIZE_NEXT_KEY_BIT_3
		FINALIZE_NEXT_KEY_BIT_4
		FINALIZE_NEXT_KEY_BIT_5
		FINALIZE_NEXT_KEY_BIT_6

	}

}

#if defined(_NV) || defined(_CPU)
#include "opencl_sboxes.h"
#else
#include "opencl_sboxes-s.h"
#endif

#define DES_bs_clear_block_8(j) 			\
	vst_private(B[j] , 0, zero); 			\
	vst_private(B[j] , 1, zero); 			\
	vst_private(B[j] , 2, zero); 			\
	vst_private(B[j] , 3, zero); 			\
	vst_private(B[j] , 4, zero); 			\
	vst_private(B[j] , 5, zero); 			\
	vst_private(B[j] , 6, zero); 			\
	vst_private(B[j] , 7, zero);

#define DES_bs_clear_block 				\
	DES_bs_clear_block_8(0); 			\
	DES_bs_clear_block_8(8); 			\
	DES_bs_clear_block_8(16); 			\
	DES_bs_clear_block_8(24); 			\
	DES_bs_clear_block_8(32); 			\
	DES_bs_clear_block_8(40); 			\
	DES_bs_clear_block_8(48); 			\
	DES_bs_clear_block_8(56);

#define H1_s()\
	s1(z(index00, 0), z(index01, 1), z(index02, 2), z(index03, 3), z(index04, 4), z(index05, 5),\
		B,40, 48, 54, 62);\
	s2(z(index06, 6), z(index07, 7), z(index08, 8), z(index09, 9), z(index10, 10), z(index11, 11),\
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

#if  (HARDCODE_SALT && !FULL_UNROLL)

#define y48(p, q) vxorf(B[p]     , _local_K[q + local_offset_K])

#ifndef RV7xx
#define z(p, q) vxorf(B[p]      , _local_K[*_index768_ptr++ + local_offset_K])
#else
#define z(p, q) vxorf(B[p]      , _local_K[index768[q + k] + local_offset_K])
#endif

__kernel void DES_bs_25( constant uint *index768
#if gpu_amd(DEVICE_INFO)
                         __attribute__((max_constant_size(3072)))
#endif
                         , __global DES_bs_transfer *DES_bs_all,
                         __global DES_bs_vector *B_global,
                         __global int *binary,
                         int num_loaded_hashes,
                         volatile __global uint *hash_ids,
			 volatile __global uint *bitmap) {

		unsigned int section = get_global_id(0), local_offset_K;
		unsigned int local_id = get_local_id(0);

		local_offset_K  = 56 * local_id;

		vtype B[64];

		__local DES_bs_vector _local_K[56 * WORK_GROUP_SIZE] ;
#ifndef RV7xx
		__local ushort _local_index768[768] ;
		__local ushort *_index768_ptr ;
#endif
		int iterations;

#ifndef SAFE_GOTO
		int rounds_and_swapped;
#else
		vtype tmp;
#endif

		long int k = 0, i;

		DES_bs_finalize_keys(section, DES_bs_all, local_offset_K, _local_K);

		{
			vtype zero = vzero;
			DES_bs_clear_block
		}

		if(!section) {
			hash_ids[0] = 0;
			for (i = 0; i < (num_loaded_hashes - 1)/32 + 1; i++)
				bitmap[i] = 0;
		}
		barrier(CLK_GLOBAL_MEM_FENCE);

		k = 0;
#ifndef SAFE_GOTO
		rounds_and_swapped = 8;
#endif
		iterations = 25;

#ifndef RV7xx
		if (!local_id )
			for (i = 0; i < 768; i++)
				_local_index768[i] = index768[i];
		barrier(CLK_LOCAL_MEM_FENCE);
#endif
#ifdef SAFE_GOTO
		for (iterations = 24; iterations >= 0; iterations--) {
			for (k = 0; k < 768; k += 96) {
#ifndef RV7xx
				_index768_ptr = _local_index768 + k ;
#endif
				H1_s();
				H2_s();
			}
			for (i = 0; i < 32 && iterations; i++) {
				tmp = B[i];
				B[i] = B[i + 32];
				B[i + 32] = tmp;
			}
		}
#else
start:
#ifndef RV7xx
		_index768_ptr = _local_index768 + k ;
#endif
		H1_s();
		if (rounds_and_swapped == 0x100) goto next;
		H2_s();
		k += 96;
		rounds_and_swapped--;

		if (rounds_and_swapped > 0) goto start;
		k -= (0x300 + 48);
		rounds_and_swapped = 0x108;
		if (--iterations) goto swap;
#endif
		cmp(B, binary, num_loaded_hashes, hash_ids, bitmap, B_global, section);

		return;
#ifndef SAFE_GOTO
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
#endif
