/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9 
 */
 
#include "opencl_DES_WGS.h"
#include "opencl_device_info.h"
 
 
#define ARCH_WORD     			int
#define DES_BS_DEPTH                    32
#define DES_bs_vector                   ARCH_WORD

typedef unsigned ARCH_WORD vtype;

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
		unsigned char c[8][8][sizeof(DES_bs_vector)];
		DES_bs_vector v[8][8];
	} xkeys;
		
	int keys_changed;
} DES_bs_transfer ;

#define vxorf(a, b) \
	((a) ^ (b))

#define vnot(dst, a) \
	(dst) = ~(a)
#define vand(dst, a, b) \
	(dst) = (a) & (b)
#define vor(dst, a, b) \
	(dst) = (a) | (b)
#define vandn(dst, a, b) \
	(dst) = (a) & ~(b)

#if defined(_NV)||defined(_CPU)	
#define vsel(dst, a, b, c) \
	(dst) = (((a) & ~(c)) ^ ((b) & (c)))
#else
#define vsel(dst, a, b, c) \
	(dst) = bitselect((a),(b),(c))
#endif	

#define vshl(dst, src, shift) \
	(dst) = (src) << (shift)
#define vshr(dst, src, shift) \
	(dst) = (src) >> (shift)

#define vzero 0

#define vones (~(vtype)0)

#define vst(dst, ofs, src) \
	*((MAYBE_GLOBAL vtype *)((MAYBE_GLOBAL DES_bs_vector *)&(dst) + (ofs))) = (src)
	
#define vst_private(dst, ofs, src) \
	*((__private vtype *)((__private DES_bs_vector *)&(dst) + (ofs))) = (src)	

#define vxor(dst, a, b) \
	(dst) = vxorf((a), (b))

#define vshl1(dst, src) \
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


#define LOAD_V \
	kvtype v0 = *(MAYBE_GLOBAL kvtype *)&vp[0]; \
	kvtype v1 = *(MAYBE_GLOBAL kvtype *)&vp[1]; \
	kvtype v2 = *(MAYBE_GLOBAL kvtype *)&vp[2]; \
	kvtype v3 = *(MAYBE_GLOBAL kvtype *)&vp[3]; \
	kvtype v4 = *(MAYBE_GLOBAL kvtype *)&vp[4]; \
	kvtype v5 = *(MAYBE_GLOBAL kvtype *)&vp[5]; \
	kvtype v6 = *(MAYBE_GLOBAL kvtype *)&vp[6]; \
	kvtype v7 = *(MAYBE_GLOBAL kvtype *)&vp[7];

#define kvand_shl1_or(dst, src, mask) \
	kvand(tmp, src, mask); \
	kvshl1(tmp, tmp); \
	kvor(dst, dst, tmp)

#define kvand_shl_or(dst, src, mask, shift) \
	kvand(tmp, src, mask); \
	kvshl(tmp, tmp, shift); \
	kvor(dst, dst, tmp)

#define kvand_shl1(dst, src, mask) \
	kvand(tmp, src, mask); \
	kvshl1(dst, tmp)

#define kvand_or(dst, src, mask) \
	kvand(tmp, src, mask); \
	kvor(dst, dst, tmp)

#define kvand_shr_or(dst, src, mask, shift) \
	kvand(tmp, src, mask); \
	kvshr(tmp, tmp, shift); \
	kvor(dst, dst, tmp)

#define kvand_shr(dst, src, mask, shift) \
	kvand(tmp, src, mask); \
	kvshr(dst, tmp, shift)

#define FINALIZE_NEXT_KEY_BIT_0 { \
	kvtype m = mask01, va, vb, tmp; \
	kvand(va, v0, m); \
	kvand_shl1(vb, v1, m); \
	kvand_shl_or(va, v2, m, 2); \
	kvand_shl_or(vb, v3, m, 3); \
	kvand_shl_or(va, v4, m, 4); \
	kvand_shl_or(vb, v5, m, 5); \
	kvand_shl_or(va, v6, m, 6); \
	kvand_shl_or(vb, v7, m, 7); \
	kvor(kp[0], va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_1 { \
	kvtype m = mask02, va, vb, tmp; \
	kvand_shr(va, v0, m, 1); \
	kvand(vb, v1, m); \
	kvand_shl1_or(va, v2, m); \
	kvand_shl_or(vb, v3, m, 2); \
	kvand_shl_or(va, v4, m, 3); \
	kvand_shl_or(vb, v5, m, 4); \
	kvand_shl_or(va, v6, m, 5); \
	kvand_shl_or(vb, v7, m, 6); \
	kvor(kp[0], va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_2 { \
	kvtype m = mask04, va, vb, tmp; \
	kvand_shr(va, v0, m, 2); \
	kvand_shr(vb, v1, m, 1); \
	kvand_or(va, v2, m); \
	kvand_shl1_or(vb, v3, m); \
	kvand_shl_or(va, v4, m, 2); \
	kvand_shl_or(vb, v5, m, 3); \
	kvand_shl_or(va, v6, m, 4); \
	kvand_shl_or(vb, v7, m, 5); \
	kvor(kp[0], va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_3 { \
	kvtype m = mask08, va, vb, tmp; \
	kvand_shr(va, v0, m, 3); \
	kvand_shr(vb, v1, m, 2); \
	kvand_shr_or(va, v2, m, 1); \
	kvand_or(vb, v3, m); \
	kvand_shl1_or(va, v4, m); \
	kvand_shl_or(vb, v5, m, 2); \
	kvand_shl_or(va, v6, m, 3); \
	kvand_shl_or(vb, v7, m, 4); \
	kvor(kp[0], va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_4 { \
	kvtype m = mask10, va, vb, tmp; \
	kvand_shr(va, v0, m, 4); \
	kvand_shr(vb, v1, m, 3); \
	kvand_shr_or(va, v2, m, 2); \
	kvand_shr_or(vb, v3, m, 1); \
	kvand_or(va, v4, m); \
	kvand_shl1_or(vb, v5, m); \
	kvand_shl_or(va, v6, m, 2); \
	kvand_shl_or(vb, v7, m, 3); \
	kvor(kp[0], va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_5 { \
	kvtype m = mask20, va, vb, tmp; \
	kvand_shr(va, v0, m, 5); \
	kvand_shr(vb, v1, m, 4); \
	kvand_shr_or(va, v2, m, 3); \
	kvand_shr_or(vb, v3, m, 2); \
	kvand_shr_or(va, v4, m, 1); \
	kvand_or(vb, v5, m); \
	kvand_shl1_or(va, v6, m); \
	kvand_shl_or(vb, v7, m, 2); \
	kvor(kp[0], va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_6 { \
	kvtype m = mask40, va, vb, tmp; \
	kvand_shr(va, v0, m, 6); \
	kvand_shr(vb, v1, m, 5); \
	kvand_shr_or(va, v2, m, 4); \
	kvand_shr_or(vb, v3, m, 3); \
	kvand_shr_or(va, v4, m, 2); \
	kvand_shr_or(vb, v5, m, 1); \
	kvand_or(va, v6, m); \
	kvand_shl1_or(vb, v7, m); \
	kvor(kp[0], va, vb); \
	kp++; \
}

#define FINALIZE_NEXT_KEY_BIT_7 { \
	kvtype m = mask80, va, vb, tmp; \
	kvand_shr(va, v0, m, 7); \
	kvand_shr(vb, v1, m, 6); \
	kvand_shr_or(va, v2, m, 5); \
	kvand_shr_or(vb, v3, m, 4); \
	kvand_shr_or(va, v4, m, 3); \
	kvand_shr_or(vb, v5, m, 2); \
	kvand_shr_or(va, v6, m, 1); \
	kvand_or(vb, v7, m); \
	kvor(kp[0], va, vb); \
	kp++; \

inline void DES_bs_finalize_keys( unsigned int section,
				  __global DES_bs_transfer *DES_bs_all,
				  int local_offset_K, 
				  __local DES_bs_vector *K )

{ 
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

#if defined(_NV)||defined(_CPU)
#include "opencl_sboxes.h"
#else
#include "opencl_sboxes-s.h"
#endif

#define DES_bs_clear_block_8(j) \
		vst_private(B[j] , 0, zero); \
		vst_private(B[j] , 1, zero); \
		vst_private(B[j] , 2, zero); \
		vst_private(B[j] , 3, zero); \
		vst_private(B[j] , 4, zero); \
		vst_private(B[j] , 5, zero); \
		vst_private(B[j] , 6, zero); \
		vst_private(B[j] , 7, zero); 

#define DES_bs_clear_block \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56);

#ifndef RV7xx 	
#define x(p) vxorf(B[index96[p] ], _local_K[_local_index768[p+k] + local_offset_K])
#define y(p, q) vxorf(B[p]       , _local_K[_local_index768[q+k] + local_offset_K])
#else
#define x(p) vxorf(B[index96[p] ], _local_K[index768[p+k] + local_offset_K])
#define y(p, q) vxorf(B[p]       , _local_K[index768[q+k] + local_offset_K])
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
		k +=96;\
		rounds_and_swapped--;\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k +=96;\
		rounds_and_swapped--;\
                barrier(CLK_LOCAL_MEM_FENCE);
#elif defined(_NV)
#define loop_body()\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k +=96;\
		rounds_and_swapped--;\
		barrier(CLK_LOCAL_MEM_FENCE);
#else
#define loop_body()\
		H1();\
		if (rounds_and_swapped == 0x100) goto next;\
		H2();\
		k +=96;\
		rounds_and_swapped--;
#endif
			

 __kernel void DES_bs_25( constant uint *index768 __attribute__((max_constant_size(3072))), 
			  __global int *index96 ,
			  __global DES_bs_transfer *DES_bs_all,
			  __global DES_bs_vector *B_global )
 {
		unsigned int section = get_global_id(0), global_offset_B ,local_offset_K;
		unsigned int local_id = get_local_id(0); 
		 
		global_offset_B = 64*section;
		local_offset_K  = 56*local_id;
		
		vtype B[64]; 
				
		__local DES_bs_vector _local_K[56*WORK_GROUP_SIZE] ;
#ifndef RV7xx
		__local ushort _local_index768[768] ;
#endif		
		int iterations, rounds_and_swapped;
		
		long int k=0,i;
					
		if (DES_bs_all[section].keys_changed)
			goto finalize_keys;
				
body:		
		{
			vtype zero = vzero;
			DES_bs_clear_block
		}
		
		k=0;
		rounds_and_swapped = 8;
		iterations = 25;

#ifndef RV7xx		
		if(!local_id )
			for(i=0;i<768;i++)
				_local_index768[i] = index768[i];
		
		barrier(CLK_LOCAL_MEM_FENCE);
#endif

start:
		loop_body();

		if (rounds_and_swapped>0) goto start;
		k -= (0x300 + 48);
		rounds_and_swapped = 0x108;
		if (--iterations) goto swap;
		
		for(i=0;i<64; i++)
			B_global[global_offset_B +i] = (DES_bs_vector)B[i] ;
			
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

finalize_keys:
		DES_bs_all[section].keys_changed = 0;

	        DES_bs_finalize_keys(section,DES_bs_all,local_offset_K,_local_K);

		goto body;	

 }
