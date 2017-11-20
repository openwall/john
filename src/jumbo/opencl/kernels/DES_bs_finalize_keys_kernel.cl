/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */
#include "opencl_DES_kernel_params.h"
#include "opencl_mask.h"

#if 1
#define MAYBE_GLOBAL __global
#else
#define MAYBE_GLOBAL
#endif

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

#define LOAD_V 						\
	kvtype v0 = *(MAYBE_GLOBAL kvtype *)&vp[0]; 	\
	kvtype v1 = *(MAYBE_GLOBAL kvtype *)&vp[1]; 	\
	kvtype v2 = *(MAYBE_GLOBAL kvtype *)&vp[2]; 	\
	kvtype v3 = *(MAYBE_GLOBAL kvtype *)&vp[3]; 	\
	kvtype v4 = *(MAYBE_GLOBAL kvtype *)&vp[4]; 	\
	kvtype v5 = *(MAYBE_GLOBAL kvtype *)&vp[5]; 	\
	kvtype v6 = *(MAYBE_GLOBAL kvtype *)&vp[6]; 	\
	kvtype v7 = *(MAYBE_GLOBAL kvtype *)&vp[7];

#define FINALIZE_NEXT_KEY_BIT_0g { 			\
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
	kp += (gws * ITER_COUNT);			\
}

#define FINALIZE_NEXT_KEY_BIT_1g { 			\
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
	kp += (gws * ITER_COUNT);			\
}

#define FINALIZE_NEXT_KEY_BIT_2g { 			\
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
	kp += (gws * ITER_COUNT);			\
}

#define FINALIZE_NEXT_KEY_BIT_3g { 			\
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
	kp += (gws * ITER_COUNT);			\
}

#define FINALIZE_NEXT_KEY_BIT_4g { 			\
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
	kp += (gws * ITER_COUNT);			\
}

#define FINALIZE_NEXT_KEY_BIT_5g { 			\
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
	kp += (gws * ITER_COUNT);			\
}

#define FINALIZE_NEXT_KEY_BIT_6g { 			\
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
	kp += (gws * ITER_COUNT); 			\
}

#define FINALIZE_NEXT_KEY_BIT_7g { 			\
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
	kp += (gws * ITER_COUNT);			\
}

#if LOC_3 >= 0
#define ACTIVE_PLACEHOLDER	4
#elif LOC_2 >= 0
#define ACTIVE_PLACEHOLDER	3
#elif LOC_1 >= 0
#define ACTIVE_PLACEHOLDER	2
#elif LOC_0 >= 0
#define ACTIVE_PLACEHOLDER	1
#else
#define ACTIVE_PLACEHOLDER	0
#endif

#if (CONST_CACHE_SIZE >= ACTIVE_PLACEHOLDER * 32 * ITER_COUNT) && ACTIVE_PLACEHOLDER
#define USE_CONST_CACHED_INT_KEYS	1
#else
#define USE_CONST_CACHED_INT_KEYS	0
#endif

__kernel void DES_bs_finalize_keys(__global opencl_DES_bs_transfer *des_raw_keys,
#if USE_CONST_CACHED_INT_KEYS
				   constant
#else
				   __global
#endif
				   unsigned int *des_int_keys
#if !defined(__OS_X__) && USE_CONST_CACHED_INT_KEYS && gpu_amd(DEVICE_INFO)
				   __attribute__((max_constant_size((ACTIVE_PLACEHOLDER * 32 * ITER_COUNT))))
#endif
				   , __global unsigned int *des_int_key_loc,
				   __global DES_bs_vector *des_bs_keys) {

	int section = get_global_id(0);
	int gws = get_global_size(0);
	__global DES_bs_vector *kp = (__global DES_bs_vector *)&des_bs_keys[section];

	int ic ;
	for (ic = 0; ic < 8; ic++) {
		MAYBE_GLOBAL DES_bs_vector *vp =
		    (MAYBE_GLOBAL DES_bs_vector *)&des_raw_keys[section].xkeys.v[ic][0];
		LOAD_V
		FINALIZE_NEXT_KEY_BIT_0g
		FINALIZE_NEXT_KEY_BIT_1g
		FINALIZE_NEXT_KEY_BIT_2g
		FINALIZE_NEXT_KEY_BIT_3g
		FINALIZE_NEXT_KEY_BIT_4g
		FINALIZE_NEXT_KEY_BIT_5g
		FINALIZE_NEXT_KEY_BIT_6g
	}

#if MASK_ENABLED && !IS_STATIC_GPU_MASK
	uint ikl = des_int_key_loc[section];
	uint loc0 = (ikl & 0xff) * 7;
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
	uint loc1 = ((ikl & 0xff00) >> 8) * 7;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
	uint loc2 = ((ikl & 0xff0000) >> 16) * 7;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
	uint loc3 = ((ikl & 0xff000000) >> 24) * 7;
#endif
#endif
#endif

#if !IS_STATIC_GPU_MASK
#define GPU_LOC_0 loc0
#define GPU_LOC_1 loc1
#define GPU_LOC_2 loc2
#define GPU_LOC_3 loc3
#else
#define GPU_LOC_0 (LOC_0 * 7)
#define GPU_LOC_1 (LOC_1 * 7)
#define GPU_LOC_2 (LOC_2 * 7)
#define GPU_LOC_3 (LOC_3 * 7)
#endif

#if MASK_ENABLED
	int i;
	for (i = 0; i < 56; i++)
	for (ic = 1; ic < ITER_COUNT; ic++) {
		des_bs_keys[i * ITER_COUNT * gws + ic * gws + section] = des_bs_keys[i * ITER_COUNT * gws + section];
	}

	for (ic = 0; ic < ITER_COUNT; ic++) {
		des_bs_keys[GPU_LOC_0 * ITER_COUNT * gws + ic * gws + section] = des_int_keys[ic * 7];
		des_bs_keys[(GPU_LOC_0 + 1) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[ic * 7 + 1];
		des_bs_keys[(GPU_LOC_0 + 2) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[ic * 7 + 2];
		des_bs_keys[(GPU_LOC_0 + 3) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[ic * 7 + 3];
		des_bs_keys[(GPU_LOC_0 + 4) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[ic * 7 + 4];
		des_bs_keys[(GPU_LOC_0 + 5) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[ic * 7 + 5];
		des_bs_keys[(GPU_LOC_0 + 6) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[ic * 7 + 6];

#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
#define OFFSET 	(1 * ITER_COUNT * 7)
		des_bs_keys[GPU_LOC_1 * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7];
		des_bs_keys[(GPU_LOC_1 + 1) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 1];
		des_bs_keys[(GPU_LOC_1 + 2) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 2];
		des_bs_keys[(GPU_LOC_1 + 3) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 3];
		des_bs_keys[(GPU_LOC_1 + 4) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 4];
		des_bs_keys[(GPU_LOC_1 + 5) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 5];
		des_bs_keys[(GPU_LOC_1 + 6) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 6];
#endif
#endif

#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
#undef OFFSET
#define OFFSET 	(2 * ITER_COUNT * 7)
		des_bs_keys[GPU_LOC_2 * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7];
		des_bs_keys[(GPU_LOC_2 + 1) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 1];
		des_bs_keys[(GPU_LOC_2 + 2) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 2];
		des_bs_keys[(GPU_LOC_2 + 3) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 3];
		des_bs_keys[(GPU_LOC_2 + 4) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 4];
		des_bs_keys[(GPU_LOC_2 + 5) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 5];
		des_bs_keys[(GPU_LOC_2 + 6) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 6];
#endif
#endif

#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
#undef OFFSET
#define OFFSET 	(3 * ITER_COUNT * 7)
		des_bs_keys[GPU_LOC_3 * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7];
		des_bs_keys[(GPU_LOC_3 + 1) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 1];
		des_bs_keys[(GPU_LOC_3 + 2) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 2];
		des_bs_keys[(GPU_LOC_3 + 3) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 3];
		des_bs_keys[(GPU_LOC_3 + 4) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 4];
		des_bs_keys[(GPU_LOC_3 + 5) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 5];
		des_bs_keys[(GPU_LOC_3 + 6) * ITER_COUNT * gws + ic * gws + section] = des_int_keys[OFFSET + ic * 7 + 6];
#endif
#endif
	}
#endif
}
