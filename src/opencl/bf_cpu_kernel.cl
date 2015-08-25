/*
 * This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Solar Designer implementation of bf_std.c in jtr-v1.7.8
 */
#include "opencl_device_info.h"

#define BF_ROUNDS          	16

#define pos_S(row, col, base)						\
	base + (row * 256 + col)

#define pos_P(i , base)							\
        base + i

#define pos_S_local(row, col)						\
	(row << 8) + col

#define BF_ROUNDx(ctx_S, ctx_P, L, R, N, tmp1, tmp2, tmp3, tmp4) 	\
	tmp1 = L & 0xff ; 						\
	tmp1 = Sptr4[tmp1].x ;						\
	tmp2 = L >> 8 ; 						\
        tmp3 = tmp2 >> 8 ;						\
	tmp4 = tmp3 >> 8 ;   						\
        tmp2 = tmp2 & 0xff ; 						\
        tmp2 = Sptr3[tmp2].x ; 						\
	tmp3 = tmp3 & 0xff ; 						\
	tmp4 = tmp4 & 0xff ; 						\
	tmp3 = Sptr2[tmp3].x + Sptr[tmp4].x ; 				\
        tmp3 ^= tmp2 ; 							\
	R = R ^ ctx_P[N + 1].x ; 					\
	tmp3 = tmp3 + tmp1 ;  						\
	R = R ^ tmp3 ;

#define BF_ENCRYPTx(ctx_S, ctx_P, L, R) 				\
	L ^= ctx_P[0].x ; 						\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 0, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 1, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 2, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 3, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 4, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 5, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 6, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 7, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 8, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 9, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 10, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 11, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 12, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 13, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, L, R, 14, u1, u2, u3, u4) ; 		\
	BF_ROUNDx(ctx_S, ctx_P, R, L, 15, u1, u2, u3, u4) ; 		\
	u4 = R ; 							\
	R = L ; 							\
	L = u4 ^ ctx_P[BF_ROUNDS + 1].x ;

#define BF_ROUNDy(ctx_S, ctx_P, L, R, N, tmp1, tmp2, tmp3, tmp4 ) 	\
	tmp1 = L & 0xff ; 						\
	tmp1 = Sptr4[tmp1].y ;						\
	tmp2 = L >> 8 ; 						\
        tmp3 = tmp2 >> 8 ;						\
	tmp4 = tmp3>>8 ;						\
        tmp2 = tmp2 & 0xff ; 						\
        tmp2 = Sptr3[tmp2].y ; 						\
	tmp3 = tmp3 & 0xff ;						\
	tmp4 = tmp4 & 0xff ;						\
	tmp3 = Sptr2[tmp3].y + Sptr[tmp4].y ;				\
        tmp3 ^= tmp2 ;							\
	R = R ^ ctx_P[N + 1].y ;					\
	tmp3 = tmp3 + tmp1 ; 						\
	R = R ^ tmp3 ;

#define BF_ENCRYPTy(ctx_S, ctx_P, L, R)					\
	L ^= ctx_P[0].y ;						\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 0, u1, u2, u3, u4) ;		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 1, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 2, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 3, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 4, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 5, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 6, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 7, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 8, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 9, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 10, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 11, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 12, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 13, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, L, R, 14, u1, u2, u3, u4) ; 		\
	BF_ROUNDy(ctx_S, ctx_P, R, L, 15, u1, u2, u3, u4) ; 		\
	u4 = R ; 							\
	R = L ; 							\
	L = u4 ^ ctx_P[BF_ROUNDS + 1].y ;

#define BF_ROUND(ctx_S, ctx_P, L, R, N, tmp1, tmp2, tmp3, tmp4 ) 	\
	tmp1.x = L.x & 0xff ; 						\
	tmp1.y = L.y & 0xff ; 						\
	tmp1.x = Sptr4[tmp1.x].x ;					\
	tmp1.y = Sptr4[tmp1.y].y ;					\
	tmp2.x =  L.x >> 8 ; 						\
	tmp2.y =  L.y >> 8 ; 						\
        tmp3.x =  tmp2.x >> 8 ;						\
        tmp3.y =  tmp2.y >> 8 ;						\
	tmp4.x =  tmp3.x >> 8 ; 					\
	tmp4.y =  tmp3.y >> 8 ; 					\
	tmp2.x =  tmp2.x & 0xff ; 					\
        tmp2.y =  tmp2.y & 0xff ; 					\
        tmp2.x = Sptr3[tmp2.x].x ; 					\
        tmp2.y = Sptr3[tmp2.y].y ; 					\
	tmp3.x = tmp3.x & 0xff ; 					\
	tmp3.y = tmp3.y & 0xff ; 					\
	tmp4.x = tmp4.x & 0xff ; 					\
	tmp4.y = tmp4.y & 0xff ; 					\
	tmp3.x = Sptr2[tmp3.x].x+ Sptr[tmp4.x].x ; 			\
	tmp3.y = Sptr2[tmp3.y].y+ Sptr[tmp4.y].y ; 			\
        tmp3.x ^= tmp2.x ; 						\
        tmp3.y ^= tmp2.y ; 						\
	R.x = R.x ^ ctx_P[N + 1].x ; 					\
	R.y = R.y ^ ctx_P[N + 1].y ; 					\
	tmp3.x = tmp3.x + tmp1.x ; 					\
	tmp3.y = tmp3.y + tmp1.y ; 					\
	R.x = R.x ^ tmp3.x ; 						\
	R.y = R.y ^ tmp3.y ;

#define BF_ENCRYPT(ctx_S, ctx_P, L, R) 					\
	L.x ^= ctx_P[0].x ; 						\
	L.y ^= ctx_P[0].y ; 						\
	BF_ROUND(ctx_S, ctx_P, L, R, 0, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 1, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 2, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 3, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 4, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 5, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 6, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 7, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 8, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 9, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 10, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 11, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 12, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 13, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, L, R, 14, u01, u02, u03, u04) ; 		\
	BF_ROUND(ctx_S, ctx_P, R, L, 15, u01, u02, u03, u04) ; 		\
	u04.x = R.x ; 							\
	u04.y = R.y ; 							\
	R.x = L.x ; 							\
	R.y = L.y ; 							\
	L.x = u04.x ^ ctx_P[BF_ROUNDS + 1].x ; 				\
	L.y = u04.y ^ ctx_P[BF_ROUNDS + 1].y ;

#define BF_body(ctx_P) 							\
	L00.x = R00.x = L00.y = R00.y = 0; 				\
	for (i = 0; i < 18; i = i + 2) {				\
	BF_ENCRYPTx(Sptr, ctx_P, L00.x, R00.x) ;			\
	BF_ENCRYPTy(Sptr, ctx_P, L00.y, R00.y) ;			\
	BF_current_P[i].x = L00.x ;					\
	BF_current_P[i].y = L00.y ;					\
	BF_current_P[i + 1].x = R00.x ;					\
	BF_current_P[i + 1].y = R00.y ;					\
	}								\
									\
	for (i = 0; i < 1024; i += 8) {					\
	      BF_ENCRYPTx(Sptr, ctx_P, L00.x, R00.x) ;			\
	      BF_ENCRYPTy(Sptr, ctx_P, L00.y, R00.y) ;			\
	      Sptr[i] = L00 ;						\
	      Sptr[i + 1] = R00 ;					\
	      BF_ENCRYPTx(Sptr, ctx_P, L00.x, R00.x) ;			\
	      BF_ENCRYPTy(Sptr, ctx_P, L00.y, R00.y) ;			\
	      Sptr[i + 2] = L00 ;					\
	      Sptr[i + 3] = R00 ;					\
	      BF_ENCRYPTx(Sptr, ctx_P, L00.x, R00.x) ;			\
	      BF_ENCRYPTy(Sptr, ctx_P, L00.y, R00.y) ;			\
	      Sptr[i + 4] = L00 ;					\
	      Sptr[i + 5] = R00 ;					\
	      BF_ENCRYPTx(Sptr, ctx_P, L00.x, R00.x) ;			\
	      BF_ENCRYPTy(Sptr, ctx_P, L00.y, R00.y) ;			\
	      Sptr[i + 6] = L00 ;					\
	      Sptr[i + 7] = R00 ;					\
	     }

__kernel void blowfish(	constant uint *salt
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
	__attribute__((max_constant_size(16)))
#endif
	, constant uint *P_box
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
	__attribute__((max_constant_size(72)))
#endif
	, __global uint *BF_out,
	__global uint *BF_current_S,
	__global uint *BF_current_P_global,
	uint rounds,
	constant uint *S_box
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
	__attribute__((max_constant_size(4096)))
#endif
	)
{
		int index = 2 * get_global_id(0);

		int _index_S1,_index_S2 ;
		int _index_P1,_index_P2 ;

		_index_S1 = index * 1024 ;
		_index_P1 = index * 18 ;

		_index_S2 = (index + 1) * 1024 ;
		_index_P2 = 18 * (index+1) ;

		int i,j ;
		uint2 tmp0 ;
		uint2 BF_key_exp[18] ;
		uint2 BF_current_P[18] ;

		 uint2 S_Buffer[1024] ;
		 uint2 *Sptr = S_Buffer ;
		 uint2 *Sptr2 = Sptr + 256 ;
		 uint2 *Sptr3 = Sptr + 512 ;
		 uint2 *Sptr4 = Sptr + 768 ;

		for (i = 0; i < 18; i++) {
			tmp0.x          = BF_current_P_global [pos_P(i , _index_P1)] ;
			tmp0.y          = BF_current_P_global [pos_P(i , _index_P2)] ;
			BF_current_P[i] = tmp0 ;
			BF_key_exp[i]   = tmp0 ^ P_box[i] ;
	        }

	  	for (i = 0; i < 1024; i++) {
			j = i >> 8 ;
			S_Buffer[pos_S_local(j, (i & 0xff))] = S_box[i] ;
		}

		uint u1, u2, u3, u4 ;

		uint2 L00, R00 ;
		uint2 u01, u02, u03, u04 ;

		uint count ;

		L00.x = R00.x = L00.y =  R00.y = 0 ;
		for (i = 0; i < (BF_ROUNDS + 2); i += 2) {
			L00 ^= salt[i & 2] ;
			R00 ^= salt[(i & 2) + 1] ;
			BF_ENCRYPTx(Sptr, BF_current_P, L00.x, R00.x) ;
			BF_ENCRYPTy(Sptr, BF_current_P, L00.y, R00.y) ;
			BF_current_P[i] = L00 ;
			BF_current_P[i + 1] = R00 ;
		}

		for (i = 0; i < 1023 ;i = i + 4) {
			j = i >> 8  ;
			L00 ^= salt[(BF_ROUNDS + 2) & 3] ;
			R00 ^= salt[(BF_ROUNDS + 3) & 3] ;
			BF_ENCRYPTx(Sptr, BF_current_P, L00.x, R00.x) ;
			BF_ENCRYPTy(Sptr, BF_current_P, L00.y, R00.y) ;
			S_Buffer[pos_S_local(j, (i & 0xff))] = L00 ;
			S_Buffer[pos_S_local(j, ((i + 1) & 0xff))] = R00 ;
			L00 ^= salt[(BF_ROUNDS + 4) & 3] ;
			R00 ^= salt[(BF_ROUNDS + 5) & 3] ;
			BF_ENCRYPTy(Sptr, BF_current_P, L00.y, R00.y) ;
			BF_ENCRYPTx(Sptr, BF_current_P, L00.x, R00.x) ;
			S_Buffer[pos_S_local(j, ((i + 2) & 0xff))] = L00 ;
			S_Buffer[pos_S_local(j, ((i + 3) & 0xff))] = R00 ;

		}

		count = 1 << rounds ;

		do {
			BF_current_P[0] ^= BF_key_exp[0] ;
			BF_current_P[1] ^= BF_key_exp[1] ;
			BF_current_P[2] ^= BF_key_exp[2] ;
			BF_current_P[3] ^= BF_key_exp[3] ;
			BF_current_P[4] ^= BF_key_exp[4] ;
			BF_current_P[5] ^= BF_key_exp[5] ;
			BF_current_P[6] ^= BF_key_exp[6] ;
			BF_current_P[7] ^= BF_key_exp[7] ;
			BF_current_P[8] ^= BF_key_exp[8] ;
			BF_current_P[9] ^= BF_key_exp[9] ;
			BF_current_P[10] ^= BF_key_exp[10] ;
			BF_current_P[11] ^= BF_key_exp[11] ;
			BF_current_P[12] ^= BF_key_exp[12] ;
			BF_current_P[13] ^= BF_key_exp[13] ;
			BF_current_P[14] ^= BF_key_exp[14] ;
			BF_current_P[15] ^= BF_key_exp[15] ;
			BF_current_P[16] ^= BF_key_exp[16] ;
			BF_current_P[17] ^= BF_key_exp[17] ;

			BF_body(BF_current_P) ;

			u01 = salt[0] ;
			u02 = salt[1] ;
			u03 = salt[2] ;
			u04 = salt[3] ;

			BF_current_P[0] ^= u01 ;
			BF_current_P[1] ^= u02 ;
			BF_current_P[2] ^= u03 ;
			BF_current_P[3] ^= u04 ;
			BF_current_P[4] ^= u01 ;
			BF_current_P[5] ^= u02 ;
			BF_current_P[6] ^= u03 ;
			BF_current_P[7] ^= u04 ;
			BF_current_P[8] ^= u01 ;
			BF_current_P[9] ^= u02 ;
			BF_current_P[10] ^= u03 ;
			BF_current_P[11] ^= u04 ;
			BF_current_P[12] ^= u01 ;
			BF_current_P[13] ^= u02 ;
			BF_current_P[14] ^= u03 ;
			BF_current_P[15] ^= u04 ;
			BF_current_P[16] ^= u01 ;
			BF_current_P[17] ^= u02 ;

			BF_body(BF_current_P) ;

		} while (--count);


		L00 = 0x4F727068 ;
		R00 = 0x65616E42 ;

		count = 64 ;

		do {
			BF_ENCRYPTx(Sptr, BF_current_P, L00.x, R00.x) ;
			BF_ENCRYPTy(Sptr, BF_current_P, L00.y, R00.y) ;
		} while (--count) ;

		BF_out[2 * index] = L00.x ;
		BF_out[2 * index + 1] = R00.x ;

		BF_out[2 * (index + 1)] = L00.y;
		BF_out[2 * (index + 1) + 1] = R00.y;

		for (i = 0; i < 18; i++) {

			BF_current_P_global [pos_P(i, _index_P1)] = BF_current_P[i].x ;
			BF_current_P_global [pos_P(i, _index_P2)] = BF_current_P[i].y ;
		}

		for (i = 0; i < 1024; i++) {
			j = i >> 8 ;
			BF_current_S[pos_S(j, (i & 0xff), _index_S1)] = S_Buffer[pos_S_local(j, (i & 0xff))].x ;
			BF_current_S[pos_S(j, (i & 0xff), _index_S2)] = S_Buffer[pos_S_local(j, (i & 0xff))].y ;
		}

}
