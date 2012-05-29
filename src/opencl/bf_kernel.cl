/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on Solar Designer implementation of bf_std.c in jtr-v1.7.8 
*/
#define BF_ROUNDS 16

#define WAVEFRONT_SIZE  64

#define NUM_CHANNELS    13

#define OFFSET 0

#define CHANNEL_INTERLEAVE WAVEFRONT_SIZE*NUM_CHANNELS

#define pos_S(row,col)\
	_index_S + (row*256+col)*(CHANNEL_INTERLEAVE) 

#define pos_P(i)\
	_index_P + i*(CHANNEL_INTERLEAVE) 

#define BF_ROUND(ctx_S,ctx_P, L, R, N, tmp1, tmp2, tmp3, tmp4) \
	tmp1 = L & 0xff; \
	tmp1 = ctx_S[pos_S(3,tmp1)];\
	tmp2 = (L >> 8); \
        tmp3=  (tmp2>>8);\
	tmp4=  tmp3>>8;   \
        tmp2=  tmp2 & 0xff; \
        tmp2 = ctx_S[pos_S(2,tmp2)]; \
	tmp3 = tmp3 & 0xff; \
	tmp4 = tmp4 & 0xff; \
	tmp3 = ctx_S[pos_S(1,tmp3)]+ctx_S[pos_S(0,tmp4)]; \
        tmp3 ^= tmp2; \
	R =R ^ ctx_P[N + 1]; \
	tmp3 = tmp3 + tmp1; \
	R =R ^ tmp3;

#define BF_ENCRYPT(ctx_S,ctx_P, L, R) \
	L ^= ctx_P[0]; \
	BF_ROUND(ctx_S,ctx_P, L, R, 0, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 1, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 2, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 3, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 4, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 5, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 6, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 7, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 8, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 9, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 10, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 11, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 12, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, R, L, 13, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P, L, R, 14, u1, u2, u3, u4); \
	BF_ROUND(ctx_S,ctx_P,R, L, 15, u1, u2, u3, u4); \
	u4 = R; \
	R = L; \
	L = u4 ^ ctx_P[BF_ROUNDS + 1];


#define BF_body() \
	L0 = R0 = 0; \
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[0]= L0;\
	BF_current_P[1]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[2]= L0;\
	BF_current_P[3]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[4]= L0;\
	BF_current_P[5]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[6]= L0;\
	BF_current_P[7]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[8]= L0;\
	BF_current_P[9]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[10]= L0;\
	BF_current_P[11]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[12]= L0;\
	BF_current_P[13]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[14]= L0;\
	BF_current_P[15]= R0;\
	BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
	BF_current_P[16]= L0;\
	BF_current_P[17]= R0;\
\
	for(i=0;i<1024;i=i+2)\
	    { j=i>>8;\
              BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);\
              BF_current_S[pos_S(j,(i&0xff))] = L0;\
              BF_current_S[pos_S(j,((i+1)&0xff))] = R0;\
	    }


__kernel void blowfish(constant uint *salt __attribute__((max_constant_size(16))),
		       constant uint *P_box __attribute__((max_constant_size(72))),
                             __global uint *BF_out,
                             __global uint *BF_current_S,
			     __global uint *BF_current_P_global ,
			     uint rounds	)
{	
	uint index = get_global_id(0),tmp0;
        uint _index_S =(index/(CHANNEL_INTERLEAVE))*(CHANNEL_INTERLEAVE)*1024 + index%(CHANNEL_INTERLEAVE) + OFFSET;
        uint _index_P =(index/(CHANNEL_INTERLEAVE))*(CHANNEL_INTERLEAVE)*18 + index%(CHANNEL_INTERLEAVE);
	int i,j;
        uint BF_key_exp[20];
	uint BF_current_P[20];
	for(i=0;i<18;i++){ 
		tmp0 = BF_current_P_global[pos_P(i)];
		BF_key_exp[i]= tmp0^P_box[i];
		BF_current_P[i]= tmp0;
	      }
	
              
		uint L0, R0;
		uint u1, u2, u3, u4;
		uint count;
		
				
		L0 = R0 = 0;
		for (i = 0; i < (BF_ROUNDS + 2); i += 2) {
			L0 ^= salt[i & 2];
			R0 ^= salt[(i & 2) + 1];
			BF_ENCRYPT(BF_current_S,BF_current_P , L0, R0);
			BF_current_P[i] = L0;
			BF_current_P[i + 1] = R0;
		}
		
		
		for(i=0; i<1024 ;i=i+4)
                    {	j=i>>8;
			L0 ^= salt[(BF_ROUNDS + 2) & 3];
			R0 ^= salt[(BF_ROUNDS + 3) & 3];
			BF_ENCRYPT(BF_current_S,BF_current_P , L0, R0);
			BF_current_S[pos_S(j,(i&0xff))] = L0;
			BF_current_S[pos_S(j,((i+1)&0xff))] = R0;
			L0 ^= salt[(BF_ROUNDS + 4) & 3];
			R0 ^= salt[(BF_ROUNDS + 5) & 3];
			BF_ENCRYPT(BF_current_S,BF_current_P  , L0, R0);
			BF_current_S[pos_S(j,((i+2)&0xff))] = L0;
			BF_current_S[pos_S(j,((i+3)&0xff))] = R0;
		      
		    }
               
		count = 1 << rounds;
		  
		do {
			BF_current_P[0] ^= BF_key_exp[0];
			BF_current_P[1] ^= BF_key_exp[1];
			BF_current_P[2] ^= BF_key_exp[2];
			BF_current_P[3] ^= BF_key_exp[3];
			BF_current_P[4] ^= BF_key_exp[4];
			BF_current_P[5] ^= BF_key_exp[5];
			BF_current_P[6] ^= BF_key_exp[6];
			BF_current_P[7] ^= BF_key_exp[7];
			BF_current_P[8] ^= BF_key_exp[8];
			BF_current_P[9] ^= BF_key_exp[9];
			BF_current_P[10] ^= BF_key_exp[10];
			BF_current_P[11] ^= BF_key_exp[11];
			BF_current_P[12] ^= BF_key_exp[12];
			BF_current_P[13] ^= BF_key_exp[13];
			BF_current_P[14] ^= BF_key_exp[14];
			BF_current_P[15] ^= BF_key_exp[15];
			BF_current_P[16] ^= BF_key_exp[16];
			BF_current_P[17] ^= BF_key_exp[17];
	 
			BF_body();
			
			u1 = salt[0];
			u2 = salt[1];
			u3 = salt[2];
			u4 = salt[3];

			BF_current_P[0] ^= u1;
			BF_current_P[1] ^= u2;
			BF_current_P[2] ^= u3;
			BF_current_P[3] ^= u4;
			BF_current_P[4] ^= u1;
			BF_current_P[5] ^= u2;
			BF_current_P[6] ^= u3;
			BF_current_P[7] ^= u4;
			BF_current_P[8] ^= u1;
			BF_current_P[9] ^= u2;
			BF_current_P[10] ^= u3;
			BF_current_P[11] ^= u4;
			BF_current_P[12] ^= u1;
			BF_current_P[13] ^= u2;
			BF_current_P[14] ^= u3;
			BF_current_P[15] ^= u4;
			BF_current_P[16] ^= u1;
			BF_current_P[17] ^= u2;

			BF_body();
		    
		} while (--count);
		
 		
		L0 = 0x4F727068;
		R0 = 0x65616E42;

		count = 64;
		
		do {
			BF_ENCRYPT(BF_current_S ,BF_current_P , L0, R0);
		} while (--count);
		
		BF_out[2*index]=L0;
		BF_out[2*index+1]=R0;

	    for(i=0;i<18;i++)
		BF_current_P_global[pos_P(i)]=BF_current_P[i]; 

}




  