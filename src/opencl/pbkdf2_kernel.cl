/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/

#define ITERATIONS                  10240

#define INIT_MD4_A                  0x67452301
#define INIT_MD4_B                  0xefcdab89
#define INIT_MD4_C                  0x98badcfe
#define INIT_MD4_D                  0x10325476

#define SQRT_2                      0x5a827999
#define SQRT_3                      0x6ed9eba1

#define SHA1_DIGEST_LENGTH          20

#define INIT_SHA1_A                 0x67452301
#define INIT_SHA1_B                 0xEFCDAB89
#define INIT_SHA1_C                 0x98BADCFE
#define INIT_SHA1_D                 0x10325476
#define INIT_SHA1_E                 0xC3D2E1F0


#ifndef GET_WORD_32_BE
#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i) ] <<24 )\
        | ( (unsigned long) ((b)[(i) ]&0xff00) << 8 )\
        | ( (unsigned long) ((b)[(i) ]>>8)&0xff00 )\
        | ( (unsigned long) (b)[(i) ] >>24 );\
}
#endif

#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = ((unsigned char) ( (n) >> 24 ))|((unsigned char) ( (n) >> 16 ))<<8|((unsigned char) ( (n) >>  8 ))<<16|((unsigned char) ( (n) ))<<24;       \
}
#endif

#define S1(x) ((x << 1) | ((x ) >> 31))

#define S5(x) ((x << 5) | ((x ) >> 27))

#define S30(x) ((x << 30) | ((x ) >> 2))

#define R0                                              \
(                                                       \
    W[0] = S1((W[13] ^ W[8] ^ W[2] ^ W[0]))   \
)

#define R1                                              \
(                                                       \
     W[1] = S1((W[14] ^ W[9] ^ W[3] ^ W[1]))  \
)

#define R2                                              \
(                                                       \
     W[2] = S1((W[15] ^ W[10] ^ W[4] ^ W[2]))  \
)

#define R3                                              \
(                                                       \
    W[3] = S1((W[0] ^ W[11] ^ W[5] ^ W[3]))   \
)

#define R4                                              \
(                                                       \
    W[4] = S1((W[1] ^ W[12] ^ W[6] ^ W[4]))   \
)

#define R5                                              \
(                                                       \
    W[5] = S1((W[2] ^ W[13] ^ W[7] ^ W[5]))   \
)

#define R6                                              \
(                                                       \
    W[6] = S1((W[3] ^ W[14] ^ W[8] ^ W[6]))  \
)

#define R7                                              \
(                                                       \
    W[7] = S1((W[4] ^ W[15] ^ W[9] ^ W[7]))  \
)

#define R8                                              \
(                                                       \
   W[8] = S1((W[5] ^ W[0] ^ W[10] ^ W[8])) \
)

#define R9                                              \
(                                                       \
   W[9] = S1((W[6] ^ W[1] ^ W[11] ^ W[9]) )  \
)

#define RA                                              \
(                                                       \
   W[10] = S1((W[7] ^ W[2] ^ W[12] ^ W[10]) ) \
)

#define RB                                              \
(                                                       \
   W[11] = S1((W[8] ^ W[3] ^ W[13] ^ W[11]) ) \
)

#define RC                                              \
(                                                       \
   W[12]  = S1((W[9] ^ W[4] ^ W[14] ^ W[12] )) \
)

#define RD                                              \
(                                                       \
   W[13] = S1(( W[10] ^ W[5] ^ W[15] ^ W[13]) ) \
)

#define RE                                              \
(                                                       \
   W[14] = S1((W[11] ^ W[6] ^ W[0] ^ W[14] ) ) \
)

#define RF                                              \
(                                                       \
   W[15] = S1((W[12] ^ W[7] ^ W[1] ^ W[15])  ) \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S5(a) + F(b,c,d) + K + x; b = S30(b);        \
}

#define SHA1_part0(A,B,C,D,E,W) \
        P(A, B, C, D, E, W[0]);\
	P(E, A, B, C, D, W[1]);\
	P(D, E, A, B, C, W[2]);\
	P(C, D, E, A, B, W[3]);\
	P(B, C, D, E, A, W[4]);\
	P(A, B, C, D, E, W[5]);\
	P(E, A, B, C, D, W[6]);\
	P(D, E, A, B, C, W[7]);\
	P(C, D, E, A, B, W[8]);\
	P(B, C, D, E, A, W[9]);\
	P(A, B, C, D, E, W[10]);\
	P(E, A, B, C, D, W[11]);\
	P(D, E, A, B, C, W[12]);\
	P(C, D, E, A, B, W[13]);\
	P(B, C, D, E, A, W[14]);\
	P(A, B, C, D, E, W[15]);\
	P(E, A, B, C, D, R0);\
	P(D, E, A, B, C, R1);\
	P(C, D, E, A, B, R2);\
	P(B, C, D, E, A, R3);

#define SHA1_part1(A,B,C,D,E) \
        P(A, B, C, D, E, R4);\
	P(E, A, B, C, D, R5);\
	P(D, E, A, B, C, R6);\
	P(C, D, E, A, B, R7);\
	P(B, C, D, E, A, R8);\
	P(A, B, C, D, E, R9);\
	P(E, A, B, C, D, RA);\
	P(D, E, A, B, C, RB);\
	P(C, D, E, A, B, RC);\
	P(B, C, D, E, A, RD);\
	P(A, B, C, D, E, RE);\
	P(E, A, B, C, D, RF);\
	P(D, E, A, B, C, R0);\
	P(C, D, E, A, B, R1);\
	P(B, C, D, E, A, R2);\
	P(A, B, C, D, E, R3);\
	P(E, A, B, C, D, R4);\
	P(D, E, A, B, C, R5);\
	P(C, D, E, A, B, R6);\
	P(B, C, D, E, A, R7);

#define SHA1_part2(A,B,C,D,E)\
        P(A, B, C, D, E, R8);\
	P(E, A, B, C, D, R9);\
	P(D, E, A, B, C, RA);\
	P(C, D, E, A, B, RB);\
	P(B, C, D, E, A, RC);\
	P(A, B, C, D, E, RD);\
	P(E, A, B, C, D, RE);\
	P(D, E, A, B, C, RF);\
	P(C, D, E, A, B, R0);\
	P(B, C, D, E, A, R1);\
	P(A, B, C, D, E, R2);\
	P(E, A, B, C, D, R3);\
	P(D, E, A, B, C, R4);\
	P(C, D, E, A, B, R5);\
	P(B, C, D, E, A, R6);\
	P(A, B, C, D, E, R7);\
	P(E, A, B, C, D, R8);\
	P(D, E, A, B, C, R9);\
	P(C, D, E, A, B, RA);\
	P(B, C, D, E, A, RB);

#define SHA1_part3(A,B,C,D,E)\
        P(A, B, C, D, E, RC);\
	P(E, A, B, C, D, RD);\
	P(D, E, A, B, C, RE);\
	P(C, D, E, A, B, RF);\
	P(B, C, D, E, A, R0);\
	P(A, B, C, D, E, R1);\
	P(E, A, B, C, D, R2);\
	P(D, E, A, B, C, R3);\
	P(C, D, E, A, B, R4);\
	P(B, C, D, E, A, R5);\
	P(A, B, C, D, E, R6);\
	P(E, A, B, C, D, R7);\
	P(D, E, A, B, C, R8);\
	P(C, D, E, A, B, R9);\
	P(B, C, D, E, A, RA);\
	P(A, B, C, D, E, RB);\
	P(E, A, B, C, D, RC);\
	P(D, E, A, B, C, RD);\
	P(C, D, E, A, B, RE);\
	P(B, C, D, E, A, RF);

inline void SHA1(__private uint *A,__private uint *W)
{
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999
	SHA1_part0(A[0],A[1],A[2],A[3],A[4],W);
#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1
	SHA1_part1(A[0],A[1],A[2],A[3],A[4]);
#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC
	SHA1_part2(A[0],A[1],A[2],A[3],A[4]);
#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6
	SHA1_part3(A[0],A[1],A[2],A[3],A[4]);
#undef K
#undef F

}

inline void hmac_sha1(__private uint *ipad,__private uint *opad,__private uint *state,private uint *buf, __private uint *temp_char){
	
        uint A[5],W[16];
        
        GET_WORD_32_BE(W[0], ipad, 0);
	GET_WORD_32_BE(W[1], ipad, 1);
	GET_WORD_32_BE(W[2], ipad, 2);
	GET_WORD_32_BE(W[3], ipad, 3);
	GET_WORD_32_BE(W[4], ipad, 4);
	GET_WORD_32_BE(W[5], ipad, 5);
	GET_WORD_32_BE(W[6], ipad, 6);
	GET_WORD_32_BE(W[7], ipad, 7);
	GET_WORD_32_BE(W[8], ipad, 8);
	GET_WORD_32_BE(W[9], ipad, 9);
	GET_WORD_32_BE(W[10], ipad, 10);
	GET_WORD_32_BE(W[11], ipad, 11);
	GET_WORD_32_BE(W[12], ipad, 12);
	GET_WORD_32_BE(W[13], ipad, 13);
	GET_WORD_32_BE(W[14], ipad, 14);
	GET_WORD_32_BE(W[15], ipad, 15);

	A[0] = INIT_SHA1_A;
	A[1] = INIT_SHA1_B;
	A[2] = INIT_SHA1_C;
	A[3] = INIT_SHA1_D;
	A[4] = INIT_SHA1_E;

SHA1(A,W);

	A[0] += INIT_SHA1_A;
	A[1] += INIT_SHA1_B;
	A[2] += INIT_SHA1_C;
	A[3] += INIT_SHA1_D;
	A[4] += INIT_SHA1_E;

	state[0] = A[0];
	state[1] = A[1];
	state[2] = A[2];
	state[3] = A[3];
	state[4] = A[4];

	GET_WORD_32_BE(W[0], buf, 0);
	GET_WORD_32_BE(W[1], buf, 1);
	GET_WORD_32_BE(W[2], buf, 2);
	GET_WORD_32_BE(W[3], buf, 3);
	GET_WORD_32_BE(W[4], buf, 4);
	GET_WORD_32_BE(W[5], buf, 5);
	GET_WORD_32_BE(W[6], buf, 6);
	GET_WORD_32_BE(W[7], buf, 7);
	GET_WORD_32_BE(W[8], buf, 8);
	GET_WORD_32_BE(W[9], buf, 9);
	GET_WORD_32_BE(W[10], buf, 10);
	GET_WORD_32_BE(W[11], buf, 11);
	GET_WORD_32_BE(W[12], buf, 12);
	GET_WORD_32_BE(W[13], buf, 13);
	GET_WORD_32_BE(W[14], buf, 14);
	GET_WORD_32_BE(W[15], buf, 15);

SHA1(A,W);

	A[0] += state[0];
	A[1] += state[1];
	A[2] += state[2];
	A[3] += state[3];
	A[4] += state[4];

	PUT_WORD_32_BE(A[0], buf, 0);
	PUT_WORD_32_BE(A[1], buf, 1);
	PUT_WORD_32_BE(A[2], buf, 2);
	PUT_WORD_32_BE(A[3], buf, 3);
	PUT_WORD_32_BE(A[4], buf, 4);

	buf[5] = 0x80 | (buf[5] & 0xffffff00);

	PUT_WORD_32_BE(0x2A0, buf, 15);

	GET_WORD_32_BE(W[0], opad, 0);
	GET_WORD_32_BE(W[1], opad, 1);
	GET_WORD_32_BE(W[2], opad, 2);
	GET_WORD_32_BE(W[3], opad, 3);
	GET_WORD_32_BE(W[4], opad, 4);
	GET_WORD_32_BE(W[5], opad, 5);
	GET_WORD_32_BE(W[6], opad, 6);
	GET_WORD_32_BE(W[7], opad, 7);
	GET_WORD_32_BE(W[8], opad, 8);
	GET_WORD_32_BE(W[9], opad, 9);
	GET_WORD_32_BE(W[10], opad, 10);
	GET_WORD_32_BE(W[11], opad, 11);
	GET_WORD_32_BE(W[12], opad, 12);
	GET_WORD_32_BE(W[13], opad, 13);
	GET_WORD_32_BE(W[14], opad, 14);
	GET_WORD_32_BE(W[15], opad, 15);

	A[0] = INIT_SHA1_A;
	A[1] = INIT_SHA1_B;
	A[2] = INIT_SHA1_C;
	A[3] = INIT_SHA1_D;
	A[4] = INIT_SHA1_E;

SHA1(A,W);

	A[0] += INIT_SHA1_A;
	A[1] += INIT_SHA1_B;
	A[2] += INIT_SHA1_C;
	A[3] += INIT_SHA1_D;
	A[4] += INIT_SHA1_E;

	state[0] = A[0];
	state[1] = A[1];
	state[2] = A[2];
	state[3] = A[3];
	state[4] = A[4];

	GET_WORD_32_BE(W[0], buf, 0);
	GET_WORD_32_BE(W[1], buf, 1);
	GET_WORD_32_BE(W[2], buf, 2);
	GET_WORD_32_BE(W[3], buf, 3);
	GET_WORD_32_BE(W[4], buf, 4);
	GET_WORD_32_BE(W[5], buf, 5);
	GET_WORD_32_BE(W[6], buf, 6);
	GET_WORD_32_BE(W[7], buf, 7);
	GET_WORD_32_BE(W[8], buf, 8);
	GET_WORD_32_BE(W[9], buf, 9);
	GET_WORD_32_BE(W[10], buf, 10);
	GET_WORD_32_BE(W[11], buf, 11);
	GET_WORD_32_BE(W[12], buf, 12);
	GET_WORD_32_BE(W[13], buf, 13);
	GET_WORD_32_BE(W[14], buf, 14);
	GET_WORD_32_BE(W[15], buf, 15);
	
SHA1(A,W);

	A[0] += state[0];
	A[1] += state[1];
	A[2] += state[2];
	A[3] += state[3];
	A[4] += state[4];

        PUT_WORD_32_BE(A[0], temp_char, 0);
	PUT_WORD_32_BE(A[1], temp_char, 1);
	PUT_WORD_32_BE(A[2], temp_char, 2);
	PUT_WORD_32_BE(A[3], temp_char, 3);
	PUT_WORD_32_BE(A[4], temp_char, 4);

}

__kernel 
void PBKDF2 ( const __global unsigned int *pass_global, 
              const __global unsigned int *salt, 
              int usrlen,  
              uint num_keys,
	      __global unsigned int *out_global)
{
	int lid = get_local_id(0);
	
        int id = get_global_id(0);
	
	unsigned int i, j;
	
	__local unsigned int salt_local[32];
	  
	if (lid == 0)
	    for (i = 0; i <= usrlen / 2; ++i)
		salt_local[i] = salt[i];
	
		
	barrier(CLK_LOCAL_MEM_FENCE);

	unsigned int pass[4];
	
	unsigned int buf[16] = { 0 };

#define SHA1_DIGEST_LENGTH_by_4 SHA1_DIGEST_LENGTH/4
	
	uint temp_char[SHA1_DIGEST_LENGTH_by_4];
	
	unsigned int state[5],out[4];
	
	unsigned int ipad[16];
	
	unsigned int opad[16];
          
	/*for (i = id, j = 0; i < 4 * num_keys; i = i + num_keys, j++)
		pass[j] = pass_global[i];*/

	pass[0]=pass_global[id];
	id+=num_keys;
	pass[1]=pass_global[id];
	id+=num_keys;
	pass[2]=pass_global[id];
	id+=num_keys;
	pass[3]=pass_global[id];
	

	if (usrlen % 2 == 1) {
		for (i = 0; i <= usrlen / 2; i++)
			buf[i] = salt_local[i];
		buf[(usrlen / 2) + 1] = 0x01 << 8;
	} 
        
        else {
		for (i = 0; i < usrlen / 2; i++)
			buf[i] = salt_local[i];
		buf[usrlen / 2] = 0x01 << 24;
	}

		
        for (i = 0; i < 16; i++) {
		ipad[i] = 0x36363636;
		opad[i] = 0x5C5C5C5C;
	}

	if (usrlen % 2 == 1)
		buf[usrlen / 2 + 1] = 0x80 << 16 | buf[usrlen / 2 + 1];
	else
		buf[usrlen / 2 + 1] = 0x80 | buf[usrlen / 2 + 1];


	PUT_WORD_32_BE((64 + usrlen * 2 + 4) << 3, buf, 60 / 4);

	
	 for (j = 0; j < 4; j++) {
		ipad[j] = ipad[j] ^ pass[j];
		opad[j] = opad[j] ^ pass[j];
	  }

	hmac_sha1(ipad,opad,state,buf,temp_char);
	
	out[0] = temp_char[0];
	out[1] = temp_char[1];
	out[2] = temp_char[2];
	out[3] = temp_char[3];

        for (i = 0; i < 16; i++) 
		buf[i] = 0;
	
     
	for (i = 1; i < ITERATIONS; i++) {
			
		
		buf[0] = temp_char[0];
		buf[1] = temp_char[1];
		buf[2] = temp_char[2];
		buf[3] = temp_char[3];
		buf[4] = temp_char[4];

		buf[SHA1_DIGEST_LENGTH_by_4] =  0x80 | buf[SHA1_DIGEST_LENGTH_by_4];
		
		PUT_WORD_32_BE((64 + SHA1_DIGEST_LENGTH) << 3, buf, 15);

		hmac_sha1(ipad,opad,state,buf,temp_char);

		out[0] ^= temp_char[0];
		out[1] ^= temp_char[1];
		out[2] ^= temp_char[2];
		out[3] ^= temp_char[3];

	}
	
	out_global[id]=out[3];
	id-=num_keys;
	out_global[id]=out[2];
	id-=num_keys;
	out_global[id]=out[1];
	id-=num_keys;
	out_global[id]=out[0];
	id-=num_keys;
}
