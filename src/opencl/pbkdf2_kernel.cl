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
        | ( (unsigned long) ((b)[(i) ]&0x0000ff00) << 8 )\
        | ( (unsigned long) ((b)[(i) ]&0x00ff0000) >> 8 )\
        | ( (unsigned long) (b)[(i) ] >>24 );\
}
#endif

#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = ((unsigned char) ( (n) >> 24 ))|((unsigned char) ( (n) >> 16 ))<<8|((unsigned char) ( (n) >>  8 ))<<16|((unsigned char) ( (n) ))<<24;       \
}
#endif

#define R0                                              \
(                                                       \
    W.s0 = rotate((int)(W.sd ^ W.s8 ^ W.s2 ^ W.s0),1)   \
)

#define R1                                              \
(                                                       \
     W.s1 = rotate((int)(W.se ^ W.s9 ^ W.s3 ^ W.s1),1)  \
)

#define R2                                              \
(                                                       \
     W.s2 = rotate((int)(W.sf ^ W.sa ^ W.s4 ^ W.s2),1)  \
)

#define R3                                              \
(                                                       \
    W.s3 = rotate((int)(W.s0 ^ W.sb ^ W.s5 ^ W.s3),1)   \
)

#define R4                                              \
(                                                       \
    W.s4 = rotate((int)(W.s1 ^ W.sc ^ W.s6 ^ W.s4),1)   \
)

#define R5                                              \
(                                                       \
    W.s5 = rotate((int)(W.s2 ^ W.sd ^ W.s7 ^ W.s5),1)   \
)

#define R6                                              \
(                                                       \
    W.s6 = rotate((int)(W.s3 ^ W.se ^ W.s8 ^ W.s6),1 )  \
)

#define R7                                              \
(                                                       \
    W.s7 = rotate((int)(W.s4 ^ W.sf ^ W.s9 ^ W.s7),1)   \
)

#define R8                                              \
(                                                       \
   W.s8 = rotate((int)( W.s5 ^ W.s0 ^ W.sa ^ W.s8 ),1 ) \
)

#define R9                                              \
(                                                       \
   W.s9 = rotate((int)(W.s6 ^ W.s1 ^ W.sb ^ W.s9 ),1)   \
)

#define RA                                              \
(                                                       \
   W.sa = rotate((int)(W.s7 ^ W.s2 ^ W.sc ^ W.sa ),1 )  \
)

#define RB                                              \
(                                                       \
   W.sb = rotate((int)(W.s8 ^ W.s3 ^ W.sd ^ W.sb ),1 )  \
)

#define RC                                              \
(                                                       \
   W.sc  = rotate((int)(W.s9 ^ W.s4 ^ W.se ^ W.sc ),1 ) \
)

#define RD                                              \
(                                                       \
   W.sd = rotate((int)( W.sa ^ W.s5 ^ W.sf ^ W.sd ),1 ) \
)

#define RE                                              \
(                                                       \
   W.se = rotate((int)(W.sb ^ W.s6 ^ W.s0 ^ W.se  ),1 ) \
)

#define RF                                              \
(                                                       \
   W.sf = rotate((int)(W.sc ^ W.s7 ^ W.s1 ^ W.sf  ),1 ) \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += rotate((int)a,5) + F(b,c,d) + K + x; b = rotate((int)b,30);        \
}

__kernel __attribute__ ((reqd_work_group_size(64, 1, 1)))
void PBKDF2 ( const __global unsigned int *pass_global, 
              const __global unsigned int *salt, 
              int usrlen,  
              uint num_keys,
              __global unsigned int *out_global)
{
	int lid = get_local_id(0);
	
        int id = get_global_id(0);
	
	unsigned int i, j, k;
	
	__local unsigned int salt_local[32], out[4 * 64];
	  
	if (lid == 0)
	    for (i = 0; i <= usrlen / 2; ++i)
		salt_local[i] = salt[i];
	
	k = 4 * lid;
	
	for (i = 0; i < 4; ++i)
		out[k + i] = 0;
	
	barrier(CLK_LOCAL_MEM_FENCE);

	unsigned int pass[4];
	
	unsigned int buf[16] = { 0 };
	
	uint temp_char[SHA1_DIGEST_LENGTH / 4];
	
	uint16 W;
	
	unsigned int A, B, C, D, E, state[5];
	
	unsigned int ipad[16];
	
	unsigned int opad[16];

	for (i = id, j = 0; i < 4 * num_keys; i = i + num_keys, j++)
		pass[j] = pass_global[i];

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



	// step 1: append zeros to the end of K to create a B Byte string

	if (usrlen % 2 == 1)
		buf[usrlen / 2 + 1] = 0x80 << 16 | buf[usrlen / 2 + 1];
	else
		buf[usrlen / 2 + 1] = 0x80 | buf[usrlen / 2 + 1];



	PUT_WORD_32_BE((64 + usrlen * 2 + 4) << 3, buf, 60 / 4);

	
	  // step 2: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with ipad
	  // step 5: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with opad    

	
	  for (j = 0; j < 4; j++) {
		ipad[j] = ipad[j] ^ pass[j];
		opad[j] = opad[j] ^ pass[j];
	  }

	// step 3: append the stream of data 'text' to the B byte sting resulting from step 2
	// first part of stream (64 bytes) is ipad, second part of stream (64 bytes) is buf
	// step 4: apply H to the stream (ipad & buf) generated in step 3

	GET_WORD_32_BE(W.s0, ipad, 0);
	GET_WORD_32_BE(W.s1, ipad, 1);
	GET_WORD_32_BE(W.s2, ipad, 2);
	GET_WORD_32_BE(W.s3, ipad, 3);
	GET_WORD_32_BE(W.s4, ipad, 4);
	GET_WORD_32_BE(W.s5, ipad, 5);
	GET_WORD_32_BE(W.s6, ipad, 6);
	GET_WORD_32_BE(W.s7, ipad, 7);
	GET_WORD_32_BE(W.s8, ipad, 8);
	GET_WORD_32_BE(W.s9, ipad, 9);
	GET_WORD_32_BE(W.sa, ipad, 10);
	GET_WORD_32_BE(W.sb, ipad, 11);
	GET_WORD_32_BE(W.sc, ipad, 12);
	GET_WORD_32_BE(W.sd, ipad, 13);
	GET_WORD_32_BE(W.se, ipad, 14);
	GET_WORD_32_BE(W.sf, ipad, 15);


	A = INIT_SHA1_A;
	B = INIT_SHA1_B;
	C = INIT_SHA1_C;
	D = INIT_SHA1_D;
	E = INIT_SHA1_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W.s0);
	P(E, A, B, C, D, W.s1);
	P(D, E, A, B, C, W.s2);
	P(C, D, E, A, B, W.s3);
	P(B, C, D, E, A, W.s4);
	P(A, B, C, D, E, W.s5);
	P(E, A, B, C, D, W.s6);
	P(D, E, A, B, C, W.s7);
	P(C, D, E, A, B, W.s8);
	P(B, C, D, E, A, W.s9);
	P(A, B, C, D, E, W.sa);
	P(E, A, B, C, D, W.sb);
	P(D, E, A, B, C, W.sc);
	P(C, D, E, A, B, W.sd);
	P(B, C, D, E, A, W.se);
	P(A, B, C, D, E, W.sf);
	P(E, A, B, C, D, R0);
	P(D, E, A, B, C, R1);
	P(C, D, E, A, B, R2);
	P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R4);
	P(E, A, B, C, D, R5);
	P(D, E, A, B, C, R6);
	P(C, D, E, A, B, R7);
	P(B, C, D, E, A, R8);
	P(A, B, C, D, E, R9);
	P(E, A, B, C, D, RA);
	P(D, E, A, B, C, RB);
	P(C, D, E, A, B, RC);
	P(B, C, D, E, A, RD);
	P(A, B, C, D, E, RE);
	P(E, A, B, C, D, RF);
	P(D, E, A, B, C, R0);
	P(C, D, E, A, B, R1);
	P(B, C, D, E, A, R2);
	P(A, B, C, D, E, R3);
	P(E, A, B, C, D, R4);
	P(D, E, A, B, C, R5);
	P(C, D, E, A, B, R6);
	P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R8);
	P(E, A, B, C, D, R9);
	P(D, E, A, B, C, RA);
	P(C, D, E, A, B, RB);
	P(B, C, D, E, A, RC);
	P(A, B, C, D, E, RD);
	P(E, A, B, C, D, RE);
	P(D, E, A, B, C, RF);
	P(C, D, E, A, B, R0);
	P(B, C, D, E, A, R1);
	P(A, B, C, D, E, R2);
	P(E, A, B, C, D, R3);
	P(D, E, A, B, C, R4);
	P(C, D, E, A, B, R5);
	P(B, C, D, E, A, R6);
	P(A, B, C, D, E, R7);
	P(E, A, B, C, D, R8);
	P(D, E, A, B, C, R9);
	P(C, D, E, A, B, RA);
	P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, RC);
	P(E, A, B, C, D, RD);
	P(D, E, A, B, C, RE);
	P(C, D, E, A, B, RF);
	P(B, C, D, E, A, R0);
	P(A, B, C, D, E, R1);
	P(E, A, B, C, D, R2);
	P(D, E, A, B, C, R3);
	P(C, D, E, A, B, R4);
	P(B, C, D, E, A, R5);
	P(A, B, C, D, E, R6);
	P(E, A, B, C, D, R7);
	P(D, E, A, B, C, R8);
	P(C, D, E, A, B, R9);
	P(B, C, D, E, A, RA);
	P(A, B, C, D, E, RB);
	P(E, A, B, C, D, RC);
	P(D, E, A, B, C, RD);
	P(C, D, E, A, B, RE);
	P(B, C, D, E, A, RF);


#undef K
#undef F

	A += INIT_SHA1_A;
	B += INIT_SHA1_B;
	C += INIT_SHA1_C;
	D += INIT_SHA1_D;
	E += INIT_SHA1_E;

	state[0] = A;
	state[1] = B;
	state[2] = C;
	state[3] = D;
	state[4] = E;

	// process buf (2nd part of stream)
	GET_WORD_32_BE(W.s0, buf, 0);
	GET_WORD_32_BE(W.s1, buf, 1);
	GET_WORD_32_BE(W.s2, buf, 2);
	GET_WORD_32_BE(W.s3, buf, 3);
	GET_WORD_32_BE(W.s4, buf, 4);
	GET_WORD_32_BE(W.s5, buf, 5);
	GET_WORD_32_BE(W.s6, buf, 6);
	GET_WORD_32_BE(W.s7, buf, 7);
	GET_WORD_32_BE(W.s8, buf, 8);
	GET_WORD_32_BE(W.s9, buf, 9);
	GET_WORD_32_BE(W.sa, buf, 10);
	GET_WORD_32_BE(W.sb, buf, 11);
	GET_WORD_32_BE(W.sc, buf, 12);
	GET_WORD_32_BE(W.sd, buf, 13);
	GET_WORD_32_BE(W.se, buf, 14);
	GET_WORD_32_BE(W.sf, buf, 15);

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W.s0);
	P(E, A, B, C, D, W.s1);
	P(D, E, A, B, C, W.s2);
	P(C, D, E, A, B, W.s3);
	P(B, C, D, E, A, W.s4);
	P(A, B, C, D, E, W.s5);
	P(E, A, B, C, D, W.s6);
	P(D, E, A, B, C, W.s7);
	P(C, D, E, A, B, W.s8);
	P(B, C, D, E, A, W.s9);
	P(A, B, C, D, E, W.sa);
	P(E, A, B, C, D, W.sb);
	P(D, E, A, B, C, W.sc);
	P(C, D, E, A, B, W.sd);
	P(B, C, D, E, A, W.se);
	P(A, B, C, D, E, W.sf);
	P(E, A, B, C, D, R0);
	P(D, E, A, B, C, R1);
	P(C, D, E, A, B, R2);
	P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R4);
	P(E, A, B, C, D, R5);
	P(D, E, A, B, C, R6);
	P(C, D, E, A, B, R7);
	P(B, C, D, E, A, R8);
	P(A, B, C, D, E, R9);
	P(E, A, B, C, D, RA);
	P(D, E, A, B, C, RB);
	P(C, D, E, A, B, RC);
	P(B, C, D, E, A, RD);
	P(A, B, C, D, E, RE);
	P(E, A, B, C, D, RF);
	P(D, E, A, B, C, R0);
	P(C, D, E, A, B, R1);
	P(B, C, D, E, A, R2);
	P(A, B, C, D, E, R3);
	P(E, A, B, C, D, R4);
	P(D, E, A, B, C, R5);
	P(C, D, E, A, B, R6);
	P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R8);
	P(E, A, B, C, D, R9);
	P(D, E, A, B, C, RA);
	P(C, D, E, A, B, RB);
	P(B, C, D, E, A, RC);
	P(A, B, C, D, E, RD);
	P(E, A, B, C, D, RE);
	P(D, E, A, B, C, RF);
	P(C, D, E, A, B, R0);
	P(B, C, D, E, A, R1);
	P(A, B, C, D, E, R2);
	P(E, A, B, C, D, R3);
	P(D, E, A, B, C, R4);
	P(C, D, E, A, B, R5);
	P(B, C, D, E, A, R6);
	P(A, B, C, D, E, R7);
	P(E, A, B, C, D, R8);
	P(D, E, A, B, C, R9);
	P(C, D, E, A, B, RA);
	P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, RC);
	P(E, A, B, C, D, RD);
	P(D, E, A, B, C, RE);
	P(C, D, E, A, B, RF);
	P(B, C, D, E, A, R0);
	P(A, B, C, D, E, R1);
	P(E, A, B, C, D, R2);
	P(D, E, A, B, C, R3);
	P(C, D, E, A, B, R4);
	P(B, C, D, E, A, R5);
	P(A, B, C, D, E, R6);
	P(E, A, B, C, D, R7);
	P(D, E, A, B, C, R8);
	P(C, D, E, A, B, R9);
	P(B, C, D, E, A, RA);
	P(A, B, C, D, E, RB);
	P(E, A, B, C, D, RC);
	P(D, E, A, B, C, RD);
	P(C, D, E, A, B, RE);
	P(B, C, D, E, A, RF);


#undef K
#undef F

	A += state[0];
	B += state[1];
	C += state[2];
	D += state[3];
	E += state[4];

	PUT_WORD_32_BE(A, buf, 0);
	PUT_WORD_32_BE(B, buf, 1);
	PUT_WORD_32_BE(C, buf, 2);
	PUT_WORD_32_BE(D, buf, 3);
	PUT_WORD_32_BE(E, buf, 4);

	buf[5] = 0x80 | (buf[5] & 0xffffff00);

	PUT_WORD_32_BE(0x2A0, buf, 15);

	// step 6: append the stream of data 'text' to the B byte sting resulting from step 2
	// first part of stream (64 bytes) is opad, second part of stream (64 bytes) is the H result from step 4
	// step 7: apply H to the stream (opad & buf) generated in step 6 and output the result


	GET_WORD_32_BE(W.s0, opad, 0);
	GET_WORD_32_BE(W.s1, opad, 1);
	GET_WORD_32_BE(W.s2, opad, 2);
	GET_WORD_32_BE(W.s3, opad, 3);
	GET_WORD_32_BE(W.s4, opad, 4);
	GET_WORD_32_BE(W.s5, opad, 5);
	GET_WORD_32_BE(W.s6, opad, 6);
	GET_WORD_32_BE(W.s7, opad, 7);
	GET_WORD_32_BE(W.s8, opad, 8);
	GET_WORD_32_BE(W.s9, opad, 9);
	GET_WORD_32_BE(W.sa, opad, 10);
	GET_WORD_32_BE(W.sb, opad, 11);
	GET_WORD_32_BE(W.sc, opad, 12);
	GET_WORD_32_BE(W.sd, opad, 13);
	GET_WORD_32_BE(W.se, opad, 14);
	GET_WORD_32_BE(W.sf, opad, 15);


	A = INIT_SHA1_A;
	B = INIT_SHA1_B;
	C = INIT_SHA1_C;
	D = INIT_SHA1_D;
	E = INIT_SHA1_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W.s0);
	P(E, A, B, C, D, W.s1);
	P(D, E, A, B, C, W.s2);
	P(C, D, E, A, B, W.s3);
	P(B, C, D, E, A, W.s4);
	P(A, B, C, D, E, W.s5);
	P(E, A, B, C, D, W.s6);
	P(D, E, A, B, C, W.s7);
	P(C, D, E, A, B, W.s8);
	P(B, C, D, E, A, W.s9);
	P(A, B, C, D, E, W.sa);
	P(E, A, B, C, D, W.sb);
	P(D, E, A, B, C, W.sc);
	P(C, D, E, A, B, W.sd);
	P(B, C, D, E, A, W.se);
	P(A, B, C, D, E, W.sf);
	P(E, A, B, C, D, R0);
	P(D, E, A, B, C, R1);
	P(C, D, E, A, B, R2);
	P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R4);
	P(E, A, B, C, D, R5);
	P(D, E, A, B, C, R6);
	P(C, D, E, A, B, R7);
	P(B, C, D, E, A, R8);
	P(A, B, C, D, E, R9);
	P(E, A, B, C, D, RA);
	P(D, E, A, B, C, RB);
	P(C, D, E, A, B, RC);
	P(B, C, D, E, A, RD);
	P(A, B, C, D, E, RE);
	P(E, A, B, C, D, RF);
	P(D, E, A, B, C, R0);
	P(C, D, E, A, B, R1);
	P(B, C, D, E, A, R2);
	P(A, B, C, D, E, R3);
	P(E, A, B, C, D, R4);
	P(D, E, A, B, C, R5);
	P(C, D, E, A, B, R6);
	P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R8);
	P(E, A, B, C, D, R9);
	P(D, E, A, B, C, RA);
	P(C, D, E, A, B, RB);
	P(B, C, D, E, A, RC);
	P(A, B, C, D, E, RD);
	P(E, A, B, C, D, RE);
	P(D, E, A, B, C, RF);
	P(C, D, E, A, B, R0);
	P(B, C, D, E, A, R1);
	P(A, B, C, D, E, R2);
	P(E, A, B, C, D, R3);
	P(D, E, A, B, C, R4);
	P(C, D, E, A, B, R5);
	P(B, C, D, E, A, R6);
	P(A, B, C, D, E, R7);
	P(E, A, B, C, D, R8);
	P(D, E, A, B, C, R9);
	P(C, D, E, A, B, RA);
	P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, RC);
	P(E, A, B, C, D, RD);
	P(D, E, A, B, C, RE);
	P(C, D, E, A, B, RF);
	P(B, C, D, E, A, R0);
	P(A, B, C, D, E, R1);
	P(E, A, B, C, D, R2);
	P(D, E, A, B, C, R3);
	P(C, D, E, A, B, R4);
	P(B, C, D, E, A, R5);
	P(A, B, C, D, E, R6);
	P(E, A, B, C, D, R7);
	P(D, E, A, B, C, R8);
	P(C, D, E, A, B, R9);
	P(B, C, D, E, A, RA);
	P(A, B, C, D, E, RB);
	P(E, A, B, C, D, RC);
	P(D, E, A, B, C, RD);
	P(C, D, E, A, B, RE);
	P(B, C, D, E, A, RF);



#undef K
#undef F

	A += INIT_SHA1_A;
	B += INIT_SHA1_B;
	C += INIT_SHA1_C;
	D += INIT_SHA1_D;
	E += INIT_SHA1_E;

	// store state for 2nd part
	state[0] = A;
	state[1] = B;
	state[2] = C;
	state[3] = D;
	state[4] = E;

	GET_WORD_32_BE(W.s0, buf, 0);
	GET_WORD_32_BE(W.s1, buf, 1);
	GET_WORD_32_BE(W.s2, buf, 2);
	GET_WORD_32_BE(W.s3, buf, 3);
	GET_WORD_32_BE(W.s4, buf, 4);
	GET_WORD_32_BE(W.s5, buf, 5);
	GET_WORD_32_BE(W.s6, buf, 6);
	GET_WORD_32_BE(W.s7, buf, 7);
	GET_WORD_32_BE(W.s8, buf, 8);
	GET_WORD_32_BE(W.s9, buf, 9);
	GET_WORD_32_BE(W.sa, buf, 10);
	GET_WORD_32_BE(W.sb, buf, 11);
	GET_WORD_32_BE(W.sc, buf, 12);
	GET_WORD_32_BE(W.sd, buf, 13);
	GET_WORD_32_BE(W.se, buf, 14);
	GET_WORD_32_BE(W.sf, buf, 15);

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W.s0);
	P(E, A, B, C, D, W.s1);
	P(D, E, A, B, C, W.s2);
	P(C, D, E, A, B, W.s3);
	P(B, C, D, E, A, W.s4);
	P(A, B, C, D, E, W.s5);
	P(E, A, B, C, D, W.s6);
	P(D, E, A, B, C, W.s7);
	P(C, D, E, A, B, W.s8);
	P(B, C, D, E, A, W.s9);
	P(A, B, C, D, E, W.sa);
	P(E, A, B, C, D, W.sb);
	P(D, E, A, B, C, W.sc);
	P(C, D, E, A, B, W.sd);
	P(B, C, D, E, A, W.se);
	P(A, B, C, D, E, W.sf);
	P(E, A, B, C, D, R0);
	P(D, E, A, B, C, R1);
	P(C, D, E, A, B, R2);
	P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R4);
	P(E, A, B, C, D, R5);
	P(D, E, A, B, C, R6);
	P(C, D, E, A, B, R7);
	P(B, C, D, E, A, R8);
	P(A, B, C, D, E, R9);
	P(E, A, B, C, D, RA);
	P(D, E, A, B, C, RB);
	P(C, D, E, A, B, RC);
	P(B, C, D, E, A, RD);
	P(A, B, C, D, E, RE);
	P(E, A, B, C, D, RF);
	P(D, E, A, B, C, R0);
	P(C, D, E, A, B, R1);
	P(B, C, D, E, A, R2);
	P(A, B, C, D, E, R3);
	P(E, A, B, C, D, R4);
	P(D, E, A, B, C, R5);
	P(C, D, E, A, B, R6);
	P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R8);
	P(E, A, B, C, D, R9);
	P(D, E, A, B, C, RA);
	P(C, D, E, A, B, RB);
	P(B, C, D, E, A, RC);
	P(A, B, C, D, E, RD);
	P(E, A, B, C, D, RE);
	P(D, E, A, B, C, RF);
	P(C, D, E, A, B, R0);
	P(B, C, D, E, A, R1);
	P(A, B, C, D, E, R2);
	P(E, A, B, C, D, R3);
	P(D, E, A, B, C, R4);
	P(C, D, E, A, B, R5);
	P(B, C, D, E, A, R6);
	P(A, B, C, D, E, R7);
	P(E, A, B, C, D, R8);
	P(D, E, A, B, C, R9);
	P(C, D, E, A, B, RA);
	P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, RC);
	P(E, A, B, C, D, RD);
	P(D, E, A, B, C, RE);
	P(C, D, E, A, B, RF);
	P(B, C, D, E, A, R0);
	P(A, B, C, D, E, R1);
	P(E, A, B, C, D, R2);
	P(D, E, A, B, C, R3);
	P(C, D, E, A, B, R4);
	P(B, C, D, E, A, R5);
	P(A, B, C, D, E, R6);
	P(E, A, B, C, D, R7);
	P(D, E, A, B, C, R8);
	P(C, D, E, A, B, R9);
	P(B, C, D, E, A, RA);
	P(A, B, C, D, E, RB);
	P(E, A, B, C, D, RC);
	P(D, E, A, B, C, RD);
	P(C, D, E, A, B, RE);
	P(B, C, D, E, A, RF);

#undef K
#undef F

	A += state[0];
	B += state[1];
	C += state[2];
	D += state[3];
	E += state[4];

	PUT_WORD_32_BE(A, temp_char, 0);
	PUT_WORD_32_BE(B, temp_char, 1);
	PUT_WORD_32_BE(C, temp_char, 2);
	PUT_WORD_32_BE(D, temp_char, 3);
	PUT_WORD_32_BE(E, temp_char, 4);


	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	for (i = 0; i < 4; ++i)
		out[k + i] = temp_char[i];


	for (i = 1; i < ITERATIONS; i++) {
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		for (j = 0; j < 16; j++) {
			ipad[j] = 0x36363636;
			opad[j] = 0x5C5C5C5C;
			buf[j] = 0;
		}

		// step 1: append zeros to the end of K to create a B Byte string

		for (j = 0; j < SHA1_DIGEST_LENGTH / 4; j++)
			buf[j] = temp_char[j];

		buf[SHA1_DIGEST_LENGTH / 4] =
		    0x80 | buf[SHA1_DIGEST_LENGTH / 4];
		PUT_WORD_32_BE((64 + SHA1_DIGEST_LENGTH) << 3, buf, 15);

		// step 2: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with ipad
		// step 5: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with opad    

		for (j = 0; j < 4; j++) {
			ipad[j] = ipad[j] ^ pass[j];
			opad[j] = opad[j] ^ pass[j];
		}

		// step 3: append the stream of data 'text' to the B byte sting resulting from step 2
		// first part of stream (64 bytes) is ipad, second part of stream (64 bytes) is buf
		// step 4: apply H to the stream (ipad & buf) generated in step 3

		GET_WORD_32_BE(W.s0, ipad, 0);
		GET_WORD_32_BE(W.s1, ipad, 1);
		GET_WORD_32_BE(W.s2, ipad, 2);
		GET_WORD_32_BE(W.s3, ipad, 3);
		GET_WORD_32_BE(W.s4, ipad, 4);
		GET_WORD_32_BE(W.s5, ipad, 5);
		GET_WORD_32_BE(W.s6, ipad, 6);
		GET_WORD_32_BE(W.s7, ipad, 7);
		GET_WORD_32_BE(W.s8, ipad, 8);
		GET_WORD_32_BE(W.s9, ipad, 9);
		GET_WORD_32_BE(W.sa, ipad, 10);
		GET_WORD_32_BE(W.sb, ipad, 11);
		GET_WORD_32_BE(W.sc, ipad, 12);
		GET_WORD_32_BE(W.sd, ipad, 13);
		GET_WORD_32_BE(W.se, ipad, 14);
		GET_WORD_32_BE(W.sf, ipad, 15);

		A = INIT_SHA1_A;
		B = INIT_SHA1_B;
		C = INIT_SHA1_C;
		D = INIT_SHA1_D;
		E = INIT_SHA1_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

		P(A, B, C, D, E, W.s0);
		P(E, A, B, C, D, W.s1);
		P(D, E, A, B, C, W.s2);
		P(C, D, E, A, B, W.s3);
		P(B, C, D, E, A, W.s4);
		P(A, B, C, D, E, W.s5);
		P(E, A, B, C, D, W.s6);
		P(D, E, A, B, C, W.s7);
		P(C, D, E, A, B, W.s8);
		P(B, C, D, E, A, W.s9);
		P(A, B, C, D, E, W.sa);
		P(E, A, B, C, D, W.sb);
		P(D, E, A, B, C, W.sc);
		P(C, D, E, A, B, W.sd);
		P(B, C, D, E, A, W.se);
		P(A, B, C, D, E, W.sf);
		P(E, A, B, C, D, R0);
		P(D, E, A, B, C, R1);
		P(C, D, E, A, B, R2);
		P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

		P(A, B, C, D, E, R4);
		P(E, A, B, C, D, R5);
		P(D, E, A, B, C, R6);
		P(C, D, E, A, B, R7);
		P(B, C, D, E, A, R8);
		P(A, B, C, D, E, R9);
		P(E, A, B, C, D, RA);
		P(D, E, A, B, C, RB);
		P(C, D, E, A, B, RC);
		P(B, C, D, E, A, RD);
		P(A, B, C, D, E, RE);
		P(E, A, B, C, D, RF);
		P(D, E, A, B, C, R0);
		P(C, D, E, A, B, R1);
		P(B, C, D, E, A, R2);
		P(A, B, C, D, E, R3);
		P(E, A, B, C, D, R4);
		P(D, E, A, B, C, R5);
		P(C, D, E, A, B, R6);
		P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

		P(A, B, C, D, E, R8);
		P(E, A, B, C, D, R9);
		P(D, E, A, B, C, RA);
		P(C, D, E, A, B, RB);
		P(B, C, D, E, A, RC);
		P(A, B, C, D, E, RD);
		P(E, A, B, C, D, RE);
		P(D, E, A, B, C, RF);
		P(C, D, E, A, B, R0);
		P(B, C, D, E, A, R1);
		P(A, B, C, D, E, R2);
		P(E, A, B, C, D, R3);
		P(D, E, A, B, C, R4);
		P(C, D, E, A, B, R5);
		P(B, C, D, E, A, R6);
		P(A, B, C, D, E, R7);
		P(E, A, B, C, D, R8);
		P(D, E, A, B, C, R9);
		P(C, D, E, A, B, RA);
		P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

		P(A, B, C, D, E, RC);
		P(E, A, B, C, D, RD);
		P(D, E, A, B, C, RE);
		P(C, D, E, A, B, RF);
		P(B, C, D, E, A, R0);
		P(A, B, C, D, E, R1);
		P(E, A, B, C, D, R2)
		    P(D, E, A, B, C, R3);
		P(C, D, E, A, B, R4);
		P(B, C, D, E, A, R5);
		P(A, B, C, D, E, R6);
		P(E, A, B, C, D, R7);
		P(D, E, A, B, C, R8);
		P(C, D, E, A, B, R9);
		P(B, C, D, E, A, RA);
		P(A, B, C, D, E, RB);
		P(E, A, B, C, D, RC);
		P(D, E, A, B, C, RD);
		P(C, D, E, A, B, RE);
		P(B, C, D, E, A, RF);

#undef K
#undef F

		A += INIT_SHA1_A;
		B += INIT_SHA1_B;
		C += INIT_SHA1_C;
		D += INIT_SHA1_D;
		E += INIT_SHA1_E;

		state[0] = A;
		state[1] = B;
		state[2] = C;
		state[3] = D;
		state[4] = E;

		// process buf (2nd part of stream)

		GET_WORD_32_BE(W.s0, buf, 0);
		GET_WORD_32_BE(W.s1, buf, 1);
		GET_WORD_32_BE(W.s2, buf, 2);
		GET_WORD_32_BE(W.s3, buf, 3);
		GET_WORD_32_BE(W.s4, buf, 4);
		GET_WORD_32_BE(W.s5, buf, 5);
		GET_WORD_32_BE(W.s6, buf, 6);
		GET_WORD_32_BE(W.s7, buf, 7);
		GET_WORD_32_BE(W.s8, buf, 8);
		GET_WORD_32_BE(W.s9, buf, 9);
		GET_WORD_32_BE(W.sa, buf, 10);
		GET_WORD_32_BE(W.sb, buf, 11);
		GET_WORD_32_BE(W.sc, buf, 12);
		GET_WORD_32_BE(W.sd, buf, 13);
		GET_WORD_32_BE(W.se, buf, 14);
		GET_WORD_32_BE(W.sf, buf, 15);

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

		P(A, B, C, D, E, W.s0);
		P(E, A, B, C, D, W.s1);
		P(D, E, A, B, C, W.s2);
		P(C, D, E, A, B, W.s3);
		P(B, C, D, E, A, W.s4);
		P(A, B, C, D, E, W.s5);
		P(E, A, B, C, D, W.s6);
		P(D, E, A, B, C, W.s7);
		P(C, D, E, A, B, W.s8);
		P(B, C, D, E, A, W.s9);
		P(A, B, C, D, E, W.sa);
		P(E, A, B, C, D, W.sb);
		P(D, E, A, B, C, W.sc);
		P(C, D, E, A, B, W.sd);
		P(B, C, D, E, A, W.se);
		P(A, B, C, D, E, W.sf);
		P(E, A, B, C, D, R0);
		P(D, E, A, B, C, R1);
		P(C, D, E, A, B, R2);
		P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

		P(A, B, C, D, E, R4);
		P(E, A, B, C, D, R5);
		P(D, E, A, B, C, R6);
		P(C, D, E, A, B, R7);
		P(B, C, D, E, A, R8);
		P(A, B, C, D, E, R9);
		P(E, A, B, C, D, RA);
		P(D, E, A, B, C, RB);
		P(C, D, E, A, B, RC);
		P(B, C, D, E, A, RD);
		P(A, B, C, D, E, RE);
		P(E, A, B, C, D, RF);
		P(D, E, A, B, C, R0);
		P(C, D, E, A, B, R1);
		P(B, C, D, E, A, R2);
		P(A, B, C, D, E, R3);
		P(E, A, B, C, D, R4);
		P(D, E, A, B, C, R5);
		P(C, D, E, A, B, R6);
		P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

		P(A, B, C, D, E, R8);
		P(E, A, B, C, D, R9);
		P(D, E, A, B, C, RA);
		P(C, D, E, A, B, RB);
		P(B, C, D, E, A, RC);
		P(A, B, C, D, E, RD);
		P(E, A, B, C, D, RE);
		P(D, E, A, B, C, RF);
		P(C, D, E, A, B, R0);
		P(B, C, D, E, A, R1);
		P(A, B, C, D, E, R2);
		P(E, A, B, C, D, R3);
		P(D, E, A, B, C, R4);
		P(C, D, E, A, B, R5);
		P(B, C, D, E, A, R6);
		P(A, B, C, D, E, R7);
		P(E, A, B, C, D, R8);
		P(D, E, A, B, C, R9);
		P(C, D, E, A, B, RA);
		P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

		P(A, B, C, D, E, RC);
		P(E, A, B, C, D, RD);
		P(D, E, A, B, C, RE);
		P(C, D, E, A, B, RF);
		P(B, C, D, E, A, R0);
		P(A, B, C, D, E, R1);
		P(E, A, B, C, D, R2);
		P(D, E, A, B, C, R3);
		P(C, D, E, A, B, R4);
		P(B, C, D, E, A, R5);
		P(A, B, C, D, E, R6);
		P(E, A, B, C, D, R7);
		P(D, E, A, B, C, R8);
		P(C, D, E, A, B, R9);
		P(B, C, D, E, A, RA);
		P(A, B, C, D, E, RB);
		P(E, A, B, C, D, RC);
		P(D, E, A, B, C, RD);
		P(C, D, E, A, B, RE);
		P(B, C, D, E, A, RF);

#undef K
#undef F

		A += state[0];
		B += state[1];
		C += state[2];
		D += state[3];
		E += state[4];

		PUT_WORD_32_BE(A, buf, 0);
		PUT_WORD_32_BE(B, buf, 1);
		PUT_WORD_32_BE(C, buf, 2);
		PUT_WORD_32_BE(D, buf, 3);
		PUT_WORD_32_BE(E, buf, 4);

		buf[5] = 0x80 | (buf[5] & 0xffffff00);
		PUT_WORD_32_BE(0x2A0, buf, 15);

		// step 6: append the stream of data 'text' to the B byte sting resulting from step 2
		// first part of stream (64 bytes) is opad, second part of stream (64 bytes) is the H result from step 4

		// step 7: apply H to the stream (opad & buf) generated in step 6 and output the result

		GET_WORD_32_BE(W.s0, opad, 0);
		GET_WORD_32_BE(W.s1, opad, 1);
		GET_WORD_32_BE(W.s2, opad, 2);
		GET_WORD_32_BE(W.s3, opad, 3);
		GET_WORD_32_BE(W.s4, opad, 4);
		GET_WORD_32_BE(W.s5, opad, 5);
		GET_WORD_32_BE(W.s6, opad, 6);
		GET_WORD_32_BE(W.s7, opad, 7);
		GET_WORD_32_BE(W.s8, opad, 8);
		GET_WORD_32_BE(W.s9, opad, 9);
		GET_WORD_32_BE(W.sa, opad, 10);
		GET_WORD_32_BE(W.sb, opad, 11);
		GET_WORD_32_BE(W.sc, opad, 12);
		GET_WORD_32_BE(W.sd, opad, 13);
		GET_WORD_32_BE(W.se, opad, 14);
		GET_WORD_32_BE(W.sf, opad, 15);

		A = INIT_SHA1_A;
		B = INIT_SHA1_B;
		C = INIT_SHA1_C;
		D = INIT_SHA1_D;
		E = INIT_SHA1_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

		P(A, B, C, D, E, W.s0);
		P(E, A, B, C, D, W.s1);
		P(D, E, A, B, C, W.s2);
		P(C, D, E, A, B, W.s3);
		P(B, C, D, E, A, W.s4);
		P(A, B, C, D, E, W.s5);
		P(E, A, B, C, D, W.s6);
		P(D, E, A, B, C, W.s7);
		P(C, D, E, A, B, W.s8);
		P(B, C, D, E, A, W.s9);
		P(A, B, C, D, E, W.sa);
		P(E, A, B, C, D, W.sb);
		P(D, E, A, B, C, W.sc);
		P(C, D, E, A, B, W.sd);
		P(B, C, D, E, A, W.se);
		P(A, B, C, D, E, W.sf);
		P(E, A, B, C, D, R0);
		P(D, E, A, B, C, R1);
		P(C, D, E, A, B, R2);
		P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

		P(A, B, C, D, E, R4);
		P(E, A, B, C, D, R5);
		P(D, E, A, B, C, R6);
		P(C, D, E, A, B, R7);
		P(B, C, D, E, A, R8);
		P(A, B, C, D, E, R9);
		P(E, A, B, C, D, RA);
		P(D, E, A, B, C, RB);
		P(C, D, E, A, B, RC);
		P(B, C, D, E, A, RD);
		P(A, B, C, D, E, RE);
		P(E, A, B, C, D, RF);
		P(D, E, A, B, C, R0);
		P(C, D, E, A, B, R1);
		P(B, C, D, E, A, R2);
		P(A, B, C, D, E, R3);
		P(E, A, B, C, D, R4);
		P(D, E, A, B, C, R5);
		P(C, D, E, A, B, R6);
		P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

		P(A, B, C, D, E, R8);
		P(E, A, B, C, D, R9);
		P(D, E, A, B, C, RA);
		P(C, D, E, A, B, RB);
		P(B, C, D, E, A, RC);
		P(A, B, C, D, E, RD);
		P(E, A, B, C, D, RE);
		P(D, E, A, B, C, RF);
		P(C, D, E, A, B, R0);
		P(B, C, D, E, A, R1);
		P(A, B, C, D, E, R2);
		P(E, A, B, C, D, R3);
		P(D, E, A, B, C, R4);
		P(C, D, E, A, B, R5);
		P(B, C, D, E, A, R6);
		P(A, B, C, D, E, R7);
		P(E, A, B, C, D, R8);
		P(D, E, A, B, C, R9);
		P(C, D, E, A, B, RA);
		P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

		P(A, B, C, D, E, RC);
		P(E, A, B, C, D, RD);
		P(D, E, A, B, C, RE);
		P(C, D, E, A, B, RF);
		P(B, C, D, E, A, R0);
		P(A, B, C, D, E, R1);
		P(E, A, B, C, D, R2);
		P(D, E, A, B, C, R3);
		P(C, D, E, A, B, R4);
		P(B, C, D, E, A, R5);
		P(A, B, C, D, E, R6);
		P(E, A, B, C, D, R7);
		P(D, E, A, B, C, R8);
		P(C, D, E, A, B, R9);
		P(B, C, D, E, A, RA);
		P(A, B, C, D, E, RB);
		P(E, A, B, C, D, RC);
		P(D, E, A, B, C, RD);
		P(C, D, E, A, B, RE);
		P(B, C, D, E, A, RF);

#undef K
#undef F

		A += INIT_SHA1_A;
		B += INIT_SHA1_B;
		C += INIT_SHA1_C;
		D += INIT_SHA1_D;
		E += INIT_SHA1_E;

		// store state for 2nd part
		state[0] = A;
		state[1] = B;
		state[2] = C;
		state[3] = D;
		state[4] = E;

		GET_WORD_32_BE(W.s0, buf, 0);
		GET_WORD_32_BE(W.s1, buf, 1);
		GET_WORD_32_BE(W.s2, buf, 2);
		GET_WORD_32_BE(W.s3, buf, 3);
		GET_WORD_32_BE(W.s4, buf, 4);
		GET_WORD_32_BE(W.s5, buf, 5);
		GET_WORD_32_BE(W.s6, buf, 6);
		GET_WORD_32_BE(W.s7, buf, 7);
		GET_WORD_32_BE(W.s8, buf, 8);
		GET_WORD_32_BE(W.s9, buf, 9);
		GET_WORD_32_BE(W.sa, buf, 10);
		GET_WORD_32_BE(W.sb, buf, 11);
		GET_WORD_32_BE(W.sc, buf, 12);
		GET_WORD_32_BE(W.sd, buf, 13);
		GET_WORD_32_BE(W.se, buf, 14);
		GET_WORD_32_BE(W.sf, buf, 15);

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

		P(A, B, C, D, E, W.s0);
		P(E, A, B, C, D, W.s1);
		P(D, E, A, B, C, W.s2);
		P(C, D, E, A, B, W.s3);
		P(B, C, D, E, A, W.s4);
		P(A, B, C, D, E, W.s5);
		P(E, A, B, C, D, W.s6);
		P(D, E, A, B, C, W.s7);
		P(C, D, E, A, B, W.s8);
		P(B, C, D, E, A, W.s9);
		P(A, B, C, D, E, W.sa);
		P(E, A, B, C, D, W.sb);
		P(D, E, A, B, C, W.sc);
		P(C, D, E, A, B, W.sd);
		P(B, C, D, E, A, W.se);
		P(A, B, C, D, E, W.sf);
		P(E, A, B, C, D, R0);
		P(D, E, A, B, C, R1);
		P(C, D, E, A, B, R2);
		P(B, C, D, E, A, R3);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

		P(A, B, C, D, E, R4);
		P(E, A, B, C, D, R5);
		P(D, E, A, B, C, R6);
		P(C, D, E, A, B, R7);
		P(B, C, D, E, A, R8);
		P(A, B, C, D, E, R9);
		P(E, A, B, C, D, RA);
		P(D, E, A, B, C, RB);
		P(C, D, E, A, B, RC);
		P(B, C, D, E, A, RD);
		P(A, B, C, D, E, RE);
		P(E, A, B, C, D, RF);
		P(D, E, A, B, C, R0);
		P(C, D, E, A, B, R1);
		P(B, C, D, E, A, R2);
		P(A, B, C, D, E, R3);
		P(E, A, B, C, D, R4);
		P(D, E, A, B, C, R5);
		P(C, D, E, A, B, R6);
		P(B, C, D, E, A, R7);

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

		P(A, B, C, D, E, R8);
		P(E, A, B, C, D, R9);
		P(D, E, A, B, C, RA);
		P(C, D, E, A, B, RB);
		P(B, C, D, E, A, RC);
		P(A, B, C, D, E, RD);
		P(E, A, B, C, D, RE);
		P(D, E, A, B, C, RF);
		P(C, D, E, A, B, R0);
		P(B, C, D, E, A, R1);
		P(A, B, C, D, E, R2);
		P(E, A, B, C, D, R3);
		P(D, E, A, B, C, R4);
		P(C, D, E, A, B, R5);
		P(B, C, D, E, A, R6);
		P(A, B, C, D, E, R7);
		P(E, A, B, C, D, R8);
		P(D, E, A, B, C, R9);
		P(C, D, E, A, B, RA);
		P(B, C, D, E, A, RB);

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

		P(A, B, C, D, E, RC);
		P(E, A, B, C, D, RD);
		P(D, E, A, B, C, RE);
		P(C, D, E, A, B, RF);
		P(B, C, D, E, A, R0);
		P(A, B, C, D, E, R1);
		P(E, A, B, C, D, R2);
		P(D, E, A, B, C, R3);
		P(C, D, E, A, B, R4);
		P(B, C, D, E, A, R5);
		P(A, B, C, D, E, R6);
		P(E, A, B, C, D, R7);
		P(D, E, A, B, C, R8);
		P(C, D, E, A, B, R9);
		P(B, C, D, E, A, RA);
		P(A, B, C, D, E, RB);
		P(E, A, B, C, D, RC);
		P(D, E, A, B, C, RD);
		P(C, D, E, A, B, RE);
		P(B, C, D, E, A, RF);

#undef K
#undef F

		A += state[0];
		B += state[1];
		C += state[2];
		D += state[3];
		E += state[4];

		PUT_WORD_32_BE(A, temp_char, 0);
		PUT_WORD_32_BE(B, temp_char, 1);
		PUT_WORD_32_BE(C, temp_char, 2);
		PUT_WORD_32_BE(D, temp_char, 3);
		PUT_WORD_32_BE(E, temp_char, 4);


		/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		out[k] ^= temp_char[0];
		out[k + 1] ^= temp_char[1];
		out[k + 2] ^= temp_char[2];
		out[k + 3] ^= temp_char[3];

	}

	for (i = id, j = 0; i < 4 * num_keys; i = i + num_keys, j++)
		out_global[i] = out[j + k];



}
