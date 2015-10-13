/*
* This software is Copyright (c) 2012 Sayantan Datta <std2048 at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
* Modified to support salts upto 19 characters. Bug in orginal code allowed only upto 8 characters.
*/
#include "opencl_device_info.h"
#include "opencl_misc.h"

#define SHA1_DIGEST_LENGTH          20

#define INIT_SHA1_A                 0x67452301
#define INIT_SHA1_B                 0xEFCDAB89
#define INIT_SHA1_C                 0x98BADCFE
#define INIT_SHA1_D                 0x10325476
#define INIT_SHA1_E                 0xC3D2E1F0

typedef struct {

	    unsigned int istate[5] ;
	    unsigned int ostate[5] ;
	    unsigned int buf[5] ;
	    unsigned int out[4] ;

} temp_buf ;

#ifndef GET_WORD_32_BE
#define GET_WORD_32_BE(n,b,i)				\
{							\
    (n) = ( (unsigned long) (b)[(i) ] << 24 )		\
        | ( (unsigned long) ((b)[(i) ] & 0xff00) << 8 )	\
        | ( (unsigned long) ((b)[(i) ] >> 8) & 0xff00 )	\
        | ( (unsigned long) (b)[(i) ] >> 24 );		\
}
#endif

#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n, b, i)				\
{							\
    (b)[(i) ] = ((unsigned char) ((n) >> 24 ))		\
	      | ((unsigned char) ((n) >> 16 )) << 8	\
	      | ((unsigned char) ((n) >>  8 )) << 16	\
	      | ((unsigned char) ((n))) << 24 ;		\
}
#endif


#define S1(x) rotate((x), (uint)1)
#define S5(x) rotate((x), (uint)5)
#define S30(x) rotate((x), (uint)30)


#define R0						\
(							\
    W[0] = S1((W[13] ^ W[8] ^ W[2] ^ W[0]))		\
)

#define R1						\
(							\
     W[1] = S1((W[14] ^ W[9] ^ W[3] ^ W[1]))		\
)

#define R2						\
(							\
     W[2] = S1((W[15] ^ W[10] ^ W[4] ^ W[2]))		\
)

#define R3						\
(							\
    W[3] = S1((W[0] ^ W[11] ^ W[5] ^ W[3]))		\
)

#define R4						\
(							\
    W[4] = S1((W[1] ^ W[12] ^ W[6] ^ W[4]))		\
)

#define R5						\
(							\
    W[5] = S1((W[2] ^ W[13] ^ W[7] ^ W[5]))		\
)

#define R6						\
(							\
    W[6] = S1((W[3] ^ W[14] ^ W[8] ^ W[6]))		\
)

#define R7						\
(							\
    W[7] = S1((W[4] ^ W[15] ^ W[9] ^ W[7]))		\
)

#define R8						\
(							\
   W[8] = S1((W[5] ^ W[0] ^ W[10] ^ W[8]))		\
)

#define R9						\
(							\
   W[9] = S1((W[6] ^ W[1] ^ W[11] ^ W[9]))		\
)

#define RA						\
(							\
   W[10] = S1((W[7] ^ W[2] ^ W[12] ^ W[10]))		\
)

#define RB						\
(							\
   W[11] = S1((W[8] ^ W[3] ^ W[13] ^ W[11]))		\
)

#define RC						\
(							\
   W[12] = S1((W[9] ^ W[4] ^ W[14] ^ W[12])) 		\
)

#define RD						\
(							\
   W[13] = S1(( W[10] ^ W[5] ^ W[15] ^ W[13]))		\
)

#define RE						\
(							\
   W[14] = S1((W[11] ^ W[6] ^ W[0] ^ W[14] ))		\
)

#define RF						\
(							\
   W[15] = S1((W[12] ^ W[7] ^ W[1] ^ W[15]))		\
)

#define Q0						\
(							\
    W[0] = S1((W[2] ^ W[0]))				\
)

#define Q1						\
(							\
     W[1] = S1((W[3] ^ W[1]))				\
)

#define Q2						\
(							\
     W[2] = S1((W[15] ^ W[4] ^ W[2]))			\
)

#define Q3						\
(							\
    W[3] = S1((W[0] ^ W[5] ^ W[3]))			\
)

#define Q4						\
(							\
    W[4] = S1((W[1] ^ W[4]))				\
)

#define Q5						\
(							\
    W[5] = S1((W[2] ^ W[5]))				\
)

#define Q6						\
(							\
    W[6] = S1(W[3])					\
)

#define Q7						\
(							\
    W[7] = S1((W[4] ^ W[15]))				\
)

#define Q8						\
(							\
   W[8] = S1((W[5] ^ W[0]))				\
)

#define Q9						\
(							\
   W[9] = S1((W[6] ^ W[1]))				\
)

#define QA						\
(							\
   W[10] = S1((W[7] ^ W[2]))				\
)

#define QB						\
(							\
   W[11] = S1((W[8] ^ W[3]))				\
)

#define QC						\
(							\
   W[12]  = S1((W[9] ^ W[4]))				\
)

#define QD						\
(							\
   W[13] = S1(( W[10] ^ W[5] ^ W[15]))			\
)

#define QE						\
(							\
   W[14] = S1((W[11] ^ W[6] ^ W[0]))			\
)

#define P(a,b,c,d,e,x)					\
{							\
    e += S5(a) + F(b,c,d) + K + x; b = S30(b);		\
}

#define PZ(a,b,c,d,e)					\
{							\
    e += S5(a) + F(b,c,d) + K ; b = S30(b);		\
}

#define SHA1_part0(A,B,C,D,E,W)				\
        P(A, B, C, D, E, W[0]);				\
	P(E, A, B, C, D, W[1]);				\
	P(D, E, A, B, C, W[2]);				\
	P(C, D, E, A, B, W[3]);				\
	P(B, C, D, E, A, W[4]);				\
	P(A, B, C, D, E, W[5]);				\
	P(E, A, B, C, D, W[6]);				\
	P(D, E, A, B, C, W[7]);				\
	P(C, D, E, A, B, W[8]);				\
	P(B, C, D, E, A, W[9]);				\
	P(A, B, C, D, E, W[10]);			\
	P(E, A, B, C, D, W[11]);			\
	P(D, E, A, B, C, W[12]);			\
	P(C, D, E, A, B, W[13]);			\
	P(B, C, D, E, A, W[14]);			\
	P(A, B, C, D, E, W[15]);			\
	P(E, A, B, C, D, R0);				\
	P(D, E, A, B, C, R1);				\
	P(C, D, E, A, B, R2);				\
	P(B, C, D, E, A, R3);

#define SHA1_part1(A,B,C,D,E) 				\
        P(A, B, C, D, E, R4);				\
	P(E, A, B, C, D, R5);				\
	P(D, E, A, B, C, R6);				\
	P(C, D, E, A, B, R7);				\
	P(B, C, D, E, A, R8);				\
	P(A, B, C, D, E, R9);				\
	P(E, A, B, C, D, RA);				\
	P(D, E, A, B, C, RB);				\
	P(C, D, E, A, B, RC);				\
	P(B, C, D, E, A, RD);				\
	P(A, B, C, D, E, RE);				\
	P(E, A, B, C, D, RF);				\
	P(D, E, A, B, C, R0);				\
	P(C, D, E, A, B, R1);				\
	P(B, C, D, E, A, R2);				\
	P(A, B, C, D, E, R3);				\
	P(E, A, B, C, D, R4);				\
	P(D, E, A, B, C, R5);				\
	P(C, D, E, A, B, R6);				\
	P(B, C, D, E, A, R7);

#define SHA1_part2(A,B,C,D,E)				\
        P(A, B, C, D, E, R8);				\
	P(E, A, B, C, D, R9);				\
	P(D, E, A, B, C, RA);				\
	P(C, D, E, A, B, RB);				\
	P(B, C, D, E, A, RC);				\
	P(A, B, C, D, E, RD);				\
	P(E, A, B, C, D, RE);				\
	P(D, E, A, B, C, RF);				\
	P(C, D, E, A, B, R0);				\
	P(B, C, D, E, A, R1);				\
	P(A, B, C, D, E, R2);				\
	P(E, A, B, C, D, R3);				\
	P(D, E, A, B, C, R4);				\
	P(C, D, E, A, B, R5);				\
	P(B, C, D, E, A, R6);				\
	P(A, B, C, D, E, R7);				\
	P(E, A, B, C, D, R8);				\
	P(D, E, A, B, C, R9);				\
	P(C, D, E, A, B, RA);				\
	P(B, C, D, E, A, RB);

#define SHA1_part3(A,B,C,D,E)				\
        P(A, B, C, D, E, RC);				\
	P(E, A, B, C, D, RD);				\
	P(D, E, A, B, C, RE);				\
	P(C, D, E, A, B, RF);				\
	P(B, C, D, E, A, R0);				\
	P(A, B, C, D, E, R1);				\
	P(E, A, B, C, D, R2);				\
	P(D, E, A, B, C, R3);				\
	P(C, D, E, A, B, R4);				\
	P(B, C, D, E, A, R5);				\
	P(A, B, C, D, E, R6);				\
	P(E, A, B, C, D, R7);				\
	P(D, E, A, B, C, R8);				\
	P(C, D, E, A, B, R9);				\
	P(B, C, D, E, A, RA);				\
	P(A, B, C, D, E, RB);				\
	P(E, A, B, C, D, RC);				\
	P(D, E, A, B, C, RD);				\
	P(C, D, E, A, B, RE);				\
	P(B, C, D, E, A, RF);

#define SHA1_digest_part0(A,B,C,D,E,W) 			\
        P(A, B, C, D, E, W[0]);				\
	P(E, A, B, C, D, W[1]);				\
	P(D, E, A, B, C, W[2]);				\
	P(C, D, E, A, B, W[3]);				\
	P(B, C, D, E, A, W[4]);				\
	P(A, B, C, D, E, W[5]);				\
	PZ(E, A, B, C, D);				\
	PZ(D, E, A, B, C);				\
	PZ(C, D, E, A, B);				\
	PZ(B, C, D, E, A);				\
	PZ(A, B, C, D, E);				\
	PZ(E, A, B, C, D);				\
	PZ(D, E, A, B, C);				\
	PZ(C, D, E, A, B);				\
	PZ(B, C, D, E, A);				\
	P(A, B, C, D, E, W[15]);			\
	P(E, A, B, C, D, Q0);				\
	P(D, E, A, B, C, Q1);				\
	P(C, D, E, A, B, Q2);				\
	P(B, C, D, E, A, Q3);


#define SHA1_digest_part1(A,B,C,D,E)			 \
        P(A, B, C, D, E, Q4);				 \
	P(E, A, B, C, D, Q5);				 \
	P(D, E, A, B, C, Q6);				 \
	P(C, D, E, A, B, Q7);				 \
	P(B, C, D, E, A, Q8);				 \
	P(A, B, C, D, E, Q9);				 \
	P(E, A, B, C, D, QA);				 \
	P(D, E, A, B, C, QB);				 \
	P(C, D, E, A, B, QC);				 \
	P(B, C, D, E, A, QD);				 \
	P(A, B, C, D, E, QE);				 \
	P(E, A, B, C, D, RF);				 \
	P(D, E, A, B, C, R0);				 \
	P(C, D, E, A, B, R1);				 \
	P(B, C, D, E, A, R2);				 \
	P(A, B, C, D, E, R3);				 \
	P(E, A, B, C, D, R4);				 \
	P(D, E, A, B, C, R5);				 \
	P(C, D, E, A, B, R6);				 \
	P(B, C, D, E, A, R7);

inline void SHA1(__private uint *A, __private uint *W) {
#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0xca)
#elif USE_BITSELECT
#define F(x, y, z) bitselect(z, y, x)
#elif HAVE_ANDNOT
#define F(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define F(x, y, z) (z ^ (x & (y ^ z)))
#endif
#define K 0x5A827999
	SHA1_part0(A[0], A[1], A[2], A[3], A[4], W) ;
#undef K
#undef F

#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0x96)
#else
#define F(x, y, z) (x ^ y ^ z)
#endif
#define K 0x6ED9EBA1
	SHA1_part1(A[0], A[1], A[2], A[3], A[4]) ;
#undef K
#undef F

#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0xe8)
#elif USE_BITSELECT
#define F(x, y, z) bitselect(x, y, (z) ^ (x))
#else
#define F(x, y, z) ((x & y) | (z & (x | y)))
#endif
#define K 0x8F1BBCDC
	SHA1_part2(A[0], A[1], A[2], A[3], A[4]) ;
#undef K
#undef F

#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0x96)
#else
#define F(x, y, z) (x ^ y ^ z)
#endif
#define K 0xCA62C1D6
	SHA1_part3(A[0], A[1], A[2], A[3], A[4]) ;
#undef K
#undef F
}

inline void SHA1_digest(__private uint *A, __private uint *W) {
#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0xca)
#elif USE_BITSELECT
#define F(x, y, z) bitselect(z, y, x)
#elif HAVE_ANDNOT
#define F(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define F(x, y, z) (z ^ (x & (y ^ z)))
#endif
#define K 0x5A827999
	SHA1_digest_part0(A[0], A[1], A[2], A[3], A[4], W) ;
#undef K
#undef F

#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0x96)
#else
#define F(x, y, z) (x ^ y ^ z)
#endif
#define K 0x6ED9EBA1
	SHA1_digest_part1(A[0], A[1], A[2], A[3], A[4]) ;
#undef K
#undef F

#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0xe8)
#elif USE_BITSELECT
#define F(x, y, z) bitselect(x, y, (z) ^ (x))
#else
#define F(x, y, z) ((x & y) | (z & (x | y)))
#endif
#define K 0x8F1BBCDC
	SHA1_part2(A[0], A[1], A[2], A[3], A[4]) ;
#undef K
#undef F

#if HAVE_LUT3
#define F(x, y, z) lut3(x, y, z, 0x96)
#else
#define F(x, y, z) (x ^ y ^ z)
#endif
#define K 0xCA62C1D6
	SHA1_part3(A[0], A[1], A[2], A[3], A[4]) ;
#undef K
#undef F
}

inline void sha1_pad(__private uint *pad, __private uint *state) {
	uint 		A[5], W[16] ;

	GET_WORD_32_BE(W[0], pad, 0) ;
	GET_WORD_32_BE(W[1], pad, 1) ;
	GET_WORD_32_BE(W[2], pad, 2) ;
	GET_WORD_32_BE(W[3], pad, 3) ;
	GET_WORD_32_BE(W[4], pad, 4) ;
	GET_WORD_32_BE(W[5], pad, 5) ;
	GET_WORD_32_BE(W[6], pad, 6) ;
	GET_WORD_32_BE(W[7], pad, 7) ;
	GET_WORD_32_BE(W[8], pad, 8) ;
	GET_WORD_32_BE(W[9], pad, 9) ;
	GET_WORD_32_BE(W[10], pad, 10) ;
	GET_WORD_32_BE(W[11], pad, 11) ;
	GET_WORD_32_BE(W[12], pad, 12) ;
	GET_WORD_32_BE(W[13], pad, 13) ;
	GET_WORD_32_BE(W[14], pad, 14) ;
	GET_WORD_32_BE(W[15], pad, 15) ;

	A[0] = INIT_SHA1_A ;
	A[1] = INIT_SHA1_B ;
	A[2] = INIT_SHA1_C ;
	A[3] = INIT_SHA1_D ;
	A[4] = INIT_SHA1_E ;

	SHA1(A, W) ;

	A[0] += INIT_SHA1_A ;
	A[1] += INIT_SHA1_B ;
	A[2] += INIT_SHA1_C ;
	A[3] += INIT_SHA1_D ;
	A[4] += INIT_SHA1_E ;

	state[0] = A[0] ;
	state[1] = A[1] ;
	state[2] = A[2] ;
	state[3] = A[3] ;
	state[4] = A[4] ;
}

inline void hmac_sha1(__private uint *istate, __private uint *ostate, __private uint *buf)
{
	uint	 A[5], W[16] ;

	A[0] = istate[0] ;
	A[1] = istate[1] ;
	A[2] = istate[2] ;
	A[3] = istate[3] ;
	A[4] = istate[4] ;

	GET_WORD_32_BE(W[0], buf, 0) ;
	GET_WORD_32_BE(W[1], buf, 1) ;
	GET_WORD_32_BE(W[2], buf, 2) ;
	GET_WORD_32_BE(W[3], buf, 3) ;
	GET_WORD_32_BE(W[4], buf, 4) ;
	GET_WORD_32_BE(W[5], buf, 5) ;
	GET_WORD_32_BE(W[6], buf, 6) ;
	GET_WORD_32_BE(W[7], buf, 7) ;
	GET_WORD_32_BE(W[8], buf, 8) ;
	GET_WORD_32_BE(W[9], buf, 9) ;
	GET_WORD_32_BE(W[10], buf, 10) ;
	GET_WORD_32_BE(W[11], buf, 11) ;
	GET_WORD_32_BE(W[12], buf, 12) ;
	GET_WORD_32_BE(W[13], buf, 13) ;
	GET_WORD_32_BE(W[14], buf, 14) ;
	GET_WORD_32_BE(W[15], buf, 15) ;

	SHA1(A, W) ;

	A[0] += istate[0] ;
	A[1] += istate[1] ;
	A[2] += istate[2] ;
	A[3] += istate[3] ;
	A[4] += istate[4] ;

	PUT_WORD_32_BE(A[0], buf, 0) ;
	PUT_WORD_32_BE(A[1], buf, 1) ;
	PUT_WORD_32_BE(A[2], buf, 2) ;
	PUT_WORD_32_BE(A[3], buf, 3) ;
	PUT_WORD_32_BE(A[4], buf, 4) ;

	buf[5] = 0x80 | (buf[5] & 0xffffff00) ;

	PUT_WORD_32_BE(0x2A0, buf, 15) ;

	A[0] = ostate[0] ;
	A[1] = ostate[1] ;
	A[2] = ostate[2] ;
	A[3] = ostate[3] ;
	A[4] = ostate[4] ;

	GET_WORD_32_BE(W[0], buf, 0) ;
	GET_WORD_32_BE(W[1], buf, 1) ;
	GET_WORD_32_BE(W[2], buf, 2) ;
	GET_WORD_32_BE(W[3], buf, 3) ;
	GET_WORD_32_BE(W[4], buf, 4) ;
	W[5] = 0x80000000 ;
        W[6] = 0 ;
	W[7] = 0 ;
	W[8] = 0 ;
	W[9] = 0 ;
	W[10] = 0 ;
	W[11] = 0 ;
	W[12] = 0 ;
	W[13] = 0 ;
	W[14] = 0 ;
	W[15] = 0x2A0 ;

	SHA1_digest(A, W) ;

	A[0] += ostate[0] ;
	A[1] += ostate[1] ;
	A[2] += ostate[2] ;
	A[3] += ostate[3] ;
	A[4] += ostate[4] ;

	buf[0] = A[0];
	buf[1] = A[1];
	buf[2] = A[2];
	buf[3] = A[3];
	buf[4] = A[4];
}

#define init_preprocess() 					\
	int id = get_global_id(0);				\
								\
	int i, j;						\
								\
	unsigned int pass[4];					\
								\
	unsigned int istate[5], ostate[5];			\
								\
	unsigned int ipad[16] = { IPAD, IPAD, IPAD, IPAD,	\
				  IPAD, IPAD, IPAD, IPAD,	\
				  IPAD, IPAD, IPAD, IPAD,	\
				  IPAD, IPAD, IPAD, IPAD };	\
	unsigned int opad[16] = { OPAD, OPAD, OPAD, OPAD,	\
				  OPAD, OPAD, OPAD, OPAD,	\
				  OPAD, OPAD, OPAD, OPAD,	\
				  OPAD, OPAD, OPAD, OPAD };	\
								\
	i = 4 * id;						\
        pass[0] = dccHahses[i++];				\
        pass[1] = dccHahses[i++];				\
        pass[2] = dccHahses[i++];				\
	pass[3] = dccHahses[i];				\
								\
	for (j = 0; j < 4; j++) {				\
		ipad[j] = ipad[j] ^ pass[j];			\
		opad[j] = opad[j] ^ pass[j];			\
	}							\
								\
	sha1_pad(ipad, istate);				\
	sha1_pad(opad, ostate);

#define IPAD	0x36363636
#define OPAD 	0x5C5C5C5C

__kernel
void pbkdf2_preprocess_short(	const __global unsigned int *dccHahses,
				constant unsigned int *salt
#if !defined(__OS_X__) && gpu_amd(DEVICE_INFO)
	__attribute__((max_constant_size(SALT_BUFFER_SIZE)))
#endif
				, int usrlen,
				__global temp_buf *tmp	)
{
	init_preprocess();

	unsigned int buf[16] = { 0 } ;

	if (usrlen & 1) {
		for (i = 0; i <= usrlen >> 1; i++)
			buf[i] = salt[i] ;
			buf[(usrlen >> 1) + 1] = 0x01 << 8 ;
	}
	else {
		for (i = 0; i < usrlen >> 1; i++)
			buf[i] = salt[i] ;
		buf[usrlen >> 1] = 0x01 << 24 ;
	}

	if (usrlen & 1)
		buf[(usrlen >> 1) + 1] = 0x80 << 16 | buf[(usrlen >> 1) + 1] ;
	else
		buf[(usrlen >> 1) + 1] = 0x80 | buf[(usrlen >> 1) + 1] ;

	PUT_WORD_32_BE((64 + (usrlen << 1) + 4) << 3, buf, 15) ;

	hmac_sha1(istate, ostate, buf) ;

	tmp[id].out[0] = buf[0] ;
	tmp[id].out[1] = buf[1] ;
	tmp[id].out[2] = buf[2] ;
	tmp[id].out[3] = buf[3] ;

	tmp[id].buf[0] = buf[0];
	tmp[id].buf[1] = buf[1] ;
	tmp[id].buf[2] = buf[2] ;
	tmp[id].buf[3] = buf[3] ;
	tmp[id].buf[4] = buf[4] ;

	for (i = 0; i< 5; i++) {
		tmp[id].istate[i] = istate[i] ;
		tmp[id].ostate[i] = ostate[i] ;
	}

}

__kernel
void pbkdf2_preprocess_long(	const __global unsigned int *dccHahses,
				__global temp_buf *tmp,
				__global unsigned int *sha1Hashes) {

	init_preprocess();

	unsigned int out[5];

	i = id * 5;
	out[0] = sha1Hashes[i++];
	out[1] = sha1Hashes[i++];
	out[2] = sha1Hashes[i++];
	out[3] = sha1Hashes[i++];
	out[4] = sha1Hashes[i];

	GET_WORD_32_BE(out[0], out, 0);
	GET_WORD_32_BE(out[1], out, 1);
	GET_WORD_32_BE(out[2], out, 2);
	GET_WORD_32_BE(out[3], out, 3);
	GET_WORD_32_BE(out[4], out, 4);

	tmp[id].buf[0] = out[0];
	tmp[id].buf[1] = out[1];
	tmp[id].buf[2] = out[2];
	tmp[id].buf[3] = out[3];
	tmp[id].buf[4] = out[4];

	tmp[id].out[0] = out[0];
	tmp[id].out[1] = out[1];
	tmp[id].out[2] = out[2];
	tmp[id].out[3] = out[3];

	for (i = 0; i< 5; i++) {
		tmp[id].istate[i] = istate[i] ;
		tmp[id].ostate[i] = ostate[i] ;
	}

}

#undef IPAD
#undef OPAD

__kernel
void pbkdf2_iter(__global temp_buf *tmp,
		uint itr_count ) {
	uint id = get_global_id(0);
	uint i;
	uint istate[5], ostate[5], buf[5], out[4];
	uint A[5], W[16];

	for (i = 0; i< 5; i++) {
		istate[i] = tmp[id].istate[i];
		ostate[i] = tmp[id].ostate[i];
		buf[i]    = tmp[id].buf[i];
	}

	out[0] = tmp[id].out[0];
	out[1] = tmp[id].out[1];
	out[2] = tmp[id].out[2];
	out[3] = tmp[id].out[3];

	for (i = 0; i < itr_count; i++) {
		W[0] = buf[0];
		W[1] = buf[1];
		W[2] = buf[2];
		W[3] = buf[3];
		W[4] = buf[4];
		W[5] = 0x80000000;
		W[6] = 0;
		W[7] = 0;
		W[8] = 0;
		W[9] = 0;
		W[10] = 0;
		W[11] = 0;
		W[12] = 0;
		W[13] = 0;
		W[14] = 0;
		W[15] = 0x2A0;

		A[0] = istate[0];
		A[1] = istate[1];
		A[2] = istate[2];
		A[3] = istate[3];
		A[4] = istate[4];

		SHA1_digest(A, W);

		W[0] = A[0] + istate[0];
		W[1] = A[1] + istate[1];
		W[2] = A[2] + istate[2];
		W[3] = A[3] + istate[3];
		W[4] = A[4] + istate[4];
		W[5] = 0x80000000;
		W[6] = 0;
		W[7] = 0;
		W[8] = 0;
		W[9] = 0;
		W[10] = 0;
		W[11] = 0;
		W[12] = 0;
		W[13] = 0;
		W[14] = 0;
		W[15] = 0x2A0;

		A[0] = ostate[0];
		A[1] = ostate[1];
		A[2] = ostate[2];
		A[3] = ostate[3];
		A[4] = ostate[4];

		SHA1_digest(A, W);

		buf[0] = A[0] + ostate[0];
		buf[1] = A[1] + ostate[1];
		buf[2] = A[2] + ostate[2];
		buf[3] = A[3] + ostate[3];
		buf[4] = A[4] + ostate[4];

		out[0] ^= buf[0];
		out[1] ^= buf[1];
		out[2] ^= buf[2];
		out[3] ^= buf[3];
	}

	tmp[id].buf[0] = buf[0];
	tmp[id].buf[1] = buf[1];
	tmp[id].buf[2] = buf[2];
	tmp[id].buf[3] = buf[3];
	tmp[id].buf[4] = buf[4];

	tmp[id].out[0] = out[0];
	tmp[id].out[1] = out[1];
	tmp[id].out[2] = out[2];
	tmp[id].out[3] = out[3];
}

__kernel
void pbkdf2_postprocess(__global temp_buf *tmp,
			__global unsigned int *out_global)
{
	uint id = get_global_id(0) ;
	uint i ;
	uint out[4] ;

	for (i = 0; i< 4; i++)
		out[i] = tmp[id].out[i] ;

	i = id * 4;
	PUT_WORD_32_BE(out[0], out_global, i++) ;
	PUT_WORD_32_BE(out[1], out_global, i++) ;
	PUT_WORD_32_BE(out[2], out_global, i++) ;
	PUT_WORD_32_BE(out[3], out_global, i) ;

}
