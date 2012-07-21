/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/
#ifndef _MSCASH2_H
#define _MSCASH2_H

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

#define THREADS			128//set at least 256 on fermi
#define BLOCKS			14
#define	KEYS_PER_CRYPT		(THREADS)*(BLOCKS)

#define BINARY_SIZE		16
#define PLAINTEXT_LENGTH	27
#define SALT_SIZE		sizeof(mscash2_salt)

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

#define MAX(x,y)		((x) > (y) ? (x) : (y))
#define MIN(x,y)		((x) < (y) ? (x) : (y))
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

#define ITERATIONS		10240

#define INIT_A			0x67452301
#define INIT_B			0xefcdab89
#define INIT_C			0x98badcfe
#define INIT_D			0x10325476
#define INIT_E			0xc3d2e1f0

#define SQRT_2			0x5a827999
#define SQRT_3			0x6ed9eba1

#define SHA1_DIGEST_LENGTH	20

#define K1			0x5a827999
#define K2			0x6ed9eba1
#define K3			0x8f1bbcdc
#define K4			0xca62c1d6

#define F1(x,y,z)		(z ^ (x & (y ^ z)))
#define F2(x,y,z)		(x ^ y ^ z)
#define F3(x,y,z)		((x & y) | (z & (x | y)))
#define F4(x,y,z)		(x ^ y ^ z)

#ifndef GET_WORD_32_BE
#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P1(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F1(b,c,d) + K1 + x; b = S(b,30);        \
}

#define P2(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F2(b,c,d) + K2 + x; b = S(b,30);        \
}

#define P3(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F3(b,c,d) + K3 + x; b = S(b,30);        \
}

#define P4(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F4(b,c,d) + K4 + x; b = S(b,30);        \
}

#define SHA1(A,B,C,D,E,W) \
    P1(A, B, C, D, E, W[0] );\
    P1(E, A, B, C, D, W[1] );\
    P1(D, E, A, B, C, W[2] );\
    P1(C, D, E, A, B, W[3] );\
    P1(B, C, D, E, A, W[4] );\
    P1(A, B, C, D, E, W[5] );\
    P1(E, A, B, C, D, W[6] );\
    P1(D, E, A, B, C, W[7] );\
    P1(C, D, E, A, B, W[8] );\
    P1(B, C, D, E, A, W[9] );\
    P1(A, B, C, D, E, W[10]);\
    P1(E, A, B, C, D, W[11]);\
    P1(D, E, A, B, C, W[12]);\
    P1(C, D, E, A, B, W[13]);\
    P1(B, C, D, E, A, W[14]);\
    P1(A, B, C, D, E, W[15]);\
    P1(E, A, B, C, D, R(16));\
    P1(D, E, A, B, C, R(17));\
    P1(C, D, E, A, B, R(18));\
    P1(B, C, D, E, A, R(19));\
    P2(A, B, C, D, E, R(20));\
    P2(E, A, B, C, D, R(21));\
    P2(D, E, A, B, C, R(22));\
    P2(C, D, E, A, B, R(23));\
    P2(B, C, D, E, A, R(24));\
    P2(A, B, C, D, E, R(25));\
    P2(E, A, B, C, D, R(26));\
    P2(D, E, A, B, C, R(27));\
    P2(C, D, E, A, B, R(28));\
    P2(B, C, D, E, A, R(29));\
    P2(A, B, C, D, E, R(30));\
    P2(E, A, B, C, D, R(31));\
    P2(D, E, A, B, C, R(32));\
    P2(C, D, E, A, B, R(33));\
    P2(B, C, D, E, A, R(34));\
    P2(A, B, C, D, E, R(35));\
    P2(E, A, B, C, D, R(36));\
    P2(D, E, A, B, C, R(37));\
    P2(C, D, E, A, B, R(38));\
    P2(B, C, D, E, A, R(39));\
    P3(A, B, C, D, E, R(40));\
    P3(E, A, B, C, D, R(41));\
    P3(D, E, A, B, C, R(42));\
    P3(C, D, E, A, B, R(43));\
    P3(B, C, D, E, A, R(44));\
    P3(A, B, C, D, E, R(45));\
    P3(E, A, B, C, D, R(46));\
    P3(D, E, A, B, C, R(47));\
    P3(C, D, E, A, B, R(48));\
    P3(B, C, D, E, A, R(49));\
    P3(A, B, C, D, E, R(50));\
    P3(E, A, B, C, D, R(51));\
    P3(D, E, A, B, C, R(52));\
    P3(C, D, E, A, B, R(53));\
    P3(B, C, D, E, A, R(54));\
    P3(A, B, C, D, E, R(55));\
    P3(E, A, B, C, D, R(56));\
    P3(D, E, A, B, C, R(57));\
    P3(C, D, E, A, B, R(58));\
    P3(B, C, D, E, A, R(59));\
    P4(A, B, C, D, E, R(60));\
    P4(E, A, B, C, D, R(61));\
    P4(D, E, A, B, C, R(62));\
    P4(C, D, E, A, B, R(63));\
    P4(B, C, D, E, A, R(64));\
    P4(A, B, C, D, E, R(65));\
    P4(E, A, B, C, D, R(66));\
    P4(D, E, A, B, C, R(67));\
    P4(C, D, E, A, B, R(68));\
    P4(B, C, D, E, A, R(69));\
    P4(A, B, C, D, E, R(70));\
    P4(E, A, B, C, D, R(71));\
    P4(D, E, A, B, C, R(72));\
    P4(C, D, E, A, B, R(73));\
    P4(B, C, D, E, A, R(74));\
    P4(A, B, C, D, E, R(75));\
    P4(E, A, B, C, D, R(76));\
    P4(D, E, A, B, C, R(77));\
    P4(C, D, E, A, B, R(78));\
    P4(B, C, D, E, A, R(79));

static const char mscash2_prefix[] = "$DCC2$";

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
	uint32_t dcc_hash[4];
} mscash2_password;

typedef struct {
	uint32_t v[8];
} mscash2_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[19];
	uint8_t unicode_salt[64];
} mscash2_salt;

#endif
