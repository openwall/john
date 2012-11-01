/*
 * Modified by Dhiru Kholia <dhiru at openwall.com> for ODF format.
 *
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted. */

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

typedef struct {
	uint8_t length;
	uint8_t v[24];
} odf_password;

typedef struct {
	uint32_t v[17];		// 16*4=64
} odf_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	int iterations;
} odf_salt;

# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

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

#define S(x,n) ((x << n) | ((x) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define R2(t)                                            \
(                                                       \
    S((W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
     W[(t - 14) & 0x0F] ^ W[ t      & 0x0F]),1)          \
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

#define PZ(a,b,c,d,e)                                  \
{                                                       \
    e += S(a,5) + F1(b,c,d) + K1 ; b = S(b,30);        \
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

#define SHA2BEG(A,B,C,D,E,W) \
    P1(A, B, C, D, E, W[0]);\
    P1(E, A, B, C, D, W[1]);\
    P1(D, E, A, B, C, W[2]);\
    P1(C, D, E, A, B, W[3]);\
    P1(B, C, D, E, A, W[4]);\
    P1(A, B, C, D, E, W[5]);\
    PZ(E, A, B, C, D);\
    PZ(D, E, A, B, C);\
    PZ(C, D, E, A, B);\
    PZ(B, C, D, E, A);\
    PZ(A, B, C, D, E);\
    PZ(E, A, B, C, D);\
    PZ(D, E, A, B, C);\
    PZ(C, D, E, A, B);\
    PZ(B, C, D, E, A);\
    P1(A, B, C, D, E, W[15]);\

#define Q16 (W[0] = S((W[2] ^ W[0]),1))
#define Q17 (W[1] = S((W[3] ^ W[1]),1))
#define Q18 (W[2] = S((W[15] ^ W[4] ^ W[2]),1))
#define Q19 (W[3] = S((W[0]  ^ W[5] ^ W[3]),1))
#define Q20 (W[4] = S((W[1]  ^ W[4]),1))
#define Q21 (W[5] = S((W[2] ^ W[5]),1))
#define Q22 (W[6] = S(W[3],1))
#define Q23 (W[7] = S((W[4] ^ W[15]),1))
#define Q24 (W[8] = S((W[5] ^ W[0]),1))
#define Q25 (W[9] = S((W[6] ^ W[1]),1))
#define Q26 (W[10] = S((W[7] ^ W[2]),1))
#define Q27 (W[11] = S((W[8] ^ W[3]),1))
#define Q28 (W[12] = S((W[9] ^ W[4]),1))
#define Q29 (W[13] = S((W[10] ^ W[5] ^ W[15]),1))
#define Q30 (W[14] = S((W[11] ^ W[6] ^ W[0]),1))
#define SHA2END(A,B,C,D,E,W)\
    P1(E, A, B, C, D, Q16);\
    P1(D, E, A, B, C, Q17);\
    P1(C, D, E, A, B, Q18);\
    P1(B, C, D, E, A, Q19);\
    P2(A, B, C, D, E, Q20);\
    P2(E, A, B, C, D, Q21);\
    P2(D, E, A, B, C, Q22);\
    P2(C, D, E, A, B, Q23);\
    P2(B, C, D, E, A, Q24);\
    P2(A, B, C, D, E, Q25);\
    P2(E, A, B, C, D, Q26);\
    P2(D, E, A, B, C, Q27);\
    P2(C, D, E, A, B, Q28);\
    P2(B, C, D, E, A, Q29);\
    P2(A, B, C, D, E, Q30);\
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
    P4(D, E, A, B, C, R2(77));\
    P4(C, D, E, A, B, R2(78));\
    P4(B, C, D, E, A, R2(79));

#define  SHA2(A,B,C,D,E,W) SHA2BEG(A,B,C,D,E,W) SHA2END(A,B,C,D,E,W)


inline void preproc(__global const uint8_t * key, uint32_t keylen,
    __private uint32_t * state, uint8_t var1, uint32_t var4)
{
	uint32_t i;
	uint32_t W[16], temp;
	uint8_t ipad[20];

	for (i = 0; i < keylen; i++)
		ipad[i] = var1 ^ key[i];
	for (i = keylen; i < 20; i++)
		ipad[i] = var1;

	for (i = 0; i < 5; i++)
		GET_WORD_32_BE(W[i], ipad, i * 4);

	for (i = 5; i < 16; i++)
		W[i] = var4;

	uint32_t A = INIT_A;
	uint32_t B = INIT_B;
	uint32_t C = INIT_C;
	uint32_t D = INIT_D;
	uint32_t E = INIT_E;

	SHA1(A, B, C, D, E, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;

}

inline void hmac_sha1_(__private uint32_t * output,
    __private uint32_t * ipad_state,
    __private uint32_t * opad_state,
    __global const uint8_t * salt, int saltlen, uint8_t add)
{
	int i;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;
	uint8_t buf[64];
	uint32_t *src = (uint32_t *) buf;
	i = 64 / 4;
	while (i--)
		*src++ = 0;
	//memcpy(buf, salt, saltlen);
	for (i = 0; i < saltlen; i++)
		buf[i] = salt[i];

	buf[saltlen + 4] = 0x80;
	buf[saltlen + 3] = add;
	PUT_WORD_32_BE((64 + saltlen + 4) << 3, buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += ipad_state[0];
	B += ipad_state[1];
	C += ipad_state[2];
	D += ipad_state[3];
	E += ipad_state[4];

	PUT_WORD_32_BE(A, buf, 0);
	PUT_WORD_32_BE(B, buf, 4);
	PUT_WORD_32_BE(C, buf, 8);
	PUT_WORD_32_BE(D, buf, 12);
	PUT_WORD_32_BE(E, buf, 16);
	PUT_WORD_32_BE(0, buf, 20);
	PUT_WORD_32_BE(0, buf, 24);


	buf[20] = 0x80;
	PUT_WORD_32_BE(0x2A0, buf, 60);

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA1(A, B, C, D, E, W);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
}



inline void big_hmac_sha1(__private uint32_t * input, uint32_t inputlen,
    __private uint32_t * ipad_state,
    __private uint32_t * opad_state, __private uint32_t * tmp_out, int iterations)
{
	int i, lo;
	uint32_t temp, W[16];
	uint32_t A, B, C, D, E;

	for (i = 0; i < 5; i++)
		W[i] = input[i];

	for (lo = 1; lo < iterations; lo++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];

		W[5] = 0x80000000;
		W[15] = 0x2A0;

		SHA2(A, B, C, D, E, W);

		A += ipad_state[0];
		B += ipad_state[1];
		C += ipad_state[2];
		D += ipad_state[3];
		E += ipad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = 0x80000000;
		W[15] = 0x2A0;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];

		SHA2(A, B, C, D, E, W);

		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
	}

	for (i = 0; i < 5; i++)
		tmp_out[i] = SWAP(tmp_out[i]);
}

inline void pbkdf2(__global const uint8_t * pass, int passlen,
    __global const uint8_t * salt, int saltlen, int n, __global uint32_t * out)
{
	uint32_t ipad_state[5];
	uint32_t opad_state[5];
	uint32_t tmp_out[5];
	int i;

	preproc(pass, passlen, ipad_state, 0x36, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c, 0x5c5c5c5c);

	uint8_t rnd = 0x01;
	__global unsigned char *dst = (__global unsigned char*)out;
	unsigned char *src;
	for (; rnd < 0x04;) {
		hmac_sha1_(tmp_out, ipad_state, opad_state, salt, saltlen,
		    rnd++);

		big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH, ipad_state,
		              opad_state, tmp_out, n);
		src = (unsigned char*)tmp_out;
		for(i = 0; i < 20; i++)
			dst[i] = src[i];
		dst+=(5*4);
	}
	hmac_sha1_(tmp_out, ipad_state, opad_state, salt, saltlen, 0x04);
	big_hmac_sha1(tmp_out, SHA1_DIGEST_LENGTH, ipad_state, opad_state,
	              tmp_out, n);
	for(i = 0; i < 6; i++)
		dst[i] = src[i];
}

__kernel void odf(__global const odf_password * inbuffer,
    __global odf_hash * outbuffer, __global const odf_salt * salt)
{
	uint32_t idx = get_global_id(0);

	pbkdf2(inbuffer[idx].v, inbuffer[idx].length,
	    salt->salt, salt->length, salt->iterations, outbuffer[idx].v);
}
