/*
* This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include "opencl_device_info.h"
#define uint8_t		unsigned char
#define uint32_t		unsigned int

#define PLAINTEXT_LENGTH	55
#define MIN(a,b)		(((a)<(b))?(a):(b))

#if gpu_amd(DEVICE_INFO)
#define Ch(x, y, z)	bitselect(z, y, x)
#define Maj(x, y, z)	bitselect(x, y, z ^ x)
#define ror(x, n)	rotate(x, (uint32_t) 32-n)
#define SWAP(n)	(as_uint(as_uchar4(n).s3210))
#else
#define Ch(x,y,z)	(z ^ (x & (y ^ z)))
#define Maj(x,y,z)	((x & y) | (z & (x | y)))
#define ror(x, n)	((x >> n) | (x << (32-n)))
#define SWAP(n) \
            (((n) << 24) | (((n) & 0xff00) << 8) |\
            (((n) >> 8) & 0xff00) | ((n) >> 24))
#endif

#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^(x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^(x>>10))

#define ROUND_A(a,b,c,d,e,f,g,h,ki,wi)\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));

#define ROUND_Z(a,b,c,d,e,f,g,h,ki)\
 t = (ki) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));

#define ROUND_B(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma1(wj) + sigma0(wk) + wl + wm;\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));

//0110
#define ROUND_I(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma0(wk) + wl;\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));
//1110
#define ROUND_J(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma1(wj) + sigma0(wk) + wl;\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));
//1011
#define ROUND_K(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma1(wj) + wl + wm;\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));
//1001
#define ROUND_L(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma1(wj)+ wm;\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));
//1101
#define ROUND_M(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma1(wj) + sigma0(wk) + wm;\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));

#define SHA256(A,B,C,D,E,F,G,H)\
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0]);\
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1]);\
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2]);\
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3]);\
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4]);\
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5]);\
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6]);\
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7]);\
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8]);\
	ROUND_A(H,A,B,C,D,E,F,G,k[9],W[9]);\
	ROUND_A(G,H,A,B,C,D,E,F,k[10],W[10]);\
	ROUND_A(F,G,H,A,B,C,D,E,k[11],W[11]);\
	ROUND_A(E,F,G,H,A,B,C,D,k[12],W[12]);\
	ROUND_A(D,E,F,G,H,A,B,C,k[13],W[13]);\
	ROUND_A(C,D,E,F,G,H,A,B,k[14],W[14]);\
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15]);\
	ROUND_B(A,B,C,D,E,F,G,H,k[16],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])

#define Z (0)
//W[9]-W[14] are zeros
#define SHA256_ZEROS(A,B,C,D,E,F,G,H)\
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0]);\
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1]);\
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2]);\
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3]);\
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4]);\
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5]);\
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6]);\
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7]);\
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8]);\
	ROUND_Z(H,A,B,C,D,E,F,G,k[9]);\
	ROUND_Z(G,H,A,B,C,D,E,F,k[10]);\
	ROUND_Z(F,G,H,A,B,C,D,E,k[11]);\
	ROUND_Z(E,F,G,H,A,B,C,D,k[12]);\
	ROUND_Z(D,E,F,G,H,A,B,C,k[13]);\
	ROUND_Z(C,D,E,F,G,H,A,B,k[14]);\
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15]);\
	ROUND_I(A,B,C,D,E,F,G,H,k[16],W[0],  Z,W[1],W[0],Z)\
	ROUND_J(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],Z)\
	ROUND_J(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],Z)\
	ROUND_J(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],Z)\
	ROUND_J(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],Z)\
	ROUND_J(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],Z)\
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_K(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],Z,W[8],W[1])\
	ROUND_L(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],Z,Z,W[2])\
	ROUND_L(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],Z,Z,W[3])\
	ROUND_L(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],Z,Z,W[4])\
	ROUND_L(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],Z,Z,W[5])\
	ROUND_L(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],Z,Z,W[6])\
	ROUND_M(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],Z,W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])

#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (uint) (b)[(i)    ] << 24 )        \
        | ( (uint) (b)[(i) + 1] << 16 )        \
        | ( (uint) (b)[(i) + 2] <<  8 )        \
        | ( (uint) (b)[(i) + 3]       );       \
}

#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = (uchar) ( (n) >> 24 );       \
    (b)[(i) + 1] = (uchar) ( (n) >> 16 );       \
    (b)[(i) + 2] = (uchar) ( (n) >>  8 );       \
    (b)[(i) + 3] = (uchar) ( (n)       );       \
}

#if gpu_amd(DEVICE_INFO) || no_byte_addressable(DEVICE_INFO)
#define XORCHAR_BE(buf, index, val) (buf)[(index)>>2] = ((buf)[(index)>>2]) ^ ((val) << ((((index) & 3) ^ 3) << 3))
#else
#define XORCHAR_BE(buf, index, val) ((uchar*)(buf))[(index) ^ 3] ^= (val)
#endif

__constant uint32_t h[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__constant uint32_t k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[8]; /** 256 bits **/
} crack_t;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	uint32_t rounds;  /** 12000 by default **/
} salt_t;

typedef struct {
	uint32_t ipad[8];
	uint32_t opad[8];
	uint32_t hash[8];
	uint32_t W[8];
	uint32_t rounds;
} state_t;

inline void preproc(__global const uint8_t * key, uint32_t keylen,
    uint32_t * state, uint32_t padding)
{
	uint j, t;
	uint32_t W[16];
	uint32_t A = h[0];
	uint32_t B = h[1];
	uint32_t C = h[2];
	uint32_t D = h[3];
	uint32_t E = h[4];
	uint32_t F = h[5];
	uint32_t G = h[6];
	uint32_t H = h[7];

	for (j = 0; j < 16; j++)
		W[j] = padding;

	for (j = 0; j < keylen; j++)
		XORCHAR_BE(W, j, key[j]);

	SHA256(A, B, C, D, E, F, G, H);

	state[0] = A + h[0];
	state[1] = B + h[1];
	state[2] = C + h[2];
	state[3] = D + h[3];
	state[4] = E + h[4];
	state[5] = F + h[5];
	state[6] = G + h[6];
	state[7] = H + h[7];
}


inline void hmac_sha256(uint32_t * output, uint32_t * ipad_state,
    uint32_t * opad_state, __global const uint8_t * salt, int saltlen)
{
	uint32_t i, t;
	uint32_t W[16];
	uint32_t A, B, C, D, E, F, G, H;
	uint8_t buf[64];
	uint32_t *buf32 = (uint32_t *) buf;
	i = 64 / 4;
	while (i--)
		*buf32++ = 0;

	for (i = 0; i < saltlen; i++)
		buf[i] = salt[i];

	buf[saltlen + 3] = 0x1;
	buf[saltlen + 4] = 0x80;

	PUT_WORD_32_BE((uint32_t) ((64 + saltlen + 4) << 3), buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	for (i = 0; i < 16; i++)
		GET_WORD_32_BE(W[i], buf, i * 4);

	SHA256(A, B, C, D, E, F, G, H);

	A += ipad_state[0];
	B += ipad_state[1];
	C += ipad_state[2];
	D += ipad_state[3];
	E += ipad_state[4];
	F += ipad_state[5];
	G += ipad_state[6];
	H += ipad_state[7];


	W[0] = A;
	W[1] = B;
	W[2] = C;
	W[3] = D;
	W[4] = E;
	W[5] = F;
	W[6] = G;
	W[7] = H;
	W[8] = 0x80000000;
	W[15] = 0x300;
	for (i = 9; i < 15; i++)
		W[i] = 0;

	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];
	F = opad_state[5];
	G = opad_state[6];
	H = opad_state[7];

	SHA256(A, B, C, D, E, F, G, H);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];
	F += opad_state[5];
	G += opad_state[6];
	H += opad_state[7];


	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
	output[5] = F;
	output[6] = G;
	output[7] = H;
}




__kernel void pbkdf2_sha256_loop(__global state_t *state, __global crack_t *out)
{
	uint idx = get_global_id(0);
	uint i, round, rounds = state[idx].rounds;
	uint W[16];
	uint ipad_state[8];
	uint opad_state[8];
	uint tmp_out[8];
	uint A, B, C, D, E, F, G, H, t;

	for (i = 0; i < 8; i++) {
		W[i] = state[idx].W[i];
		ipad_state[i] = state[idx].ipad[i];
		opad_state[i] = state[idx].opad[i];
		tmp_out[i] = state[idx].hash[i];
	}

	for (round = 0; round < MIN(rounds,HASH_LOOPS); round++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];
		F = ipad_state[5];
		G = ipad_state[6];
		H = ipad_state[7];

		W[8] = 0x80000000;
		W[15] = 0x300;

		SHA256_ZEROS(A, B, C, D, E, F, G, H);

		A += ipad_state[0];
		B += ipad_state[1];
		C += ipad_state[2];
		D += ipad_state[3];
		E += ipad_state[4];
		F += ipad_state[5];
		G += ipad_state[6];
		H += ipad_state[7];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = F;
		W[6] = G;
		W[7] = H;
		W[8] = 0x80000000;
		W[15] = 0x300;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];
		F = opad_state[5];
		G = opad_state[6];
		H = opad_state[7];

		SHA256_ZEROS(A, B, C, D, E, F, G, H);

		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];
		F += opad_state[5];
		G += opad_state[6];
		H += opad_state[7];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = F;
		W[6] = G;
		W[7] = H;

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
		tmp_out[5] ^= F;
		tmp_out[6] ^= G;
		tmp_out[7] ^= H;
	}

	if(rounds >= HASH_LOOPS){ // there is still work to do
		state[idx].rounds = rounds - HASH_LOOPS;
		for(i = 0; i < 8; i++) {
			state[idx].hash[i] = tmp_out[i];
			state[idx].W[i] = W[i];
		}
	}
	else { // rounds == 0 - we're done
		for (i = 0; i < 8; i++)
			out[idx].hash[i] = SWAP(tmp_out[i]);
	}
}



__kernel void pbkdf2_sha256_kernel(__global const pass_t * inbuffer,
    __global const salt_t * gsalt, __global state_t * state)
{

	uint ipad_state[8];
	uint opad_state[8];
	uint tmp_out[8];
	uint i, idx = get_global_id(0);

	__global const uchar *pass = inbuffer[idx].v;
	__global const uchar *salt = gsalt->salt;
	uint passlen = inbuffer[idx].length;
	uint saltlen = gsalt->length;
	state[idx].rounds = gsalt->rounds - 1;

	preproc(pass, passlen, ipad_state, 0x36363636);
	preproc(pass, passlen, opad_state, 0x5c5c5c5c);

	hmac_sha256(tmp_out, ipad_state, opad_state, salt, saltlen);

	for(i=0; i < 8; i++) {
		state[idx].ipad[i] = ipad_state[i];
		state[idx].opad[i] = opad_state[i];
		state[idx].hash[i] = tmp_out[i];
		state[idx].W[i] = tmp_out[i];
	}
}
