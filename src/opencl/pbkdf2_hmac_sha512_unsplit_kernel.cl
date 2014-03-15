/*
* This software is Copyright (c) 2012, 2013 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/

#define uint8_t  unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long int


/*# define SWAP64(n) \
  ((((uint64_t)(n)) << 56)                 \
   | ((((uint64_t)(n)) & 0xff00) << 40)    \
   | ((((uint64_t)(n)) & 0xff0000) << 24)  \
   | ((((uint64_t)(n)) & 0xff000000) << 8) \
   | ((((uint64_t)(n)) >> 8) & 0xff000000) \
   | ((((uint64_t)(n)) >> 24) & 0xff0000)  \
   | ((((uint64_t)(n)) >> 40) & 0xff00)    \
   | (((uint64_t)(n)) >> 56))

#define rol(x,n) ((x << n) | (x >> (64-n)))
#define ror(x,n) ((x >> n) | (x << (64-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
*/
        #define Ch(x,y,z)       bitselect(z, y, x)
        #define Maj(x,y,z)      bitselect(x, y, z ^ x)
        #define ror(x, n)       rotate(x, (64UL-n))
        #define SWAP64(n)       (as_ulong(as_uchar8(n).s76543210))

#define Sigma0(x) ((ror(x,28))  ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x) ((ror(x,14))  ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x) ((ror(x,1))  ^ (ror(x,8)) ^(x>>7))
#define sigma1(x) ((ror(x,19)) ^ (ror(x,61)) ^(x>>6))

#define INIT_A	0x6a09e667f3bcc908UL
#define INIT_B	0xbb67ae8584caa73bUL
#define INIT_C	0x3c6ef372fe94f82bUL
#define INIT_D	0xa54ff53a5f1d36f1UL
#define INIT_E	0x510e527fade682d1UL
#define INIT_F	0x9b05688c2b3e6c1fUL
#define INIT_G	0x1f83d9abfb41bd6bUL
#define INIT_H	0x5be0cd19137e2179UL


#define ROUND_A(a,b,c,d,e,f,g,h,ki,wi)\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));\

#define ROUND_B(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma1(wj) + sigma0(wk) + wl + wm;\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));\

#define SHA512(a, b, c, d, e, f, g, h)\
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0])\
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1])\
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2])\
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3])\
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4])\
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5])\
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6])\
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7])\
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8])\
	ROUND_A(H,A,B,C,D,E,F,G,k[9],W[9])\
	ROUND_A(G,H,A,B,C,D,E,F,k[10],W[10])\
	ROUND_A(F,G,H,A,B,C,D,E,k[11],W[11])\
	ROUND_A(E,F,G,H,A,B,C,D,k[12],W[12])\
	ROUND_A(D,E,F,G,H,A,B,C,k[13],W[13])\
	ROUND_A(C,D,E,F,G,H,A,B,k[14],W[14])\
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15])\
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
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])\
	ROUND_B(A,B,C,D,E,F,G,H,k[64],W[0],  W[14],W[1],W[0],W[9])\
	ROUND_B(H,A,B,C,D,E,F,G,k[65],W[1],  W[15],W[2],W[1],W[10])\
	ROUND_B(G,H,A,B,C,D,E,F,k[66],W[2],  W[0],W[3],W[2],W[11])\
	ROUND_B(F,G,H,A,B,C,D,E,k[67],W[3],  W[1],W[4],W[3],W[12])\
	ROUND_B(E,F,G,H,A,B,C,D,k[68],W[4],  W[2],W[5],W[4],W[13])\
	ROUND_B(D,E,F,G,H,A,B,C,k[69],W[5],  W[3],W[6],W[5],W[14])\
	ROUND_B(C,D,E,F,G,H,A,B,k[70],W[6],  W[4],W[7],W[6],W[15])\
	ROUND_B(B,C,D,E,F,G,H,A,k[71],W[7],  W[5],W[8],W[7],W[0])\
	ROUND_B(A,B,C,D,E,F,G,H,k[72],W[8],  W[6],W[9],W[8],W[1])\
	ROUND_B(H,A,B,C,D,E,F,G,k[73],W[9],  W[7],W[10],W[9],W[2])\
	ROUND_B(G,H,A,B,C,D,E,F,k[74],W[10],  W[8],W[11],W[10],W[3])\
	ROUND_B(F,G,H,A,B,C,D,E,k[75],W[11],  W[9],W[12],W[11],W[4])\
	ROUND_B(E,F,G,H,A,B,C,D,k[76],W[12],  W[10],W[13],W[12],W[5])\
	ROUND_B(D,E,F,G,H,A,B,C,k[77],W[13],  W[11],W[14],W[13],W[6])\
	ROUND_B(C,D,E,F,G,H,A,B,k[78],W[14],  W[12],W[15],W[14],W[7])\
	ROUND_B(B,C,D,E,F,G,H,A,k[79],W[15],  W[13],W[0],W[15],W[8])

#define GET_WORD_64(n,b,i)\
{\
    (n) = ( (uint64_t) (b)[(i)    ] << 56 )\
        | ( (uint64_t) (b)[(i) + 1] << 48 )\
        | ( (uint64_t) (b)[(i) + 2] << 40 )\
        | ( (uint64_t) (b)[(i) + 3] << 32 )\
        | ( (uint64_t) (b)[(i) + 4] << 24 )\
        | ( (uint64_t) (b)[(i) + 5] << 16 )\
        | ( (uint64_t) (b)[(i) + 6] <<  8 )\
        | ( (uint64_t) (b)[(i) + 7]       );\
}

#define PUT_WORD_64(n,b,i)\
{\
    (b)[(i)    ] = (uint8_t) ( (n) >> 56 );\
    (b)[(i) + 1] = (uint8_t) ( (n) >> 48 );\
    (b)[(i) + 2] = (uint8_t) ( (n) >> 40 );\
    (b)[(i) + 3] = (uint8_t) ( (n) >> 32 );\
    (b)[(i) + 4] = (uint8_t) ( (n) >> 24 );\
    (b)[(i) + 5] = (uint8_t) ( (n) >> 16 );\
    (b)[(i) + 6] = (uint8_t) ( (n) >>  8 );\
    (b)[(i) + 7] = (uint8_t) ( (n)       );\
}
__constant uint64_t k[] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

typedef struct {
	uint8_t length;
	uint8_t v[15];
} pbkdf2_password;

typedef struct {
	uint64_t hash[8];
} pbkdf2_hash;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	uint32_t rounds;

} pbkdf2_salt;

inline void preproc(__global const uint8_t * key, uint32_t keylen,
    uint64_t * state, uint8_t var1, uint64_t var4)
{
	int i;
	uint64_t W[16],t;
	uint8_t ipad[16];

	uint64_t A = INIT_A;
	uint64_t B = INIT_B;
	uint64_t C = INIT_C;
	uint64_t D = INIT_D;
	uint64_t E = INIT_E;
	uint64_t F = INIT_F;
	uint64_t G = INIT_G;
	uint64_t H = INIT_H;


	for (i = 0; i < keylen; i++)
		ipad[i] = var1 ^ key[i];
	for (i = keylen; i < 16; i++)
		ipad[i] = var1;


	for (i = 0; i < 2; i++)
		GET_WORD_64(W[i], ipad, i * 8);

	for (i = 2; i < 16; i++)
		W[i] = var4;

	SHA512(A, B, C, D, E, F, G, H);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;
	state[5] = F + INIT_F;
	state[6] = G + INIT_G;
	state[7] = H + INIT_H;
}


inline void hmac_sha512(uint64_t * output,
    uint64_t * ipad_state, uint64_t * opad_state, __global const uint8_t * salt,
    int saltlen)
{
	uint32_t i;
	uint64_t W[16],t;
	uint64_t A, B, C, D, E, F, G, H;
	uint8_t buf[128];
	uint64_t *buf64 = (uint64_t *) buf;
	i = 128 / 8;
	while (i--)
		*buf64++ = 0;
	buf64 = (uint64_t *) buf;

	for(i=0;i<saltlen;i++)
		buf[i]=salt[i];

	buf[saltlen + 0] = (1 & 0xff000000) >> 24;
	buf[saltlen + 1] = (1 & 0x00ff0000) >> 16;
	buf[saltlen + 2] = (1 & 0x0000ff00) >> 8;
	buf[saltlen + 3] = (1 & 0x000000ff) >> 0;

	saltlen += 4;
	buf[saltlen] = 0x80;

	PUT_WORD_64((uint64_t) ((128 + saltlen) << 3), buf, 120);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	for (i = 0; i < 16; i++)
		GET_WORD_64(W[i], buf, i * 8);


	SHA512(A, B, C, D, E, F, G, H);

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
	W[8] = 0x8000000000000000UL;
	W[15] = 0x600;
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

	SHA512(A, B, C, D, E, F, G, H);

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


inline void big_hmac_sha512(uint64_t * input, uint32_t rounds,
    uint64_t * ipad_state, uint64_t * opad_state, uint64_t * tmp_out)
{
	int i, round;
	uint64_t W[16],t;
	uint64_t A, B, C, D, E, F, G, H;

	for (i = 0; i < 8; i++)
		W[i] = input[i];

	for (round = 1; round < rounds; round++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];
		F = ipad_state[5];
		G = ipad_state[6];
		H = ipad_state[7];

		W[8] = 0x8000000000000000UL;
		W[15] = 0x600;

		for (i = 9; i < 15; i++)
			W[i] = 0;

	SHA512(A, B, C, D, E, F, G, H);

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
		W[8] = 0x8000000000000000UL;
		W[15] = 0x600;

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


	SHA512(A, B, C, D, E, F, G, H);

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


	for (i = 0; i < 8; i++)
		tmp_out[i] = SWAP64(tmp_out[i]);
}


__kernel void pbkdf2_sha512_kernel(__global const pbkdf2_password * inbuffer,
	__global const pbkdf2_salt *gsalt,
	__global pbkdf2_hash * outbuffer)
{

	uint64_t ipad_state[8];
	uint64_t opad_state[8];
	uint64_t tmp_out[8];
	uint32_t  i;
	uint idx = get_global_id(0);

	__global const uint8_t *pass = inbuffer[idx].v;
	__global const uint8_t *salt = gsalt->salt;
	uint32_t passlen = inbuffer[idx].length;
	uint32_t saltlen = gsalt->length;
	uint32_t rounds = gsalt->rounds;

	preproc(pass, passlen, ipad_state, 0x36, 0x3636363636363636UL);
	preproc(pass, passlen, opad_state, 0x5c, 0x5c5c5c5c5c5c5c5cUL);

	hmac_sha512(tmp_out, ipad_state, opad_state, salt, saltlen);
	big_hmac_sha512(tmp_out, rounds, ipad_state, opad_state, tmp_out);

	for (i = 0; i < 8; i++)
		outbuffer[idx].hash[i] = tmp_out[i];
}




