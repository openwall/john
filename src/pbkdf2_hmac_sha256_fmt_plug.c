/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <ctype.h>
#include <string.h>
#include <assert.h>
#include "misc.h"
#include "arch.h"
#include "common.h"
#include "base64.h"
#include "formats.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE		24
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"PBKDF2-HMAC-SHA256"
#define FORMAT_NAME		""
#define ALGORITHM_NAME		"PBKDF2-SHA256"

#define BENCHMARK_COMMENT	", rounds=12000"
#define BENCHMARK_LENGTH	-1
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	2

#define BINARY_ALIGN		4
#define SALT_ALIGN		1

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

#define PLAINTEXT_LENGTH	55
#define SALT_LENGTH		50
#define BINARY_SIZE		32
#define	SALT_SIZE		sizeof(struct salt_t)
#define FMT_PREFIX		"$pbkdf2-sha256$"
#define MIN(a,b)		(((a)<(b))?(a):(b))

#define SWAP(n) \
            (((n) << 24)               | (((n) & 0xff00) << 8) |     \
            (((n) >> 8) & 0xff00)      | ((n) >> 24))

#define ror(x,n) ((x >> n) | (x << (32-n)))
#define Ch(x,y,z) ( z ^ (x & ( y ^ z)) )
#define Maj(x,y,z) ( (x & y) | (z & (x | y)) )
#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^(x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^(x>>10))

#define ROUND_A(a,b,c,d,e,f,g,h,ki,wi)\
 t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g));\
 d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c));

#define ROUND_B(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)\
 wi = sigma1(wj) + sigma0(wk) + wl + wm;\
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

#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}

#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

static struct salt_t {
	uint8_t length;
	uint8_t salt[SALT_LENGTH];
	uint32_t rounds;		// 12000 by default
	uint32_t hash[8];		// 256 bits
} *cur_salt;

static pass_t *host_pass;		// plaintexts
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static const uint32_t h[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t k[] = {
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

static struct fmt_tests tests[] = {

	// testcases generated by passlib, format: $pbkdf2-256$rounds$salt$checksum
	// salt and checksum are encoded in "adapted base64"
	{"$pbkdf2-sha256$12000$2NtbSwkhRChF6D3nvJfSGg$OEWLc4keep8Vx3S/WnXgsfalb9q0RQdS1s05LfalSG4", ""},
	{"$pbkdf2-sha256$12000$fK8VAoDQuvees5ayVkpp7Q$xfzKAoBR/Iaa68tjn.O8KfGxV.zdidcqEeDoTFvDz2A", "1"},
	{"$pbkdf2-sha256$12000$GoMQYsxZ6/0fo5QyhtAaAw$xQ9L6toKn0q245SIZKoYjCu/Fy15hwGme9.08hBde1w", "12"},
	{"$pbkdf2-sha256$12000$6r3XWgvh/D/HeA/hXAshJA$11YY39OaSkJuwb.ONKVy5ebCZ00i5f8Qpcgwfe3d5kY", "123"},
	{"$pbkdf2-sha256$12000$09q711rLmbMWYgwBIGRMqQ$kHdAHlnQ1i1FHKBCPLV0sA20ai2xtYA1Ev8ODfIkiQg", "1234"},
	{"$pbkdf2-sha256$12000$Nebce08pJcT43zuHUMo5Rw$bMW/EsVqy8tMaDecFwuZNEPVfQbXBclwN78okLrxJoA", "openwall"},
	{"$pbkdf2-sha256$12000$mtP6/39PSQlhzBmDsJZS6g$zUXxf/9XBGrkedXVwhpC9wLLwwKSvHX39QRz7MeojYE", "password"},
	{"$pbkdf2-sha256$12000$35tzjhGi9J5TSilF6L0XAg$MiJA1gPN1nkuaKPVzSJMUL7ucH4bWIQetzX/JrXRYpw", "pbkdf2-sha256"},
	{"$pbkdf2-sha256$12000$sxbCeE8pxVjL2ds7hxBizA$uIiwKdo9DbPiiaLi1y3Ljv.r9G1tzxLRdlkD1uIOwKM", " 15 characters "},
	{"$pbkdf2-sha256$12000$CUGI8V7rHeP8nzMmhJDyXg$qjq3rBcsUgahqSO/W4B1bvsuWnrmmC4IW8WKMc5bKYE", " 16 characters__"},
	{"$pbkdf2-sha256$12000$FmIM4VxLaY1xLuWc8z6n1A$OVe6U1d5dJzYFKlJsZrW1NzUrfgiTpb9R5cAfn96WCk", " 20 characters______"},
	{"$pbkdf2-sha256$12000$fA8BAMAY41wrRQihdO4dow$I9BSCuV6UjG55LktTKbV.bIXtyqKKNvT3uL7JQwMLp8", " 24 characters______1234"},
	{"$pbkdf2-sha256$12000$/j8npJTSOmdMKcWYszYGgA$PbhiSNRzrELfAavXEsLI1FfitlVjv9NIB.jU1HHRdC8", " 28 characters______12345678"},
	{"$pbkdf2-sha256$12000$xfj/f6/1PkcIoXROCeE8Bw$ci.FEcPOKKKhX5b3JwzSDo6TGuYjgj1jKfCTZ9UpDM0", " 32 characters______123456789012"},
	{"$pbkdf2-sha256$12000$6f3fW8tZq7WWUmptzfmfEw$GDm/yhq1TnNR1MVGy73UngeOg9QJ7DtW4BnmV2F065s", " 40 characters______12345678901234567890"},
	{"$pbkdf2-sha256$12000$dU5p7T2ndM7535tzjpGyVg$ILbppLkipmonlfH1I2W3/vFMyr2xvCI8QhksH8DWn/M", " 55 characters______________________________________end"},
	{"$pbkdf2-sha256$12000$iDFmDCHE2FtrDaGUEmKMEaL0Xqv1/t/b.x.DcC6lFEI$tUdEcw3csCnsfiYbFdXH6nvbftH8rzvBDl1nABeN0nE", "salt length = 32"},
	{"$pbkdf2-sha256$12000$0zoHwNgbIwSAkDImZGwNQUjpHcNYa43xPqd0DuH8H0OIUWqttfY.h5DynvPeG.O8N.Y$.XK4LNIeewI7w9QF5g9p5/NOYMYrApW03bcv/MaD6YQ", "salt length = 50"},
	{"$pbkdf2-sha256$12000$HGPMeS9lTAkhROhd653Tuvc.ZyxFSOk9x5gTYgyBEAIAgND6PwfAmA$WdCipc7O/9tTgbpZvcz.mAkIDkdrebVKBUgGbncvoNw", "salt length = 40"},
	{NULL}
};

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	if (omp_t > 1) {
		self->params.min_keys_per_crypt *= omp_t;
		omp_t *= OMP_SCALE;
		self->params.max_keys_per_crypt *= omp_t;
	}
#endif
	host_pass =
	    mem_alloc_tiny(sizeof(pass_t) * self->params.max_keys_per_crypt,
	    MEM_ALIGN_CACHE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
	        self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void preproc(const uint8_t * key, uint32_t keylen, uint32_t * state,
    uint32_t padding)
{
	uint32_t W[16], t, i;
	uint32_t A = h[0];
	uint32_t B = h[1];
	uint32_t C = h[2];
	uint32_t D = h[3];
	uint32_t E = h[4];
	uint32_t F = h[5];
	uint32_t G = h[6];
	uint32_t H = h[7];

	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		((uint8_t *) W)[i ^ 3] ^= key[i];

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

static void hmac_sha256(uint32_t * output, uint32_t * ipad_state,
    uint32_t * opad_state, const uint8_t * salt, int saltlen, uint32_t rounds)
{
	uint32_t i, round;
	uint32_t W[16];
	uint32_t A, B, C, D, E, F, G, H, t;
	uint8_t buf[64];
	memset(buf, 0, 64);
	memcpy(buf, salt, saltlen);
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

	output[0] = W[0] = A;
	output[1] = W[1] = B;
	output[2] = W[2] = C;
	output[3] = W[3] = D;
	output[4] = W[4] = E;
	output[5] = W[5] = F;
	output[6] = W[6] = G;
	output[7] = W[7] = H;

	for (round = 1; round < rounds; round++) {

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

		for (i = 9; i < 15; i++)
			W[i] = 0;

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

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = F;
		W[6] = G;
		W[7] = H;

		output[0] ^= A;
		output[1] ^= B;
		output[2] ^= C;
		output[3] ^= D;
		output[4] ^= E;
		output[5] ^= F;
		output[6] ^= G;
		output[7] ^= H;
	}

	for (i = 0; i < 8; i++)
		output[i] = SWAP(output[i]);
}

static void pbkdf2_sha256(uint32_t count)
{
	uint32_t i;
	uint8_t *salt = cur_salt->salt;
	uint32_t saltlen = cur_salt->length;
	uint32_t rounds = cur_salt->rounds;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		uint8_t *pass = host_pass[i].v;
		uint32_t passlen = host_pass[i].length;
		uint32_t ipad_state[8];
		uint32_t opad_state[8];

		preproc(pass, passlen, ipad_state, 0x36363636);
		preproc(pass, passlen, opad_state, 0x5c5c5c5c);
		hmac_sha256(crypt_out[i], ipad_state, opad_state, salt, saltlen,
		    rounds);
	}
}

static int isabase64(char a)
{
	int ret = 0;
	if (a >= 'a' && a <= 'z')
		ret = 1;
	if (a >= 'A' && a <= 'Z')
		ret = 1;
	if (a >= '0' && a <= '9')
		ret = 1;
	if (a == '.' || a == '/')
		ret = 1;
	return ret;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int saltlen = 0;
	char *p, *c = ciphertext;
	if (strncmp(ciphertext, FMT_PREFIX, strlen(FMT_PREFIX) != 0))
		return 0;
	if (strlen(ciphertext) < 44 + strlen(FMT_PREFIX))
		return 0;
	c += strlen(FMT_PREFIX);
	if (strtol(c, NULL, 10) == 0)
		return 0;
	c = strchr(c, '$');
	if (c == NULL)
		return 0;
	c++;
	p = strchr(c, '$');
	if (p == NULL)
		return 0;
	while (c < p) {
		if (!isabase64(*c++))
			return 0;
		saltlen++;
	}
	saltlen = saltlen * 3 / 4;
	if (saltlen > SALT_LENGTH)
		return 0;
	c++;
	if (strlen(c) != 43)
		return 0;
	while (*c)
		if (!isabase64(*c++))
			return 0;
	return 1;
}

/* adapted base64 encoding used by passlib - s/./+/ and trim padding */
static void abase64_decode(const char *in, int length, char *out)
{
	int i;
	static char hash[70 + 1];
#ifdef DEBUG
	assert(length <= 70);
	assert(length % 4 != 1);
#endif
	memset(hash, '=', 70);
	memcpy(hash, in, length);
	for (i = 0; i < length; i++)
		if (hash[i] == '.')
			hash[i] = '+';
	switch (length % 4) {
	case 2:
		length += 2;
		break;
	case 3:
		length++;
		break;
	}
	hash[length] = 0;
	base64_decode(hash, length, out);
}

static void *binary(char *ciphertext)
{
	static char ret[256 / 8];
	char *c = ciphertext;
	c += strlen(FMT_PREFIX) + 1;
	c = strchr(c, '$') + 1;
	c = strchr(c, '$') + 1;
#ifdef DEBUG
	assert(strlen(c) == 43);
#endif
	abase64_decode(c, 43, ret);
	return ret;
}

static void *get_salt(char *ciphertext)
{
	static struct salt_t salt;
	char *p, *c = ciphertext, *oc;
	c += strlen(FMT_PREFIX);
	salt.rounds = strtol(c, NULL, 10);
	c = strchr(c, '$') + 1;
	p = strchr(c, '$');
	salt.length = 0;
	oc = c;
	while (c++ < p)
		salt.length++;
	abase64_decode(oc, salt.length, (char *)salt.salt);
	salt.length = salt.length * 3 / 4;
	memcpy(salt.hash, (char *)binary(ciphertext), BINARY_SIZE);
	return (void *)&salt;
}

static void set_salt(void *salt)
{
	cur_salt = (struct salt_t *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count;
	count = *pcount;
	pbkdf2_sha256(count);

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void set_key(char *key, int index)
{
	int length = MIN(strlen(key), PLAINTEXT_LENGTH);
	memcpy(host_pass[index].v, key, length);
	host_pass[index].length = length;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
	ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
	return ret;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct salt_t * my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->rounds;
}
#endif

struct fmt_main fmt_pbkdf2_hmac_sha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	},{
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
