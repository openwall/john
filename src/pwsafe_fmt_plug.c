/*
 * Password Safe and Password Gorilla cracker patch for JtR. Hacked together
 * during May of 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * Optimization patch during January of 2013 by Brian Wallace <brian.wallace9809 at gmail.com>.
 *
 * This software is Copyright (c) 2012-2013, Dhiru Kholia <dhiru.kholia at gmail.com> and
 * Brian Wallace <brian.wallace9809 at gmail.com> and it is hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pwsafe;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pwsafe);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "sha2.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "johnswap.h"
#include "pwsafe_common.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL            "pwsafe"
#define FORMAT_NAME             "Password Safe"
#define FORMAT_TAG              "$pwsafe$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "SHA256 " SHA256_ALGORITHM_NAME
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             32
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(int)

#ifdef SIMD_COEF_32
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#endif
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_32*SIMD_PARA_SHA256 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               32 // Tuned w/ MKPC for core i7
#endif

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$pwsafe$*" */
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.iterations = (unsigned int)atoi(p);
	MEM_FREE(keeptr);

	return (void *)&cs;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

#ifndef SIMD_COEF_32

#define rotl(x,y) ( x<<y | x>>(32-y) )
#define rotr(x,y) ( x>>y | x<<(32-y) )
#define CHOICE(x,y,z) ( z ^ (x & ( y ^ z)) )
#define MAJORITY(x,y,z) ( (x & y) | (z & (x | y)) )
#define ROTXOR1(x) (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22))
#define ROTXOR2(x) (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25))
#define ROTXOR3(x) (rotr(x,7) ^ rotr(x,18) ^ (x>>3))
#define ROTXOR4(x) (rotr(x,17) ^ rotr(x,19) ^ (x>>10))
#if ARCH_LITTLE_ENDIAN
#define bytereverse(x) ( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) )
#else
#define bytereverse(x) (x)
#endif

static void pwsafe_sha256_iterate(unsigned int * state, unsigned int iterations)
{
	unsigned int word00,word01,word02,word03,word04,word05,word06,word07;
	unsigned int word08,word09,word10,word11,word12,word13,word14,word15;
	unsigned int temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;

	iterations++;
	word00 = state[0];
	word01 = state[1];
	word02 = state[2];
	word03 = state[3];
	word04 = state[4];
	word05 = state[5];
	word06 = state[6];
	word07 = state[7];
	while (iterations) {
		iterations--;
		temp0 = 0x6a09e667UL;
		temp1 = 0xbb67ae85UL;
		temp2 = 0x3c6ef372UL;
		temp3 = 0xa54ff53aUL;
		temp4 = 0x510e527fUL;
		temp5 = 0x9b05688cUL;
		temp6 = 0x1f83d9abUL;
		temp7 = 0x5be0cd19UL;

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x428a2f98 + (word00);
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x71374491 + (word01);
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb5c0fbcf + (word02);
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xe9b5dba5 + (word03);
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x3956c25b + (word04);
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x59f111f1 + (word05);
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x923f82a4 + (word06);
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xab1c5ed5 + (word07);
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xd807aa98 + ( (word08 = 0x80000000U) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x12835b01 + ( (word09 = 0) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x243185be + ( (word10 = 0) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x550c7dc3 + ( (word11 = 0) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x72be5d74 + ( (word12 = 0) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x80deb1fe + ( (word13 = 0) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x9bdc06a7 + ( (word14 = 0) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc19bf174 + ( (word15 = 256) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );



		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xe49b69c1 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xefbe4786 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x0fc19dc6 + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x240ca1cc + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x2de92c6f + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4a7484aa + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5cb0a9dc + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x76f988da + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x983e5152 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa831c66d + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb00327c8 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xbf597fc7 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xc6e00bf3 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd5a79147 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x06ca6351 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x14292967 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x27b70a85 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x2e1b2138 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x4d2c6dfc + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x53380d13 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x650a7354 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x766a0abb + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x81c2c92e + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x92722c85 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xa2bfe8a1 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa81a664b + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xc24b8b70 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xc76c51a3 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xd192e819 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd6990624 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xf40e3585 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x106aa070 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x19a4c116 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x1e376c08 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x2748774c + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x34b0bcb5 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x391c0cb3 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4ed8aa4a + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5b9cca4f + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x682e6ff3 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x748f82ee + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x78a5636f + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x84c87814 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x8cc70208 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x90befffa + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xa4506ceb + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xbef9a3f7 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc67178f2 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		word00 = 0x6a09e667UL + temp0;
		word01 = 0xbb67ae85UL + temp1;
		word02 = 0x3c6ef372UL + temp2;
		word03 = 0xa54ff53aUL + temp3;
		word04 = 0x510e527fUL + temp4;
		word05 = 0x9b05688cUL + temp5;
		word06 = 0x1f83d9abUL + temp6;
		word07 = 0x5be0cd19UL + temp7;
	}
	state[0] = bytereverse(word00);
	state[1] = bytereverse(word01);
	state[2] = bytereverse(word02);
	state[3] = bytereverse(word03);
	state[4] = bytereverse(word04);
	state[5] = bytereverse(word05);
	state[6] = bytereverse(word06);
	state[7] = bytereverse(word07);
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index+=MIN_KEYS_PER_CRYPT) {
		SHA256_CTX ctx;
#ifdef SIMD_COEF_32
		unsigned int i;
		unsigned char _IBuf[64*MIN_KEYS_PER_CRYPT+MEM_ALIGN_CACHE], *keys, tmpBuf[32];
		uint32_t *keys32, j;

		keys = (unsigned char*)mem_align(_IBuf, MEM_ALIGN_CACHE);
		keys32 = (uint32_t*)keys;
		memset(keys, 0, 64*MIN_KEYS_PER_CRYPT);

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, saved_key[index+i], strlen(saved_key[index+i]));
			SHA256_Update(&ctx, cur_salt->salt, 32);
			SHA256_Final(tmpBuf, &ctx);
			for (j = 0; j < 32; ++j)
				keys[GETPOS(j, i)] = tmpBuf[j];
			keys[GETPOS(j, i)] = 0x80;
			// 32 bytes of crypt data (0x100 bits).
			keys[GETPOS(62, i)] = 0x01;
		}
		for (i = 0; i < cur_salt->iterations; i++) {
			SIMDSHA256body(keys, keys32, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);
		}
		// Last one with FLAT_OUT
		SIMDSHA256body(keys, crypt_out[index], NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT|SSEi_FLAT_OUT);
#else
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		SHA256_Update(&ctx, cur_salt->salt, 32);
		SHA256_Final((unsigned char*)crypt_out[index], &ctx);
#if 1
		// This complex crap only boosted speed on my quad-HT from 5016 to 5285.
		// A ton of complex code for VERY little gain. The SIMD change gave us
		// a 4x improvement with very little change. This pwsafe_sha256_iterate
		// does get 5% gain, but 400% is so much better, lol. I put the other
		// code in to be able to dump data out easier, getting dump_stuff()
		// data in flat, to be able to help get the SIMD code working.
		pwsafe_sha256_iterate(ctx.h, cur_salt->iterations);
		memcpy(crypt_out[index], ctx.h, 32);
#else
		{ int i;
		for (i = 0; i <= cur_salt->iterations; ++i) {
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, (unsigned char*)crypt_out[index], 32);
			SHA256_Final((unsigned char*)crypt_out[index], &ctx);
		} }
#endif
#endif
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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

static void pwsafe_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;

	return (unsigned int) my_salt->iterations;
}

struct fmt_main fmt_pwsafe = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		pwsafe_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		pwsafe_valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			iteration_count,
		},
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
		NULL,
		set_salt,
		pwsafe_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
