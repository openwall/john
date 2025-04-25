/*
 * AES OpenCL functions
 *
 * Copyright (c) 2017-2024, magnum.
 * This software is hereby released to the general public under
 * the following terms: Redistribution and use in source and binary
 * forms, with or without modification, are permitted.
 *
 * Derived from:
 * rijndael-alg-fst.c
 *
 * @version 3.0 (December 2000)
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 * @author Antoon Bosselaers <antoon.bosselaers@esat.kuleuven.ac.be>
 * @author Paulo Barreto <paulo.barreto@terra.com.br>
 */
#ifndef _AES_PLAIN
#define _AES_PLAIN

/*
 * Copy tables to local memory.
 */
#if gpu(DEVICE_INFO)
#define AES_LOCAL_TABLES
#endif

/*
 * This slows AMD down - doesn't make much of a difference elsewhere except it
 * seems to work around some auto-vectorizer bug in old Intel CPU runtimes.
 */
#if gpu_nvidia(DEVICE_INFO) || cpu_intel(DEVICE_INFO)
#define FULL_UNROLL
#endif

/*
 * Declare td4 as 32-bit repeated values, and use logical 'and' instead of shift
 */
#if gpu_amd(DEVICE_INFO)
#define TD4_32_BIT
#endif

#include "opencl_aes_tables.h"

#define AES_MAXNR   14

typedef struct aes_tables {
	u32 Te0[256];
	u32 Te1[256];
	u32 Te2[256];
	u32 Te3[256];
	u32 Td0[256];
	u32 Td1[256];
	u32 Td2[256];
	u32 Td3[256];
#ifdef TD4_32_BIT
	u32 Td4[256];
#else
	u8 Td4[256];
#endif
	u32 rcon[10];
} aes_local_t;

typedef struct aes_key_st {
	uint rd_key[4 * (AES_MAXNR + 1)];
	int rounds;
	__local aes_local_t *lt;
} AES_KEY;

#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

#define MAXKC   (256/32)
#define MAXKB   (256/8)

#ifdef AES_LOCAL_TABLES

#define THREAD      get_local_id(0)
#define LWS         get_local_size(0)

/**
 * Copy tables to local memory
 */
INLINE void aes_table_init(__local aes_local_t *lt)
{
	for (uint i = THREAD; i < 256; i += LWS) {
		lt->Te0[i] = Te0[i];
		lt->Te1[i] = Te1[i];
		lt->Te2[i] = Te2[i];
		lt->Te3[i] = Te3[i];
		lt->Td0[i] = Td0[i];
		lt->Td1[i] = Td1[i];
		lt->Td2[i] = Td2[i];
		lt->Td3[i] = Td3[i];
		lt->Td4[i] = Td4[i];
		if (i < 10)
			lt->rcon[i] = rcon[i];
	}

	barrier(CLK_LOCAL_MEM_FENCE);
}

/* Do not move from this spot */
#define Te0	lt->Te0
#define Te1	lt->Te1
#define Te2	lt->Te2
#define Te3	lt->Te3
#define Td0	lt->Td0
#define Td1	lt->Td1
#define Td2	lt->Td2
#define Td3	lt->Td3
#define Td4	lt->Td4
#define rcon lt->rcon

#endif	/* AES_LOCAL_TABLES */

/**
 * Expand the cipher key into the encryption key schedule.
 */
INLINE void AES_set_encrypt_key(AES_KEY_TYPE void *_userKey,
                                const int bits, AES_KEY *key)
{
	AES_KEY_TYPE uchar *userKey = _userKey;
	u32 *rk;
	int i = 0;
	u32 temp;

#ifdef AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;
	aes_table_init(lt);
#endif

	rk = key->rd_key;

	if (bits==128)
		key->rounds = 10;
	else if (bits==192)
		key->rounds = 12;
	else
		key->rounds = 14;

	rk[0] = GETU32(userKey     );
	rk[1] = GETU32(userKey +  4);
	rk[2] = GETU32(userKey +  8);
	rk[3] = GETU32(userKey + 12);
	if (bits == 128) {
		while (1) {
			temp  = rk[3];
			rk[4] = rk[0] ^
				(Te2[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te1[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];
			if (++i == 10) {
				return;
			}
			rk += 4;
		}
	}
	rk[4] = GETU32(userKey + 16);
	rk[5] = GETU32(userKey + 20);
	if (bits == 192) {
		while (1) {
			temp = rk[ 5];
			rk[ 6] = rk[ 0] ^
				(Te2[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te1[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[ 7] = rk[ 1] ^ rk[ 6];
			rk[ 8] = rk[ 2] ^ rk[ 7];
			rk[ 9] = rk[ 3] ^ rk[ 8];
			if (++i == 8) {
				return;
			}
			rk[10] = rk[ 4] ^ rk[ 9];
			rk[11] = rk[ 5] ^ rk[10];
			rk += 6;
		}
	}
	rk[6] = GETU32(userKey + 24);
	rk[7] = GETU32(userKey + 28);
	if (bits == 256) {
		while (1) {
			temp = rk[ 7];
			rk[ 8] = rk[ 0] ^
				(Te2[(temp >> 16) & 0xff] & 0xff000000) ^
				(Te3[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(Te1[(temp >> 24)       ] & 0x000000ff) ^
				rcon[i];
			rk[ 9] = rk[ 1] ^ rk[ 8];
			rk[10] = rk[ 2] ^ rk[ 9];
			rk[11] = rk[ 3] ^ rk[10];
			if (++i == 7) {
				return;
			}
			temp = rk[11];
			rk[12] = rk[ 4] ^
				(Te2[(temp >> 24)       ] & 0xff000000) ^
				(Te3[(temp >> 16) & 0xff] & 0x00ff0000) ^
				(Te0[(temp >>  8) & 0xff] & 0x0000ff00) ^
				(Te1[(temp      ) & 0xff] & 0x000000ff);
			rk[13] = rk[ 5] ^ rk[12];
			rk[14] = rk[ 6] ^ rk[13];
			rk[15] = rk[ 7] ^ rk[14];

			rk += 8;
		}
	}
}

/**
 * Expand the cipher key into the decryption key schedule.
 */
INLINE void AES_set_decrypt_key(AES_KEY_TYPE void *_userKey,
                                const int bits, AES_KEY *key)
{
	AES_KEY_TYPE uchar *userKey = _userKey;
	u32 *rk;
	int i, j;
	u32 temp;
#ifdef AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;
#endif

	/* first, start with an encryption schedule */
	AES_set_encrypt_key(userKey, bits, key);

	rk = key->rd_key;

	/* invert the order of the round keys: */
	for (i = 0, j = 4*(key->rounds); i < j; i += 4, j -= 4) {
		temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
		temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
		temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
		temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
	}
	/* apply the inverse MixColumn transform to all round keys but the first and the last: */
	for (i = 1; i < (key->rounds); i++) {
		rk += 4;
		rk[0] =
			Td0[Te1[(rk[0] >> 24)       ] & 0xff] ^
			Td1[Te1[(rk[0] >> 16) & 0xff] & 0xff] ^
			Td2[Te1[(rk[0] >>  8) & 0xff] & 0xff] ^
			Td3[Te1[(rk[0]      ) & 0xff] & 0xff];
		rk[1] =
			Td0[Te1[(rk[1] >> 24)       ] & 0xff] ^
			Td1[Te1[(rk[1] >> 16) & 0xff] & 0xff] ^
			Td2[Te1[(rk[1] >>  8) & 0xff] & 0xff] ^
			Td3[Te1[(rk[1]      ) & 0xff] & 0xff];
		rk[2] =
			Td0[Te1[(rk[2] >> 24)       ] & 0xff] ^
			Td1[Te1[(rk[2] >> 16) & 0xff] & 0xff] ^
			Td2[Te1[(rk[2] >>  8) & 0xff] & 0xff] ^
			Td3[Te1[(rk[2]      ) & 0xff] & 0xff];
		rk[3] =
			Td0[Te1[(rk[3] >> 24)       ] & 0xff] ^
			Td1[Te1[(rk[3] >> 16) & 0xff] & 0xff] ^
			Td2[Te1[(rk[3] >>  8) & 0xff] & 0xff] ^
			Td3[Te1[(rk[3]      ) & 0xff] & 0xff];
	}
}

/*
 * Encrypt a single block.
 */
INLINE void AES_encrypt(const uchar *in, uchar *out, const AES_KEY *key)
{
	const u32 *rk;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
#ifdef AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;
#endif

	rk = key->rd_key;

	/*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(in     ) ^ rk[0];
	s1 = GETU32(in +  4) ^ rk[1];
	s2 = GETU32(in +  8) ^ rk[2];
	s3 = GETU32(in + 12) ^ rk[3];
#ifdef FULL_UNROLL
	/* round 1: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
	/* round 2: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
	/* round 3: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
	/* round 4: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
	/* round 5: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
	/* round 6: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
	/* round 7: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
	/* round 8: */
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
	/* round 9: */
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
		s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
		s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
		s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
		/* round 11: */
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
			s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
			s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
			s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
			/* round 13: */
			t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
			t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
			t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
			t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
		}
	}
	rk += key->rounds << 2;
#else  /* !FULL_UNROLL */
	/*
	 * Nr - 1 full rounds:
	 */
	int r = key->rounds >> 1;
	for (;;) {
		t0 =
			Te0[(s0 >> 24)       ] ^
			Te1[(s1 >> 16) & 0xff] ^
			Te2[(s2 >>  8) & 0xff] ^
			Te3[(s3      ) & 0xff] ^
			rk[4];
		t1 =
			Te0[(s1 >> 24)       ] ^
			Te1[(s2 >> 16) & 0xff] ^
			Te2[(s3 >>  8) & 0xff] ^
			Te3[(s0      ) & 0xff] ^
			rk[5];
		t2 =
			Te0[(s2 >> 24)       ] ^
			Te1[(s3 >> 16) & 0xff] ^
			Te2[(s0 >>  8) & 0xff] ^
			Te3[(s1      ) & 0xff] ^
			rk[6];
		t3 =
			Te0[(s3 >> 24)       ] ^
			Te1[(s0 >> 16) & 0xff] ^
			Te2[(s1 >>  8) & 0xff] ^
			Te3[(s2      ) & 0xff] ^
			rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
			Te0[(t0 >> 24)       ] ^
			Te1[(t1 >> 16) & 0xff] ^
			Te2[(t2 >>  8) & 0xff] ^
			Te3[(t3      ) & 0xff] ^
			rk[0];
		s1 =
			Te0[(t1 >> 24)       ] ^
			Te1[(t2 >> 16) & 0xff] ^
			Te2[(t3 >>  8) & 0xff] ^
			Te3[(t0      ) & 0xff] ^
			rk[1];
		s2 =
			Te0[(t2 >> 24)       ] ^
			Te1[(t3 >> 16) & 0xff] ^
			Te2[(t0 >>  8) & 0xff] ^
			Te3[(t1      ) & 0xff] ^
			rk[2];
		s3 =
			Te0[(t3 >> 24)       ] ^
			Te1[(t0 >> 16) & 0xff] ^
			Te2[(t1 >>  8) & 0xff] ^
			Te3[(t2      ) & 0xff] ^
			rk[3];
	}
#endif /* ?FULL_UNROLL */
	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
	s0 =
		(Te2[(t0 >> 24)       ] & 0xff000000) ^
		(Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t3      ) & 0xff] & 0x000000ff) ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		(Te2[(t1 >> 24)       ] & 0xff000000) ^
		(Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t0      ) & 0xff] & 0x000000ff) ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		(Te2[(t2 >> 24)       ] & 0xff000000) ^
		(Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t1      ) & 0xff] & 0x000000ff) ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		(Te2[(t3 >> 24)       ] & 0xff000000) ^
		(Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
		(Te1[(t2      ) & 0xff] & 0x000000ff) ^
		rk[3];
	PUTU32(out + 12, s3);
}

/*
 * Decrypt a single block.
 */
INLINE void AES_decrypt(const uchar *in, uchar *out, const AES_KEY *key)
{
	const u32 *rk;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
#ifdef AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;
#endif

//	assert(in && out && key);
	rk = key->rd_key;

	/*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(in     ) ^ rk[0];
	s1 = GETU32(in +  4) ^ rk[1];
	s2 = GETU32(in +  8) ^ rk[2];
	s3 = GETU32(in + 12) ^ rk[3];
#ifdef FULL_UNROLL
	/* round 1: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[ 4];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[ 5];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[ 6];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[ 7];
	/* round 2: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[ 8];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[ 9];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[10];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[11];
	/* round 3: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[12];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[13];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[14];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[15];
	/* round 4: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[16];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[17];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[18];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[19];
	/* round 5: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[20];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[21];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[22];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[23];
	/* round 6: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[24];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[25];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[26];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[27];
	/* round 7: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[28];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[29];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[30];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[31];
	/* round 8: */
	s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[32];
	s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[33];
	s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[34];
	s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[35];
	/* round 9: */
	t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[36];
	t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[37];
	t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[38];
	t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[40];
		s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[41];
		s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[42];
		s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[43];
		/* round 11: */
		t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[44];
		t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[45];
		t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[46];
		t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[48];
			s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[49];
			s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[50];
			s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[51];
			/* round 13: */
			t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[52];
			t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[53];
			t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[54];
			t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[55];
		}
	}
	rk += key->rounds << 2;
#else  /* !FULL_UNROLL */
	/*
	 * Nr - 1 full rounds:
	 */
	int r = key->rounds >> 1;
	for (;;) {
		t0 =
			Td0[(s0 >> 24)       ] ^
			Td1[(s3 >> 16) & 0xff] ^
			Td2[(s2 >>  8) & 0xff] ^
			Td3[(s1      ) & 0xff] ^
			rk[4];
		t1 =
			Td0[(s1 >> 24)       ] ^
			Td1[(s0 >> 16) & 0xff] ^
			Td2[(s3 >>  8) & 0xff] ^
			Td3[(s2      ) & 0xff] ^
			rk[5];
		t2 =
			Td0[(s2 >> 24)       ] ^
			Td1[(s1 >> 16) & 0xff] ^
			Td2[(s0 >>  8) & 0xff] ^
			Td3[(s3      ) & 0xff] ^
			rk[6];
		t3 =
			Td0[(s3 >> 24)       ] ^
			Td1[(s2 >> 16) & 0xff] ^
			Td2[(s1 >>  8) & 0xff] ^
			Td3[(s0      ) & 0xff] ^
			rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
			Td0[(t0 >> 24)       ] ^
			Td1[(t3 >> 16) & 0xff] ^
			Td2[(t2 >>  8) & 0xff] ^
			Td3[(t1      ) & 0xff] ^
			rk[0];
		s1 =
			Td0[(t1 >> 24)       ] ^
			Td1[(t0 >> 16) & 0xff] ^
			Td2[(t3 >>  8) & 0xff] ^
			Td3[(t2      ) & 0xff] ^
			rk[1];
		s2 =
			Td0[(t2 >> 24)       ] ^
			Td1[(t1 >> 16) & 0xff] ^
			Td2[(t0 >>  8) & 0xff] ^
			Td3[(t3      ) & 0xff] ^
			rk[2];
		s3 =
			Td0[(t3 >> 24)       ] ^
			Td1[(t2 >> 16) & 0xff] ^
			Td2[(t1 >>  8) & 0xff] ^
			Td3[(t0      ) & 0xff] ^
			rk[3];
	}
#endif /* ?FULL_UNROLL */
	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
#ifdef TD4_32_BIT
	s0 =
		( ((uint)(Td4[(t0 >> 24)])) & 0xff000000U) ^
		(Td4[(t3 >> 16) & 0xff] & 0x00ff0000U) ^
		(Td4[(t2 >>  8) & 0xff] & 0x0000ff00U) ^
		(Td4[(t1      ) & 0xff] & 0x000000ffU) ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		( ((uint)(Td4[(t1 >> 24)])) & 0xff000000U) ^
		(Td4[(t0 >> 16) & 0xff] & 0x00ff0000U) ^
		(Td4[(t3 >>  8) & 0xff] & 0x0000ff00U) ^
		(Td4[(t2      ) & 0xff] & 0x000000ffU) ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		( ((uint)(Td4[(t2 >> 24)])) & 0xff000000U) ^
		(Td4[(t1 >> 16) & 0xff] & 0x00ff0000U) ^
		(Td4[(t0 >>  8) & 0xff] & 0x0000ff00U) ^
		(Td4[(t3      ) & 0xff] & 0x000000ffU) ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		( ((uint)(Td4[(t3 >> 24)])) & 0xff000000U) ^
		(Td4[(t2 >> 16) & 0xff] & 0x00ff0000U) ^
		(Td4[(t1 >>  8) & 0xff] & 0x0000ff00U) ^
		(Td4[(t0      ) & 0xff] & 0x000000ffU) ^
		rk[3];
	PUTU32(out + 12, s3);
#else
	s0 =
		( ((uint)(Td4[(t0 >> 24)])) << 24) ^
		(Td4[(t3 >> 16) & 0xff] << 16) ^
		(Td4[(t2 >>  8) & 0xff] <<  8) ^
		(Td4[(t1      ) & 0xff])       ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		( ((uint)(Td4[(t1 >> 24)])) << 24) ^
		(Td4[(t0 >> 16) & 0xff] << 16) ^
		(Td4[(t3 >>  8) & 0xff] <<  8) ^
		(Td4[(t2      ) & 0xff])       ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		( ((uint)(Td4[(t2 >> 24)])) << 24) ^
		(Td4[(t1 >> 16) & 0xff] << 16) ^
		(Td4[(t0 >>  8) & 0xff] <<  8) ^
		(Td4[(t3      ) & 0xff])       ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		( ((uint)(Td4[(t3 >> 24)])) << 24) ^
		(Td4[(t2 >> 16) & 0xff] << 16) ^
		(Td4[(t1 >>  8) & 0xff] <<  8) ^
		(Td4[(t0      ) & 0xff])       ^
		rk[3];
	PUTU32(out + 12, s3);
#endif
}

#endif /* _AES_PLAIN */
