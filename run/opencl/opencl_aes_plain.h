/*
 * AES OpenCL functions
 *
 * Copyright (c) 2017-2025, magnum. Kudos to Br0kenUK for the reverse
 * T-tables in decryption key schedule.
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
 * Copy tables to local memory. Pointless for CPU (so a regression) but a huge
 * boost for most any GPU.
 */
#if gpu(DEVICE_INFO)
#define AES_LOCAL_TABLES	1
#endif

/*
 * Use fewer tables, traded against some rotates that may be faster than
 * shared memory bank conflicts.
 *
 * For cryptosafe on nvidia, enabling this is a slight boost. For AMD it
 * doesn't seem to matter.
 */
#if AES_LOCAL_TABLES && gpu_nvidia(DEVICE_INFO)
#define AES_ROTATE_TABLES	1
#endif

/*
 * Use inverse T-tables. This should boost AES_set_decrypt_key() when tables
 * are in shared memory by halving the number of table lookups, decreasing
 * bank conflicts. For some reason it doesn't and can even yield a regression.
 *
 * It appears to be good otherwise, which is expected.
 */
#if !AES_LOCAL_TABLES
#define AES_INVERSE_TABLES	1
#endif

/*
 * This slows AMD down and boosts nvidia. It also seems to work around some
 * auto-vectorizer bug in old Intel CPU runtimes.
 */
#if gpu_nvidia(DEVICE_INFO) || cpu_intel(DEVICE_INFO)
#define FULL_UNROLL	1
#endif

/*
 * Declare Te4 and use it instead of Te0..Te3 for last round encryption.
 * Does no good on GPU.
 */
#if cpu(DEVICE_INFO)
#define USE_TE4	1
#endif

/*
 * Declare Te4/Td4, if used, as 32-bit repeated values, and use logical 'and'
 * instead of shift. Does no good on nvidia.
 */
#if gpu_amd(DEVICE_INFO)
#define TE4_32_BIT	1
#define TD4_32_BIT	1
#endif

/*
 * Back Te4/Td4, if used, in shared memory.
 */
#define TE4_LOCAL	1
#define TD4_LOCAL	1

#include "opencl_aes_tables.h"
#if AES_ROTATE_TABLES
#include "opencl_rotate.h"
#endif

/* AES-128 has 10 rounds, AES-192 has 12 and AES-256 has 14 rounds. */
#define AES_MAXNR   14

typedef struct aes_tables {
	u32 Te0[256];
#if !AES_ROTATE_TABLES
	u32 Te1[256];
	u32 Te2[256];
	u32 Te3[256];
#endif
#if USE_TE4 && TE4_LOCAL
#if TE4_32_BIT
	u32 Te4[256];
#else
	u8 Te4[256];
#endif
#endif
	u32 Td0[256];
#if !AES_ROTATE_TABLES
	u32 Td1[256];
	u32 Td2[256];
	u32 Td3[256];
#endif
#if TD4_LOCAL
#if TD4_32_BIT
	u32 Td4[256];
#else
	u8 Td4[256];
#endif
#endif
} aes_local_t;

typedef struct aes_key_st {
	uint rd_key[4 * (AES_MAXNR + 1)];
	int rounds;
	__local aes_local_t *lt;
} AES_KEY;

#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

#if AES_LOCAL_TABLES

#define THREAD      get_local_id(0)
#define LWS         get_local_size(0)

/**
 * Copy tables to local memory
 */
INLINE void aes_enc_table_init(__local aes_local_t *lt)
{
	const uint stride = MIN(WARP_SIZE, LWS);

	if (THREAD < WARP_SIZE) {
		for (uint i = THREAD; i < 256; i += stride) {
			lt->Te0[i] = Te0[i];
#if !AES_ROTATE_TABLES
			lt->Te1[i] = Te1[i];
			lt->Te2[i] = Te2[i];
			lt->Te3[i] = Te3[i];
#endif
#if USE_TE4 && TE4_LOCAL
			lt->Te4[i] = Te4[i];
#endif
		}
	}
	barrier(CLK_LOCAL_MEM_FENCE);
}

INLINE void aes_dec_table_init(__local aes_local_t *lt)
{
	const uint stride = MIN(WARP_SIZE, LWS);

	if (THREAD < WARP_SIZE) {
		for (uint i = THREAD; i < 256; i += stride) {
			lt->Td0[i] = Td0[i];
#if !AES_ROTATE_TABLES
			lt->Td1[i] = Td1[i];
			lt->Td2[i] = Td2[i];
			lt->Td3[i] = Td3[i];
#endif
#if TD4_LOCAL
			lt->Td4[i] = Td4[i];
#endif
		}
	}
	/*
	 * Intentionally no barrier here - it's in aes_enc_table_init() which
	 * is always called after this one, via AES_set_encrypt_key().
	 */
}

/* Do not move from this spot */
#define Te0	lt->Te0
#define Te1	lt->Te1
#define Te2	lt->Te2
#define Te3	lt->Te3
#if USE_TE4 && TE4_LOCAL
#define Te4	lt->Te4
#endif
#define Td0	lt->Td0
#define Td1	lt->Td1
#define Td2	lt->Td2
#define Td3	lt->Td3
#if TD4_LOCAL
#define Td4	lt->Td4
#endif
#endif	/* AES_LOCAL_TABLES */

#if AES_ROTATE_TABLES
#define TE1(i) ror32(Te0[i], 8)
#define TE2(i) ror32(Te0[i], 16)
#define TE3(i) ror32(Te0[i], 24)
#define TD1(i) ror32(Td0[i], 8)
#define TD2(i) ror32(Td0[i], 16)
#define TD3(i) ror32(Td0[i], 24)
#else
#define TE1(i) Te1[i]
#define TE2(i) Te2[i]
#define TE3(i) Te3[i]
#define TD1(i) Td1[i]
#define TD2(i) Td2[i]
#define TD3(i) Td3[i]
#endif	/* AES_ROTATE_TABLES */

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

#if AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;

	aes_enc_table_init(lt);
#endif

	rk = key->rd_key;

	rk[0] = GETU32(userKey     );
	rk[1] = GETU32(userKey +  4);
	rk[2] = GETU32(userKey +  8);
	rk[3] = GETU32(userKey + 12);
	if (bits == 128) {
		key->rounds = 10;
#pragma unroll
		for (i = 0; i < 10; i++) {
			temp  = rk[3];
			rk[4] = rk[0] ^
				(TE2((temp >> 16) & 0xff) & 0xff000000) ^
				(TE3((temp >>  8) & 0xff) & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(TE1(temp >> 24) & 0x000000ff) ^
				rcon[i];
			rk[5] = rk[1] ^ rk[4];
			rk[6] = rk[2] ^ rk[5];
			rk[7] = rk[3] ^ rk[6];

			rk += 4;
		}
		return;
	}
	rk[4] = GETU32(userKey + 16);
	rk[5] = GETU32(userKey + 20);
	if (bits == 192) {
		key->rounds = 12;
#pragma unroll
		for (i = 0; i < 8; i++) {
			temp = rk[ 5];
			rk[ 6] = rk[ 0] ^
				(TE2((temp >> 16) & 0xff) & 0xff000000) ^
				(TE3((temp >>  8) & 0xff) & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(TE1(temp >> 24) & 0x000000ff) ^
				rcon[i];
			rk[ 7] = rk[ 1] ^ rk[ 6];
			rk[ 8] = rk[ 2] ^ rk[ 7];
			rk[ 9] = rk[ 3] ^ rk[ 8];
			if (i < 7) {
				rk[10] = rk[ 4] ^ rk[ 9];
				rk[11] = rk[ 5] ^ rk[10];

				rk += 6;
			}
		}
		return;
	}
	rk[6] = GETU32(userKey + 24);
	rk[7] = GETU32(userKey + 28);
	if (bits == 256) {
		key->rounds = 14;
#pragma unroll
		for (i = 0; i < 7; i++) {
			temp = rk[ 7];
			rk[ 8] = rk[ 0] ^
				(TE2((temp >> 16) & 0xff) & 0xff000000) ^
				(TE3((temp >>  8) & 0xff) & 0x00ff0000) ^
				(Te0[(temp      ) & 0xff] & 0x0000ff00) ^
				(TE1(temp >> 24) & 0x000000ff) ^
				rcon[i];
			rk[ 9] = rk[ 1] ^ rk[ 8];
			rk[10] = rk[ 2] ^ rk[ 9];
			rk[11] = rk[ 3] ^ rk[10];
			if (i < 6) {
				temp = rk[11];
				rk[12] = rk[ 4] ^
					(TE2((temp >> 24)       ) & 0xff000000) ^
					(TE3((temp >> 16) & 0xff) & 0x00ff0000) ^
					(Te0[(temp >>  8) & 0xff] & 0x0000ff00) ^
					(TE1(temp & 0xff) & 0x000000ff);
				rk[13] = rk[ 5] ^ rk[12];
				rk[14] = rk[ 6] ^ rk[13];
				rk[15] = rk[ 7] ^ rk[14];

				rk += 8;
			}
		}
		return;
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
#if AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;

#if AES_INVERSE_TABLES
	__local u32 lt_Inv0[256];
#if !AES_ROTATE_TABLES
	__local u32 lt_Inv1[256];
	__local u32 lt_Inv2[256];
	__local u32 lt_Inv3[256];
#endif

	const uint stride = MIN(WARP_SIZE, LWS);

	if (THREAD < WARP_SIZE) {
		for (uint i = THREAD; i < 256; i += stride) {
			lt_Inv0[i] = Inv0[i];
#if !AES_ROTATE_TABLES
			lt_Inv1[i] = Inv1[i];
			lt_Inv2[i] = Inv2[i];
			lt_Inv3[i] = Inv3[i];
#endif
		}
	}
	/*
	 * Intentionally no barrier here - it's in aes_enc_table_init() which
	 * is called later down via AES_set_encrypt_key().
	 */

#define Inv0	lt_Inv0
#define Inv1	lt_Inv1
#define Inv2	lt_Inv2
#define Inv3	lt_Inv3

#endif	/* AES_INVERSE_TABLES */

	aes_dec_table_init(lt);

#endif	/* AES_LOCAL_TABLES */

	/* first, start with an encryption schedule */
	AES_set_encrypt_key(userKey, bits, key);

	rk = key->rd_key;

#define SWAP(a, b)	do { u32 t = a; a = b; b = t; } while (0)

	const int rk_last = key->rounds << 2;

	/* 2) Swap first 4 elements of rk with the last 4 (no T-box on these) */
	SWAP(rk[0], rk[rk_last + 0]);
	SWAP(rk[1], rk[rk_last + 1]);
	SWAP(rk[2], rk[rk_last + 2]);
	SWAP(rk[3], rk[rk_last + 3]);

#if AES_INVERSE_TABLES

	/* Use inverse T-box tables, halving the number of table lookups. */
#if AES_ROTATE_TABLES
#define INV(w)	  \
	( Inv0[ (w) >> 24] ^ \
	  ror32(Inv0[((w) >> 16) & 0xff],  8) ^ \
	  ror32(Inv0[((w) >>  8) & 0xff], 16) ^ \
	  ror32(Inv0[ (w)        & 0xff], 24) )
#else
#define INV(w)	  \
	( Inv0[ (w) >> 24] ^ \
	  Inv1[((w) >> 16) & 0xff] ^ \
	  Inv2[((w) >>  8) & 0xff] ^ \
	  Inv3[ (w)        & 0xff] )
#endif

#else

	/* The same but using the existing tables. */

#define INV(w)	  \
	( Td0[TE1(((w) >> 24)       ) & 0xff] ^ \
	  TD1(TE1(((w) >> 16) & 0xff) & 0xff) ^ \
	  TD2(TE1(((w) >>  8) & 0xff) & 0xff) ^ \
	  TD3(TE1( (w)        & 0xff) & 0xff) )

#endif	/* AES_INVERSE_TABLES */

	/*
	 * Apply the inverse MixColumn transform to all round keys but the first
	 * and the last.
	 */
	for (int b = 0; b < (key->rounds - 2) / 2; b++) {
		const int i = 4  + (b << 2);
		const int j = rk_last - 4 - (b << 2);

		/* load both halves */
		u32 a0 = rk[i + 0], a1 = rk[i + 1], a2 = rk[i + 2], a3 = rk[i + 3];
		u32 b0 = rk[j + 0], b1 = rk[j + 1], b2 = rk[j + 2], b3 = rk[j + 3];

		/* write back swapped + inverted */
		rk[i + 0] = INV(b0);
		rk[i + 1] = INV(b1);
		rk[i + 2] = INV(b2);
		rk[i + 3] = INV(b3);

		rk[j + 0] = INV(a0);
		rk[j + 1] = INV(a1);
		rk[j + 2] = INV(a2);
		rk[j + 3] = INV(a3);
	}

	/*
	 * Finally invert the middle four words:
	 * These were never touched by the swap above.
	 */
	for (int k = rk_last >> 1; k < (rk_last >> 1) + 4; k++)
		rk[k] = INV(rk[k]);

#undef INV
#undef SWAP
}

/*
 * Encrypt a single block.
 */
INLINE void AES_encrypt(const uchar *in, uchar *out, const AES_KEY *key)
{
	const u32 *rk;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
#if AES_LOCAL_TABLES
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
#if FULL_UNROLL
	/* round 1: */
	t0 = Te0[s0 >> 24] ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[ 4];
	t1 = Te0[s1 >> 24] ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[ 5];
	t2 = Te0[s2 >> 24] ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[ 6];
	t3 = Te0[s3 >> 24] ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[ 7];
	/* round 2: */
	s0 = Te0[t0 >> 24] ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[ 8];
	s1 = Te0[t1 >> 24] ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[ 9];
	s2 = Te0[t2 >> 24] ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[10];
	s3 = Te0[t3 >> 24] ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[11];
	/* round 3: */
	t0 = Te0[s0 >> 24] ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[12];
	t1 = Te0[s1 >> 24] ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[13];
	t2 = Te0[s2 >> 24] ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[14];
	t3 = Te0[s3 >> 24] ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[15];
	/* round 4: */
	s0 = Te0[t0 >> 24] ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[16];
	s1 = Te0[t1 >> 24] ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[17];
	s2 = Te0[t2 >> 24] ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[18];
	s3 = Te0[t3 >> 24] ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[19];
	/* round 5: */
	t0 = Te0[s0 >> 24] ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[20];
	t1 = Te0[s1 >> 24] ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[21];
	t2 = Te0[s2 >> 24] ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[22];
	t3 = Te0[s3 >> 24] ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[23];
	/* round 6: */
	s0 = Te0[t0 >> 24] ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[24];
	s1 = Te0[t1 >> 24] ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[25];
	s2 = Te0[t2 >> 24] ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[26];
	s3 = Te0[t3 >> 24] ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[27];
	/* round 7: */
	t0 = Te0[s0 >> 24] ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[28];
	t1 = Te0[s1 >> 24] ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[29];
	t2 = Te0[s2 >> 24] ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[30];
	t3 = Te0[s3 >> 24] ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[31];
	/* round 8: */
	s0 = Te0[t0 >> 24] ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[32];
	s1 = Te0[t1 >> 24] ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[33];
	s2 = Te0[t2 >> 24] ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[34];
	s3 = Te0[t3 >> 24] ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[35];
	/* round 9: */
	t0 = Te0[s0 >> 24] ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[36];
	t1 = Te0[s1 >> 24] ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[37];
	t2 = Te0[s2 >> 24] ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[38];
	t3 = Te0[s3 >> 24] ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = Te0[t0 >> 24] ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[40];
		s1 = Te0[t1 >> 24] ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[41];
		s2 = Te0[t2 >> 24] ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[42];
		s3 = Te0[t3 >> 24] ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[43];
		/* round 11: */
		t0 = Te0[s0 >> 24] ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[44];
		t1 = Te0[s1 >> 24] ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[45];
		t2 = Te0[s2 >> 24] ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[46];
		t3 = Te0[s3 >> 24] ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = Te0[t0 >> 24] ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[48];
			s1 = Te0[t1 >> 24] ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[49];
			s2 = Te0[t2 >> 24] ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[50];
			s3 = Te0[t3 >> 24] ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[51];
			/* round 13: */
			t0 = Te0[s0 >> 24] ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[52];
			t1 = Te0[s1 >> 24] ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[53];
			t2 = Te0[s2 >> 24] ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[54];
			t3 = Te0[s3 >> 24] ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[55];
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
			TE1((s1 >> 16) & 0xff) ^
			TE2((s2 >>  8) & 0xff) ^
			TE3((s3      ) & 0xff) ^
			rk[4];
		t1 =
			Te0[(s1 >> 24)       ] ^
			TE1((s2 >> 16) & 0xff) ^
			TE2((s3 >>  8) & 0xff) ^
			TE3((s0      ) & 0xff) ^
			rk[5];
		t2 =
			Te0[(s2 >> 24)       ] ^
			TE1((s3 >> 16) & 0xff) ^
			TE2((s0 >>  8) & 0xff) ^
			TE3((s1      ) & 0xff) ^
			rk[6];
		t3 =
			Te0[(s3 >> 24)       ] ^
			TE1((s0 >> 16) & 0xff) ^
			TE2((s1 >>  8) & 0xff) ^
			TE3((s2      ) & 0xff) ^
			rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
			Te0[(t0 >> 24)       ] ^
			TE1((t1 >> 16) & 0xff) ^
			TE2((t2 >>  8) & 0xff) ^
			TE3((t3      ) & 0xff) ^
			rk[0];
		s1 =
			Te0[(t1 >> 24)       ] ^
			TE1((t2 >> 16) & 0xff) ^
			TE2((t3 >>  8) & 0xff) ^
			TE3((t0      ) & 0xff) ^
			rk[1];
		s2 =
			Te0[(t2 >> 24)       ] ^
			TE1((t3 >> 16) & 0xff) ^
			TE2((t0 >>  8) & 0xff) ^
			TE3((t1      ) & 0xff) ^
			rk[2];
		s3 =
			Te0[(t3 >> 24)       ] ^
			TE1((t0 >> 16) & 0xff) ^
			TE2((t1 >>  8) & 0xff) ^
			TE3((t2      ) & 0xff) ^
			rk[3];
	}
#endif /* ?FULL_UNROLL */
	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
#if USE_TE4
#if TE4_32_BIT
	s0 =
		(Te4[(t0 >> 24)       ] & 0xff000000) ^
		(Te4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t3      ) & 0xff] & 0x000000ff) ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		(Te4[(t1 >> 24)       ] & 0xff000000) ^
		(Te4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t0      ) & 0xff] & 0x000000ff) ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		(Te4[(t2 >> 24)       ] & 0xff000000) ^
		(Te4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t1      ) & 0xff] & 0x000000ff) ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		(Te4[(t3 >> 24)       ] & 0xff000000) ^
		(Te4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
		(Te4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
		(Te4[(t2      ) & 0xff] & 0x000000ff) ^
		rk[3];
	PUTU32(out + 12, s3);
#else
	s0 =
		( ((uint)(Te4[(t0 >> 24)])) << 24) ^
		(Te4[(t1 >> 16) & 0xff] << 16) ^
		(Te4[(t2 >>  8) & 0xff] <<  8) ^
		(Te4[(t3      ) & 0xff])       ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		( ((uint)(Te4[(t1 >> 24)])) << 24) ^
		(Te4[(t2 >> 16) & 0xff] << 16) ^
		(Te4[(t3 >>  8) & 0xff] <<  8) ^
		(Te4[(t0      ) & 0xff])       ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		( ((uint)(Te4[(t2 >> 24)])) << 24) ^
		(Te4[(t3 >> 16) & 0xff] << 16) ^
		(Te4[(t0 >>  8) & 0xff] <<  8) ^
		(Te4[(t1      ) & 0xff])       ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		( ((uint)(Te4[(t3 >> 24)])) << 24) ^
		(Te4[(t0 >> 16) & 0xff] << 16) ^
		(Te4[(t1 >>  8) & 0xff] <<  8) ^
		(Te4[(t2      ) & 0xff])       ^
		rk[3];
	PUTU32(out + 12, s3);
#endif	/* TE4_32_BIT */
#else
	s0 =
		(TE2((t0 >> 24)       ) & 0xff000000) ^
		(TE3((t1 >> 16) & 0xff) & 0x00ff0000) ^
		(Te0[(t2 >>  8) & 0xff] & 0x0000ff00) ^
		(TE1((t3      ) & 0xff) & 0x000000ff) ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		(TE2((t1 >> 24)       ) & 0xff000000) ^
		(TE3((t2 >> 16) & 0xff) & 0x00ff0000) ^
		(Te0[(t3 >>  8) & 0xff] & 0x0000ff00) ^
		(TE1((t0      ) & 0xff) & 0x000000ff) ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		(TE2((t2 >> 24)       ) & 0xff000000) ^
		(TE3((t3 >> 16) & 0xff) & 0x00ff0000) ^
		(Te0[(t0 >>  8) & 0xff] & 0x0000ff00) ^
		(TE1((t1      ) & 0xff) & 0x000000ff) ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		(TE2((t3 >> 24)       ) & 0xff000000) ^
		(TE3((t0 >> 16) & 0xff) & 0x00ff0000) ^
		(Te0[(t1 >>  8) & 0xff] & 0x0000ff00) ^
		(TE1((t2      ) & 0xff) & 0x000000ff) ^
		rk[3];
	PUTU32(out + 12, s3);
#endif	/* USE_TE4 */
}

/*
 * Decrypt a single block.
 */
INLINE void AES_decrypt(const uchar *in, uchar *out, const AES_KEY *key)
{
	const u32 *rk;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
#if AES_LOCAL_TABLES
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
#if FULL_UNROLL
	/* round 1: */
	t0 = Td0[s0 >> 24] ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[ 4];
	t1 = Td0[s1 >> 24] ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[ 5];
	t2 = Td0[s2 >> 24] ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[ 6];
	t3 = Td0[s3 >> 24] ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[ 7];
	/* round 2: */
	s0 = Td0[t0 >> 24] ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[ 8];
	s1 = Td0[t1 >> 24] ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[ 9];
	s2 = Td0[t2 >> 24] ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[10];
	s3 = Td0[t3 >> 24] ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[11];
	/* round 3: */
	t0 = Td0[s0 >> 24] ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[12];
	t1 = Td0[s1 >> 24] ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[13];
	t2 = Td0[s2 >> 24] ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[14];
	t3 = Td0[s3 >> 24] ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[15];
	/* round 4: */
	s0 = Td0[t0 >> 24] ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[16];
	s1 = Td0[t1 >> 24] ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[17];
	s2 = Td0[t2 >> 24] ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[18];
	s3 = Td0[t3 >> 24] ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[19];
	/* round 5: */
	t0 = Td0[s0 >> 24] ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[20];
	t1 = Td0[s1 >> 24] ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[21];
	t2 = Td0[s2 >> 24] ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[22];
	t3 = Td0[s3 >> 24] ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[23];
	/* round 6: */
	s0 = Td0[t0 >> 24] ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[24];
	s1 = Td0[t1 >> 24] ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[25];
	s2 = Td0[t2 >> 24] ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[26];
	s3 = Td0[t3 >> 24] ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[27];
	/* round 7: */
	t0 = Td0[s0 >> 24] ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[28];
	t1 = Td0[s1 >> 24] ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[29];
	t2 = Td0[s2 >> 24] ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[30];
	t3 = Td0[s3 >> 24] ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[31];
	/* round 8: */
	s0 = Td0[t0 >> 24] ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[32];
	s1 = Td0[t1 >> 24] ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[33];
	s2 = Td0[t2 >> 24] ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[34];
	s3 = Td0[t3 >> 24] ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[35];
	/* round 9: */
	t0 = Td0[s0 >> 24] ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[36];
	t1 = Td0[s1 >> 24] ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[37];
	t2 = Td0[s2 >> 24] ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[38];
	t3 = Td0[s3 >> 24] ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = Td0[t0 >> 24] ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[40];
		s1 = Td0[t1 >> 24] ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[41];
		s2 = Td0[t2 >> 24] ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[42];
		s3 = Td0[t3 >> 24] ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[43];
		/* round 11: */
		t0 = Td0[s0 >> 24] ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[44];
		t1 = Td0[s1 >> 24] ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[45];
		t2 = Td0[s2 >> 24] ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[46];
		t3 = Td0[s3 >> 24] ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = Td0[t0 >> 24] ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[48];
			s1 = Td0[t1 >> 24] ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[49];
			s2 = Td0[t2 >> 24] ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[50];
			s3 = Td0[t3 >> 24] ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[51];
			/* round 13: */
			t0 = Td0[s0 >> 24] ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[52];
			t1 = Td0[s1 >> 24] ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[53];
			t2 = Td0[s2 >> 24] ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[54];
			t3 = Td0[s3 >> 24] ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[55];
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
			TD1((s3 >> 16) & 0xff) ^
			TD2((s2 >>  8) & 0xff) ^
			TD3((s1      ) & 0xff) ^
			rk[4];
		t1 =
			Td0[(s1 >> 24)       ] ^
			TD1((s0 >> 16) & 0xff) ^
			TD2((s3 >>  8) & 0xff) ^
			TD3((s2      ) & 0xff) ^
			rk[5];
		t2 =
			Td0[(s2 >> 24)       ] ^
			TD1((s1 >> 16) & 0xff) ^
			TD2((s0 >>  8) & 0xff) ^
			TD3((s3      ) & 0xff) ^
			rk[6];
		t3 =
			Td0[(s3 >> 24)       ] ^
			TD1((s2 >> 16) & 0xff) ^
			TD2((s1 >>  8) & 0xff) ^
			TD3((s0      ) & 0xff) ^
			rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
			Td0[(t0 >> 24)       ] ^
			TD1((t3 >> 16) & 0xff) ^
			TD2((t2 >>  8) & 0xff) ^
			TD3((t1      ) & 0xff) ^
			rk[0];
		s1 =
			Td0[(t1 >> 24)       ] ^
			TD1((t0 >> 16) & 0xff) ^
			TD2((t3 >>  8) & 0xff) ^
			TD3((t2      ) & 0xff) ^
			rk[1];
		s2 =
			Td0[(t2 >> 24)       ] ^
			TD1((t1 >> 16) & 0xff) ^
			TD2((t0 >>  8) & 0xff) ^
			TD3((t3      ) & 0xff) ^
			rk[2];
		s3 =
			Td0[(t3 >> 24)       ] ^
			TD1((t2 >> 16) & 0xff) ^
			TD2((t1 >>  8) & 0xff) ^
			TD3((t0      ) & 0xff) ^
			rk[3];
	}
#endif /* ?FULL_UNROLL */
	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
#if TD4_32_BIT
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
#endif	/* TD4_32_BIT */
}

#endif /* _AES_PLAIN */
