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
 * Even with 64K shared memory, an AMD device can't fit an exclusive table to
 * every thread in a wavefront, so we have to decrease it. Actually 64K would
 * be barely enough if it wasn't for the fact some of it is wasted on a pointer
 * or some other overhead.
 */
#if SHARED_MEM_SIZE < (WARP_SIZE * 1024 + 4)
#define AES_SHARED_THREADS	(SHARED_MEM_SIZE / (1024 + 4) / 32 * 32)
#define AES_SHARED_THREADS_DECREASED	1
#else
#define AES_SHARED_THREADS	WARP_SIZE
#endif

#define AES_SHARED_THREADS_MASK	(AES_SHARED_THREADS - 1)

/*
 * Copy Tx0/Inv0 (and optionally Tx4) tables to local memory. Pointless for CPU
 * (so a regression) but a huge boost for most any GPU.  We'll infer Tx1..Tx3
 * and Inv1..Inv3 using rotates, which is faster as we avoid bank conflicts.
 */
#if gpu(DEVICE_INFO)
#define AES_LOCAL_TABLES	1
#endif

/*
 * Use barriers for the local table. If not, we're declaring it volatile.
 * The latter is officially supported on nvidia but not on any other device.
 * It MAY work fine on AMD because of how we do stuff but it definitely can't
 * be used if we had to decrease AES_SHARED_THREADS because then we don't
 * have a column for every thread.
 */
#if !gpu_nvidia(DEVICE_INFO) || AES_SHARED_THREADS_DECREASED
#define AES_LOCAL_BARRIER	1
#endif

/*
 * This slows AMD down and boosts nvidia. It also seems to work around some
 * auto-vectorizer bug in old Intel CPU runtimes.
 */
#define AES_FULL_UNROLL	1

/*
 * Declare Te4 table and use it instead of Te0..Te3 for last round encryption.
 * There is no equivalent opt-out for Td4.
 */
#if !gpu(DEVICE_INFO)
#define AES_USE_TE4	1
#endif

/*
 * Use shared memory backing for Tx4 also. Ignored unless AES_LOCAL_TABLES
 * and TE4_LOCAL is also (obviously) ignored unless AES_USE_TE4
 */
#if AES_LOCAL_TABLES
#define TE4_LOCAL	1
#define TD4_LOCAL	1
#endif

/*
 * Declare Te4 (if used) and Td4 as 32-bit repeated values. This avoids shared
 * memory bank conflicts for those tables because they are otherwise uchar
 * arrays which messes up the thread->bank mapping leading to bank conflicts.
 */
#if TE4_LOCAL
#define TE4_32_BIT	1
#endif
#if TD4_LOCAL
#define TD4_32_BIT	1
#endif

#include "opencl_aes_tables.h"
#if AES_LOCAL_TABLES
#include "opencl_rotate.h"
#endif

/* AES-128 has 10 rounds, AES-192 has 12 and AES-256 has 14 rounds. */
#define AES_MAXNR   14

enum table { TE0, TE4, TD0, TD4, INV };

typedef struct aes_tables {
#if AES_LOCAL_TABLES
#if AES_LOCAL_BARRIER
	u32 T0[256][AES_SHARED_THREADS];
#else
	volatile u32 T0[256][AES_SHARED_THREADS];
#endif
#endif	/* AES_LOCAL_TABLES */
#if AES_LOCAL_BARRIER
	enum table content;
#else
	volatile enum table content;
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

#define TE0(i)	lt->T0[i][THREAD & AES_SHARED_THREADS_MASK]
#define TE1(i)	ror32(TE0(i), 8)
#define TE2(i)	ror32(TE0(i), 16)
#define TE3(i)	ror32(TE0(i), 24)
#if TE4_LOCAL
#define TE4(i)	lt->T0[i][THREAD & AES_SHARED_THREADS_MASK]
#else
#define TE4(i)	Te4[i]
#endif
#define TD0(i)	lt->T0[i][THREAD & AES_SHARED_THREADS_MASK]
#define TD1(i)	ror32(TD0(i), 8)
#define TD2(i)	ror32(TD0(i), 16)
#define TD3(i)	ror32(TD0(i), 24)
#if TD4_LOCAL
#define TD4(i)	lt->T0[i][THREAD & AES_SHARED_THREADS_MASK]
#else
#define TD4(i)	Td4[i]
#endif
#define INV0(i)	lt->T0[i][THREAD & AES_SHARED_THREADS_MASK]
#define INV1(i)	ror32(INV0(i), 8)
#define INV2(i)	ror32(INV0(i), 16)
#define INV3(i)	ror32(INV0(i), 24)

#else

#define TE0(i)	Te0[i]
#define TE1(i)	Te1[i]
#define TE2(i)	Te2[i]
#define TE3(i)	Te3[i]
#define TE4(i)	Te4[i]
#define TD0(i)	Td0[i]
#define TD1(i)	Td1[i]
#define TD2(i)	Td2[i]
#define TD3(i)	Td3[i]
#define TD4(i)	Td4[i]
#define INV0(i)	Inv0[i]
#define INV1(i)	Inv1[i]
#define INV2(i)	Inv2[i]
#define INV3(i)	Inv3[i]

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

#if AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;

	if (THREAD < AES_SHARED_THREADS)
		for (uint i = 0; i < 256; i++)
			lt->T0[i][THREAD] = Te0[i];
	if (THREAD == 0)
		lt->content = TE0;
#if AES_LOCAL_BARRIER
	barrier(CLK_LOCAL_MEM_FENCE);
#endif
#endif	/* AES_LOCAL_TABLES */

	rk = key->rd_key;

	rk[0] = GETU32(userKey     );
	rk[1] = GETU32(userKey +  4);
	rk[2] = GETU32(userKey +  8);
	rk[3] = GETU32(userKey + 12);

#if AES_FULL_UNROLL



#else	/* !AES_FULL_UNROLL */

	if (bits == 128) {
		key->rounds = 10;
#pragma unroll
		for (i = 0; i < 10; i++) {
			temp  = rk[3];
			rk[4] = rk[0] ^
				(TE2((temp >> 16) & 0xff) & 0xff000000) ^
				(TE3((temp >>  8) & 0xff) & 0x00ff0000) ^
				(TE0((temp      ) & 0xff) & 0x0000ff00) ^
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
				(TE0((temp      ) & 0xff) & 0x0000ff00) ^
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
				(TE0((temp      ) & 0xff) & 0x0000ff00) ^
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
					(TE0((temp >>  8) & 0xff) & 0x0000ff00) ^
					(TE1(temp & 0xff) & 0x000000ff);
				rk[13] = rk[ 5] ^ rk[12];
				rk[14] = rk[ 6] ^ rk[13];
				rk[15] = rk[ 7] ^ rk[14];

				rk += 8;
			}
		}
		return;
	}
#endif	/* AES_FULL_UNROLL */
}

/**
 * Expand the cipher key into the decryption key schedule.
 */
INLINE void AES_set_decrypt_key(AES_KEY_TYPE void *_userKey,
                                const int bits, AES_KEY *key)
{
	AES_KEY_TYPE uchar *userKey = _userKey;
	u32 *rk;

	/* first, start with an encryption schedule */
	AES_set_encrypt_key(userKey, bits, key);

#if AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;

	if (THREAD < AES_SHARED_THREADS)
		for (uint i = 0; i < 256; i++)
			lt->T0[i][THREAD] = Inv0[i];
	if (THREAD == 0)
		lt->content = INV;
#if AES_LOCAL_BARRIER
	barrier(CLK_LOCAL_MEM_FENCE);
#endif
#endif	/* AES_LOCAL_TABLES */

	rk = key->rd_key;

#define SWAP(a, b)	do { u32 t = a; a = b; b = t; } while (0)

	const int rk_last = key->rounds << 2;

	/* 2) Swap first 4 elements of rk with the last 4 (no T-box on these) */
	SWAP(rk[0], rk[rk_last + 0]);
	SWAP(rk[1], rk[rk_last + 1]);
	SWAP(rk[2], rk[rk_last + 2]);
	SWAP(rk[3], rk[rk_last + 3]);

	/* Use inverse T-box tables, halving the number of table lookups. */
#define INV(w)	  \
	( INV0( (w) >> 24) ^ \
	  INV1(((w) >> 16) & 0xff) ^ \
	  INV2(((w) >>  8) & 0xff) ^ \
	  INV3( (w)        & 0xff) )

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

	if (lt->content != TE0) {
		if (THREAD < AES_SHARED_THREADS)
			for (uint i = 0; i < 256; i++)
				lt->T0[i][THREAD] = Te0[i];
		if (THREAD == 0)
			lt->content = TE0;
#if AES_LOCAL_BARRIER
		barrier(CLK_LOCAL_MEM_FENCE);
#endif
	}
#endif	/* AES_LOCAL_TABLES */

	rk = key->rd_key;

	/*
	 * map byte array block to cipher state
	 * and add initial round key:
	 */
	s0 = GETU32(in     ) ^ rk[0];
	s1 = GETU32(in +  4) ^ rk[1];
	s2 = GETU32(in +  8) ^ rk[2];
	s3 = GETU32(in + 12) ^ rk[3];
#if AES_FULL_UNROLL
	/* round 1: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[ 4];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[ 5];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[ 6];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[ 7];
	/* round 2: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[ 8];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[ 9];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[10];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[11];
	/* round 3: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[12];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[13];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[14];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[15];
	/* round 4: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[16];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[17];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[18];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[19];
	/* round 5: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[20];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[21];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[22];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[23];
	/* round 6: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[24];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[25];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[26];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[27];
	/* round 7: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[28];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[29];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[30];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[31];
	/* round 8: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[32];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[33];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[34];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[35];
	/* round 9: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[36];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[37];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[38];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[40];
		s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[41];
		s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[42];
		s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[43];
		/* round 11: */
		t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[44];
		t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[45];
		t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[46];
		t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >>  8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[48];
			s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >>  8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[49];
			s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >>  8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[50];
			s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >>  8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[51];
			/* round 13: */
			t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >>  8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[52];
			t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >>  8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[53];
			t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >>  8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[54];
			t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >>  8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[55];
		}
	}
	rk += key->rounds << 2;
#else  /* !AES_FULL_UNROLL */
	/*
	 * Nr - 1 full rounds:
	 */
	int r = key->rounds >> 1;
	for (;;) {
		t0 =
			TE0((s0 >> 24)       ) ^
			TE1((s1 >> 16) & 0xff) ^
			TE2((s2 >>  8) & 0xff) ^
			TE3((s3      ) & 0xff) ^
			rk[4];
		t1 =
			TE0((s1 >> 24)       ) ^
			TE1((s2 >> 16) & 0xff) ^
			TE2((s3 >>  8) & 0xff) ^
			TE3((s0      ) & 0xff) ^
			rk[5];
		t2 =
			TE0((s2 >> 24)       ) ^
			TE1((s3 >> 16) & 0xff) ^
			TE2((s0 >>  8) & 0xff) ^
			TE3((s1      ) & 0xff) ^
			rk[6];
		t3 =
			TE0((s3 >> 24)       ) ^
			TE1((s0 >> 16) & 0xff) ^
			TE2((s1 >>  8) & 0xff) ^
			TE3((s2      ) & 0xff) ^
			rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
			TE0((t0 >> 24)       ) ^
			TE1((t1 >> 16) & 0xff) ^
			TE2((t2 >>  8) & 0xff) ^
			TE3((t3      ) & 0xff) ^
			rk[0];
		s1 =
			TE0((t1 >> 24)       ) ^
			TE1((t2 >> 16) & 0xff) ^
			TE2((t3 >>  8) & 0xff) ^
			TE3((t0      ) & 0xff) ^
			rk[1];
		s2 =
			TE0((t2 >> 24)       ) ^
			TE1((t3 >> 16) & 0xff) ^
			TE2((t0 >>  8) & 0xff) ^
			TE3((t1      ) & 0xff) ^
			rk[2];
		s3 =
			TE0((t3 >> 24)       ) ^
			TE1((t0 >> 16) & 0xff) ^
			TE2((t1 >>  8) & 0xff) ^
			TE3((t2      ) & 0xff) ^
			rk[3];
	}
#endif /* ?AES_FULL_UNROLL */
	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
#if AES_USE_TE4
#if AES_LOCAL_TABLES && TE4_LOCAL
	if (lt->content != TE4) {
		if (THREAD < AES_SHARED_THREADS)
			for (uint i = 0; i < 256; i++)
				lt->T0[i][THREAD] = Te4[i];
		if (THREAD == 0)
			lt->content = TE4;
#if AES_LOCAL_BARRIER
		barrier(CLK_LOCAL_MEM_FENCE);
#endif
	}
#endif	/* AES_LOCAL_TABLES */

#if TE4_32_BIT
	s0 =
		(TE4((t0 >> 24)       ) & 0xff000000) ^
		(TE4((t1 >> 16) & 0xff) & 0x00ff0000) ^
		(TE4((t2 >>  8) & 0xff) & 0x0000ff00) ^
		(TE4((t3      ) & 0xff) & 0x000000ff) ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		(TE4((t1 >> 24)       ) & 0xff000000) ^
		(TE4((t2 >> 16) & 0xff) & 0x00ff0000) ^
		(TE4((t3 >>  8) & 0xff) & 0x0000ff00) ^
		(TE4((t0      ) & 0xff) & 0x000000ff) ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		(TE4((t2 >> 24)       ) & 0xff000000) ^
		(TE4((t3 >> 16) & 0xff) & 0x00ff0000) ^
		(TE4((t0 >>  8) & 0xff) & 0x0000ff00) ^
		(TE4((t1      ) & 0xff) & 0x000000ff) ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		(TE4((t3 >> 24)       ) & 0xff000000) ^
		(TE4((t0 >> 16) & 0xff) & 0x00ff0000) ^
		(TE4((t1 >>  8) & 0xff) & 0x0000ff00) ^
		(TE4((t2      ) & 0xff) & 0x000000ff) ^
		rk[3];
	PUTU32(out + 12, s3);
#else
	s0 =
		( ((uint)(TE4((t0 >> 24)))) << 24) ^
		(TE4((t1 >> 16) & 0xff) << 16) ^
		(TE4((t2 >>  8) & 0xff) <<  8) ^
		(TE4((t3      ) & 0xff))       ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		( ((uint)(TE4((t1 >> 24)))) << 24) ^
		(TE4((t2 >> 16) & 0xff) << 16) ^
		(TE4((t3 >>  8) & 0xff) <<  8) ^
		(TE4((t0      ) & 0xff))       ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		( ((uint)(TE4((t2 >> 24)))) << 24) ^
		(TE4((t3 >> 16) & 0xff) << 16) ^
		(TE4((t0 >>  8) & 0xff) <<  8) ^
		(TE4((t1      ) & 0xff))       ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		( ((uint)(TE4((t3 >> 24)))) << 24) ^
		(TE4((t0 >> 16) & 0xff) << 16) ^
		(TE4((t1 >>  8) & 0xff) <<  8) ^
		(TE4((t2      ) & 0xff))       ^
		rk[3];
	PUTU32(out + 12, s3);
#endif	/* TE4_32_BIT */
#else	/* !AES_USE_TE4 */
	s0 =
		(TE2((t0 >> 24)       ) & 0xff000000) ^
		(TE3((t1 >> 16) & 0xff) & 0x00ff0000) ^
		(TE0((t2 >>  8) & 0xff) & 0x0000ff00) ^
		(TE1((t3      ) & 0xff) & 0x000000ff) ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		(TE2((t1 >> 24)       ) & 0xff000000) ^
		(TE3((t2 >> 16) & 0xff) & 0x00ff0000) ^
		(TE0((t3 >>  8) & 0xff) & 0x0000ff00) ^
		(TE1((t0      ) & 0xff) & 0x000000ff) ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		(TE2((t2 >> 24)       ) & 0xff000000) ^
		(TE3((t3 >> 16) & 0xff) & 0x00ff0000) ^
		(TE0((t0 >>  8) & 0xff) & 0x0000ff00) ^
		(TE1((t1      ) & 0xff) & 0x000000ff) ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		(TE2((t3 >> 24)       ) & 0xff000000) ^
		(TE3((t0 >> 16) & 0xff) & 0x00ff0000) ^
		(TE0((t1 >>  8) & 0xff) & 0x0000ff00) ^
		(TE1((t2      ) & 0xff) & 0x000000ff) ^
		rk[3];
	PUTU32(out + 12, s3);
#endif	/* ?AES_USE_TE4 */
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

	if (lt->content != TD0) {
		if (THREAD < AES_SHARED_THREADS)
			for (uint i = 0; i < 256; i++)
				lt->T0[i][THREAD] = Td0[i];
		if (THREAD == 0)
			lt->content = TD0;
#if AES_LOCAL_BARRIER
		barrier(CLK_LOCAL_MEM_FENCE);
#endif
	}
#endif	/* AES_LOCAL_TABLES */

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
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[ 4];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[ 5];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[ 6];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[ 7];
	/* round 2: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[ 8];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[ 9];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[10];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[11];
	/* round 3: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[12];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[13];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[14];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[15];
	/* round 4: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[16];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[17];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[18];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[19];
	/* round 5: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[20];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[21];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[22];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[23];
	/* round 6: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[24];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[25];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[26];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[27];
	/* round 7: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[28];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[29];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[30];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[31];
	/* round 8: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[32];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[33];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[34];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[35];
	/* round 9: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[36];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[37];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[38];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[40];
		s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[41];
		s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[42];
		s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[43];
		/* round 11: */
		t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[44];
		t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[45];
		t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[46];
		t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >>  8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[48];
			s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >>  8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[49];
			s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >>  8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[50];
			s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >>  8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[51];
			/* round 13: */
			t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >>  8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[52];
			t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >>  8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[53];
			t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >>  8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[54];
			t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >>  8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[55];
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
			TD0((s0 >> 24)       ) ^
			TD1((s3 >> 16) & 0xff) ^
			TD2((s2 >>  8) & 0xff) ^
			TD3((s1      ) & 0xff) ^
			rk[4];
		t1 =
			TD0((s1 >> 24)       ) ^
			TD1((s0 >> 16) & 0xff) ^
			TD2((s3 >>  8) & 0xff) ^
			TD3((s2      ) & 0xff) ^
			rk[5];
		t2 =
			TD0((s2 >> 24)       ) ^
			TD1((s1 >> 16) & 0xff) ^
			TD2((s0 >>  8) & 0xff) ^
			TD3((s3      ) & 0xff) ^
			rk[6];
		t3 =
			TD0((s3 >> 24)       ) ^
			TD1((s2 >> 16) & 0xff) ^
			TD2((s1 >>  8) & 0xff) ^
			TD3((s0      ) & 0xff) ^
			rk[7];

		rk += 8;
		if (--r == 0) {
			break;
		}

		s0 =
			TD0((t0 >> 24)       ) ^
			TD1((t3 >> 16) & 0xff) ^
			TD2((t2 >>  8) & 0xff) ^
			TD3((t1      ) & 0xff) ^
			rk[0];
		s1 =
			TD0((t1 >> 24)       ) ^
			TD1((t0 >> 16) & 0xff) ^
			TD2((t3 >>  8) & 0xff) ^
			TD3((t2      ) & 0xff) ^
			rk[1];
		s2 =
			TD0((t2 >> 24)       ) ^
			TD1((t1 >> 16) & 0xff) ^
			TD2((t0 >>  8) & 0xff) ^
			TD3((t3      ) & 0xff) ^
			rk[2];
		s3 =
			TD0((t3 >> 24)       ) ^
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
#if AES_LOCAL_TABLES && TD4_LOCAL
	if (lt->content != TD4) {
		if (THREAD < AES_SHARED_THREADS)
			for (uint i = 0; i < 256; i++)
				lt->T0[i][THREAD] = Td4[i];
		if (THREAD == 0)
			lt->content = TD4;
#if AES_LOCAL_BARRIER
		barrier(CLK_LOCAL_MEM_FENCE);
#endif
	}
#endif	/* AES_LOCAL_TABLES && TD4_LOCAL */

#if TD4_32_BIT
	s0 =
		( ((uint)(TD4((t0 >> 24)))) & 0xff000000U) ^
		(TD4((t3 >> 16) & 0xff) & 0x00ff0000U) ^
		(TD4((t2 >>  8) & 0xff) & 0x0000ff00U) ^
		(TD4((t1      ) & 0xff) & 0x000000ffU) ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		( ((uint)(TD4((t1 >> 24)))) & 0xff000000U) ^
		(TD4((t0 >> 16) & 0xff) & 0x00ff0000U) ^
		(TD4((t3 >>  8) & 0xff) & 0x0000ff00U) ^
		(TD4((t2      ) & 0xff) & 0x000000ffU) ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		( ((uint)(TD4((t2 >> 24)))) & 0xff000000U) ^
		(TD4((t1 >> 16) & 0xff) & 0x00ff0000U) ^
		(TD4((t0 >>  8) & 0xff) & 0x0000ff00U) ^
		(TD4((t3      ) & 0xff) & 0x000000ffU) ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		( ((uint)(TD4((t3 >> 24)))) & 0xff000000U) ^
		(TD4((t2 >> 16) & 0xff) & 0x00ff0000U) ^
		(TD4((t1 >>  8) & 0xff) & 0x0000ff00U) ^
		(TD4((t0      ) & 0xff) & 0x000000ffU) ^
		rk[3];
	PUTU32(out + 12, s3);
#else	/* !TD4_32_BIT */
	s0 =
		( ((uint)(TD4((t0 >> 24)))) << 24) ^
		(TD4((t3 >> 16) & 0xff) << 16) ^
		(TD4((t2 >>  8) & 0xff) <<  8) ^
		(TD4((t1      ) & 0xff))       ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		( ((uint)(TD4((t1 >> 24)))) << 24) ^
		(TD4((t0 >> 16) & 0xff) << 16) ^
		(TD4((t3 >>  8) & 0xff) <<  8) ^
		(TD4((t2      ) & 0xff))       ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		( ((uint)(TD4((t2 >> 24)))) << 24) ^
		(TD4((t1 >> 16) & 0xff) << 16) ^
		(TD4((t0 >>  8) & 0xff) <<  8) ^
		(TD4((t3      ) & 0xff))       ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		( ((uint)(TD4((t3 >> 24)))) << 24) ^
		(TD4((t2 >> 16) & 0xff) << 16) ^
		(TD4((t1 >>  8) & 0xff) <<  8) ^
		(TD4((t0      ) & 0xff))       ^
		rk[3];
	PUTU32(out + 12, s3);
#endif	/* TD4_32_BIT */
}

#endif /* _AES_PLAIN */
