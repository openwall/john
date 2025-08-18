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
 * Copy Tx0/Inv0, and separetely Tx4, tables to local memory. Pointless for CPU
 * (so a regression) but a huge boost for most any GPU.  We'll infer Tx1..Tx3
 * and Inv1..Inv3 using rotates, which is faster as we avoid bank conflicts.
 */
#if !defined AES_LOCAL_TABLES && gpu(DEVICE_INFO)
#define AES_LOCAL_TABLES	1
#endif

/*
 * Formats using two or more keys at once (AES-XTS uses two) must set this. It
 * needs to be a power of two so is named and used as a shift.
 */
#ifndef AES_SIMULTANEOUS_CTX_SHIFT
#define AES_SIMULTANEOUS_CTX_SHIFT    0
#endif

/*
 * Even with 64K LDS, an AMD device can't fit exclusive tables to every thread
 * in a wavefront of 64 threads, so we have to decrease the number.
 * Also, the number of simultaneous AES contexts need to be considered per above.
 */
#if SHARED_MEM_SIZE < (WARP_SIZE * (256*4 + 256) + 2*4 + 4)
#define AES_SHARED_THREADS            (WARP_SIZE >> (AES_SIMULTANEOUS_CTX_SHIFT + 1))
#else
#define AES_SHARED_THREADS            (WARP_SIZE >> (AES_SIMULTANEOUS_CTX_SHIFT))
#endif

#define AES_SHARED_THREADS_MASK       (AES_SHARED_THREADS - 1)

#include "opencl_aes_tables.h"
#if AES_LOCAL_TABLES
#include "opencl_rotate.h"
#endif

/* AES-128 has 10 rounds, AES-192 has 12 and AES-256 has 14 rounds. */
#define AES_MAXNR   14

enum table { TE0, TE4, TD0, TD4, INV };

typedef struct aes_tables {
#if AES_LOCAL_TABLES
	u32 T0[256][AES_SHARED_THREADS];
	u8 T4[64][AES_SHARED_THREADS][4];
	enum table content0;
	enum table content4;
#else	/* !AES_LOCAL_TABLES */
	u32 dummy;
#endif
} aes_local_t;

typedef struct aes_key_st {
	uint rd_key[4 * (AES_MAXNR + 1)];
	int rounds;
	__local aes_local_t *lt;
} AES_KEY;

#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >> 8); (ct)[3] = (u8)(st); }

#if AES_LOCAL_TABLES

#define TE0(i)	lt->T0[i][THREAD & AES_SHARED_THREADS_MASK]
#define TE1(i)	ror32(TE0(i), 8)
#define TE2(i)	ror32(TE0(i), 16)
#define TE3(i)	ror32(TE0(i), 24)
#define TE4(i)	lt->T4[(i) >> 2][THREAD & AES_SHARED_THREADS_MASK][(i) & 3]
#define TD0(i)	lt->T0[i][THREAD & AES_SHARED_THREADS_MASK]
#define TD1(i)	ror32(TD0(i), 8)
#define TD2(i)	ror32(TD0(i), 16)
#define TD3(i)	ror32(TD0(i), 24)
#define TD4(i)	lt->T4[(i) >> 2][THREAD & AES_SHARED_THREADS_MASK][(i) & 3]
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

/*
 * Entry point for normal callers. The real function is called
 * directly by AES_set_decrypt_key.
 */
#define AES_set_encrypt_key(key, bits, akey)	  \
	do { AES_set_enc_key(key, bits, akey, 0); } while (0)

/**
 * Expand the cipher key into the encryption key schedule.
 */
INLINE void AES_set_enc_key(AES_KEY_TYPE void *_userKey,
                            const int bits, AES_KEY *key, int decrypt)
{
	AES_KEY_TYPE uchar *userKey = _userKey;
	u32 *rk;

#if AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;

	/* Barrier needed in case decryption ran right before */
	barrier(CLK_LOCAL_MEM_FENCE);
	if (THREAD < AES_SHARED_THREADS)
		for (uint i = 0; i < 256; i++)
			TE0(i) = Te0[i];
	if (THREAD == 0)
		lt->content0 = TE0;

	if (!decrypt) {
		/*
		 * We init T0 table for encrypt here so that function runs as fast as
		 * possible at all with multiple blocks, with no init nor barriers.
		 */
		if (THREAD < AES_SHARED_THREADS)
#pragma unroll 4
			for (uint i = 0; i < 256; i++)
				TE4(i) = Te4[i];

		if (THREAD == 0)
			lt->content4 = TE4;
	}
	/* Needed for the content0 flag so unconditional */
	barrier(CLK_LOCAL_MEM_FENCE);
#endif	/* AES_LOCAL_TABLES */

	rk = key->rd_key;

	rk[0] = GETU32(userKey     );
	rk[1] = GETU32(userKey +  4);
	rk[2] = GETU32(userKey +  8);
	rk[3] = GETU32(userKey + 12);

	if (bits == 128) {
		key->rounds = 10;

		rk[4] = rk[0] ^
			(TE2((rk[3] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[3] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[3]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[3] >> 24)       ) & 0x000000ff) ^
			0x01000000;
		rk[5] = rk[1] ^ rk[4];
		rk[6] = rk[2] ^ rk[5];
		rk[7] = rk[3] ^ rk[6];
		rk[8] = rk[4] ^
			(TE2((rk[7] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[7] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[7]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[7] >> 24)       ) & 0x000000ff) ^
			0x02000000;
		rk[9] = rk[5] ^ rk[8];
		rk[10] = rk[6] ^ rk[9];
		rk[11] = rk[7] ^ rk[10];
		rk[12] = rk[8] ^
			(TE2((rk[11] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[11] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[11]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[11] >> 24)       ) & 0x000000ff) ^
			0x04000000;
		rk[13] = rk[9] ^ rk[12];
		rk[14] = rk[10] ^ rk[13];
		rk[15] = rk[11] ^ rk[14];
		rk[16] = rk[12] ^
			(TE2((rk[15] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[15] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[15]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[15] >> 24)       ) & 0x000000ff) ^
			0x08000000;
		rk[17] = rk[13] ^ rk[16];
		rk[18] = rk[14] ^ rk[17];
		rk[19] = rk[15] ^ rk[18];
		rk[20] = rk[16] ^
			(TE2((rk[19] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[19] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[19]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[19] >> 24)       ) & 0x000000ff) ^
			0x10000000;
		rk[21] = rk[17] ^ rk[20];
		rk[22] = rk[18] ^ rk[21];
		rk[23] = rk[19] ^ rk[22];
		rk[24] = rk[20] ^
			(TE2((rk[23] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[23] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[23]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[23] >> 24)       ) & 0x000000ff) ^
			0x20000000;
		rk[25] = rk[21] ^ rk[24];
		rk[26] = rk[22] ^ rk[25];
		rk[27] = rk[23] ^ rk[26];
		rk[28] = rk[24] ^
			(TE2((rk[27] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[27] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[27]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[27] >> 24)       ) & 0x000000ff) ^
			0x40000000;
		rk[29] = rk[25] ^ rk[28];
		rk[30] = rk[26] ^ rk[29];
		rk[31] = rk[27] ^ rk[30];
		rk[32] = rk[28] ^
			(TE2((rk[31] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[31] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[31]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[31] >> 24)       ) & 0x000000ff) ^
			0x80000000;
		rk[33] = rk[29] ^ rk[32];
		rk[34] = rk[30] ^ rk[33];
		rk[35] = rk[31] ^ rk[34];
		rk[36] = rk[32] ^
			(TE2((rk[35] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[35] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[35]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[35] >> 24)       ) & 0x000000ff) ^
			0x1b000000;
		rk[37] = rk[33] ^ rk[36];
		rk[38] = rk[34] ^ rk[37];
		rk[39] = rk[35] ^ rk[38];
		rk[40] = rk[36] ^
			(TE2((rk[39] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[39] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[39]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[39] >> 24)       ) & 0x000000ff) ^
			0x36000000;
		rk[41] = rk[37] ^ rk[40];
		rk[42] = rk[38] ^ rk[41];
		rk[43] = rk[39] ^ rk[42];
		return;
	}

	rk[4] = GETU32(userKey + 16);
	rk[5] = GETU32(userKey + 20);

	if (bits == 192) {
		key->rounds = 12;

		rk[6] = rk[0] ^
			(TE2((rk[5] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[5] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[5]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[5] >> 24)       ) & 0x000000ff) ^
			0x01000000;
		rk[7] = rk[1] ^ rk[6];
		rk[8] = rk[2] ^ rk[7];
		rk[9] = rk[3] ^ rk[8];
		rk[10] = rk[4] ^ rk[9];
		rk[11] = rk[5] ^ rk[10];
		rk[12] = rk[6] ^
			(TE2((rk[11] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[11] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[11]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[11] >> 24)       ) & 0x000000ff) ^
			0x02000000;
		rk[13] = rk[7] ^ rk[12];
		rk[14] = rk[8] ^ rk[13];
		rk[15] = rk[9] ^ rk[14];
		rk[16] = rk[10] ^ rk[15];
		rk[17] = rk[11] ^ rk[16];
		rk[18] = rk[12] ^
			(TE2((rk[17] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[17] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[17]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[17] >> 24)       ) & 0x000000ff) ^
			0x04000000;
		rk[19] = rk[13] ^ rk[18];
		rk[20] = rk[14] ^ rk[19];
		rk[21] = rk[15] ^ rk[20];
		rk[22] = rk[16] ^ rk[21];
		rk[23] = rk[17] ^ rk[22];
		rk[24] = rk[18] ^
			(TE2((rk[23] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[23] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[23]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[23] >> 24)       ) & 0x000000ff) ^
			0x08000000;
		rk[25] = rk[19] ^ rk[24];
		rk[26] = rk[20] ^ rk[25];
		rk[27] = rk[21] ^ rk[26];
		rk[28] = rk[22] ^ rk[27];
		rk[29] = rk[23] ^ rk[28];
		rk[30] = rk[24] ^
			(TE2((rk[29] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[29] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[29]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[29] >> 24)       ) & 0x000000ff) ^
			0x10000000;
		rk[31] = rk[25] ^ rk[30];
		rk[32] = rk[26] ^ rk[31];
		rk[33] = rk[27] ^ rk[32];
		rk[34] = rk[28] ^ rk[33];
		rk[35] = rk[29] ^ rk[34];
		rk[36] = rk[30] ^
			(TE2((rk[35] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[35] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[35]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[35] >> 24)       ) & 0x000000ff) ^
			0x20000000;
		rk[37] = rk[31] ^ rk[36];
		rk[38] = rk[32] ^ rk[37];
		rk[39] = rk[33] ^ rk[38];
		rk[40] = rk[34] ^ rk[39];
		rk[41] = rk[35] ^ rk[40];
		rk[42] = rk[36] ^
			(TE2((rk[41] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[41] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[41]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[41] >> 24)       ) & 0x000000ff) ^
			0x40000000;
		rk[43] = rk[37] ^ rk[42];
		rk[44] = rk[38] ^ rk[43];
		rk[45] = rk[39] ^ rk[44];
		rk[46] = rk[40] ^ rk[45];
		rk[47] = rk[41] ^ rk[46];
		rk[48] = rk[42] ^
			(TE2((rk[47] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[47] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[47]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[47] >> 24)       ) & 0x000000ff) ^
			0x80000000;
		rk[49] = rk[43] ^ rk[48];
		rk[50] = rk[44] ^ rk[49];
		rk[51] = rk[45] ^ rk[50];

		return;
	}

	rk[6] = GETU32(userKey + 24);
	rk[7] = GETU32(userKey + 28);

	if (bits == 256) {
		key->rounds = 14;

		rk[8] = rk[0] ^
			(TE2((rk[7] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[7] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[7]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[7] >> 24)       ) & 0x000000ff) ^
			0x01000000;
		rk[9] = rk[1] ^ rk[8];
		rk[10] = rk[2] ^ rk[9];
		rk[11] = rk[3] ^ rk[10];
		rk[12] = rk[4] ^
			(TE2((rk[11] >> 24)       ) & 0xff000000) ^
			(TE3((rk[11] >> 16) & 0xff) & 0x00ff0000) ^
			(TE0((rk[11] >>  8) & 0xff) & 0x0000ff00) ^
			(TE1((rk[11]      ) & 0xff) & 0x000000ff);
		rk[13] = rk[5] ^ rk[12];
		rk[14] = rk[6] ^ rk[13];
		rk[15] = rk[7] ^ rk[14];
		rk[16] = rk[8] ^
			(TE2((rk[15] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[15] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[15]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[15] >> 24)       ) & 0x000000ff) ^
			0x02000000;
		rk[17] = rk[9] ^ rk[16];
		rk[18] = rk[10] ^ rk[17];
		rk[19] = rk[11] ^ rk[18];
		rk[20] = rk[12] ^
			(TE2((rk[19] >> 24)       ) & 0xff000000) ^
			(TE3((rk[19] >> 16) & 0xff) & 0x00ff0000) ^
			(TE0((rk[19] >>  8) & 0xff) & 0x0000ff00) ^
			(TE1((rk[19]      ) & 0xff) & 0x000000ff);
		rk[21] = rk[13] ^ rk[20];
		rk[22] = rk[14] ^ rk[21];
		rk[23] = rk[15] ^ rk[22];
		rk[24] = rk[16] ^
			(TE2((rk[23] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[23] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[23]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[23] >> 24)       ) & 0x000000ff) ^
			0x04000000;
		rk[25] = rk[17] ^ rk[24];
		rk[26] = rk[18] ^ rk[25];
		rk[27] = rk[19] ^ rk[26];
		rk[28] = rk[20] ^
			(TE2((rk[27] >> 24)       ) & 0xff000000) ^
			(TE3((rk[27] >> 16) & 0xff) & 0x00ff0000) ^
			(TE0((rk[27] >>  8) & 0xff) & 0x0000ff00) ^
			(TE1((rk[27]      ) & 0xff) & 0x000000ff);
		rk[29] = rk[21] ^ rk[28];
		rk[30] = rk[22] ^ rk[29];
		rk[31] = rk[23] ^ rk[30];
		rk[32] = rk[24] ^
			(TE2((rk[31] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[31] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[31]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[31] >> 24)       ) & 0x000000ff) ^
			0x08000000;
		rk[33] = rk[25] ^ rk[32];
		rk[34] = rk[26] ^ rk[33];
		rk[35] = rk[27] ^ rk[34];
		rk[36] = rk[28] ^
			(TE2((rk[35] >> 24)       ) & 0xff000000) ^
			(TE3((rk[35] >> 16) & 0xff) & 0x00ff0000) ^
			(TE0((rk[35] >>  8) & 0xff) & 0x0000ff00) ^
			(TE1((rk[35]      ) & 0xff) & 0x000000ff);
		rk[37] = rk[29] ^ rk[36];
		rk[38] = rk[30] ^ rk[37];
		rk[39] = rk[31] ^ rk[38];
		rk[40] = rk[32] ^
			(TE2((rk[39] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[39] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[39]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[39] >> 24)       ) & 0x000000ff) ^
			0x10000000;
		rk[41] = rk[33] ^ rk[40];
		rk[42] = rk[34] ^ rk[41];
		rk[43] = rk[35] ^ rk[42];
		rk[44] = rk[36] ^
			(TE2((rk[43] >> 24)       ) & 0xff000000) ^
			(TE3((rk[43] >> 16) & 0xff) & 0x00ff0000) ^
			(TE0((rk[43] >>  8) & 0xff) & 0x0000ff00) ^
			(TE1((rk[43]      ) & 0xff) & 0x000000ff);
		rk[45] = rk[37] ^ rk[44];
		rk[46] = rk[38] ^ rk[45];
		rk[47] = rk[39] ^ rk[46];
		rk[48] = rk[40] ^
			(TE2((rk[47] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[47] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[47]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[47] >> 24)       ) & 0x000000ff) ^
			0x20000000;
		rk[49] = rk[41] ^ rk[48];
		rk[50] = rk[42] ^ rk[49];
		rk[51] = rk[43] ^ rk[50];
		rk[52] = rk[44] ^
			(TE2((rk[51] >> 24)       ) & 0xff000000) ^
			(TE3((rk[51] >> 16) & 0xff) & 0x00ff0000) ^
			(TE0((rk[51] >>  8) & 0xff) & 0x0000ff00) ^
			(TE1((rk[51]      ) & 0xff) & 0x000000ff);
		rk[53] = rk[45] ^ rk[52];
		rk[54] = rk[46] ^ rk[53];
		rk[55] = rk[47] ^ rk[54];
		rk[56] = rk[48] ^
			(TE2((rk[55] >> 16) & 0xff) & 0xff000000) ^
			(TE3((rk[55] >>  8) & 0xff) & 0x00ff0000) ^
			(TE0((rk[55]      ) & 0xff) & 0x0000ff00) ^
			(TE1((rk[55] >> 24)       ) & 0x000000ff) ^
			0x40000000;
		rk[57] = rk[49] ^ rk[56];
		rk[58] = rk[50] ^ rk[57];
		rk[59] = rk[51] ^ rk[58];

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

	/* first, start with an encryption schedule */
	AES_set_enc_key(userKey, bits, key, 1);

#if AES_LOCAL_TABLES
	__local aes_local_t *lt = key->lt;

	barrier(CLK_LOCAL_MEM_FENCE);
	if (THREAD < AES_SHARED_THREADS) {
		for (uint i = 0; i < 256; i++)
			INV0(i) = Inv0[i];
#pragma unroll 4
		for (uint i = 0; i < 256; i++)
			TD4(i) = Td4[i];
	}
	if (THREAD == 0) {
		lt->content0 = INV;
		lt->content4 = TD4;
	}
	barrier(CLK_LOCAL_MEM_FENCE);
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
#if AES_LOCAL_TABLES
	/*
	 * We init T0 table for decrypt here so that function runs as fast as
	 * possible at all with multiple blocks, with no init nor barriers.
	 */
	barrier(CLK_LOCAL_MEM_FENCE);
	if (THREAD < AES_SHARED_THREADS)
		for (uint i = 0; i < 256; i++)
			TD0(i) = Td0[i];
	if (THREAD == 0)
		lt->content0 = TD0;
	barrier(CLK_LOCAL_MEM_FENCE);
#endif	/* AES_LOCAL_TABLES */
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

	/* round 1: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >> 8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[4];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >> 8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[5];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >> 8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[6];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >> 8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[7];
	/* round 2: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >> 8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[8];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >> 8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[9];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >> 8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[10];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >> 8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[11];
	/* round 3: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >> 8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[12];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >> 8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[13];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >> 8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[14];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >> 8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[15];
	/* round 4: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >> 8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[16];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >> 8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[17];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >> 8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[18];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >> 8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[19];
	/* round 5: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >> 8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[20];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >> 8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[21];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >> 8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[22];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >> 8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[23];
	/* round 6: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >> 8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[24];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >> 8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[25];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >> 8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[26];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >> 8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[27];
	/* round 7: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >> 8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[28];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >> 8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[29];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >> 8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[30];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >> 8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[31];
	/* round 8: */
	s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >> 8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[32];
	s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >> 8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[33];
	s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >> 8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[34];
	s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >> 8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[35];
	/* round 9: */
	t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >> 8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[36];
	t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >> 8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[37];
	t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >> 8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[38];
	t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >> 8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >> 8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[40];
		s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >> 8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[41];
		s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >> 8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[42];
		s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >> 8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[43];
		/* round 11: */
		t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >> 8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[44];
		t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >> 8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[45];
		t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >> 8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[46];
		t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >> 8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = TE0(t0 >> 24) ^ TE1((t1 >> 16) & 0xff) ^ TE2((t2 >> 8) & 0xff) ^ TE3(t3 & 0xff) ^ rk[48];
			s1 = TE0(t1 >> 24) ^ TE1((t2 >> 16) & 0xff) ^ TE2((t3 >> 8) & 0xff) ^ TE3(t0 & 0xff) ^ rk[49];
			s2 = TE0(t2 >> 24) ^ TE1((t3 >> 16) & 0xff) ^ TE2((t0 >> 8) & 0xff) ^ TE3(t1 & 0xff) ^ rk[50];
			s3 = TE0(t3 >> 24) ^ TE1((t0 >> 16) & 0xff) ^ TE2((t1 >> 8) & 0xff) ^ TE3(t2 & 0xff) ^ rk[51];
			/* round 13: */
			t0 = TE0(s0 >> 24) ^ TE1((s1 >> 16) & 0xff) ^ TE2((s2 >> 8) & 0xff) ^ TE3(s3 & 0xff) ^ rk[52];
			t1 = TE0(s1 >> 24) ^ TE1((s2 >> 16) & 0xff) ^ TE2((s3 >> 8) & 0xff) ^ TE3(s0 & 0xff) ^ rk[53];
			t2 = TE0(s2 >> 24) ^ TE1((s3 >> 16) & 0xff) ^ TE2((s0 >> 8) & 0xff) ^ TE3(s1 & 0xff) ^ rk[54];
			t3 = TE0(s3 >> 24) ^ TE1((s0 >> 16) & 0xff) ^ TE2((s1 >> 8) & 0xff) ^ TE3(s2 & 0xff) ^ rk[55];
		}
	}
	rk += key->rounds << 2;

	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */
	s0 =
		(TE4((t0 >> 24)       ) << 24) ^
		(TE4((t1 >> 16) & 0xff) << 16) ^
		(TE4((t2 >>  8) & 0xff) <<  8) ^
		(TE4((t3      ) & 0xff))       ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		(TE4((t1 >> 24)       ) << 24) ^
		(TE4((t2 >> 16) & 0xff) << 16) ^
		(TE4((t3 >>  8) & 0xff) <<  8) ^
		(TE4((t0      ) & 0xff))       ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		(TE4((t2 >> 24)       ) << 24) ^
		(TE4((t3 >> 16) & 0xff) << 16) ^
		(TE4((t0 >>  8) & 0xff) <<  8) ^
		(TE4((t1      ) & 0xff))       ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		(TE4((t3 >> 24)       ) << 24) ^
		(TE4((t0 >> 16) & 0xff) << 16) ^
		(TE4((t1 >>  8) & 0xff) <<  8) ^
		(TE4((t2      ) & 0xff))       ^
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

	/* round 1: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >> 8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[4];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >> 8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[5];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >> 8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[6];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >> 8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[7];
	/* round 2: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >> 8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[8];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >> 8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[9];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >> 8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[10];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >> 8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[11];
	/* round 3: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >> 8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[12];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >> 8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[13];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >> 8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[14];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >> 8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[15];
	/* round 4: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >> 8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[16];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >> 8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[17];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >> 8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[18];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >> 8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[19];
	/* round 5: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >> 8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[20];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >> 8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[21];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >> 8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[22];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >> 8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[23];
	/* round 6: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >> 8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[24];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >> 8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[25];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >> 8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[26];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >> 8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[27];
	/* round 7: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >> 8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[28];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >> 8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[29];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >> 8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[30];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >> 8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[31];
	/* round 8: */
	s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >> 8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[32];
	s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >> 8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[33];
	s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >> 8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[34];
	s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >> 8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[35];
	/* round 9: */
	t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >> 8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[36];
	t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >> 8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[37];
	t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >> 8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[38];
	t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >> 8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[39];
	if (key->rounds > 10) {
		/* round 10: */
		s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >> 8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[40];
		s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >> 8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[41];
		s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >> 8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[42];
		s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >> 8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[43];
		/* round 11: */
		t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >> 8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[44];
		t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >> 8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[45];
		t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >> 8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[46];
		t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >> 8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[47];
		if (key->rounds > 12) {
			/* round 12: */
			s0 = TD0(t0 >> 24) ^ TD1((t3 >> 16) & 0xff) ^ TD2((t2 >> 8) & 0xff) ^ TD3(t1 & 0xff) ^ rk[48];
			s1 = TD0(t1 >> 24) ^ TD1((t0 >> 16) & 0xff) ^ TD2((t3 >> 8) & 0xff) ^ TD3(t2 & 0xff) ^ rk[49];
			s2 = TD0(t2 >> 24) ^ TD1((t1 >> 16) & 0xff) ^ TD2((t0 >> 8) & 0xff) ^ TD3(t3 & 0xff) ^ rk[50];
			s3 = TD0(t3 >> 24) ^ TD1((t2 >> 16) & 0xff) ^ TD2((t1 >> 8) & 0xff) ^ TD3(t0 & 0xff) ^ rk[51];
			/* round 13: */
			t0 = TD0(s0 >> 24) ^ TD1((s3 >> 16) & 0xff) ^ TD2((s2 >> 8) & 0xff) ^ TD3(s1 & 0xff) ^ rk[52];
			t1 = TD0(s1 >> 24) ^ TD1((s0 >> 16) & 0xff) ^ TD2((s3 >> 8) & 0xff) ^ TD3(s2 & 0xff) ^ rk[53];
			t2 = TD0(s2 >> 24) ^ TD1((s1 >> 16) & 0xff) ^ TD2((s0 >> 8) & 0xff) ^ TD3(s3 & 0xff) ^ rk[54];
			t3 = TD0(s3 >> 24) ^ TD1((s2 >> 16) & 0xff) ^ TD2((s1 >> 8) & 0xff) ^ TD3(s0 & 0xff) ^ rk[55];
		}
	}
	rk += key->rounds << 2;

	/*
	 * apply last round and
	 * map cipher state to byte array block:
	 */

	s0 =
		(TD4((t0 >> 24)       ) << 24) ^
		(TD4((t3 >> 16) & 0xff) << 16) ^
		(TD4((t2 >>  8) & 0xff) <<  8) ^
		(TD4((t1      ) & 0xff))       ^
		rk[0];
	PUTU32(out     , s0);
	s1 =
		(TD4((t1 >> 24)       ) << 24) ^
		(TD4((t0 >> 16) & 0xff) << 16) ^
		(TD4((t3 >>  8) & 0xff) <<  8) ^
		(TD4((t2      ) & 0xff))       ^
		rk[1];
	PUTU32(out +  4, s1);
	s2 =
		(TD4((t2 >> 24)       ) << 24) ^
		(TD4((t1 >> 16) & 0xff) << 16) ^
		(TD4((t0 >>  8) & 0xff) <<  8) ^
		(TD4((t3      ) & 0xff))       ^
		rk[2];
	PUTU32(out +  8, s2);
	s3 =
		(TD4((t3 >> 24)       ) << 24) ^
		(TD4((t2 >> 16) & 0xff) << 16) ^
		(TD4((t1 >>  8) & 0xff) <<  8) ^
		(TD4((t0      ) & 0xff))       ^
		rk[3];
	PUTU32(out + 12, s3);
}

#endif /* _AES_PLAIN */
