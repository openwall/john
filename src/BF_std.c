/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010,2011,2013,2015 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * A public domain version of this code, with reentrant and crypt(3)
 * interfaces added, but optimizations specific to password cracking
 * removed, is available at:
 *
 *	https://www.openwall.com/crypt/
 *
 * This implementation is compatible with OpenBSD bcrypt.c (version 2a)
 * by Niels Provos <provos at citi.umich.edu>, and uses some of his
 * ideas. The password hashing algorithm was designed by David Mazieres
 * <dm at lcs.mit.edu>.
 *
 * There's a paper on the algorithm that explains its design decisions:
 *
 *	https://www.usenix.org/events/usenix99/provos.html
 *
 * Some of the tricks in BF_ROUND might be inspired by Eric Young's
 * Blowfish library (I can't be sure if I would think of something if I
 * hadn't seen his code).
 */

#include <stdlib.h>
#include <string.h>

#include "arch.h"
#include "common.h"
#include "BF_std.h"

BF_binary BF_out[BF_N];

#if BF_N > 1
#define INDICES				[BF_N]
#define INDEX				[index]
#define INDEX0				[index]
#define for_each_index() \
	for (index = 0; index < BF_N; index++)
#else
#define INDICES
#define INDEX
#define INDEX0				[0]
#define for_each_index()
#endif

#if BF_X2 == 3
#if BF_mt > 1
#define INDEX2				[lindex]
#else
#define INDEX2				[index]
#endif
#elif BF_X2
#if BF_mt > 1
#define INDEX2				[index & 1]
#else
#define INDEX2				[index]
#endif
#else
#define INDEX2
#endif

#if BF_mt > 1
#if BF_X2 == 3
#define for_each_t() \
	for (t = 0; t < n; t += 3)
#define for_each_ti() \
	for (index = t, lindex = 0; lindex < 3; index++, lindex++)
#elif BF_X2
#define for_each_t() \
	for (t = 0; t < n; t += 2)
#define for_each_ti() \
	for (index = t; index <= t + 1; index++)
#else
#define for_each_t() \
	for (t = 0; t < n; t++)
#define for_each_ti() \
	index = t;
#endif
#else
#define for_each_t()
#define for_each_ti() \
	for_each_index()
#endif

#if BF_mt == 1
/* Current Blowfish context */
#if BF_ASM
extern
#else
static
#endif
struct BF_ctx CC_CACHE_ALIGN BF_current INDICES;
#endif

/* Current Blowfish key */
static BF_key CC_CACHE_ALIGN BF_exp_key INDICES;
#if defined(__linux__) && defined(__sparc__)
static BF_key BF_init_key INDICES;
#else
static BF_key CC_CACHE_ALIGN BF_init_key INDICES;
#endif


#if BF_SCALE
/* Architectures that can shift addresses left by 2 bits with no extra cost */
#define BF_ROUND(ctx, L, R, N, tmp1, tmp2, tmp3, tmp4) \
	tmp1 = L & 0xFF; \
	tmp2 = L >> 8; \
	tmp2 &= 0xFF; \
	tmp3 = L >> 16; \
	tmp3 &= 0xFF; \
	tmp4 = L >> 24; \
	tmp1 = ctx.S[3][tmp1]; \
	tmp2 = ctx.S[2][tmp2]; \
	tmp3 = ctx.S[1][tmp3]; \
	tmp3 += ctx.S[0][tmp4]; \
	tmp3 ^= tmp2; \
	R ^= ctx.P[N + 1]; \
	tmp3 += tmp1; \
	R ^= tmp3;
#else
/* Architectures with no complicated addressing modes supported */
#define BF_INDEX(S, i) \
	(*((BF_word *)(((unsigned char *)S) + (i))))
#define BF_ROUND(ctx, L, R, N, tmp1, tmp2, tmp3, tmp4) \
	tmp1 = L & 0xFF; \
	tmp1 <<= 2; \
	tmp2 = L >> 6; \
	tmp2 &= 0x3FC; \
	tmp3 = L >> 14; \
	tmp3 &= 0x3FC; \
	tmp4 = L >> 22; \
	tmp4 &= 0x3FC; \
	tmp1 = BF_INDEX(ctx.S[3], tmp1); \
	tmp2 = BF_INDEX(ctx.S[2], tmp2); \
	tmp3 = BF_INDEX(ctx.S[1], tmp3); \
	tmp3 += BF_INDEX(ctx.S[0], tmp4); \
	tmp3 ^= tmp2; \
	R ^= ctx.P[N + 1]; \
	tmp3 += tmp1; \
	R ^= tmp3;
#endif

/*
 * Encrypt one block, BF_ROUNDS is hardcoded here.
 */
#define BF_ENCRYPT(ctx, L, R) \
	L ^= ctx.P[0]; \
	BF_ROUND(ctx, L, R, 0, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 1, u1, u2, u3, u4); \
	BF_ROUND(ctx, L, R, 2, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 3, u1, u2, u3, u4); \
	BF_ROUND(ctx, L, R, 4, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 5, u1, u2, u3, u4); \
	BF_ROUND(ctx, L, R, 6, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 7, u1, u2, u3, u4); \
	BF_ROUND(ctx, L, R, 8, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 9, u1, u2, u3, u4); \
	BF_ROUND(ctx, L, R, 10, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 11, u1, u2, u3, u4); \
	BF_ROUND(ctx, L, R, 12, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 13, u1, u2, u3, u4); \
	BF_ROUND(ctx, L, R, 14, u1, u2, u3, u4); \
	BF_ROUND(ctx, R, L, 15, u1, u2, u3, u4); \
	u4 = R; \
	R = L; \
	L = u4 ^ ctx.P[BF_ROUNDS + 1];

#if BF_ASM

extern void (*BF_body)(void);

#else

#if BF_X2 == 3
/*
 * Encrypt three blocks in parallel.  BF_ROUNDS is hardcoded here.
 */
#define BF_ENCRYPT2 \
	L0 ^= BF_current[0].P[0]; \
	L1 ^= BF_current[1].P[0]; \
	L2 ^= BF_current[2].P[0]; \
	BF_ROUND(BF_current[0], L0, R0, 0, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 0, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 0, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 1, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 1, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 1, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], L0, R0, 2, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 2, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 2, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 3, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 3, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 3, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], L0, R0, 4, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 4, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 4, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 5, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 5, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 5, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], L0, R0, 6, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 6, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 6, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 7, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 7, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 7, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], L0, R0, 8, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 8, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 8, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 9, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 9, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 9, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], L0, R0, 10, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 10, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 10, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 11, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 11, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 11, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], L0, R0, 12, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 12, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 12, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 13, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 13, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 13, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], L0, R0, 14, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 14, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], L2, R2, 14, w1, w2, w3, w4); \
	BF_ROUND(BF_current[0], R0, L0, 15, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 15, v1, v2, v3, v4); \
	BF_ROUND(BF_current[2], R2, L2, 15, w1, w2, w3, w4); \
	u4 = R0; \
	v4 = R1; \
	w4 = R2; \
	R0 = L0; \
	R1 = L1; \
	R2 = L2; \
	L0 = u4 ^ BF_current[0].P[BF_ROUNDS + 1]; \
	L1 = v4 ^ BF_current[1].P[BF_ROUNDS + 1]; \
	L2 = w4 ^ BF_current[2].P[BF_ROUNDS + 1];

#define BF_body() \
	L0 = R0 = L1 = R1 = L2 = R2 = 0; \
	ptr = BF_current[0].P; \
	do { \
		BF_ENCRYPT2; \
		*ptr = L0; \
		*(ptr + 1) = R0; \
		*(ptr + (BF_current[1].P - BF_current[0].P)) = L1; \
		*(ptr + (BF_current[1].P - BF_current[0].P) + 1) = R1; \
		*(ptr + (BF_current[2].P - BF_current[0].P)) = L2; \
		*(ptr + (BF_current[2].P - BF_current[0].P) + 1) = R2; \
		ptr += 2; \
	} while (ptr < &BF_current[0].P[BF_ROUNDS + 2]); \
\
	ptr = BF_current[0].S[0]; \
	do { \
		ptr += 2; \
		BF_ENCRYPT2; \
		*(ptr - 2) = L0; \
		*(ptr - 1) = R0; \
		*(ptr - 2 + (BF_current[1].S[0] - BF_current[0].S[0])) = L1; \
		*(ptr - 1 + (BF_current[1].S[0] - BF_current[0].S[0])) = R1; \
		*(ptr - 2 + (BF_current[2].S[0] - BF_current[0].S[0])) = L2; \
		*(ptr - 1 + (BF_current[2].S[0] - BF_current[0].S[0])) = R2; \
	} while (ptr < &BF_current[0].S[3][0xFF]);
#elif BF_X2
/*
 * Encrypt two blocks in parallel.  BF_ROUNDS is hardcoded here.
 */
#define BF_ENCRYPT2 \
	L0 ^= BF_current[0].P[0]; \
	L1 ^= BF_current[1].P[0]; \
	BF_ROUND(BF_current[0], L0, R0, 0, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 0, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 1, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 1, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], L0, R0, 2, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 2, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 3, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 3, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], L0, R0, 4, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 4, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 5, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 5, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], L0, R0, 6, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 6, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 7, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 7, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], L0, R0, 8, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 8, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 9, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 9, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], L0, R0, 10, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 10, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 11, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 11, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], L0, R0, 12, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 12, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 13, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 13, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], L0, R0, 14, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], L1, R1, 14, v1, v2, v3, v4); \
	BF_ROUND(BF_current[0], R0, L0, 15, u1, u2, u3, u4); \
	BF_ROUND(BF_current[1], R1, L1, 15, v1, v2, v3, v4); \
	u4 = R0; \
	v4 = R1; \
	R0 = L0; \
	R1 = L1; \
	L0 = u4 ^ BF_current[0].P[BF_ROUNDS + 1]; \
	L1 = v4 ^ BF_current[1].P[BF_ROUNDS + 1];

#define BF_body() \
	L0 = R0 = L1 = R1 = 0; \
	ptr = BF_current[0].P; \
	do { \
		BF_ENCRYPT2; \
		*ptr = L0; \
		*(ptr + 1) = R0; \
		*(ptr + (BF_current[1].P - BF_current[0].P)) = L1; \
		*(ptr + (BF_current[1].P - BF_current[0].P) + 1) = R1; \
		ptr += 2; \
	} while (ptr < &BF_current[0].P[BF_ROUNDS + 2]); \
\
	ptr = BF_current[0].S[0]; \
	do { \
		ptr += 2; \
		BF_ENCRYPT2; \
		*(ptr - 2) = L0; \
		*(ptr - 1) = R0; \
		*(ptr - 2 + (BF_current[1].S[0] - BF_current[0].S[0])) = L1; \
		*(ptr - 1 + (BF_current[1].S[0] - BF_current[0].S[0])) = R1; \
	} while (ptr < &BF_current[0].S[3][0xFF]);
#else
#define BF_body() \
	L0 = R0 = 0; \
	ptr = BF_current.P; \
	do { \
		BF_ENCRYPT(BF_current, L0, R0); \
		*ptr = L0; \
		*(ptr + 1) = R0; \
		ptr += 2; \
	} while (ptr < &BF_current.P[BF_ROUNDS + 2]); \
\
	ptr = BF_current.S[0]; \
	do { \
		ptr += 2; \
		BF_ENCRYPT(BF_current, L0, R0); \
		*(ptr - 2) = L0; \
		*(ptr - 1) = R0; \
	} while (ptr < &BF_current.S[3][0xFF]);
#endif

#endif

void BF_std_set_key(char *key, int index, int sign_extension_bug) {
	char *ptr = key;
	int i, j;
	BF_word tmp;

	for (i = 0; i < BF_ROUNDS + 2; i++) {
		tmp = 0;
		for (j = 0; j < 4; j++) {
			tmp <<= 8;
			if (sign_extension_bug)
				tmp |= (int)(signed char)*ptr;
			else
				tmp |= (unsigned char)*ptr;

			if (!*ptr) ptr = key; else ptr++;
		}

		BF_exp_key INDEX[i] = tmp;
		BF_init_key INDEX[i] = BF_init_state.P[i] ^ tmp;
	}
}

void BF_std_crypt(BF_salt *salt, int n)
{
#if BF_mt > 1
	int t;
#endif

#if BF_mt > 1 && defined(_OPENMP)
#if defined(WITH_UBSAN)
#pragma omp parallel for
#else
#pragma omp parallel for default(none) private(t) shared(n, BF_init_state, BF_init_key, BF_exp_key, salt, BF_magic_w, BF_out)
#endif
#endif
	for_each_t() {
#if BF_mt > 1
#if BF_X2 == 3
		struct BF_ctx BF_current[3];
#elif BF_X2
		struct BF_ctx BF_current[2];
#else
		struct BF_ctx BF_current;
#endif
#endif

		BF_word L0, R0;
		BF_word u1, u2, u3, u4;
#if BF_X2
		BF_word L1, R1;
		BF_word v1, v2, v3, v4;
#if BF_X2 == 3
		BF_word L2, R2;
		BF_word w1, w2, w3, w4;
#endif
#endif
		BF_word *ptr;
		BF_word count;
#if BF_N > 1
		int index;
#endif
#if BF_X2 == 3 && BF_mt > 1
		int lindex;
#endif

		for_each_ti() {
			int i;

			memcpy(BF_current INDEX2.S,
			    BF_init_state.S, sizeof(BF_current INDEX2.S));
			memcpy(BF_current INDEX2.P,
			    BF_init_key INDEX, sizeof(BF_current INDEX2.P));

			L0 = R0 = 0;
			for (i = 0; i < BF_ROUNDS + 2; i += 2) {
				L0 ^= salt->salt[i & 2];
				R0 ^= salt->salt[(i & 2) + 1];
				BF_ENCRYPT(BF_current INDEX2, L0, R0);
				BF_current INDEX2.P[i] = L0;
				BF_current INDEX2.P[i + 1] = R0;
			}

			ptr = BF_current INDEX2.S[0];
			do {
				ptr += 4;
				L0 ^= salt->salt[(BF_ROUNDS + 2) & 3];
				R0 ^= salt->salt[(BF_ROUNDS + 3) & 3];
				BF_ENCRYPT(BF_current INDEX2, L0, R0);
				*(ptr - 4) = L0;
				*(ptr - 3) = R0;

				L0 ^= salt->salt[(BF_ROUNDS + 4) & 3];
				R0 ^= salt->salt[(BF_ROUNDS + 5) & 3];
				BF_ENCRYPT(BF_current INDEX2, L0, R0);
				*(ptr - 2) = L0;
				*(ptr - 1) = R0;
			} while (ptr < &BF_current INDEX2.S[3][0xFF]);
		}

		count = 1 << salt->rounds;
		do {
			for_each_ti() {
				BF_current INDEX2.P[0] ^= BF_exp_key INDEX[0];
				BF_current INDEX2.P[1] ^= BF_exp_key INDEX[1];
				BF_current INDEX2.P[2] ^= BF_exp_key INDEX[2];
				BF_current INDEX2.P[3] ^= BF_exp_key INDEX[3];
				BF_current INDEX2.P[4] ^= BF_exp_key INDEX[4];
				BF_current INDEX2.P[5] ^= BF_exp_key INDEX[5];
				BF_current INDEX2.P[6] ^= BF_exp_key INDEX[6];
				BF_current INDEX2.P[7] ^= BF_exp_key INDEX[7];
				BF_current INDEX2.P[8] ^= BF_exp_key INDEX[8];
				BF_current INDEX2.P[9] ^= BF_exp_key INDEX[9];
				BF_current INDEX2.P[10] ^= BF_exp_key INDEX[10];
				BF_current INDEX2.P[11] ^= BF_exp_key INDEX[11];
				BF_current INDEX2.P[12] ^= BF_exp_key INDEX[12];
				BF_current INDEX2.P[13] ^= BF_exp_key INDEX[13];
				BF_current INDEX2.P[14] ^= BF_exp_key INDEX[14];
				BF_current INDEX2.P[15] ^= BF_exp_key INDEX[15];
				BF_current INDEX2.P[16] ^= BF_exp_key INDEX[16];
				BF_current INDEX2.P[17] ^= BF_exp_key INDEX[17];
			}

			BF_body();

			u1 = salt->salt[0];
			u2 = salt->salt[1];
			u3 = salt->salt[2];
			u4 = salt->salt[3];
			for_each_ti() {
				BF_current INDEX2.P[0] ^= u1;
				BF_current INDEX2.P[1] ^= u2;
				BF_current INDEX2.P[2] ^= u3;
				BF_current INDEX2.P[3] ^= u4;
				BF_current INDEX2.P[4] ^= u1;
				BF_current INDEX2.P[5] ^= u2;
				BF_current INDEX2.P[6] ^= u3;
				BF_current INDEX2.P[7] ^= u4;
				BF_current INDEX2.P[8] ^= u1;
				BF_current INDEX2.P[9] ^= u2;
				BF_current INDEX2.P[10] ^= u3;
				BF_current INDEX2.P[11] ^= u4;
				BF_current INDEX2.P[12] ^= u1;
				BF_current INDEX2.P[13] ^= u2;
				BF_current INDEX2.P[14] ^= u3;
				BF_current INDEX2.P[15] ^= u4;
				BF_current INDEX2.P[16] ^= u1;
				BF_current INDEX2.P[17] ^= u2;
			}

			BF_body();
		} while (--count);

#if BF_mt == 1
		for_each_ti() {
			L0 = BF_magic_w[0];
			R0 = BF_magic_w[1];

			count = 64;
			do {
				BF_ENCRYPT(BF_current INDEX, L0, R0);
			} while (--count);

			BF_out INDEX0[0] = L0;
			BF_out INDEX0[1] = R0;
		}
#else
		for_each_ti() {
			BF_word L, R;
			BF_word u1, u2, u3, u4;
			BF_word count;
			int i;

			memcpy(&BF_out[index], &BF_magic_w,
			    sizeof(BF_out[index]));

			count = 64;
			do
			for (i = 0; i < 6; i += 2) {
				L = BF_out[index][i];
				R = BF_out[index][i + 1];
				BF_ENCRYPT(BF_current INDEX2, L, R);
				BF_out[index][i] = L;
				BF_out[index][i + 1] = R;
			} while (--count);

/* This has to be bug-compatible with the original implementation :-) */
			BF_out[index][5] &= ~(BF_word)0xFF;
		}
#endif
	}
}

#if BF_mt == 1
void BF_std_crypt_exact(int index)
{
	BF_word L, R;
	BF_word u1, u2, u3, u4;
	BF_word count;
	int i;

	memcpy(&BF_out[index][2], &BF_magic_w[2], sizeof(BF_word) * 4);

	count = 64;
	do
	for (i = 2; i < 6; i += 2) {
		L = BF_out[index][i];
		R = BF_out[index][i + 1];
		BF_ENCRYPT(BF_current INDEX, L, R);
		BF_out[index][i] = L;
		BF_out[index][i + 1] = R;
	} while (--count);

/* This has to be bug-compatible with the original implementation :-) */
	BF_out[index][5] &= ~(BF_word)0xFF;
}
#endif
