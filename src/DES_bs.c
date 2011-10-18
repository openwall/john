/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005,2010,2011 by Solar Designer
 */

#include <string.h>

#include "arch.h"
#include "common.h"
#include "DES_std.h"
#include "DES_bs.h"

#if DES_BS_VECTOR
#define DEPTH				[depth]
#define START				[0]
#define init_depth() \
	int depth; \
	depth = index >> ARCH_BITS_LOG; \
	index &= (ARCH_BITS - 1);
#define for_each_depth() \
	for (depth = 0; depth < DES_BS_VECTOR; depth++)
#else
#define DEPTH
#define START
#define init_depth()
#define for_each_depth()
#endif

#if !DES_BS_ASM
DES_bs_combined CC_CACHE_ALIGN DES_bs_all;
#endif

static unsigned char DES_LM_KP[56] = {
	1, 2, 3, 4, 5, 6, 7,
	10, 11, 12, 13, 14, 15, 0,
	19, 20, 21, 22, 23, 8, 9,
	28, 29, 30, 31, 16, 17, 18,
	37, 38, 39, 24, 25, 26, 27,
	46, 47, 32, 33, 34, 35, 36,
	55, 40, 41, 42, 43, 44, 45,
	48, 49, 50, 51, 52, 53, 54
};

static unsigned char DES_LM_reverse[16] = {
	0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15
};

#if DES_BS_ASM
extern void DES_bs_init_asm(void);
#endif

void DES_bs_init(int LM)
{
	ARCH_WORD **k;
	int round, index, bit;
	int p, q, s;
	int c;

#if DES_BS_EXPAND
	if (LM)
		k = DES_bs_all.KS.p;
	else
		k = DES_bs_all.KSp;
#else
	k = DES_bs_all.KS.p;
#endif

	s = 0;
	for (round = 0; round < 16; round++) {
		s += DES_ROT[round];
		for (index = 0; index < 48; index++) {
			p = DES_PC2[index];
			q = p < 28 ? 0 : 28;
			p += s;
			while (p >= 28) p -= 28;
			bit = DES_PC1[p + q];
			bit ^= 070;
			bit -= bit >> 3;
			bit = 55 - bit;
			if (LM) bit = DES_LM_KP[bit];
			*k++ = &DES_bs_all.K[bit] START;
		}
	}

	if (LM) {
		for (c = 0; c < 0x100; c++)
		if (c >= 'a' && c <= 'z')
			DES_bs_all.E.extras.u[c] = c & ~0x20;
		else
			DES_bs_all.E.extras.u[c] = c;
	}

#if DES_BS_ASM
	DES_bs_init_asm();
#elif defined(__MMX__) || defined(__SSE2__)
	memset(&DES_bs_all.ones, -1, sizeof(DES_bs_all.ones));
#endif
}

void DES_bs_set_salt(ARCH_WORD salt)
{
	ARCH_WORD mask;
	int src, dst;

	mask = 1;
	for (dst = 0; dst < 48; dst++) {
		if (dst == 24) mask = 1;

		if (salt & mask) {
			if (dst < 24) src = dst + 24; else src = dst - 24;
		} else src = dst;

		DES_bs_all.E.E[dst] = &DES_bs_all.B[DES_E[src]] START;
		DES_bs_all.E.E[dst + 48] = &DES_bs_all.B[DES_E[src] + 32] START;

		mask <<= 1;
	}
}

void DES_bs_set_key(char *key, int index)
{
	unsigned char *dst = &DES_bs_all.xkeys.c[0][index];

	DES_bs_all.keys_changed = 1;

	if (!key[0]) goto fill8;
	*dst = key[0];
	*(dst + DES_BS_DEPTH) = key[1];
	*(dst + DES_BS_DEPTH * 2) = key[2];
	if (!key[1]) goto fill6;
	if (!key[2]) goto fill5;
	*(dst + DES_BS_DEPTH * 3) = key[3];
	*(dst + DES_BS_DEPTH * 4) = key[4];
	if (!key[3]) goto fill4;
	if (!key[4] || !key[5]) goto fill3;
	*(dst + DES_BS_DEPTH * 5) = key[5];
	if (!key[6]) goto fill2;
	*(dst + DES_BS_DEPTH * 6) = key[6];
	*(dst + DES_BS_DEPTH * 7) = key[7];
	return;
fill8:
	dst[0] = 0;
	dst[DES_BS_DEPTH] = 0;
fill6:
	dst[DES_BS_DEPTH * 2] = 0;
fill5:
	dst[DES_BS_DEPTH * 3] = 0;
fill4:
	dst[DES_BS_DEPTH * 4] = 0;
fill3:
	dst[DES_BS_DEPTH * 5] = 0;
fill2:
	dst[DES_BS_DEPTH * 6] = 0;
	dst[DES_BS_DEPTH * 7] = 0;
}

#if ARCH_BITS >= 64
#define MASK_ONES 0x0101010101010101UL
#else
#define MASK_ONES 0x01010101UL
#endif

#define FINALIZE_NEXT_KEY_BIT(s) { \
	unsigned ARCH_WORD m = MASK_ONES << (s); \
	unsigned ARCH_WORD v = (v0 & m) >> (s); \
	int iv; \
	for (iv = 1; iv < (s); iv++) \
		v |= (vp[iv] START & m) >> ((s) - iv); \
	if ((s) > 0) \
		v |= vp[iv] START & m; \
	for (iv = (s) + 1; iv < 8; iv++) \
		v |= (vp[iv] START & m) << (iv - (s)); \
	DES_bs_all.K[ik++] DEPTH = v; \
}

void DES_bs_finalize_keys(void)
{
#if DES_BS_VECTOR
	int depth;
#endif

	if (!DES_bs_all.keys_changed)
		return;
	DES_bs_all.keys_changed = 0;

	for_each_depth() {
		int ik = 0, ic;
		for (ic = 0; ic < 8; ic++) {
			DES_bs_vector *vp =
			    (DES_bs_vector *)&DES_bs_all.xkeys.v[ic][0] DEPTH;
			unsigned ARCH_WORD v0 = vp[0] START;
			FINALIZE_NEXT_KEY_BIT(0)
			FINALIZE_NEXT_KEY_BIT(1)
			FINALIZE_NEXT_KEY_BIT(2)
			FINALIZE_NEXT_KEY_BIT(3)
			FINALIZE_NEXT_KEY_BIT(4)
			FINALIZE_NEXT_KEY_BIT(5)
			FINALIZE_NEXT_KEY_BIT(6)
		}
	}

#if DES_BS_EXPAND
	{
		int index;
		for (index = 0; index < 0x300; index++)
		for_each_depth()
#if DES_BS_VECTOR
			DES_bs_all.KS.v[index] DEPTH =
			    DES_bs_all.KSp[index] DEPTH;
#else
			DES_bs_all.KS.v[index] = *DES_bs_all.KSp[index];
#endif
	}
#endif
}

void DES_bs_set_key_LM(char *key, int index)
{
	unsigned char *dst = &DES_bs_all.xkeys.c[0][index];

/*
 * gcc 4.5.0 on x86_64 would generate redundant movzbl's without explicit
 * use of "long" here.
 */
	unsigned long c = (unsigned char)key[0];
	if (!c) goto fill7;
	*dst = DES_bs_all.E.extras.u[c];
	c = (unsigned char)key[1];
	if (!c) goto fill6;
	*(dst + DES_BS_DEPTH) = DES_bs_all.E.extras.u[c];
	c = (unsigned char)key[2];
	if (!c) goto fill5;
	*(dst + DES_BS_DEPTH * 2) = DES_bs_all.E.extras.u[c];
	c = (unsigned char)key[3];
	if (!c) goto fill4;
	*(dst + DES_BS_DEPTH * 3) = DES_bs_all.E.extras.u[c];
	c = (unsigned char)key[4];
	if (!c) goto fill3;
	*(dst + DES_BS_DEPTH * 4) = DES_bs_all.E.extras.u[c];
	c = (unsigned char)key[5];
	if (!c) goto fill2;
	*(dst + DES_BS_DEPTH * 5) = DES_bs_all.E.extras.u[c];
	c = (unsigned char)key[6];
	*(dst + DES_BS_DEPTH * 6) = DES_bs_all.E.extras.u[c];
	return;
fill7:
	dst[0] = 0;
fill6:
	dst[DES_BS_DEPTH] = 0;
fill5:
	dst[DES_BS_DEPTH * 2] = 0;
fill4:
	dst[DES_BS_DEPTH * 3] = 0;
fill3:
	dst[DES_BS_DEPTH * 4] = 0;
fill2:
	dst[DES_BS_DEPTH * 5] = 0;
	dst[DES_BS_DEPTH * 6] = 0;
}

void DES_bs_finalize_keys_LM(void)
{
#if DES_BS_VECTOR
	int depth;
#endif

	for_each_depth() {
		int ik = 0, ic;
		for (ic = 0; ic < 7; ic++) {
			DES_bs_vector *vp =
			    (DES_bs_vector *)&DES_bs_all.xkeys.v[ic][0] DEPTH;
			unsigned ARCH_WORD v0 = vp[0] START;
			FINALIZE_NEXT_KEY_BIT(0)
			FINALIZE_NEXT_KEY_BIT(1)
			FINALIZE_NEXT_KEY_BIT(2)
			FINALIZE_NEXT_KEY_BIT(3)
			FINALIZE_NEXT_KEY_BIT(4)
			FINALIZE_NEXT_KEY_BIT(5)
			FINALIZE_NEXT_KEY_BIT(6)
			FINALIZE_NEXT_KEY_BIT(7)
		}
	}
}

static ARCH_WORD *DES_bs_get_binary_raw(ARCH_WORD *raw, int count)
{
	static ARCH_WORD out[2];

/* For odd iteration counts, swap L and R here instead of doing it one
 * more time in DES_bs_crypt(). */
	count &= 1;
	out[count] = raw[0];
	out[count ^ 1] = raw[1];

	return out;
}

ARCH_WORD *DES_bs_get_binary(char *ciphertext)
{
	return DES_bs_get_binary_raw(
		DES_raw_get_binary(ciphertext),
		DES_raw_get_count(ciphertext));
}

ARCH_WORD *DES_bs_get_binary_LM(char *ciphertext)
{
	ARCH_WORD block[2], value;
	int l, h;
	int index;

	block[0] = block[1] = 0;
	for (index = 0; index < 16; index += 2) {
		l = atoi16[ARCH_INDEX(ciphertext[index])];
		h = atoi16[ARCH_INDEX(ciphertext[index + 1])];
		value = DES_LM_reverse[l] | (DES_LM_reverse[h] << 4);
		block[index >> 3] |= value << ((index << 2) & 0x18);
	}

	return DES_bs_get_binary_raw(DES_do_IP(block), 1);
}

int DES_bs_get_hash(int index, int count)
{
	int result;
	DES_bs_vector *b;

	init_depth();
	b = (DES_bs_vector *)&DES_bs_all.B[0] DEPTH;

	result = (b[0] START >> index) & 1;
	result |= ((b[1] START >> index) & 1) << 1;
	result |= ((b[2] START >> index) & 1) << 2;
	result |= ((b[3] START >> index) & 1) << 3;
	if (count == 4) return result;

	result |= ((b[4] START >> index) & 1) << 4;
	result |= ((b[5] START >> index) & 1) << 5;
	result |= ((b[6] START >> index) & 1) << 6;
	result |= ((b[7] START >> index) & 1) << 7;
	if (count == 8) return result;

	result |= ((b[8] START >> index) & 1) << 8;
	result |= ((b[9] START >> index) & 1) << 9;
	result |= ((b[10] START >> index) & 1) << 10;
	result |= ((b[11] START >> index) & 1) << 11;
	if (count == 12) return result;

	result |= ((b[12] START >> index) & 1) << 12;
	result |= ((b[13] START >> index) & 1) << 13;
	result |= ((b[14] START >> index) & 1) << 14;
	result |= ((b[15] START >> index) & 1) << 15;
	if (count == 16) return result;

	result |= ((b[16] START >> index) & 1) << 16;
	result |= ((b[17] START >> index) & 1) << 17;
	result |= ((b[18] START >> index) & 1) << 18;
	result |= ((b[19] START >> index) & 1) << 19;

	return result;
}

/*
 * The trick I used here allows to compare one ciphertext against all the
 * DES_bs_crypt() outputs in just O(log2(ARCH_BITS)) operations, assuming
 * that DES_BS_VECTOR is 0 or 1. This routine isn't vectorized, yet.
 */
int DES_bs_cmp_all(ARCH_WORD *binary)
{
	ARCH_WORD value, mask;
	int bit;
#if DES_BS_VECTOR
	int depth;
#endif
	DES_bs_vector *b;

	for_each_depth() {
		value = binary[0];
		b = (DES_bs_vector *)&DES_bs_all.B[0] DEPTH;

		mask = b[0] START ^ -(value & 1);
		mask |= b[1] START ^ -((value >> 1) & 1);
		if (mask == ~(ARCH_WORD)0) goto next_depth;
		mask |= b[2] START ^ -((value >> 2) & 1);
		mask |= b[3] START ^ -((value >> 3) & 1);
		if (mask == ~(ARCH_WORD)0) goto next_depth;
		value >>= 4;
		b += 4;
		for (bit = 4; bit < 32; bit += 2) {
			mask |= b[0] START ^
				-(value & 1);
			if (mask == ~(ARCH_WORD)0) goto next_depth;
			mask |= b[1] START ^
				-((value >> 1) & 1);
			if (mask == ~(ARCH_WORD)0) goto next_depth;
			value >>= 2;
			b += 2;
		}

		return 1;
next_depth:
		;
	}

	return 0;
}

int DES_bs_cmp_one(ARCH_WORD *binary, int count, int index)
{
	int bit;
	DES_bs_vector *b;

	init_depth();
	b = (DES_bs_vector *)&DES_bs_all.B[0] DEPTH;

	for (bit = 0; bit < 31; bit++, b++)
		if (((b[0] START >> index) ^ (binary[0] >> bit)) & 1) return 0;

	for (; bit < count; bit++, b++)
		if (((b[0] START >> index) ^
			(binary[bit >> 5] >> (bit & 0x1F))) & 1) return 0;

	return 1;
}
