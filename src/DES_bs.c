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

	for (index = 0; index < DES_BS_DEPTH; index++)
		DES_bs_all.pxkeys[index] =
		    &DES_bs_all.xkeys.c[0][index & 7][index >> 3];

	if (LM) {
		for (c = 0; c < 0x100; c++)
		if (c >= 'a' && c <= 'z')
			DES_bs_all.E.u[c] = c & ~0x20;
		else
			DES_bs_all.E.u[c] = c;
	} else {
		for (index = 0; index < 48; index++)
			DES_bs_all.Ens[index] = &DES_bs_all.B[DES_E[index]];
		DES_bs_all.salt = 0xffffff;
		DES_bs_set_salt(0);
	}

#if DES_BS_ASM
	DES_bs_init_asm();
#elif defined(__MMX__) || defined(__SSE2__)
	memset(&DES_bs_all.ones, -1, sizeof(DES_bs_all.ones));
#endif
}

void DES_bs_set_salt(ARCH_WORD salt)
{
	unsigned int new = salt;
	unsigned int old = DES_bs_all.salt;
	int dst;

	DES_bs_all.salt = new;

	for (dst = 0; dst < 24; dst++) {
		if ((new ^ old) & 1) {
			DES_bs_vector *sp1, *sp2;
			int src1 = dst;
			int src2 = dst + 24;
			if (new & 1) {
				src1 = src2;
				src2 = dst;
			}
			sp1 = DES_bs_all.Ens[src1];
			sp2 = DES_bs_all.Ens[src2];
			DES_bs_all.E.E[dst] = (ARCH_WORD *)sp1;
			DES_bs_all.E.E[dst + 24] = (ARCH_WORD *)sp2;
			DES_bs_all.E.E[dst + 48] = (ARCH_WORD *)(sp1 + 32);
			DES_bs_all.E.E[dst + 72] = (ARCH_WORD *)(sp2 + 32);
		}
		new >>= 1;
		old >>= 1;
		if (new == old)
			break;
	}
}

void DES_bs_set_key(char *key, int index)
{
	unsigned char *dst = DES_bs_all.pxkeys[index];

	DES_bs_all.keys_changed = 1;

	if (!key[0]) goto fill8;
	*dst = key[0];
	*(dst + sizeof(DES_bs_vector) * 8) = key[1];
	*(dst + sizeof(DES_bs_vector) * 8 * 2) = key[2];
	if (!key[1]) goto fill6;
	if (!key[2]) goto fill5;
	*(dst + sizeof(DES_bs_vector) * 8 * 3) = key[3];
	*(dst + sizeof(DES_bs_vector) * 8 * 4) = key[4];
	if (!key[3]) goto fill4;
	if (!key[4] || !key[5]) goto fill3;
	*(dst + sizeof(DES_bs_vector) * 8 * 5) = key[5];
	if (!key[6]) goto fill2;
	*(dst + sizeof(DES_bs_vector) * 8 * 6) = key[6];
	*(dst + sizeof(DES_bs_vector) * 8 * 7) = key[7];
	return;
fill8:
	dst[0] = 0;
	dst[sizeof(DES_bs_vector) * 8] = 0;
fill6:
	dst[sizeof(DES_bs_vector) * 8 * 2] = 0;
fill5:
	dst[sizeof(DES_bs_vector) * 8 * 3] = 0;
fill4:
	dst[sizeof(DES_bs_vector) * 8 * 4] = 0;
fill3:
	dst[sizeof(DES_bs_vector) * 8 * 5] = 0;
fill2:
	dst[sizeof(DES_bs_vector) * 8 * 6] = 0;
	dst[sizeof(DES_bs_vector) * 8 * 7] = 0;
}

#if !DES_BS_ASM

#ifdef __i386__
/* register-starved */
#define LOAD_V \
	unsigned ARCH_WORD v0 = vp[0] START; \
	unsigned ARCH_WORD v4 = vp[4] START;
#define v1 vp[1] START
#define v2 vp[2] START
#define v3 vp[3] START
#define v5 vp[5] START
#define v6 vp[6] START
#define v7 vp[7] START
#else
#define LOAD_V \
	unsigned ARCH_WORD v0 = vp[0] START; \
	unsigned ARCH_WORD v1 = vp[1] START; \
	unsigned ARCH_WORD v2 = vp[2] START; \
	unsigned ARCH_WORD v3 = vp[3] START; \
	unsigned ARCH_WORD v4 = vp[4] START; \
	unsigned ARCH_WORD v5 = vp[5] START; \
	unsigned ARCH_WORD v6 = vp[6] START; \
	unsigned ARCH_WORD v7 = vp[7] START;
#endif

#if ARCH_BITS >= 64
#define MASK_ONES 0x0101010101010101UL
#else
#define MASK_ONES 0x01010101UL
#endif

#define FINALIZE_NEXT_KEY_BIT_0 { \
	unsigned ARCH_WORD m = MASK_ONES, va, vb; \
	va = v0 & m; \
	vb = (v1 & m) << 1; \
	va |= (v2 & m) << 2; \
	vb |= (v3 & m) << 3; \
	va |= (v4 & m) << 4; \
	vb |= (v5 & m) << 5; \
	va |= (v6 & m) << 6; \
	vb |= (v7 & m) << 7; \
	*kp++ START = va | vb; \
}

#define FINALIZE_NEXT_KEY_BIT_1 { \
	unsigned ARCH_WORD m = MASK_ONES << 1, va, vb; \
	va = (v0 & m) >> 1; \
	vb = v1 & m; \
	va |= (v2 & m) << 1; \
	vb |= (v3 & m) << 2; \
	va |= (v4 & m) << 3; \
	vb |= (v5 & m) << 4; \
	va |= (v6 & m) << 5; \
	vb |= (v7 & m) << 6; \
	*kp++ START = va | vb; \
}

#define FINALIZE_NEXT_KEY_BIT_2 { \
	unsigned ARCH_WORD m = MASK_ONES << 2, va, vb; \
	va = (v0 & m) >> 2; \
	vb = (v1 & m) >> 1; \
	va |= v2 & m; \
	vb |= (v3 & m) << 1; \
	va |= (v4 & m) << 2; \
	vb |= (v5 & m) << 3; \
	va |= (v6 & m) << 4; \
	vb |= (v7 & m) << 5; \
	*kp++ START = va | vb; \
}

#define FINALIZE_NEXT_KEY_BIT_3 { \
	unsigned ARCH_WORD m = MASK_ONES << 3, va, vb; \
	va = (v0 & m) >> 3; \
	vb = (v1 & m) >> 2; \
	va |= (v2 & m) >> 1; \
	vb |= v3 & m; \
	va |= (v4 & m) << 1; \
	vb |= (v5 & m) << 2; \
	va |= (v6 & m) << 3; \
	vb |= (v7 & m) << 4; \
	*kp++ START = va | vb; \
}

#define FINALIZE_NEXT_KEY_BIT_4 { \
	unsigned ARCH_WORD m = MASK_ONES << 4, va, vb; \
	va = (v0 & m) >> 4; \
	vb = (v1 & m) >> 3; \
	va |= (v2 & m) >> 2; \
	vb |= (v3 & m) >> 1; \
	va |= v4 & m; \
	vb |= (v5 & m) << 1; \
	va |= (v6 & m) << 2; \
	vb |= (v7 & m) << 3; \
	*kp++ START = va | vb; \
}

#define FINALIZE_NEXT_KEY_BIT_5 { \
	unsigned ARCH_WORD m = MASK_ONES << 5, va, vb; \
	va = (v0 & m) >> 5; \
	vb = (v1 & m) >> 4; \
	va |= (v2 & m) >> 3; \
	vb |= (v3 & m) >> 2; \
	va |= (v4 & m) >> 1; \
	vb |= v5 & m; \
	va |= (v6 & m) << 1; \
	vb |= (v7 & m) << 2; \
	*kp++ START = va | vb; \
}

#define FINALIZE_NEXT_KEY_BIT_6 { \
	unsigned ARCH_WORD m = MASK_ONES << 6, va, vb; \
	va = (v0 & m) >> 6; \
	vb = (v1 & m) >> 5; \
	va |= (v2 & m) >> 4; \
	vb |= (v3 & m) >> 3; \
	va |= (v4 & m) >> 2; \
	vb |= (v5 & m) >> 1; \
	va |= v6 & m; \
	vb |= (v7 & m) << 1; \
	*kp++ START = va | vb; \
}

#define FINALIZE_NEXT_KEY_BIT_7 { \
	unsigned ARCH_WORD m = MASK_ONES << 7, va, vb; \
	va = (v0 & m) >> 7; \
	vb = (v1 & m) >> 6; \
	va |= (v2 & m) >> 5; \
	vb |= (v3 & m) >> 4; \
	va |= (v4 & m) >> 3; \
	vb |= (v5 & m) >> 2; \
	va |= (v6 & m) >> 1; \
	vb |= v7 & m; \
	*kp++ START = va | vb; \
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
		DES_bs_vector *kp = (DES_bs_vector *)&DES_bs_all.K[0] DEPTH;
		int ic;
		for (ic = 0; ic < 8; ic++) {
			DES_bs_vector *vp =
			    (DES_bs_vector *)&DES_bs_all.xkeys.v[ic][0] DEPTH;
			LOAD_V
			FINALIZE_NEXT_KEY_BIT_0
			FINALIZE_NEXT_KEY_BIT_1
			FINALIZE_NEXT_KEY_BIT_2
			FINALIZE_NEXT_KEY_BIT_3
			FINALIZE_NEXT_KEY_BIT_4
			FINALIZE_NEXT_KEY_BIT_5
			FINALIZE_NEXT_KEY_BIT_6
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

void DES_bs_finalize_keys_LM(void)
{
#if DES_BS_VECTOR
	int depth;
#endif

	for_each_depth() {
		DES_bs_vector *kp = (DES_bs_vector *)&DES_bs_all.K[0] DEPTH;
		int ic;
		for (ic = 0; ic < 7; ic++) {
			DES_bs_vector *vp =
			    (DES_bs_vector *)&DES_bs_all.xkeys.v[ic][0] DEPTH;
			LOAD_V
			FINALIZE_NEXT_KEY_BIT_0
			FINALIZE_NEXT_KEY_BIT_1
			FINALIZE_NEXT_KEY_BIT_2
			FINALIZE_NEXT_KEY_BIT_3
			FINALIZE_NEXT_KEY_BIT_4
			FINALIZE_NEXT_KEY_BIT_5
			FINALIZE_NEXT_KEY_BIT_6
			FINALIZE_NEXT_KEY_BIT_7
		}
	}
}

#undef v1
#undef v2
#undef v3
#undef v5
#undef v6
#undef v7

#endif

void DES_bs_set_key_LM(char *key, int index)
{
	unsigned char *dst = DES_bs_all.pxkeys[index];

/*
 * gcc 4.5.0 on x86_64 would generate redundant movzbl's without explicit
 * use of "long" here.
 */
	unsigned long c = (unsigned char)key[0];
	if (!c) goto fill7;
	*dst = DES_bs_all.E.u[c];
	c = (unsigned char)key[1];
	if (!c) goto fill6;
	*(dst + sizeof(DES_bs_vector) * 8) = DES_bs_all.E.u[c];
	c = (unsigned char)key[2];
	if (!c) goto fill5;
	*(dst + sizeof(DES_bs_vector) * 8 * 2) = DES_bs_all.E.u[c];
	c = (unsigned char)key[3];
	if (!c) goto fill4;
	*(dst + sizeof(DES_bs_vector) * 8 * 3) = DES_bs_all.E.u[c];
	c = (unsigned char)key[4];
	if (!c) goto fill3;
	*(dst + sizeof(DES_bs_vector) * 8 * 4) = DES_bs_all.E.u[c];
	c = (unsigned char)key[5];
	if (!c) goto fill2;
	*(dst + sizeof(DES_bs_vector) * 8 * 5) = DES_bs_all.E.u[c];
	c = (unsigned char)key[6];
	*(dst + sizeof(DES_bs_vector) * 8 * 6) = DES_bs_all.E.u[c];
	return;
fill7:
	dst[0] = 0;
fill6:
	dst[sizeof(DES_bs_vector) * 8] = 0;
fill5:
	dst[sizeof(DES_bs_vector) * 8 * 2] = 0;
fill4:
	dst[sizeof(DES_bs_vector) * 8 * 3] = 0;
fill3:
	dst[sizeof(DES_bs_vector) * 8 * 4] = 0;
fill2:
	dst[sizeof(DES_bs_vector) * 8 * 5] = 0;
	dst[sizeof(DES_bs_vector) * 8 * 6] = 0;
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
