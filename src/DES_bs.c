/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005 by Solar Designer
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
	register int depth; \
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

	DES_bs_all.KS_updates = 0;
	if (LM)
		DES_bs_clear_keys_LM();
	else
		DES_bs_clear_keys();

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

/* Initialize the array with right shifts needed to get past the first
 * non-zero bit in the index. */
	for (bit = 0; bit <= 7; bit++)
	for (index = 1 << bit; index < 0x100; index += 2 << bit)
		DES_bs_all.s1[index] = bit + 1;

/* Special case: instead of doing an extra check in *_set_key*(), we
 * might overrun into DES_bs_all.B, which is harmless as long as the
 * order of fields is unchanged.  57 is the smallest value to guarantee
 * we'd be past the end of K[] since we start with ofs = -1. */
	DES_bs_all.s1[0] = 57;

/* The same for second bits. */
	for (index = 0; index < 0x100; index++) {
		bit = DES_bs_all.s1[index];
		bit += DES_bs_all.s1[index >> bit];
		DES_bs_all.s2[index] = (bit <= 8) ? bit : 57;
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
#endif
}

void DES_bs_set_salt(ARCH_WORD salt)
{
	register ARCH_WORD mask;
	register int src, dst;

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

void DES_bs_clear_keys(void)
{
	if (DES_bs_all.KS_updates++ & 0xFFF) return;
	DES_bs_all.KS_updates = 1;
	memset(DES_bs_all.K, 0, sizeof(DES_bs_all.K));
	memset(DES_bs_all.keys, 0, sizeof(DES_bs_all.keys));
	DES_bs_all.keys_changed = 1;
}

void DES_bs_clear_keys_LM(void)
{
	if (DES_bs_all.KS_updates++ & 0xFFF) return;
	DES_bs_all.KS_updates = 1;
	memset(DES_bs_all.K, 0, sizeof(DES_bs_all.K));
#if !DES_BS_VECTOR && ARCH_BITS >= 64
	memset(DES_bs_all.E.extras.keys, 0, sizeof(DES_bs_all.E.extras.keys));
#else
	memset(DES_bs_all.keys, 0, sizeof(DES_bs_all.keys));
#endif
}

void DES_bs_set_key(char *key, int index)
{
	register unsigned char *new = (unsigned char *)key;
	register unsigned char *old = DES_bs_all.keys[index];
	register ARCH_WORD mask;
	register unsigned int xor;
	register int ofs, bit, s1, s2;

	init_depth();

	mask = (ARCH_WORD)1 << index;
	ofs = -1;
	while ((*new || *old) && ofs < 55) {
		if ((xor = *new ^ *old)) {
			xor &= 0x7F; /* Note: this might result in xor == 0 */
			*old = *new;
			bit = ofs;
			do {
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				DES_bs_all.K[bit + s1] DEPTH ^= mask;
				if (s2 > 8) break; /* Required for xor == 0 */
				xor >>= s2;
				DES_bs_all.K[bit += s2] DEPTH ^= mask;
				if (!xor) break;
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				xor >>= s2;
				DES_bs_all.K[bit + s1] DEPTH ^= mask;
				DES_bs_all.K[bit += s2] DEPTH ^= mask;
			} while (xor);
		}

		if (*new) new++;
		old++;
		ofs += 7;
	}

	DES_bs_all.keys_changed = 1;
}

void DES_bs_set_key_LM(char *key, int index)
{
	register unsigned char *new = (unsigned char *)key;
#if !DES_BS_VECTOR && ARCH_BITS >= 64
	register unsigned char *old = DES_bs_all.E.extras.keys[index];
#else
	register unsigned char *old = DES_bs_all.keys[index];
#endif
	register unsigned char plain;
	register ARCH_WORD mask;
	register unsigned int xor;
	register int ofs, bit, s1, s2;

	init_depth();

	mask = (ARCH_WORD)1 << index;
	ofs = -1;
	while ((*new || *old) && ofs < 55) {
		plain = DES_bs_all.E.extras.u[ARCH_INDEX(*new)];
		if ((xor = plain ^ *old)) {
			*old = plain;
			bit = ofs;
			do {
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				xor >>= s2;
				DES_bs_all.K[bit + s1] DEPTH ^= mask;
				DES_bs_all.K[bit += s2] DEPTH ^= mask;
				if (!xor) break;
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				xor >>= s2;
				DES_bs_all.K[bit + s1] DEPTH ^= mask;
				DES_bs_all.K[bit += s2] DEPTH ^= mask;
			} while (xor);
		}

		if (*new) new++;
		old++;
		ofs += 8;
	}
}

#if DES_BS_EXPAND
void DES_bs_expand_keys(void)
{
	register int index;
#if DES_BS_VECTOR
	register int depth;
#endif

	if (!DES_bs_all.keys_changed) return;

	for (index = 0; index < 0x300; index++)
	for_each_depth()
#if DES_BS_VECTOR
		DES_bs_all.KS.v[index] DEPTH = DES_bs_all.KSp[index] DEPTH;
#else
		DES_bs_all.KS.v[index] = *DES_bs_all.KSp[index];
#endif

	DES_bs_all.keys_changed = 0;
}
#endif

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
	register int result;

	init_depth();

	result = (DES_bs_all.B[0] DEPTH >> index) & 1;
	result |= ((DES_bs_all.B[1] DEPTH >> index) & 1) << 1;
	result |= ((DES_bs_all.B[2] DEPTH >> index) & 1) << 2;
	result |= ((DES_bs_all.B[3] DEPTH >> index) & 1) << 3;
	if (count == 4) return result;

	result |= ((DES_bs_all.B[4] DEPTH >> index) & 1) << 4;
	result |= ((DES_bs_all.B[5] DEPTH >> index) & 1) << 5;
	result |= ((DES_bs_all.B[6] DEPTH >> index) & 1) << 6;
	result |= ((DES_bs_all.B[7] DEPTH >> index) & 1) << 7;
	if (count == 8) return result;

	result |= ((DES_bs_all.B[8] DEPTH >> index) & 1) << 8;
	result |= ((DES_bs_all.B[9] DEPTH >> index) & 1) << 9;
	result |= ((DES_bs_all.B[10] DEPTH >> index) & 1) << 10;
	result |= ((DES_bs_all.B[11] DEPTH >> index) & 1) << 11;

	return result;
}

/*
 * The trick I used here allows to compare one ciphertext against all the
 * DES_bs_crypt() outputs in just O(log2(ARCH_BITS)) operations, assuming
 * that DES_BS_VECTOR is 0 or 1. This routine isn't vectorized, yet.
 */
int DES_bs_cmp_all(ARCH_WORD *binary)
{
	register ARCH_WORD value, mask;
	register int bit;
#if DES_BS_VECTOR
	register int depth;
#endif

	for_each_depth() {
		value = binary[0];

		mask = DES_bs_all.B[0] DEPTH ^ -(value & 1);
		mask |= DES_bs_all.B[1] DEPTH ^ -((value >> 1) & 1);
		if (mask == ~(ARCH_WORD)0) goto next_depth;
		mask |= DES_bs_all.B[2] DEPTH ^ -((value >> 2) & 1);
		mask |= DES_bs_all.B[3] DEPTH ^ -((value >> 3) & 1);
		if (mask == ~(ARCH_WORD)0) goto next_depth;
		value >>= 4;
		for (bit = 4; bit < 32; bit += 2) {
			mask |= DES_bs_all.B[bit] DEPTH ^
				-(value & 1);
			if (mask == ~(ARCH_WORD)0) goto next_depth;
			mask |= DES_bs_all.B[bit + 1] DEPTH ^
				-((value >> 1) & 1);
			if (mask == ~(ARCH_WORD)0) goto next_depth;
			value >>= 2;
		}

		return 1;
next_depth:
		;
	}

	return 0;
}

int DES_bs_cmp_one(ARCH_WORD *binary, int count, int index)
{
	register int bit;

	init_depth();

	for (bit = 0; bit < count; bit++)
	if (((DES_bs_all.B[bit] DEPTH >> index) ^
		(binary[bit >> 5] >> (bit & 0x1F))) & 1) return 0;

	return 1;
}
