/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005,2010 by Solar Designer
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
 * we'd be past the end of K[] since we start at -1. */
	DES_bs_all.s1[0] = 57;

/* The same for second bits */
	for (index = 0; index < 0x100; index++) {
		bit = DES_bs_all.s1[index];
		bit += DES_bs_all.s1[index >> bit];
		DES_bs_all.s2[index] = (bit <= 8) ? bit : 57;
	}

/* Convert to byte offsets */
	for (index = 0; index < 0x100; index++)
		DES_bs_all.s1[index] *= sizeof(DES_bs_vector);

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
/* new is NUL-terminated, but not NUL-padded to any length;
 * old is NUL-padded to 8 characters, but not always NUL-terminated. */
	unsigned char *new = (unsigned char *)key;
	unsigned char *old = DES_bs_all.keys[index];
	DES_bs_vector *k, *kbase;
	ARCH_WORD mask;
	unsigned int xor, s1, s2;

	init_depth();

	mask = (ARCH_WORD)1 << index;
	k = (DES_bs_vector *)&DES_bs_all.K[0] DEPTH - 1;
#if ARCH_ALLOWS_UNALIGNED
	if (*(ARCH_WORD_32 *)new == *(ARCH_WORD_32 *)old &&
	    old[sizeof(ARCH_WORD_32)]) {
		new += sizeof(ARCH_WORD_32);
		old += sizeof(ARCH_WORD_32);
		k += sizeof(ARCH_WORD_32) * 7;
	}
#endif
	while (*new && k < &DES_bs_all.K[55]) {
		kbase = k;
		if ((xor = *new ^ *old)) {
			xor &= 0x7F; /* Note: this might result in xor == 0 */
			*old = *new;
			do {
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				*(ARCH_WORD *)((char *)k + s1) ^= mask;
				if (s2 > 8) break; /* Required for xor == 0 */
				xor >>= s2;
				k[s2] START ^= mask;
				k += s2;
				if (!xor) break;
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				xor >>= s2;
				*(ARCH_WORD *)((char *)k + s1) ^= mask;
				k[s2] START ^= mask;
				k += s2;
			} while (xor);
		}

		new++;
		old++;
		k = kbase + 7;
	}

	while (*old && k < &DES_bs_all.K[55]) {
		kbase = k;
		xor = *old & 0x7F; /* Note: this might result in xor == 0 */
		*old++ = 0;
		do {
			s1 = DES_bs_all.s1[xor];
			s2 = DES_bs_all.s2[xor];
			*(ARCH_WORD *)((char *)k + s1) ^= mask;
			if (s2 > 8) break; /* Required for xor == 0 */
			xor >>= s2;
			k[s2] START ^= mask;
			k += s2;
			if (!xor) break;
			s1 = DES_bs_all.s1[xor];
			s2 = DES_bs_all.s2[xor];
			xor >>= s2;
			*(ARCH_WORD *)((char *)k + s1) ^= mask;
			k[s2] START ^= mask;
			k += s2;
		} while (xor);

		k = kbase + 7;
	}

	DES_bs_all.keys_changed = 1;
}

void DES_bs_set_key_LM(char *key, int index)
{
/* new is NUL-terminated, but not NUL-padded to any length;
 * old is NUL-padded to 7 characters and NUL-terminated. */
	unsigned char *new = (unsigned char *)key;
#if !DES_BS_VECTOR && ARCH_BITS >= 64
	unsigned char *old = DES_bs_all.E.extras.keys[index];
#else
	unsigned char *old = DES_bs_all.keys[index];
#endif
	DES_bs_vector *k, *kbase;
	ARCH_WORD mask;
	unsigned int xor, s1, s2;
	unsigned char plain;

	init_depth();

	mask = (ARCH_WORD)1 << index;
	k = (DES_bs_vector *)&DES_bs_all.K[0] DEPTH - 1;
#if ARCH_ALLOWS_UNALIGNED
	if (*(ARCH_WORD_32 *)new == *(ARCH_WORD_32 *)old &&
	    old[sizeof(ARCH_WORD_32)]) {
		new += sizeof(ARCH_WORD_32);
		old += sizeof(ARCH_WORD_32);
		k += sizeof(ARCH_WORD_32) * 8;
	}
#endif
	while (*new && k < &DES_bs_all.K[55]) {
		plain = DES_bs_all.E.extras.u[ARCH_INDEX(*new)];
		kbase = k;
		if ((xor = plain ^ *old)) {
			*old = plain;
			do {
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				xor >>= s2;
				*(ARCH_WORD *)((char *)k + s1) ^= mask;
				k[s2] START ^= mask;
				k += s2;
				if (!xor) break;
				s1 = DES_bs_all.s1[xor];
				s2 = DES_bs_all.s2[xor];
				xor >>= s2;
				*(ARCH_WORD *)((char *)k + s1) ^= mask;
				k[s2] START ^= mask;
				k += s2;
			} while (xor);
		}

		new++;
		old++;
		k = kbase + 8;
	}

	while (*old) {
		kbase = k;
		xor = *old;
		*old++ = 0;
		do {
			s1 = DES_bs_all.s1[xor];
			s2 = DES_bs_all.s2[xor];
			xor >>= s2;
			*(ARCH_WORD *)((char *)k + s1) ^= mask;
			k[s2] START ^= mask;
			k += s2;
			if (!xor) break;
			s1 = DES_bs_all.s1[xor];
			s2 = DES_bs_all.s2[xor];
			xor >>= s2;
			*(ARCH_WORD *)((char *)k + s1) ^= mask;
			k[s2] START ^= mask;
			k += s2;
		} while (xor);

		k = kbase + 8;
	}
}

#if DES_BS_EXPAND
void DES_bs_expand_keys(void)
{
	int index;
#if DES_BS_VECTOR
	int depth;
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
