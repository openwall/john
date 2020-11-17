/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002,2005,2010-2012,2017,2020 by Solar Designer
 *
 * Addition of single DES encryption with no salt by
 * Deepika Dutta Mishra <dipikadutta at gmail.com> in
 * 2012, no rights reserved.
 */

#ifdef _MSC_VER
#undef _OPENMP
#endif

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "common.h"
#include "DES_std.h"
#include "DES_bs.h"
#include "unicode.h"
#if DES_bs_mt
#include <omp.h>
#include <assert.h>
#endif

#if DES_BS_VECTOR
#define DEPTH				[depth]
#define START				[0]
#define init_depth() \
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

#if DES_bs_mt
int DES_bs_min_kpc, DES_bs_max_kpc;
static int DES_bs_n_alloc;
int DES_bs_nt = 0;
DES_bs_combined *DES_bs_all_p = NULL;
#elif !DES_BS_ASM
DES_bs_combined CC_CACHE_ALIGN DES_bs_all;
#endif

#if !DES_BS_ASM
DES_bs_vector DES_bs_P[64];
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

void DES_bs_init(int LM, int cpt)
{
	ARCH_WORD **k;
	int round, index, bit;
	int p, q, s;
	int c;
#if DES_bs_mt
	int t, n;

/*
 * The array of DES_bs_all's is not exactly tiny, but we use mem_alloc_tiny()
 * for its alignment support and error checking.  We do not need to free() this
 * memory anyway.
 *
 * We allocate one extra entry (will be at "thread number" -1) to hold "ones"
 * and "salt" fields that are shared between threads.
 */
retry:
	n = omp_get_max_threads();
	if (n < 1)
		n = 1;
	if (n > DES_bs_mt_max)
		n = DES_bs_mt_max;
	DES_bs_min_kpc = n * DES_BS_DEPTH;
	if (n > 1) {
		int max = n * cpt;
		while (max > DES_bs_mt_max)
			max -= n;
		n = max;
	}
	DES_bs_max_kpc = n * DES_BS_DEPTH;
	assert(!DES_bs_all_p || n <= DES_bs_n_alloc);
	DES_bs_nt = n;
	if (!DES_bs_all_p) {
		DES_bs_n_alloc = n;
		uint64_t size = (uint64_t)++n * DES_bs_all_size;
		if (size >= (1U << 31) - MEM_ALIGN_PAGE) {
			cpt--;
			assert(cpt > 0);
			goto retry;
		}
		DES_bs_all_p = mem_alloc_tiny(size, MEM_ALIGN_PAGE);
	}
#endif

	for_each_t(n) {
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
				if (LM == 1) bit = DES_LM_KP[bit];
				*k++ = &DES_bs_all.K[bit] START;
			}
		}

/*
 * Have keys go to bit layers where DES_bs_get_hash() and DES_bs_cmp_one()
 * currently expect them.
 */
		for (index = 0; index < DES_BS_DEPTH; index++)
			DES_bs_all.pxkeys[index] =
			    &DES_bs_all.xkeys.c[0][index & 7][index >> 3];

		if (LM == 1) {
			for (c = 0; c < 0x100; c++)
#ifdef BENCH_BUILD
			if (c >= 'a' && c <= 'z')
				DES_bs_all.E.u[c] = c & ~0x20;
			else
				DES_bs_all.E.u[c] = c;
#else
				/* Codepage-aware uppercasing */
				DES_bs_all.E.u[c] = CP_up[c];
#endif
		} else if (LM == 0) {
			for (index = 0; index < 48; index++)
				DES_bs_all.Ens[index] =
				    &DES_bs_all.B[DES_E[index]];
			DES_bs_all.salt = 0xffffff;
#if DES_bs_mt
			DES_bs_set_salt_for_thread(t, 0);
#else
			DES_bs_set_salt(0);
#endif
		}

#if !DES_BS_ASM
		memset(&DES_bs_all.zero, 0, sizeof(DES_bs_all.zero));
		memset(&DES_bs_all.ones, -1, sizeof(DES_bs_all.ones));
		for (bit = 0; bit < 8; bit++)
			memset(&DES_bs_all.masks[bit], 1 << bit,
			    sizeof(DES_bs_all.masks[bit]));
#endif
	}

#if DES_bs_mt
/* Skip the special entry (will be at "thread number" -1) */
	if (n > DES_bs_nt)
		DES_bs_all_p = (DES_bs_combined *)
		    ((char *)DES_bs_all_p + DES_bs_all_size);
#endif

#if DES_BS_ASM
	DES_bs_init_asm();
#endif
}

#if DES_bs_mt
void DES_bs_set_salt(ARCH_WORD salt)
{
	DES_bs_all_by_tnum(-1).salt = salt;
}
#endif

void DES_bs_set_key(char *key, int index)
{
	unsigned char *dst;

	init_t();

	dst = DES_bs_all.pxkeys[index];

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

void DES_bs_set_key_LM(char *key, int index)
{
	unsigned long c;
	unsigned char *dst;

	init_t();

	dst = DES_bs_all.pxkeys[index];

/*
 * gcc 4.5.0 on x86_64 would generate redundant movzbl's without explicit
 * use of "long" here.
 */
	c = (unsigned char)key[0];
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

static uint32_t *DES_bs_get_binary_raw(ARCH_WORD *raw, int count)
{
	static uint32_t out[2];

/* For odd iteration counts, swap L and R here instead of doing it one
 * more time in DES_bs_crypt(). */
	count &= 1;
	out[count] = raw[0];
	out[count ^ 1] = raw[1];

	return out;
}

uint32_t *DES_bs_get_binary(char *ciphertext)
{
	return DES_bs_get_binary_raw(
		DES_raw_get_binary(ciphertext),
		DES_raw_get_count(ciphertext));
}

uint32_t *DES_bs_get_binary_LM(char *ciphertext)
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

char *DES_bs_get_source_LM(uint32_t *raw)
{
	static char out[17];
	char *p;
	ARCH_WORD swapped[2], *block, value;
	int l, h;
	int index;

	swapped[0] = raw[1];
	swapped[1] = raw[0];

	block = DES_do_FP(swapped);

	p = out;
	for (index = 0; index < 16; index += 2) {
		value = (block[index >> 3] >> ((index << 2) & 0x18)) & 0xff;
		l = DES_LM_reverse[value & 0xf];
		h = DES_LM_reverse[value >> 4];
		*p++ = itoa16[l];
		*p++ = itoa16[h];
	}
	*p = 0;

	return out;
}

static MAYBE_INLINE int DES_bs_get_hash(int index, int count, int trip)
{
	int result;
	DES_bs_vector *b;
#if !ARCH_LITTLE_ENDIAN || DES_BS_VECTOR
	int depth;
#endif

	init_t();

#if ARCH_LITTLE_ENDIAN
/*
 * This is merely an optimization.  Nothing will break if this check for
 * little-endian archs is removed, even if the arch is in fact little-endian.
 */
	init_depth();
	b = (DES_bs_vector *)&DES_bs_all.B[0] DEPTH;
#define GET_BIT(bit) \
	(((unsigned ARCH_WORD)b[(bit)] START >> index) & 1)
#else
	depth = index >> 3;
	index &= 7;
	b = (DES_bs_vector *)((unsigned char *)&DES_bs_all.B[0] START + depth);
#define GET_BIT(bit) \
	(((unsigned int)*(unsigned char *)&b[(bit)] START >> index) & 1)
#endif
#define MOVE_BIT(bit) \
	(GET_BIT(bit) << (bit))

	result = GET_BIT(0);
	result |= MOVE_BIT(1);
	result |= MOVE_BIT(2);
	result |= MOVE_BIT(3);
	result |= MOVE_BIT(4);
	result |= MOVE_BIT(5);
	result |= MOVE_BIT(6);
	b += trip; /* for tripcodes, skip bit 7 */
	result |= MOVE_BIT(7);
	if (count == 8) return result;

	result |= MOVE_BIT(8);
	result |= MOVE_BIT(9);
	result |= MOVE_BIT(10);
	result |= MOVE_BIT(11);
	if (count == 12) return result;

	result |= MOVE_BIT(12);
	result |= MOVE_BIT(13);
	b += trip; /* for tripcodes, skip bit 15 */
	result |= MOVE_BIT(14);
	result |= MOVE_BIT(15);
	if (count == 16) return result;

	result |= MOVE_BIT(16);
	result |= MOVE_BIT(17);
	result |= MOVE_BIT(18);
	result |= MOVE_BIT(19);
	if (count == 20) return result;

	result |= MOVE_BIT(20);
	b += trip; /* for tripcodes, skip bit 23 */
	result |= MOVE_BIT(21);
	result |= MOVE_BIT(22);
	result |= MOVE_BIT(23);
	if (count == 24) return result;

	result |= MOVE_BIT(24);
	result |= MOVE_BIT(25);
	result |= MOVE_BIT(26);
	if (count == 27) return result;

	result |= MOVE_BIT(27);
	result |= MOVE_BIT(28);
	result |= MOVE_BIT(29);

#undef GET_BIT
#undef MOVE_BIT

	return result;
}

int DES_bs_get_hash_0(int index)
{
	return DES_bs_get_hash(index, 8, 0);
}

int DES_bs_get_hash_1(int index)
{
	return DES_bs_get_hash(index, 12, 0);
}

int DES_bs_get_hash_2(int index)
{
	return DES_bs_get_hash(index, 16, 0);
}

int DES_bs_get_hash_3(int index)
{
	return DES_bs_get_hash(index, 20, 0);
}

int DES_bs_get_hash_4(int index)
{
	return DES_bs_get_hash(index, 24, 0);
}

int DES_bs_get_hash_5(int index)
{
	return DES_bs_get_hash(index, 27, 0);
}

int DES_bs_get_hash_6(int index)
{
	return DES_bs_get_hash(index, 30, 0);
}

/*
 * The trick used here allows to compare one ciphertext against all the
 * DES_bs_crypt*() outputs in just O(log2(ARCH_BITS)) operations, assuming
 * that DES_BS_VECTOR is 0 or 1. This routine isn't vectorized yet.
 */
int DES_bs_cmp_all(uint32_t *binary, int count)
{
	ARCH_WORD value, mask;
	int bit;
	DES_bs_vector *b;
#if DES_BS_VECTOR
	int depth;
#endif
#if DES_bs_mt
	int t, n = (count + (DES_BS_DEPTH - 1)) / DES_BS_DEPTH;
#endif
	int retval = 0;

#if defined(_OPENMP) && DES_BS_VECTOR
#pragma omp parallel for if(n >= 96) default(none) private(value, mask, bit, b, depth, t) shared(n, DES_bs_all_p, retval, binary)
#elif defined(_OPENMP)
#pragma omp parallel for if(n >= 96) default(none) private(value, mask, bit, b, t) shared(n, DES_bs_all_p, retval, binary)
#endif
	for_each_t(n)
	for_each_depth() {
		value = binary[0];
		b = (DES_bs_vector *)&DES_bs_all.B[0] DEPTH;

		mask = b[0] START ^ -(value & 1);
		mask |= b[1] START ^ -((value >> 1) & 1);
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

#ifdef _OPENMP
		retval = 1;
#else
		return 1;
#endif
next_depth:
		;
	}

	return retval;
}

int DES_bs_cmp_one(uint32_t *binary, int count, int index)
{
	DES_bs_vector *b;
	int depth;

	init_t();

	depth = index >> 3;
	index &= 7;

	b = (DES_bs_vector *)((unsigned char *)&DES_bs_all.B[0] START + depth);

#define GET_BIT(bit) \
	((unsigned int)*(unsigned char *)&b[(bit)] START >> index)
#define CMP_BIT(bit) \
	if ((GET_BIT(bit) ^ (binary[0] >> (bit))) & 1) \
		return 0;

/* Start by comparing bits that are not part of get_hash*() return value */
	CMP_BIT(30);
	CMP_BIT(31);
/* These three overlap with DES_bs_get_hash_6() return value, unfortunately */
	CMP_BIT(27);
	CMP_BIT(28);
	CMP_BIT(29);

	{
		int bit;
		for (bit = 26; bit >= 0; bit--)
			CMP_BIT(bit);
#undef CMP_BIT

		b += 32; count -= 32;
		for (bit = 0; bit < count; bit++)
			if ((GET_BIT(bit) ^ (binary[1] >> bit)) & 1)
				return 0;
#undef GET_BIT
	}

	return 1;
}

int DES_bs_get_hash_0t(int index)
{
	return DES_bs_get_hash(index, 8, 1);
}

int DES_bs_get_hash_1t(int index)
{
	return DES_bs_get_hash(index, 12, 1);
}

int DES_bs_get_hash_2t(int index)
{
	return DES_bs_get_hash(index, 16, 1);
}

int DES_bs_get_hash_3t(int index)
{
	return DES_bs_get_hash(index, 20, 1);
}

int DES_bs_get_hash_4t(int index)
{
	return DES_bs_get_hash(index, 24, 1);
}

int DES_bs_get_hash_5t(int index)
{
	return DES_bs_get_hash(index, 27, 1);
}

void DES_bs_generate_plaintext(unsigned char *plaintext)
{
	int i;
#if DES_BS_VECTOR
	int depth;
#endif

	/* Set same plaintext for all bit layers */
	for (i = 0; i < 64; i++) {
		ARCH_WORD value = -(ARCH_WORD)((plaintext[i >> 3] >> (7 - (i & 7))) & 1);
		for_each_depth()
			DES_bs_P[i] DEPTH = value;
	}
}
