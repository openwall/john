/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003 by Solar Designer
 */

#include "arch.h"

#if !DES_BS_ASM
#include "DES_bs.h"

/* Include the S-boxes here, so that the compiler can inline them */
#if DES_BS == 2
#include "DES_bs_s.c"
#else
#include "DES_bs_n.c"
#endif

#define b				DES_bs_all.B
#define e				DES_bs_all.E.E

#if DES_BS_VECTOR
#define kd				[depth]
#define bd				[depth]
#define ed				[depth]
#define for_each_depth() \
	for (depth = 0; depth < DES_BS_VECTOR; depth++)
#else
#if DES_BS_EXPAND
#define kd
#else
#define kd				[0]
#endif
#define bd
#define ed				[0]
#define for_each_depth()
#endif

#define DES_bs_clear_block_8(i) \
	for_each_depth() { \
		b[i] bd = 0; \
		b[i + 1] bd = 0; \
		b[i + 2] bd = 0; \
		b[i + 3] bd = 0; \
		b[i + 4] bd = 0; \
		b[i + 5] bd = 0; \
		b[i + 6] bd = 0; \
		b[i + 7] bd = 0; \
	}

#define DES_bs_clear_block() \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56);

void DES_bs_crypt(int count)
{
#if DES_BS_EXPAND
	DES_bs_vector *k;
#else
	ARCH_WORD **k;
#endif
	int iterations, rounds_and_swapped;
#if DES_BS_VECTOR
	int depth;
#endif

	DES_bs_clear_block();

#if DES_BS_EXPAND
	k = DES_bs_all.KS.v;
#else
	k = DES_bs_all.KS.p;
#endif
	rounds_and_swapped = 8;
	iterations = count;

start:
	for_each_depth()
	s1(e[0] ed ^ k[0] kd, e[1] ed ^ k[1] kd, e[2] ed ^ k[2] kd,
		e[3] ed ^ k[3] kd, e[4] ed ^ k[4] kd, e[5] ed ^ k[5] kd,
		&b[40] bd, &b[48] bd, &b[54] bd, &b[62] bd);
	for_each_depth()
	s2(e[6] ed ^ k[6] kd, e[7] ed ^ k[7] kd, e[8] ed ^ k[8] kd,
		e[9] ed ^ k[9] kd, e[10] ed ^ k[10] kd, e[11] ed ^ k[11] kd,
		&b[44] bd, &b[59] bd, &b[33] bd, &b[49] bd);
	for_each_depth()
	s3(e[12] ed ^ k[12] kd, e[13] ed ^ k[13] kd, e[14] ed ^ k[14] kd,
		e[15] ed ^ k[15] kd, e[16] ed ^ k[16] kd, e[17] ed ^ k[17] kd,
		&b[55] bd, &b[47] bd, &b[61] bd, &b[37] bd);
	for_each_depth()
	s4(e[18] ed ^ k[18] kd, e[19] ed ^ k[19] kd, e[20] ed ^ k[20] kd,
		e[21] ed ^ k[21] kd, e[22] ed ^ k[22] kd, e[23] ed ^ k[23] kd,
		&b[57] bd, &b[51] bd, &b[41] bd, &b[32] bd);
	for_each_depth()
	s5(e[24] ed ^ k[24] kd, e[25] ed ^ k[25] kd, e[26] ed ^ k[26] kd,
		e[27] ed ^ k[27] kd, e[28] ed ^ k[28] kd, e[29] ed ^ k[29] kd,
		&b[39] bd, &b[45] bd, &b[56] bd, &b[34] bd);
	for_each_depth()
	s6(e[30] ed ^ k[30] kd, e[31] ed ^ k[31] kd, e[32] ed ^ k[32] kd,
		e[33] ed ^ k[33] kd, e[34] ed ^ k[34] kd, e[35] ed ^ k[35] kd,
		&b[35] bd, &b[60] bd, &b[42] bd, &b[50] bd);
	for_each_depth()
	s7(e[36] ed ^ k[36] kd, e[37] ed ^ k[37] kd, e[38] ed ^ k[38] kd,
		e[39] ed ^ k[39] kd, e[40] ed ^ k[40] kd, e[41] ed ^ k[41] kd,
		&b[63] bd, &b[43] bd, &b[53] bd, &b[38] bd);
	for_each_depth()
	s8(e[42] ed ^ k[42] kd, e[43] ed ^ k[43] kd, e[44] ed ^ k[44] kd,
		e[45] ed ^ k[45] kd, e[46] ed ^ k[46] kd, e[47] ed ^ k[47] kd,
		&b[36] bd, &b[58] bd, &b[46] bd, &b[52] bd);

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(e[48] ed ^ k[48] kd, e[49] ed ^ k[49] kd, e[50] ed ^ k[50] kd,
		e[51] ed ^ k[51] kd, e[52] ed ^ k[52] kd, e[53] ed ^ k[53] kd,
		&b[8] bd, &b[16] bd, &b[22] bd, &b[30] bd);
	for_each_depth()
	s2(e[54] ed ^ k[54] kd, e[55] ed ^ k[55] kd, e[56] ed ^ k[56] kd,
		e[57] ed ^ k[57] kd, e[58] ed ^ k[58] kd, e[59] ed ^ k[59] kd,
		&b[12] bd, &b[27] bd, &b[1] bd, &b[17] bd);
	for_each_depth()
	s3(e[60] ed ^ k[60] kd, e[61] ed ^ k[61] kd, e[62] ed ^ k[62] kd,
		e[63] ed ^ k[63] kd, e[64] ed ^ k[64] kd, e[65] ed ^ k[65] kd,
		&b[23] bd, &b[15] bd, &b[29] bd, &b[5] bd);
	for_each_depth()
	s4(e[66] ed ^ k[66] kd, e[67] ed ^ k[67] kd, e[68] ed ^ k[68] kd,
		e[69] ed ^ k[69] kd, e[70] ed ^ k[70] kd, e[71] ed ^ k[71] kd,
		&b[25] bd, &b[19] bd, &b[9] bd, &b[0] bd);
	for_each_depth()
	s5(e[72] ed ^ k[72] kd, e[73] ed ^ k[73] kd, e[74] ed ^ k[74] kd,
		e[75] ed ^ k[75] kd, e[76] ed ^ k[76] kd, e[77] ed ^ k[77] kd,
		&b[7] bd, &b[13] bd, &b[24] bd, &b[2] bd);
	for_each_depth()
	s6(e[78] ed ^ k[78] kd, e[79] ed ^ k[79] kd, e[80] ed ^ k[80] kd,
		e[81] ed ^ k[81] kd, e[82] ed ^ k[82] kd, e[83] ed ^ k[83] kd,
		&b[3] bd, &b[28] bd, &b[10] bd, &b[18] bd);
	for_each_depth()
	s7(e[84] ed ^ k[84] kd, e[85] ed ^ k[85] kd, e[86] ed ^ k[86] kd,
		e[87] ed ^ k[87] kd, e[88] ed ^ k[88] kd, e[89] ed ^ k[89] kd,
		&b[31] bd, &b[11] bd, &b[21] bd, &b[6] bd);
	for_each_depth()
	s8(e[90] ed ^ k[90] kd, e[91] ed ^ k[91] kd, e[92] ed ^ k[92] kd,
		e[93] ed ^ k[93] kd, e[94] ed ^ k[94] kd, e[95] ed ^ k[95] kd,
		&b[4] bd, &b[26] bd, &b[14] bd, &b[20] bd);

	k += 96;

	if (--rounds_and_swapped) goto start;
	k -= (0x300 + 48);
	rounds_and_swapped = 0x108;
	if (--iterations) goto swap;
	return;

next:
	k -= (0x300 - 48);
	rounds_and_swapped = 8;
	if (--iterations) goto start;
}

void DES_bs_crypt_25(void)
{
#if DES_BS_EXPAND
	DES_bs_vector *k;
#else
	ARCH_WORD **k;
#endif
	int iterations, rounds_and_swapped;
#if DES_BS_VECTOR
	int depth;
#endif

	DES_bs_clear_block();

#if DES_BS_EXPAND
	k = DES_bs_all.KS.v;
#else
	k = DES_bs_all.KS.p;
#endif
	rounds_and_swapped = 8;
	iterations = 25;

start:
	for_each_depth()
	s1(e[0] ed ^ k[0] kd, e[1] ed ^ k[1] kd, e[2] ed ^ k[2] kd,
		e[3] ed ^ k[3] kd, e[4] ed ^ k[4] kd, e[5] ed ^ k[5] kd,
		&b[40] bd, &b[48] bd, &b[54] bd, &b[62] bd);
	for_each_depth()
	s2(e[6] ed ^ k[6] kd, e[7] ed ^ k[7] kd, e[8] ed ^ k[8] kd,
		e[9] ed ^ k[9] kd, e[10] ed ^ k[10] kd, e[11] ed ^ k[11] kd,
		&b[44] bd, &b[59] bd, &b[33] bd, &b[49] bd);
	for_each_depth()
	s3(b[7] bd ^ k[12] kd, b[8] bd ^ k[13] kd, b[9] bd ^ k[14] kd,
		b[10] bd ^ k[15] kd, b[11] bd ^ k[16] kd, b[12] bd ^ k[17] kd,
		&b[55] bd, &b[47] bd, &b[61] bd, &b[37] bd);
	for_each_depth()
	s4(b[11] bd ^ k[18] kd, b[12] bd ^ k[19] kd, b[13] bd ^ k[20] kd,
		b[14] bd ^ k[21] kd, b[15] bd ^ k[22] kd, b[16] bd ^ k[23] kd,
		&b[57] bd, &b[51] bd, &b[41] bd, &b[32] bd);
	for_each_depth()
	s5(e[24] ed ^ k[24] kd, e[25] ed ^ k[25] kd, e[26] ed ^ k[26] kd,
		e[27] ed ^ k[27] kd, e[28] ed ^ k[28] kd, e[29] ed ^ k[29] kd,
		&b[39] bd, &b[45] bd, &b[56] bd, &b[34] bd);
	for_each_depth()
	s6(e[30] ed ^ k[30] kd, e[31] ed ^ k[31] kd, e[32] ed ^ k[32] kd,
		e[33] ed ^ k[33] kd, e[34] ed ^ k[34] kd, e[35] ed ^ k[35] kd,
		&b[35] bd, &b[60] bd, &b[42] bd, &b[50] bd);
	for_each_depth()
	s7(b[23] bd ^ k[36] kd, b[24] bd ^ k[37] kd, b[25] bd ^ k[38] kd,
		b[26] bd ^ k[39] kd, b[27] bd ^ k[40] kd, b[28] bd ^ k[41] kd,
		&b[63] bd, &b[43] bd, &b[53] bd, &b[38] bd);
	for_each_depth()
	s8(b[27] bd ^ k[42] kd, b[28] bd ^ k[43] kd, b[29] bd ^ k[44] kd,
		b[30] bd ^ k[45] kd, b[31] bd ^ k[46] kd, b[0] bd ^ k[47] kd,
		&b[36] bd, &b[58] bd, &b[46] bd, &b[52] bd);

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(e[48] ed ^ k[48] kd, e[49] ed ^ k[49] kd, e[50] ed ^ k[50] kd,
		e[51] ed ^ k[51] kd, e[52] ed ^ k[52] kd, e[53] ed ^ k[53] kd,
		&b[8] bd, &b[16] bd, &b[22] bd, &b[30] bd);
	for_each_depth()
	s2(e[54] ed ^ k[54] kd, e[55] ed ^ k[55] kd, e[56] ed ^ k[56] kd,
		e[57] ed ^ k[57] kd, e[58] ed ^ k[58] kd, e[59] ed ^ k[59] kd,
		&b[12] bd, &b[27] bd, &b[1] bd, &b[17] bd);
	for_each_depth()
	s3(b[39] bd ^ k[60] kd, b[40] bd ^ k[61] kd, b[41] bd ^ k[62] kd,
		b[42] bd ^ k[63] kd, b[43] bd ^ k[64] kd, b[44] bd ^ k[65] kd,
		&b[23] bd, &b[15] bd, &b[29] bd, &b[5] bd);
	for_each_depth()
	s4(b[43] bd ^ k[66] kd, b[44] bd ^ k[67] kd, b[45] bd ^ k[68] kd,
		b[46] bd ^ k[69] kd, b[47] bd ^ k[70] kd, b[48] bd ^ k[71] kd,
		&b[25] bd, &b[19] bd, &b[9] bd, &b[0] bd);
	for_each_depth()
	s5(e[72] ed ^ k[72] kd, e[73] ed ^ k[73] kd, e[74] ed ^ k[74] kd,
		e[75] ed ^ k[75] kd, e[76] ed ^ k[76] kd, e[77] ed ^ k[77] kd,
		&b[7] bd, &b[13] bd, &b[24] bd, &b[2] bd);
	for_each_depth()
	s6(e[78] ed ^ k[78] kd, e[79] ed ^ k[79] kd, e[80] ed ^ k[80] kd,
		e[81] ed ^ k[81] kd, e[82] ed ^ k[82] kd, e[83] ed ^ k[83] kd,
		&b[3] bd, &b[28] bd, &b[10] bd, &b[18] bd);
	for_each_depth()
	s7(b[55] bd ^ k[84] kd, b[56] bd ^ k[85] kd, b[57] bd ^ k[86] kd,
		b[58] bd ^ k[87] kd, b[59] bd ^ k[88] kd, b[60] bd ^ k[89] kd,
		&b[31] bd, &b[11] bd, &b[21] bd, &b[6] bd);
	for_each_depth()
	s8(b[59] bd ^ k[90] kd, b[60] bd ^ k[91] kd, b[61] bd ^ k[92] kd,
		b[62] bd ^ k[93] kd, b[63] bd ^ k[94] kd, b[32] bd ^ k[95] kd,
		&b[4] bd, &b[26] bd, &b[14] bd, &b[20] bd);

	k += 96;

	if (--rounds_and_swapped) goto start;
	k -= (0x300 + 48);
	rounds_and_swapped = 0x108;
	if (--iterations) goto swap;
	return;

next:
	k -= (0x300 - 48);
	rounds_and_swapped = 8;
	iterations--;
	goto start;
}

#undef kd
#if DES_BS_VECTOR
#define kd				[depth]
#else
#define kd				[0]
#endif

void DES_bs_crypt_LM(void)
{
	ARCH_WORD **k;
	int rounds;
#if DES_BS_VECTOR
	int depth;
#endif

	for_each_depth() {
		b[0] bd = 0;
		b[1] bd = 0;
		b[2] bd = 0;
		b[3] bd = 0;
		b[4] bd = 0;
		b[5] bd = 0;
		b[6] bd = 0;
		b[7] bd = 0;
		b[8] bd = ~(ARCH_WORD)0;
		b[9] bd = ~(ARCH_WORD)0;
		b[10] bd = ~(ARCH_WORD)0;
		b[11] bd = 0;
		b[12] bd = ~(ARCH_WORD)0;
		b[13] bd = 0;
		b[14] bd = 0;
		b[15] bd = 0;
		b[16] bd = 0;
		b[17] bd = 0;
		b[18] bd = 0;
		b[19] bd = 0;
		b[20] bd = 0;
		b[21] bd = 0;
		b[22] bd = 0;
		b[23] bd = ~(ARCH_WORD)0;
		b[24] bd = 0;
		b[25] bd = 0;
		b[26] bd = ~(ARCH_WORD)0;
		b[27] bd = 0;
		b[28] bd = 0;
		b[29] bd = ~(ARCH_WORD)0;
		b[30] bd = ~(ARCH_WORD)0;
		b[31] bd = ~(ARCH_WORD)0;
		b[32] bd = 0;
		b[33] bd = 0;
		b[34] bd = 0;
		b[35] bd = ~(ARCH_WORD)0;
		b[36] bd = 0;
		b[37] bd = ~(ARCH_WORD)0;
		b[38] bd = ~(ARCH_WORD)0;
		b[39] bd = ~(ARCH_WORD)0;
		b[40] bd = 0;
		b[41] bd = 0;
		b[42] bd = 0;
		b[43] bd = 0;
		b[44] bd = 0;
		b[45] bd = ~(ARCH_WORD)0;
		b[46] bd = 0;
		b[47] bd = 0;
		b[48] bd = ~(ARCH_WORD)0;
		b[49] bd = ~(ARCH_WORD)0;
		b[50] bd = 0;
		b[51] bd = 0;
		b[52] bd = 0;
		b[53] bd = 0;
		b[54] bd = ~(ARCH_WORD)0;
		b[55] bd = 0;
		b[56] bd = ~(ARCH_WORD)0;
		b[57] bd = 0;
		b[58] bd = ~(ARCH_WORD)0;
		b[59] bd = 0;
		b[60] bd = ~(ARCH_WORD)0;
		b[61] bd = ~(ARCH_WORD)0;
		b[62] bd = ~(ARCH_WORD)0;
		b[63] bd = ~(ARCH_WORD)0;
	}

	k = DES_bs_all.KS.p;
	rounds = 8;

	do {
		for_each_depth()
		s1(b[31] bd ^ k[0] kd, b[0] bd ^ k[1] kd,
			b[1] bd ^ k[2] kd, b[2] bd ^ k[3] kd,
			b[3] bd ^ k[4] kd, b[4] bd ^ k[5] kd,
			&b[40] bd, &b[48] bd, &b[54] bd, &b[62] bd);
		for_each_depth()
		s2(b[3] bd ^ k[6] kd, b[4] bd ^ k[7] kd,
			b[5] bd ^ k[8] kd, b[6] bd ^ k[9] kd,
			b[7] bd ^ k[10] kd, b[8] bd ^ k[11] kd,
			&b[44] bd, &b[59] bd, &b[33] bd, &b[49] bd);
		for_each_depth()
		s3(b[7] bd ^ k[12] kd, b[8] bd ^ k[13] kd,
			b[9] bd ^ k[14] kd, b[10] bd ^ k[15] kd,
			b[11] bd ^ k[16] kd, b[12] bd ^ k[17] kd,
			&b[55] bd, &b[47] bd, &b[61] bd, &b[37] bd);
		for_each_depth()
		s4(b[11] bd ^ k[18] kd, b[12] bd ^ k[19] kd,
			b[13] bd ^ k[20] kd, b[14] bd ^ k[21] kd,
			b[15] bd ^ k[22] kd, b[16] bd ^ k[23] kd,
			&b[57] bd, &b[51] bd, &b[41] bd, &b[32] bd);
		for_each_depth()
		s5(b[15] bd ^ k[24] kd, b[16] bd ^ k[25] kd,
			b[17] bd ^ k[26] kd, b[18] bd ^ k[27] kd,
			b[19] bd ^ k[28] kd, b[20] bd ^ k[29] kd,
			&b[39] bd, &b[45] bd, &b[56] bd, &b[34] bd);
		for_each_depth()
		s6(b[19] bd ^ k[30] kd, b[20] bd ^ k[31] kd,
			b[21] bd ^ k[32] kd, b[22] bd ^ k[33] kd,
			b[23] bd ^ k[34] kd, b[24] bd ^ k[35] kd,
			&b[35] bd, &b[60] bd, &b[42] bd, &b[50] bd);
		for_each_depth()
		s7(b[23] bd ^ k[36] kd, b[24] bd ^ k[37] kd,
			b[25] bd ^ k[38] kd, b[26] bd ^ k[39] kd,
			b[27] bd ^ k[40] kd, b[28] bd ^ k[41] kd,
			&b[63] bd, &b[43] bd, &b[53] bd, &b[38] bd);
		for_each_depth()
		s8(b[27] bd ^ k[42] kd, b[28] bd ^ k[43] kd,
			b[29] bd ^ k[44] kd, b[30] bd ^ k[45] kd,
			b[31] bd ^ k[46] kd, b[0] bd ^ k[47] kd,
			&b[36] bd, &b[58] bd, &b[46] bd, &b[52] bd);

		for_each_depth()
		s1(b[63] bd ^ k[48] kd, b[32] bd ^ k[49] kd,
			b[33] bd ^ k[50] kd, b[34] bd ^ k[51] kd,
			b[35] bd ^ k[52] kd, b[36] bd ^ k[53] kd,
			&b[8] bd, &b[16] bd, &b[22] bd, &b[30] bd);
		for_each_depth()
		s2(b[35] bd ^ k[54] kd, b[36] bd ^ k[55] kd,
			b[37] bd ^ k[56] kd, b[38] bd ^ k[57] kd,
			b[39] bd ^ k[58] kd, b[40] bd ^ k[59] kd,
			&b[12] bd, &b[27] bd, &b[1] bd, &b[17] bd);
		for_each_depth()
		s3(b[39] bd ^ k[60] kd, b[40] bd ^ k[61] kd,
			b[41] bd ^ k[62] kd, b[42] bd ^ k[63] kd,
			b[43] bd ^ k[64] kd, b[44] bd ^ k[65] kd,
			&b[23] bd, &b[15] bd, &b[29] bd, &b[5] bd);
		for_each_depth()
		s4(b[43] bd ^ k[66] kd, b[44] bd ^ k[67] kd,
			b[45] bd ^ k[68] kd, b[46] bd ^ k[69] kd,
			b[47] bd ^ k[70] kd, b[48] bd ^ k[71] kd,
			&b[25] bd, &b[19] bd, &b[9] bd, &b[0] bd);
		for_each_depth()
		s5(b[47] bd ^ k[72] kd, b[48] bd ^ k[73] kd,
			b[49] bd ^ k[74] kd, b[50] bd ^ k[75] kd,
			b[51] bd ^ k[76] kd, b[52] bd ^ k[77] kd,
			&b[7] bd, &b[13] bd, &b[24] bd, &b[2] bd);
		for_each_depth()
		s6(b[51] bd ^ k[78] kd, b[52] bd ^ k[79] kd,
			b[53] bd ^ k[80] kd, b[54] bd ^ k[81] kd,
			b[55] bd ^ k[82] kd, b[56] bd ^ k[83] kd,
			&b[3] bd, &b[28] bd, &b[10] bd, &b[18] bd);
		for_each_depth()
		s7(b[55] bd ^ k[84] kd, b[56] bd ^ k[85] kd,
			b[57] bd ^ k[86] kd, b[58] bd ^ k[87] kd,
			b[59] bd ^ k[88] kd, b[60] bd ^ k[89] kd,
			&b[31] bd, &b[11] bd, &b[21] bd, &b[6] bd);
		for_each_depth()
		s8(b[59] bd ^ k[90] kd, b[60] bd ^ k[91] kd,
			b[61] bd ^ k[92] kd, b[62] bd ^ k[93] kd,
			b[63] bd ^ k[94] kd, b[32] bd ^ k[95] kd,
			&b[4] bd, &b[26] bd, &b[14] bd, &b[20] bd);

		k += 96;
	} while (--rounds);
}
#endif
