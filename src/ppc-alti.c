/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1998-2001,2005 by Solar Designer
 */

#include "arch.h"
#include "common.h"
#include "DES_bs.h"

typedef vector signed int altivec;

/* Include the S-boxes here, so that the compiler can inline them */
#include "DES_bs_a.c"

DES_bs_combined CC_CACHE_ALIGN DES_bs_all;

#define b				DES_bs_all.B
#define e				DES_bs_all.E.E
#define x(p, q)				vec_xor(*(altivec *)p, *(altivec *)q)

#define DES_bs_clear_block_8(i) \
{ \
	altivec *bi = (altivec *)b[i]; \
	vec_st(zero, 0, bi); \
	vec_st(zero, 16, bi); \
	vec_st(zero, 32, bi); \
	vec_st(zero, 48, bi); \
	vec_st(zero, 64, bi); \
	vec_st(zero, 80, bi); \
	vec_st(zero, 96, bi); \
	vec_st(zero, 112, bi); \
}

#define DES_bs_clear_block() \
{ \
	altivec zero; \
	zero = vec_xor(zero, zero); \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56); \
}

void DES_bs_init_asm(void)
{
}

void DES_bs_crypt(int count)
{
#if DES_BS_EXPAND
	DES_bs_vector *k;
#else
	ARCH_WORD **k;
#endif
	int iterations, rounds_and_swapped;

	DES_bs_clear_block();

#if DES_BS_EXPAND
	k = DES_bs_all.KS.v;
#else
	k = DES_bs_all.KS.p;
#endif
	rounds_and_swapped = 8;
	iterations = count;

start:
	s1(x(e[0], k[0]), x(e[1], k[1]), x(e[2], k[2]),
		x(e[3], k[3]), x(e[4], k[4]), x(e[5], k[5]),
		(altivec *)&b[40], (altivec *)&b[48],
		(altivec *)&b[54], (altivec *)&b[62]);
	s2(x(e[6], k[6]), x(e[7], k[7]), x(e[8], k[8]),
		x(e[9], k[9]), x(e[10], k[10]), x(e[11], k[11]),
		(altivec *)&b[44], (altivec *)&b[59],
		(altivec *)&b[33], (altivec *)&b[49]);
	s3(x(e[12], k[12]), x(e[13], k[13]), x(e[14], k[14]),
		x(e[15], k[15]), x(e[16], k[16]), x(e[17], k[17]),
		(altivec *)&b[55], (altivec *)&b[47],
		(altivec *)&b[61], (altivec *)&b[37]);
	s4(x(e[18], k[18]), x(e[19], k[19]), x(e[20], k[20]),
		x(e[21], k[21]), x(e[22], k[22]), x(e[23], k[23]),
		(altivec *)&b[57], (altivec *)&b[51],
		(altivec *)&b[41], (altivec *)&b[32]);
	s5(x(e[24], k[24]), x(e[25], k[25]), x(e[26], k[26]),
		x(e[27], k[27]), x(e[28], k[28]), x(e[29], k[29]),
		(altivec *)&b[39], (altivec *)&b[45],
		(altivec *)&b[56], (altivec *)&b[34]);
	s6(x(e[30], k[30]), x(e[31], k[31]), x(e[32], k[32]),
		x(e[33], k[33]), x(e[34], k[34]), x(e[35], k[35]),
		(altivec *)&b[35], (altivec *)&b[60],
		(altivec *)&b[42], (altivec *)&b[50]);
	s7(x(e[36], k[36]), x(e[37], k[37]), x(e[38], k[38]),
		x(e[39], k[39]), x(e[40], k[40]), x(e[41], k[41]),
		(altivec *)&b[63], (altivec *)&b[43],
		(altivec *)&b[53], (altivec *)&b[38]);
	s8(x(e[42], k[42]), x(e[43], k[43]), x(e[44], k[44]),
		x(e[45], k[45]), x(e[46], k[46]), x(e[47], k[47]),
		(altivec *)&b[36], (altivec *)&b[58],
		(altivec *)&b[46], (altivec *)&b[52]);

	if (rounds_and_swapped == 0x100) goto next;

swap:
	s1(x(e[48], k[48]), x(e[49], k[49]), x(e[50], k[50]),
		x(e[51], k[51]), x(e[52], k[52]), x(e[53], k[53]),
		(altivec *)&b[8], (altivec *)&b[16],
		(altivec *)&b[22], (altivec *)&b[30]);
	s2(x(e[54], k[54]), x(e[55], k[55]), x(e[56], k[56]),
		x(e[57], k[57]), x(e[58], k[58]), x(e[59], k[59]),
		(altivec *)&b[12], (altivec *)&b[27],
		(altivec *)&b[1], (altivec *)&b[17]);
	s3(x(e[60], k[60]), x(e[61], k[61]), x(e[62], k[62]),
		x(e[63], k[63]), x(e[64], k[64]), x(e[65], k[65]),
		(altivec *)&b[23], (altivec *)&b[15],
		(altivec *)&b[29], (altivec *)&b[5]);
	s4(x(e[66], k[66]), x(e[67], k[67]), x(e[68], k[68]),
		x(e[69], k[69]), x(e[70], k[70]), x(e[71], k[71]),
		(altivec *)&b[25], (altivec *)&b[19],
		(altivec *)&b[9], (altivec *)&b[0]);
	s5(x(e[72], k[72]), x(e[73], k[73]), x(e[74], k[74]),
		x(e[75], k[75]), x(e[76], k[76]), x(e[77], k[77]),
		(altivec *)&b[7], (altivec *)&b[13],
		(altivec *)&b[24], (altivec *)&b[2]);
	s6(x(e[78], k[78]), x(e[79], k[79]), x(e[80], k[80]),
		x(e[81], k[81]), x(e[82], k[82]), x(e[83], k[83]),
		(altivec *)&b[3], (altivec *)&b[28],
		(altivec *)&b[10], (altivec *)&b[18]);
	s7(x(e[84], k[84]), x(e[85], k[85]), x(e[86], k[86]),
		x(e[87], k[87]), x(e[88], k[88]), x(e[89], k[89]),
		(altivec *)&b[31], (altivec *)&b[11],
		(altivec *)&b[21], (altivec *)&b[6]);
	s8(x(e[90], k[90]), x(e[91], k[91]), x(e[92], k[92]),
		x(e[93], k[93]), x(e[94], k[94]), x(e[95], k[95]),
		(altivec *)&b[4], (altivec *)&b[26],
		(altivec *)&b[14], (altivec *)&b[20]);

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
	s1(x(e[0], k[0]), x(e[1], k[1]), x(e[2], k[2]),
		x(e[3], k[3]), x(e[4], k[4]), x(e[5], k[5]),
		(altivec *)&b[40], (altivec *)&b[48],
		(altivec *)&b[54], (altivec *)&b[62]);
	s2(x(e[6], k[6]), x(e[7], k[7]), x(e[8], k[8]),
		x(e[9], k[9]), x(e[10], k[10]), x(e[11], k[11]),
		(altivec *)&b[44], (altivec *)&b[59],
		(altivec *)&b[33], (altivec *)&b[49]);
	s3(x(b[7], k[12]), x(b[8], k[13]), x(b[9], k[14]),
		x(b[10], k[15]), x(b[11], k[16]), x(b[12], k[17]),
		(altivec *)&b[55], (altivec *)&b[47],
		(altivec *)&b[61], (altivec *)&b[37]);
	s4(x(b[11], k[18]), x(b[12], k[19]), x(b[13], k[20]),
		x(b[14], k[21]), x(b[15], k[22]), x(b[16], k[23]),
		(altivec *)&b[57], (altivec *)&b[51],
		(altivec *)&b[41], (altivec *)&b[32]);
	s5(x(e[24], k[24]), x(e[25], k[25]), x(e[26], k[26]),
		x(e[27], k[27]), x(e[28], k[28]), x(e[29], k[29]),
		(altivec *)&b[39], (altivec *)&b[45],
		(altivec *)&b[56], (altivec *)&b[34]);
	s6(x(e[30], k[30]), x(e[31], k[31]), x(e[32], k[32]),
		x(e[33], k[33]), x(e[34], k[34]), x(e[35], k[35]),
		(altivec *)&b[35], (altivec *)&b[60],
		(altivec *)&b[42], (altivec *)&b[50]);
	s7(x(b[23], k[36]), x(b[24], k[37]), x(b[25], k[38]),
		x(b[26], k[39]), x(b[27], k[40]), x(b[28], k[41]),
		(altivec *)&b[63], (altivec *)&b[43],
		(altivec *)&b[53], (altivec *)&b[38]);
	s8(x(b[27], k[42]), x(b[28], k[43]), x(b[29], k[44]),
		x(b[30], k[45]), x(b[31], k[46]), x(b[0], k[47]),
		(altivec *)&b[36], (altivec *)&b[58],
		(altivec *)&b[46], (altivec *)&b[52]);

	if (rounds_and_swapped == 0x100) goto next;

swap:
	s1(x(e[48], k[48]), x(e[49], k[49]), x(e[50], k[50]),
		x(e[51], k[51]), x(e[52], k[52]), x(e[53], k[53]),
		(altivec *)&b[8], (altivec *)&b[16],
		(altivec *)&b[22], (altivec *)&b[30]);
	s2(x(e[54], k[54]), x(e[55], k[55]), x(e[56], k[56]),
		x(e[57], k[57]), x(e[58], k[58]), x(e[59], k[59]),
		(altivec *)&b[12], (altivec *)&b[27],
		(altivec *)&b[1], (altivec *)&b[17]);
	s3(x(b[39], k[60]), x(b[40], k[61]), x(b[41], k[62]),
		x(b[42], k[63]), x(b[43], k[64]), x(b[44], k[65]),
		(altivec *)&b[23], (altivec *)&b[15],
		(altivec *)&b[29], (altivec *)&b[5]);
	s4(x(b[43], k[66]), x(b[44], k[67]), x(b[45], k[68]),
		x(b[46], k[69]), x(b[47], k[70]), x(b[48], k[71]),
		(altivec *)&b[25], (altivec *)&b[19],
		(altivec *)&b[9], (altivec *)&b[0]);
	s5(x(e[72], k[72]), x(e[73], k[73]), x(e[74], k[74]),
		x(e[75], k[75]), x(e[76], k[76]), x(e[77], k[77]),
		(altivec *)&b[7], (altivec *)&b[13],
		(altivec *)&b[24], (altivec *)&b[2]);
	s6(x(e[78], k[78]), x(e[79], k[79]), x(e[80], k[80]),
		x(e[81], k[81]), x(e[82], k[82]), x(e[83], k[83]),
		(altivec *)&b[3], (altivec *)&b[28],
		(altivec *)&b[10], (altivec *)&b[18]);
	s7(x(b[55], k[84]), x(b[56], k[85]), x(b[57], k[86]),
		x(b[58], k[87]), x(b[59], k[88]), x(b[60], k[89]),
		(altivec *)&b[31], (altivec *)&b[11],
		(altivec *)&b[21], (altivec *)&b[6]);
	s8(x(b[59], k[90]), x(b[60], k[91]), x(b[61], k[92]),
		x(b[62], k[93]), x(b[63], k[94]), x(b[32], k[95]),
		(altivec *)&b[4], (altivec *)&b[26],
		(altivec *)&b[14], (altivec *)&b[20]);

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

void DES_bs_crypt_LM(void)
{
	altivec zero, ones;
	ARCH_WORD **k;
	int rounds;

	zero = vec_xor(zero, zero);
	ones = vec_nor(zero, zero);
	vec_st(zero, 0, (altivec *)b[0]);
	vec_st(zero, 0, (altivec *)b[1]);
	vec_st(zero, 0, (altivec *)b[2]);
	vec_st(zero, 0, (altivec *)b[3]);
	vec_st(zero, 0, (altivec *)b[4]);
	vec_st(zero, 0, (altivec *)b[5]);
	vec_st(zero, 0, (altivec *)b[6]);
	vec_st(zero, 0, (altivec *)b[7]);
	vec_st(ones, 0, (altivec *)b[8]);
	vec_st(ones, 0, (altivec *)b[9]);
	vec_st(ones, 0, (altivec *)b[10]);
	vec_st(zero, 0, (altivec *)b[11]);
	vec_st(ones, 0, (altivec *)b[12]);
	vec_st(zero, 0, (altivec *)b[13]);
	vec_st(zero, 0, (altivec *)b[14]);
	vec_st(zero, 0, (altivec *)b[15]);
	vec_st(zero, 0, (altivec *)b[16]);
	vec_st(zero, 0, (altivec *)b[17]);
	vec_st(zero, 0, (altivec *)b[18]);
	vec_st(zero, 0, (altivec *)b[19]);
	vec_st(zero, 0, (altivec *)b[20]);
	vec_st(zero, 0, (altivec *)b[21]);
	vec_st(zero, 0, (altivec *)b[22]);
	vec_st(ones, 0, (altivec *)b[23]);
	vec_st(zero, 0, (altivec *)b[24]);
	vec_st(zero, 0, (altivec *)b[25]);
	vec_st(ones, 0, (altivec *)b[26]);
	vec_st(zero, 0, (altivec *)b[27]);
	vec_st(zero, 0, (altivec *)b[28]);
	vec_st(ones, 0, (altivec *)b[29]);
	vec_st(ones, 0, (altivec *)b[30]);
	vec_st(ones, 0, (altivec *)b[31]);
	vec_st(zero, 0, (altivec *)b[32]);
	vec_st(zero, 0, (altivec *)b[33]);
	vec_st(zero, 0, (altivec *)b[34]);
	vec_st(ones, 0, (altivec *)b[35]);
	vec_st(zero, 0, (altivec *)b[36]);
	vec_st(ones, 0, (altivec *)b[37]);
	vec_st(ones, 0, (altivec *)b[38]);
	vec_st(ones, 0, (altivec *)b[39]);
	vec_st(zero, 0, (altivec *)b[40]);
	vec_st(zero, 0, (altivec *)b[41]);
	vec_st(zero, 0, (altivec *)b[42]);
	vec_st(zero, 0, (altivec *)b[43]);
	vec_st(zero, 0, (altivec *)b[44]);
	vec_st(ones, 0, (altivec *)b[45]);
	vec_st(zero, 0, (altivec *)b[46]);
	vec_st(zero, 0, (altivec *)b[47]);
	vec_st(ones, 0, (altivec *)b[48]);
	vec_st(ones, 0, (altivec *)b[49]);
	vec_st(zero, 0, (altivec *)b[50]);
	vec_st(zero, 0, (altivec *)b[51]);
	vec_st(zero, 0, (altivec *)b[52]);
	vec_st(zero, 0, (altivec *)b[53]);
	vec_st(ones, 0, (altivec *)b[54]);
	vec_st(zero, 0, (altivec *)b[55]);
	vec_st(ones, 0, (altivec *)b[56]);
	vec_st(zero, 0, (altivec *)b[57]);
	vec_st(ones, 0, (altivec *)b[58]);
	vec_st(zero, 0, (altivec *)b[59]);
	vec_st(ones, 0, (altivec *)b[60]);
	vec_st(ones, 0, (altivec *)b[61]);
	vec_st(ones, 0, (altivec *)b[62]);
	vec_st(ones, 0, (altivec *)b[63]);

	k = DES_bs_all.KS.p;
	rounds = 8;

	do {
		s1(x(b[31], k[0]), x(b[0], k[1]),
			x(b[1], k[2]), x(b[2], k[3]),
			x(b[3], k[4]), x(b[4], k[5]),
			(altivec *)&b[40], (altivec *)&b[48],
			(altivec *)&b[54], (altivec *)&b[62]);
		s2(x(b[3], k[6]), x(b[4], k[7]),
			x(b[5], k[8]), x(b[6], k[9]),
			x(b[7], k[10]), x(b[8], k[11]),
			(altivec *)&b[44], (altivec *)&b[59],
			(altivec *)&b[33], (altivec *)&b[49]);
		s3(x(b[7], k[12]), x(b[8], k[13]),
			x(b[9], k[14]), x(b[10], k[15]),
			x(b[11], k[16]), x(b[12], k[17]),
			(altivec *)&b[55], (altivec *)&b[47],
			(altivec *)&b[61], (altivec *)&b[37]);
		s4(x(b[11], k[18]), x(b[12], k[19]),
			x(b[13], k[20]), x(b[14], k[21]),
			x(b[15], k[22]), x(b[16], k[23]),
			(altivec *)&b[57], (altivec *)&b[51],
			(altivec *)&b[41], (altivec *)&b[32]);
		s5(x(b[15], k[24]), x(b[16], k[25]),
			x(b[17], k[26]), x(b[18], k[27]),
			x(b[19], k[28]), x(b[20], k[29]),
			(altivec *)&b[39], (altivec *)&b[45],
			(altivec *)&b[56], (altivec *)&b[34]);
		s6(x(b[19], k[30]), x(b[20], k[31]),
			x(b[21], k[32]), x(b[22], k[33]),
			x(b[23], k[34]), x(b[24], k[35]),
			(altivec *)&b[35], (altivec *)&b[60],
			(altivec *)&b[42], (altivec *)&b[50]);
		s7(x(b[23], k[36]), x(b[24], k[37]),
			x(b[25], k[38]), x(b[26], k[39]),
			x(b[27], k[40]), x(b[28], k[41]),
			(altivec *)&b[63], (altivec *)&b[43],
			(altivec *)&b[53], (altivec *)&b[38]);
		s8(x(b[27], k[42]), x(b[28], k[43]),
			x(b[29], k[44]), x(b[30], k[45]),
			x(b[31], k[46]), x(b[0], k[47]),
			(altivec *)&b[36], (altivec *)&b[58],
			(altivec *)&b[46], (altivec *)&b[52]);

		s1(x(b[63], k[48]), x(b[32], k[49]),
			x(b[33], k[50]), x(b[34], k[51]),
			x(b[35], k[52]), x(b[36], k[53]),
			(altivec *)&b[8], (altivec *)&b[16],
			(altivec *)&b[22], (altivec *)&b[30]);
		s2(x(b[35], k[54]), x(b[36], k[55]),
			x(b[37], k[56]), x(b[38], k[57]),
			x(b[39], k[58]), x(b[40], k[59]),
			(altivec *)&b[12], (altivec *)&b[27],
			(altivec *)&b[1], (altivec *)&b[17]);
		s3(x(b[39], k[60]), x(b[40], k[61]),
			x(b[41], k[62]), x(b[42], k[63]),
			x(b[43], k[64]), x(b[44], k[65]),
			(altivec *)&b[23], (altivec *)&b[15],
			(altivec *)&b[29], (altivec *)&b[5]);
		s4(x(b[43], k[66]), x(b[44], k[67]),
			x(b[45], k[68]), x(b[46], k[69]),
			x(b[47], k[70]), x(b[48], k[71]),
			(altivec *)&b[25], (altivec *)&b[19],
			(altivec *)&b[9], (altivec *)&b[0]);
		s5(x(b[47], k[72]), x(b[48], k[73]),
			x(b[49], k[74]), x(b[50], k[75]),
			x(b[51], k[76]), x(b[52], k[77]),
			(altivec *)&b[7], (altivec *)&b[13],
			(altivec *)&b[24], (altivec *)&b[2]);
		s6(x(b[51], k[78]), x(b[52], k[79]),
			x(b[53], k[80]), x(b[54], k[81]),
			x(b[55], k[82]), x(b[56], k[83]),
			(altivec *)&b[3], (altivec *)&b[28],
			(altivec *)&b[10], (altivec *)&b[18]);
		s7(x(b[55], k[84]), x(b[56], k[85]),
			x(b[57], k[86]), x(b[58], k[87]),
			x(b[59], k[88]), x(b[60], k[89]),
			(altivec *)&b[31], (altivec *)&b[11],
			(altivec *)&b[21], (altivec *)&b[6]);
		s8(x(b[59], k[90]), x(b[60], k[91]),
			x(b[61], k[92]), x(b[62], k[93]),
			x(b[63], k[94]), x(b[32], k[95]),
			(altivec *)&b[4], (altivec *)&b[26],
			(altivec *)&b[14], (altivec *)&b[20]);

		k += 96;
	} while (--rounds);
}
