/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2003,2010 by Solar Designer
 */

#include "arch.h"

#if !DES_BS_ASM
#include "DES_bs.h"

#define zero				0
#define ones				~(ARCH_WORD)0

#define vst(dst, src) \
	(dst) = (src)

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
		vst(b[i] bd, zero); \
		vst(b[i + 1] bd, zero); \
		vst(b[i + 2] bd, zero); \
		vst(b[i + 3] bd, zero); \
		vst(b[i + 4] bd, zero); \
		vst(b[i + 5] bd, zero); \
		vst(b[i + 6] bd, zero); \
		vst(b[i + 7] bd, zero); \
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

#define DES_bs_set_block_8(i, v0, v1, v2, v3, v4, v5, v6, v7) \
	for_each_depth() { \
		vst(b[i] bd, v0); \
		vst(b[i + 1] bd, v1); \
		vst(b[i + 2] bd, v2); \
		vst(b[i + 3] bd, v3); \
		vst(b[i + 4] bd, v4); \
		vst(b[i + 5] bd, v5); \
		vst(b[i + 6] bd, v6); \
		vst(b[i + 7] bd, v7); \
	}

#define x(p) (e[p] ed ^ k[p] kd)
#define y(p, q) (b[p] bd ^ k[q] kd)
#define z(r) (&b[r] bd)

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
	s1(x(0), x(1), x(2), x(3), x(4), x(5),
		z(40), z(48), z(54), z(62));
	for_each_depth()
	s2(x(6), x(7), x(8), x(9), x(10), x(11),
		z(44), z(59), z(33), z(49));
	for_each_depth()
	s3(x(12), x(13), x(14), x(15), x(16), x(17),
		z(55), z(47), z(61), z(37));
	for_each_depth()
	s4(x(18), x(19), x(20), x(21), x(22), x(23),
		z(57), z(51), z(41), z(32));
	for_each_depth()
	s5(x(24), x(25), x(26), x(27), x(28), x(29),
		z(39), z(45), z(56), z(34));
	for_each_depth()
	s6(x(30), x(31), x(32), x(33), x(34), x(35),
		z(35), z(60), z(42), z(50));
	for_each_depth()
	s7(x(36), x(37), x(38), x(39), x(40), x(41),
		z(63), z(43), z(53), z(38));
	for_each_depth()
	s8(x(42), x(43), x(44), x(45), x(46), x(47),
		z(36), z(58), z(46), z(52));

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(x(48), x(49), x(50), x(51), x(52), x(53),
		z(8), z(16), z(22), z(30));
	for_each_depth()
	s2(x(54), x(55), x(56), x(57), x(58), x(59),
		z(12), z(27), z(1), z(17));
	for_each_depth()
	s3(x(60), x(61), x(62), x(63), x(64), x(65),
		z(23), z(15), z(29), z(5));
	for_each_depth()
	s4(x(66), x(67), x(68), x(69), x(70), x(71),
		z(25), z(19), z(9), z(0));
	for_each_depth()
	s5(x(72), x(73), x(74), x(75), x(76), x(77),
		z(7), z(13), z(24), z(2));
	for_each_depth()
	s6(x(78), x(79), x(80), x(81), x(82), x(83),
		z(3), z(28), z(10), z(18));
	for_each_depth()
	s7(x(84), x(85), x(86), x(87), x(88), x(89),
		z(31), z(11), z(21), z(6));
	for_each_depth()
	s8(x(90), x(91), x(92), x(93), x(94), x(95),
		z(4), z(26), z(14), z(20));

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
	s1(x(0), x(1), x(2), x(3), x(4), x(5),
		z(40), z(48), z(54), z(62));
	for_each_depth()
	s2(x(6), x(7), x(8), x(9), x(10), x(11),
		z(44), z(59), z(33), z(49));
	for_each_depth()
	s3(y(7, 12), y(8, 13), y(9, 14),
		y(10, 15), y(11, 16), y(12, 17),
		z(55), z(47), z(61), z(37));
	for_each_depth()
	s4(y(11, 18), y(12, 19), y(13, 20),
		y(14, 21), y(15, 22), y(16, 23),
		z(57), z(51), z(41), z(32));
	for_each_depth()
	s5(x(24), x(25), x(26), x(27), x(28), x(29),
		z(39), z(45), z(56), z(34));
	for_each_depth()
	s6(x(30), x(31), x(32), x(33), x(34), x(35),
		z(35), z(60), z(42), z(50));
	for_each_depth()
	s7(y(23, 36), y(24, 37), y(25, 38),
		y(26, 39), y(27, 40), y(28, 41),
		z(63), z(43), z(53), z(38));
	for_each_depth()
	s8(y(27, 42), y(28, 43), y(29, 44),
		y(30, 45), y(31, 46), y(0, 47),
		z(36), z(58), z(46), z(52));

	if (rounds_and_swapped == 0x100) goto next;

swap:
	for_each_depth()
	s1(x(48), x(49), x(50), x(51), x(52), x(53),
		z(8), z(16), z(22), z(30));
	for_each_depth()
	s2(x(54), x(55), x(56), x(57), x(58), x(59),
		z(12), z(27), z(1), z(17));
	for_each_depth()
	s3(y(39, 60), y(40, 61), y(41, 62),
		y(42, 63), y(43, 64), y(44, 65),
		z(23), z(15), z(29), z(5));
	for_each_depth()
	s4(y(43, 66), y(44, 67), y(45, 68),
		y(46, 69), y(47, 70), y(48, 71),
		z(25), z(19), z(9), z(0));
	for_each_depth()
	s5(x(72), x(73), x(74), x(75), x(76), x(77),
		z(7), z(13), z(24), z(2));
	for_each_depth()
	s6(x(78), x(79), x(80), x(81), x(82), x(83),
		z(3), z(28), z(10), z(18));
	for_each_depth()
	s7(y(55, 84), y(56, 85), y(57, 86),
		y(58, 87), y(59, 88), y(60, 89),
		z(31), z(11), z(21), z(6));
	for_each_depth()
	s8(y(59, 90), y(60, 91), y(61, 92),
		y(62, 93), y(63, 94), y(32, 95),
		z(4), z(26), z(14), z(20));

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

#undef x

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

	DES_bs_set_block_8(0, zero, zero, zero, zero, zero, zero, zero, zero);
	DES_bs_set_block_8(8, ones, ones, ones, zero, ones, zero, zero, zero);
	DES_bs_set_block_8(16, zero, zero, zero, zero, zero, zero, zero, ones);
	DES_bs_set_block_8(24, zero, zero, ones, zero, zero, ones, ones, ones);
	DES_bs_set_block_8(32, zero, zero, zero, ones, zero, ones, ones, ones);
	DES_bs_set_block_8(40, zero, zero, zero, zero, zero, ones, zero, zero);
	DES_bs_set_block_8(48, ones, ones, zero, zero, zero, zero, ones, zero);
	DES_bs_set_block_8(56, ones, zero, ones, zero, ones, ones, ones, ones);

	k = DES_bs_all.KS.p;
	rounds = 8;

	do {
		for_each_depth()
		s1(y(31, 0), y(0, 1), y(1, 2),
			y(2, 3), y(3, 4), y(4, 5),
			z(40), z(48), z(54), z(62));
		for_each_depth()
		s2(y(3, 6), y(4, 7), y(5, 8),
			y(6, 9), y(7, 10), y(8, 11),
			z(44), z(59), z(33), z(49));
		for_each_depth()
		s3(y(7, 12), y(8, 13), y(9, 14),
			y(10, 15), y(11, 16), y(12, 17),
			z(55), z(47), z(61), z(37));
		for_each_depth()
		s4(y(11, 18), y(12, 19), y(13, 20),
			y(14, 21), y(15, 22), y(16, 23),
			z(57), z(51), z(41), z(32));
		for_each_depth()
		s5(y(15, 24), y(16, 25), y(17, 26),
			y(18, 27), y(19, 28), y(20, 29),
			z(39), z(45), z(56), z(34));
		for_each_depth()
		s6(y(19, 30), y(20, 31), y(21, 32),
			y(22, 33), y(23, 34), y(24, 35),
			z(35), z(60), z(42), z(50));
		for_each_depth()
		s7(y(23, 36), y(24, 37), y(25, 38),
			y(26, 39), y(27, 40), y(28, 41),
			z(63), z(43), z(53), z(38));
		for_each_depth()
		s8(y(27, 42), y(28, 43), y(29, 44),
			y(30, 45), y(31, 46), y(0, 47),
			z(36), z(58), z(46), z(52));

		for_each_depth()
		s1(y(63, 48), y(32, 49), y(33, 50),
			y(34, 51), y(35, 52), y(36, 53),
			z(8), z(16), z(22), z(30));
		for_each_depth()
		s2(y(35, 54), y(36, 55), y(37, 56),
			y(38, 57), y(39, 58), y(40, 59),
			z(12), z(27), z(1), z(17));
		for_each_depth()
		s3(y(39, 60), y(40, 61), y(41, 62),
			y(42, 63), y(43, 64), y(44, 65),
			z(23), z(15), z(29), z(5));
		for_each_depth()
		s4(y(43, 66), y(44, 67), y(45, 68),
			y(46, 69), y(47, 70), y(48, 71),
			z(25), z(19), z(9), z(0));
		for_each_depth()
		s5(y(47, 72), y(48, 73), y(49, 74),
			y(50, 75), y(51, 76), y(52, 77),
			z(7), z(13), z(24), z(2));
		for_each_depth()
		s6(y(51, 78), y(52, 79), y(53, 80),
			y(54, 81), y(55, 82), y(56, 83),
			z(3), z(28), z(10), z(18));
		for_each_depth()
		s7(y(55, 84), y(56, 85), y(57, 86),
			y(58, 87), y(59, 88), y(60, 89),
			z(31), z(11), z(21), z(6));
		for_each_depth()
		s8(y(59, 90), y(60, 91), y(61, 92),
			y(62, 93), y(63, 94), y(32, 95),
			z(4), z(26), z(14), z(20));

		k += 96;
	} while (--rounds);
}
#endif
