/*
 * This software is Copyright (c) 2015 Sayantan Datta <std2048 at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 * Based on Solar Designer implementation of DES_bs_b.c in jtr-v1.7.9
 */

#include "opencl_lm_finalize_keys.h"
#include "opencl_mask.h"

#if WORK_GROUP_SIZE
#define y(p, q) vxorf(B[p], lm_keys[q + s_key_offset])
#else
#define y(p, q) vxorf(B[p], lm_keys[q * gws + section])
#endif

#define H1_k0()\
	s1(y(31, 15), y(0, 43), y(1, 26),\
	y(2, 51), y(3, 45), y(4, 9),\
	B, 40, 48, 54, 62);\
	s2(y(3, 27), y(4, 54), y(5, 6),\
	y(6, 0), y(7, 23), y(8, 35),\
	B, 44, 59, 33, 49);\
	s3(y(7, 5), y(8, 25), y(9, 17),\
	y(10, 18), y(11, 33), y(12, 53),\
	B, 55, 47, 61, 37);\
	s4(y(11, 52), y(12, 7), y(13, 24),\
	y(14, 16), y(15, 8), y(16, 36),\
	B, 57, 51, 41, 32);\
	s5(y(15, 20), y(16, 31), y(17, 37),\
	y(18, 40), y(19, 39), y(20, 4),\
	B, 39, 45, 56, 34);\
	s6(y(19, 46), y(20, 29), y(21, 3),\
	y(22, 41), y(23, 19), y(24, 30),\
	B, 35, 60, 42, 50);\
	s7(y(23, 50), y(24, 21), y(25, 38),\
	y(26, 48), y(27, 10), y(28, 22),\
	B, 63, 43, 53, 38);\
	s8(y(27, 32), y(28, 11), y(29, 12),\
	y(30, 49), y(31, 55), y(0, 28),\
	B, 36, 58, 46, 52);

#define H2_k0()\
	s1(y(63, 6), y(32, 34), y(33, 17),\
	y(34, 42), y(35, 36), y(36, 0),\
	B, 8, 16, 22, 30);\
	s2(y(35, 18), y(36, 45), y(37, 52),\
	y(38, 7), y(39, 14), y(40, 26),\
	B, 12, 27, 1, 17);\
	s3(y(39, 51), y(40, 16), y(41, 8),\
	y(42, 9), y(43, 24), y(44, 44),\
	B, 23, 15, 29, 5);\
	s4(y(43, 43), y(44, 53), y(45, 54),\
	y(46, 23), y(47, 15), y(48, 27),\
	B, 25, 19, 9, 0);\
	s5(y(47, 11), y(48, 22), y(49, 28),\
	y(50, 47), y(51, 30), y(52, 48),\
	B, 7, 13, 24, 2);\
	s6(y(51, 37), y(52, 20), y(53, 31),\
	y(54, 32), y(55, 10), y(56, 21),\
	B, 3, 28, 10, 18);\
	s7(y(55, 41), y(56, 12), y(57, 29),\
	y(58, 55), y(59, 1), y(60, 13),\
	B, 31, 11, 21, 6);\
	s8(y(59, 39), y(60, 2), y(61, 3),\
	y(62, 40), y(63, 46), y(32, 19),\
	B, 4, 26, 14, 20);

#define H1_k1()\
	s1(y(31, 43), y(0, 16), y(1, 15),\
	y(2, 24), y(3, 18), y(4, 53),\
	B, 40, 48, 54, 62);\
	s2(y(3, 0), y(4, 27), y(5, 34),\
	y(6, 44), y(7, 51), y(8, 8),\
	B, 44, 59, 33, 49);\
	s3(y(7, 33), y(8, 14), y(9, 6),\
	y(10, 7), y(11, 45), y(12, 26),\
	B, 55, 47, 61, 37);\
	s4(y(11, 25), y(12, 35), y(13, 36),\
	y(14, 5), y(15, 52), y(16, 9),\
	B, 57, 51, 41, 32);\
	s5(y(15, 50), y(16, 4), y(17, 10),\
	y(18, 29), y(19, 12), y(20, 46),\
	B, 39, 45, 56, 34);\
	s6(y(19, 19), y(20, 2), y(21, 13),\
	y(22, 30), y(23, 49), y(24, 3),\
	B, 35, 60, 42, 50);\
	s7(y(23, 39), y(24, 31), y(25, 11),\
	y(26, 37), y(27, 40), y(28, 48),\
	B, 63, 43, 53, 38);\
	s8(y(27, 21), y(28, 41), y(29, 22),\
	y(30, 38), y(31, 28), y(0, 1),\
	B, 36, 58, 46, 52);

#define H2_k1()\
	s1(y(63, 25), y(32, 14), y(33, 52),\
	y(34, 45), y(35, 0), y(36, 35),\
	B, 8, 16, 22, 30);\
	s2(y(35, 53), y(36, 9), y(37, 16),\
	y(38, 26), y(39, 33), y(40, 6),\
	B, 12, 27, 1, 17);\
	s3(y(39, 54), y(40, 51), y(41, 43),\
	y(42, 44), y(43, 27), y(44, 8),\
	B, 23, 15, 29, 5);\
	s4(y(43, 23), y(44, 17), y(45, 18),\
	y(46, 42), y(47, 34), y(48, 7),\
	B, 25, 19, 9, 0);\
	s5(y(47, 32), y(48, 55), y(49, 49),\
	y(50, 11), y(51, 31), y(52, 28),\
	B, 7, 13, 24, 2);\
	s6(y(51, 1), y(52, 41), y(53, 48),\
	y(54, 12), y(55, 47), y(56, 22),\
	B, 3, 28, 10, 18);\
	s7(y(55, 21), y(56, 13), y(57, 50),\
	y(58, 19), y(59, 38), y(60, 46),\
	B, 31, 11, 21, 6);\
	s8(y(59, 3), y(60, 39), y(61, 4),\
	y(62, 20), y(63, 10), y(32, 40),\
	B, 4, 26, 14, 20);

#define H1_k2()\
	s1(y(31, 23), y(0, 51), y(1, 34),\
	y(2, 27), y(3, 53), y(4, 17),\
	B, 40, 48, 54, 62);\
	s2(y(3, 35), y(4, 7), y(5, 14),\
	y(6, 8), y(7, 54), y(8, 43),\
	B, 44, 59, 33, 49);\
	s3(y(7, 36), y(8, 33), y(9, 25),\
	y(10, 26), y(11, 9), y(12, 6),\
	B, 55, 47, 61, 37);\
	s4(y(11, 5), y(12, 15), y(13, 0),\
	y(14, 24), y(15, 16), y(16, 44),\
	B, 57, 51, 41, 32);\
	s5(y(15, 30), y(16, 37), y(17, 47),\
	y(18, 50), y(19, 13), y(20, 10),\
	B, 39, 45, 56, 34);\
	s6(y(19, 40), y(20, 39), y(21, 46),\
	y(22, 31), y(23, 29), y(24, 4),\
	B, 35, 60, 42, 50);\
	s7(y(23, 3), y(24, 48), y(25, 32),\
	y(26, 1), y(27, 20), y(28, 28),\
	B, 63, 43, 53, 38);\
	s8(y(27, 22), y(28, 21), y(29, 55),\
	y(30, 2), y(31, 49), y(0, 38),\
	B, 36, 58, 46, 52);

#define H2_k2()\
	s1(y(63, 5), y(32, 33), y(33, 16),\
	y(34, 9), y(35, 35), y(36, 15),\
	B, 8, 16, 22, 30);\
	s2(y(35, 17), y(36, 44), y(37, 51),\
	y(38, 6), y(39, 36), y(40, 25),\
	B, 12, 27, 1, 17);\
	s3(y(39, 18), y(40, 54), y(41, 23),\
	y(42, 8), y(43, 7), y(44, 43),\
	B, 23, 15, 29, 5);\
	s4(y(43, 42), y(44, 52), y(45, 53),\
	y(46, 45), y(47, 14), y(48, 26),\
	B, 25, 19, 9, 0);\
	s5(y(47, 12), y(48, 19), y(49, 29),\
	y(50, 32), y(51, 48), y(52, 49),\
	B, 7, 13, 24, 2);\
	s6(y(51, 38), y(52, 21), y(53, 28),\
	y(54, 13), y(55, 11), y(56, 55),\
	B, 3, 28, 10, 18);\
	s7(y(55, 22), y(56, 46), y(57, 30),\
	y(58, 40), y(59, 2), y(60, 10),\
	B, 31, 11, 21, 6);\
	s8(y(59, 4), y(60, 3), y(61, 37),\
	y(62, 41), y(63, 47), y(32, 20),\
	B, 4, 26, 14, 20);

#define H1_k3()\
	s1(y(31, 42), y(0, 54), y(1, 14),\
	y(2, 7), y(3, 17), y(4, 52),\
	B, 40, 48, 54, 62);\
	s2(y(3, 15), y(4, 26), y(5, 33),\
	y(6, 43), y(7, 18), y(8, 23),\
	B, 44, 59, 33, 49);\
	s3(y(7, 0), y(8, 36), y(9, 5),\
	y(10, 6), y(11, 44), y(12, 25),\
	B, 55, 47, 61, 37);\
	s4(y(11, 24), y(12, 34), y(13, 35),\
	y(14, 27), y(15, 51), y(16, 8),\
	B, 57, 51, 41, 32);\
	s5(y(15, 31), y(16, 1), y(17, 11),\
	y(18, 30), y(19, 46), y(20, 47),\
	B, 39, 45, 56, 34);\
	s6(y(19, 20), y(20, 3), y(21, 10),\
	y(22, 48), y(23, 50), y(24, 37),\
	B, 35, 60, 42, 50);\
	s7(y(23, 4), y(24, 28), y(25, 12),\
	y(26, 38), y(27, 41), y(28, 49),\
	B, 63, 43, 53, 38);\
	s8(y(27, 55), y(28, 22), y(29, 19),\
	y(30, 39), y(31, 29), y(0, 2),\
	B, 36, 58, 46, 52);

#define H2_k3()\
	s1(y(63, 24), y(32, 36), y(33, 51),\
	y(34, 44), y(35, 15), y(36, 34),\
	B, 8, 16, 22, 30);\
	s2(y(35, 52), y(36, 8), y(37, 54),\
	y(38, 25), y(39, 0), y(40, 5),\
	B, 12, 27, 1, 17);\
	s3(y(39, 53), y(40, 18), y(41, 42),\
	y(42, 43), y(43, 26), y(44, 23),\
	B, 23, 15, 29, 5);\
	s4(y(43, 45), y(44, 16), y(45, 17),\
	y(46, 9), y(47, 33), y(48, 6),\
	B, 25, 19, 9, 0);\
	s5(y(47, 13), y(48, 40), y(49, 50),\
	y(50, 12), y(51, 28), y(52, 29),\
	B, 7, 13, 24, 2);\
	s6(y(51, 2), y(52, 22), y(53, 49),\
	y(54, 46), y(55, 32), y(56, 19),\
	B, 3, 28, 10, 18);\
	s7(y(55, 55), y(56, 10), y(57, 31),\
	y(58, 20), y(59, 39), y(60, 47),\
	B, 31, 11, 21, 6);\
	s8(y(59, 37), y(60, 4), y(61, 1),\
	y(62, 21), y(63, 11), y(32, 41),\
	B, 4, 26, 14, 20);

#define H1_k4()\
	s1(y(31, 54), y(0, 27), y(1, 42),\
	y(2, 35), y(3, 6), y(4, 25),\
	B, 40, 48, 54, 62);\
	s2(y(3, 43), y(4, 15), y(5, 45),\
	y(6, 16), y(7, 7), y(8, 51),\
	B, 44, 59, 33, 49);\
	s3(y(7, 44), y(8, 9), y(9, 33),\
	y(10, 34), y(11, 17), y(12, 14),\
	B, 55, 47, 61, 37);\
	s4(y(11, 36), y(12, 23), y(13, 8),\
	y(14, 0), y(15, 24), y(16, 52),\
	B, 57, 51, 41, 32);\
	s5(y(15, 4), y(16, 47), y(17, 41),\
	y(18, 3), y(19, 19), y(20, 20),\
	B, 39, 45, 56, 34);\
	s6(y(19, 50), y(20, 13), y(21, 40),\
	y(22, 37), y(23, 39), y(24, 10),\
	B, 35, 60, 42, 50);\
	s7(y(23, 46), y(24, 1), y(25, 22),\
	y(26, 11), y(27, 30), y(28, 38),\
	B, 63, 43, 53, 38);\
	s8(y(27, 28), y(28, 48), y(29, 49),\
	y(30, 12), y(31, 2), y(0, 32),\
	B, 36, 58, 46, 52);

#define H2_k4()\
	s1(y(63, 36), y(32, 9), y(33, 24),\
	y(34, 17), y(35, 43), y(36, 23),\
	B, 8, 16, 22, 30);\
	s2(y(35, 25), y(36, 52), y(37, 27),\
	y(38, 14), y(39, 44), y(40, 33),\
	B, 12, 27, 1, 17);\
	s3(y(39, 26), y(40, 7), y(41, 54),\
	y(42, 16), y(43, 15), y(44, 51),\
	B, 23, 15, 29, 5);\
	s4(y(43, 18), y(44, 5), y(45, 6),\
	y(46, 53), y(47, 45), y(48, 34),\
	B, 25, 19, 9, 0);\
	s5(y(47, 55), y(48, 29), y(49, 39),\
	y(50, 22), y(51, 1), y(52, 2),\
	B, 7, 13, 24, 2);\
	s6(y(51, 32), y(52, 48), y(53, 38),\
	y(54, 19), y(55, 21), y(56, 49),\
	B, 3, 28, 10, 18);\
	s7(y(55, 28), y(56, 40), y(57, 4),\
	y(58, 50), y(59, 12), y(60, 20),\
	B, 31, 11, 21, 6);\
	s8(y(59, 10), y(60, 46), y(61, 47),\
	y(62, 31), y(63, 41), y(32, 30),\
	B, 4, 26, 14, 20);

#define H1_k5()\
	s1(y(31, 18), y(0, 7), y(1, 45),\
	y(2, 15), y(3, 25), y(4, 5),\
	B, 40, 48, 54, 62);\
	s2(y(3, 23), y(4, 34), y(5, 9),\
	y(6, 51), y(7, 26), y(8, 54),\
	B, 44, 59, 33, 49);\
	s3(y(7, 8), y(8, 44), y(9, 36),\
	y(10, 14), y(11, 52), y(12, 33),\
	B, 55, 47, 61, 37);\
	s4(y(11, 0), y(12, 42), y(13, 43),\
	y(14, 35), y(15, 27), y(16, 16),\
	B, 57, 51, 41, 32);\
	s5(y(15, 37), y(16, 11), y(17, 21),\
	y(18, 4), y(19, 40), y(20, 41),\
	B, 39, 45, 56, 34);\
	s6(y(19, 30), y(20, 46), y(21, 20),\
	y(22, 1), y(23, 3), y(24, 47),\
	B, 35, 60, 42, 50);\
	s7(y(23, 10), y(24, 38), y(25, 55),\
	y(26, 32), y(27, 31), y(28, 2),\
	B, 63, 43, 53, 38);\
	s8(y(27, 49), y(28, 28), y(29, 29),\
	y(30, 13), y(31, 39), y(0, 12),\
	B, 36, 58, 46, 52);

#define H2_k5()\
	s1(y(63, 0), y(32, 44), y(33, 27),\
	y(34, 52), y(35, 23), y(36, 42),\
	B, 8, 16, 22, 30);\
	s2(y(35, 5), y(36, 16), y(37, 7),\
	y(38, 33), y(39, 8), y(40, 36),\
	B, 12, 27, 1, 17);\
	s3(y(39, 6), y(40, 26), y(41, 18),\
	y(42, 51), y(43, 34), y(44, 54),\
	B, 23, 15, 29, 5);\
	s4(y(43, 53), y(44, 24), y(45, 25),\
	y(46, 17), y(47, 9), y(48, 14),\
	B, 25, 19, 9, 0);\
	s5(y(47, 19), y(48, 50), y(49, 3),\
	y(50, 55), y(51, 38), y(52, 39),\
	B, 7, 13, 24, 2);\
	s6(y(51, 12), y(52, 28), y(53, 2),\
	y(54, 40), y(55, 22), y(56, 29),\
	B, 3, 28, 10, 18);\
	s7(y(55, 49), y(56, 20), y(57, 37),\
	y(58, 30), y(59, 13), y(60, 41),\
	B, 31, 11, 21, 6);\
	s8(y(59, 47), y(60, 10), y(61, 11),\
	y(62, 48), y(63, 21), y(32, 31),\
	B, 4, 26, 14, 20);

#define H1_k6()\
	s1(y(31, 53), y(0, 26), y(1, 9),\
	y(2, 34), y(3, 5), y(4, 24),\
	B, 40, 48, 54, 62);\
	s2(y(3, 42), y(4, 14), y(5, 44),\
	y(6, 54), y(7, 6), y(8, 18),\
	B, 44, 59, 33, 49);\
	s3(y(7, 43), y(8, 8), y(9, 0),\
	y(10, 33), y(11, 16), y(12, 36),\
	B, 55, 47, 61, 37);\
	s4(y(11, 35), y(12, 45), y(13, 23),\
	y(14, 15), y(15, 7), y(16, 51),\
	B, 57, 51, 41, 32);\
	s5(y(15, 1), y(16, 32), y(17, 22),\
	y(18, 37), y(19, 20), y(20, 21),\
	B, 39, 45, 56, 34);\
	s6(y(19, 31), y(20, 10), y(21, 41),\
	y(22, 38), y(23, 4), y(24, 11),\
	B, 35, 60, 42, 50);\
	s7(y(23, 47), y(24, 2), y(25, 19),\
	y(26, 12), y(27, 48), y(28, 39),\
	B, 63, 43, 53, 38);\
	s8(y(27, 29), y(28, 49), y(29, 50),\
	y(30, 46), y(31, 3), y(0, 13),\
	B, 36, 58, 46, 52);

#define H2_k6()\
	s1(y(63, 35), y(32, 8), y(33, 7),\
	y(34, 16), y(35, 42), y(36, 45),\
	B, 8, 16, 22, 30);\
	s2(y(35, 24), y(36, 51), y(37, 26),\
	y(38, 36), y(39, 43), y(40, 0),\
	B, 12, 27, 1, 17);\
	s3(y(39, 25), y(40, 6), y(41, 53),\
	y(42, 54), y(43, 14), y(44, 18),\
	B, 23, 15, 29, 5);\
	s4(y(43, 17), y(44, 27), y(45, 5),\
	y(46, 52), y(47, 44), y(48, 33),\
	B, 25, 19, 9, 0);\
	s5(y(47, 40), y(48, 30), y(49, 4),\
	y(50, 19), y(51, 2), y(52, 3),\
	B, 7, 13, 24, 2);\
	s6(y(51, 13), y(52, 49), y(53, 39),\
	y(54, 20), y(55, 55), y(56, 50),\
	B, 3, 28, 10, 18);\
	s7(y(55, 29), y(56, 41), y(57, 1),\
	y(58, 31), y(59, 46), y(60, 21),\
	B, 31, 11, 21, 6);\
	s8(y(59, 11), y(60, 47), y(61, 32),\
	y(62, 28), y(63, 22), y(32, 48),\
	B, 4, 26, 14, 20);

#define H1_k7()\
	s1(y(31, 17), y(0, 6), y(1, 44),\
	y(2, 14), y(3, 24), y(4, 27),\
	B, 40, 48, 54, 62);\
	s2(y(3, 45), y(4, 33), y(5, 8),\
	y(6, 18), y(7, 25), y(8, 53),\
	B, 44, 59, 33, 49);\
	s3(y(7, 23), y(8, 43), y(9, 35),\
	y(10, 36), y(11, 51), y(12, 0),\
	B, 55, 47, 61, 37);\
	s4(y(11, 15), y(12, 9), y(13, 42),\
	y(14, 34), y(15, 26), y(16, 54),\
	B, 57, 51, 41, 32);\
	s5(y(15, 38), y(16, 12), y(17, 55),\
	y(18, 1), y(19, 41), y(20, 22),\
	B, 39, 45, 56, 34);\
	s6(y(19, 48), y(20, 47), y(21, 21),\
	y(22, 2), y(23, 37), y(24, 32),\
	B, 35, 60, 42, 50);\
	s7(y(23, 11), y(24, 39), y(25, 40),\
	y(26, 13), y(27, 28), y(28, 3),\
	B, 63, 43, 53, 38);\
	s8(y(27, 50), y(28, 29), y(29, 30),\
	y(30, 10), y(31, 4), y(0, 46),\
	B, 36, 58, 46, 52);

#define H2_k7()\
	s1(y(63, 8), y(32, 52), y(33, 35),\
	y(34, 5), y(35, 54), y(36, 18),\
	B, 8, 16, 22, 30);\
	s2(y(35, 36), y(36, 24), y(37, 15),\
	y(38, 9), y(39, 16), y(40, 44),\
	B, 12, 27, 1, 17);\
	s3(y(39, 14), y(40, 34), y(41, 26),\
	y(42, 27), y(43, 42), y(44, 7),\
	B, 23, 15, 29, 5);\
	s4(y(43, 6), y(44, 0), y(45,33),\
	y(46, 25), y(47, 17), y(48, 45),\
	B, 25, 19, 9, 0);\
	s5(y(47, 29), y(48, 3), y(49, 46),\
	y(50, 49), y(51, 32), y(52, 13),\
	B, 7, 13, 24, 2);\
	s6(y(51, 55), y(52, 38), y(53, 12),\
	y(54, 50), y(55, 28), y(56, 39),\
	B, 3, 28, 10, 18);\
	s7(y(55, 2), y(56, 30), y(57, 47),\
	y(58, 4), y(59, 19), y(60, 31),\
	B, 31, 11, 21, 6);\
	s8(y(59, 41), y(60, 20), y(61, 21),\
	y(62, 1), y(63, 48), y(32, 37),\
	B, 4, 26, 14, 20);

#define lm_set_block_8(b, i, v0, v1, v2, v3, v4, v5, v6, v7) \
	{ \
		b[i] = v0; \
		b[i + 1] = v1; \
		b[i + 2] = v2; \
		b[i + 3] = v3; \
		b[i + 4] = v4; \
		b[i + 5] = v5; \
		b[i + 6] = v6; \
		b[i + 7] = v7; \
	}

#define vzero 0
#define vones (~(vtype)0)

inline void lm_loop(vtype *B,
#if WORK_GROUP_SIZE
		__local lm_vector *lm_keys,
#else
		__global lm_vector *lm_keys,
#endif
#if WORK_GROUP_SIZE
		unsigned int s_key_offset
#else
		unsigned int gws,
		unsigned int section
#endif
		) {

	int iterations = 0;
#pragma unroll 1
	for (iterations = 0; iterations >= 0; iterations--) {
		H1_k0();
		H2_k0();
		H1_k1();
		H2_k1();
		H1_k2();
		H2_k2();
		H1_k3();
		H2_k3();
		H1_k4();
		H2_k4();
		H1_k5();
		H2_k5();
		H1_k6();
		H2_k6();
		H1_k7();
		H2_k7();
	}
}

#if LOC_3 >= 0
#define ACTIVE_PLACEHOLDER	4
#elif LOC_2 >= 0
#define ACTIVE_PLACEHOLDER	3
#elif LOC_1 >= 0
#define ACTIVE_PLACEHOLDER	2
#elif LOC_0 >= 0
#define ACTIVE_PLACEHOLDER	1
#else
#define ACTIVE_PLACEHOLDER	0
#endif

#if FULL_UNROLL == 1
#if (CONST_CACHE_SIZE >= ACTIVE_PLACEHOLDER * 32 * ITER_COUNT) && ACTIVE_PLACEHOLDER
#define USE_CONST_CACHED_INT_KEYS	1
#else
#define USE_CONST_CACHED_INT_KEYS	0
#endif

/*
 * Note: Change in kernel name or number of kernel arguments
 * must be updated on host side set_kernel_args(), set_kernel_args_gws().
 */
__kernel void lm_bs_f(__global opencl_lm_transfer *lm_raw_keys, // Do not change kernel argument index.
		    __global unsigned int *lm_key_loc, // Do not change kernel argument index.
#if (WORK_GROUP_SIZE == 0)
		    __global lm_vector *lm_keys, // Do not change kernel argument name or its index.
#endif
#if USE_CONST_CACHED_INT_KEYS
		    constant
#else
		    __global
#endif
		    unsigned int *lm_int_keys /* Memory allocated on host side must not exceed CONST_CACHE_SIZE if constant is used. */
#if !defined(__OS_X__) && USE_CONST_CACHED_INT_KEYS && gpu_amd(DEVICE_INFO)
		__attribute__((max_constant_size ((ACTIVE_PLACEHOLDER * 32 * ITER_COUNT))))
#endif
		    , __global unsigned int *offset_table,
		    __global unsigned int *hash_table,
		    __global unsigned int *bitmaps,
                    volatile __global uint *hash_ids,
		    volatile __global uint *bitmap_dupe)
{
		unsigned int i;
		unsigned int section = get_global_id(0);

#if !WORK_GROUP_SIZE
		unsigned int gws = get_global_size(0);
#endif
		vtype B[64];

#if WORK_GROUP_SIZE
		unsigned int lid = get_local_id(0);
		unsigned int s_key_offset  = 56 * lid;
		__local lm_vector s_lm_key[56 * WORK_GROUP_SIZE];
		lm_bs_finalize_keys(lm_raw_keys,
				section, s_lm_key, s_key_offset);
		barrier(CLK_LOCAL_MEM_FENCE);
#else
		lm_bs_finalize_keys(lm_raw_keys,
				section, lm_keys, gws);
#endif

#if MASK_ENABLE && !IS_STATIC_GPU_MASK
	uint ikl = lm_key_loc[section];
	uint loc0 = (ikl & 0xff) << 3;
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
	uint loc1 = (ikl & 0xff00) >> 5;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
	uint loc2 = (ikl & 0xff0000) >> 13;
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
	uint loc3 = (ikl & 0xff000000) >> 21;
#endif
#endif
#endif

#if !IS_STATIC_GPU_MASK
#define GPU_LOC_0 loc0
#define GPU_LOC_1 loc1
#define GPU_LOC_2 loc2
#define GPU_LOC_3 loc3
#else
#define GPU_LOC_0 (LOC_0 << 3)
#define GPU_LOC_1 (LOC_1 << 3)
#define GPU_LOC_2 (LOC_2 << 3)
#define GPU_LOC_3 (LOC_3 << 3)
#endif

	for (i = 0; i < ITER_COUNT; i++) {
#if MASK_ENABLE

#if WORK_GROUP_SIZE
		s_lm_key[s_key_offset + GPU_LOC_0] = lm_int_keys[i * 8];
		s_lm_key[s_key_offset + GPU_LOC_0 + 1] = lm_int_keys[i * 8 + 1];
		s_lm_key[s_key_offset + GPU_LOC_0 + 2] = lm_int_keys[i * 8 + 2];
		s_lm_key[s_key_offset + GPU_LOC_0 + 3] = lm_int_keys[i * 8 + 3];
		s_lm_key[s_key_offset + GPU_LOC_0 + 4] = lm_int_keys[i * 8 + 4];
		s_lm_key[s_key_offset + GPU_LOC_0 + 5] = lm_int_keys[i * 8 + 5];
		s_lm_key[s_key_offset + GPU_LOC_0 + 6] = lm_int_keys[i * 8 + 6];
		s_lm_key[s_key_offset + GPU_LOC_0 + 7] = lm_int_keys[i * 8 + 7];
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
#define OFFSET 	(1 * ITER_COUNT * 8)
		s_lm_key[s_key_offset + GPU_LOC_1] = lm_int_keys[OFFSET + i * 8];
		s_lm_key[s_key_offset + GPU_LOC_1 + 1] = lm_int_keys[OFFSET + i * 8 + 1];
		s_lm_key[s_key_offset + GPU_LOC_1 + 2] = lm_int_keys[OFFSET + i * 8 + 2];
		s_lm_key[s_key_offset + GPU_LOC_1 + 3] = lm_int_keys[OFFSET + i * 8 + 3];
		s_lm_key[s_key_offset + GPU_LOC_1 + 4] = lm_int_keys[OFFSET + i * 8 + 4];
		s_lm_key[s_key_offset + GPU_LOC_1 + 5] = lm_int_keys[OFFSET + i * 8 + 5];
		s_lm_key[s_key_offset + GPU_LOC_1 + 6] = lm_int_keys[OFFSET + i * 8 + 6];
		s_lm_key[s_key_offset + GPU_LOC_1 + 7] = lm_int_keys[OFFSET + i * 8 + 7];
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
#undef OFFSET
#define OFFSET 	(2 * ITER_COUNT * 8)
		s_lm_key[s_key_offset + GPU_LOC_2] = lm_int_keys[OFFSET + i * 8];
		s_lm_key[s_key_offset + GPU_LOC_2 + 1] = lm_int_keys[OFFSET + i * 8 + 1];
		s_lm_key[s_key_offset + GPU_LOC_2 + 2] = lm_int_keys[OFFSET + i * 8 + 2];
		s_lm_key[s_key_offset + GPU_LOC_2 + 3] = lm_int_keys[OFFSET + i * 8 + 3];
		s_lm_key[s_key_offset + GPU_LOC_2 + 4] = lm_int_keys[OFFSET + i * 8 + 4];
		s_lm_key[s_key_offset + GPU_LOC_2 + 5] = lm_int_keys[OFFSET + i * 8 + 5];
		s_lm_key[s_key_offset + GPU_LOC_2 + 6] = lm_int_keys[OFFSET + i * 8 + 6];
		s_lm_key[s_key_offset + GPU_LOC_2 + 7] = lm_int_keys[OFFSET + i * 8 + 7];
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
#undef OFFSET
#define OFFSET 	(3 * ITER_COUNT * 8)
		s_lm_key[s_key_offset + GPU_LOC_3] = lm_int_keys[OFFSET + i * 8];
		s_lm_key[s_key_offset + GPU_LOC_3 + 1] = lm_int_keys[OFFSET + i * 8 + 1];
		s_lm_key[s_key_offset + GPU_LOC_3 + 2] = lm_int_keys[OFFSET + i * 8 + 2];
		s_lm_key[s_key_offset + GPU_LOC_3 + 3] = lm_int_keys[OFFSET + i * 8 + 3];
		s_lm_key[s_key_offset + GPU_LOC_3 + 4] = lm_int_keys[OFFSET + i * 8 + 4];
		s_lm_key[s_key_offset + GPU_LOC_3 + 5] = lm_int_keys[OFFSET + i * 8 + 5];
		s_lm_key[s_key_offset + GPU_LOC_3 + 6] = lm_int_keys[OFFSET + i * 8 + 6];
		s_lm_key[s_key_offset + GPU_LOC_3 + 7] = lm_int_keys[OFFSET + i * 8 + 7];
#endif
#endif

#else
		lm_keys[GPU_LOC_0 * gws + section] = lm_int_keys[i * 8];
		lm_keys[(GPU_LOC_0 + 1) * gws + section] = lm_int_keys[i * 8 + 1];
		lm_keys[(GPU_LOC_0 + 2) * gws + section] = lm_int_keys[i * 8 + 2];
		lm_keys[(GPU_LOC_0 + 3) * gws + section] = lm_int_keys[i * 8 + 3];
		lm_keys[(GPU_LOC_0 + 4) * gws + section] = lm_int_keys[i * 8 + 4];
		lm_keys[(GPU_LOC_0 + 5) * gws + section] = lm_int_keys[i * 8 + 5];
		lm_keys[(GPU_LOC_0 + 6) * gws + section] = lm_int_keys[i * 8 + 6];
		lm_keys[(GPU_LOC_0 + 7) * gws + section] = lm_int_keys[i * 8 + 7];
#if MASK_FMT_INT_PLHDR > 1
#if LOC_1 >= 0
#define OFFSET 	(1 * ITER_COUNT * 8)
		lm_keys[GPU_LOC_1 * gws + section] = lm_int_keys[OFFSET + i * 8];
		lm_keys[(GPU_LOC_1 + 1) * gws + section] = lm_int_keys[OFFSET + i * 8 + 1];
		lm_keys[(GPU_LOC_1 + 2) * gws + section] = lm_int_keys[OFFSET + i * 8 + 2];
		lm_keys[(GPU_LOC_1 + 3) * gws + section] = lm_int_keys[OFFSET + i * 8 + 3];
		lm_keys[(GPU_LOC_1 + 4) * gws + section] = lm_int_keys[OFFSET + i * 8 + 4];
		lm_keys[(GPU_LOC_1 + 5) * gws + section] = lm_int_keys[OFFSET + i * 8 + 5];
		lm_keys[(GPU_LOC_1 + 6) * gws + section] = lm_int_keys[OFFSET + i * 8 + 6];
		lm_keys[(GPU_LOC_1 + 7) * gws + section] = lm_int_keys[OFFSET + i * 8 + 7];
#endif
#endif
#if MASK_FMT_INT_PLHDR > 2
#if LOC_2 >= 0
#undef OFFSET
#define OFFSET 	(2 * ITER_COUNT * 8)
		lm_keys[GPU_LOC_2 * gws + section] = lm_int_keys[OFFSET + i * 8];
		lm_keys[(GPU_LOC_2 + 1) * gws + section] = lm_int_keys[OFFSET + i * 8 + 1];
		lm_keys[(GPU_LOC_2 + 2) * gws + section] = lm_int_keys[OFFSET + i * 8 + 2];
		lm_keys[(GPU_LOC_2 + 3) * gws + section] = lm_int_keys[OFFSET + i * 8 + 3];
		lm_keys[(GPU_LOC_2 + 4) * gws + section] = lm_int_keys[OFFSET + i * 8 + 4];
		lm_keys[(GPU_LOC_2 + 5) * gws + section] = lm_int_keys[OFFSET + i * 8 + 5];
		lm_keys[(GPU_LOC_2 + 6) * gws + section] = lm_int_keys[OFFSET + i * 8 + 6];
		lm_keys[(GPU_LOC_2 + 7) * gws + section] = lm_int_keys[OFFSET + i * 8 + 7];
#endif
#endif
#if MASK_FMT_INT_PLHDR > 3
#if LOC_3 >= 0
#undef OFFSET
#define OFFSET 	(3 * ITER_COUNT * 8)
		lm_keys[GPU_LOC_3 * gws + section] = lm_int_keys[OFFSET + i * 8];
		lm_keys[(GPU_LOC_3 + 1) * gws + section] = lm_int_keys[OFFSET + i * 8 + 1];
		lm_keys[(GPU_LOC_3 + 2) * gws + section] = lm_int_keys[OFFSET + i * 8 + 2];
		lm_keys[(GPU_LOC_3 + 3) * gws + section] = lm_int_keys[OFFSET + i * 8 + 3];
		lm_keys[(GPU_LOC_3 + 4) * gws + section] = lm_int_keys[OFFSET + i * 8 + 4];
		lm_keys[(GPU_LOC_3 + 5) * gws + section] = lm_int_keys[OFFSET + i * 8 + 5];
		lm_keys[(GPU_LOC_3 + 6) * gws + section] = lm_int_keys[OFFSET + i * 8 + 6];
		lm_keys[(GPU_LOC_3 + 7) * gws + section] = lm_int_keys[OFFSET + i * 8 + 7];
#endif
#endif

#endif /* WORK_GROUP_SIZE */

#endif /* MASK_ENABLE */

		vtype z = vzero, o = vones;
		lm_set_block_8(B, 0, z, z, z, z, z, z, z, z);
		lm_set_block_8(B, 8, o, o, o, z, o, z, z, z);
		lm_set_block_8(B, 16, z, z, z, z, z, z, z, o);
		lm_set_block_8(B, 24, z, z, o, z, z, o, o, o);
		lm_set_block_8(B, 32, z, z, z, o, z, o, o, o);
		lm_set_block_8(B, 40, z, z, z, z, z, o, z, z);
		lm_set_block_8(B, 48, o, o, z, z, z, z, o, z);
		lm_set_block_8(B, 56, o, z, o, z, o, o, o, o);

		lm_loop(B,
#if WORK_GROUP_SIZE
		s_lm_key,
#else
		lm_keys,
#endif
#if WORK_GROUP_SIZE
		s_key_offset
#else
		gws,
		section
#endif
		);

		cmp(B, offset_table, hash_table, bitmaps, hash_ids, bitmap_dupe, section, i);
	}
}

#endif
