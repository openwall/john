/* sboxes-alti.c 
Bitslice DES faster implementation for Cell/SpursEngine SPU (GPL Ver.)

Copyright (C) 2008 Dumplinger Boy (Dango-Chu).

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

/* 
#include <altivec.h>
typedef vector unsigned int altivec;
*/
 
static void s1(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32, x33, x34, x35, x36;
	altivec x37, x38, x39, x40, x41, x42;
	altivec x43, x44, x45;

	x1 = vec_nor(a3, a5);
	x2 = vec_xor(x1, a4);
	x3 = vec_xor(a3, a5);
	x4 = vec_xor(x3, x2);
	x5 = vec_sel(x4, x2, a2);
	x6 = vec_sel(x2, x3, a5);
	x7 = vec_andc(a3, a4);
	x8 = vec_or(x7, x1);
	x9 = vec_sel(x8, x6, a2);
	x10 = vec_sel(x9, x5, a6);
	x11 = vec_sel(x8, a4, x9);
	x12 = vec_xor(x3, x11);
	x13 = vec_sel(a4, x4, a3);
	x14 = vec_sel(x8, x6, x4);
	x15 = vec_sel(x14, x13, a2);
	x16 = vec_sel(x15, x12, a6);
	x17 = vec_sel(x16, x10, a1);
	*out2 = vec_xor(*out2, x17);
	x18 = vec_sel(a3, x12, x9);
	x19 = vec_xor(x8, x18);
	x20 = vec_sel(x12, x4, a4);
	x21 = vec_xor(a2, x20);
	x22 = vec_sel(x21, x19, a6);
	x23 = vec_or(a2, x14);
	x24 = vec_xor(x23, x19);
	x25 = vec_xor(a5, x15);
	x26 = vec_xor(x25, x19);
	x27 = vec_sel(x26, x24, a6);
	x28 = vec_sel(x27, x22, a1);
	*out4 = vec_xor(*out4, x28);
	x29 = vec_nor(x5, x26);
	x30 = vec_xor(x29, x15);
	x31 = vec_sel(x13, x14, a2);
	x32 = vec_sel(x31, x30, a6);
	x33 = vec_and(a3, a4);
	x34 = vec_xor(x33, x21);
	x35 = vec_or(x4, x8);
	x36 = vec_xor(x35, x34);
	x37 = vec_sel(x36, x34, a6);
	x38 = vec_sel(x37, x32, a1);
	*out1 = vec_xor(*out1, x38);
	x39 = vec_sel(x25, x21, x11);
	x40 = vec_sel(x26, x24, x13);
	x41 = vec_sel(x40, x39, a6);
	x42 = vec_sel(x3, x9, x26);
	x43 = vec_sel(x34, x19, x23);
	x44 = vec_sel(x43, x42, a6);
	x45 = vec_sel(x44, x41, a1);
	*out3 = vec_xor(*out3, x45);
}

static void s2(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32, x33, x34, x35, x36;
	altivec x37, x38, x39, x40, x41, x42;

	x1 = vec_xor(a3, a5);
	x2 = vec_nor(x1, x1);
	x3 = vec_or(a3, x2);
	x4 = vec_xor(x3, a4);
	x5 = vec_sel(x4, x2, a2);
	x6 = vec_sel(x4, a3, a5);
	x7 = vec_sel(a4, x6, a2);
	x8 = vec_sel(x7, x5, a6);
	x9 = vec_xor(a2, a5);
	x10 = vec_xor(x9, x6);
	x11 = vec_sel(x1, a3, x7);
	x12 = vec_xor(x6, x11);
	x13 = vec_sel(x12, x10, a6);
	x14 = vec_sel(x13, x8, a1);
	*out4 = vec_xor(*out4, x14);
	x15 = vec_sel(x10, a4, a3);
	x16 = vec_xor(a5, x15);
	x17 = vec_sel(x4, x11, x9);
	x18 = vec_xor(x3, x17);
	x19 = vec_sel(x18, x16, a6);
	x20 = vec_nor(x16, x16);
	x21 = vec_sel(a2, x3, x9);
	x22 = vec_xor(x5, x21);
	x23 = vec_sel(x22, x20, a6);
	x24 = vec_sel(x23, x19, a1);
	*out2 = vec_xor(*out2, x24);
	x25 = vec_sel(x18, x21, x4);
	x26 = vec_xor(x11, x25);
	x27 = vec_sel(a5, x21, x2);
	x28 = vec_xor(x26, x27);
	x29 = vec_sel(x28, x26, a6);
	x30 = vec_sel(x22, a3, x26);
	x31 = vec_sel(x3, x1, a4);
	x32 = vec_xor(a2, x31);
	x33 = vec_sel(x32, x30, a6);
	x34 = vec_sel(x33, x29, a1);
	*out3 = vec_xor(*out3, x34);
	x35 = vec_xor(x20, x30);
	x36 = vec_sel(x1, x32, a4);
	x37 = vec_sel(x36, x35, a6);
	x38 = vec_sel(x1, x32, x25);
	x39 = vec_xor(x27, x38);
	x40 = vec_sel(x35, x4, x9);
	x41 = vec_sel(x40, x39, a6);
	x42 = vec_sel(x41, x37, a1);
	*out1 = vec_xor(*out1, x42);
}

static void s3(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32, x33, x34, x35, x36;
	altivec x37, x38, x39, x40, x41, x42;
	altivec x43;

	x1 = vec_xor(a4, a5);
	x2 = vec_xor(x1, a3);
	x3 = vec_nor(x2, x2);
	x4 = vec_xor(x3, a6);
	x5 = vec_or(a5, a3);
	x6 = vec_sel(x5, x3, a4);
	x7 = vec_sel(x2, x6, a6);
	x8 = vec_sel(x7, x4, a1);
	x9 = vec_xor(a5, x3);
	x10 = vec_xor(x9, x5);
	x11 = vec_sel(x10, x1, a6);
	x12 = vec_sel(x7, a4, x10);
	x13 = vec_xor(x9, x12);
	x14 = vec_sel(x13, x11, a1);
	x15 = vec_sel(x14, x8, a2);
	*out1 = vec_xor(*out1, x15);
	x16 = vec_sel(a5, x6, x2);
	x17 = vec_xor(a5, x10);
	x18 = vec_sel(x17, x16, a6);
	x19 = vec_sel(a3, x1, a5);
	x20 = vec_xor(x4, x19);
	x21 = vec_sel(x20, x18, a1);
	x22 = vec_sel(x3, x4, a4);
	x23 = vec_nor(x20, x20);
	x24 = vec_sel(x23, x22, a1);
	x25 = vec_sel(x24, x21, a2);
	*out4 = vec_xor(*out4, x25);
	x26 = vec_sel(x11, x20, x1);
	x27 = vec_xor(x9, x26);
	x28 = vec_or(x4, x23);
	x29 = vec_xor(x28, x9);
	x30 = vec_sel(x29, x27, a1);
	x31 = vec_xor(x2, x22);
	x32 = vec_xor(x31, x27);
	x33 = vec_sel(x19, x27, x31);
	x34 = vec_sel(x33, x32, a1);
	x35 = vec_sel(x34, x30, a2);
	*out2 = vec_xor(*out2, x35);
	x36 = vec_sel(x1, x28, x18);
	x37 = vec_sel(x33, x3, x12);
	x38 = vec_sel(x37, x36, a1);
	x39 = vec_sel(x19, x4, a3);
	x40 = vec_sel(x18, a3, x33);
	x41 = vec_xor(a5, x40);
	x42 = vec_sel(x41, x39, a1);
	x43 = vec_sel(x42, x38, a2);
	*out3 = vec_xor(*out3, x43);
}

static void s4(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32;

	x1 = vec_nor(a3, a3);
	x2 = vec_andc(a3, a5);
	x3 = vec_sel(x2, x1, a2);
	x4 = vec_nor(x2, x3);
	x5 = vec_sel(x4, x3, a1);
	x6 = vec_sel(x1, x4, a5);
	x7 = vec_xor(a2, a5);
	x8 = vec_xor(x7, x1);
	x9 = vec_sel(x8, x6, a1);
	x10 = vec_sel(x9, x5, a4);
	x11 = vec_or(x2, x5);
	x12 = vec_xor(x11, x8);
	x13 = vec_sel(a2, x7, a3);
	x14 = vec_sel(x1, x7, a2);
	x15 = vec_sel(x14, x13, a1);
	x16 = vec_sel(x15, x12, a4);
	x17 = vec_sel(x16, x10, a6);
	*out4 = vec_xor(*out4, x17);
	x18 = vec_sel(a1, x5, a3);
	x19 = vec_xor(x9, x18);
	x20 = vec_sel(x2, x7, x1);
	x21 = vec_sel(x5, x20, a1);
	x22 = vec_sel(x21, x19, a4);
	x23 = vec_sel(x4, x3, x20);
	x24 = vec_sel(x23, x8, a1);
	x25 = vec_nor(a1, x6);
	x26 = vec_xor(x25, x12);
	x27 = vec_sel(x26, x24, a4);
	x28 = vec_sel(x27, x22, a6);
	*out1 = vec_xor(*out1, x28);
	x29 = vec_sel(x22, x27, a6);
	x30 = vec_xor(a6, x29);
	*out2 = vec_xor(*out2, x30);
	x31 = vec_sel(x10, x16, a6);
	x32 = vec_xor(a6, x31);
	*out3 = vec_xor(*out3, x32);
}

static void s5(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32, x33, x34, x35, x36;
	altivec x37, x38, x39, x40, x41, x42;
	altivec x43, x44;

	x1 = vec_xor(a2, a6);
	x2 = vec_nor(x1, x1);
	x3 = vec_xor(x2, a5);
	x4 = vec_sel(x1, x3, a3);
	x5 = vec_xor(a3, x3);
	x6 = vec_sel(x5, x4, a1);
	x7 = vec_sel(a5, x5, a2);
	x8 = vec_sel(a2, x2, x3);
	x9 = vec_sel(x8, x7, a3);
	x10 = vec_sel(a5, x8, a3);
	x11 = vec_xor(a6, x10);
	x12 = vec_sel(x11, x9, a1);
	x13 = vec_sel(x12, x6, a4);
	*out2 = vec_xor(*out2, x13);
	x14 = vec_sel(x4, x7, x8);
	x15 = vec_xor(x11, x14);
	x16 = vec_sel(x2, x5, a2);
	x17 = vec_sel(a2, x11, x14);
	x18 = vec_sel(x17, x16, a3);
	x19 = vec_sel(x18, x15, a1);
	x20 = vec_nor(a6, x9);
	x21 = vec_xor(x20, x17);
	x22 = vec_sel(x3, x18, x7);
	x23 = vec_xor(x14, x22);
	x24 = vec_sel(x23, x21, a1);
	x25 = vec_sel(x24, x19, a4);
	*out3 = vec_xor(*out3, x25);
	x26 = vec_sel(x22, x23, x16);
	x27 = vec_xor(a5, x26);
	x28 = vec_sel(a2, x16, a5);
	x29 = vec_xor(a3, x28);
	x30 = vec_sel(x29, x27, a1);
	x31 = vec_sel(a1, x8, a5);
	x32 = vec_xor(x22, x31);
	x33 = vec_sel(x14, x27, x4);
	x34 = vec_sel(x33, x32, a1);
	x35 = vec_sel(x34, x30, a4);
	*out4 = vec_xor(*out4, x35);
	x36 = vec_sel(x3, x31, a3);
	x37 = vec_andc(a4, x36);
	x38 = vec_sel(x1, x32, x21);
	x39 = vec_sel(x38, x37, a1);
	x40 = vec_sel(x4, x18, x32);
	x41 = vec_sel(x4, x2, x18);
	x42 = vec_xor(x21, x41);
	x43 = vec_sel(x42, x40, a1);
	x44 = vec_sel(x43, x39, a4);
	*out1 = vec_xor(*out1, x44);
}

static void s6(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32, x33, x34, x35, x36;
	altivec x37, x38, x39, x40, x41, x42;
	altivec x43;

	x1 = vec_andc(a5, a6);
	x2 = vec_xor(x1, a4);
	x3 = vec_nor(a4, a6);
	x4 = vec_xor(x3, a5);
	x5 = vec_sel(x4, x2, a1);
	x6 = vec_nor(x2, x3);
	x7 = vec_sel(x1, a6, a4);
	x8 = vec_sel(x7, x6, a1);
	x9 = vec_sel(x8, x5, a3);
	x10 = vec_or(a5, x5);
	x11 = vec_xor(x10, x8);
	x12 = vec_andc(x7, a5);
	x13 = vec_nor(x12, x8);
	x14 = vec_sel(x13, x11, a3);
	x15 = vec_sel(x14, x9, a2);
	*out1 = vec_xor(*out1, x15);
	x16 = vec_sel(a6, x7, x13);
	x17 = vec_xor(x10, x16);
	x18 = vec_sel(x5, x1, x7);
	x19 = vec_nor(x12, x18);
	x20 = vec_sel(x19, x17, a3);
	x21 = vec_nor(x1, x18);
	x22 = vec_xor(x21, x8);
	x23 = vec_sel(a1, x17, x6);
	x24 = vec_xor(x19, x23);
	x25 = vec_sel(x24, x22, a3);
	x26 = vec_sel(x25, x20, a2);
	*out3 = vec_xor(*out3, x26);
	x27 = vec_sel(a4, x17, a5);
	x28 = vec_sel(x27, x13, a1);
	x29 = vec_sel(x28, a6, x11);
	x30 = vec_sel(x29, x28, a3);
	x31 = vec_sel(a3, x12, x28);
	x32 = vec_or(x7, x23);
	x33 = vec_xor(x32, x16);
	x34 = vec_sel(x33, x31, a3);
	x35 = vec_sel(x34, x30, a2);
	*out4 = vec_xor(*out4, x35);
	x36 = vec_xor(x11, x27);
	x37 = vec_sel(a6, x24, a4);
	x38 = vec_xor(x29, x37);
	x39 = vec_sel(x38, x36, a3);
	x40 = vec_andc(x24, x1);
	x41 = vec_sel(x17, x11, x28);
	x42 = vec_sel(x41, x40, a3);
	x43 = vec_sel(x42, x39, a2);
	*out2 = vec_xor(*out2, x43);
}

static void s7(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32, x33, x34, x35, x36;
	altivec x37, x38, x39, x40, x41, x42;

	x1 = vec_and(a4, a5);
	x2 = vec_xor(x1, a3);
	x3 = vec_nor(x2, x2);
	x4 = vec_xor(x3, a6);
	x5 = vec_sel(x3, a3, a4);
	x6 = vec_sel(a4, a3, a5);
	x7 = vec_sel(x6, x5, a6);
	x8 = vec_sel(x7, x4, a2);
	x9 = vec_sel(a3, x3, x5);
	x10 = vec_xor(a5, x5);
	x11 = vec_sel(x10, x9, a6);
	x12 = vec_nor(x10, x11);
	x13 = vec_xor(x12, x1);
	x14 = vec_sel(x13, x11, a2);
	x15 = vec_sel(x14, x8, a1);
	*out3 = vec_xor(*out3, x15);
	x16 = vec_sel(x11, x13, a5);
	x17 = vec_sel(a1, x3, a5);
	x18 = vec_xor(x16, x17);
	x19 = vec_sel(x18, x16, a2);
	x20 = vec_sel(x6, x13, x5);
	x21 = vec_sel(x20, x10, a6);
	x22 = vec_sel(x9, a4, a6);
	x23 = vec_xor(x10, x22);
	x24 = vec_sel(x23, x21, a2);
	x25 = vec_sel(x24, x19, a1);
	*out1 = vec_xor(*out1, x25);
	x26 = vec_sel(x6, x21, x5);
	x27 = vec_xor(a6, x26);
	x28 = vec_sel(x24, x27, a2);
	x29 = vec_sel(x10, x13, x22);
	x30 = vec_xor(a3, x10);
	x31 = vec_andc(x30, x20);
	x32 = vec_sel(x31, x29, a2);
	x33 = vec_sel(x32, x28, a1);
	*out2 = vec_xor(*out2, x33);
	x34 = vec_sel(x5, x21, x22);
	x35 = vec_or(a6, x16);
	x36 = vec_xor(x35, x21);
	x37 = vec_sel(x36, x34, a2);
	x38 = vec_or(x10, x12);
	x39 = vec_xor(x38, x34);
	x40 = vec_sel(x12, x35, x21);
	x41 = vec_sel(x40, x39, a2);
	x42 = vec_sel(x41, x37, a1);
	*out4 = vec_xor(*out4, x42);
}

static void s8(
	altivec a1,
	altivec a2,
	altivec a3,
	altivec a4,
	altivec a5,
	altivec a6,
	altivec *out1,
	altivec *out2,
	altivec *out3,
	altivec *out4
) {
	altivec x1, x2, x3, x4, x5, x6;
	altivec x7, x8, x9, x10, x11, x12;
	altivec x13, x14, x15, x16, x17, x18;
	altivec x19, x20, x21, x22, x23, x24;
	altivec x25, x26, x27, x28, x29, x30;
	altivec x31, x32, x33, x34, x35, x36;
	altivec x37, x38, x39, x40, x41;

	x1 = vec_xor(a2, a4);
	x2 = vec_xor(a3, x1);
	x3 = vec_sel(x2, x1, a5);
	x4 = vec_nor(a2, a3);
	x5 = vec_xor(x4, x1);
	x6 = vec_sel(a4, x1, x2);
	x7 = vec_sel(x6, x5, a5);
	x8 = vec_sel(x7, x3, a1);
	x9 = vec_sel(x5, a4, x2);
	x10 = vec_xor(a5, x9);
	x11 = vec_nor(x7, x7);
	x12 = vec_sel(x11, x10, a1);
	x13 = vec_sel(x12, x8, a6);
	*out2 = vec_xor(*out2, x13);
	x14 = vec_sel(a5, x9, a4);
	x15 = vec_xor(x5, x14);
	x16 = vec_xor(x6, x14);
	x17 = vec_nor(x15, x15);
	x18 = vec_sel(x17, x16, a5);
	x19 = vec_sel(x18, x15, a1);
	x20 = vec_sel(x5, x17, x7);
	x21 = vec_or(a5, a4);
	x22 = vec_xor(x21, x3);
	x23 = vec_sel(x22, x20, a1);
	x24 = vec_sel(x23, x19, a6);
	*out3 = vec_xor(*out3, x24);
	x25 = vec_andc(a5, x5);
	x26 = vec_xor(x25, x6);
	x27 = vec_xor(x11, x20);
	x28 = vec_xor(x27, x26);
	x29 = vec_sel(x28, x26, a1);
	x30 = vec_sel(a3, x22, x21);
	x31 = vec_andc(a2, x21);
	x32 = vec_xor(x31, x10);
	x33 = vec_sel(x32, x30, a1);
	x34 = vec_sel(x33, x29, a6);
	*out1 = vec_xor(*out1, x34);
	x35 = vec_or(x9, x21);
	x36 = vec_xor(x35, x32);
	x37 = vec_sel(x1, x36, x26);
	x38 = vec_andc(x35, x37);
	x39 = vec_sel(x38, x36, a1);
	x40 = vec_nor(x29, x29);
	x41 = vec_sel(x40, x39, a6);
	*out4 = vec_xor(*out4, x41);
}
