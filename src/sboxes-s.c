/*
 * Bitslice DES S-boxes making use of a vector conditional select operation
 * (e.g., vsel on PowerPC with AltiVec).
 *
 * Copyright (C) 2008 Dumplinger Boy (Dango-Chu).
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

MAYBE_INLINE static void s1(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32, x33, x34, x35, x36;
	vtype x37, x38, x39, x40, x41, x42;
	vtype x43, x44, x45;

	vnor(x1, a3, a5);
	vxor(x2, x1, a4);
	vxor(x3, a3, a5);
	vxor(x4, x3, x2);
	vsel(x5, x4, x2, a2);
	vsel(x6, x2, x3, a5);
	vandn(x7, a3, a4);
	vor(x8, x7, x1);
	vsel(x9, x8, x6, a2);
	vsel(x10, x9, x5, a6);
	vsel(x11, x8, a4, x9);
	vxor(x12, x3, x11);
	vsel(x13, a4, x4, a3);
	vsel(x14, x8, x6, x4);
	vsel(x15, x14, x13, a2);
	vsel(x16, x15, x12, a6);
	vsel(x17, x16, x10, a1);
	vxor(*out2, *out2, x17);
	vsel(x18, a3, x12, x9);
	vxor(x19, x8, x18);
	vsel(x20, x12, x4, a4);
	vxor(x21, a2, x20);
	vsel(x22, x21, x19, a6);
	vor(x23, a2, x14);
	vxor(x24, x23, x19);
	vxor(x25, a5, x15);
	vxor(x26, x25, x19);
	vsel(x27, x26, x24, a6);
	vsel(x28, x27, x22, a1);
	vxor(*out4, *out4, x28);
	vnor(x29, x5, x26);
	vxor(x30, x29, x15);
	vsel(x31, x13, x14, a2);
	vsel(x32, x31, x30, a6);
	vand(x33, a3, a4);
	vxor(x34, x33, x21);
	vor(x35, x4, x8);
	vxor(x36, x35, x34);
	vsel(x37, x36, x34, a6);
	vsel(x38, x37, x32, a1);
	vxor(*out1, *out1, x38);
	vsel(x39, x25, x21, x11);
	vsel(x40, x26, x24, x13);
	vsel(x41, x40, x39, a6);
	vsel(x42, x3, x9, x26);
	vsel(x43, x34, x19, x23);
	vsel(x44, x43, x42, a6);
	vsel(x45, x44, x41, a1);
	vxor(*out3, *out3, x45);
}

MAYBE_INLINE static void s2(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32, x33, x34, x35, x36;
	vtype x37, x38, x39, x40, x41, x42;

	vxor(x1, a3, a5);
	vnor(x2, x1, x1);
	vor(x3, a3, x2);
	vxor(x4, x3, a4);
	vsel(x5, x4, x2, a2);
	vsel(x6, x4, a3, a5);
	vsel(x7, a4, x6, a2);
	vsel(x8, x7, x5, a6);
	vxor(x9, a2, a5);
	vxor(x10, x9, x6);
	vsel(x11, x1, a3, x7);
	vxor(x12, x6, x11);
	vsel(x13, x12, x10, a6);
	vsel(x14, x13, x8, a1);
	vxor(*out4, *out4, x14);
	vsel(x15, x10, a4, a3);
	vxor(x16, a5, x15);
	vsel(x17, x4, x11, x9);
	vxor(x18, x3, x17);
	vsel(x19, x18, x16, a6);
	vnor(x20, x16, x16);
	vsel(x21, a2, x3, x9);
	vxor(x22, x5, x21);
	vsel(x23, x22, x20, a6);
	vsel(x24, x23, x19, a1);
	vxor(*out2, *out2, x24);
	vsel(x25, x18, x21, x4);
	vxor(x26, x11, x25);
	vsel(x27, a5, x21, x2);
	vxor(x28, x26, x27);
	vsel(x29, x28, x26, a6);
	vsel(x30, x22, a3, x26);
	vsel(x31, x3, x1, a4);
	vxor(x32, a2, x31);
	vsel(x33, x32, x30, a6);
	vsel(x34, x33, x29, a1);
	vxor(*out3, *out3, x34);
	vxor(x35, x20, x30);
	vsel(x36, x1, x32, a4);
	vsel(x37, x36, x35, a6);
	vsel(x38, x1, x32, x25);
	vxor(x39, x27, x38);
	vsel(x40, x35, x4, x9);
	vsel(x41, x40, x39, a6);
	vsel(x42, x41, x37, a1);
	vxor(*out1, *out1, x42);
}

MAYBE_INLINE static void s3(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32, x33, x34, x35, x36;
	vtype x37, x38, x39, x40, x41, x42;
	vtype x43;

	vxor(x1, a4, a5);
	vxor(x2, x1, a3);
	vnor(x3, x2, x2);
	vxor(x4, x3, a6);
	vor(x5, a5, a3);
	vsel(x6, x5, x3, a4);
	vsel(x7, x2, x6, a6);
	vsel(x8, x7, x4, a1);
	vxor(x9, a5, x3);
	vxor(x10, x9, x5);
	vsel(x11, x10, x1, a6);
	vsel(x12, x7, a4, x10);
	vxor(x13, x9, x12);
	vsel(x14, x13, x11, a1);
	vsel(x15, x14, x8, a2);
	vxor(*out1, *out1, x15);
	vsel(x16, a5, x6, x2);
	vxor(x17, a5, x10);
	vsel(x18, x17, x16, a6);
	vsel(x19, a3, x1, a5);
	vxor(x20, x4, x19);
	vsel(x21, x20, x18, a1);
	vsel(x22, x3, x4, a4);
	vnor(x23, x20, x20);
	vsel(x24, x23, x22, a1);
	vsel(x25, x24, x21, a2);
	vxor(*out4, *out4, x25);
	vsel(x26, x11, x20, x1);
	vxor(x27, x9, x26);
	vor(x28, x4, x23);
	vxor(x29, x28, x9);
	vsel(x30, x29, x27, a1);
	vxor(x31, x2, x22);
	vxor(x32, x31, x27);
	vsel(x33, x19, x27, x31);
	vsel(x34, x33, x32, a1);
	vsel(x35, x34, x30, a2);
	vxor(*out2, *out2, x35);
	vsel(x36, x1, x28, x18);
	vsel(x37, x33, x3, x12);
	vsel(x38, x37, x36, a1);
	vsel(x39, x19, x4, a3);
	vsel(x40, x18, a3, x33);
	vxor(x41, a5, x40);
	vsel(x42, x41, x39, a1);
	vsel(x43, x42, x38, a2);
	vxor(*out3, *out3, x43);
}

MAYBE_INLINE static void s4(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32;

	vnor(x1, a3, a3);
	vandn(x2, a3, a5);
	vsel(x3, x2, x1, a2);
	vnor(x4, x2, x3);
	vsel(x5, x4, x3, a1);
	vsel(x6, x1, x4, a5);
	vxor(x7, a2, a5);
	vxor(x8, x7, x1);
	vsel(x9, x8, x6, a1);
	vsel(x10, x9, x5, a4);
	vor(x11, x2, x5);
	vxor(x12, x11, x8);
	vsel(x13, a2, x7, a3);
	vsel(x14, x1, x7, a2);
	vsel(x15, x14, x13, a1);
	vsel(x16, x15, x12, a4);
	vsel(x17, x16, x10, a6);
	vxor(*out4, *out4, x17);
	vsel(x18, a1, x5, a3);
	vxor(x19, x9, x18);
	vsel(x20, x2, x7, x1);
	vsel(x21, x5, x20, a1);
	vsel(x22, x21, x19, a4);
	vsel(x23, x4, x3, x20);
	vsel(x24, x23, x8, a1);
	vnor(x25, a1, x6);
	vxor(x26, x25, x12);
	vsel(x27, x26, x24, a4);
	vsel(x28, x27, x22, a6);
	vxor(*out1, *out1, x28);
	vsel(x29, x22, x27, a6);
	vxor(x30, a6, x29);
	vxor(*out2, *out2, x30);
	vsel(x31, x10, x16, a6);
	vxor(x32, a6, x31);
	vxor(*out3, *out3, x32);
}

MAYBE_INLINE static void s5(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32, x33, x34, x35, x36;
	vtype x37, x38, x39, x40, x41, x42;
	vtype x43, x44;

	vxor(x1, a2, a6);
	vnor(x2, x1, x1);
	vxor(x3, x2, a5);
	vsel(x4, x1, x3, a3);
	vxor(x5, a3, x3);
	vsel(x6, x5, x4, a1);
	vsel(x7, a5, x5, a2);
	vsel(x8, a2, x2, x3);
	vsel(x9, x8, x7, a3);
	vsel(x10, a5, x8, a3);
	vxor(x11, a6, x10);
	vsel(x12, x11, x9, a1);
	vsel(x13, x12, x6, a4);
	vxor(*out2, *out2, x13);
	vsel(x14, x4, x7, x8);
	vxor(x15, x11, x14);
	vsel(x16, x2, x5, a2);
	vsel(x17, a2, x11, x14);
	vsel(x18, x17, x16, a3);
	vsel(x19, x18, x15, a1);
	vnor(x20, a6, x9);
	vxor(x21, x20, x17);
	vsel(x22, x3, x18, x7);
	vxor(x23, x14, x22);
	vsel(x24, x23, x21, a1);
	vsel(x25, x24, x19, a4);
	vxor(*out3, *out3, x25);
	vsel(x26, x22, x23, x16);
	vxor(x27, a5, x26);
	vsel(x28, a2, x16, a5);
	vxor(x29, a3, x28);
	vsel(x30, x29, x27, a1);
	vsel(x31, a1, x8, a5);
	vxor(x32, x22, x31);
	vsel(x33, x14, x27, x4);
	vsel(x34, x33, x32, a1);
	vsel(x35, x34, x30, a4);
	vxor(*out4, *out4, x35);
	vsel(x36, x3, x31, a3);
	vandn(x37, a4, x36);
	vsel(x38, x1, x32, x21);
	vsel(x39, x38, x37, a1);
	vsel(x40, x4, x18, x32);
	vsel(x41, x4, x2, x18);
	vxor(x42, x21, x41);
	vsel(x43, x42, x40, a1);
	vsel(x44, x43, x39, a4);
	vxor(*out1, *out1, x44);
}

MAYBE_INLINE static void s6(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32, x33, x34, x35, x36;
	vtype x37, x38, x39, x40, x41, x42;
	vtype x43;

	vandn(x1, a5, a6);
	vxor(x2, x1, a4);
	vnor(x3, a4, a6);
	vxor(x4, x3, a5);
	vsel(x5, x4, x2, a1);
	vnor(x6, x2, x3);
	vsel(x7, x1, a6, a4);
	vsel(x8, x7, x6, a1);
	vsel(x9, x8, x5, a3);
	vor(x10, a5, x5);
	vxor(x11, x10, x8);
	vandn(x12, x7, a5);
	vnor(x13, x12, x8);
	vsel(x14, x13, x11, a3);
	vsel(x15, x14, x9, a2);
	vxor(*out1, *out1, x15);
	vsel(x16, a6, x7, x13);
	vxor(x17, x10, x16);
	vsel(x18, x5, x1, x7);
	vnor(x19, x12, x18);
	vsel(x20, x19, x17, a3);
	vnor(x21, x1, x18);
	vxor(x22, x21, x8);
	vsel(x23, a1, x17, x6);
	vxor(x24, x19, x23);
	vsel(x25, x24, x22, a3);
	vsel(x26, x25, x20, a2);
	vxor(*out3, *out3, x26);
	vsel(x27, a4, x17, a5);
	vsel(x28, x27, x13, a1);
	vsel(x29, x28, a6, x11);
	vsel(x30, x29, x28, a3);
	vsel(x31, a3, x12, x28);
	vor(x32, x7, x23);
	vxor(x33, x32, x16);
	vsel(x34, x33, x31, a3);
	vsel(x35, x34, x30, a2);
	vxor(*out4, *out4, x35);
	vxor(x36, x11, x27);
	vsel(x37, a6, x24, a4);
	vxor(x38, x29, x37);
	vsel(x39, x38, x36, a3);
	vandn(x40, x24, x1);
	vsel(x41, x17, x11, x28);
	vsel(x42, x41, x40, a3);
	vsel(x43, x42, x39, a2);
	vxor(*out2, *out2, x43);
}

MAYBE_INLINE static void s7(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32, x33, x34, x35, x36;
	vtype x37, x38, x39, x40, x41, x42;

	vand(x1, a4, a5);
	vxor(x2, x1, a3);
	vnor(x3, x2, x2);
	vxor(x4, x3, a6);
	vsel(x5, x3, a3, a4);
	vsel(x6, a4, a3, a5);
	vsel(x7, x6, x5, a6);
	vsel(x8, x7, x4, a2);
	vsel(x9, a3, x3, x5);
	vxor(x10, a5, x5);
	vsel(x11, x10, x9, a6);
	vnor(x12, x10, x11);
	vxor(x13, x12, x1);
	vsel(x14, x13, x11, a2);
	vsel(x15, x14, x8, a1);
	vxor(*out3, *out3, x15);
	vsel(x16, x11, x13, a5);
	vsel(x17, a1, x3, a5);
	vxor(x18, x16, x17);
	vsel(x19, x18, x16, a2);
	vsel(x20, x6, x13, x5);
	vsel(x21, x20, x10, a6);
	vsel(x22, x9, a4, a6);
	vxor(x23, x10, x22);
	vsel(x24, x23, x21, a2);
	vsel(x25, x24, x19, a1);
	vxor(*out1, *out1, x25);
	vsel(x26, x6, x21, x5);
	vxor(x27, a6, x26);
	vsel(x28, x24, x27, a2);
	vsel(x29, x10, x13, x22);
	vxor(x30, a3, x10);
	vandn(x31, x30, x20);
	vsel(x32, x31, x29, a2);
	vsel(x33, x32, x28, a1);
	vxor(*out2, *out2, x33);
	vsel(x34, x5, x21, x22);
	vor(x35, a6, x16);
	vxor(x36, x35, x21);
	vsel(x37, x36, x34, a2);
	vor(x38, x10, x12);
	vxor(x39, x38, x34);
	vsel(x40, x12, x35, x21);
	vsel(x41, x40, x39, a2);
	vsel(x42, x41, x37, a1);
	vxor(*out4, *out4, x42);
}

MAYBE_INLINE static void s8(
	vtype a1,
	vtype a2,
	vtype a3,
	vtype a4,
	vtype a5,
	vtype a6,
	vtype *out1,
	vtype *out2,
	vtype *out3,
	vtype *out4
) {
	vtype x1, x2, x3, x4, x5, x6;
	vtype x7, x8, x9, x10, x11, x12;
	vtype x13, x14, x15, x16, x17, x18;
	vtype x19, x20, x21, x22, x23, x24;
	vtype x25, x26, x27, x28, x29, x30;
	vtype x31, x32, x33, x34, x35, x36;
	vtype x37, x38, x39, x40, x41;

	vxor(x1, a2, a4);
	vxor(x2, a3, x1);
	vsel(x3, x2, x1, a5);
	vnor(x4, a2, a3);
	vxor(x5, x4, x1);
	vsel(x6, a4, x1, x2);
	vsel(x7, x6, x5, a5);
	vsel(x8, x7, x3, a1);
	vsel(x9, x5, a4, x2);
	vxor(x10, a5, x9);
	vnor(x11, x7, x7);
	vsel(x12, x11, x10, a1);
	vsel(x13, x12, x8, a6);
	vxor(*out2, *out2, x13);
	vsel(x14, a5, x9, a4);
	vxor(x15, x5, x14);
	vxor(x16, x6, x14);
	vnor(x17, x15, x15);
	vsel(x18, x17, x16, a5);
	vsel(x19, x18, x15, a1);
	vsel(x20, x5, x17, x7);
	vor(x21, a5, a4);
	vxor(x22, x21, x3);
	vsel(x23, x22, x20, a1);
	vsel(x24, x23, x19, a6);
	vxor(*out3, *out3, x24);
	vandn(x25, a5, x5);
	vxor(x26, x25, x6);
	vxor(x27, x11, x20);
	vxor(x28, x27, x26);
	vsel(x29, x28, x26, a1);
	vsel(x30, a3, x22, x21);
	vandn(x31, a2, x21);
	vxor(x32, x31, x10);
	vsel(x33, x32, x30, a1);
	vsel(x34, x33, x29, a6);
	vxor(*out1, *out1, x34);
	vor(x35, x9, x21);
	vxor(x36, x35, x32);
	vsel(x37, x1, x36, x26);
	vandn(x38, x35, x37);
	vsel(x39, x38, x36, a1);
	vnor(x40, x29, x29);
	vsel(x41, x40, x39, a6);
	vxor(*out4, *out4, x41);
}
