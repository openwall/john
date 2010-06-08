/*
 * Generated S-box files.
 *
 * This software may be modified, redistributed, and used for any purpose,
 * so long as its origin is acknowledged.
 *
 * Produced by Matthew Kwan - May 1998
 *
 * Modified in John the Ripper to use a custom data type and cpp macros instead
 * of explicit C operators for bitwise ops.  This allows DES_bs_b.c to use
 * compiler intrinsics for SIMD bitwise ops.  The conversion was made using the
 * DES_vec.pl script.  No copyright to these minor changes is claimed.
 */


static void
s1 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42, x43, x44, x45, x46, x47, x48;
	vtype	x49, x50, x51, x52, x53, x54, x55, x56;

	vandn(x1, a3, a5);
	vxor(x2, x1, a4);
	vandn(x3, a3, a4);
	vor(x4, x3, a5);
	vand(x5, a6, x4);
	vxor(x6, x2, x5);
	vandn(x7, a4, a5);
	vxor(x8, a3, a4);
	vandn(x9, a6, x8);
	vxor(x10, x7, x9);
	vor(x11, a2, x10);
	vxor(x12, x6, x11);
	vxor(x13, a5, x5);
	vand(x14, x13, x8);
	vandn(x15, a5, a4);
	vxor(x16, x3, x14);
	vor(x17, a6, x16);
	vxor(x18, x15, x17);
	vor(x19, a2, x18);
	vxor(x20, x14, x19);
	vand(x21, a1, x20);
	vxorn(x22, x12, x21);
	vxor(*out2, *out2, x22);
	vor(x23, x1, x5);
	vxor(x24, x23, x8);
	vandn(x25, x18, x2);
	vandn(x26, a2, x25);
	vxor(x27, x24, x26);
	vor(x28, x6, x7);
	vxor(x29, x28, x25);
	vxor(x30, x9, x24);
	vandn(x31, x18, x30);
	vand(x32, a2, x31);
	vxor(x33, x29, x32);
	vand(x34, a1, x33);
	vxor(x35, x27, x34);
	vxor(*out4, *out4, x35);
	vand(x36, a3, x28);
	vandn(x37, x18, x36);
	vor(x38, a2, x3);
	vxor(x39, x37, x38);
	vor(x40, a3, x31);
	vandn(x41, x24, x37);
	vor(x42, x41, x3);
	vandn(x43, x42, a2);
	vxor(x44, x40, x43);
	vandn(x45, a1, x44);
	vxorn(x46, x39, x45);
	vxor(*out1, *out1, x46);
	vandn(x47, x33, x9);
	vxor(x48, x47, x39);
	vxor(x49, x4, x36);
	vandn(x50, x49, x5);
	vor(x51, x42, x18);
	vxor(x52, x51, a5);
	vandn(x53, a2, x52);
	vxor(x54, x50, x53);
	vor(x55, a1, x54);
	vxorn(x56, x48, x55);
	vxor(*out3, *out3, x56);
}


static void
s2 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42, x43, x44, x45, x46, x47, x48;
	vtype	x49, x50;

	vxor(x1, a1, a6);
	vxor(x2, x1, a5);
	vand(x3, a6, a5);
	vandn(x4, a1, x3);
	vandn(x5, a2, x4);
	vxor(x6, x2, x5);
	vor(x7, x3, x5);
	vandn(x8, x7, x1);
	vor(x9, a3, x8);
	vxor(x10, x6, x9);
	vandn(x11, a5, x4);
	vor(x12, x11, a2);
	vand(x13, a4, x12);
	vxorn(x14, x10, x13);
	vxor(*out1, *out1, x14);
	vxor(x15, x4, x14);
	vandn(x16, x15, a2);
	vxor(x17, x2, x16);
	vandn(x18, a6, x4);
	vxor(x19, x6, x11);
	vand(x20, a2, x19);
	vxor(x21, x18, x20);
	vand(x22, a3, x21);
	vxor(x23, x17, x22);
	vxor(x24, a5, a2);
	vandn(x25, x24, x8);
	vor(x26, x6, a1);
	vxor(x27, x26, a2);
	vandn(x28, a3, x27);
	vxor(x29, x25, x28);
	vor(x30, a4, x29);
	vxor(x31, x23, x30);
	vxor(*out3, *out3, x31);
	vor(x32, x18, x25);
	vxor(x33, x32, x10);
	vor(x34, x27, x20);
	vand(x35, a3, x34);
	vxor(x36, x33, x35);
	vand(x37, x24, x34);
	vandn(x38, x12, x37);
	vor(x39, a4, x38);
	vxorn(x40, x36, x39);
	vxor(*out4, *out4, x40);
	vxor(x41, a2, x2);
	vandn(x42, x41, x33);
	vxor(x43, x42, x29);
	vandn(x44, a3, x43);
	vxor(x45, x41, x44);
	vor(x46, x3, x20);
	vand(x47, a3, x3);
	vxor(x48, x46, x47);
	vandn(x49, a4, x48);
	vxorn(x50, x45, x49);
	vxor(*out2, *out2, x50);
}


static void
s3 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42, x43, x44, x45, x46, x47, x48;
	vtype	x49, x50, x51, x52, x53;

	vxor(x1, a2, a3);
	vxor(x2, x1, a6);
	vand(x3, a2, x2);
	vor(x4, a5, x3);
	vxor(x5, x2, x4);
	vxor(x6, a3, x3);
	vandn(x7, x6, a5);
	vor(x8, a1, x7);
	vxor(x9, x5, x8);
	vandn(x10, a6, x3);
	vxor(x11, x10, a5);
	vand(x12, a1, x11);
	vxor(x13, a5, x12);
	vor(x14, a4, x13);
	vxor(x15, x9, x14);
	vxor(*out4, *out4, x15);
	vand(x16, a3, a6);
	vor(x17, x16, x3);
	vxor(x18, x17, a5);
	vandn(x19, x2, x7);
	vxor(x20, x19, x16);
	vor(x21, a1, x20);
	vxor(x22, x18, x21);
	vor(x23, a2, x7);
	vxor(x24, x23, x4);
	vor(x25, x11, x19);
	vxor(x26, x25, x17);
	vor(x27, a1, x26);
	vxor(x28, x24, x27);
	vandn(x29, a4, x28);
	vxorn(x30, x22, x29);
	vxor(*out3, *out3, x30);
	vand(x31, a3, a5);
	vxor(x32, x31, x2);
	vandn(x33, x7, a3);
	vor(x34, a1, x33);
	vxor(x35, x32, x34);
	vor(x36, x10, x26);
	vxor(x37, a6, x17);
	vandn(x38, x37, x5);
	vand(x39, a1, x38);
	vxor(x40, x36, x39);
	vand(x41, a4, x40);
	vxor(x42, x35, x41);
	vxor(*out2, *out2, x42);
	vor(x43, a2, x19);
	vxor(x44, x43, x18);
	vand(x45, a6, x15);
	vxor(x46, x45, x6);
	vandn(x47, x46, a1);
	vxor(x48, x44, x47);
	vandn(x49, x42, x23);
	vor(x50, a1, x49);
	vxor(x51, x47, x50);
	vand(x52, a4, x51);
	vxorn(x53, x48, x52);
	vxor(*out1, *out1, x53);
}


static void
s4 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39;

	vor(x1, a1, a3);
	vand(x2, a5, x1);
	vxor(x3, a1, x2);
	vor(x4, a2, a3);
	vxor(x5, x3, x4);
	vandn(x6, a3, a1);
	vor(x7, x6, x3);
	vand(x8, a2, x7);
	vxor(x9, a5, x8);
	vand(x10, a4, x9);
	vxor(x11, x5, x10);
	vxor(x12, a3, x2);
	vandn(x13, a2, x12);
	vxor(x14, x7, x13);
	vor(x15, x12, x3);
	vxor(x16, a3, a5);
	vandn(x17, x16, a2);
	vxor(x18, x15, x17);
	vor(x19, a4, x18);
	vxor(x20, x14, x19);
	vor(x21, a6, x20);
	vxor(x22, x11, x21);
	vxor(*out1, *out1, x22);
	vand(x23, a6, x20);
	vxorn(x24, x23, x11);
	vxor(*out2, *out2, x24);
	vand(x25, a2, x9);
	vxor(x26, x25, x15);
	vxor(x27, a3, x8);
	vxor(x28, x27, x17);
	vandn(x29, a4, x28);
	vxor(x30, x26, x29);
	vxor(x31, x11, x30);
	vandn(x32, a2, x31);
	vxor(x33, x22, x32);
	vandn(x34, x31, a4);
	vxor(x35, x33, x34);
	vor(x36, a6, x35);
	vxorn(x37, x30, x36);
	vxor(*out3, *out3, x37);
	vxor(x38, x23, x35);
	vxor(x39, x38, x37);
	vxor(*out4, *out4, x39);
}


static void
s5 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42, x43, x44, x45, x46, x47, x48;
	vtype	x49, x50, x51, x52, x53, x54, x55, x56;

	vandn(x1, a3, a4);
	vxor(x2, x1, a1);
	vandn(x3, a1, a3);
	vor(x4, a6, x3);
	vxor(x5, x2, x4);
	vxor(x6, a4, a1);
	vor(x7, x6, x1);
	vandn(x8, x7, a6);
	vxor(x9, a3, x8);
	vor(x10, a5, x9);
	vxor(x11, x5, x10);
	vand(x12, a3, x7);
	vxor(x13, x12, a4);
	vandn(x14, x13, x3);
	vxor(x15, a4, x3);
	vor(x16, a6, x15);
	vxor(x17, x14, x16);
	vor(x18, a5, x17);
	vxor(x19, x13, x18);
	vandn(x20, x19, a2);
	vxor(x21, x11, x20);
	vxor(*out4, *out4, x21);
	vand(x22, a4, x4);
	vxor(x23, x22, x17);
	vxor(x24, a1, x9);
	vand(x25, x2, x24);
	vandn(x26, a5, x25);
	vxor(x27, x23, x26);
	vor(x28, a4, x24);
	vandn(x29, x28, a2);
	vxor(x30, x27, x29);
	vxor(*out2, *out2, x30);
	vand(x31, x17, x5);
	vandn(x32, x7, x31);
	vandn(x33, x8, a4);
	vxor(x34, x33, a3);
	vand(x35, a5, x34);
	vxor(x36, x32, x35);
	vor(x37, x13, x16);
	vxor(x38, x9, x31);
	vor(x39, a5, x38);
	vxor(x40, x37, x39);
	vor(x41, a2, x40);
	vxorn(x42, x36, x41);
	vxor(*out3, *out3, x42);
	vandn(x43, x19, x32);
	vxor(x44, x43, x24);
	vor(x45, x27, x43);
	vxor(x46, x45, x6);
	vandn(x47, a5, x46);
	vxor(x48, x44, x47);
	vand(x49, x6, x38);
	vxor(x50, x49, x34);
	vxor(x51, x21, x38);
	vandn(x52, x28, x51);
	vand(x53, a5, x52);
	vxor(x54, x50, x53);
	vor(x55, a2, x54);
	vxor(x56, x48, x55);
	vxor(*out1, *out1, x56);
}


static void
s6 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42, x43, x44, x45, x46, x47, x48;
	vtype	x49, x50, x51, x52, x53;

	vxor(x1, a5, a1);
	vxor(x2, x1, a6);
	vand(x3, a1, a6);
	vandn(x4, x3, a5);
	vandn(x5, a4, x4);
	vxor(x6, x2, x5);
	vxor(x7, a6, x3);
	vor(x8, x4, x7);
	vandn(x9, x8, a4);
	vxor(x10, x7, x9);
	vand(x11, a2, x10);
	vxor(x12, x6, x11);
	vor(x13, a6, x6);
	vandn(x14, x13, a5);
	vor(x15, x4, x10);
	vandn(x16, a2, x15);
	vxor(x17, x14, x16);
	vandn(x18, x17, a3);
	vxorn(x19, x12, x18);
	vxor(*out1, *out1, x19);
	vandn(x20, x19, x1);
	vxor(x21, x20, x15);
	vandn(x22, a6, x21);
	vxor(x23, x22, x6);
	vandn(x24, a2, x23);
	vxor(x25, x21, x24);
	vor(x26, a5, a6);
	vandn(x27, x26, x1);
	vandn(x28, a2, x24);
	vxor(x29, x27, x28);
	vandn(x30, a3, x29);
	vxorn(x31, x25, x30);
	vxor(*out4, *out4, x31);
	vxor(x32, x3, x6);
	vandn(x33, x32, x10);
	vxor(x34, a6, x25);
	vandn(x35, a5, x34);
	vandn(x36, a2, x35);
	vxor(x37, x33, x36);
	vandn(x38, x21, a5);
	vor(x39, a3, x38);
	vxorn(x40, x37, x39);
	vxor(*out3, *out3, x40);
	vor(x41, x35, x2);
	vand(x42, a5, x7);
	vandn(x43, a4, x42);
	vor(x44, a2, x43);
	vxor(x45, x41, x44);
	vor(x46, x23, x35);
	vxor(x47, x46, x5);
	vand(x48, x26, x33);
	vxor(x49, x48, x2);
	vand(x50, a2, x49);
	vxor(x51, x47, x50);
	vandn(x52, a3, x51);
	vxorn(x53, x45, x52);
	vxor(*out2, *out2, x53);
}


static void
s7 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42, x43, x44, x45, x46, x47, x48;
	vtype	x49, x50, x51;

	vand(x1, a2, a4);
	vxor(x2, x1, a5);
	vand(x3, a4, x2);
	vxor(x4, x3, a2);
	vandn(x5, a3, x4);
	vxor(x6, x2, x5);
	vxor(x7, a3, x5);
	vandn(x8, a6, x7);
	vxor(x9, x6, x8);
	vor(x10, a2, a4);
	vor(x11, x10, a5);
	vandn(x12, a5, a2);
	vor(x13, a3, x12);
	vxor(x14, x11, x13);
	vxor(x15, x3, x6);
	vor(x16, a6, x15);
	vxor(x17, x14, x16);
	vand(x18, a1, x17);
	vxor(x19, x9, x18);
	vxor(*out1, *out1, x19);
	vandn(x20, a4, a3);
	vandn(x21, a2, x20);
	vand(x22, a6, x21);
	vxor(x23, x9, x22);
	vxor(x24, a4, x4);
	vor(x25, a3, x3);
	vxor(x26, x24, x25);
	vxor(x27, a3, x3);
	vand(x28, x27, a2);
	vandn(x29, a6, x28);
	vxor(x30, x26, x29);
	vor(x31, a1, x30);
	vxorn(x32, x23, x31);
	vxor(*out2, *out2, x32);
	vxor(x33, x7, x30);
	vor(x34, a2, x24);
	vxor(x35, x34, x19);
	vandn(x36, x35, a6);
	vxor(x37, x33, x36);
	vandn(x38, x26, a3);
	vor(x39, x38, x30);
	vandn(x40, x39, a1);
	vxor(x41, x37, x40);
	vxor(*out3, *out3, x41);
	vor(x42, a5, x20);
	vxor(x43, x42, x33);
	vxor(x44, a2, x15);
	vandn(x45, x24, x44);
	vand(x46, a6, x45);
	vxor(x47, x43, x46);
	vand(x48, a3, x22);
	vxor(x49, x48, x46);
	vor(x50, a1, x49);
	vxor(x51, x47, x50);
	vxor(*out4, *out4, x51);
}


static void
s8 (
	vtype	a1,
	vtype	a2,
	vtype	a3,
	vtype	a4,
	vtype	a5,
	vtype	a6,
	vtype	*out1,
	vtype	*out2,
	vtype	*out3,
	vtype	*out4
) {
	vtype	x1, x2, x3, x4, x5, x6, x7, x8;
	vtype	x9, x10, x11, x12, x13, x14, x15, x16;
	vtype	x17, x18, x19, x20, x21, x22, x23, x24;
	vtype	x25, x26, x27, x28, x29, x30, x31, x32;
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42, x43, x44, x45, x46, x47, x48;
	vtype	x49, x50;

	vxor(x1, a3, a1);
	vandn(x2, a1, a3);
	vxor(x3, x2, a4);
	vor(x4, a5, x3);
	vxor(x5, x1, x4);
	vandn(x6, x5, a1);
	vxor(x7, x6, a3);
	vandn(x8, x7, a5);
	vxor(x9, a4, x8);
	vandn(x10, a2, x9);
	vxor(x11, x5, x10);
	vor(x12, x6, a4);
	vxor(x13, x12, x1);
	vxor(x14, x13, a5);
	vandn(x15, x3, x14);
	vxor(x16, x15, x7);
	vandn(x17, a2, x16);
	vxor(x18, x14, x17);
	vor(x19, a6, x18);
	vxorn(x20, x11, x19);
	vxor(*out1, *out1, x20);
	vor(x21, x5, a5);
	vxor(x22, x21, x3);
	vandn(x23, x11, a4);
	vandn(x24, a2, x23);
	vxor(x25, x22, x24);
	vand(x26, a1, x21);
	vand(x27, a5, x2);
	vxor(x28, x27, x23);
	vand(x29, a2, x28);
	vxor(x30, x26, x29);
	vandn(x31, x30, a6);
	vxor(x32, x25, x31);
	vxor(*out3, *out3, x32);
	vandn(x33, a3, x16);
	vor(x34, x9, x33);
	vor(x35, a2, x6);
	vxor(x36, x34, x35);
	vandn(x37, x2, x14);
	vor(x38, x22, x32);
	vandn(x39, a2, x38);
	vxor(x40, x37, x39);
	vor(x41, a6, x40);
	vxorn(x42, x36, x41);
	vxor(*out2, *out2, x42);
	vandn(x43, x1, a5);
	vor(x44, x43, a4);
	vxor(x45, a3, a5);
	vxor(x46, x45, x37);
	vandn(x47, x46, a2);
	vxor(x48, x44, x47);
	vand(x49, a6, x48);
	vxorn(x50, x11, x49);
	vxor(*out4, *out4, x50);
}
