/*
 * Generated S-box files.
 *
 * This software may be modified, redistributed, and used for any purpose,
 * so long as its origin is acknowledged.
 *
 * Produced by Matthew Kwan - March 1998
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
	vtype	x57, x58, x59, x60, x61, x62, x63;

	vnot(x1, a4);
	vnot(x2, a1);
	vxor(x3, a4, a3);
	vxor(x4, x3, x2);
	vor(x5, a3, x2);
	vand(x6, x5, x1);
	vor(x7, a6, x6);
	vxor(x8, x4, x7);
	vor(x9, x1, x2);
	vand(x10, a6, x9);
	vxor(x11, x7, x10);
	vor(x12, a2, x11);
	vxor(x13, x8, x12);
	vxor(x14, x9, x13);
	vor(x15, a6, x14);
	vxor(x16, x1, x15);
	vnot(x17, x14);
	vand(x18, x17, x3);
	vor(x19, a2, x18);
	vxor(x20, x16, x19);
	vor(x21, a5, x20);
	vxor(x22, x13, x21);
	vxor(*out4, *out4, x22);
	vor(x23, a3, x4);
	vnot(x24, x23);
	vor(x25, a6, x24);
	vxor(x26, x6, x25);
	vand(x27, x1, x8);
	vor(x28, a2, x27);
	vxor(x29, x26, x28);
	vor(x30, x1, x8);
	vxor(x31, x30, x6);
	vand(x32, x5, x14);
	vxor(x33, x32, x8);
	vand(x34, a2, x33);
	vxor(x35, x31, x34);
	vor(x36, a5, x35);
	vxor(x37, x29, x36);
	vxor(*out1, *out1, x37);
	vand(x38, a3, x10);
	vor(x39, x38, x4);
	vand(x40, a3, x33);
	vxor(x41, x40, x25);
	vor(x42, a2, x41);
	vxor(x43, x39, x42);
	vor(x44, a3, x26);
	vxor(x45, x44, x14);
	vor(x46, a1, x8);
	vxor(x47, x46, x20);
	vor(x48, a2, x47);
	vxor(x49, x45, x48);
	vand(x50, a5, x49);
	vxor(x51, x43, x50);
	vxor(*out2, *out2, x51);
	vxor(x52, x8, x40);
	vxor(x53, a3, x11);
	vand(x54, x53, x5);
	vor(x55, a2, x54);
	vxor(x56, x52, x55);
	vor(x57, a6, x4);
	vxor(x58, x57, x38);
	vand(x59, x13, x56);
	vand(x60, a2, x59);
	vxor(x61, x58, x60);
	vand(x62, a5, x61);
	vxor(x63, x56, x62);
	vxor(*out3, *out3, x63);
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
	vtype	x49, x50, x51, x52, x53, x54, x55, x56;

	vnot(x1, a5);
	vnot(x2, a1);
	vxor(x3, a5, a6);
	vxor(x4, x3, x2);
	vxor(x5, x4, a2);
	vor(x6, a6, x1);
	vor(x7, x6, x2);
	vand(x8, a2, x7);
	vxor(x9, a6, x8);
	vand(x10, a3, x9);
	vxor(x11, x5, x10);
	vand(x12, a2, x9);
	vxor(x13, a5, x6);
	vor(x14, a3, x13);
	vxor(x15, x12, x14);
	vand(x16, a4, x15);
	vxor(x17, x11, x16);
	vxor(*out2, *out2, x17);
	vor(x18, a5, a1);
	vor(x19, a6, x18);
	vxor(x20, x13, x19);
	vxor(x21, x20, a2);
	vor(x22, a6, x4);
	vand(x23, x22, x17);
	vor(x24, a3, x23);
	vxor(x25, x21, x24);
	vor(x26, a6, x2);
	vand(x27, a5, x2);
	vor(x28, a2, x27);
	vxor(x29, x26, x28);
	vxor(x30, x3, x27);
	vxor(x31, x2, x19);
	vand(x32, a2, x31);
	vxor(x33, x30, x32);
	vand(x34, a3, x33);
	vxor(x35, x29, x34);
	vor(x36, a4, x35);
	vxor(x37, x25, x36);
	vxor(*out3, *out3, x37);
	vand(x38, x21, x32);
	vxor(x39, x38, x5);
	vor(x40, a1, x15);
	vxor(x41, x40, x13);
	vor(x42, a3, x41);
	vxor(x43, x39, x42);
	vor(x44, x28, x41);
	vand(x45, a4, x44);
	vxor(x46, x43, x45);
	vxor(*out1, *out1, x46);
	vand(x47, x19, x21);
	vxor(x48, x47, x26);
	vand(x49, a2, x33);
	vxor(x50, x49, x21);
	vand(x51, a3, x50);
	vxor(x52, x48, x51);
	vand(x53, x18, x28);
	vand(x54, x53, x50);
	vor(x55, a4, x54);
	vxor(x56, x52, x55);
	vxor(*out4, *out4, x56);
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
	vtype	x49, x50, x51, x52, x53, x54, x55, x56;
	vtype	x57;

	vnot(x1, a5);
	vnot(x2, a6);
	vand(x3, a5, a3);
	vxor(x4, x3, a6);
	vand(x5, a4, x1);
	vxor(x6, x4, x5);
	vxor(x7, x6, a2);
	vand(x8, a3, x1);
	vxor(x9, a5, x2);
	vor(x10, a4, x9);
	vxor(x11, x8, x10);
	vand(x12, x7, x11);
	vxor(x13, a5, x11);
	vor(x14, x13, x7);
	vand(x15, a4, x14);
	vxor(x16, x12, x15);
	vand(x17, a2, x16);
	vxor(x18, x11, x17);
	vand(x19, a1, x18);
	vxor(x20, x7, x19);
	vxor(*out4, *out4, x20);
	vxor(x21, a3, a4);
	vxor(x22, x21, x9);
	vor(x23, x2, x4);
	vxor(x24, x23, x8);
	vor(x25, a2, x24);
	vxor(x26, x22, x25);
	vxor(x27, a6, x23);
	vor(x28, x27, a4);
	vxor(x29, a3, x15);
	vor(x30, x29, x5);
	vor(x31, a2, x30);
	vxor(x32, x28, x31);
	vor(x33, a1, x32);
	vxor(x34, x26, x33);
	vxor(*out1, *out1, x34);
	vxor(x35, a3, x9);
	vor(x36, x35, x5);
	vor(x37, x4, x29);
	vxor(x38, x37, a4);
	vor(x39, a2, x38);
	vxor(x40, x36, x39);
	vand(x41, a6, x11);
	vor(x42, x41, x6);
	vxor(x43, x34, x38);
	vxor(x44, x43, x41);
	vand(x45, a2, x44);
	vxor(x46, x42, x45);
	vor(x47, a1, x46);
	vxor(x48, x40, x47);
	vxor(*out3, *out3, x48);
	vor(x49, x2, x38);
	vxor(x50, x49, x13);
	vxor(x51, x27, x28);
	vor(x52, a2, x51);
	vxor(x53, x50, x52);
	vand(x54, x12, x23);
	vand(x55, x54, x52);
	vor(x56, a1, x55);
	vxor(x57, x53, x56);
	vxor(*out2, *out2, x57);
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
	vtype	x33, x34, x35, x36, x37, x38, x39, x40;
	vtype	x41, x42;

	vnot(x1, a1);
	vnot(x2, a3);
	vor(x3, a1, a3);
	vand(x4, a5, x3);
	vxor(x5, x1, x4);
	vor(x6, a2, a3);
	vxor(x7, x5, x6);
	vand(x8, a1, a5);
	vxor(x9, x8, x3);
	vand(x10, a2, x9);
	vxor(x11, a5, x10);
	vand(x12, a4, x11);
	vxor(x13, x7, x12);
	vxor(x14, x2, x4);
	vand(x15, a2, x14);
	vxor(x16, x9, x15);
	vand(x17, x5, x14);
	vxor(x18, a5, x2);
	vor(x19, a2, x18);
	vxor(x20, x17, x19);
	vor(x21, a4, x20);
	vxor(x22, x16, x21);
	vand(x23, a6, x22);
	vxor(x24, x13, x23);
	vxor(*out2, *out2, x24);
	vnot(x25, x13);
	vor(x26, a6, x22);
	vxor(x27, x25, x26);
	vxor(*out1, *out1, x27);
	vand(x28, a2, x11);
	vxor(x29, x28, x17);
	vxor(x30, a3, x10);
	vxor(x31, x30, x19);
	vand(x32, a4, x31);
	vxor(x33, x29, x32);
	vxor(x34, x25, x33);
	vand(x35, a2, x34);
	vxor(x36, x24, x35);
	vor(x37, a4, x34);
	vxor(x38, x36, x37);
	vand(x39, a6, x38);
	vxor(x40, x33, x39);
	vxor(*out4, *out4, x40);
	vxor(x41, x26, x38);
	vxor(x42, x41, x40);
	vxor(*out3, *out3, x42);
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
	vtype	x57, x58, x59, x60, x61, x62;

	vnot(x1, a6);
	vnot(x2, a3);
	vor(x3, x1, x2);
	vxor(x4, x3, a4);
	vand(x5, a1, x3);
	vxor(x6, x4, x5);
	vor(x7, a6, a4);
	vxor(x8, x7, a3);
	vor(x9, a3, x7);
	vor(x10, a1, x9);
	vxor(x11, x8, x10);
	vand(x12, a5, x11);
	vxor(x13, x6, x12);
	vnot(x14, x4);
	vand(x15, x14, a6);
	vor(x16, a1, x15);
	vxor(x17, x8, x16);
	vor(x18, a5, x17);
	vxor(x19, x10, x18);
	vor(x20, a2, x19);
	vxor(x21, x13, x20);
	vxor(*out3, *out3, x21);
	vor(x22, x2, x15);
	vxor(x23, x22, a6);
	vxor(x24, a4, x22);
	vand(x25, a1, x24);
	vxor(x26, x23, x25);
	vxor(x27, a1, x11);
	vand(x28, x27, x22);
	vor(x29, a5, x28);
	vxor(x30, x26, x29);
	vor(x31, a4, x27);
	vnot(x32, x31);
	vor(x33, a2, x32);
	vxor(x34, x30, x33);
	vxor(*out2, *out2, x34);
	vxor(x35, x2, x15);
	vand(x36, a1, x35);
	vxor(x37, x14, x36);
	vxor(x38, x5, x7);
	vand(x39, x38, x34);
	vor(x40, a5, x39);
	vxor(x41, x37, x40);
	vxor(x42, x2, x5);
	vand(x43, x42, x16);
	vand(x44, x4, x27);
	vand(x45, a5, x44);
	vxor(x46, x43, x45);
	vor(x47, a2, x46);
	vxor(x48, x41, x47);
	vxor(*out1, *out1, x48);
	vand(x49, x24, x48);
	vxor(x50, x49, x5);
	vxor(x51, x11, x30);
	vor(x52, x51, x50);
	vand(x53, a5, x52);
	vxor(x54, x50, x53);
	vxor(x55, x14, x19);
	vxor(x56, x55, x34);
	vxor(x57, x4, x16);
	vand(x58, x57, x30);
	vand(x59, a5, x58);
	vxor(x60, x56, x59);
	vor(x61, a2, x60);
	vxor(x62, x54, x61);
	vxor(*out4, *out4, x62);
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
	vtype	x49, x50, x51, x52, x53, x54, x55, x56;
	vtype	x57;

	vnot(x1, a2);
	vnot(x2, a5);
	vxor(x3, a2, a6);
	vxor(x4, x3, x2);
	vxor(x5, x4, a1);
	vand(x6, a5, a6);
	vor(x7, x6, x1);
	vand(x8, a5, x5);
	vand(x9, a1, x8);
	vxor(x10, x7, x9);
	vand(x11, a4, x10);
	vxor(x12, x5, x11);
	vxor(x13, a6, x10);
	vand(x14, x13, a1);
	vand(x15, a2, a6);
	vxor(x16, x15, a5);
	vand(x17, a1, x16);
	vxor(x18, x2, x17);
	vor(x19, a4, x18);
	vxor(x20, x14, x19);
	vand(x21, a3, x20);
	vxor(x22, x12, x21);
	vxor(*out2, *out2, x22);
	vxor(x23, a6, x18);
	vand(x24, a1, x23);
	vxor(x25, a5, x24);
	vxor(x26, a2, x17);
	vor(x27, x26, x6);
	vand(x28, a4, x27);
	vxor(x29, x25, x28);
	vnot(x30, x26);
	vor(x31, a6, x29);
	vnot(x32, x31);
	vand(x33, a4, x32);
	vxor(x34, x30, x33);
	vand(x35, a3, x34);
	vxor(x36, x29, x35);
	vxor(*out4, *out4, x36);
	vxor(x37, x6, x34);
	vand(x38, a5, x23);
	vxor(x39, x38, x5);
	vor(x40, a4, x39);
	vxor(x41, x37, x40);
	vor(x42, x16, x24);
	vxor(x43, x42, x1);
	vxor(x44, x15, x24);
	vxor(x45, x44, x31);
	vor(x46, a4, x45);
	vxor(x47, x43, x46);
	vor(x48, a3, x47);
	vxor(x49, x41, x48);
	vxor(*out1, *out1, x49);
	vor(x50, x5, x38);
	vxor(x51, x50, x6);
	vand(x52, x8, x31);
	vor(x53, a4, x52);
	vxor(x54, x51, x53);
	vand(x55, x30, x43);
	vor(x56, a3, x55);
	vxor(x57, x54, x56);
	vxor(*out3, *out3, x57);
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
	vtype	x49, x50, x51, x52, x53, x54, x55, x56;
	vtype	x57;

	vnot(x1, a2);
	vnot(x2, a5);
	vand(x3, a2, a4);
	vxor(x4, x3, a5);
	vxor(x5, x4, a3);
	vand(x6, a4, x4);
	vxor(x7, x6, a2);
	vand(x8, a3, x7);
	vxor(x9, a1, x8);
	vor(x10, a6, x9);
	vxor(x11, x5, x10);
	vand(x12, a4, x2);
	vor(x13, x12, a2);
	vor(x14, a2, x2);
	vand(x15, a3, x14);
	vxor(x16, x13, x15);
	vxor(x17, x6, x11);
	vor(x18, a6, x17);
	vxor(x19, x16, x18);
	vand(x20, a1, x19);
	vxor(x21, x11, x20);
	vxor(*out1, *out1, x21);
	vor(x22, a2, x21);
	vxor(x23, x22, x6);
	vxor(x24, x23, x15);
	vxor(x25, x5, x6);
	vor(x26, x25, x12);
	vor(x27, a6, x26);
	vxor(x28, x24, x27);
	vand(x29, x1, x19);
	vand(x30, x23, x26);
	vand(x31, a6, x30);
	vxor(x32, x29, x31);
	vor(x33, a1, x32);
	vxor(x34, x28, x33);
	vxor(*out4, *out4, x34);
	vand(x35, a4, x16);
	vor(x36, x35, x1);
	vand(x37, a6, x36);
	vxor(x38, x11, x37);
	vand(x39, a4, x13);
	vor(x40, a3, x7);
	vxor(x41, x39, x40);
	vor(x42, x1, x24);
	vor(x43, a6, x42);
	vxor(x44, x41, x43);
	vor(x45, a1, x44);
	vxor(x46, x38, x45);
	vxor(*out2, *out2, x46);
	vxor(x47, x8, x44);
	vxor(x48, x6, x15);
	vor(x49, a6, x48);
	vxor(x50, x47, x49);
	vxor(x51, x19, x44);
	vxor(x52, a4, x25);
	vand(x53, x52, x46);
	vand(x54, a6, x53);
	vxor(x55, x51, x54);
	vor(x56, a1, x55);
	vxor(x57, x50, x56);
	vxor(*out3, *out3, x57);
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
	vtype	x49, x50, x51, x52, x53, x54;

	vnot(x1, a1);
	vnot(x2, a4);
	vxor(x3, a3, x1);
	vor(x4, a3, x1);
	vxor(x5, x4, x2);
	vor(x6, a5, x5);
	vxor(x7, x3, x6);
	vor(x8, x1, x5);
	vxor(x9, x2, x8);
	vand(x10, a5, x9);
	vxor(x11, x8, x10);
	vand(x12, a2, x11);
	vxor(x13, x7, x12);
	vxor(x14, x6, x9);
	vand(x15, x3, x9);
	vand(x16, a5, x8);
	vxor(x17, x15, x16);
	vor(x18, a2, x17);
	vxor(x19, x14, x18);
	vor(x20, a6, x19);
	vxor(x21, x13, x20);
	vxor(*out1, *out1, x21);
	vor(x22, a5, x3);
	vand(x23, x22, x2);
	vnot(x24, a3);
	vand(x25, x24, x8);
	vand(x26, a5, x4);
	vxor(x27, x25, x26);
	vor(x28, a2, x27);
	vxor(x29, x23, x28);
	vand(x30, a6, x29);
	vxor(x31, x13, x30);
	vxor(*out4, *out4, x31);
	vxor(x32, x5, x6);
	vxor(x33, x32, x22);
	vor(x34, a4, x13);
	vand(x35, a2, x34);
	vxor(x36, x33, x35);
	vand(x37, a1, x33);
	vxor(x38, x37, x8);
	vxor(x39, a1, x23);
	vand(x40, x39, x7);
	vand(x41, a2, x40);
	vxor(x42, x38, x41);
	vor(x43, a6, x42);
	vxor(x44, x36, x43);
	vxor(*out3, *out3, x44);
	vxor(x45, a1, x10);
	vxor(x46, x45, x22);
	vnot(x47, x7);
	vand(x48, x47, x8);
	vor(x49, a2, x48);
	vxor(x50, x46, x49);
	vxor(x51, x19, x29);
	vor(x52, x51, x38);
	vand(x53, a6, x52);
	vxor(x54, x50, x53);
	vxor(*out2, *out2, x54);
}
