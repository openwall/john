/*
 * Generated S-box files.
 *
 * Produced by Matthew Kwan - May 1998
 */


static void
s1 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42, x43, x44, x45, x46, x47, x48;
	unsigned long	x49, x50, x51, x52, x53, x54, x55, x56;

	x1 = a3 & ~a5;
	x2 = x1 ^ a4;
	x3 = a3 & ~a4;
	x4 = x3 | a5;
	x5 = a6 & x4;
	x6 = x2 ^ x5;
	x7 = a4 & ~a5;
	x8 = a3 ^ a4;
	x9 = a6 & ~x8;
	x10 = x7 ^ x9;
	x11 = a2 | x10;
	x12 = x6 ^ x11;
	x13 = a5 ^ x5;
	x14 = x13 & x8;
	x15 = a5 & ~a4;
	x16 = x3 ^ x14;
	x17 = a6 | x16;
	x18 = x15 ^ x17;
	x19 = a2 | x18;
	x20 = x14 ^ x19;
	x21 = a1 & x20;
	x22 = x12 ^ ~x21;
	*out2 ^= x22;
	x23 = x1 | x5;
	x24 = x23 ^ x8;
	x25 = x18 & ~x2;
	x26 = a2 & ~x25;
	x27 = x24 ^ x26;
	x28 = x6 | x7;
	x29 = x28 ^ x25;
	x30 = x9 ^ x24;
	x31 = x18 & ~x30;
	x32 = a2 & x31;
	x33 = x29 ^ x32;
	x34 = a1 & x33;
	x35 = x27 ^ x34;
	*out4 ^= x35;
	x36 = a3 & x28;
	x37 = x18 & ~x36;
	x38 = a2 | x3;
	x39 = x37 ^ x38;
	x40 = a3 | x31;
	x41 = x24 & ~x37;
	x42 = x41 | x3;
	x43 = x42 & ~a2;
	x44 = x40 ^ x43;
	x45 = a1 & ~x44;
	x46 = x39 ^ ~x45;
	*out1 ^= x46;
	x47 = x33 & ~x9;
	x48 = x47 ^ x39;
	x49 = x4 ^ x36;
	x50 = x49 & ~x5;
	x51 = x42 | x18;
	x52 = x51 ^ a5;
	x53 = a2 & ~x52;
	x54 = x50 ^ x53;
	x55 = a1 | x54;
	x56 = x48 ^ ~x55;
	*out3 ^= x56;
}


static void
s2 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42, x43, x44, x45, x46, x47, x48;
	unsigned long	x49, x50;

	x1 = a1 ^ a6;
	x2 = x1 ^ a5;
	x3 = a6 & a5;
	x4 = a1 & ~x3;
	x5 = a2 & ~x4;
	x6 = x2 ^ x5;
	x7 = x3 | x5;
	x8 = x7 & ~x1;
	x9 = a3 | x8;
	x10 = x6 ^ x9;
	x11 = a5 & ~x4;
	x12 = x11 | a2;
	x13 = a4 & x12;
	x14 = x10 ^ ~x13;
	*out1 ^= x14;
	x15 = x4 ^ x14;
	x16 = x15 & ~a2;
	x17 = x2 ^ x16;
	x18 = a6 & ~x4;
	x19 = x6 ^ x11;
	x20 = a2 & x19;
	x21 = x18 ^ x20;
	x22 = a3 & x21;
	x23 = x17 ^ x22;
	x24 = a5 ^ a2;
	x25 = x24 & ~x8;
	x26 = x6 | a1;
	x27 = x26 ^ a2;
	x28 = a3 & ~x27;
	x29 = x25 ^ x28;
	x30 = a4 | x29;
	x31 = x23 ^ x30;
	*out3 ^= x31;
	x32 = x18 | x25;
	x33 = x32 ^ x10;
	x34 = x27 | x20;
	x35 = a3 & x34;
	x36 = x33 ^ x35;
	x37 = x24 & x34;
	x38 = x12 & ~x37;
	x39 = a4 | x38;
	x40 = x36 ^ ~x39;
	*out4 ^= x40;
	x41 = a2 ^ x2;
	x42 = x41 & ~x33;
	x43 = x42 ^ x29;
	x44 = a3 & ~x43;
	x45 = x41 ^ x44;
	x46 = x3 | x20;
	x47 = a3 & x3;
	x48 = x46 ^ x47;
	x49 = a4 & ~x48;
	x50 = x45 ^ ~x49;
	*out2 ^= x50;
}


static void
s3 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42, x43, x44, x45, x46, x47, x48;
	unsigned long	x49, x50, x51, x52, x53;

	x1 = a2 ^ a3;
	x2 = x1 ^ a6;
	x3 = a2 & x2;
	x4 = a5 | x3;
	x5 = x2 ^ x4;
	x6 = a3 ^ x3;
	x7 = x6 & ~a5;
	x8 = a1 | x7;
	x9 = x5 ^ x8;
	x10 = a6 & ~x3;
	x11 = x10 ^ a5;
	x12 = a1 & x11;
	x13 = a5 ^ x12;
	x14 = a4 | x13;
	x15 = x9 ^ x14;
	*out4 ^= x15;
	x16 = a3 & a6;
	x17 = x16 | x3;
	x18 = x17 ^ a5;
	x19 = x2 & ~x7;
	x20 = x19 ^ x16;
	x21 = a1 | x20;
	x22 = x18 ^ x21;
	x23 = a2 | x7;
	x24 = x23 ^ x4;
	x25 = x11 | x19;
	x26 = x25 ^ x17;
	x27 = a1 | x26;
	x28 = x24 ^ x27;
	x29 = a4 & ~x28;
	x30 = x22 ^ ~x29;
	*out3 ^= x30;
	x31 = a3 & a5;
	x32 = x31 ^ x2;
	x33 = x7 & ~a3;
	x34 = a1 | x33;
	x35 = x32 ^ x34;
	x36 = x10 | x26;
	x37 = a6 ^ x17;
	x38 = x37 & ~x5;
	x39 = a1 & x38;
	x40 = x36 ^ x39;
	x41 = a4 & x40;
	x42 = x35 ^ x41;
	*out2 ^= x42;
	x43 = a2 | x19;
	x44 = x43 ^ x18;
	x45 = a6 & x15;
	x46 = x45 ^ x6;
	x47 = x46 & ~a1;
	x48 = x44 ^ x47;
	x49 = x42 & ~x23;
	x50 = a1 | x49;
	x51 = x47 ^ x50;
	x52 = a4 & x51;
	x53 = x48 ^ ~x52;
	*out1 ^= x53;
}


static void
s4 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39;

	x1 = a1 | a3;
	x2 = a5 & x1;
	x3 = a1 ^ x2;
	x4 = a2 | a3;
	x5 = x3 ^ x4;
	x6 = a3 & ~a1;
	x7 = x6 | x3;
	x8 = a2 & x7;
	x9 = a5 ^ x8;
	x10 = a4 & x9;
	x11 = x5 ^ x10;
	x12 = a3 ^ x2;
	x13 = a2 & ~x12;
	x14 = x7 ^ x13;
	x15 = x12 | x3;
	x16 = a3 ^ a5;
	x17 = x16 & ~a2;
	x18 = x15 ^ x17;
	x19 = a4 | x18;
	x20 = x14 ^ x19;
	x21 = a6 | x20;
	x22 = x11 ^ x21;
	*out1 ^= x22;
	x23 = a6 & x20;
	x24 = x23 ^ ~x11;
	*out2 ^= x24;
	x25 = a2 & x9;
	x26 = x25 ^ x15;
	x27 = a3 ^ x8;
	x28 = x27 ^ x17;
	x29 = a4 & ~x28;
	x30 = x26 ^ x29;
	x31 = x11 ^ x30;
	x32 = a2 & ~x31;
	x33 = x22 ^ x32;
	x34 = x31 & ~a4;
	x35 = x33 ^ x34;
	x36 = a6 | x35;
	x37 = x30 ^ ~x36;
	*out3 ^= x37;
	x38 = x23 ^ x35;
	x39 = x38 ^ x37;
	*out4 ^= x39;
}


static void
s5 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42, x43, x44, x45, x46, x47, x48;
	unsigned long	x49, x50, x51, x52, x53, x54, x55, x56;

	x1 = a3 & ~a4;
	x2 = x1 ^ a1;
	x3 = a1 & ~a3;
	x4 = a6 | x3;
	x5 = x2 ^ x4;
	x6 = a4 ^ a1;
	x7 = x6 | x1;
	x8 = x7 & ~a6;
	x9 = a3 ^ x8;
	x10 = a5 | x9;
	x11 = x5 ^ x10;
	x12 = a3 & x7;
	x13 = x12 ^ a4;
	x14 = x13 & ~x3;
	x15 = a4 ^ x3;
	x16 = a6 | x15;
	x17 = x14 ^ x16;
	x18 = a5 | x17;
	x19 = x13 ^ x18;
	x20 = x19 & ~a2;
	x21 = x11 ^ x20;
	*out4 ^= x21;
	x22 = a4 & x4;
	x23 = x22 ^ x17;
	x24 = a1 ^ x9;
	x25 = x2 & x24;
	x26 = a5 & ~x25;
	x27 = x23 ^ x26;
	x28 = a4 | x24;
	x29 = x28 & ~a2;
	x30 = x27 ^ x29;
	*out2 ^= x30;
	x31 = x17 & x5;
	x32 = x7 & ~x31;
	x33 = x8 & ~a4;
	x34 = x33 ^ a3;
	x35 = a5 & x34;
	x36 = x32 ^ x35;
	x37 = x13 | x16;
	x38 = x9 ^ x31;
	x39 = a5 | x38;
	x40 = x37 ^ x39;
	x41 = a2 | x40;
	x42 = x36 ^ ~x41;
	*out3 ^= x42;
	x43 = x19 & ~x32;
	x44 = x43 ^ x24;
	x45 = x27 | x43;
	x46 = x45 ^ x6;
	x47 = a5 & ~x46;
	x48 = x44 ^ x47;
	x49 = x6 & x38;
	x50 = x49 ^ x34;
	x51 = x21 ^ x38;
	x52 = x28 & ~x51;
	x53 = a5 & x52;
	x54 = x50 ^ x53;
	x55 = a2 | x54;
	x56 = x48 ^ x55;
	*out1 ^= x56;
}


static void
s6 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42, x43, x44, x45, x46, x47, x48;
	unsigned long	x49, x50, x51, x52, x53;

	x1 = a5 ^ a1;
	x2 = x1 ^ a6;
	x3 = a1 & a6;
	x4 = x3 & ~a5;
	x5 = a4 & ~x4;
	x6 = x2 ^ x5;
	x7 = a6 ^ x3;
	x8 = x4 | x7;
	x9 = x8 & ~a4;
	x10 = x7 ^ x9;
	x11 = a2 & x10;
	x12 = x6 ^ x11;
	x13 = a6 | x6;
	x14 = x13 & ~a5;
	x15 = x4 | x10;
	x16 = a2 & ~x15;
	x17 = x14 ^ x16;
	x18 = x17 & ~a3;
	x19 = x12 ^ ~x18;
	*out1 ^= x19;
	x20 = x19 & ~x1;
	x21 = x20 ^ x15;
	x22 = a6 & ~x21;
	x23 = x22 ^ x6;
	x24 = a2 & ~x23;
	x25 = x21 ^ x24;
	x26 = a5 | a6;
	x27 = x26 & ~x1;
	x28 = a2 & ~x24;
	x29 = x27 ^ x28;
	x30 = a3 & ~x29;
	x31 = x25 ^ ~x30;
	*out4 ^= x31;
	x32 = x3 ^ x6;
	x33 = x32 & ~x10;
	x34 = a6 ^ x25;
	x35 = a5 & ~x34;
	x36 = a2 & ~x35;
	x37 = x33 ^ x36;
	x38 = x21 & ~a5;
	x39 = a3 | x38;
	x40 = x37 ^ ~x39;
	*out3 ^= x40;
	x41 = x35 | x2;
	x42 = a5 & x7;
	x43 = a4 & ~x42;
	x44 = a2 | x43;
	x45 = x41 ^ x44;
	x46 = x23 | x35;
	x47 = x46 ^ x5;
	x48 = x26 & x33;
	x49 = x48 ^ x2;
	x50 = a2 & x49;
	x51 = x47 ^ x50;
	x52 = a3 & ~x51;
	x53 = x45 ^ ~x52;
	*out2 ^= x53;
}


static void
s7 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42, x43, x44, x45, x46, x47, x48;
	unsigned long	x49, x50, x51;

	x1 = a2 & a4;
	x2 = x1 ^ a5;
	x3 = a4 & x2;
	x4 = x3 ^ a2;
	x5 = a3 & ~x4;
	x6 = x2 ^ x5;
	x7 = a3 ^ x5;
	x8 = a6 & ~x7;
	x9 = x6 ^ x8;
	x10 = a2 | a4;
	x11 = x10 | a5;
	x12 = a5 & ~a2;
	x13 = a3 | x12;
	x14 = x11 ^ x13;
	x15 = x3 ^ x6;
	x16 = a6 | x15;
	x17 = x14 ^ x16;
	x18 = a1 & x17;
	x19 = x9 ^ x18;
	*out1 ^= x19;
	x20 = a4 & ~a3;
	x21 = a2 & ~x20;
	x22 = a6 & x21;
	x23 = x9 ^ x22;
	x24 = a4 ^ x4;
	x25 = a3 | x3;
	x26 = x24 ^ x25;
	x27 = a3 ^ x3;
	x28 = x27 & a2;
	x29 = a6 & ~x28;
	x30 = x26 ^ x29;
	x31 = a1 | x30;
	x32 = x23 ^ ~x31;
	*out2 ^= x32;
	x33 = x7 ^ x30;
	x34 = a2 | x24;
	x35 = x34 ^ x19;
	x36 = x35 & ~a6;
	x37 = x33 ^ x36;
	x38 = x26 & ~a3;
	x39 = x38 | x30;
	x40 = x39 & ~a1;
	x41 = x37 ^ x40;
	*out3 ^= x41;
	x42 = a5 | x20;
	x43 = x42 ^ x33;
	x44 = a2 ^ x15;
	x45 = x24 & ~x44;
	x46 = a6 & x45;
	x47 = x43 ^ x46;
	x48 = a3 & x22;
	x49 = x48 ^ x46;
	x50 = a1 | x49;
	x51 = x47 ^ x50;
	*out4 ^= x51;
}


static void
s8 (
	unsigned long	a1,
	unsigned long	a2,
	unsigned long	a3,
	unsigned long	a4,
	unsigned long	a5,
	unsigned long	a6,
	unsigned long	*out1,
	unsigned long	*out2,
	unsigned long	*out3,
	unsigned long	*out4
) {
	unsigned long	x1, x2, x3, x4, x5, x6, x7, x8;
	unsigned long	x9, x10, x11, x12, x13, x14, x15, x16;
	unsigned long	x17, x18, x19, x20, x21, x22, x23, x24;
	unsigned long	x25, x26, x27, x28, x29, x30, x31, x32;
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42, x43, x44, x45, x46, x47, x48;
	unsigned long	x49, x50;

	x1 = a3 ^ a1;
	x2 = a1 & ~a3;
	x3 = x2 ^ a4;
	x4 = a5 | x3;
	x5 = x1 ^ x4;
	x6 = x5 & ~a1;
	x7 = x6 ^ a3;
	x8 = x7 & ~a5;
	x9 = a4 ^ x8;
	x10 = a2 & ~x9;
	x11 = x5 ^ x10;
	x12 = x6 | a4;
	x13 = x12 ^ x1;
	x14 = x13 ^ a5;
	x15 = x3 & ~x14;
	x16 = x15 ^ x7;
	x17 = a2 & ~x16;
	x18 = x14 ^ x17;
	x19 = a6 | x18;
	x20 = x11 ^ ~x19;
	*out1 ^= x20;
	x21 = x5 | a5;
	x22 = x21 ^ x3;
	x23 = x11 & ~a4;
	x24 = a2 & ~x23;
	x25 = x22 ^ x24;
	x26 = a1 & x21;
	x27 = a5 & x2;
	x28 = x27 ^ x23;
	x29 = a2 & x28;
	x30 = x26 ^ x29;
	x31 = x30 & ~a6;
	x32 = x25 ^ x31;
	*out3 ^= x32;
	x33 = a3 & ~x16;
	x34 = x9 | x33;
	x35 = a2 | x6;
	x36 = x34 ^ x35;
	x37 = x2 & ~x14;
	x38 = x22 | x32;
	x39 = a2 & ~x38;
	x40 = x37 ^ x39;
	x41 = a6 | x40;
	x42 = x36 ^ ~x41;
	*out2 ^= x42;
	x43 = x1 & ~a5;
	x44 = x43 | a4;
	x45 = a3 ^ a5;
	x46 = x45 ^ x37;
	x47 = x46 & ~a2;
	x48 = x44 ^ x47;
	x49 = a6 & x48;
	x50 = x11 ^ ~x49;
	*out4 ^= x50;
}
