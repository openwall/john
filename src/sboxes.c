/*
 * Generated S-box files.
 *
 * Produced by Matthew Kwan - March 1998
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
	unsigned long	x57, x58, x59, x60, x61, x62, x63;

	x1 = ~a4;
	x2 = ~a1;
	x3 = a4 ^ a3;
	x4 = x3 ^ x2;
	x5 = a3 | x2;
	x6 = x5 & x1;
	x7 = a6 | x6;
	x8 = x4 ^ x7;
	x9 = x1 | x2;
	x10 = a6 & x9;
	x11 = x7 ^ x10;
	x12 = a2 | x11;
	x13 = x8 ^ x12;
	x14 = x9 ^ x13;
	x15 = a6 | x14;
	x16 = x1 ^ x15;
	x17 = ~x14;
	x18 = x17 & x3;
	x19 = a2 | x18;
	x20 = x16 ^ x19;
	x21 = a5 | x20;
	x22 = x13 ^ x21;
	*out4 ^= x22;
	x23 = a3 | x4;
	x24 = ~x23;
	x25 = a6 | x24;
	x26 = x6 ^ x25;
	x27 = x1 & x8;
	x28 = a2 | x27;
	x29 = x26 ^ x28;
	x30 = x1 | x8;
	x31 = x30 ^ x6;
	x32 = x5 & x14;
	x33 = x32 ^ x8;
	x34 = a2 & x33;
	x35 = x31 ^ x34;
	x36 = a5 | x35;
	x37 = x29 ^ x36;
	*out1 ^= x37;
	x38 = a3 & x10;
	x39 = x38 | x4;
	x40 = a3 & x33;
	x41 = x40 ^ x25;
	x42 = a2 | x41;
	x43 = x39 ^ x42;
	x44 = a3 | x26;
	x45 = x44 ^ x14;
	x46 = a1 | x8;
	x47 = x46 ^ x20;
	x48 = a2 | x47;
	x49 = x45 ^ x48;
	x50 = a5 & x49;
	x51 = x43 ^ x50;
	*out2 ^= x51;
	x52 = x8 ^ x40;
	x53 = a3 ^ x11;
	x54 = x53 & x5;
	x55 = a2 | x54;
	x56 = x52 ^ x55;
	x57 = a6 | x4;
	x58 = x57 ^ x38;
	x59 = x13 & x56;
	x60 = a2 & x59;
	x61 = x58 ^ x60;
	x62 = a5 & x61;
	x63 = x56 ^ x62;
	*out3 ^= x63;
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
	unsigned long	x49, x50, x51, x52, x53, x54, x55, x56;

	x1 = ~a5;
	x2 = ~a1;
	x3 = a5 ^ a6;
	x4 = x3 ^ x2;
	x5 = x4 ^ a2;
	x6 = a6 | x1;
	x7 = x6 | x2;
	x8 = a2 & x7;
	x9 = a6 ^ x8;
	x10 = a3 & x9;
	x11 = x5 ^ x10;
	x12 = a2 & x9;
	x13 = a5 ^ x6;
	x14 = a3 | x13;
	x15 = x12 ^ x14;
	x16 = a4 & x15;
	x17 = x11 ^ x16;
	*out2 ^= x17;
	x18 = a5 | a1;
	x19 = a6 | x18;
	x20 = x13 ^ x19;
	x21 = x20 ^ a2;
	x22 = a6 | x4;
	x23 = x22 & x17;
	x24 = a3 | x23;
	x25 = x21 ^ x24;
	x26 = a6 | x2;
	x27 = a5 & x2;
	x28 = a2 | x27;
	x29 = x26 ^ x28;
	x30 = x3 ^ x27;
	x31 = x2 ^ x19;
	x32 = a2 & x31;
	x33 = x30 ^ x32;
	x34 = a3 & x33;
	x35 = x29 ^ x34;
	x36 = a4 | x35;
	x37 = x25 ^ x36;
	*out3 ^= x37;
	x38 = x21 & x32;
	x39 = x38 ^ x5;
	x40 = a1 | x15;
	x41 = x40 ^ x13;
	x42 = a3 | x41;
	x43 = x39 ^ x42;
	x44 = x28 | x41;
	x45 = a4 & x44;
	x46 = x43 ^ x45;
	*out1 ^= x46;
	x47 = x19 & x21;
	x48 = x47 ^ x26;
	x49 = a2 & x33;
	x50 = x49 ^ x21;
	x51 = a3 & x50;
	x52 = x48 ^ x51;
	x53 = x18 & x28;
	x54 = x53 & x50;
	x55 = a4 | x54;
	x56 = x52 ^ x55;
	*out4 ^= x56;
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
	unsigned long	x49, x50, x51, x52, x53, x54, x55, x56;
	unsigned long	x57;

	x1 = ~a5;
	x2 = ~a6;
	x3 = a5 & a3;
	x4 = x3 ^ a6;
	x5 = a4 & x1;
	x6 = x4 ^ x5;
	x7 = x6 ^ a2;
	x8 = a3 & x1;
	x9 = a5 ^ x2;
	x10 = a4 | x9;
	x11 = x8 ^ x10;
	x12 = x7 & x11;
	x13 = a5 ^ x11;
	x14 = x13 | x7;
	x15 = a4 & x14;
	x16 = x12 ^ x15;
	x17 = a2 & x16;
	x18 = x11 ^ x17;
	x19 = a1 & x18;
	x20 = x7 ^ x19;
	*out4 ^= x20;
	x21 = a3 ^ a4;
	x22 = x21 ^ x9;
	x23 = x2 | x4;
	x24 = x23 ^ x8;
	x25 = a2 | x24;
	x26 = x22 ^ x25;
	x27 = a6 ^ x23;
	x28 = x27 | a4;
	x29 = a3 ^ x15;
	x30 = x29 | x5;
	x31 = a2 | x30;
	x32 = x28 ^ x31;
	x33 = a1 | x32;
	x34 = x26 ^ x33;
	*out1 ^= x34;
	x35 = a3 ^ x9;
	x36 = x35 | x5;
	x37 = x4 | x29;
	x38 = x37 ^ a4;
	x39 = a2 | x38;
	x40 = x36 ^ x39;
	x41 = a6 & x11;
	x42 = x41 | x6;
	x43 = x34 ^ x38;
	x44 = x43 ^ x41;
	x45 = a2 & x44;
	x46 = x42 ^ x45;
	x47 = a1 | x46;
	x48 = x40 ^ x47;
	*out3 ^= x48;
	x49 = x2 | x38;
	x50 = x49 ^ x13;
	x51 = x27 ^ x28;
	x52 = a2 | x51;
	x53 = x50 ^ x52;
	x54 = x12 & x23;
	x55 = x54 & x52;
	x56 = a1 | x55;
	x57 = x53 ^ x56;
	*out2 ^= x57;
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
	unsigned long	x33, x34, x35, x36, x37, x38, x39, x40;
	unsigned long	x41, x42;

	x1 = ~a1;
	x2 = ~a3;
	x3 = a1 | a3;
	x4 = a5 & x3;
	x5 = x1 ^ x4;
	x6 = a2 | a3;
	x7 = x5 ^ x6;
	x8 = a1 & a5;
	x9 = x8 ^ x3;
	x10 = a2 & x9;
	x11 = a5 ^ x10;
	x12 = a4 & x11;
	x13 = x7 ^ x12;
	x14 = x2 ^ x4;
	x15 = a2 & x14;
	x16 = x9 ^ x15;
	x17 = x5 & x14;
	x18 = a5 ^ x2;
	x19 = a2 | x18;
	x20 = x17 ^ x19;
	x21 = a4 | x20;
	x22 = x16 ^ x21;
	x23 = a6 & x22;
	x24 = x13 ^ x23;
	*out2 ^= x24;
	x25 = ~x13;
	x26 = a6 | x22;
	x27 = x25 ^ x26;
	*out1 ^= x27;
	x28 = a2 & x11;
	x29 = x28 ^ x17;
	x30 = a3 ^ x10;
	x31 = x30 ^ x19;
	x32 = a4 & x31;
	x33 = x29 ^ x32;
	x34 = x25 ^ x33;
	x35 = a2 & x34;
	x36 = x24 ^ x35;
	x37 = a4 | x34;
	x38 = x36 ^ x37;
	x39 = a6 & x38;
	x40 = x33 ^ x39;
	*out4 ^= x40;
	x41 = x26 ^ x38;
	x42 = x41 ^ x40;
	*out3 ^= x42;
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
	unsigned long	x57, x58, x59, x60, x61, x62;

	x1 = ~a6;
	x2 = ~a3;
	x3 = x1 | x2;
	x4 = x3 ^ a4;
	x5 = a1 & x3;
	x6 = x4 ^ x5;
	x7 = a6 | a4;
	x8 = x7 ^ a3;
	x9 = a3 | x7;
	x10 = a1 | x9;
	x11 = x8 ^ x10;
	x12 = a5 & x11;
	x13 = x6 ^ x12;
	x14 = ~x4;
	x15 = x14 & a6;
	x16 = a1 | x15;
	x17 = x8 ^ x16;
	x18 = a5 | x17;
	x19 = x10 ^ x18;
	x20 = a2 | x19;
	x21 = x13 ^ x20;
	*out3 ^= x21;
	x22 = x2 | x15;
	x23 = x22 ^ a6;
	x24 = a4 ^ x22;
	x25 = a1 & x24;
	x26 = x23 ^ x25;
	x27 = a1 ^ x11;
	x28 = x27 & x22;
	x29 = a5 | x28;
	x30 = x26 ^ x29;
	x31 = a4 | x27;
	x32 = ~x31;
	x33 = a2 | x32;
	x34 = x30 ^ x33;
	*out2 ^= x34;
	x35 = x2 ^ x15;
	x36 = a1 & x35;
	x37 = x14 ^ x36;
	x38 = x5 ^ x7;
	x39 = x38 & x34;
	x40 = a5 | x39;
	x41 = x37 ^ x40;
	x42 = x2 ^ x5;
	x43 = x42 & x16;
	x44 = x4 & x27;
	x45 = a5 & x44;
	x46 = x43 ^ x45;
	x47 = a2 | x46;
	x48 = x41 ^ x47;
	*out1 ^= x48;
	x49 = x24 & x48;
	x50 = x49 ^ x5;
	x51 = x11 ^ x30;
	x52 = x51 | x50;
	x53 = a5 & x52;
	x54 = x50 ^ x53;
	x55 = x14 ^ x19;
	x56 = x55 ^ x34;
	x57 = x4 ^ x16;
	x58 = x57 & x30;
	x59 = a5 & x58;
	x60 = x56 ^ x59;
	x61 = a2 | x60;
	x62 = x54 ^ x61;
	*out4 ^= x62;
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
	unsigned long	x49, x50, x51, x52, x53, x54, x55, x56;
	unsigned long	x57;

	x1 = ~a2;
	x2 = ~a5;
	x3 = a2 ^ a6;
	x4 = x3 ^ x2;
	x5 = x4 ^ a1;
	x6 = a5 & a6;
	x7 = x6 | x1;
	x8 = a5 & x5;
	x9 = a1 & x8;
	x10 = x7 ^ x9;
	x11 = a4 & x10;
	x12 = x5 ^ x11;
	x13 = a6 ^ x10;
	x14 = x13 & a1;
	x15 = a2 & a6;
	x16 = x15 ^ a5;
	x17 = a1 & x16;
	x18 = x2 ^ x17;
	x19 = a4 | x18;
	x20 = x14 ^ x19;
	x21 = a3 & x20;
	x22 = x12 ^ x21;
	*out2 ^= x22;
	x23 = a6 ^ x18;
	x24 = a1 & x23;
	x25 = a5 ^ x24;
	x26 = a2 ^ x17;
	x27 = x26 | x6;
	x28 = a4 & x27;
	x29 = x25 ^ x28;
	x30 = ~x26;
	x31 = a6 | x29;
	x32 = ~x31;
	x33 = a4 & x32;
	x34 = x30 ^ x33;
	x35 = a3 & x34;
	x36 = x29 ^ x35;
	*out4 ^= x36;
	x37 = x6 ^ x34;
	x38 = a5 & x23;
	x39 = x38 ^ x5;
	x40 = a4 | x39;
	x41 = x37 ^ x40;
	x42 = x16 | x24;
	x43 = x42 ^ x1;
	x44 = x15 ^ x24;
	x45 = x44 ^ x31;
	x46 = a4 | x45;
	x47 = x43 ^ x46;
	x48 = a3 | x47;
	x49 = x41 ^ x48;
	*out1 ^= x49;
	x50 = x5 | x38;
	x51 = x50 ^ x6;
	x52 = x8 & x31;
	x53 = a4 | x52;
	x54 = x51 ^ x53;
	x55 = x30 & x43;
	x56 = a3 | x55;
	x57 = x54 ^ x56;
	*out3 ^= x57;
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
	unsigned long	x49, x50, x51, x52, x53, x54, x55, x56;
	unsigned long	x57;

	x1 = ~a2;
	x2 = ~a5;
	x3 = a2 & a4;
	x4 = x3 ^ a5;
	x5 = x4 ^ a3;
	x6 = a4 & x4;
	x7 = x6 ^ a2;
	x8 = a3 & x7;
	x9 = a1 ^ x8;
	x10 = a6 | x9;
	x11 = x5 ^ x10;
	x12 = a4 & x2;
	x13 = x12 | a2;
	x14 = a2 | x2;
	x15 = a3 & x14;
	x16 = x13 ^ x15;
	x17 = x6 ^ x11;
	x18 = a6 | x17;
	x19 = x16 ^ x18;
	x20 = a1 & x19;
	x21 = x11 ^ x20;
	*out1 ^= x21;
	x22 = a2 | x21;
	x23 = x22 ^ x6;
	x24 = x23 ^ x15;
	x25 = x5 ^ x6;
	x26 = x25 | x12;
	x27 = a6 | x26;
	x28 = x24 ^ x27;
	x29 = x1 & x19;
	x30 = x23 & x26;
	x31 = a6 & x30;
	x32 = x29 ^ x31;
	x33 = a1 | x32;
	x34 = x28 ^ x33;
	*out4 ^= x34;
	x35 = a4 & x16;
	x36 = x35 | x1;
	x37 = a6 & x36;
	x38 = x11 ^ x37;
	x39 = a4 & x13;
	x40 = a3 | x7;
	x41 = x39 ^ x40;
	x42 = x1 | x24;
	x43 = a6 | x42;
	x44 = x41 ^ x43;
	x45 = a1 | x44;
	x46 = x38 ^ x45;
	*out2 ^= x46;
	x47 = x8 ^ x44;
	x48 = x6 ^ x15;
	x49 = a6 | x48;
	x50 = x47 ^ x49;
	x51 = x19 ^ x44;
	x52 = a4 ^ x25;
	x53 = x52 & x46;
	x54 = a6 & x53;
	x55 = x51 ^ x54;
	x56 = a1 | x55;
	x57 = x50 ^ x56;
	*out3 ^= x57;
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
	unsigned long	x49, x50, x51, x52, x53, x54;

	x1 = ~a1;
	x2 = ~a4;
	x3 = a3 ^ x1;
	x4 = a3 | x1;
	x5 = x4 ^ x2;
	x6 = a5 | x5;
	x7 = x3 ^ x6;
	x8 = x1 | x5;
	x9 = x2 ^ x8;
	x10 = a5 & x9;
	x11 = x8 ^ x10;
	x12 = a2 & x11;
	x13 = x7 ^ x12;
	x14 = x6 ^ x9;
	x15 = x3 & x9;
	x16 = a5 & x8;
	x17 = x15 ^ x16;
	x18 = a2 | x17;
	x19 = x14 ^ x18;
	x20 = a6 | x19;
	x21 = x13 ^ x20;
	*out1 ^= x21;
	x22 = a5 | x3;
	x23 = x22 & x2;
	x24 = ~a3;
	x25 = x24 & x8;
	x26 = a5 & x4;
	x27 = x25 ^ x26;
	x28 = a2 | x27;
	x29 = x23 ^ x28;
	x30 = a6 & x29;
	x31 = x13 ^ x30;
	*out4 ^= x31;
	x32 = x5 ^ x6;
	x33 = x32 ^ x22;
	x34 = a4 | x13;
	x35 = a2 & x34;
	x36 = x33 ^ x35;
	x37 = a1 & x33;
	x38 = x37 ^ x8;
	x39 = a1 ^ x23;
	x40 = x39 & x7;
	x41 = a2 & x40;
	x42 = x38 ^ x41;
	x43 = a6 | x42;
	x44 = x36 ^ x43;
	*out3 ^= x44;
	x45 = a1 ^ x10;
	x46 = x45 ^ x22;
	x47 = ~x7;
	x48 = x47 & x8;
	x49 = a2 | x48;
	x50 = x46 ^ x49;
	x51 = x19 ^ x29;
	x52 = x51 | x38;
	x53 = a6 & x52;
	x54 = x50 ^ x53;
	*out2 ^= x54;
}
