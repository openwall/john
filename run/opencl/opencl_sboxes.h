#include "opencl_misc.h"

#if HAVE_LUT3

/*
 * Bitslice DES S-boxes with NVIDIA LOP3.LUT and x86-64 AVX-512 VPTERNLOG
 * by Sovyn Y., 28.02.2024
 *
 * Gate counts: 23 22 24 17 23 22 23 23 (Total: 177)
 * Average: 22.125
 *
 * Alternative versions by DeepLearningJohnDoe, version 0.1.6, 2015/07/19
 *
 * Gate counts: 25 24 25 18 25 24 24 23 (Total: 188)
 * Average: 23.5
 * Depth: 8 7 7 6 8 10 10 8
 * Average: 8
 *
 * Also included is alternative S4 with 17 gates discovered by Roman Rusakov
 *
 * This OpenCL source code representation is
 * Copyright (c) 2015 <deeplearningjohndoe at gmail.com>
 * Copyright (c) 2019,2024 Solar Designer <solar at openwall.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * The underlying mathematical formulas are NOT copyrighted.
 */

INLINE void
s1(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#ifndef JOHN_DES_OPT_REG /* 23 gates by Sovyn Y. */
	vtype t0  = lut3( a3,  a2,  a1, 0x29);
	vtype t1  = lut3( a6,  a5,  t0, 0x96);
	vtype t2  = lut3( a6,  a5,  a1, 0x35);
	vtype t3  = lut3( a4,  a3,  t2, 0x2e);
	vtype t4  = lut3( a5,  a2,  t1, 0x9c);
	vtype t5  = lut3( a4,  t0,  t4, 0x61);
	vtype x1  = lut3( t1,  t3,  t5, 0xd1);
	vtype t6  = lut3( a5,  a1,  t0, 0x94);
	vtype t7  = lut3( a4,  t0,  t1, 0x6b);
	vtype t8  = lut3( a1,  t5,  t7, 0xd8);
	vtype t9  = lut3( a6,  a4,  a3, 0x89);
	vtype t10 = lut3( t0,  t1,  t9, 0xe9);
	vtype x2  = lut3( t6,  t8, t10, 0xc6);
	vtype t11 = lut3( a6,  a2,  t7, 0x88);
	vtype t12 = lut3( a6,  a4,  x1, 0x01);
	vtype t13 = lut3( a3,  a1, t12, 0xb6);
	vtype t14 = lut3( a3,  t0,  t1, 0x7c);
	vtype t15 = lut3( a5,  t5, t14, 0x79);
	vtype x4  = lut3(t11, t13, t15, 0xc6);
	vtype t16 = lut3( a4,  a1,  t2, 0xcd);
	vtype t17 = lut3( t8, t12, t16, 0xda);
	vtype t18 = lut3( a6,  t4, t15, 0x81);
	vtype x3  = lut3(t14, t17, t18, 0xe3);
#else /* 25 gates by DeepLearningJohnDoe */
	vtype xAA55AA5500550055 = lut3(a1, a4, a6, 0xC1);
	vtype xA55AA55AF0F5F0F5 = lut3(a3, a6, xAA55AA5500550055, 0x9E);
	vtype x5F5F5F5FA5A5A5A5 = lut3(a1, a3, a6, 0xD6);
	vtype xF5A0F5A0A55AA55A = lut3(a4, xAA55AA5500550055, x5F5F5F5FA5A5A5A5, 0x56);
	vtype x947A947AD1E7D1E7 = lut3(a2, xA55AA55AF0F5F0F5, xF5A0F5A0A55AA55A, 0x6C);
	vtype x5FFF5FFFFFFAFFFA = lut3(a6, xAA55AA5500550055, x5F5F5F5FA5A5A5A5, 0x7B);
	vtype xB96CB96C69936993 = lut3(a2, xF5A0F5A0A55AA55A, x5FFF5FFFFFFAFFFA, 0xD6);
	vtype x3 = lut3(a5, x947A947AD1E7D1E7, xB96CB96C69936993, 0x6A);
	vtype x55EE55EE55EE55EE = lut3(a1, a2, a4, 0x7A);
	vtype x084C084CB77BB77B = lut3(a2, a6, xF5A0F5A0A55AA55A, 0xC9);
	vtype x9C329C32E295E295 = lut3(x947A947AD1E7D1E7, x55EE55EE55EE55EE, x084C084CB77BB77B, 0x72);
	vtype xA51EA51E50E050E0 = lut3(a3, a6, x55EE55EE55EE55EE, 0x29);
	vtype x4AD34AD3BE3CBE3C = lut3(a2, x947A947AD1E7D1E7, xA51EA51E50E050E0, 0x95);
	vtype x2 = lut3(a5, x9C329C32E295E295, x4AD34AD3BE3CBE3C, 0xC6);
	vtype xD955D95595D195D1 = lut3(a1, a2, x9C329C32E295E295, 0xD2);
	vtype x8058805811621162 = lut3(x947A947AD1E7D1E7, x55EE55EE55EE55EE, x084C084CB77BB77B, 0x90);
	vtype x7D0F7D0FC4B3C4B3 = lut3(xA51EA51E50E050E0, xD955D95595D195D1, x8058805811621162, 0x76);
	vtype x0805080500010001 = lut3(a3, xAA55AA5500550055, xD955D95595D195D1, 0x80);
	vtype x4A964A96962D962D = lut3(xB96CB96C69936993, x4AD34AD3BE3CBE3C, x0805080500010001, 0xA6);
	vtype x4 = lut3(a5, x7D0F7D0FC4B3C4B3, x4A964A96962D962D, 0xA6);
	vtype x148014807B087B08 = lut3(a1, xAA55AA5500550055, x947A947AD1E7D1E7, 0x21);
	vtype x94D894D86B686B68 = lut3(xA55AA55AF0F5F0F5, x8058805811621162, x148014807B087B08, 0x6A);
	vtype x5555555540044004 = lut3(a1, a6, x084C084CB77BB77B, 0x70);
	vtype xAFB4AFB4BF5BBF5B = lut3(x5F5F5F5FA5A5A5A5, xA51EA51E50E050E0, x5555555540044004, 0x97);
	vtype x1 = lut3(a5, x94D894D86B686B68, xAFB4AFB4BF5BBF5B, 0x6C);
#endif
#define XOROUT \
	out[c1] ^= x1; \
	out[c2] ^= x2; \
	out[c3] ^= x3; \
	out[c4] ^= x4;
	XOROUT
}

INLINE void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#if 1 /* 22 gates by Sovyn Y. */
	vtype t0  = lut3( a5,  a4,  a1, 0x69);
	vtype t1  = lut3( a6,  a3,  a2, 0xc1);
	vtype t2  = lut3( a6,  a5,  a1, 0xc7);
	vtype t3  = lut3( a4,  a3,  t2, 0x28);
	vtype t4  = lut3( a6,  a2,  t3, 0x94);
	vtype x2  = lut3( t0,  t1,  t4, 0xd2);
	vtype t5  = lut3( a5,  a1,  t1, 0x19);
	vtype t6  = lut3( a5,  a2,  t0, 0x98);
	vtype t7  = lut3( a4,  a2,  t3, 0x21);
	vtype t8  = lut3( a6,  a3,  t7, 0x09);
	vtype x1  = lut3( t5,  t6,  t8, 0xc9);
	vtype t9  = lut3( a6,  a1,  x1, 0x74);
	vtype t10 = lut3( a4,  t4,  t9, 0x68);
	vtype t11 = lut3( a6,  a5,  x1, 0x4d);
	vtype t12 = lut3( a2,  x2, t11, 0x69);
	vtype x4  = lut3( t9, t10, t12, 0xc5);
	vtype t13 = lut3( a5,  x1, t10, 0x09);
	vtype t14 = lut3(t12,  x4, t13, 0x69);
	vtype t15 = lut3( t1,  t2,  x2, 0xb7);
	vtype t16 = lut3( a2,  t3,  t9, 0xe2);
	vtype t17 = lut3( t4, t10, t15, 0x92);
	vtype x3  = lut3(t14, t16, t17, 0xf2);
#else /* 24 gates by DeepLearningJohnDoe */
	vtype xEEEEEEEE99999999 = lut3(a1, a2, a6, 0x97);
	vtype xFFFFEEEE66666666 = lut3(a5, a6, xEEEEEEEE99999999, 0x67);
	vtype x5555FFFFFFFF0000 = lut3(a1, a5, a6, 0x76);
	vtype x6666DDDD5555AAAA = lut3(a2, xFFFFEEEE66666666, x5555FFFFFFFF0000, 0x69);
	vtype x6969D3D35353ACAC = lut3(a3, xFFFFEEEE66666666, x6666DDDD5555AAAA, 0x6A);
	vtype xCFCF3030CFCF3030 = lut3(a2, a3, a5, 0x65);
	vtype xE4E4EEEE9999F0F0 = lut3(a3, xEEEEEEEE99999999, x5555FFFFFFFF0000, 0x8D);
	vtype xE5E5BABACDCDB0B0 = lut3(a1, xCFCF3030CFCF3030, xE4E4EEEE9999F0F0, 0xCA);
	vtype x3 = lut3(a4, x6969D3D35353ACAC, xE5E5BABACDCDB0B0, 0xC6);
	vtype x3333CCCC00000000 = lut3(a2, a5, a6, 0x14);
	vtype xCCCCDDDDFFFF0F0F = lut3(a5, xE4E4EEEE9999F0F0, x3333CCCC00000000, 0xB5);
	vtype x00000101F0F0F0F0 = lut3(a3, a6, xFFFFEEEE66666666, 0x1C);
	vtype x9A9A64646A6A9595 = lut3(a1, xCFCF3030CFCF3030, x00000101F0F0F0F0, 0x96);
	vtype x2 = lut3(a4, xCCCCDDDDFFFF0F0F, x9A9A64646A6A9595, 0x6A);
	vtype x3333BBBB3333FFFF = lut3(a1, a2, x6666DDDD5555AAAA, 0xDE);
	vtype x1414141441410000 = lut3(a1, a3, xE4E4EEEE9999F0F0, 0x90);
	vtype x7F7FF3F3F5F53939 = lut3(x6969D3D35353ACAC, x9A9A64646A6A9595, x3333BBBB3333FFFF, 0x79);
	vtype x9494E3E34B4B3939 = lut3(a5, x1414141441410000, x7F7FF3F3F5F53939, 0x29);
	vtype x1 = lut3(a4, x3333BBBB3333FFFF, x9494E3E34B4B3939, 0xA6);
	vtype xB1B1BBBBCCCCA5A5 = lut3(a1, a1, xE4E4EEEE9999F0F0, 0x4A);
	vtype xFFFFECECEEEEDDDD = lut3(a2, x3333CCCC00000000, x9A9A64646A6A9595, 0xEF);
	vtype xB1B1A9A9DCDC8787 = lut3(xE5E5BABACDCDB0B0, xB1B1BBBBCCCCA5A5, xFFFFECECEEEEDDDD, 0x8D);
	vtype xFFFFCCCCEEEE4444 = lut3(a2, a5, xFFFFEEEE66666666, 0x2B);
	vtype x4 = lut3(a4, xB1B1A9A9DCDC8787, xFFFFCCCCEEEE4444, 0x6C);
#endif
	XOROUT
}

INLINE void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#ifndef JOHN_DES_OPT_REG /* 24 gates by Sovyn Y. */
	vtype t0  = lut3( a5,  a3,  a1, 0x37);
	vtype t1  = lut3( a6,  a2,  t0, 0x96);
	vtype t2  = lut3( a6,  a5,  a4, 0x63);
	vtype t3  = lut3( a4,  a1,  t2, 0x68);
	vtype t4  = lut3( a2,  a1,  t2, 0x80);
	vtype x4  = lut3( t1,  t3,  t4, 0xc9);
	vtype t5  = lut3( a4,  t0,  t1, 0x62);
	vtype t6  = lut3( a4,  a3,  a2, 0x29);
	vtype t7  = lut3( a1,  t2,  t6, 0x69);
	vtype t8  = lut3( a3,  a1,  x4, 0xae);
	vtype t9  = lut3( a4,  a2,  t8, 0x19);
	vtype x1  = lut3( t5,  t7,  t9, 0xc9);
	vtype t10 = lut3( a6,  a5,  a2, 0x06);
	vtype t11 = lut3( a4,  t7, t10, 0x6c);
	vtype t12 = lut3( a4,  a3, t11, 0xa9);
	vtype t13 = lut3( t6,  x1, t11, 0x83);
	vtype t14 = lut3( a5,  x4, t13, 0x26);
	vtype x2  = lut3( a3, t12, t14, 0x39);
	vtype t15 = lut3( a3,  x1, t10, 0xa7);
	vtype t16 = lut3(t13, t14, t15, 0x56);
	vtype t17 = lut3( a1,  t9,  x2, 0x0d);
	vtype t18 = lut3( a5,  x4,  x2, 0x4e);
	vtype t19 = lut3( a2,  x1, t18, 0x96);
	vtype x3  = lut3(t16, t17, t19, 0xb8);
#else /* 25 gates by DeepLearningJohnDoe */
	vtype xA50FA50FA50FA50F = lut3(a1, a3, a4, 0xC9);
	vtype xF0F00F0FF0F0F0F0 = lut3(a3, a5, a6, 0x4B);
	vtype xAF0FA0AAAF0FAF0F = lut3(a1, xA50FA50FA50FA50F, xF0F00F0FF0F0F0F0, 0x4D);
	vtype x5AA5A55A5AA55AA5 = lut3(a1, a4, xF0F00F0FF0F0F0F0, 0x69);
	vtype xAA005FFFAA005FFF = lut3(a3, a5, xA50FA50FA50FA50F, 0xD6);
	vtype x5AA5A55A0F5AFAA5 = lut3(a6, x5AA5A55A5AA55AA5, xAA005FFFAA005FFF, 0x9C);
	vtype x1 = lut3(a2, xAF0FA0AAAF0FAF0F, x5AA5A55A0F5AFAA5, 0xA6);
	vtype xAA55AA5500AA00AA = lut3(a1, a4, a6, 0x49);
	vtype xFAFAA50FFAFAA50F = lut3(a1, a5, xA50FA50FA50FA50F, 0x9B);
	vtype x50AF0F5AFA50A5A5 = lut3(a1, xAA55AA5500AA00AA, xFAFAA50FFAFAA50F, 0x66);
	vtype xAFAFAFAFFAFAFAFA = lut3(a1, a3, a6, 0x6F);
	vtype xAFAFFFFFFFFAFAFF = lut3(a4, x50AF0F5AFA50A5A5, xAFAFAFAFFAFAFAFA, 0xEB);
	vtype x4 = lut3(a2, x50AF0F5AFA50A5A5, xAFAFFFFFFFFAFAFF, 0x6C);
	vtype x500F500F500F500F = lut3(a1, a3, a4, 0x98);
	vtype xF0505A0505A5050F = lut3(x5AA5A55A0F5AFAA5, xAA55AA5500AA00AA, xAFAFAFAFFAFAFAFA, 0x1D);
	vtype xF0505A05AA55AAFF = lut3(a6, x500F500F500F500F, xF0505A0505A5050F, 0x9A);
	vtype xFF005F55FF005F55 = lut3(a1, a4, xAA005FFFAA005FFF, 0xB2);
	vtype xA55F5AF0A55F5AF0 = lut3(a5, xA50FA50FA50FA50F, x5AA5A55A5AA55AA5, 0x3D);
	vtype x5A5F05A5A55F5AF0 = lut3(a6, xFF005F55FF005F55, xA55F5AF0A55F5AF0, 0xA6);
	vtype x3 = lut3(a2, xF0505A05AA55AAFF, x5A5F05A5A55F5AF0, 0xA6);
	vtype x0F0F0F0FA5A5A5A5 = lut3(a1, a3, a6, 0xC6);
	vtype x5FFFFF5FFFA0FFA0 = lut3(x5AA5A55A5AA55AA5, xAFAFAFAFFAFAFAFA, x0F0F0F0FA5A5A5A5, 0xDB);
	vtype xF5555AF500A05FFF = lut3(a5, xFAFAA50FFAFAA50F, xF0505A0505A5050F, 0xB9);
	vtype x05A5AAF55AFA55A5 = lut3(xF0505A05AA55AAFF, x0F0F0F0FA5A5A5A5, xF5555AF500A05FFF, 0x9B);
	vtype x2 = lut3(a2, x5FFFFF5FFFA0FFA0, x05A5AAF55AFA55A5, 0xA6);
#endif
	XOROUT
}

INLINE void
s4(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#if 0 /* 17 gates by Sovyn Y. */
	vtype t0  = lut3( a5,  a4,  a1, 0xc9);
	vtype t1  = lut3( a3,  a2,  t0, 0x64);
	vtype t2  = lut3( a5,  a4,  a3, 0xdb);
	vtype t3  = lut3( a1,  t1,  t2, 0x6d);
	vtype t4  = lut3( a5,  a4,  a1, 0x93);
	vtype t5  = lut3( a3,  a2,  t4, 0x46);
	vtype t6  = lut3( a1,  t2,  t5, 0x49);
	vtype t7  = lut3( a1,  t3,  t5, 0x2c);
	vtype t8  = lut3( a5,  t6,  t7, 0x16);
	vtype t9  = lut3( a3,  a2,  t8, 0x6a);
	vtype t10 = lut3( t2,  t3,  t6, 0xe4);
	vtype t11 = lut3( a4,  a2, t10, 0xd8);
	vtype t12 = lut3( t3,  t9, t11, 0x96);
	vtype x1  = lut3( a6,  t6, t12, 0xc6);
	vtype x2  = lut3( a6,  t6, t12, 0x9c);
	vtype x3  = lut3( a6,  t3,  t9, 0xc6);
	vtype x4  = lut3( a6,  t3,  t9, 0x63);
#elif 1 /* 17 gates by Roman Rusakov */
	vtype x55AAFF00 = lut3(a1, a4, a5, 0x36);
	vtype x00F00F00 = lut3(a3, a4, a5, 0x24);
	vtype x1926330C = lut3(a2, a3, x55AAFF00, 0xA4);
	vtype x4CA36B59 = lut3(x00F00F00, a1, x1926330C, 0xB6);
	vtype x00FF55AA = lut3(a1, a4, a5, 0x6C);
	vtype x3FCC6E9D = lut3(a2, a3, x00FF55AA, 0x5E);
	vtype x6A7935C8 = lut3(a1, x00F00F00, x3FCC6E9D, 0xD6);
	vtype x5D016B55 = lut3(a1, x4CA36B59, x00FF55AA, 0xD4);
	vtype x07AE9F5A = lut3(a3, x55AAFF00, x5D016B55, 0xD6);
	vtype x61C8F93C = lut3(a1, a2, x07AE9F5A, 0x96);
	vtype x3 = lut3(a6, x4CA36B59, x61C8F93C, 0xC9);
	vtype x4 = lut3(a6, x4CA36B59, x61C8F93C, 0x93);
	vtype x26DA5E91; vxor(x26DA5E91, x4CA36B59, x6A7935C8);
	vtype x37217F22 = lut3(a2, a4, x26DA5E91, 0x72);
	vtype x56E9861E; vxor(x56E9861E, x37217F22, x61C8F93C);
	vtype x1 = lut3(a6, x56E9861E, x6A7935C8, 0x5C);
	vtype x2 = lut3(a6, x56E9861E, x6A7935C8, 0x35);
#else /* 18 gates by DeepLearningJohnDoe */
	vtype x55F055F055F055F0 = lut3(a1, a3, a4, 0x72);
	vtype xA500F5F0A500F5F0 = lut3(a3, a5, x55F055F055F055F0, 0xAD);
	vtype xF50AF50AF50AF50A = lut3(a1, a3, a4, 0x59);
	vtype xF5FA0FFFF5FA0FFF = lut3(a3, a5, xF50AF50AF50AF50A, 0xE7);
	vtype x61C8F93C61C8F93C = lut3(a2, xA500F5F0A500F5F0, xF5FA0FFFF5FA0FFF, 0xC6);
	vtype x9999666699996666 = lut3(a1, a2, a5, 0x69);
	vtype x22C022C022C022C0 = lut3(a2, a4, x55F055F055F055F0, 0x18);
	vtype xB35C94A6B35C94A6 = lut3(xF5FA0FFFF5FA0FFF, x9999666699996666, x22C022C022C022C0, 0x63);
	vtype x4 = lut3(a6, x61C8F93C61C8F93C, xB35C94A6B35C94A6, 0x6A);
	vtype x4848484848484848 = lut3(a1, a2, a3, 0x12);
	vtype x55500AAA55500AAA = lut3(a1, a5, xF5FA0FFFF5FA0FFF, 0x28);
	vtype x3C90B3D63C90B3D6 = lut3(x61C8F93C61C8F93C, x4848484848484848, x55500AAA55500AAA, 0x1E);
	vtype x8484333384843333 = lut3(a1, x9999666699996666, x4848484848484848, 0x14);
	vtype x4452F1AC4452F1AC = lut3(xF50AF50AF50AF50A, xF5FA0FFFF5FA0FFF, xB35C94A6B35C94A6, 0x78);
	vtype x9586CA379586CA37 = lut3(x55500AAA55500AAA, x8484333384843333, x4452F1AC4452F1AC, 0xD6);
	vtype x2 = lut3(a6, x3C90B3D63C90B3D6, x9586CA379586CA37, 0x6A);
	vtype x1 = lut3(a6, x3C90B3D63C90B3D6, x9586CA379586CA37, 0xA9);
	vtype x3 = lut3(a6, x61C8F93C61C8F93C, xB35C94A6B35C94A6, 0x56);
#endif
	XOROUT
}

INLINE void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#if 1 /* 23 gates by Sovyn Y. */
	vtype t0  = lut3( a6,  a4,  a3, 0x46);
	vtype t1  = lut3( a5,  a1,  t0, 0xe9);
	vtype t2  = lut3( a6,  a2,  t1, 0x69);
	vtype t3  = lut3( a6,  a3,  a1, 0x97);
	vtype t4  = lut3( a5,  a2,  t3, 0x27);
	vtype x2  = lut3( a4,  t2,  t4, 0xc9);
	vtype t5  = lut3( a6,  a2,  t3, 0x8c);
	vtype t6  = lut3( a5,  a2,  t0, 0x53);
	vtype t7  = lut3( a4,  a1,  t6, 0x94);
	vtype t8  = lut3( a3,  a1,  x2, 0x25);
	vtype t9  = lut3( a6,  t1,  t8, 0x6e);
	vtype x3  = lut3( t5,  t7,  t9, 0xc6);
	vtype t10 = lut3( a4,  t0,  t1, 0x29);
	vtype t11 = lut3( a4,  a2,  a1, 0x76);
	vtype t12 = lut3( a4,  t3, t11, 0xb6);
	vtype t13 = lut3( a5,  a2,  a1, 0x1f);
	vtype t14 = lut3( a6,  x2, t13, 0x6a);
	vtype x1  = lut3(t10, t12, t14, 0xc6);
	vtype t15 = lut3( a5,  a2,  x2, 0xb9);
	vtype t16 = lut3( a3,  x1, t15, 0xe6);
	vtype t17 = lut3( t0,  t1,  t2, 0x6b);
	vtype t18 = lut3( t8, t12, t17, 0x24);
	vtype x4  = lut3( x3, t16, t18, 0xb4);
#else /* 25 gates by DeepLearningJohnDoe */
	vtype xA0A0A0A0FFFFFFFF = lut3(a1, a3, a6, 0xAB);
	vtype xFFFF00005555FFFF = lut3(a1, a5, a6, 0xB9);
	vtype xB3B320207777FFFF = lut3(a2, xA0A0A0A0FFFFFFFF, xFFFF00005555FFFF, 0xE8);
	vtype x50505A5A5A5A5050 = lut3(a1, a3, xFFFF00005555FFFF, 0x34);
	vtype xA2A2FFFF2222FFFF = lut3(a1, a5, xB3B320207777FFFF, 0xCE);
	vtype x2E2E6969A4A46363 = lut3(a2, x50505A5A5A5A5050, xA2A2FFFF2222FFFF, 0x29);
	vtype x3 = lut3(a4, xB3B320207777FFFF, x2E2E6969A4A46363, 0xA6);
	vtype xA5A50A0AA5A50A0A = lut3(a1, a3, a5, 0x49);
	vtype x969639396969C6C6 = lut3(a2, a6, xA5A50A0AA5A50A0A, 0x96);
	vtype x1B1B1B1B1B1B1B1B = lut3(a1, a2, a3, 0xCA);
	vtype xBFBFBFBFF6F6F9F9 = lut3(a3, xA0A0A0A0FFFFFFFF, x969639396969C6C6, 0x7E);
	vtype x5B5BA4A4B8B81D1D = lut3(xFFFF00005555FFFF, x1B1B1B1B1B1B1B1B, xBFBFBFBFF6F6F9F9, 0x96);
	vtype x2 = lut3(a4, x969639396969C6C6, x5B5BA4A4B8B81D1D, 0xCA);
	vtype x5555BBBBFFFF5555 = lut3(a1, a2, xFFFF00005555FFFF, 0xE5);
	vtype x6D6D9C9C95956969 = lut3(x50505A5A5A5A5050, xA2A2FFFF2222FFFF, x969639396969C6C6, 0x97);
	vtype x1A1A67676A6AB4B4 = lut3(xA5A50A0AA5A50A0A, x5555BBBBFFFF5555, x6D6D9C9C95956969, 0x47);
	vtype xA0A0FFFFAAAA0000 = lut3(a3, xFFFF00005555FFFF, xA5A50A0AA5A50A0A, 0x3B);
	vtype x36369C9CC1C1D6D6 = lut3(x969639396969C6C6, x6D6D9C9C95956969, xA0A0FFFFAAAA0000, 0xD9);
	vtype x1 = lut3(a4, x1A1A67676A6AB4B4, x36369C9CC1C1D6D6, 0xCA);
	vtype x5555F0F0F5F55555 = lut3(a1, a3, xFFFF00005555FFFF, 0xB1);
	vtype x79790202DCDC0808 = lut3(xA2A2FFFF2222FFFF, xA5A50A0AA5A50A0A, x969639396969C6C6, 0x47);
	vtype x6C6CF2F229295D5D = lut3(xBFBFBFBFF6F6F9F9, x5555F0F0F5F55555, x79790202DCDC0808, 0x6E);
	vtype xA3A3505010101A1A = lut3(a2, xA2A2FFFF2222FFFF, x36369C9CC1C1D6D6, 0x94);
	vtype x7676C7C74F4FC7C7 = lut3(a1, x2E2E6969A4A46363, xA3A3505010101A1A, 0xD9);
	vtype x4 = lut3(a4, x6C6CF2F229295D5D, x7676C7C74F4FC7C7, 0xC6);
#endif
	XOROUT
}

INLINE void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#if 1 /* 22 gates by Sovyn Y. */
	vtype t0  = lut3( a6,  a5,  a1, 0x36);
	vtype t1  = lut3( a4,  a3,  t0, 0x6c);
	vtype t2  = lut3( a2,  a1,  t0, 0x1e);
	vtype t3  = lut3( a6,  a4,  t2, 0x69);
	vtype t4  = lut3( a6,  a1,  t3, 0x3a);
	vtype t5  = lut3( t0,  t2,  t4, 0xd2);
	vtype x4  = lut3( t1,  t3,  t5, 0xc6);
	vtype t6  = lut3( a5,  t1,  t4, 0x96);
	vtype t7  = lut3( a4,  t3,  t5, 0xba);
	vtype t8  = lut3( a6,  a4,  t6, 0x09);
	vtype t9  = lut3( t0,  x4,  t8, 0x9a);
	vtype x3  = lut3( t6,  t7,  t9, 0xb4);
	vtype t10 = lut3( a6,  a5,  t3, 0x4a);
	vtype t11 = lut3( a2,  t1, t10, 0x9a);
	vtype t12 = lut3( a2,  t3,  t4, 0x24);
	vtype t13 = lut3( a5,  t1, t12, 0xa9);
	vtype x1  = lut3( t7, t11, t13, 0xe1);
	vtype t14 = lut3( a6,  a5,  x4, 0x51);
	vtype t15 = lut3( a2,  x3, t14, 0x69);
	vtype t16 = lut3( t3,  t4,  x3, 0x6b);
	vtype t17 = lut3( t2, t10, t16, 0x96);
	vtype x2  = lut3( x1, t15, t17, 0x3a);
#else /* 24 gates by DeepLearningJohnDoe */
	vtype x5050F5F55050F5F5 = lut3(a1, a3, a5, 0xB2);
	vtype x6363C6C66363C6C6 = lut3(a1, a2, x5050F5F55050F5F5, 0x66);
	vtype xAAAA5555AAAA5555 = lut3(a1, a1, a5, 0xA9);
	vtype x3A3A65653A3A6565 = lut3(a3, x6363C6C66363C6C6, xAAAA5555AAAA5555, 0xA9);
	vtype x5963A3C65963A3C6 = lut3(a4, x6363C6C66363C6C6, x3A3A65653A3A6565, 0xC6);
	vtype xE7E76565E7E76565 = lut3(a5, x6363C6C66363C6C6, x3A3A65653A3A6565, 0xAD);
	vtype x455D45DF455D45DF = lut3(a1, a4, xE7E76565E7E76565, 0xE4);
	vtype x4 = lut3(a6, x5963A3C65963A3C6, x455D45DF455D45DF, 0x6C);
	vtype x1101220211012202 = lut3(a2, xAAAA5555AAAA5555, x5963A3C65963A3C6, 0x20);
	vtype xF00F0FF0F00F0FF0 = lut3(a3, a4, a5, 0x69);
	vtype x16E94A9716E94A97 = lut3(xE7E76565E7E76565, x1101220211012202, xF00F0FF0F00F0FF0, 0x9E);
	vtype x2992922929929229 = lut3(a1, a2, xF00F0FF0F00F0FF0, 0x49);
	vtype xAFAF9823AFAF9823 = lut3(a5, x5050F5F55050F5F5, x2992922929929229, 0x93);
	vtype x3 = lut3(a6, x16E94A9716E94A97, xAFAF9823AFAF9823, 0x6C);
	vtype x4801810248018102 = lut3(a4, x5963A3C65963A3C6, x1101220211012202, 0xA4);
	vtype x5EE8FFFD5EE8FFFD = lut3(a5, x16E94A9716E94A97, x4801810248018102, 0x76);
	vtype xF0FF00FFF0FF00FF = lut3(a3, a4, a5, 0xCD);
	vtype x942D9A67942D9A67 = lut3(x3A3A65653A3A6565, x5EE8FFFD5EE8FFFD, xF0FF00FFF0FF00FF, 0x86);
	vtype x1 = lut3(a6, x5EE8FFFD5EE8FFFD, x942D9A67942D9A67, 0xA6);
	vtype x6A40D4ED6F4DD4EE = lut3(a2, x4, xAFAF9823AFAF9823, 0x2D);
	vtype x6CA89C7869A49C79 = lut3(x1101220211012202, x16E94A9716E94A97, x6A40D4ED6F4DD4EE, 0x26);
	vtype xD6DE73F9D6DE73F9 = lut3(a3, x6363C6C66363C6C6, x455D45DF455D45DF, 0x6B);
	vtype x925E63E1965A63E1 = lut3(x3A3A65653A3A6565, x6CA89C7869A49C79, xD6DE73F9D6DE73F9, 0xA2);
	vtype x2 = lut3(a6, x6CA89C7869A49C79, x925E63E1965A63E1, 0xCA);
#endif
	XOROUT
}

INLINE void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#if 1 /* 23 gates by Sovyn Y. */
	vtype t0  = lut3( a5,  a4,  a2, 0x59);
	vtype t1  = lut3( a6,  a5,  a4, 0x49);
	vtype t2  = lut3( a3,  a1,  t1, 0x96);
	vtype t3  = lut3( a2,  a1,  t2, 0xb8);
	vtype t4  = lut3( a6,  a3,  t3, 0x9c);
	vtype x4  = lut3( t0,  t2,  t4, 0x36);
	vtype t5  = lut3( a1,  t0,  t4, 0x65);
	vtype t6  = lut3( a5,  a2,  a1, 0x74);
	vtype t7  = lut3( a6,  t0,  t1, 0x49);
	vtype t8  = lut3( a6,  t2,  t5, 0xc2);
	vtype t9  = lut3( a6,  t7,  t8, 0x61);
	vtype x1  = lut3( t5,  t6,  t9, 0x47);
	vtype t10 = lut3( a5,  t0,  t2, 0x69);
	vtype t11 = lut3( a4,  a1,  t7, 0xab);
	vtype t12 = lut3( a4,  t1,  t3, 0x65);
	vtype t13 = lut3( a5,  a1,  t5, 0x25);
	vtype t14 = lut3( a6, t12, t13, 0xc6);
	vtype x3  = lut3(t10, t11, t14, 0x74);
	vtype t15 = lut3( x4,  t5, t11, 0x96);
	vtype t16 = lut3( a4,  a2, t12, 0xb9);
	vtype t17 = lut3( a6,  a4, t16, 0x8a);
	vtype t18 = lut3( a1,  t1,  t4, 0x0e);
	vtype x2  = lut3(t15, t17, t18, 0x4b);
#else /* 24 gates by DeepLearningJohnDoe */
	vtype x88AA88AA88AA88AA = lut3(a1, a2, a4, 0x0B);
	vtype xAAAAFF00AAAAFF00 = lut3(a1, a4, a5, 0x27);
	vtype xADAFF8A5ADAFF8A5 = lut3(a3, x88AA88AA88AA88AA, xAAAAFF00AAAAFF00, 0x9E);
	vtype x0A0AF5F50A0AF5F5 = lut3(a1, a3, a5, 0xA6);
	vtype x6B69C5DC6B69C5DC = lut3(a2, xADAFF8A5ADAFF8A5, x0A0AF5F50A0AF5F5, 0x6B);
	vtype x1C69B2DC1C69B2DC = lut3(a4, x88AA88AA88AA88AA, x6B69C5DC6B69C5DC, 0xA9);
	vtype x1 = lut3(a6, xADAFF8A5ADAFF8A5, x1C69B2DC1C69B2DC, 0x6A);
	vtype x9C9C9C9C9C9C9C9C = lut3(a1, a2, a3, 0x63);
	vtype xE6E63BFDE6E63BFD = lut3(a2, xAAAAFF00AAAAFF00, x0A0AF5F50A0AF5F5, 0xE7);
	vtype x6385639E6385639E = lut3(a4, x9C9C9C9C9C9C9C9C, xE6E63BFDE6E63BFD, 0x93);
	vtype x5959C4CE5959C4CE = lut3(a2, x6B69C5DC6B69C5DC, xE6E63BFDE6E63BFD, 0x5D);
	vtype x5B53F53B5B53F53B = lut3(a4, x0A0AF5F50A0AF5F5, x5959C4CE5959C4CE, 0x6E);
	vtype x3 = lut3(a6, x6385639E6385639E, x5B53F53B5B53F53B, 0xC6);
	vtype xFAF505FAFAF505FA = lut3(a3, a4, x0A0AF5F50A0AF5F5, 0x6D);
	vtype x6A65956A6A65956A = lut3(a3, x9C9C9C9C9C9C9C9C, xFAF505FAFAF505FA, 0xA6);
	vtype x8888CCCC8888CCCC = lut3(a1, a2, a5, 0x23);
	vtype x94E97A9494E97A94 = lut3(x1C69B2DC1C69B2DC, x6A65956A6A65956A, x8888CCCC8888CCCC, 0x72);
	vtype x4 = lut3(a6, x6A65956A6A65956A, x94E97A9494E97A94, 0xAC);
	vtype xA050A050A050A050 = lut3(a1, a3, a4, 0x21);
	vtype xC1B87A2BC1B87A2B = lut3(xAAAAFF00AAAAFF00, x5B53F53B5B53F53B, x94E97A9494E97A94, 0xA4);
	vtype xE96016B7E96016B7 = lut3(x8888CCCC8888CCCC, xA050A050A050A050, xC1B87A2BC1B87A2B, 0x96);
	vtype xE3CF1FD5E3CF1FD5 = lut3(x88AA88AA88AA88AA, x6A65956A6A65956A, xE96016B7E96016B7, 0x3E);
	vtype x6776675B6776675B = lut3(xADAFF8A5ADAFF8A5, x94E97A9494E97A94, xE3CF1FD5E3CF1FD5, 0x6B);
	vtype x2 = lut3(a6, xE96016B7E96016B7, x6776675B6776675B, 0xC6);
#endif
	XOROUT
}

INLINE void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
   vtype *out, vtype c1, vtype c2, vtype c3, vtype c4)
{
#if 0 /* 23 gates by Sovyn Y. */
	vtype t0  = lut3( a5,  a4,  a3, 0x56);
	vtype t1  = lut3( a5,  a2,  t0, 0x1b);
	vtype t2  = lut3( a6,  a4,  t1, 0x96);
	vtype t3  = lut3( a6,  t0,  t2, 0x06);
	vtype t4  = lut3( a2,  t0,  t3, 0xa4);
	vtype t5  = lut3( a5,  a4,  t4, 0xa6);
	vtype x2  = lut3( a1,  t2,  t5, 0x6c);
	vtype t6  = lut3( a4,  t5,  x2, 0xc5);
	vtype t7  = lut3( a1,  t0,  t6, 0x69);
	vtype t8  = lut3( a2,  a1,  t3, 0x17);
	vtype t9  = lut3( a5,  t6,  t8, 0xc9);
	vtype t10 = lut3( a4,  a2,  t9, 0xa6);
	vtype x4  = lut3( a6,  t7, t10, 0x36);
	vtype t11 = lut3( t4,  t5,  x2, 0x76);
	vtype t12 = lut3( a3,  a2,  t7, 0x9a);
	vtype t13 = lut3( a3,  t3,  t8, 0x24);
	vtype t14 = lut3( t6, t10, t13, 0x6e);
	vtype x1  = lut3(t11, t12, t14, 0xd1);
	vtype t15 = lut3( a4,  t1,  x1, 0x91);
	vtype t16 = lut3( a3,  t7, t15, 0x69);
	vtype t17 = lut3( t3, t11, t13, 0xba);
	vtype t18 = lut3(t10,  x1, t17, 0x5b);
	vtype x3  = lut3(t11, t16, t18, 0x47);
#else /* 23 gates by DeepLearningJohnDoe */
	vtype xEEEE3333EEEE3333 = lut3(a1, a2, a5, 0x9D);
	vtype xBBBBBBBBBBBBBBBB = lut3(a1, a1, a2, 0x83);
	vtype xDDDDAAAADDDDAAAA = lut3(a1, a2, a5, 0x5B);
	vtype x29295A5A29295A5A = lut3(a3, xBBBBBBBBBBBBBBBB, xDDDDAAAADDDDAAAA, 0x85);
	vtype xC729695AC729695A = lut3(a4, xEEEE3333EEEE3333, x29295A5A29295A5A, 0xA6);
	vtype x3BF77B7B3BF77B7B = lut3(a2, a5, xC729695AC729695A, 0xF9);
	vtype x2900FF002900FF00 = lut3(a4, a5, x29295A5A29295A5A, 0x0E);
	vtype x56B3803F56B3803F = lut3(xBBBBBBBBBBBBBBBB, x3BF77B7B3BF77B7B, x2900FF002900FF00, 0x61);
	vtype x4 = lut3(a6, xC729695AC729695A, x56B3803F56B3803F, 0x6C);
	vtype xFBFBFBFBFBFBFBFB = lut3(a1, a2, a3, 0xDF);
	vtype x3012B7B73012B7B7 = lut3(a2, a5, xC729695AC729695A, 0xD4);
	vtype x34E9B34C34E9B34C = lut3(a4, xFBFBFBFBFBFBFBFB, x3012B7B73012B7B7, 0x69);
	vtype xBFEAEBBEBFEAEBBE = lut3(a1, x29295A5A29295A5A, x34E9B34C34E9B34C, 0x6F);
	vtype xFFAEAFFEFFAEAFFE = lut3(a3, xBBBBBBBBBBBBBBBB, xBFEAEBBEBFEAEBBE, 0xB9);
	vtype x2 = lut3(a6, x34E9B34C34E9B34C, xFFAEAFFEFFAEAFFE, 0xC6);
	vtype xCFDE88BBCFDE88BB = lut3(a2, xDDDDAAAADDDDAAAA, x34E9B34C34E9B34C, 0x5C);
	vtype x3055574530555745 = lut3(a1, xC729695AC729695A, xCFDE88BBCFDE88BB, 0x71);
	vtype x99DDEEEE99DDEEEE = lut3(a4, xBBBBBBBBBBBBBBBB, xDDDDAAAADDDDAAAA, 0xB9);
	vtype x693CD926693CD926 = lut3(x3BF77B7B3BF77B7B, x34E9B34C34E9B34C, x99DDEEEE99DDEEEE, 0x69);
	vtype x3 = lut3(a6, x3055574530555745, x693CD926693CD926, 0x6A);
	vtype x9955EE559955EE55 = lut3(a1, a4, x99DDEEEE99DDEEEE, 0xE2);
	vtype x9D48FA949D48FA94 = lut3(x3BF77B7B3BF77B7B, xBFEAEBBEBFEAEBBE, x9955EE559955EE55, 0x9C);
	vtype x1 = lut3(a6, xC729695AC729695A, x9D48FA949D48FA94, 0x39);
#endif
	XOROUT
#undef XOROUT
}

#else

#undef andn
#define andn 0
#include "opencl_nonstd.h"

#endif /* HAVE_LUT3 */
