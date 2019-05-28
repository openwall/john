/*
 * Bitslice DES S-boxes for x86 with MMX/SSE2/AVX and for typical RISC
 * architectures.  These use AND, OR, XOR, NOT, and AND-NOT gates.
 *
 * Gate counts: 49 44 46 33 48 46 46 41
 * Average: 44.125
 *
 * Several same-gate-count expressions for each S-box are included (for use on
 * different CPUs/GPUs).
 *
 * These Boolean expressions corresponding to DES S-boxes have been generated
 * by Roman Rusakov <roman_rus at openwall.com> for use in Openwall's
 * John the Ripper password cracker: https://www.openwall.com/john/
 * Being mathematical formulas, they are not copyrighted and are free for reuse
 * by anyone.
 *
 * This file (a specific representation of the S-box expressions, surrounding
 * logic) is Copyright (c) 2011 by Solar Designer <solar at openwall.com>.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.  (This is a heavily cut-down "BSD license".)
 *
 * The effort has been sponsored by Rapid7: https://www.rapid7.com
 */

#ifndef andn
#define andn 1
#endif

#undef triop
#if (defined(__x86_64__) || defined(__i386__)) && !defined(__AVX__)
#define triop 0
#else
#define triop 1
#endif

#undef regs
#if defined(__x86_64__) && defined(__SSE2__)
/* Also for AVX, XOP (we assume that these imply/define SSE2) */
#define regs 16
#elif defined(__x86_64__)
#define regs 15
#elif defined(__i386__)
/* Hopefully, at least MMX */
#define regs 8
#else
/* PowerPC with AltiVec, etc. */
#define regs 32
#endif

#undef latency
/* Latency 2 may also mean dual-issue with latency 1 */
#define latency 2

#if andn && triop && regs >= 18 && latency <= 3
/* s1-00104, 49 gates, 18 regs, 13 andn, 2/7/41/79/122 stalls, 75 biop */
MAYBE_INLINE static void
s1(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x55005500, x5A0F5A0F, x3333FFFF, x66666666, x22226666, x2D2D6969,
	    x25202160;
	vtype x00FFFF00, x33CCCC33, x4803120C, x2222FFFF, x6A21EDF3, x4A01CC93;
	vtype x5555FFFF, x7F75FFFF, x00D20096, x7FA7FF69;
	vtype x0A0A0000, x0AD80096, x00999900, x0AD99996;
	vtype x22332233, x257AA5F0, x054885C0, xFAB77A3F, x2221EDF3, xD89697CC;
	vtype x05B77AC0, x05F77AD6, x50A22F83, x6391D07C, xBB0747B0;
	vtype x00B700C0, x5AB85ACF, x50204249, x4090904C, x10B0D205;
	vtype x2220EDF3, x99070200, x9CB078C0, xDCB07AC9;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x55005500, a1, a5);
	vxor(x5A0F5A0F, a4, x55005500);
	vor(x3333FFFF, a3, a6);
	vxor(x66666666, a1, a3);
	vand(x22226666, x3333FFFF, x66666666);
	vxor(x2D2D6969, a4, x22226666);
	vandn(x25202160, x2D2D6969, x5A0F5A0F);

	vxor(x00FFFF00, a5, a6);
	vxor(x33CCCC33, a3, x00FFFF00);
	vandn(x4803120C, x5A0F5A0F, x33CCCC33);
	vor(x2222FFFF, a6, x22226666);
	vxor(x6A21EDF3, x4803120C, x2222FFFF);
	vandn(x4A01CC93, x6A21EDF3, x25202160);

	vor(x5555FFFF, a1, a6);
	vor(x7F75FFFF, x6A21EDF3, x5555FFFF);
	vandn(x00D20096, a5, x2D2D6969);
	vxor(x7FA7FF69, x7F75FFFF, x00D20096);

	vandn(x0A0A0000, a4, x5555FFFF);
	vxor(x0AD80096, x00D20096, x0A0A0000);
	vandn(x00999900, x00FFFF00, x66666666);
	vor(x0AD99996, x0AD80096, x00999900);

	vandn(x22332233, a3, x55005500);
	vxor(x257AA5F0, x5A0F5A0F, x7F75FFFF);
	vandn(x054885C0, x257AA5F0, x22332233);
	vnot(xFAB77A3F, x054885C0);
	vand(x2221EDF3, x3333FFFF, x6A21EDF3);
	vxor(xD89697CC, xFAB77A3F, x2221EDF3);
	vandn(x20, x7FA7FF69, a2);
	vxor(x21, x20, xD89697CC);
	vxor(*out3, *out3, x21);

	vxor(x05B77AC0, x00FFFF00, x054885C0);
	vor(x05F77AD6, x00D20096, x05B77AC0);
	vxor(x50A22F83, a1, x05F77AD6);
	vxor(x6391D07C, x3333FFFF, x50A22F83);
	vxor(xBB0747B0, xD89697CC, x6391D07C);
	vor(x00, x25202160, a2);
	vxor(x01, x00, xBB0747B0);
	vxor(*out1, *out1, x01);

	vand(x00B700C0, a5, x05B77AC0);
	vxor(x5AB85ACF, x5A0F5A0F, x00B700C0);
	vandn(x50204249, x5AB85ACF, x0AD99996);
	vand(x4090904C, xD89697CC, x6391D07C);
	vxor(x10B0D205, x50204249, x4090904C);
	vor(x30, x10B0D205, a2);
	vxor(x31, x30, x0AD99996);
	vxor(*out4, *out4, x31);

	vand(x2220EDF3, x2222FFFF, x6A21EDF3);
	vandn(x99070200, xBB0747B0, x2220EDF3);
	vxor(x9CB078C0, x05B77AC0, x99070200);
	vor(xDCB07AC9, x50204249, x9CB078C0);
	vandn(x10, a2, x4A01CC93);
	vxor(x11, x10, xDCB07AC9);
	vxor(*out2, *out2, x11);
}
#elif !andn || !triop || latency >= 3
/* s1-00484, 49 gates, 17 regs, 11 andn, 4/9/39/79/120 stalls, 74 biop */
/* Currently used for MMX/SSE2 and x86-64 SSE2 */
MAYBE_INLINE static void
s1(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x55005500, x5A0F5A0F, x3333FFFF, x66666666, x22226666, x2D2D6969,
	    x25202160;
	vtype x00FFFF00, x33CCCC33, x4803120C, x2222FFFF, x6A21EDF3, x4A01CC93;
	vtype x5555FFFF, x7F75FFFF, x00D20096, x7FA7FF69;
	vtype x0A0A0000, x0AD80096, x00999900, x0AD99996;
	vtype x22332233, x257AA5F0, x054885C0, xFAB77A3F, x2221EDF3, xD89697CC;
	vtype x05B77AC0, x05F77AD6, x36C48529, x6391D07C, xBB0747B0;
	vtype x4C460000, x4EDF9996, x2D4E49EA, xBBFFFFB0, x96B1B65A;
	vtype x5AFF5AFF, x52B11215, x4201C010, x10B0D205;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x55005500, a1, a5);
	vxor(x5A0F5A0F, a4, x55005500);
	vor(x3333FFFF, a3, a6);
	vxor(x66666666, a1, a3);
	vand(x22226666, x3333FFFF, x66666666);
	vxor(x2D2D6969, a4, x22226666);
	vandn(x25202160, x2D2D6969, x5A0F5A0F);

	vxor(x00FFFF00, a5, a6);
	vxor(x33CCCC33, a3, x00FFFF00);
	vandn(x4803120C, x5A0F5A0F, x33CCCC33);
	vor(x2222FFFF, a6, x22226666);
	vxor(x6A21EDF3, x4803120C, x2222FFFF);
	vandn(x4A01CC93, x6A21EDF3, x25202160);

	vor(x5555FFFF, a1, a6);
	vor(x7F75FFFF, x6A21EDF3, x5555FFFF);
	vandn(x00D20096, a5, x2D2D6969);
	vxor(x7FA7FF69, x7F75FFFF, x00D20096);

	vandn(x0A0A0000, a4, x5555FFFF);
	vxor(x0AD80096, x00D20096, x0A0A0000);
	vandn(x00999900, x00FFFF00, x66666666);
	vor(x0AD99996, x0AD80096, x00999900);

	vandn(x22332233, a3, x55005500);
	vxor(x257AA5F0, x5A0F5A0F, x7F75FFFF);
	vandn(x054885C0, x257AA5F0, x22332233);
	vnot(xFAB77A3F, x054885C0);
	vand(x2221EDF3, x3333FFFF, x6A21EDF3);
	vxor(xD89697CC, xFAB77A3F, x2221EDF3);
	vandn(x20, x7FA7FF69, a2);
	vxor(x21, x20, xD89697CC);
	vxor(*out3, *out3, x21);

	vxor(x05B77AC0, x00FFFF00, x054885C0);
	vor(x05F77AD6, x00D20096, x05B77AC0);
	vxor(x36C48529, x3333FFFF, x05F77AD6);
	vxor(x6391D07C, a1, x36C48529);
	vxor(xBB0747B0, xD89697CC, x6391D07C);
	vor(x00, x25202160, a2);
	vxor(x01, x00, xBB0747B0);
	vxor(*out1, *out1, x01);

	vxor(x4C460000, x3333FFFF, x7F75FFFF);
	vor(x4EDF9996, x0AD99996, x4C460000);
	vxor(x2D4E49EA, x6391D07C, x4EDF9996);
	vor(xBBFFFFB0, x00FFFF00, xBB0747B0);
	vxor(x96B1B65A, x2D4E49EA, xBBFFFFB0);
	vor(x10, x4A01CC93, a2);
	vxor(x11, x10, x96B1B65A);
	vxor(*out2, *out2, x11);

	vor(x5AFF5AFF, a5, x5A0F5A0F);
	vandn(x52B11215, x5AFF5AFF, x2D4E49EA);
	vand(x4201C010, x4A01CC93, x6391D07C);
	vxor(x10B0D205, x52B11215, x4201C010);
	vor(x30, x10B0D205, a2);
	vxor(x31, x30, x0AD99996);
	vxor(*out4, *out4, x31);
}
#else
/* s1-01753, 49 gates, 17/18 regs, 14 andn, 3/16/48/88/132 stalls, 76 biop */
MAYBE_INLINE static void
s1(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x55005500, x5A0F5A0F, x3333FFFF, x66666666, x22226666, x2D2D6969,
	    x25202160;
	vtype x00FFFF00, x33CCCC33, x4803120C, x2222FFFF, x6A21EDF3, x4A01CC93;
	vtype x5555FFFF, x7F75FFFF, x00D20096, x7FA7FF69;
	vtype x0A0A0000, x0AD80096, x00999900, x0AD99996;
	vtype x22332233, x257AA5F0, x054885C0, xFAB77A3F, x2221EDF3, xD89697CC;
	vtype x05B77AC0, x05F77AD6, x36C48529, x6391D07C, xBB0747B0;
	vtype x50064209, x55B138C9, x361685BF, x89014200, xDCB07AC9;
	vtype x33555533, xDC54BDFF, xCC00A8CC, x10B0D205;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x55005500, a1, a5);
	vxor(x5A0F5A0F, a4, x55005500);
	vor(x3333FFFF, a3, a6);
	vxor(x66666666, a1, a3);
	vand(x22226666, x3333FFFF, x66666666);
	vxor(x2D2D6969, a4, x22226666);
	vandn(x25202160, x2D2D6969, x5A0F5A0F);

	vxor(x00FFFF00, a5, a6);
	vxor(x33CCCC33, a3, x00FFFF00);
	vandn(x4803120C, x5A0F5A0F, x33CCCC33);
	vor(x2222FFFF, a6, x22226666);
	vxor(x6A21EDF3, x4803120C, x2222FFFF);
	vandn(x4A01CC93, x6A21EDF3, x25202160);

	vor(x5555FFFF, a1, a6);
	vor(x7F75FFFF, x6A21EDF3, x5555FFFF);
	vandn(x00D20096, a5, x2D2D6969);
	vxor(x7FA7FF69, x7F75FFFF, x00D20096);

	vandn(x0A0A0000, a4, x5555FFFF);
	vxor(x0AD80096, x00D20096, x0A0A0000);
	vandn(x00999900, x00FFFF00, x66666666);
	vor(x0AD99996, x0AD80096, x00999900);

	vandn(x22332233, a3, x55005500);
	vxor(x257AA5F0, x5A0F5A0F, x7F75FFFF);
	vandn(x054885C0, x257AA5F0, x22332233);
	vnot(xFAB77A3F, x054885C0);
	vand(x2221EDF3, x3333FFFF, x6A21EDF3);
	vxor(xD89697CC, xFAB77A3F, x2221EDF3);
	vandn(x20, x7FA7FF69, a2);
	vxor(x21, x20, xD89697CC);
	vxor(*out3, *out3, x21);

	vxor(x05B77AC0, x00FFFF00, x054885C0);
	vor(x05F77AD6, x00D20096, x05B77AC0);
	vxor(x36C48529, x3333FFFF, x05F77AD6);
	vxor(x6391D07C, a1, x36C48529);
	vxor(xBB0747B0, xD89697CC, x6391D07C);
	vor(x00, x25202160, a2);
	vxor(x01, x00, xBB0747B0);
	vxor(*out1, *out1, x01);

	vandn(x50064209, x5A0F5A0F, x0AD99996);
	vxor(x55B138C9, x05B77AC0, x50064209);
	vxor(x361685BF, x00D20096, x36C48529);
	vandn(x89014200, xBB0747B0, x361685BF);
	vxor(xDCB07AC9, x55B138C9, x89014200);
	vandn(x10, a2, x4A01CC93);
	vxor(x11, x10, xDCB07AC9);
	vxor(*out2, *out2, x11);

	vxor(x33555533, x33CCCC33, x00999900);
	vxor(xDC54BDFF, x5555FFFF, x89014200);
	vandn(xCC00A8CC, xDC54BDFF, x33555533);
	vxor(x10B0D205, xDCB07AC9, xCC00A8CC);
	vor(x30, x10B0D205, a2);
	vxor(x31, x30, x0AD99996);
	vxor(*out4, *out4, x31);
}
#endif

#if andn && triop && latency <= 4
/* s2-016251, 44 gates, 14 regs, 13 andn, 1/9/22/61/108 stalls, 66 biop */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x55550000, x00AA00FF, x33BB33FF;
	vtype x33CC0000, x11441144, x11BB11BB, x003311BB;
	vtype x00000F0F, x336600FF, x332200FF, x332200F0;
	vtype x0302000F, xAAAAAAAA, xA9A8AAA5, x33CCCC33, x33CCC030, x9A646A95;
	vtype x00333303, x118822B8, xA8208805, x3CC3C33C, x94E34B39;
	vtype x0331330C, x3FF3F33C, xA9DF596A, xA9DF5F6F, x962CAC53;
	vtype x0A042084, x12752248, x1A7522CC, x00301083, x1A45324F;
	vtype x0A451047, xBBDFDD7B, xB19ACD3C;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vandn(x55550000, a1, a6);
	vandn(x00AA00FF, a5, x55550000);
	vor(x33BB33FF, a2, x00AA00FF);

	vandn(x33CC0000, x33CC33CC, a6);
	vand(x11441144, a1, x33CC33CC);
	vxor(x11BB11BB, a5, x11441144);
	vandn(x003311BB, x11BB11BB, x33CC0000);

	vand(x00000F0F, a3, a6);
	vxor(x336600FF, x00AA00FF, x33CC0000);
	vand(x332200FF, x33BB33FF, x336600FF);
	vandn(x332200F0, x332200FF, x00000F0F);

	vand(x0302000F, a3, x332200FF);
	vnot(xAAAAAAAA, a1);
	vxor(xA9A8AAA5, x0302000F, xAAAAAAAA);
	vxor(x33CCCC33, a6, x33CC33CC);
	vandn(x33CCC030, x33CCCC33, x00000F0F);
	vxor(x9A646A95, xA9A8AAA5, x33CCC030);
	vandn(x10, a4, x332200F0);
	vxor(x11, x10, x9A646A95);
	vxor(*out2, *out2, x11);

	vandn(x00333303, a2, x33CCC030);
	vxor(x118822B8, x11BB11BB, x00333303);
	vandn(xA8208805, xA9A8AAA5, x118822B8);
	vxor(x3CC3C33C, a3, x33CCCC33);
	vxor(x94E34B39, xA8208805, x3CC3C33C);
	vandn(x00, x33BB33FF, a4);
	vxor(x01, x00, x94E34B39);
	vxor(*out1, *out1, x01);

	vxor(x0331330C, x0302000F, x00333303);
	vor(x3FF3F33C, x3CC3C33C, x0331330C);
	vxor(xA9DF596A, x33BB33FF, x9A646A95);
	vor(xA9DF5F6F, x00000F0F, xA9DF596A);
	vxor(x962CAC53, x3FF3F33C, xA9DF5F6F);

	vandn(x0A042084, x9A646A95, x94E34B39);
	vxor(x12752248, x11441144, x0331330C);
	vor(x1A7522CC, x0A042084, x12752248);
	vandn(x00301083, x003311BB, x3CC3C33C);
	vxor(x1A45324F, x1A7522CC, x00301083);
	vor(x20, x1A45324F, a4);
	vxor(x21, x20, x962CAC53);
	vxor(*out3, *out3, x21);

	vandn(x0A451047, x1A45324F, x118822B8);
	vor(xBBDFDD7B, x33CCCC33, xA9DF596A);
	vxor(xB19ACD3C, x0A451047, xBBDFDD7B);
	vor(x30, x003311BB, a4);
	vxor(x31, x30, xB19ACD3C);
	vxor(*out4, *out4, x31);
}
#elif !andn && regs >= 15
/* s2-016276, 44 gates, 15 regs, 11 andn, 1/9/24/59/104 stalls, 67 biop */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x55550000, x00AA00FF, x33BB33FF;
	vtype x33CC0000, x11441144, x11BB11BB, x003311BB;
	vtype x00000F0F, x336600FF, x332200FF, x332200F0;
	vtype x0302000F, xAAAAAAAA, xA9A8AAA5, x33CCCC33, x33CCC030, x9A646A95;
	vtype x00333303, x118822B8, xA8208805, x3CC3C33C, x94E34B39;
	vtype x0331330C, x3FF3F33C, xA9DF596A, xA9DF5F6F, x962CAC53;
	vtype xA9466A6A, x3DA52153, x29850143, x33C0330C, x1A45324F;
	vtype x0A451047, xBBDFDD7B, xB19ACD3C;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vandn(x55550000, a1, a6);
	vandn(x00AA00FF, a5, x55550000);
	vor(x33BB33FF, a2, x00AA00FF);

	vandn(x33CC0000, x33CC33CC, a6);
	vand(x11441144, a1, x33CC33CC);
	vxor(x11BB11BB, a5, x11441144);
	vandn(x003311BB, x11BB11BB, x33CC0000);

	vand(x00000F0F, a3, a6);
	vxor(x336600FF, x00AA00FF, x33CC0000);
	vand(x332200FF, x33BB33FF, x336600FF);
	vandn(x332200F0, x332200FF, x00000F0F);

	vand(x0302000F, a3, x332200FF);
	vnot(xAAAAAAAA, a1);
	vxor(xA9A8AAA5, x0302000F, xAAAAAAAA);
	vxor(x33CCCC33, a6, x33CC33CC);
	vandn(x33CCC030, x33CCCC33, x00000F0F);
	vxor(x9A646A95, xA9A8AAA5, x33CCC030);
	vandn(x10, a4, x332200F0);
	vxor(x11, x10, x9A646A95);
	vxor(*out2, *out2, x11);

	vandn(x00333303, a2, x33CCC030);
	vxor(x118822B8, x11BB11BB, x00333303);
	vandn(xA8208805, xA9A8AAA5, x118822B8);
	vxor(x3CC3C33C, a3, x33CCCC33);
	vxor(x94E34B39, xA8208805, x3CC3C33C);
	vandn(x00, x33BB33FF, a4);
	vxor(x01, x00, x94E34B39);
	vxor(*out1, *out1, x01);

	vxor(x0331330C, x0302000F, x00333303);
	vor(x3FF3F33C, x3CC3C33C, x0331330C);
	vxor(xA9DF596A, x33BB33FF, x9A646A95);
	vor(xA9DF5F6F, x00000F0F, xA9DF596A);
	vxor(x962CAC53, x3FF3F33C, xA9DF5F6F);

	vxor(xA9466A6A, x332200FF, x9A646A95);
	vxor(x3DA52153, x94E34B39, xA9466A6A);
	vand(x29850143, xA9DF5F6F, x3DA52153);
	vand(x33C0330C, x33CC33CC, x3FF3F33C);
	vxor(x1A45324F, x29850143, x33C0330C);
	vor(x20, x1A45324F, a4);
	vxor(x21, x20, x962CAC53);
	vxor(*out3, *out3, x21);

	vandn(x0A451047, x1A45324F, x118822B8);
	vor(xBBDFDD7B, x33CCCC33, xA9DF596A);
	vxor(xB19ACD3C, x0A451047, xBBDFDD7B);
	vor(x30, x003311BB, a4);
	vxor(x31, x30, xB19ACD3C);
	vxor(*out4, *out4, x31);
}
#elif andn && !triop && regs >= 15 && latency <= 2
/* s2-016277, 44 gates, 15 regs, 12 andn, 4/15/35/74/121 stalls, 65 biop */
/* Currently used for x86-64 SSE2 */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x55550000, x00AA00FF, x33BB33FF;
	vtype x33CC0000, x11441144, x11BB11BB, x003311BB;
	vtype x00000F0F, x336600FF, x332200FF, x332200F0;
	vtype x0302000F, xAAAAAAAA, xA9A8AAA5, x33CCCC33, x33CCC030, x9A646A95;
	vtype x00333303, x118822B8, xA8208805, x3CC3C33C, x94E34B39;
	vtype x0331330C, x3FF3F33C, xA9DF596A, xA9DF5F6F, x962CAC53;
	vtype x97D27835, x81D25825, x812D58DA, x802158DA, x1A45324F;
	vtype x0A451047, xBBDFDD7B, xB19ACD3C;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vandn(x55550000, a1, a6);
	vandn(x00AA00FF, a5, x55550000);
	vor(x33BB33FF, a2, x00AA00FF);

	vandn(x33CC0000, x33CC33CC, a6);
	vand(x11441144, a1, x33CC33CC);
	vxor(x11BB11BB, a5, x11441144);
	vandn(x003311BB, x11BB11BB, x33CC0000);

	vand(x00000F0F, a3, a6);
	vxor(x336600FF, x00AA00FF, x33CC0000);
	vand(x332200FF, x33BB33FF, x336600FF);
	vandn(x332200F0, x332200FF, x00000F0F);

	vand(x0302000F, a3, x332200FF);
	vnot(xAAAAAAAA, a1);
	vxor(xA9A8AAA5, x0302000F, xAAAAAAAA);
	vxor(x33CCCC33, a6, x33CC33CC);
	vandn(x33CCC030, x33CCCC33, x00000F0F);
	vxor(x9A646A95, xA9A8AAA5, x33CCC030);
	vandn(x10, a4, x332200F0);
	vxor(x11, x10, x9A646A95);
	vxor(*out2, *out2, x11);

	vandn(x00333303, a2, x33CCC030);
	vxor(x118822B8, x11BB11BB, x00333303);
	vandn(xA8208805, xA9A8AAA5, x118822B8);
	vxor(x3CC3C33C, a3, x33CCCC33);
	vxor(x94E34B39, xA8208805, x3CC3C33C);
	vandn(x00, x33BB33FF, a4);
	vxor(x01, x00, x94E34B39);
	vxor(*out1, *out1, x01);

	vxor(x0331330C, x0302000F, x00333303);
	vor(x3FF3F33C, x3CC3C33C, x0331330C);
	vxor(xA9DF596A, x33BB33FF, x9A646A95);
	vor(xA9DF5F6F, x00000F0F, xA9DF596A);
	vxor(x962CAC53, x3FF3F33C, xA9DF5F6F);

	vxor(x97D27835, x94E34B39, x0331330C);
	vand(x81D25825, xA9DF5F6F, x97D27835);
	vxor(x812D58DA, a5, x81D25825);
	vandn(x802158DA, x812D58DA, x33CC0000);
	vxor(x1A45324F, x9A646A95, x802158DA);
	vor(x20, x1A45324F, a4);
	vxor(x21, x20, x962CAC53);
	vxor(*out3, *out3, x21);

	vandn(x0A451047, x1A45324F, x118822B8);
	vor(xBBDFDD7B, x33CCCC33, xA9DF596A);
	vxor(xB19ACD3C, x0A451047, xBBDFDD7B);
	vor(x30, x003311BB, a4);
	vxor(x31, x30, xB19ACD3C);
	vxor(*out4, *out4, x31);
}
#elif !andn || (triop && latency >= 5)
/* s2-016380, 44 gates, 14/15 regs, 12 andn, 1/9/27/55/99 stalls, 68 biop */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x55550000, x00AA00FF, x33BB33FF;
	vtype x33CC0000, x11441144, x11BB11BB, x003311BB;
	vtype x00000F0F, x336600FF, x332200FF, x332200F0;
	vtype x0302000F, xAAAAAAAA, xA9A8AAA5, x33CCCC33, x33CCC030, x9A646A95;
	vtype x00333303, x118822B8, xA8208805, x3CC3C33C, x94E34B39;
	vtype x33333030, x3FF3F33C, xA9DF596A, xA9DF5F6F, x962CAC53;
	vtype xA9466A6A, x3DA52153, x29850143, x33C0330C, x1A45324F;
	vtype x0A451047, xBBDFDD7B, xB19ACD3C;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vandn(x55550000, a1, a6);
	vandn(x00AA00FF, a5, x55550000);
	vor(x33BB33FF, a2, x00AA00FF);

	vandn(x33CC0000, x33CC33CC, a6);
	vand(x11441144, a1, x33CC33CC);
	vxor(x11BB11BB, a5, x11441144);
	vandn(x003311BB, x11BB11BB, x33CC0000);

	vand(x00000F0F, a3, a6);
	vxor(x336600FF, x00AA00FF, x33CC0000);
	vand(x332200FF, x33BB33FF, x336600FF);
	vandn(x332200F0, x332200FF, x00000F0F);

	vand(x0302000F, a3, x332200FF);
	vnot(xAAAAAAAA, a1);
	vxor(xA9A8AAA5, x0302000F, xAAAAAAAA);
	vxor(x33CCCC33, a6, x33CC33CC);
	vandn(x33CCC030, x33CCCC33, x00000F0F);
	vxor(x9A646A95, xA9A8AAA5, x33CCC030);
	vandn(x10, a4, x332200F0);
	vxor(x11, x10, x9A646A95);
	vxor(*out2, *out2, x11);

	vandn(x00333303, a2, x33CCC030);
	vxor(x118822B8, x11BB11BB, x00333303);
	vandn(xA8208805, xA9A8AAA5, x118822B8);
	vxor(x3CC3C33C, a3, x33CCCC33);
	vxor(x94E34B39, xA8208805, x3CC3C33C);
	vandn(x00, x33BB33FF, a4);
	vxor(x01, x00, x94E34B39);
	vxor(*out1, *out1, x01);

	vandn(x33333030, a2, x00000F0F);
	vor(x3FF3F33C, x3CC3C33C, x33333030);
	vxor(xA9DF596A, x33BB33FF, x9A646A95);
	vor(xA9DF5F6F, x00000F0F, xA9DF596A);
	vxor(x962CAC53, x3FF3F33C, xA9DF5F6F);

	vxor(xA9466A6A, x332200FF, x9A646A95);
	vxor(x3DA52153, x94E34B39, xA9466A6A);
	vand(x29850143, xA9DF5F6F, x3DA52153);
	vand(x33C0330C, x33CC33CC, x3FF3F33C);
	vxor(x1A45324F, x29850143, x33C0330C);
	vor(x20, x1A45324F, a4);
	vxor(x21, x20, x962CAC53);
	vxor(*out3, *out3, x21);

	vandn(x0A451047, x1A45324F, x118822B8);
	vor(xBBDFDD7B, x33CCCC33, xA9DF596A);
	vxor(xB19ACD3C, x0A451047, xBBDFDD7B);
	vor(x30, x003311BB, a4);
	vxor(x31, x30, xB19ACD3C);
	vxor(*out4, *out4, x31);
}
#else
/* s2-016520, 44 gates, 15 regs, 13 andn, 5/17/41/78/125 stalls, 68 biop */
/* Currently used for MMX/SSE2 */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x55550000, x00AA00FF, x33BB33FF;
	vtype x33CC0000, x11441144, x11BB11BB, x003311BB;
	vtype x00000F0F, x336600FF, x332200FF, x332200F0;
	vtype x0302000F, xAAAAAAAA, xA9A8AAA5, x33CCCC33, x33CCC030, x9A646A95;
	vtype x00333303, x118822B8, xA8208805, x3CC3C33C, x94E34B39;
	vtype x03303003, xA9DF596A, xAAEF6969, xAAEF6F6F, x962CAC53;
	vtype x0903030C, x093012B7, x19B832BF, x03FD00F0, x1A45324F;
	vtype x0A451047, xBBDFDD7B, xB19ACD3C;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vandn(x55550000, a1, a6);
	vandn(x00AA00FF, a5, x55550000);
	vor(x33BB33FF, a2, x00AA00FF);

	vandn(x33CC0000, x33CC33CC, a6);
	vand(x11441144, a1, x33CC33CC);
	vxor(x11BB11BB, a5, x11441144);
	vandn(x003311BB, x11BB11BB, x33CC0000);

	vand(x00000F0F, a3, a6);
	vxor(x336600FF, x00AA00FF, x33CC0000);
	vand(x332200FF, x33BB33FF, x336600FF);
	vandn(x332200F0, x332200FF, x00000F0F);

	vand(x0302000F, a3, x332200FF);
	vnot(xAAAAAAAA, a1);
	vxor(xA9A8AAA5, x0302000F, xAAAAAAAA);
	vxor(x33CCCC33, a6, x33CC33CC);
	vandn(x33CCC030, x33CCCC33, x00000F0F);
	vxor(x9A646A95, xA9A8AAA5, x33CCC030);
	vandn(x10, a4, x332200F0);
	vxor(x11, x10, x9A646A95);
	vxor(*out2, *out2, x11);

	vandn(x00333303, a2, x33CCC030);
	vxor(x118822B8, x11BB11BB, x00333303);
	vandn(xA8208805, xA9A8AAA5, x118822B8);
	vxor(x3CC3C33C, a3, x33CCCC33);
	vxor(x94E34B39, xA8208805, x3CC3C33C);
	vandn(x00, x33BB33FF, a4);
	vxor(x01, x00, x94E34B39);
	vxor(*out1, *out1, x01);

	vandn(x03303003, a2, x3CC3C33C);
	vxor(xA9DF596A, x33BB33FF, x9A646A95);
	vxor(xAAEF6969, x03303003, xA9DF596A);
	vor(xAAEF6F6F, x00000F0F, xAAEF6969);
	vxor(x962CAC53, x3CC3C33C, xAAEF6F6F);

	vandn(x0903030C, a3, x962CAC53);
	vxor(x093012B7, x003311BB, x0903030C);
	vor(x19B832BF, x118822B8, x093012B7);
	vxor(x03FD00F0, a5, x0302000F);
	vxor(x1A45324F, x19B832BF, x03FD00F0);
	vor(x20, x1A45324F, a4);
	vxor(x21, x20, x962CAC53);
	vxor(*out3, *out3, x21);

	vandn(x0A451047, x1A45324F, x118822B8);
	vor(xBBDFDD7B, x33CCCC33, xA9DF596A);
	vxor(xB19ACD3C, x0A451047, xBBDFDD7B);
	vor(x30, x003311BB, a4);
	vxor(x31, x30, xB19ACD3C);
	vxor(*out4, *out4, x31);
}
#endif

#if andn && !triop && regs < 16
/* s3-000406, 46 gates, 15 regs, 12 andn, 3/7/19/50/89 stalls, 70 biop */
/* Currently used for MMX/SSE2 */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44444444, x0F0FF0F0, x4F4FF4F4, x00FFFF00, x00AAAA00, x4FE55EF4;
	vtype x3C3CC3C3, x3C3C0000, x7373F4F4, x0C840A00;
	vtype x00005EF4, x00FF5EFF, x00555455, x3C699796;
	vtype x000FF000, x55AA55AA, x26D9A15E, x2FDFAF5F, x2FD00F5F;
	vtype x55AAFFAA, x28410014, x000000FF, x000000CC, x284100D8;
	vtype x204000D0, x3C3CC3FF, x1C3CC32F, x4969967A;
	vtype x3F3F3F3F, x40C040C0, x69963C69, x9669C396, xD6A98356;
	vtype x7A855A0A, xFEEDDB9E, xB108856A, x8D6112FC, xB25E2DC3;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x44444444, a1, a2);
	vxor(x0F0FF0F0, a3, a6);
	vor(x4F4FF4F4, x44444444, x0F0FF0F0);
	vxor(x00FFFF00, a4, a6);
	vandn(x00AAAA00, x00FFFF00, a1);
	vxor(x4FE55EF4, x4F4FF4F4, x00AAAA00);

	vxor(x3C3CC3C3, a2, x0F0FF0F0);
	vandn(x3C3C0000, x3C3CC3C3, a6);
	vxor(x7373F4F4, x4F4FF4F4, x3C3C0000);
	vandn(x0C840A00, x4FE55EF4, x7373F4F4);

	vand(x00005EF4, a6, x4FE55EF4);
	vor(x00FF5EFF, a4, x00005EF4);
	vand(x00555455, a1, x00FF5EFF);
	vxor(x3C699796, x3C3CC3C3, x00555455);
	vandn(x30, x4FE55EF4, a5);
	vxor(x31, x30, x3C699796);
	vxor(*out4, *out4, x31);

	vand(x000FF000, x0F0FF0F0, x00FFFF00);
	vxor(x55AA55AA, a1, a4);
	vxor(x26D9A15E, x7373F4F4, x55AA55AA);
	vor(x2FDFAF5F, a3, x26D9A15E);
	vandn(x2FD00F5F, x2FDFAF5F, x000FF000);

	vor(x55AAFFAA, x00AAAA00, x55AA55AA);
	vandn(x28410014, x3C699796, x55AAFFAA);
	vand(x000000FF, a4, a6);
	vandn(x000000CC, x000000FF, a2);
	vxor(x284100D8, x28410014, x000000CC);

	vandn(x204000D0, x284100D8, a3);
	vor(x3C3CC3FF, x3C3CC3C3, x000000FF);
	vandn(x1C3CC32F, x3C3CC3FF, x204000D0);
	vxor(x4969967A, a1, x1C3CC32F);
	vand(x10, x2FD00F5F, a5);
	vxor(x11, x10, x4969967A);
	vxor(*out2, *out2, x11);

	vor(x3F3F3F3F, a2, a3);
	vandn(x40C040C0, x4FE55EF4, x3F3F3F3F);
	vxor(x69963C69, x3C3CC3C3, x55AAFFAA);
	vnot(x9669C396, x69963C69);
	vxor(xD6A98356, x40C040C0, x9669C396);
	vandn(x00, a5, x0C840A00);
	vxor(x01, x00, xD6A98356);
	vxor(*out1, *out1, x01);

	vxor(x7A855A0A, a1, x2FD00F5F);
	vor(xFEEDDB9E, x9669C396, x7A855A0A);
	vxor(xB108856A, x4FE55EF4, xFEEDDB9E);
	vxor(x8D6112FC, x3C699796, xB108856A);
	vxor(xB25E2DC3, x3F3F3F3F, x8D6112FC);
	vor(x20, x284100D8, a5);
	vxor(x21, x20, xB25E2DC3);
	vxor(*out3, *out3, x21);
}
#elif andn && !triop && regs >= 16
/* s3-000426, 46 gates, 16 regs, 14 andn, 2/5/12/35/75 stalls, 68 biop */
/* Currently used for x86-64 SSE2 */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44444444, x0F0FF0F0, x4F4FF4F4, x00FFFF00, x00AAAA00, x4FE55EF4;
	vtype x3C3CC3C3, x3C3C0000, x7373F4F4, x0C840A00;
	vtype x00005EF4, x00FF5EFF, x00555455, x3C699796;
	vtype x000FF000, x55AA55AA, x26D9A15E, x2FDFAF5F, x2FD00F5F;
	vtype x55AAFFAA, x28410014, x000000FF, x000000CC, x284100D8;
	vtype x204000D0, x3C3CC3FF, x1C3CC32F, x4969967A;
	vtype x4CC44CC4, x40C040C0, x69963C69, x9669C396, xD6A98356;
	vtype x000F00F0, xFEBDC3D7, xFEB0C307, x4CEEEEC4, xB25E2DC3;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x44444444, a1, a2);
	vxor(x0F0FF0F0, a3, a6);
	vor(x4F4FF4F4, x44444444, x0F0FF0F0);
	vxor(x00FFFF00, a4, a6);
	vandn(x00AAAA00, x00FFFF00, a1);
	vxor(x4FE55EF4, x4F4FF4F4, x00AAAA00);

	vxor(x3C3CC3C3, a2, x0F0FF0F0);
	vandn(x3C3C0000, x3C3CC3C3, a6);
	vxor(x7373F4F4, x4F4FF4F4, x3C3C0000);
	vandn(x0C840A00, x4FE55EF4, x7373F4F4);

	vand(x00005EF4, a6, x4FE55EF4);
	vor(x00FF5EFF, a4, x00005EF4);
	vand(x00555455, a1, x00FF5EFF);
	vxor(x3C699796, x3C3CC3C3, x00555455);
	vandn(x30, x4FE55EF4, a5);
	vxor(x31, x30, x3C699796);
	vxor(*out4, *out4, x31);

	vand(x000FF000, x0F0FF0F0, x00FFFF00);
	vxor(x55AA55AA, a1, a4);
	vxor(x26D9A15E, x7373F4F4, x55AA55AA);
	vor(x2FDFAF5F, a3, x26D9A15E);
	vandn(x2FD00F5F, x2FDFAF5F, x000FF000);

	vor(x55AAFFAA, x00AAAA00, x55AA55AA);
	vandn(x28410014, x3C699796, x55AAFFAA);
	vand(x000000FF, a4, a6);
	vandn(x000000CC, x000000FF, a2);
	vxor(x284100D8, x28410014, x000000CC);

	vandn(x204000D0, x284100D8, a3);
	vor(x3C3CC3FF, x3C3CC3C3, x000000FF);
	vandn(x1C3CC32F, x3C3CC3FF, x204000D0);
	vxor(x4969967A, a1, x1C3CC32F);
	vand(x10, x2FD00F5F, a5);
	vxor(x11, x10, x4969967A);
	vxor(*out2, *out2, x11);

	vandn(x4CC44CC4, x4FE55EF4, a2);
	vandn(x40C040C0, x4CC44CC4, a3);
	vxor(x69963C69, x3C3CC3C3, x55AAFFAA);
	vnot(x9669C396, x69963C69);
	vxor(xD6A98356, x40C040C0, x9669C396);
	vandn(x00, a5, x0C840A00);
	vxor(x01, x00, xD6A98356);
	vxor(*out1, *out1, x01);

	vand(x000F00F0, a4, x0F0FF0F0);
	vor(xFEBDC3D7, x3C3CC3C3, xD6A98356);
	vandn(xFEB0C307, xFEBDC3D7, x000F00F0);
	vor(x4CEEEEC4, x00AAAA00, x4CC44CC4);
	vxor(xB25E2DC3, xFEB0C307, x4CEEEEC4);
	vor(x20, x284100D8, a5);
	vxor(x21, x20, xB25E2DC3);
	vxor(*out3, *out3, x21);
}
#elif andn && triop && !(regs >= 17 && latency == 3)
/* s3-000470, 46 gates, 15 regs, 15 andn, 2/5/10/30/69 stalls, 69 biop */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44444444, x0F0FF0F0, x4F4FF4F4, x00FFFF00, x00AAAA00, x4FE55EF4;
	vtype x3C3CC3C3, x3C3C0000, x7373F4F4, x0C840A00;
	vtype x00005EF4, x00FF5EFF, x00555455, x3C699796;
	vtype x000FF000, x55AA55AA, x26D9A15E, x2FDFAF5F, x2FD00F5F;
	vtype x55AAFFAA, x28410014, x000000FF, x000000CC, x284100D8;
	vtype x204000D0, x3C3CC3FF, x1C3CC32F, x4969967A;
	vtype x4CC44CC4, x40C040C0, xC3C33C3C, x9669C396, xD6A98356;
	vtype xD6E9C3D6, x4CEEEEC4, x9A072D12, x001A000B, x9A1F2D1B;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x44444444, a1, a2);
	vxor(x0F0FF0F0, a3, a6);
	vor(x4F4FF4F4, x44444444, x0F0FF0F0);
	vxor(x00FFFF00, a4, a6);
	vandn(x00AAAA00, x00FFFF00, a1);
	vxor(x4FE55EF4, x4F4FF4F4, x00AAAA00);

	vxor(x3C3CC3C3, a2, x0F0FF0F0);
	vandn(x3C3C0000, x3C3CC3C3, a6);
	vxor(x7373F4F4, x4F4FF4F4, x3C3C0000);
	vandn(x0C840A00, x4FE55EF4, x7373F4F4);

	vand(x00005EF4, a6, x4FE55EF4);
	vor(x00FF5EFF, a4, x00005EF4);
	vand(x00555455, a1, x00FF5EFF);
	vxor(x3C699796, x3C3CC3C3, x00555455);
	vandn(x30, x4FE55EF4, a5);
	vxor(x31, x30, x3C699796);
	vxor(*out4, *out4, x31);

	vand(x000FF000, x0F0FF0F0, x00FFFF00);
	vxor(x55AA55AA, a1, a4);
	vxor(x26D9A15E, x7373F4F4, x55AA55AA);
	vor(x2FDFAF5F, a3, x26D9A15E);
	vandn(x2FD00F5F, x2FDFAF5F, x000FF000);

	vor(x55AAFFAA, x00AAAA00, x55AA55AA);
	vandn(x28410014, x3C699796, x55AAFFAA);
	vand(x000000FF, a4, a6);
	vandn(x000000CC, x000000FF, a2);
	vxor(x284100D8, x28410014, x000000CC);

	vandn(x204000D0, x284100D8, a3);
	vor(x3C3CC3FF, x3C3CC3C3, x000000FF);
	vandn(x1C3CC32F, x3C3CC3FF, x204000D0);
	vxor(x4969967A, a1, x1C3CC32F);
	vand(x10, x2FD00F5F, a5);
	vxor(x11, x10, x4969967A);
	vxor(*out2, *out2, x11);

	vandn(x4CC44CC4, x4FE55EF4, a2);
	vandn(x40C040C0, x4CC44CC4, a3);
	vnot(xC3C33C3C, x3C3CC3C3);
	vxor(x9669C396, x55AAFFAA, xC3C33C3C);
	vxor(xD6A98356, x40C040C0, x9669C396);
	vandn(x00, a5, x0C840A00);
	vxor(x01, x00, xD6A98356);
	vxor(*out1, *out1, x01);

	vor(xD6E9C3D6, x40C040C0, x9669C396);
	vor(x4CEEEEC4, x00AAAA00, x4CC44CC4);
	vxor(x9A072D12, xD6E9C3D6, x4CEEEEC4);
	vandn(x001A000B, a4, x4FE55EF4);
	vor(x9A1F2D1B, x9A072D12, x001A000B);
	vandn(x20, a5, x284100D8);
	vxor(x21, x20, x9A1F2D1B);
	vxor(*out3, *out3, x21);
}
#elif !andn && triop && regs >= 17 && latency >= 4
/* s3-001117, 46 gates, 17 regs, 10 andn, 2/4/19/47/92 stalls, 69 biop */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44444444, x0F0FF0F0, x4F4FF4F4, x00FFFF00, x00AAAA00, x4FE55EF4;
	vtype x3C3CC3C3, x3C3C0000, x7373F4F4, x0C840A00;
	vtype x00005EF4, x00FF5EFF, x00555455, x3C699796;
	vtype x000FF000, x55AA55AA, x26D9A15E, x2FDFAF5F, x2FD00F5F;
	vtype x55AAFFAA, x28410014, x000000FF, x000000CC, x284100D8;
	vtype x204100D0, x3C3CC3FF, x1C3CC32F, x4969967A;
	vtype x3F3F3F3F, xB01AA10B, xBF3FBF3F, x83037CFC, xD6A98356;
	vtype x001A000B, x3C73979D, xBF73FFFD, x0D2DD23E, xB25E2DC3;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x44444444, a1, a2);
	vxor(x0F0FF0F0, a3, a6);
	vor(x4F4FF4F4, x44444444, x0F0FF0F0);
	vxor(x00FFFF00, a4, a6);
	vandn(x00AAAA00, x00FFFF00, a1);
	vxor(x4FE55EF4, x4F4FF4F4, x00AAAA00);

	vxor(x3C3CC3C3, a2, x0F0FF0F0);
	vandn(x3C3C0000, x3C3CC3C3, a6);
	vxor(x7373F4F4, x4F4FF4F4, x3C3C0000);
	vandn(x0C840A00, x4FE55EF4, x7373F4F4);

	vand(x00005EF4, a6, x4FE55EF4);
	vor(x00FF5EFF, a4, x00005EF4);
	vand(x00555455, a1, x00FF5EFF);
	vxor(x3C699796, x3C3CC3C3, x00555455);
	vandn(x30, x4FE55EF4, a5);
	vxor(x31, x30, x3C699796);
	vxor(*out4, *out4, x31);

	vand(x000FF000, x0F0FF0F0, x00FFFF00);
	vxor(x55AA55AA, a1, a4);
	vxor(x26D9A15E, x7373F4F4, x55AA55AA);
	vor(x2FDFAF5F, a3, x26D9A15E);
	vandn(x2FD00F5F, x2FDFAF5F, x000FF000);

	vor(x55AAFFAA, x00AAAA00, x55AA55AA);
	vandn(x28410014, x3C699796, x55AAFFAA);
	vand(x000000FF, a4, a6);
	vandn(x000000CC, x000000FF, a2);
	vxor(x284100D8, x28410014, x000000CC);

	vand(x204100D0, x7373F4F4, x284100D8);
	vor(x3C3CC3FF, x3C3CC3C3, x000000FF);
	vandn(x1C3CC32F, x3C3CC3FF, x204100D0);
	vxor(x4969967A, a1, x1C3CC32F);
	vand(x10, x2FD00F5F, a5);
	vxor(x11, x10, x4969967A);
	vxor(*out2, *out2, x11);

	vor(x3F3F3F3F, a2, a3);
	vnot(xB01AA10B, x4FE55EF4);
	vor(xBF3FBF3F, x3F3F3F3F, xB01AA10B);
	vxor(x83037CFC, x3C3CC3C3, xBF3FBF3F);
	vxor(xD6A98356, x55AAFFAA, x83037CFC);
	vandn(x00, a5, x0C840A00);
	vxor(x01, x00, xD6A98356);
	vxor(*out1, *out1, x01);

	vand(x001A000B, a4, xB01AA10B);
	vxor(x3C73979D, x3C699796, x001A000B);
	vor(xBF73FFFD, x83037CFC, x3C73979D);
	vxor(x0D2DD23E, x44444444, x4969967A);
	vxor(xB25E2DC3, xBF73FFFD, x0D2DD23E);
	vor(x20, x284100D8, a5);
	vxor(x21, x20, xB25E2DC3);
	vxor(*out3, *out3, x21);
}
#elif triop && regs >= 17 && latency <= 3
/* s3-001172, 46 gates, 17 regs, 10 andn, 2/3/19/55/98 stalls, 69 biop */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44444444, x0F0FF0F0, x4F4FF4F4, x00FFFF00, x00AAAA00, x4FE55EF4;
	vtype x3C3CC3C3, x3C3C0000, x7373F4F4, x0C840A00;
	vtype x00005EF4, x00FF5EFF, x00555455, x3C699796;
	vtype x000FF000, x55AA55AA, x26D9A15E, x2FDFAF5F, x2FD00F5F;
	vtype x55AAFFAA, x28410014, x000000FF, x000000CC, x284100D8;
	vtype x204100D0, x3C3CC3FF, x1C3CC32F, x4969967A;
	vtype xB01AA10B, xB33BB33B, xBF3FBF3F, x83037CFC, xD6A98356;
	vtype x001A000B, x3C73979D, xBF73FFFD, x0D2DD23E, xB25E2DC3;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x44444444, a1, a2);
	vxor(x0F0FF0F0, a3, a6);
	vor(x4F4FF4F4, x44444444, x0F0FF0F0);
	vxor(x00FFFF00, a4, a6);
	vandn(x00AAAA00, x00FFFF00, a1);
	vxor(x4FE55EF4, x4F4FF4F4, x00AAAA00);

	vxor(x3C3CC3C3, a2, x0F0FF0F0);
	vandn(x3C3C0000, x3C3CC3C3, a6);
	vxor(x7373F4F4, x4F4FF4F4, x3C3C0000);
	vandn(x0C840A00, x4FE55EF4, x7373F4F4);

	vand(x00005EF4, a6, x4FE55EF4);
	vor(x00FF5EFF, a4, x00005EF4);
	vand(x00555455, a1, x00FF5EFF);
	vxor(x3C699796, x3C3CC3C3, x00555455);
	vandn(x30, x4FE55EF4, a5);
	vxor(x31, x30, x3C699796);
	vxor(*out4, *out4, x31);

	vand(x000FF000, x0F0FF0F0, x00FFFF00);
	vxor(x55AA55AA, a1, a4);
	vxor(x26D9A15E, x7373F4F4, x55AA55AA);
	vor(x2FDFAF5F, a3, x26D9A15E);
	vandn(x2FD00F5F, x2FDFAF5F, x000FF000);

	vor(x55AAFFAA, x00AAAA00, x55AA55AA);
	vandn(x28410014, x3C699796, x55AAFFAA);
	vand(x000000FF, a4, a6);
	vandn(x000000CC, x000000FF, a2);
	vxor(x284100D8, x28410014, x000000CC);

	vand(x204100D0, x7373F4F4, x284100D8);
	vor(x3C3CC3FF, x3C3CC3C3, x000000FF);
	vandn(x1C3CC32F, x3C3CC3FF, x204100D0);
	vxor(x4969967A, a1, x1C3CC32F);
	vand(x10, x2FD00F5F, a5);
	vxor(x11, x10, x4969967A);
	vxor(*out2, *out2, x11);

	vnot(xB01AA10B, x4FE55EF4);
	vor(xB33BB33B, a2, xB01AA10B);
	vor(xBF3FBF3F, a3, xB33BB33B);
	vxor(x83037CFC, x3C3CC3C3, xBF3FBF3F);
	vxor(xD6A98356, x55AAFFAA, x83037CFC);
	vandn(x00, a5, x0C840A00);
	vxor(x01, x00, xD6A98356);
	vxor(*out1, *out1, x01);

	vand(x001A000B, a4, xB01AA10B);
	vxor(x3C73979D, x3C699796, x001A000B);
	vor(xBF73FFFD, x83037CFC, x3C73979D);
	vxor(x0D2DD23E, x44444444, x4969967A);
	vxor(xB25E2DC3, xBF73FFFD, x0D2DD23E);
	vor(x20, x284100D8, a5);
	vxor(x21, x20, xB25E2DC3);
	vxor(*out3, *out3, x21);
}
#else
/* s3-001283, 46 gates, 16 regs, 14 andn, 2/5/10/30/69 stalls, 69 biop */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44444444, x0F0FF0F0, x4F4FF4F4, x00FFFF00, x00AAAA00, x4FE55EF4;
	vtype x3C3CC3C3, x3C3C0000, x7373F4F4, x0C840A00;
	vtype x00005EF4, x00FF5EFF, x00555455, x3C699796;
	vtype x000FF000, x55AA55AA, x26D9A15E, x2FDFAF5F, x2FD00F5F;
	vtype x55AAFFAA, x28410014, x000000FF, x000000CC, x284100D8;
	vtype x204100D0, x3C3CC3FF, x1C3CC32F, x4969967A;
	vtype x4CC44CC4, x40C040C0, xC3C33C3C, x9669C396, xD6A98356;
	vtype xD6E9C3D6, x4CEEEEC4, x9A072D12, x001A000B, x9A1F2D1B;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x44444444, a1, a2);
	vxor(x0F0FF0F0, a3, a6);
	vor(x4F4FF4F4, x44444444, x0F0FF0F0);
	vxor(x00FFFF00, a4, a6);
	vandn(x00AAAA00, x00FFFF00, a1);
	vxor(x4FE55EF4, x4F4FF4F4, x00AAAA00);

	vxor(x3C3CC3C3, a2, x0F0FF0F0);
	vandn(x3C3C0000, x3C3CC3C3, a6);
	vxor(x7373F4F4, x4F4FF4F4, x3C3C0000);
	vandn(x0C840A00, x4FE55EF4, x7373F4F4);

	vand(x00005EF4, a6, x4FE55EF4);
	vor(x00FF5EFF, a4, x00005EF4);
	vand(x00555455, a1, x00FF5EFF);
	vxor(x3C699796, x3C3CC3C3, x00555455);
	vandn(x30, x4FE55EF4, a5);
	vxor(x31, x30, x3C699796);
	vxor(*out4, *out4, x31);

	vand(x000FF000, x0F0FF0F0, x00FFFF00);
	vxor(x55AA55AA, a1, a4);
	vxor(x26D9A15E, x7373F4F4, x55AA55AA);
	vor(x2FDFAF5F, a3, x26D9A15E);
	vandn(x2FD00F5F, x2FDFAF5F, x000FF000);

	vor(x55AAFFAA, x00AAAA00, x55AA55AA);
	vandn(x28410014, x3C699796, x55AAFFAA);
	vand(x000000FF, a4, a6);
	vandn(x000000CC, x000000FF, a2);
	vxor(x284100D8, x28410014, x000000CC);

	vand(x204100D0, x7373F4F4, x284100D8);
	vor(x3C3CC3FF, x3C3CC3C3, x000000FF);
	vandn(x1C3CC32F, x3C3CC3FF, x204100D0);
	vxor(x4969967A, a1, x1C3CC32F);
	vand(x10, x2FD00F5F, a5);
	vxor(x11, x10, x4969967A);
	vxor(*out2, *out2, x11);

	vandn(x4CC44CC4, x4FE55EF4, a2);
	vandn(x40C040C0, x4CC44CC4, a3);
	vnot(xC3C33C3C, x3C3CC3C3);
	vxor(x9669C396, x55AAFFAA, xC3C33C3C);
	vxor(xD6A98356, x40C040C0, x9669C396);
	vandn(x00, a5, x0C840A00);
	vxor(x01, x00, xD6A98356);
	vxor(*out1, *out1, x01);

	vor(xD6E9C3D6, x40C040C0, x9669C396);
	vor(x4CEEEEC4, x00AAAA00, x4CC44CC4);
	vxor(x9A072D12, xD6E9C3D6, x4CEEEEC4);
	vandn(x001A000B, a4, x4FE55EF4);
	vor(x9A1F2D1B, x9A072D12, x001A000B);
	vandn(x20, a5, x284100D8);
	vxor(x21, x20, x9A1F2D1B);
	vxor(*out3, *out3, x21);
}
#endif

/* s4, 33 gates, 11/12 regs, 9 andn, 2/21/53/86/119 stalls, 52 biop */
MAYBE_INLINE static void
s4(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x5A5A5A5A, x0F0FF0F0;
	vtype x33FF33FF, x33FFCC00, x0C0030F0, x0C0CC0C0, x0CF3C03F, x5EFBDA7F,
	    x52FBCA0F, x61C8F93C;
	vtype x00C0C03C, x0F0F30C0, x3B92A366, x30908326, x3C90B3D6;
	vtype x33CC33CC, x0C0CFFFF, x379E5C99, x04124C11, x56E9861E, xA91679E1;
	vtype x9586CA37, x8402C833, x84C2C83F, xB35C94A6;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x5A5A5A5A, a1, a3);
	vxor(x0F0FF0F0, a3, a5);
	vor(x33FF33FF, a2, a4);
	vxor(x33FFCC00, a5, x33FF33FF);
	vandn(x0C0030F0, x0F0FF0F0, x33FFCC00);
	vandn(x0C0CC0C0, x0F0FF0F0, a2);
	vxor(x0CF3C03F, a4, x0C0CC0C0);
	vor(x5EFBDA7F, x5A5A5A5A, x0CF3C03F);
	vandn(x52FBCA0F, x5EFBDA7F, x0C0030F0);
	vxor(x61C8F93C, a2, x52FBCA0F);

	vand(x00C0C03C, x0CF3C03F, x61C8F93C);
	vandn(x0F0F30C0, x0F0FF0F0, x00C0C03C);
	vxor(x3B92A366, x5A5A5A5A, x61C8F93C);
	vandn(x30908326, x3B92A366, x0F0F30C0);
	vxor(x3C90B3D6, x0C0030F0, x30908326);

	vxor(x33CC33CC, a2, a4);
	vor(x0C0CFFFF, a5, x0C0CC0C0);
	vxor(x379E5C99, x3B92A366, x0C0CFFFF);
	vandn(x04124C11, x379E5C99, x33CC33CC);
	vxor(x56E9861E, x52FBCA0F, x04124C11);
	vandn(x00, a6, x3C90B3D6);
	vxor(x01, x00, x56E9861E);
	vxor(*out1, *out1, x01);

	vnot(xA91679E1, x56E9861E);
	vandn(x10, x3C90B3D6, a6);
	vxor(x11, x10, xA91679E1);
	vxor(*out2, *out2, x11);

	vxor(x9586CA37, x3C90B3D6, xA91679E1);
	vandn(x8402C833, x9586CA37, x33CC33CC);
	vor(x84C2C83F, x00C0C03C, x8402C833);
	vxor(xB35C94A6, x379E5C99, x84C2C83F);
	vor(x20, x61C8F93C, a6);
	vxor(x21, x20, xB35C94A6);
	vxor(*out3, *out3, x21);

	vand(x30, a6, x61C8F93C);
	vxor(x31, x30, xB35C94A6);
	vxor(*out4, *out4, x31);
}

#if triop && latency >= 3 && latency <= 5
/* s5-02432, 48 gates, 15/16 regs, 9 andn, 6/22/61/109/160 stalls, 72 biop */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x77777777, x77770000, x22225555, x11116666, x1F1F6F6F;
	vtype x70700000, x43433333, x00430033, x55557777, x55167744, x5A19784B;
	vtype x5A1987B4, x7A3BD7F5, x003B00F5, x221955A0, x05050707, x271C52A7;
	vtype x2A2A82A0, x6969B193, x1FE06F90, x16804E00, xE97FB1FF;
	vtype x43403302, x35CAED30, x37DEFFB7, x349ECCB5, x0B01234A;
	vtype x101884B4, x0FF8EB24, x41413113, x4FF9FB37, x4FC2FBC2;
	vtype x43E9BBC2, x16BCEE97, x0F080B04, x19B4E593;
	vtype x5C5C5C5C, x4448184C, x2DDABE71, x6992A63D;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vor(x77777777, a1, a3);
	vandn(x77770000, x77777777, a6);
	vxor(x22225555, a1, x77770000);
	vxor(x11116666, a3, x22225555);
	vor(x1F1F6F6F, a4, x11116666);

	vandn(x70700000, x77770000, a4);
	vxor(x43433333, a3, x70700000);
	vand(x00430033, a5, x43433333);
	vor(x55557777, a1, x11116666);
	vxor(x55167744, x00430033, x55557777);
	vxor(x5A19784B, a4, x55167744);

	vxor(x5A1987B4, a6, x5A19784B);
	vor(x7A3BD7F5, x22225555, x5A1987B4);
	vand(x003B00F5, a5, x7A3BD7F5);
	vxor(x221955A0, x22225555, x003B00F5);
	vand(x05050707, a4, x55557777);
	vxor(x271C52A7, x221955A0, x05050707);

	vandn(x2A2A82A0, x7A3BD7F5, a1);
	vxor(x6969B193, x43433333, x2A2A82A0);
	vxor(x1FE06F90, a5, x1F1F6F6F);
	vandn(x16804E00, x1FE06F90, x6969B193);
	vnot(xE97FB1FF, x16804E00);
	vandn(x20, xE97FB1FF, a2);
	vxor(x21, x20, x5A19784B);
	vxor(*out3, *out3, x21);

	vandn(x43403302, x43433333, x003B00F5);
	vxor(x35CAED30, x2A2A82A0, x1FE06F90);
	vor(x37DEFFB7, x271C52A7, x35CAED30);
	vandn(x349ECCB5, x37DEFFB7, x43403302);
	vandn(x0B01234A, x1F1F6F6F, x349ECCB5);

	vand(x101884B4, x5A1987B4, x349ECCB5);
	vxor(x0FF8EB24, x1FE06F90, x101884B4);
	vand(x41413113, x43433333, x6969B193);
	vor(x4FF9FB37, x0FF8EB24, x41413113);
	vxor(x4FC2FBC2, x003B00F5, x4FF9FB37);
	vand(x30, x4FC2FBC2, a2);
	vxor(x31, x30, x271C52A7);
	vxor(*out4, *out4, x31);

	vxor(x43E9BBC2, x77777777, x349ECCB5);
	vxor(x16BCEE97, a1, x43E9BBC2);
	vand(x0F080B04, a4, x0FF8EB24);
	vxor(x19B4E593, x16BCEE97, x0F080B04);
	vor(x00, x0B01234A, a2);
	vxor(x01, x00, x19B4E593);
	vxor(*out1, *out1, x01);

	vxor(x5C5C5C5C, x1F1F6F6F, x43433333);
	vandn(x4448184C, x5C5C5C5C, x19B4E593);
	vxor(x2DDABE71, x22225555, x0FF8EB24);
	vxor(x6992A63D, x4448184C, x2DDABE71);
	vand(x10, x1F1F6F6F, a2);
	vxor(x11, x10, x6992A63D);
	vxor(*out2, *out2, x11);
}
#elif (!triop && regs >= 16) || (triop && latency <= 2)
/* s5-04829, 48 gates, 15/16 regs, 9 andn, 4/24/65/113/163 stalls, 72 biop */
/* Currently used for x86-64 SSE2 */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x77777777, x77770000, x22225555, x11116666, x1F1F6F6F;
	vtype x70700000, x43433333, x00430033, x55557777, x55167744, x5A19784B;
	vtype x5A1987B4, x7A3BD7F5, x003B00F5, x221955A0, x05050707, x271C52A7;
	vtype x2A2A82A0, x6969B193, x1FE06F90, x16804E00, xE97FB1FF;
	vtype x43403302, x35CAED30, x37DEFFB7, x349ECCB5, x0B01234A;
	vtype x101884B4, x0FF8EB24, x41413333, x4FF9FB37, x4FC2FBC2;
	vtype x22222222, x16BCEE97, x0F080B04, x19B4E593;
	vtype x5C5C5C5C, x4448184C, x2DDABE71, x6992A63D;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vor(x77777777, a1, a3);
	vandn(x77770000, x77777777, a6);
	vxor(x22225555, a1, x77770000);
	vxor(x11116666, a3, x22225555);
	vor(x1F1F6F6F, a4, x11116666);

	vandn(x70700000, x77770000, a4);
	vxor(x43433333, a3, x70700000);
	vand(x00430033, a5, x43433333);
	vor(x55557777, a1, x11116666);
	vxor(x55167744, x00430033, x55557777);
	vxor(x5A19784B, a4, x55167744);

	vxor(x5A1987B4, a6, x5A19784B);
	vor(x7A3BD7F5, x22225555, x5A1987B4);
	vand(x003B00F5, a5, x7A3BD7F5);
	vxor(x221955A0, x22225555, x003B00F5);
	vand(x05050707, a4, x55557777);
	vxor(x271C52A7, x221955A0, x05050707);

	vandn(x2A2A82A0, x7A3BD7F5, a1);
	vxor(x6969B193, x43433333, x2A2A82A0);
	vxor(x1FE06F90, a5, x1F1F6F6F);
	vandn(x16804E00, x1FE06F90, x6969B193);
	vnot(xE97FB1FF, x16804E00);
	vandn(x20, xE97FB1FF, a2);
	vxor(x21, x20, x5A19784B);
	vxor(*out3, *out3, x21);

	vandn(x43403302, x43433333, x003B00F5);
	vxor(x35CAED30, x2A2A82A0, x1FE06F90);
	vor(x37DEFFB7, x271C52A7, x35CAED30);
	vandn(x349ECCB5, x37DEFFB7, x43403302);
	vandn(x0B01234A, x1F1F6F6F, x349ECCB5);

	vand(x101884B4, x5A1987B4, x349ECCB5);
	vxor(x0FF8EB24, x1FE06F90, x101884B4);
	vand(x41413333, x43433333, x55557777);
	vor(x4FF9FB37, x0FF8EB24, x41413333);
	vxor(x4FC2FBC2, x003B00F5, x4FF9FB37);
	vand(x30, x4FC2FBC2, a2);
	vxor(x31, x30, x271C52A7);
	vxor(*out4, *out4, x31);

	vxor(x22222222, a1, x77777777);
	vxor(x16BCEE97, x349ECCB5, x22222222);
	vand(x0F080B04, a4, x0FF8EB24);
	vxor(x19B4E593, x16BCEE97, x0F080B04);
	vor(x00, x0B01234A, a2);
	vxor(x01, x00, x19B4E593);
	vxor(*out1, *out1, x01);

	vxor(x5C5C5C5C, x1F1F6F6F, x43433333);
	vandn(x4448184C, x5C5C5C5C, x19B4E593);
	vxor(x2DDABE71, x22225555, x0FF8EB24);
	vxor(x6992A63D, x4448184C, x2DDABE71);
	vand(x10, x1F1F6F6F, a2);
	vxor(x11, x10, x6992A63D);
	vxor(*out2, *out2, x11);
}
#else
/* s5-04832, 48 gates, 15/16 regs, 9 andn, 5/23/62/109/159 stalls, 72 biop */
/* Currently used for MMX/SSE2 */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x77777777, x77770000, x22225555, x11116666, x1F1F6F6F;
	vtype x70700000, x43433333, x00430033, x55557777, x55167744, x5A19784B;
	vtype x5A1987B4, x7A3BD7F5, x003B00F5, x221955A0, x05050707, x271C52A7;
	vtype x2A2A82A0, x6969B193, x1FE06F90, x16804E00, xE97FB1FF;
	vtype x43403302, x35CAED30, x37DEFFB7, x349ECCB5, x0B01234A;
	vtype x101884B4, x0FF8EB24, x41413333, x4FF9FB37, x4FC2FBC2;
	vtype x43E9BBC2, x16BCEE97, x0F080B04, x19B4E593;
	vtype x5C5C5C5C, x4448184C, x2DDABE71, x6992A63D;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vor(x77777777, a1, a3);
	vandn(x77770000, x77777777, a6);
	vxor(x22225555, a1, x77770000);
	vxor(x11116666, a3, x22225555);
	vor(x1F1F6F6F, a4, x11116666);

	vandn(x70700000, x77770000, a4);
	vxor(x43433333, a3, x70700000);
	vand(x00430033, a5, x43433333);
	vor(x55557777, a1, x11116666);
	vxor(x55167744, x00430033, x55557777);
	vxor(x5A19784B, a4, x55167744);

	vxor(x5A1987B4, a6, x5A19784B);
	vor(x7A3BD7F5, x22225555, x5A1987B4);
	vand(x003B00F5, a5, x7A3BD7F5);
	vxor(x221955A0, x22225555, x003B00F5);
	vand(x05050707, a4, x55557777);
	vxor(x271C52A7, x221955A0, x05050707);

	vandn(x2A2A82A0, x7A3BD7F5, a1);
	vxor(x6969B193, x43433333, x2A2A82A0);
	vxor(x1FE06F90, a5, x1F1F6F6F);
	vandn(x16804E00, x1FE06F90, x6969B193);
	vnot(xE97FB1FF, x16804E00);
	vandn(x20, xE97FB1FF, a2);
	vxor(x21, x20, x5A19784B);
	vxor(*out3, *out3, x21);

	vandn(x43403302, x43433333, x003B00F5);
	vxor(x35CAED30, x2A2A82A0, x1FE06F90);
	vor(x37DEFFB7, x271C52A7, x35CAED30);
	vandn(x349ECCB5, x37DEFFB7, x43403302);
	vandn(x0B01234A, x1F1F6F6F, x349ECCB5);

	vand(x101884B4, x5A1987B4, x349ECCB5);
	vxor(x0FF8EB24, x1FE06F90, x101884B4);
	vand(x41413333, x43433333, x55557777);
	vor(x4FF9FB37, x0FF8EB24, x41413333);
	vxor(x4FC2FBC2, x003B00F5, x4FF9FB37);
	vand(x30, x4FC2FBC2, a2);
	vxor(x31, x30, x271C52A7);
	vxor(*out4, *out4, x31);

	vxor(x43E9BBC2, x77777777, x349ECCB5);
	vxor(x16BCEE97, a1, x43E9BBC2);
	vand(x0F080B04, a4, x0FF8EB24);
	vxor(x19B4E593, x16BCEE97, x0F080B04);
	vor(x00, x0B01234A, a2);
	vxor(x01, x00, x19B4E593);
	vxor(*out1, *out1, x01);

	vxor(x5C5C5C5C, x1F1F6F6F, x43433333);
	vandn(x4448184C, x5C5C5C5C, x19B4E593);
	vxor(x2DDABE71, x22225555, x0FF8EB24);
	vxor(x6992A63D, x4448184C, x2DDABE71);
	vand(x10, x1F1F6F6F, a2);
	vxor(x11, x10, x6992A63D);
	vxor(*out2, *out2, x11);
}
#endif

#if !triop && regs >= 16
/* s6-000007, 46 gates, 19 regs, 8 andn, 3/19/39/66/101 stalls, 69 biop */
/* Currently used for x86-64 SSE2 */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x3333FFFF, x11115555, x22DD6699, x22DD9966, x00220099;
	vtype x00551144, x33662277, x5A5A5A5A, x7B7E7A7F, x59A31CE6;
	vtype x09030C06, x09030000, x336622FF, x3A6522FF;
	vtype x484D494C, x0000B6B3, x0F0FB9BC, x00FC00F9, x0FFFB9FD;
	vtype x5DF75DF7, x116600F7, x1E69B94B, x1668B94B;
	vtype x7B7B7B7B, x411E5984, x1FFFFDFD, x5EE1A479;
	vtype x3CB4DFD2, x004B002D, xB7B2B6B3, xCCC9CDC8, xCC82CDE5;
	vtype x0055EEBB, x5A5AECE9, x0050ECA9, xC5CAC1CE, xC59A2D67;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vor(x3333FFFF, a2, a6);
	vand(x11115555, a1, x3333FFFF);
	vxor(x22DD6699, x33CC33CC, x11115555);
	vxor(x22DD9966, a6, x22DD6699);
	vandn(x00220099, a5, x22DD9966);

	vand(x00551144, a1, x22DD9966);
	vxor(x33662277, a2, x00551144);
	vxor(x5A5A5A5A, a1, a3);
	vor(x7B7E7A7F, x33662277, x5A5A5A5A);
	vxor(x59A31CE6, x22DD6699, x7B7E7A7F);

	vand(x09030C06, a3, x59A31CE6);
	vandn(x09030000, x09030C06, a6);
	vor(x336622FF, x00220099, x33662277);
	vxor(x3A6522FF, x09030000, x336622FF);
	vand(x30, x3A6522FF, a4);
	vxor(x31, x30, x59A31CE6);
	vxor(*out4, *out4, x31);

	vxor(x484D494C, a2, x7B7E7A7F);
	vandn(x0000B6B3, a6, x484D494C);
	vxor(x0F0FB9BC, a3, x0000B6B3);
	vandn(x00FC00F9, a5, x09030C06);
	vor(x0FFFB9FD, x0F0FB9BC, x00FC00F9);

	vor(x5DF75DF7, a1, x59A31CE6);
	vand(x116600F7, x336622FF, x5DF75DF7);
	vxor(x1E69B94B, x0F0FB9BC, x116600F7);
	vandn(x1668B94B, x1E69B94B, x09030000);
	vor(x20, x00220099, a4);
	vxor(x21, x20, x1668B94B);
	vxor(*out3, *out3, x21);

	vor(x7B7B7B7B, a2, x5A5A5A5A);
	vxor(x411E5984, x3A6522FF, x7B7B7B7B);
	vor(x1FFFFDFD, x11115555, x0FFFB9FD);
	vxor(x5EE1A479, x411E5984, x1FFFFDFD);

	vxor(x3CB4DFD2, x22DD6699, x1E69B94B);
	vandn(x004B002D, a5, x3CB4DFD2);
	vnot(xB7B2B6B3, x484D494C);
	vxor(xCCC9CDC8, x7B7B7B7B, xB7B2B6B3);
	vxor(xCC82CDE5, x004B002D, xCCC9CDC8);
	vandn(x10, xCC82CDE5, a4);
	vxor(x11, x10, x5EE1A479);
	vxor(*out2, *out2, x11);

	vxor(x0055EEBB, a6, x00551144);
	vxor(x5A5AECE9, a1, x0F0FB9BC);
	vand(x0050ECA9, x0055EEBB, x5A5AECE9);
	vxor(xC5CAC1CE, x09030C06, xCCC9CDC8);
	vxor(xC59A2D67, x0050ECA9, xC5CAC1CE);
	vandn(x00, x0FFFB9FD, a4);
	vxor(x01, x00, xC59A2D67);
	vxor(*out1, *out1, x01);
}
#elif !triop && regs < 16
/* s6-000009, 46 gates, 19 regs, 8 andn, 3/20/41/69/110 stalls, 69 biop */
/* Currently used for MMX/SSE2 */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x3333FFFF, x11115555, x22DD6699, x22DD9966, x00220099;
	vtype x00551144, x33662277, x5A5A5A5A, x7B7E7A7F, x59A31CE6;
	vtype x09030C06, x09030000, x336622FF, x3A6522FF;
	vtype x484D494C, x0000B6B3, x0F0FB9BC, x00FC00F9, x0FFFB9FD;
	vtype x5DF75DF7, x116600F7, x1E69B94B, x1668B94B;
	vtype x1FFFFDFD, x7B7B7B7B, x64848686, x5EE1A479;
	vtype x3CB4DFD2, x004B002D, x33363237, xCCC9CDC8, xCC82CDE5;
	vtype x0055EEBB, x5A5AECE9, x0050ECA9, x0953E0AF, xC59A2D67;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vor(x3333FFFF, a2, a6);
	vand(x11115555, a1, x3333FFFF);
	vxor(x22DD6699, x33CC33CC, x11115555);
	vxor(x22DD9966, a6, x22DD6699);
	vandn(x00220099, a5, x22DD9966);

	vand(x00551144, a1, x22DD9966);
	vxor(x33662277, a2, x00551144);
	vxor(x5A5A5A5A, a1, a3);
	vor(x7B7E7A7F, x33662277, x5A5A5A5A);
	vxor(x59A31CE6, x22DD6699, x7B7E7A7F);

	vand(x09030C06, a3, x59A31CE6);
	vandn(x09030000, x09030C06, a6);
	vor(x336622FF, x00220099, x33662277);
	vxor(x3A6522FF, x09030000, x336622FF);
	vand(x30, x3A6522FF, a4);
	vxor(x31, x30, x59A31CE6);
	vxor(*out4, *out4, x31);

	vxor(x484D494C, a2, x7B7E7A7F);
	vandn(x0000B6B3, a6, x484D494C);
	vxor(x0F0FB9BC, a3, x0000B6B3);
	vandn(x00FC00F9, a5, x09030C06);
	vor(x0FFFB9FD, x0F0FB9BC, x00FC00F9);

	vor(x5DF75DF7, a1, x59A31CE6);
	vand(x116600F7, x336622FF, x5DF75DF7);
	vxor(x1E69B94B, x0F0FB9BC, x116600F7);
	vandn(x1668B94B, x1E69B94B, x09030000);
	vor(x20, x00220099, a4);
	vxor(x21, x20, x1668B94B);
	vxor(*out3, *out3, x21);

	vor(x1FFFFDFD, x11115555, x0FFFB9FD);
	vor(x7B7B7B7B, a2, x5A5A5A5A);
	vxor(x64848686, x1FFFFDFD, x7B7B7B7B);
	vxor(x5EE1A479, x3A6522FF, x64848686);

	vxor(x3CB4DFD2, x22DD6699, x1E69B94B);
	vandn(x004B002D, a5, x3CB4DFD2);
	vxor(x33363237, x484D494C, x7B7B7B7B);
	vnot(xCCC9CDC8, x33363237);
	vxor(xCC82CDE5, x004B002D, xCCC9CDC8);
	vandn(x10, xCC82CDE5, a4);
	vxor(x11, x10, x5EE1A479);
	vxor(*out2, *out2, x11);

	vxor(x0055EEBB, a6, x00551144);
	vxor(x5A5AECE9, a1, x0F0FB9BC);
	vand(x0050ECA9, x0055EEBB, x5A5AECE9);
	vxor(x0953E0AF, x09030C06, x0050ECA9);
	vxor(xC59A2D67, xCCC9CDC8, x0953E0AF);
	vandn(x00, x0FFFB9FD, a4);
	vxor(x01, x00, xC59A2D67);
	vxor(*out1, *out1, x01);
}
#elif latency >= 3
/* s6-000028, 46 gates, 19 regs, 8 andn, 4/16/39/65/101 stalls, 69 biop */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x3333FFFF, x11115555, x22DD6699, x22DD9966, x00220099;
	vtype x00551144, x33662277, x5A5A5A5A, x7B7E7A7F, x59A31CE6;
	vtype x09030C06, x09030000, x336622FF, x3A6522FF;
	vtype x484D494C, x0000B6B3, x0F0FB9BC, x00FC00F9, x0FFFB9FD;
	vtype x7B7B7B7B, x411E5984, x1FFFFDFD, x5EE1A479;
	vtype x5DF75DF7, x116600F7, x1E69B94B, x1668B94B;
	vtype x3CB4DFD2, x004B002D, x33363237, xCCC9CDC8, xCC82CDE5;
	vtype x0055EEBB, x5A5AECE9, x0050ECA9, xC5CAC1CE, xC59A2D67;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vor(x3333FFFF, a2, a6);
	vand(x11115555, a1, x3333FFFF);
	vxor(x22DD6699, x33CC33CC, x11115555);
	vxor(x22DD9966, a6, x22DD6699);
	vandn(x00220099, a5, x22DD9966);

	vand(x00551144, a1, x22DD9966);
	vxor(x33662277, a2, x00551144);
	vxor(x5A5A5A5A, a1, a3);
	vor(x7B7E7A7F, x33662277, x5A5A5A5A);
	vxor(x59A31CE6, x22DD6699, x7B7E7A7F);

	vand(x09030C06, a3, x59A31CE6);
	vandn(x09030000, x09030C06, a6);
	vor(x336622FF, x00220099, x33662277);
	vxor(x3A6522FF, x09030000, x336622FF);
	vand(x30, x3A6522FF, a4);
	vxor(x31, x30, x59A31CE6);
	vxor(*out4, *out4, x31);

	vxor(x484D494C, a2, x7B7E7A7F);
	vandn(x0000B6B3, a6, x484D494C);
	vxor(x0F0FB9BC, a3, x0000B6B3);
	vandn(x00FC00F9, a5, x09030C06);
	vor(x0FFFB9FD, x0F0FB9BC, x00FC00F9);

	vor(x7B7B7B7B, a2, x5A5A5A5A);
	vxor(x411E5984, x3A6522FF, x7B7B7B7B);
	vor(x1FFFFDFD, x11115555, x0FFFB9FD);
	vxor(x5EE1A479, x411E5984, x1FFFFDFD);

	vor(x5DF75DF7, a1, x59A31CE6);
	vand(x116600F7, x336622FF, x5DF75DF7);
	vxor(x1E69B94B, x0F0FB9BC, x116600F7);
	vandn(x1668B94B, x1E69B94B, x09030000);
	vor(x20, x00220099, a4);
	vxor(x21, x20, x1668B94B);
	vxor(*out3, *out3, x21);

	vxor(x3CB4DFD2, x22DD6699, x1E69B94B);
	vandn(x004B002D, a5, x3CB4DFD2);
	vxor(x33363237, x484D494C, x7B7B7B7B);
	vnot(xCCC9CDC8, x33363237);
	vxor(xCC82CDE5, x004B002D, xCCC9CDC8);
	vandn(x10, xCC82CDE5, a4);
	vxor(x11, x10, x5EE1A479);
	vxor(*out2, *out2, x11);

	vxor(x0055EEBB, a6, x00551144);
	vxor(x5A5AECE9, a1, x0F0FB9BC);
	vand(x0050ECA9, x0055EEBB, x5A5AECE9);
	vxor(xC5CAC1CE, x09030C06, xCCC9CDC8);
	vxor(xC59A2D67, x0050ECA9, xC5CAC1CE);
	vandn(x00, x0FFFB9FD, a4);
	vxor(x01, x00, xC59A2D67);
	vxor(*out1, *out1, x01);
}
#else
/* s6-000031, 46 gates, 19 regs, 8 andn, 3/16/42/68/111 stalls, 69 biop */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x33CC33CC;
	vtype x3333FFFF, x11115555, x22DD6699, x22DD9966, x00220099;
	vtype x00551144, x33662277, x5A5A5A5A, x7B7E7A7F, x59A31CE6;
	vtype x09030C06, x09030000, x336622FF, x3A6522FF;
	vtype x484D494C, x0000B6B3, x0F0FB9BC, x00FC00F9, x0FFFB9FD;
	vtype x7B7B7B7B, x411E5984, x1FFFFDFD, x5EE1A479;
	vtype x5DF75DF7, x116600F7, x1E69B94B, x1668B94B;
	vtype x3CB4DFD2, x004B002D, x84848484, xCCC9CDC8, xCC82CDE5;
	vtype x0055EEBB, x5A5AECE9, x0050ECA9, xC5CAC1CE, xC59A2D67;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x33CC33CC, a2, a5);

	vor(x3333FFFF, a2, a6);
	vand(x11115555, a1, x3333FFFF);
	vxor(x22DD6699, x33CC33CC, x11115555);
	vxor(x22DD9966, a6, x22DD6699);
	vandn(x00220099, a5, x22DD9966);

	vand(x00551144, a1, x22DD9966);
	vxor(x33662277, a2, x00551144);
	vxor(x5A5A5A5A, a1, a3);
	vor(x7B7E7A7F, x33662277, x5A5A5A5A);
	vxor(x59A31CE6, x22DD6699, x7B7E7A7F);

	vand(x09030C06, a3, x59A31CE6);
	vandn(x09030000, x09030C06, a6);
	vor(x336622FF, x00220099, x33662277);
	vxor(x3A6522FF, x09030000, x336622FF);
	vand(x30, x3A6522FF, a4);
	vxor(x31, x30, x59A31CE6);
	vxor(*out4, *out4, x31);

	vxor(x484D494C, a2, x7B7E7A7F);
	vandn(x0000B6B3, a6, x484D494C);
	vxor(x0F0FB9BC, a3, x0000B6B3);
	vandn(x00FC00F9, a5, x09030C06);
	vor(x0FFFB9FD, x0F0FB9BC, x00FC00F9);

	vor(x7B7B7B7B, a2, x5A5A5A5A);
	vxor(x411E5984, x3A6522FF, x7B7B7B7B);
	vor(x1FFFFDFD, x11115555, x0FFFB9FD);
	vxor(x5EE1A479, x411E5984, x1FFFFDFD);

	vor(x5DF75DF7, a1, x59A31CE6);
	vand(x116600F7, x336622FF, x5DF75DF7);
	vxor(x1E69B94B, x0F0FB9BC, x116600F7);
	vandn(x1668B94B, x1E69B94B, x09030000);
	vor(x20, x00220099, a4);
	vxor(x21, x20, x1668B94B);
	vxor(*out3, *out3, x21);

	vxor(x3CB4DFD2, x22DD6699, x1E69B94B);
	vandn(x004B002D, a5, x3CB4DFD2);
	vnot(x84848484, x7B7B7B7B);
	vxor(xCCC9CDC8, x484D494C, x84848484);
	vxor(xCC82CDE5, x004B002D, xCCC9CDC8);
	vandn(x10, xCC82CDE5, a4);
	vxor(x11, x10, x5EE1A479);
	vxor(*out2, *out2, x11);

	vxor(x0055EEBB, a6, x00551144);
	vxor(x5A5AECE9, a1, x0F0FB9BC);
	vand(x0050ECA9, x0055EEBB, x5A5AECE9);
	vxor(xC5CAC1CE, x09030C06, xCCC9CDC8);
	vxor(xC59A2D67, x0050ECA9, xC5CAC1CE);
	vandn(x00, x0FFFB9FD, a4);
	vxor(x01, x00, xC59A2D67);
	vxor(*out1, *out1, x01);
}
#endif

#if andn && triop && regs <= 16 && latency >= 5
/* s7-000072, 46 gates, 16 regs, 10 andn, 2/5/17/51/93 stalls, 69 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x00FF0000, x33CC3333, x3FCF3F3F, x55AA55AA, x55AAAA55, x6A65956A;
	vtype x5AA5A55A, x05505005, x05AF5005, x018C1001, x01731001;
	vtype x33FF33FF, x030F030F, x575F575F, x5250075A;
	vtype x5BD6B55B, x04294004, x33D633FB, x54A054A0, x6776675B;
	vtype x550A0255, x68E58668, x7DEF867D, x4E39B586;
	vtype x50000050, x518C1051, x518C0000, x0B29A55A, x38D696A5;
	vtype x63333363, x23132343, x26BC7346, x5B53F53B;
	vtype xFFFF0000, xFFFF54A0, xADAF53FA, xA8AA02AA, x8E1671EC;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x00FF0000, a4, a5);
	vxor(x33CC3333, a2, x00FF0000);
	vor(x3FCF3F3F, a3, x33CC3333);
	vxor(x55AA55AA, a1, a4);
	vxor(x55AAAA55, a5, x55AA55AA);
	vxor(x6A65956A, x3FCF3F3F, x55AAAA55);

	vxor(x5AA5A55A, a3, x55AAAA55);
	vandn(x05505005, a1, x5AA5A55A);
	vxor(x05AF5005, x00FF0000, x05505005);
	vand(x018C1001, x33CC3333, x05AF5005);
	vxor(x01731001, x00FF0000, x018C1001);
	vandn(x30, a6, x01731001);
	vxor(x31, x30, x6A65956A);
	vxor(*out4, *out4, x31);

	vor(x33FF33FF, a2, a4);
	vand(x030F030F, a3, x33FF33FF);
	vor(x575F575F, a1, x030F030F);
	vandn(x5250075A, x575F575F, x05AF5005);

	vxor(x5BD6B55B, x5AA5A55A, x01731001);
	vandn(x04294004, x05AF5005, x5BD6B55B);
	vandn(x33D633FB, x33FF33FF, x04294004);
	vandn(x54A054A0, x55AA55AA, x030F030F);
	vxor(x6776675B, x33D633FB, x54A054A0);

	vand(x550A0255, x55AAAA55, x575F575F);
	vxor(x68E58668, a2, x5BD6B55B);
	vor(x7DEF867D, x550A0255, x68E58668);
	vxor(x4E39B586, x33D633FB, x7DEF867D);
	vor(x00, x5250075A, a6);
	vxor(x01, x00, x4E39B586);
	vxor(*out1, *out1, x01);

	vand(x50000050, x5AA5A55A, x550A0255);
	vor(x518C1051, x018C1001, x50000050);
	vandn(x518C0000, x518C1051, a5);
	vxor(x0B29A55A, x5AA5A55A, x518C0000);
	vxor(x38D696A5, x33FF33FF, x0B29A55A);

	vxor(x63333363, a2, x50000050);
	vandn(x23132343, x63333363, x54A054A0);
	vxor(x26BC7346, x05AF5005, x23132343);
	vxor(x5B53F53B, x7DEF867D, x26BC7346);
	vand(x20, x5B53F53B, a6);
	vxor(x21, x20, x38D696A5);
	vxor(*out3, *out3, x21);

	vnot(xFFFF0000, a5);
	vor(xFFFF54A0, x54A054A0, xFFFF0000);
	vxor(xADAF53FA, x5250075A, xFFFF54A0);
	vandn(xA8AA02AA, xADAF53FA, a1);
	vxor(x8E1671EC, x26BC7346, xA8AA02AA);
	vand(x10, x6776675B, a6);
	vxor(x11, x10, x8E1671EC);
	vxor(*out2, *out2, x11);
}
#elif andn && triop && regs <= 16 && latency == 3
/* s7-000788, 46 gates, 16 regs, 10 andn, 2/3/18/51/94 stalls, 69 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x00FF0000, x33CC3333, x3FCF3F3F, x55AA55AA, x55AAAA55, x6A65956A;
	vtype x5AA5A55A, x05505005, x05AF5005, x018C1001, x01731001;
	vtype x33FF33FF, x030F030F, x575F575F, x5250075A;
	vtype x5BD6B55B, x04294004, x33D633FB, x54A054A0, x6776675B;
	vtype x550A0255, x68E58668, x7DEF867D, x4E39B586;
	vtype x50000050, x63333363, x23132343, x26BC7346, x5B53F53B;
	vtype x518C1051, x518C0000, x0B29A55A, x38D696A5;
	vtype x0000AB5F, x5250AC05, x5755FD55, xD9438CB9, x8E1671EC;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x00FF0000, a4, a5);
	vxor(x33CC3333, a2, x00FF0000);
	vor(x3FCF3F3F, a3, x33CC3333);
	vxor(x55AA55AA, a1, a4);
	vxor(x55AAAA55, a5, x55AA55AA);
	vxor(x6A65956A, x3FCF3F3F, x55AAAA55);

	vxor(x5AA5A55A, a3, x55AAAA55);
	vandn(x05505005, a1, x5AA5A55A);
	vxor(x05AF5005, x00FF0000, x05505005);
	vand(x018C1001, x33CC3333, x05AF5005);
	vxor(x01731001, x00FF0000, x018C1001);
	vandn(x30, a6, x01731001);
	vxor(x31, x30, x6A65956A);
	vxor(*out4, *out4, x31);

	vor(x33FF33FF, a2, a4);
	vand(x030F030F, a3, x33FF33FF);
	vor(x575F575F, a1, x030F030F);
	vandn(x5250075A, x575F575F, x05AF5005);

	vxor(x5BD6B55B, x5AA5A55A, x01731001);
	vandn(x04294004, x05AF5005, x5BD6B55B);
	vandn(x33D633FB, x33FF33FF, x04294004);
	vandn(x54A054A0, x55AA55AA, x030F030F);
	vxor(x6776675B, x33D633FB, x54A054A0);

	vand(x550A0255, x55AAAA55, x575F575F);
	vxor(x68E58668, a2, x5BD6B55B);
	vor(x7DEF867D, x550A0255, x68E58668);
	vxor(x4E39B586, x33D633FB, x7DEF867D);
	vor(x00, x5250075A, a6);
	vxor(x01, x00, x4E39B586);
	vxor(*out1, *out1, x01);

	vand(x50000050, x5AA5A55A, x550A0255);
	vxor(x63333363, a2, x50000050);
	vandn(x23132343, x63333363, x54A054A0);
	vxor(x26BC7346, x05AF5005, x23132343);
	vxor(x5B53F53B, x7DEF867D, x26BC7346);

	vor(x518C1051, x018C1001, x50000050);
	vandn(x518C0000, x518C1051, a5);
	vxor(x0B29A55A, x5AA5A55A, x518C0000);
	vxor(x38D696A5, x33FF33FF, x0B29A55A);
	vand(x20, x5B53F53B, a6);
	vxor(x21, x20, x38D696A5);
	vxor(*out3, *out3, x21);

	vandn(x0000AB5F, a5, x54A054A0);
	vxor(x5250AC05, x5250075A, x0000AB5F);
	vor(x5755FD55, a1, x5250AC05);
	vnot(xD9438CB9, x26BC7346);
	vxor(x8E1671EC, x5755FD55, xD9438CB9);
	vand(x10, x6776675B, a6);
	vxor(x11, x10, x8E1671EC);
	vxor(*out2, *out2, x11);
}
#elif andn && triop && regs == 18 && latency >= 6
/* s7-002149, 46 gates, 18 regs, 11 andn, 2/5/20/40/66 stalls, 68 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x00FF0000, x33CC3333, x3FCF3F3F, x55AA55AA, x55AAAA55, x6A65956A;
	vtype x5AA5A55A, x05505005, x05AF5005, x018C1001, x01731001;
	vtype x33FF33FF, x030F030F, x575F575F, x5250075A;
	vtype x69969669, x04294004, x33D633FB, x54A054A0, x6776675B;
	vtype x68E58668, x550A0255, x7DEF867D, x4E39B586;
	vtype x0AA5A50A, x63333363, x23132343, x26BC7346, x5B53F53B;
	vtype x018C0000, x63FF33FF, x627333FF, x38D696A5;
	vtype x5659A956, x0251A854, x5755FD55, xA8AA02AA, x8E1671EC;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x00FF0000, a4, a5);
	vxor(x33CC3333, a2, x00FF0000);
	vor(x3FCF3F3F, a3, x33CC3333);
	vxor(x55AA55AA, a1, a4);
	vxor(x55AAAA55, a5, x55AA55AA);
	vxor(x6A65956A, x3FCF3F3F, x55AAAA55);

	vxor(x5AA5A55A, a3, x55AAAA55);
	vandn(x05505005, a1, x5AA5A55A);
	vxor(x05AF5005, x00FF0000, x05505005);
	vand(x018C1001, x33CC3333, x05AF5005);
	vxor(x01731001, x00FF0000, x018C1001);
	vandn(x30, a6, x01731001);
	vxor(x31, x30, x6A65956A);
	vxor(*out4, *out4, x31);

	vor(x33FF33FF, a2, a4);
	vand(x030F030F, a3, x33FF33FF);
	vor(x575F575F, a1, x030F030F);
	vandn(x5250075A, x575F575F, x05AF5005);

	vxor(x69969669, a2, x5AA5A55A);
	vandn(x04294004, x05AF5005, x69969669);
	vandn(x33D633FB, x33FF33FF, x04294004);
	vandn(x54A054A0, x55AA55AA, x030F030F);
	vxor(x6776675B, x33D633FB, x54A054A0);

	vxor(x68E58668, x01731001, x69969669);
	vand(x550A0255, x55AAAA55, x575F575F);
	vor(x7DEF867D, x68E58668, x550A0255);
	vxor(x4E39B586, x33D633FB, x7DEF867D);
	vor(x00, x5250075A, a6);
	vxor(x01, x00, x4E39B586);
	vxor(*out1, *out1, x01);

	vandn(x0AA5A50A, x5AA5A55A, x550A0255);
	vxor(x63333363, x69969669, x0AA5A50A);
	vandn(x23132343, x63333363, x54A054A0);
	vxor(x26BC7346, x05AF5005, x23132343);
	vxor(x5B53F53B, x7DEF867D, x26BC7346);

	vandn(x018C0000, x018C1001, a5);
	vor(x63FF33FF, a4, x63333363);
	vxor(x627333FF, x018C0000, x63FF33FF);
	vxor(x38D696A5, x5AA5A55A, x627333FF);
	vand(x20, x5B53F53B, a6);
	vxor(x21, x20, x38D696A5);
	vxor(*out3, *out3, x21);

	vxor(x5659A956, x3FCF3F3F, x69969669);
	vandn(x0251A854, x5659A956, x55AA55AA);
	vor(x5755FD55, a1, x0251A854);
	vnot(xA8AA02AA, x5755FD55);
	vxor(x8E1671EC, x26BC7346, xA8AA02AA);
	vand(x10, x6776675B, a6);
	vxor(x11, x10, x8E1671EC);
	vxor(*out2, *out2, x11);
}
#elif andn && triop && regs >= 18 && latency == 5
/* s7-002689, 46 gates, 18 regs, 10 andn, 2/5/14/31/69 stalls, 69 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x00FF0000, x33CC3333, x3FCF3F3F, x55AA55AA, x55AAAA55, x6A65956A;
	vtype x5AA5A55A, x05505005, x05AF5005, x018C1001, x01731001;
	vtype x33FF33FF, x030F030F, x575F575F, x5250075A;
	vtype x69969669, x04294004, x33D633FB, x54A054A0, x6776675B;
	vtype x68E58668, x550A0255, x7DEF867D, x4E39B586;
	vtype x50000050, x63333363, x23132343, x26BC7346, x5B53F53B;
	vtype x518C1051, x518C0000, x0B29A55A, x38D696A5;
	vtype xFFFF0000, xA8A0575F, xA8FF57FF, xA8AA02AA, x8E1671EC;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x00FF0000, a4, a5);
	vxor(x33CC3333, a2, x00FF0000);
	vor(x3FCF3F3F, a3, x33CC3333);
	vxor(x55AA55AA, a1, a4);
	vxor(x55AAAA55, a5, x55AA55AA);
	vxor(x6A65956A, x3FCF3F3F, x55AAAA55);

	vxor(x5AA5A55A, a3, x55AAAA55);
	vandn(x05505005, a1, x5AA5A55A);
	vxor(x05AF5005, x00FF0000, x05505005);
	vand(x018C1001, x33CC3333, x05AF5005);
	vxor(x01731001, x00FF0000, x018C1001);
	vandn(x30, a6, x01731001);
	vxor(x31, x30, x6A65956A);
	vxor(*out4, *out4, x31);

	vor(x33FF33FF, a2, a4);
	vand(x030F030F, a3, x33FF33FF);
	vor(x575F575F, a1, x030F030F);
	vandn(x5250075A, x575F575F, x05AF5005);

	vxor(x69969669, a2, x5AA5A55A);
	vandn(x04294004, x05AF5005, x69969669);
	vandn(x33D633FB, x33FF33FF, x04294004);
	vandn(x54A054A0, x55AA55AA, x030F030F);
	vxor(x6776675B, x33D633FB, x54A054A0);

	vxor(x68E58668, x01731001, x69969669);
	vand(x550A0255, x55AAAA55, x575F575F);
	vor(x7DEF867D, x68E58668, x550A0255);
	vxor(x4E39B586, x33D633FB, x7DEF867D);
	vor(x00, x5250075A, a6);
	vxor(x01, x00, x4E39B586);
	vxor(*out1, *out1, x01);

	vand(x50000050, x5AA5A55A, x550A0255);
	vxor(x63333363, a2, x50000050);
	vandn(x23132343, x63333363, x54A054A0);
	vxor(x26BC7346, x05AF5005, x23132343);
	vxor(x5B53F53B, x7DEF867D, x26BC7346);

	vor(x518C1051, x018C1001, x50000050);
	vandn(x518C0000, x518C1051, a5);
	vxor(x0B29A55A, x5AA5A55A, x518C0000);
	vxor(x38D696A5, x33FF33FF, x0B29A55A);
	vand(x20, x5B53F53B, a6);
	vxor(x21, x20, x38D696A5);
	vxor(*out3, *out3, x21);

	vnot(xFFFF0000, a5);
	vxor(xA8A0575F, x575F575F, xFFFF0000);
	vor(xA8FF57FF, a4, xA8A0575F);
	vandn(xA8AA02AA, xA8FF57FF, a1);
	vxor(x8E1671EC, x26BC7346, xA8AA02AA);
	vand(x10, x6776675B, a6);
	vxor(x11, x10, x8E1671EC);
	vxor(*out2, *out2, x11);
}
#elif andn && triop && regs >= 19 && latency >= 6
/* s7-003344, 46 gates, 19 regs, 10 andn, 3/9/14/39/66 stalls, 68 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x00FF0000, x33CC3333, x3FCF3F3F, x55AA55AA, x55AAAA55, x6A65956A;
	vtype x5AA5A55A, x05505005, x05AF5005, x018C1001, x01731001;
	vtype x33FF33FF, x030F030F, x575F575F, x5250075A;
	vtype x69969669, x04294004, x33D633FB, x54A054A0, x6776675B;
	vtype x68E58668, x550A0255, x7DEF867D, x4E39B586;
	vtype x50000050, x63333363, x23132343, x26BC7346, x5B53F53B;
	vtype x518C1051, x518C0000, x695A96A5, x38D696A5;
	vtype x5659A956, x0251A854, x5755FD55, xA8AA02AA, x8E1671EC;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x00FF0000, a4, a5);
	vxor(x33CC3333, a2, x00FF0000);
	vor(x3FCF3F3F, a3, x33CC3333);
	vxor(x55AA55AA, a1, a4);
	vxor(x55AAAA55, a5, x55AA55AA);
	vxor(x6A65956A, x3FCF3F3F, x55AAAA55);

	vxor(x5AA5A55A, a3, x55AAAA55);
	vandn(x05505005, a1, x5AA5A55A);
	vxor(x05AF5005, x00FF0000, x05505005);
	vand(x018C1001, x33CC3333, x05AF5005);
	vxor(x01731001, x00FF0000, x018C1001);
	vandn(x30, a6, x01731001);
	vxor(x31, x30, x6A65956A);
	vxor(*out4, *out4, x31);

	vor(x33FF33FF, a2, a4);
	vand(x030F030F, a3, x33FF33FF);
	vor(x575F575F, a1, x030F030F);
	vandn(x5250075A, x575F575F, x05AF5005);

	vxor(x69969669, a2, x5AA5A55A);
	vandn(x04294004, x05AF5005, x69969669);
	vandn(x33D633FB, x33FF33FF, x04294004);
	vandn(x54A054A0, x55AA55AA, x030F030F);
	vxor(x6776675B, x33D633FB, x54A054A0);

	vxor(x68E58668, x01731001, x69969669);
	vand(x550A0255, x55AAAA55, x575F575F);
	vor(x7DEF867D, x68E58668, x550A0255);
	vxor(x4E39B586, x33D633FB, x7DEF867D);
	vor(x00, x5250075A, a6);
	vxor(x01, x00, x4E39B586);
	vxor(*out1, *out1, x01);

	vand(x50000050, x5AA5A55A, x550A0255);
	vxor(x63333363, a2, x50000050);
	vandn(x23132343, x63333363, x54A054A0);
	vxor(x26BC7346, x05AF5005, x23132343);
	vxor(x5B53F53B, x7DEF867D, x26BC7346);

	vor(x518C1051, x018C1001, x50000050);
	vandn(x518C0000, x518C1051, a5);
	vxor(x695A96A5, x5AA5A55A, x33FF33FF);
	vxor(x38D696A5, x518C0000, x695A96A5);
	vand(x20, x5B53F53B, a6);
	vxor(x21, x20, x38D696A5);
	vxor(*out3, *out3, x21);

	vxor(x5659A956, x3FCF3F3F, x69969669);
	vandn(x0251A854, x5659A956, x55AA55AA);
	vor(x5755FD55, a1, x0251A854);
	vnot(xA8AA02AA, x5755FD55);
	vxor(x8E1671EC, x26BC7346, xA8AA02AA);
	vand(x10, x6776675B, a6);
	vxor(x11, x10, x8E1671EC);
	vxor(*out2, *out2, x11);
}
#elif andn && triop && regs >= 17 && latency >= 4
/* s7-003395, 46 gates, 17 regs, 11 andn, 3/5/10/39/67 stalls, 70 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x00FF0000, x33CC3333, x3FCF3F3F, x55AA55AA, x55AAAA55, x6A65956A;
	vtype x5AA5A55A, x05505005, x05AF5005, x018C1001, x01731001;
	vtype x33FF33FF, x030F030F, x575F575F, x5250075A;
	vtype x69969669, x04294004, x33D633FB, x54A054A0, x6776675B;
	vtype x68E58668, x550A0255, x7DEF867D, x4E39B586;
	vtype x50000050, x63333363, x23132343, x26BC7346, x5B53F53B;
	vtype x518C1051, x518C0000, x695A96A5, x38D696A5;
	vtype x0000AB5F, x5250AC05, xAAAAAAAA, xA8AA02AA, x8E1671EC;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x00FF0000, a4, a5);
	vxor(x33CC3333, a2, x00FF0000);
	vor(x3FCF3F3F, a3, x33CC3333);
	vxor(x55AA55AA, a1, a4);
	vxor(x55AAAA55, a5, x55AA55AA);
	vxor(x6A65956A, x3FCF3F3F, x55AAAA55);

	vxor(x5AA5A55A, a3, x55AAAA55);
	vandn(x05505005, a1, x5AA5A55A);
	vxor(x05AF5005, x00FF0000, x05505005);
	vand(x018C1001, x33CC3333, x05AF5005);
	vxor(x01731001, x00FF0000, x018C1001);
	vandn(x30, a6, x01731001);
	vxor(x31, x30, x6A65956A);
	vxor(*out4, *out4, x31);

	vor(x33FF33FF, a2, a4);
	vand(x030F030F, a3, x33FF33FF);
	vor(x575F575F, a1, x030F030F);
	vandn(x5250075A, x575F575F, x05AF5005);

	vxor(x69969669, a2, x5AA5A55A);
	vandn(x04294004, x05AF5005, x69969669);
	vandn(x33D633FB, x33FF33FF, x04294004);
	vandn(x54A054A0, x55AA55AA, x030F030F);
	vxor(x6776675B, x33D633FB, x54A054A0);

	vxor(x68E58668, x01731001, x69969669);
	vand(x550A0255, x55AAAA55, x575F575F);
	vor(x7DEF867D, x68E58668, x550A0255);
	vxor(x4E39B586, x33D633FB, x7DEF867D);
	vor(x00, x5250075A, a6);
	vxor(x01, x00, x4E39B586);
	vxor(*out1, *out1, x01);

	vand(x50000050, x5AA5A55A, x550A0255);
	vxor(x63333363, a2, x50000050);
	vandn(x23132343, x63333363, x54A054A0);
	vxor(x26BC7346, x05AF5005, x23132343);
	vxor(x5B53F53B, x7DEF867D, x26BC7346);

	vor(x518C1051, x018C1001, x50000050);
	vandn(x518C0000, x518C1051, a5);
	vxor(x695A96A5, x5AA5A55A, x33FF33FF);
	vxor(x38D696A5, x518C0000, x695A96A5);
	vand(x20, x5B53F53B, a6);
	vxor(x21, x20, x38D696A5);
	vxor(*out3, *out3, x21);

	vandn(x0000AB5F, a5, x54A054A0);
	vxor(x5250AC05, x5250075A, x0000AB5F);
	vnot(xAAAAAAAA, a1);
	vandn(xA8AA02AA, xAAAAAAAA, x5250AC05);
	vxor(x8E1671EC, x26BC7346, xA8AA02AA);
	vand(x10, x6776675B, a6);
	vxor(x11, x10, x8E1671EC);
	vxor(*out2, *out2, x11);
}
#elif andn && triop && regs >= 17
/* s7-036457, 46 gates, 17 regs, 9 andn, 1/6/16/50/93 stalls, 71 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x0FF0C0CC, x0FFFC3CF, x2E222B22, x28000802, x27FFCBCD;
	vtype x48444844, x4FF4C8CC, x6F9C5F5B, x4F944848, x686B8385;
	vtype x0FC3C3F3, x0000C3F3, x0000DBF3, x4F9493BB;
	vtype x96B1A572, xB14E6EBF, x00008AA2, xB14EE41D;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vandn(x0FF0C0CC, x0FF0CCCC, x00000F00);
	vor(x0FFFC3CF, x000F0303, x0FF0C0CC);
	vxor(x2E222B22, a2, x7B777E77);
	vand(x28000802, x699C585B, x2E222B22);
	vxor(x27FFCBCD, x0FFFC3CF, x28000802);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vandn(x48444844, x5A555A55, a3);
	vor(x4FF4C8CC, x0FF0C0CC, x48444844);
	vor(x6F9C5F5B, x0F000F00, x699C585B);
	vand(x4F944848, x4FF4C8CC, x6F9C5F5B);
	vxor(x686B8385, x27FFCBCD, x4F944848);

	vxor(x0FC3C3F3, x003C003C, x0FFFC3CF);
	vand(x0000C3F3, a6, x0FC3C3F3);
	vor(x0000DBF3, x00001841, x0000C3F3);
	vxor(x4F9493BB, x4F944848, x0000DBF3);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vnot(x96B1A572, x694E5A8D);
	vxor(xB14E6EBF, x27FFCBCD, x96B1A572);
	vandn(x00008AA2, x0000DBF3, a2);
	vxor(xB14EE41D, xB14E6EBF, x00008AA2);
	vandn(x10, a1, x686B8385);
	vxor(x11, x10, xB14EE41D);
	vxor(*out2, *out2, x11);
}
#elif !andn && triop && regs >= 17 && latency <= 4
/* s7-036496, 46 gates, 17 regs, 7 andn, 3/9/20/52/95 stalls, 70 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x0FF0C0CC, x0FFFC3CF, x2E222B22, x28000802, x27FFCBCD;
	vtype x48444844, x4FF4C8CC, x6F9C5F5B, x4F944848, x686B8385;
	vtype x0FC3C3F3, x0000C3F3, x0000DBF3, x4F9493BB;
	vtype x00005151, x96B1A572, x96B1F423, xD9256798;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vandn(x0FF0C0CC, x0FF0CCCC, x00000F00);
	vor(x0FFFC3CF, x000F0303, x0FF0C0CC);
	vxor(x2E222B22, a2, x7B777E77);
	vand(x28000802, x699C585B, x2E222B22);
	vxor(x27FFCBCD, x0FFFC3CF, x28000802);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vandn(x48444844, x5A555A55, a3);
	vor(x4FF4C8CC, x0FF0C0CC, x48444844);
	vor(x6F9C5F5B, x0F000F00, x699C585B);
	vand(x4F944848, x4FF4C8CC, x6F9C5F5B);
	vxor(x686B8385, x27FFCBCD, x4F944848);

	vxor(x0FC3C3F3, x003C003C, x0FFFC3CF);
	vand(x0000C3F3, a6, x0FC3C3F3);
	vor(x0000DBF3, x00001841, x0000C3F3);
	vxor(x4F9493BB, x4F944848, x0000DBF3);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vand(x00005151, a2, x0000DBF3);
	vnot(x96B1A572, x694E5A8D);
	vxor(x96B1F423, x00005151, x96B1A572);
	vxor(xD9256798, x4F9493BB, x96B1F423);
	vor(x10, x686B8385, a1);
	vxor(x11, x10, xD9256798);
	vxor(*out2, *out2, x11);
}
#elif !andn && triop && regs >= 17 && latency >= 5
/* s7-036532, 46 gates, 17 regs, 7 andn, 3/9/23/51/93 stalls, 71 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x0FF0C0CC, x0FFFC3CF, x2E222B22, x28000802, x27FFCBCD;
	vtype x48444844, x4FF4C8CC, x6F9C5F5B, x4F944848, x686B8385;
	vtype x0FC3C3F3, x0FC3DBF3, x0000DBF3, x4F9493BB;
	vtype xFFFF240C, xFFFF755D, x26DA12C5, xD9256798;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vandn(x0FF0C0CC, x0FF0CCCC, x00000F00);
	vor(x0FFFC3CF, x000F0303, x0FF0C0CC);
	vxor(x2E222B22, a2, x7B777E77);
	vand(x28000802, x699C585B, x2E222B22);
	vxor(x27FFCBCD, x0FFFC3CF, x28000802);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vandn(x48444844, x5A555A55, a3);
	vor(x4FF4C8CC, x0FF0C0CC, x48444844);
	vor(x6F9C5F5B, x0F000F00, x699C585B);
	vand(x4F944848, x4FF4C8CC, x6F9C5F5B);
	vxor(x686B8385, x27FFCBCD, x4F944848);

	vxor(x0FC3C3F3, x003C003C, x0FFFC3CF);
	vor(x0FC3DBF3, x00001841, x0FC3C3F3);
	vand(x0000DBF3, a6, x0FC3DBF3);
	vxor(x4F9493BB, x4F944848, x0000DBF3);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vnot(xFFFF240C, x0000DBF3);
	vor(xFFFF755D, a2, xFFFF240C);
	vxor(x26DA12C5, x694E5A8D, x4F944848);
	vxor(xD9256798, xFFFF755D, x26DA12C5);
	vor(x10, x686B8385, a1);
	vxor(x11, x10, xD9256798);
	vxor(*out2, *out2, x11);
}
#elif andn && triop && regs <= 16
/* s7-036610, 46 gates, 16 regs, 9 andn, 1/6/16/53/98 stalls, 70 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x0FF0C0CC, x0FFFC3CF, x2E222B22, x28000802, x27FFCBCD;
	vtype x48444844, x4FF4C8CC, x6F9C5F5B, x4F944848, x686B8385;
	vtype x6FFFDBCF, x6FC3DBF3, x0000DBF3, x4F9493BB;
	vtype x96B1A572, xB14E6EBF, x00008AA2, xB14EE41D;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vandn(x0FF0C0CC, x0FF0CCCC, x00000F00);
	vor(x0FFFC3CF, x000F0303, x0FF0C0CC);
	vxor(x2E222B22, a2, x7B777E77);
	vand(x28000802, x699C585B, x2E222B22);
	vxor(x27FFCBCD, x0FFFC3CF, x28000802);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vandn(x48444844, x5A555A55, a3);
	vor(x4FF4C8CC, x0FF0C0CC, x48444844);
	vor(x6F9C5F5B, x0F000F00, x699C585B);
	vand(x4F944848, x4FF4C8CC, x6F9C5F5B);
	vxor(x686B8385, x27FFCBCD, x4F944848);

	vor(x6FFFDBCF, x694E5A8D, x0FFFC3CF);
	vxor(x6FC3DBF3, x003C003C, x6FFFDBCF);
	vand(x0000DBF3, a6, x6FC3DBF3);
	vxor(x4F9493BB, x4F944848, x0000DBF3);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vnot(x96B1A572, x694E5A8D);
	vxor(xB14E6EBF, x27FFCBCD, x96B1A572);
	vandn(x00008AA2, x0000DBF3, a2);
	vxor(xB14EE41D, xB14E6EBF, x00008AA2);
	vandn(x10, a1, x686B8385);
	vxor(x11, x10, xB14EE41D);
	vxor(*out2, *out2, x11);
}
#elif !andn && triop && latency >= 5
/* s7-036634, 46 gates, 16 regs, 7 andn, 3/9/23/54/98 stalls, 70 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x0FF0C0CC, x0FFFC3CF, x2E222B22, x28000802, x27FFCBCD;
	vtype x48444844, x4FF4C8CC, x6F9C5F5B, x4F944848, x686B8385;
	vtype x6FFFDBCF, x6FC3DBF3, x0000DBF3, x4F9493BB;
	vtype xFFFF240C, xFFFF755D, x26DA12C5, xD9256798;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vandn(x0FF0C0CC, x0FF0CCCC, x00000F00);
	vor(x0FFFC3CF, x000F0303, x0FF0C0CC);
	vxor(x2E222B22, a2, x7B777E77);
	vand(x28000802, x699C585B, x2E222B22);
	vxor(x27FFCBCD, x0FFFC3CF, x28000802);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vandn(x48444844, x5A555A55, a3);
	vor(x4FF4C8CC, x0FF0C0CC, x48444844);
	vor(x6F9C5F5B, x0F000F00, x699C585B);
	vand(x4F944848, x4FF4C8CC, x6F9C5F5B);
	vxor(x686B8385, x27FFCBCD, x4F944848);

	vor(x6FFFDBCF, x694E5A8D, x0FFFC3CF);
	vxor(x6FC3DBF3, x003C003C, x6FFFDBCF);
	vand(x0000DBF3, a6, x6FC3DBF3);
	vxor(x4F9493BB, x4F944848, x0000DBF3);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vnot(xFFFF240C, x0000DBF3);
	vor(xFFFF755D, a2, xFFFF240C);
	vxor(x26DA12C5, x694E5A8D, x4F944848);
	vxor(xD9256798, xFFFF755D, x26DA12C5);
	vor(x10, x686B8385, a1);
	vxor(x11, x10, xD9256798);
	vxor(*out2, *out2, x11);
}
#elif !andn && triop && latency <= 4
/* s7-036649, 46 gates, 16 regs, 7 andn, 3/9/20/55/100 stalls, 69 biop */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x0FF0C0CC, x0FFFC3CF, x2E222B22, x28000802, x27FFCBCD;
	vtype x48444844, x4FF4C8CC, x6F9C5F5B, x4F944848, x686B8385;
	vtype x6FFFDBCF, x6FC3DBF3, x0000DBF3, x4F9493BB;
	vtype x00005151, x96B1A572, x96B1F423, xD9256798;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vandn(x0FF0C0CC, x0FF0CCCC, x00000F00);
	vor(x0FFFC3CF, x000F0303, x0FF0C0CC);
	vxor(x2E222B22, a2, x7B777E77);
	vand(x28000802, x699C585B, x2E222B22);
	vxor(x27FFCBCD, x0FFFC3CF, x28000802);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vandn(x48444844, x5A555A55, a3);
	vor(x4FF4C8CC, x0FF0C0CC, x48444844);
	vor(x6F9C5F5B, x0F000F00, x699C585B);
	vand(x4F944848, x4FF4C8CC, x6F9C5F5B);
	vxor(x686B8385, x27FFCBCD, x4F944848);

	vor(x6FFFDBCF, x694E5A8D, x0FFFC3CF);
	vxor(x6FC3DBF3, x003C003C, x6FFFDBCF);
	vand(x0000DBF3, a6, x6FC3DBF3);
	vxor(x4F9493BB, x4F944848, x0000DBF3);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vand(x00005151, a2, x0000DBF3);
	vnot(x96B1A572, x694E5A8D);
	vxor(x96B1F423, x00005151, x96B1A572);
	vxor(xD9256798, x4F9493BB, x96B1F423);
	vor(x10, x686B8385, a1);
	vxor(x11, x10, xD9256798);
	vxor(*out2, *out2, x11);
}
#elif andn && !triop && regs >= 16
/* s7-056931, 46 gates, 16 regs, 7 andn, 7/24/55/100/149 stalls, 67 biop */
/* Currently used for x86-64 SSE2 */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x7F878F78, x21101013, x7F979F7B, x30030CC0, x4F9493BB;
	vtype x6F9CDBFB, x0000DBFB, x00005151, x26DAC936, x26DA9867;
	vtype x21FF10FF, x21FFCB04, x2625C9C9, x27FFCBCD;
	vtype x27FF1036, x27FF103E, xB06B6C44, x97947C7A;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vor(x7F878F78, x0F000F00, x74878E78);
	vand(x21101013, a3, x699C585B);
	vor(x7F979F7B, x7F878F78, x21101013);
	vandn(x30030CC0, x3CC33CC3, x0FF0F00F);
	vxor(x4F9493BB, x7F979F7B, x30030CC0);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vor(x6F9CDBFB, x699C585B, x4F9493BB);
	vand(x0000DBFB, a6, x6F9CDBFB);
	vand(x00005151, a2, x0000DBFB);
	vxor(x26DAC936, x694E5A8D, x4F9493BB);
	vxor(x26DA9867, x00005151, x26DAC936);

	vor(x21FF10FF, a5, x21101013);
	vxor(x21FFCB04, x0000DBFB, x21FF10FF);
	vxor(x2625C9C9, a5, x26DAC936);
	vor(x27FFCBCD, x21FFCB04, x2625C9C9);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vxor(x27FF1036, x0000DBFB, x27FFCBCD);
	vor(x27FF103E, x003C003C, x27FF1036);
	vnot(xB06B6C44, x4F9493BB);
	vxor(x97947C7A, x27FF103E, xB06B6C44);
	vandn(x10, x97947C7A, a1);
	vxor(x11, x10, x26DA9867);
	vxor(*out2, *out2, x11);
}
#else
/* s7-056945, 46 gates, 16 regs, 7 andn, 10/31/62/107/156 stalls, 67 biop */
/* Currently used for MMX/SSE2 */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0FF00FF0, x3CC33CC3, x00003CC3, x0F000F00, x5A555A55, x00001841;
	vtype x00000F00, x33333C33, x7B777E77, x0FF0F00F, x74878E78;
	vtype x003C003C, x5A7D5A7D, x333300F0, x694E5A8D;
	vtype x0FF0CCCC, x000F0303, x5A505854, x33CC000F, x699C585B;
	vtype x7F878F78, x21101013, x7F979F7B, x30030CC0, x4F9493BB;
	vtype x6F9CDBFB, x0000DBFB, x00005151, x26DAC936, x26DA9867;
	vtype x27DA9877, x27DA438C, x2625C9C9, x27FFCBCD;
	vtype x27FF1036, x27FF103E, xB06B6C44, x97947C7A;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vxor(x0FF00FF0, a4, a5);
	vxor(x3CC33CC3, a3, x0FF00FF0);
	vand(x00003CC3, a6, x3CC33CC3);
	vand(x0F000F00, a4, x0FF00FF0);
	vxor(x5A555A55, a2, x0F000F00);
	vand(x00001841, x00003CC3, x5A555A55);

	vand(x00000F00, a6, x0F000F00);
	vxor(x33333C33, a3, x00000F00);
	vor(x7B777E77, x5A555A55, x33333C33);
	vxor(x0FF0F00F, a6, x0FF00FF0);
	vxor(x74878E78, x7B777E77, x0FF0F00F);
	vandn(x30, a1, x00001841);
	vxor(x31, x30, x74878E78);
	vxor(*out4, *out4, x31);

	vandn(x003C003C, a5, x3CC33CC3);
	vor(x5A7D5A7D, x5A555A55, x003C003C);
	vxor(x333300F0, x00003CC3, x33333C33);
	vxor(x694E5A8D, x5A7D5A7D, x333300F0);

	vxor(x0FF0CCCC, x00003CC3, x0FF0F00F);
	vandn(x000F0303, a4, x0FF0CCCC);
	vandn(x5A505854, x5A555A55, x000F0303);
	vxor(x33CC000F, a5, x333300F0);
	vxor(x699C585B, x5A505854, x33CC000F);

	vor(x7F878F78, x0F000F00, x74878E78);
	vand(x21101013, a3, x699C585B);
	vor(x7F979F7B, x7F878F78, x21101013);
	vandn(x30030CC0, x3CC33CC3, x0FF0F00F);
	vxor(x4F9493BB, x7F979F7B, x30030CC0);
	vandn(x00, x4F9493BB, a1);
	vxor(x01, x00, x694E5A8D);
	vxor(*out1, *out1, x01);

	vor(x6F9CDBFB, x699C585B, x4F9493BB);
	vand(x0000DBFB, a6, x6F9CDBFB);
	vand(x00005151, a2, x0000DBFB);
	vxor(x26DAC936, x694E5A8D, x4F9493BB);
	vxor(x26DA9867, x00005151, x26DAC936);

	vor(x27DA9877, x21101013, x26DA9867);
	vxor(x27DA438C, x0000DBFB, x27DA9877);
	vxor(x2625C9C9, a5, x26DAC936);
	vor(x27FFCBCD, x27DA438C, x2625C9C9);
	vand(x20, x27FFCBCD, a1);
	vxor(x21, x20, x699C585B);
	vxor(*out3, *out3, x21);

	vxor(x27FF1036, x0000DBFB, x27FFCBCD);
	vor(x27FF103E, x003C003C, x27FF1036);
	vnot(xB06B6C44, x4F9493BB);
	vxor(x97947C7A, x27FF103E, xB06B6C44);
	vandn(x10, x97947C7A, a1);
	vxor(x11, x10, x26DA9867);
	vxor(*out2, *out2, x11);
}
#endif

#if andn && !triop && regs <= 8
/* s8-004798, 41 gates, 14 regs, 7 andn, 7/35/76/118/160 stalls, 59 biop */
/* Currently used for MMX/SSE2 */
MAYBE_INLINE static void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0C0C0C0C, x0000F0F0, x00FFF00F, x00555005, x00515001;
	vtype x33000330, x77555775, x30303030, x3030CFCF, x30104745, x30555745;
	vtype x30EFB74A, xCF1048B5, x080A080A, xC71A40BF, xCB164CB3;
	vtype x9E4319E6, x000019E6, xF429738C, xF4296A6A, xC729695A;
	vtype xF4FF73FF, x33D61AA5, x03E6D56A, x56B3803F;
	vtype xC47C3D2F, xF77F3F3F, x693C26D9, x693CD926;
	vtype x9EFF19FF, x6100C000, x6151D001, x62B7056B;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x0C0C0C0C, a3, a2);
	vandn(x0000F0F0, a5, a3);
	vxor(x00FFF00F, a4, x0000F0F0);
	vand(x00555005, a1, x00FFF00F);
	vandn(x00515001, x00555005, x0C0C0C0C);

	vandn(x33000330, a2, x00FFF00F);
	vor(x77555775, a1, x33000330);
	vandn(x30303030, a2, a3);
	vxor(x3030CFCF, a5, x30303030);
	vand(x30104745, x77555775, x3030CFCF);
	vor(x30555745, x00555005, x30104745);

	vxor(x30EFB74A, x00FFF00F, x30104745);
	vnot(xCF1048B5, x30EFB74A);
	vandn(x080A080A, a3, x77555775);
	vxor(xC71A40BF, xCF1048B5, x080A080A);
	vxor(xCB164CB3, x0C0C0C0C, xC71A40BF);
	vor(x10, x00515001, a6);
	vxor(x11, x10, xCB164CB3);
	vxor(*out2, *out2, x11);

	vxor(x9E4319E6, a1, xCB164CB3);
	vand(x000019E6, a5, x9E4319E6);
	vxor(xF429738C, a2, xC71A40BF);
	vxor(xF4296A6A, x000019E6, xF429738C);
	vxor(xC729695A, x33000330, xF4296A6A);

	vor(xF4FF73FF, a4, xF429738C);
	vxor(x33D61AA5, xC729695A, xF4FF73FF);
	vxor(x03E6D56A, x3030CFCF, x33D61AA5);
	vxor(x56B3803F, a1, x03E6D56A);
	vand(x30, x56B3803F, a6);
	vxor(x31, x30, xC729695A);
	vxor(*out4, *out4, x31);

	vxor(xC47C3D2F, x30555745, xF4296A6A);
	vor(xF77F3F3F, a2, xC47C3D2F);
	vxor(x693C26D9, x9E4319E6, xF77F3F3F);
	vxor(x693CD926, a5, x693C26D9);
	vand(x20, x30555745, a6);
	vxor(x21, x20, x693CD926);
	vxor(*out3, *out3, x21);

	vor(x9EFF19FF, a4, x9E4319E6);
	vandn(x6100C000, x693CD926, x9EFF19FF);
	vor(x6151D001, x00515001, x6100C000);
	vxor(x62B7056B, x03E6D56A, x6151D001);
	vor(x00, x62B7056B, a6);
	vxor(x01, x00, xC729695A);
	vxor(*out1, *out1, x01);
}
#elif andn && triop && latency <= 2
/* s8-005322, 41 gates, 14 regs, 11 andn, 3/26/67/109/151 stalls, 62 biop */
MAYBE_INLINE static void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0C0C0C0C, x0000F0F0, x00FFF00F, x00555005, x00515001;
	vtype x33000330, x77555775, x30303030, x3030CFCF, x30104745, x30555745;
	vtype x30EFB74A, xCF1048B5, x080A080A, xC71A40BF, xCB164CB3;
	vtype x9E4319E6, x000019E6, x33001AD6, xF429738C, xC729695A;
	vtype x00332121, x9E4018C6, xC72996A5, x59698E63;
	vtype xF4FF73FF, x33D6E55A, x65656565, x56B3803F;
	vtype xF40083F0, x03D6640A, x61616161, x62B7056B;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x0C0C0C0C, a3, a2);
	vandn(x0000F0F0, a5, a3);
	vxor(x00FFF00F, a4, x0000F0F0);
	vand(x00555005, a1, x00FFF00F);
	vandn(x00515001, x00555005, x0C0C0C0C);

	vandn(x33000330, a2, x00FFF00F);
	vor(x77555775, a1, x33000330);
	vandn(x30303030, a2, a3);
	vxor(x3030CFCF, a5, x30303030);
	vand(x30104745, x77555775, x3030CFCF);
	vor(x30555745, x00555005, x30104745);

	vxor(x30EFB74A, x00FFF00F, x30104745);
	vnot(xCF1048B5, x30EFB74A);
	vandn(x080A080A, a3, x77555775);
	vxor(xC71A40BF, xCF1048B5, x080A080A);
	vxor(xCB164CB3, x0C0C0C0C, xC71A40BF);
	vor(x10, x00515001, a6);
	vxor(x11, x10, xCB164CB3);
	vxor(*out2, *out2, x11);

	vxor(x9E4319E6, a1, xCB164CB3);
	vand(x000019E6, a5, x9E4319E6);
	vxor(x33001AD6, x33000330, x000019E6);
	vxor(xF429738C, a2, xC71A40BF);
	vxor(xC729695A, x33001AD6, xF429738C);

	vandn(x00332121, a2, x33001AD6);
	vandn(x9E4018C6, x9E4319E6, x00332121);
	vxor(xC72996A5, a5, xC729695A);
	vxor(x59698E63, x9E4018C6, xC72996A5);
	vandn(x20, x30555745, a6);
	vxor(x21, x20, x59698E63);
	vxor(*out3, *out3, x21);

	vor(xF4FF73FF, a4, xF429738C);
	vxor(x33D6E55A, xC72996A5, xF4FF73FF);
	vxor(x65656565, a1, x30303030);
	vxor(x56B3803F, x33D6E55A, x65656565);
	vand(x30, x56B3803F, a6);
	vxor(x31, x30, xC729695A);
	vxor(*out4, *out4, x31);

	vxor(xF40083F0, x00FFF00F, xF4FF73FF);
	vandn(x03D6640A, x33D6E55A, xF40083F0);
	vandn(x61616161, x65656565, x0C0C0C0C);
	vxor(x62B7056B, x03D6640A, x61616161);
	vor(x00, x62B7056B, a6);
	vxor(x01, x00, xC729695A);
	vxor(*out1, *out1, x01);
}
#elif triop && (latency >= 4 || (!andn && latency == 3))
/* s8-015415, 41 gates, 14 regs, 7 andn, 5/23/57/98/140 stalls, 60 biop */
MAYBE_INLINE static void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0C0C0C0C, x0000F0F0, x00FFF00F, x00555005, x00515001;
	vtype x33000330, x77555775, x30303030, x3030CFCF, x30104745, x30555745;
	vtype xFF000FF0, xCF1048B5, x080A080A, xC71A40BF, xCB164CB3;
	vtype xF429738C, xC72970BC, x9E4319E6, x000019E6, xC729695A;
	vtype xF77C3E1F, xF77F3F3F, x9E43E619, x693CD926;
	vtype xF719A695, xF4FF73FF, x03E6D56A, x56B3803F;
	vtype xF700A600, x61008000, x03B7856B, x62B7056B;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x0C0C0C0C, a3, a2);
	vandn(x0000F0F0, a5, a3);
	vxor(x00FFF00F, a4, x0000F0F0);
	vand(x00555005, a1, x00FFF00F);
	vandn(x00515001, x00555005, x0C0C0C0C);

	vandn(x33000330, a2, x00FFF00F);
	vor(x77555775, a1, x33000330);
	vandn(x30303030, a2, a3);
	vxor(x3030CFCF, a5, x30303030);
	vand(x30104745, x77555775, x3030CFCF);
	vor(x30555745, x00555005, x30104745);

	vnot(xFF000FF0, x00FFF00F);
	vxor(xCF1048B5, x30104745, xFF000FF0);
	vandn(x080A080A, a3, x77555775);
	vxor(xC71A40BF, xCF1048B5, x080A080A);
	vxor(xCB164CB3, x0C0C0C0C, xC71A40BF);
	vor(x10, x00515001, a6);
	vxor(x11, x10, xCB164CB3);
	vxor(*out2, *out2, x11);

	vxor(xF429738C, a2, xC71A40BF);
	vxor(xC72970BC, x33000330, xF429738C);
	vxor(x9E4319E6, a1, xCB164CB3);
	vand(x000019E6, a5, x9E4319E6);
	vxor(xC729695A, xC72970BC, x000019E6);

	vxor(xF77C3E1F, x30555745, xC729695A);
	vor(xF77F3F3F, a2, xF77C3E1F);
	vxor(x9E43E619, a5, x9E4319E6);
	vxor(x693CD926, xF77F3F3F, x9E43E619);
	vand(x20, x30555745, a6);
	vxor(x21, x20, x693CD926);
	vxor(*out3, *out3, x21);

	vxor(xF719A695, x3030CFCF, xC729695A);
	vor(xF4FF73FF, a4, xF429738C);
	vxor(x03E6D56A, xF719A695, xF4FF73FF);
	vxor(x56B3803F, a1, x03E6D56A);
	vand(x30, x56B3803F, a6);
	vxor(x31, x30, xC729695A);
	vxor(*out4, *out4, x31);

	vandn(xF700A600, xF719A695, a4);
	vand(x61008000, x693CD926, xF700A600);
	vxor(x03B7856B, x00515001, x03E6D56A);
	vxor(x62B7056B, x61008000, x03B7856B);
	vor(x00, x62B7056B, a6);
	vxor(x01, x00, xC729695A);
	vxor(*out1, *out1, x01);
}
#elif !andn || !triop
/* s8-019374, 41 gates, 14 regs, 7 andn, 4/25/61/103/145 stalls, 59 biop */
/* Currently used for x86-64 SSE2 */
MAYBE_INLINE static void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0C0C0C0C, x0000F0F0, x00FFF00F, x00555005, x00515001;
	vtype x33000330, x77555775, x30303030, x3030CFCF, x30104745, x30555745;
	vtype xFF000FF0, xCF1048B5, x080A080A, xC71A40BF, xCB164CB3;
	vtype x9E4319E6, x000019E6, xF429738C, xF4296A6A, xC729695A;
	vtype xC47C3D2F, xF77F3F3F, x9E43E619, x693CD926;
	vtype xF719A695, xF4FF73FF, x03E6D56A, x56B3803F;
	vtype xF700A600, x61008000, x03B7856B, x62B7056B;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x0C0C0C0C, a3, a2);
	vandn(x0000F0F0, a5, a3);
	vxor(x00FFF00F, a4, x0000F0F0);
	vand(x00555005, a1, x00FFF00F);
	vandn(x00515001, x00555005, x0C0C0C0C);

	vandn(x33000330, a2, x00FFF00F);
	vor(x77555775, a1, x33000330);
	vandn(x30303030, a2, a3);
	vxor(x3030CFCF, a5, x30303030);
	vand(x30104745, x77555775, x3030CFCF);
	vor(x30555745, x00555005, x30104745);

	vnot(xFF000FF0, x00FFF00F);
	vxor(xCF1048B5, x30104745, xFF000FF0);
	vandn(x080A080A, a3, x77555775);
	vxor(xC71A40BF, xCF1048B5, x080A080A);
	vxor(xCB164CB3, x0C0C0C0C, xC71A40BF);
	vor(x10, x00515001, a6);
	vxor(x11, x10, xCB164CB3);
	vxor(*out2, *out2, x11);

	vxor(x9E4319E6, a1, xCB164CB3);
	vand(x000019E6, a5, x9E4319E6);
	vxor(xF429738C, a2, xC71A40BF);
	vxor(xF4296A6A, x000019E6, xF429738C);
	vxor(xC729695A, x33000330, xF4296A6A);

	vxor(xC47C3D2F, x30555745, xF4296A6A);
	vor(xF77F3F3F, a2, xC47C3D2F);
	vxor(x9E43E619, a5, x9E4319E6);
	vxor(x693CD926, xF77F3F3F, x9E43E619);
	vand(x20, x30555745, a6);
	vxor(x21, x20, x693CD926);
	vxor(*out3, *out3, x21);

	vxor(xF719A695, x3030CFCF, xC729695A);
	vor(xF4FF73FF, a4, xF429738C);
	vxor(x03E6D56A, xF719A695, xF4FF73FF);
	vxor(x56B3803F, a1, x03E6D56A);
	vand(x30, x56B3803F, a6);
	vxor(x31, x30, xC729695A);
	vxor(*out4, *out4, x31);

	vandn(xF700A600, xF719A695, a4);
	vand(x61008000, x693CD926, xF700A600);
	vxor(x03B7856B, x00515001, x03E6D56A);
	vxor(x62B7056B, x61008000, x03B7856B);
	vor(x00, x62B7056B, a6);
	vxor(x01, x00, xC729695A);
	vxor(*out1, *out1, x01);
}
#else
/* s8-019630, 41 gates, 14 regs, 11 andn, 4/21/60/101/143 stalls, 62 biop */
MAYBE_INLINE static void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0C0C0C0C, x0000F0F0, x00FFF00F, x00555005, x00515001;
	vtype x33000330, x77555775, x30303030, x3030CFCF, x30104745, x30555745;
	vtype xFF000FF0, xCF1048B5, x080A080A, xC71A40BF, xCB164CB3;
	vtype x9E4319E6, x000019E6, x33001AD6, xF429738C, xC729695A;
	vtype x00332121, x9E4018C6, xC72996A5, x59698E63;
	vtype xF4FF73FF, x33D6E55A, x65656565, x56B3803F;
	vtype x38299955, x03D6640A, x61616161, x62B7056B;
	vtype x00, x01, x10, x11, x20, x21, x30, x31;

	vandn(x0C0C0C0C, a3, a2);
	vandn(x0000F0F0, a5, a3);
	vxor(x00FFF00F, a4, x0000F0F0);
	vand(x00555005, a1, x00FFF00F);
	vandn(x00515001, x00555005, x0C0C0C0C);

	vandn(x33000330, a2, x00FFF00F);
	vor(x77555775, a1, x33000330);
	vandn(x30303030, a2, a3);
	vxor(x3030CFCF, a5, x30303030);
	vand(x30104745, x77555775, x3030CFCF);
	vor(x30555745, x00555005, x30104745);

	vnot(xFF000FF0, x00FFF00F);
	vxor(xCF1048B5, x30104745, xFF000FF0);
	vandn(x080A080A, a3, x77555775);
	vxor(xC71A40BF, xCF1048B5, x080A080A);
	vxor(xCB164CB3, x0C0C0C0C, xC71A40BF);
	vor(x10, x00515001, a6);
	vxor(x11, x10, xCB164CB3);
	vxor(*out2, *out2, x11);

	vxor(x9E4319E6, a1, xCB164CB3);
	vand(x000019E6, a5, x9E4319E6);
	vxor(x33001AD6, x33000330, x000019E6);
	vxor(xF429738C, a2, xC71A40BF);
	vxor(xC729695A, x33001AD6, xF429738C);

	vandn(x00332121, a2, x33001AD6);
	vandn(x9E4018C6, x9E4319E6, x00332121);
	vxor(xC72996A5, a5, xC729695A);
	vxor(x59698E63, x9E4018C6, xC72996A5);
	vandn(x20, x30555745, a6);
	vxor(x21, x20, x59698E63);
	vxor(*out3, *out3, x21);

	vor(xF4FF73FF, a4, xF429738C);
	vxor(x33D6E55A, xC72996A5, xF4FF73FF);
	vxor(x65656565, a1, x30303030);
	vxor(x56B3803F, x33D6E55A, x65656565);
	vand(x30, x56B3803F, a6);
	vxor(x31, x30, xC729695A);
	vxor(*out4, *out4, x31);

	vxor(x38299955, xFF000FF0, xC72996A5);
	vandn(x03D6640A, x33D6E55A, x38299955);
	vandn(x61616161, x65656565, x0C0C0C0C);
	vxor(x62B7056B, x03D6640A, x61616161);
	vor(x00, x62B7056B, a6);
	vxor(x01, x00, xC729695A);
	vxor(*out1, *out1, x01);
}
#endif
