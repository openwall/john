/*
 * Bitslice DES S-boxes making use of a vector conditional select operation
 * (e.g., vsel on PowerPC with AltiVec).
 *
 * Gate counts: 36 33 33 26 35 34 34 32
 * Average: 32.875
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

#undef regs
#if defined(__x86_64__) && defined(__XOP__)
#define regs 16
#elif defined(__x86_64__)
#define regs 15
#elif defined(__i386__)
/* Hopefully, AMD XOP (but in 32-bit mode) */
#define regs 8
#else
/* PowerPC with AltiVec, etc. */
#define regs 32
#endif

#undef latency
/* Latency 2 may also mean dual-issue with latency 1 */
#define latency 2

#if regs >= 17 || latency >= 3
/* s1-000010, 36 gates, 17 regs, 8/28/65/102/139 stall cycles */
MAYBE_INLINE static void
s1(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0F0F3333, x3C3C3C3C, x55FF55FF, x69C369C3, x0903B73F, x09FCB7C0,
	    x5CA9E295;
	vtype x55AFD1B7, x3C3C69C3, x6993B874;
	vtype x5CEDE59F, x09FCE295, x5D91A51E, x529E962D;
	vtype x29EEADC0, x4B8771A3, x428679F3, x6B68D433;
	vtype x5BA7E193, x026F12F3, x6B27C493, x94D83B6C;
	vtype x965E0B0F, x3327A113, x847F0A1F, xD6E19C32;
	vtype x0DBCE883, x3A25A215, x37994A96;
	vtype xC9C93B62, x89490F02, xB96C2D16;
	vtype x0, x1, x2, x3;

	vsel(x0F0F3333, a3, a2, a5);
	vxor(x3C3C3C3C, a2, a3);
	vor(x55FF55FF, a1, a4);
	vxor(x69C369C3, x3C3C3C3C, x55FF55FF);
	vsel(x0903B73F, a5, x0F0F3333, x69C369C3);
	vxor(x09FCB7C0, a4, x0903B73F);
	vxor(x5CA9E295, a1, x09FCB7C0);

	vsel(x55AFD1B7, x5CA9E295, x55FF55FF, x0F0F3333);
	vsel(x3C3C69C3, x3C3C3C3C, x69C369C3, a5);
	vxor(x6993B874, x55AFD1B7, x3C3C69C3);

	vsel(x5CEDE59F, x55FF55FF, x5CA9E295, x6993B874);
	vsel(x09FCE295, x09FCB7C0, x5CA9E295, a5);
	vsel(x5D91A51E, x5CEDE59F, x6993B874, x09FCE295);
	vxor(x529E962D, x0F0F3333, x5D91A51E);

	vsel(x29EEADC0, x69C369C3, x09FCB7C0, x5CEDE59F);
	vsel(x4B8771A3, x0F0F3333, x69C369C3, x5CA9E295);
	vsel(x428679F3, a5, x4B8771A3, x529E962D);
	vxor(x6B68D433, x29EEADC0, x428679F3);

	vsel(x5BA7E193, x5CA9E295, x4B8771A3, a3);
	vsel(x026F12F3, a4, x0F0F3333, x529E962D);
	vsel(x6B27C493, x6B68D433, x5BA7E193, x026F12F3);
	vnot(x94D83B6C, x6B27C493);
	vsel(x0, x94D83B6C, x6B68D433, a6);
	vxor(*out1, *out1, x0);

	vsel(x965E0B0F, x94D83B6C, a3, x428679F3);
	vsel(x3327A113, x5BA7E193, a2, x69C369C3);
	vsel(x847F0A1F, x965E0B0F, a4, x3327A113);
	vxor(xD6E19C32, x529E962D, x847F0A1F);
	vsel(x1, xD6E19C32, x5CA9E295, a6);
	vxor(*out2, *out2, x1);

	vsel(x0DBCE883, x09FCE295, x3C3C69C3, x847F0A1F);
	vsel(x3A25A215, x3327A113, x5CA9E295, x0903B73F);
	vxor(x37994A96, x0DBCE883, x3A25A215);
	vsel(x3, x37994A96, x529E962D, a6);
	vxor(*out4, *out4, x3);

	vsel(xC9C93B62, x94D83B6C, x69C369C3, x5D91A51E);
	vsel(x89490F02, a3, xC9C93B62, x965E0B0F);
	vsel(xB96C2D16, x89490F02, x3C3C3C3C, x3A25A215);
	vsel(x2, xB96C2D16, x6993B874, a6);
	vxor(*out3, *out3, x2);
}
#else
/* s1-000011, 36 gates, 16 regs, 10/37/74/111/148 stall cycles */
MAYBE_INLINE static void
s1(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0F0F3333, x3C3C3C3C, x55FF55FF, x69C369C3, x0903B73F, x09FCB7C0,
	    x5CA9E295;
	vtype x55AFD1B7, x3C3C69C3, x6993B874;
	vtype x5CEDE59F, x09FCE295, x5D91A51E, x529E962D;
	vtype x29EEADC0, x4B8771A3, x428679F3, x6B68D433;
	vtype x5BA7E193, x026F12F3, x6B27C493, x94D83B6C;
	vtype x965E0B0F, x3327A113, x847F0A1F, xD6E19C32;
	vtype x0DBCE883, x3A25A215, x37994A96;
	vtype x8A487EA7, x8B480F07, xB96C2D16;
	vtype x0, x1, x2, x3;

	vsel(x0F0F3333, a3, a2, a5);
	vxor(x3C3C3C3C, a2, a3);
	vor(x55FF55FF, a1, a4);
	vxor(x69C369C3, x3C3C3C3C, x55FF55FF);
	vsel(x0903B73F, a5, x0F0F3333, x69C369C3);
	vxor(x09FCB7C0, a4, x0903B73F);
	vxor(x5CA9E295, a1, x09FCB7C0);

	vsel(x55AFD1B7, x5CA9E295, x55FF55FF, x0F0F3333);
	vsel(x3C3C69C3, x3C3C3C3C, x69C369C3, a5);
	vxor(x6993B874, x55AFD1B7, x3C3C69C3);

	vsel(x5CEDE59F, x55FF55FF, x5CA9E295, x6993B874);
	vsel(x09FCE295, x09FCB7C0, x5CA9E295, a5);
	vsel(x5D91A51E, x5CEDE59F, x6993B874, x09FCE295);
	vxor(x529E962D, x0F0F3333, x5D91A51E);

	vsel(x29EEADC0, x69C369C3, x09FCB7C0, x5CEDE59F);
	vsel(x4B8771A3, x0F0F3333, x69C369C3, x5CA9E295);
	vsel(x428679F3, a5, x4B8771A3, x529E962D);
	vxor(x6B68D433, x29EEADC0, x428679F3);

	vsel(x5BA7E193, x5CA9E295, x4B8771A3, a3);
	vsel(x026F12F3, a4, x0F0F3333, x529E962D);
	vsel(x6B27C493, x6B68D433, x5BA7E193, x026F12F3);
	vnot(x94D83B6C, x6B27C493);
	vsel(x0, x94D83B6C, x6B68D433, a6);
	vxor(*out1, *out1, x0);

	vsel(x965E0B0F, x94D83B6C, a3, x428679F3);
	vsel(x3327A113, x5BA7E193, a2, x69C369C3);
	vsel(x847F0A1F, x965E0B0F, a4, x3327A113);
	vxor(xD6E19C32, x529E962D, x847F0A1F);
	vsel(x1, xD6E19C32, x5CA9E295, a6);
	vxor(*out2, *out2, x1);

	vsel(x0DBCE883, x09FCE295, x3C3C69C3, x847F0A1F);
	vsel(x3A25A215, x3327A113, x5CA9E295, x0903B73F);
	vxor(x37994A96, x0DBCE883, x3A25A215);
	vsel(x3, x37994A96, x529E962D, a6);
	vxor(*out4, *out4, x3);

	vxor(x8A487EA7, x5CA9E295, xD6E19C32);
	vsel(x8B480F07, a3, x8A487EA7, x847F0A1F);
	vsel(xB96C2D16, x8B480F07, x3C3C3C3C, x3A25A215);
	vsel(x2, xB96C2D16, x6993B874, a6);
	vxor(*out3, *out3, x2);
}
#endif

#if regs >= 18 && latency <= 2
/* s2-000000, 33 gates, 18 regs, 3/26/57/90/125 stall cycles */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x55553333, x0055FF33, x33270F03, x66725A56, x00FFFF00, x668DA556;
	vtype x0F0F5A56, xF0F0A5A9, xA5A5969A, xA55A699A;
	vtype x0F5AF03C, x6600FF56, x87A5F09C;
	vtype xA55A963C, x3C69C30F, xB44BC32D;
	vtype x66D7CC56, x0F4B0F2D, x699CC37B, x996C66D2;
	vtype xB46C662D, x278DB412, xB66CB43B;
	vtype xD2DC4E52, x27993333, xD2994E33;
	vtype x278D0F2D, x2E0E547B, x09976748;
	vtype x0, x1, x2, x3;

	vsel(x55553333, a1, a3, a6);
	vsel(x0055FF33, a6, x55553333, a5);
	vsel(x33270F03, a3, a4, x0055FF33);
	vxor(x66725A56, a1, x33270F03);
	vxor(x00FFFF00, a5, a6);
	vxor(x668DA556, x66725A56, x00FFFF00);

	vsel(x0F0F5A56, a4, x66725A56, a6);
	vnot(xF0F0A5A9, x0F0F5A56);
	vxor(xA5A5969A, x55553333, xF0F0A5A9);
	vxor(xA55A699A, x00FFFF00, xA5A5969A);
	vsel(x1, xA55A699A, x668DA556, a2);
	vxor(*out2, *out2, x1);

	vxor(x0F5AF03C, a4, x0055FF33);
	vsel(x6600FF56, x66725A56, a6, x00FFFF00);
	vsel(x87A5F09C, xA5A5969A, x0F5AF03C, x6600FF56);

	vsel(xA55A963C, xA5A5969A, x0F5AF03C, a5);
	vxor(x3C69C30F, a3, x0F5AF03C);
	vsel(xB44BC32D, xA55A963C, x3C69C30F, a1);

	vsel(x66D7CC56, x66725A56, x668DA556, xA5A5969A);
	vsel(x0F4B0F2D, a4, xB44BC32D, a5);
	vxor(x699CC37B, x66D7CC56, x0F4B0F2D);
	vxor(x996C66D2, xF0F0A5A9, x699CC37B);
	vsel(x0, x996C66D2, xB44BC32D, a2);
	vxor(*out1, *out1, x0);

	vsel(xB46C662D, xB44BC32D, x996C66D2, x00FFFF00);
	vsel(x278DB412, x668DA556, xA5A5969A, a1);
	vsel(xB66CB43B, xB46C662D, x278DB412, x6600FF56);

	vsel(xD2DC4E52, x66D7CC56, x996C66D2, xB44BC32D);
	vsel(x27993333, x278DB412, a3, x0055FF33);
	vsel(xD2994E33, xD2DC4E52, x27993333, a5);
	vsel(x3, x87A5F09C, xD2994E33, a2);
	vxor(*out4, *out4, x3);

	vsel(x278D0F2D, x278DB412, x0F4B0F2D, a6);
	vsel(x2E0E547B, x0F0F5A56, xB66CB43B, x278D0F2D);
	vxor(x09976748, x27993333, x2E0E547B);
	vsel(x2, xB66CB43B, x09976748, a2);
	vxor(*out3, *out3, x2);
}
#elif regs >= 18 && latency >= 4
/* s2-000002, 33 gates, 18 regs, 4/22/49/82/117 stall cycles */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x55553333, x0055FF33, x33270F03, x66725A56, x00FFFF00, x668DA556;
	vtype x0F0F5A56, xF0F0A5A9, xA5A5969A, xA55A699A;
	vtype x0F5AF03C, x6600FF56, x87A5F09C;
	vtype xA55A963C, x3C69C30F, xB44BC32D;
	vtype x0F4B0F2D, x66D7CC56, x962769FF, x996C66D2;
	vtype xB46C662D, x278DB412, xB66CB43B;
	vtype xD2DC4E52, x27993333, xD2994E33;
	vtype x278D0F2D, x2E0E547B, x09976748;
	vtype x0, x1, x2, x3;

	vsel(x55553333, a1, a3, a6);
	vsel(x0055FF33, a6, x55553333, a5);
	vsel(x33270F03, a3, a4, x0055FF33);
	vxor(x66725A56, a1, x33270F03);
	vxor(x00FFFF00, a5, a6);
	vxor(x668DA556, x66725A56, x00FFFF00);

	vsel(x0F0F5A56, a4, x66725A56, a6);
	vnot(xF0F0A5A9, x0F0F5A56);
	vxor(xA5A5969A, x55553333, xF0F0A5A9);
	vxor(xA55A699A, x00FFFF00, xA5A5969A);
	vsel(x1, xA55A699A, x668DA556, a2);
	vxor(*out2, *out2, x1);

	vxor(x0F5AF03C, a4, x0055FF33);
	vsel(x6600FF56, x66725A56, a6, x00FFFF00);
	vsel(x87A5F09C, xA5A5969A, x0F5AF03C, x6600FF56);

	vsel(xA55A963C, xA5A5969A, x0F5AF03C, a5);
	vxor(x3C69C30F, a3, x0F5AF03C);
	vsel(xB44BC32D, xA55A963C, x3C69C30F, a1);

	vsel(x0F4B0F2D, a4, xB44BC32D, a5);
	vsel(x66D7CC56, x66725A56, x668DA556, xA5A5969A);
	vxor(x962769FF, xF0F0A5A9, x66D7CC56);
	vxor(x996C66D2, x0F4B0F2D, x962769FF);
	vsel(x0, x996C66D2, xB44BC32D, a2);
	vxor(*out1, *out1, x0);

	vsel(xB46C662D, xB44BC32D, x996C66D2, x00FFFF00);
	vsel(x278DB412, x668DA556, xA5A5969A, a1);
	vsel(xB66CB43B, xB46C662D, x278DB412, x6600FF56);

	vsel(xD2DC4E52, x66D7CC56, x996C66D2, xB44BC32D);
	vsel(x27993333, x278DB412, a3, x0055FF33);
	vsel(xD2994E33, xD2DC4E52, x27993333, a5);
	vsel(x3, x87A5F09C, xD2994E33, a2);
	vxor(*out4, *out4, x3);

	vsel(x278D0F2D, x278DB412, x0F4B0F2D, a6);
	vsel(x2E0E547B, x0F0F5A56, xB66CB43B, x278D0F2D);
	vxor(x09976748, x27993333, x2E0E547B);
	vsel(x2, xB66CB43B, x09976748, a2);
	vxor(*out3, *out3, x2);
}
#else
/* s2-000012, 33 gates, 17 regs, 5/17/51/86/121 stall cycles */
MAYBE_INLINE static void
s2(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x55553333, x0055FF33, x33270F03, x66725A56, x00FFFF00, x668DA556;
	vtype x0F0F5A56, xF0F0A5A9, xA5A5969A, xA55A699A;
	vtype x0F5AF03C, x6600FF56, x87A5F09C;
	vtype x875AF03C, xF00F0FA9, xB44BC32D;
	vtype x6627A556, xD26C667B, x278DB412, xB66CB43B;
	vtype x668DC32D, x99723CD2, x996C66D2;
	vtype xD20E4EA9, x27993333, xD2994E33;
	vtype x9927C3E1, x089F3F0C, x09976748;
	vtype x0, x1, x2, x3;

	vsel(x55553333, a1, a3, a6);
	vsel(x0055FF33, a6, x55553333, a5);
	vsel(x33270F03, a3, a4, x0055FF33);
	vxor(x66725A56, a1, x33270F03);
	vxor(x00FFFF00, a5, a6);
	vxor(x668DA556, x66725A56, x00FFFF00);

	vsel(x0F0F5A56, a4, x66725A56, a6);
	vnot(xF0F0A5A9, x0F0F5A56);
	vxor(xA5A5969A, x55553333, xF0F0A5A9);
	vxor(xA55A699A, x00FFFF00, xA5A5969A);
	vsel(x1, xA55A699A, x668DA556, a2);
	vxor(*out2, *out2, x1);

	vxor(x0F5AF03C, a4, x0055FF33);
	vsel(x6600FF56, x66725A56, a6, x00FFFF00);
	vsel(x87A5F09C, xA5A5969A, x0F5AF03C, x6600FF56);

	vsel(x875AF03C, x87A5F09C, x0F5AF03C, a5);
	vsel(xF00F0FA9, xF0F0A5A9, a4, x00FFFF00);
	vsel(xB44BC32D, x875AF03C, xF00F0FA9, a3);

	vsel(x6627A556, x66725A56, x668DA556, x0055FF33);
	vxor(xD26C667B, xB44BC32D, x6627A556);
	vsel(x278DB412, x668DA556, xA5A5969A, a1);
	vsel(xB66CB43B, xD26C667B, x278DB412, x6600FF56);

	vsel(x668DC32D, x668DA556, xB44BC32D, a6);
	vnot(x99723CD2, x668DC32D);
	vsel(x996C66D2, x99723CD2, xD26C667B, x00FFFF00);
	vsel(x0, x996C66D2, xB44BC32D, a2);
	vxor(*out1, *out1, x0);

	vsel(xD20E4EA9, xF00F0FA9, xD26C667B, x668DC32D);
	vsel(x27993333, x278DB412, a3, x0055FF33);
	vsel(xD2994E33, xD20E4EA9, x27993333, a5);
	vsel(x3, x87A5F09C, xD2994E33, a2);
	vxor(*out4, *out4, x3);

	vxor(x9927C3E1, x0055FF33, x99723CD2);
	vsel(x089F3F0C, a4, x00FFFF00, x27993333);
	vsel(x09976748, x089F3F0C, x9927C3E1, x0F0F5A56);
	vsel(x2, xB66CB43B, x09976748, a2);
	vxor(*out3, *out3, x2);
}
#endif

#if latency >= 3
/* s3-000000, 33 gates, 17 regs, 6/10/33/66/102 stall cycles */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0F330F33, x0F33F0CC, x5A66A599;
	vtype x2111B7BB, x03FF3033, x05BB50EE, x074F201F, x265E97A4;
	vtype x556BA09E, x665A93AC, x99A56C53;
	vtype x25A1A797, x5713754C, x66559355, x47B135C6;
	vtype x9A5A5C60, xD07AF8F8, x87698DB4, xE13C1EE1;
	vtype x9E48CDE4, x655B905E, x00A55CFF, x9E49915E;
	vtype xD6599874, x05330022, xD2699876;
	vtype x665F9364, xD573F0F2, xB32C6396;
	vtype x0, x1, x2, x3;

	vsel(x0F330F33, a4, a3, a5);
	vxor(x0F33F0CC, a6, x0F330F33);
	vxor(x5A66A599, a2, x0F33F0CC);

	vsel(x2111B7BB, a3, a6, x5A66A599);
	vsel(x03FF3033, a5, a3, x0F33F0CC);
	vsel(x05BB50EE, a5, x0F33F0CC, a2);
	vsel(x074F201F, x03FF3033, a4, x05BB50EE);
	vxor(x265E97A4, x2111B7BB, x074F201F);

	vsel(x556BA09E, x5A66A599, x05BB50EE, a4);
	vsel(x665A93AC, x556BA09E, x265E97A4, a3);
	vnot(x99A56C53, x665A93AC);
	vsel(x1, x265E97A4, x99A56C53, a1);
	vxor(*out2, *out2, x1);

	vxor(x25A1A797, x03FF3033, x265E97A4);
	vsel(x5713754C, a2, x0F33F0CC, x074F201F);
	vsel(x66559355, x665A93AC, a2, a5);
	vsel(x47B135C6, x25A1A797, x5713754C, x66559355);

	vxor(x9A5A5C60, x03FF3033, x99A56C53);
	vsel(xD07AF8F8, x9A5A5C60, x556BA09E, x5A66A599);
	vxor(x87698DB4, x5713754C, xD07AF8F8);
	vxor(xE13C1EE1, x66559355, x87698DB4);

	vsel(x9E48CDE4, x9A5A5C60, x87698DB4, x265E97A4);
	vsel(x655B905E, x66559355, x05BB50EE, a4);
	vsel(x00A55CFF, a5, a6, x9A5A5C60);
	vsel(x9E49915E, x9E48CDE4, x655B905E, x00A55CFF);
	vsel(x0, x9E49915E, xE13C1EE1, a1);
	vxor(*out1, *out1, x0);

	vsel(xD6599874, xD07AF8F8, x66559355, x0F33F0CC);
	vand(x05330022, x0F330F33, x05BB50EE);
	vsel(xD2699876, xD6599874, x00A55CFF, x05330022);
	vsel(x3, x5A66A599, xD2699876, a1);
	vxor(*out4, *out4, x3);

	vsel(x665F9364, x265E97A4, x66559355, x47B135C6);
	vsel(xD573F0F2, xD07AF8F8, x05330022, a4);
	vxor(xB32C6396, x665F9364, xD573F0F2);
	vsel(x2, xB32C6396, x47B135C6, a1);
	vxor(*out3, *out3, x2);
}
#else
/* s3-000004, 33 gates, 17 regs, 3/13/41/77/113 stall cycles */
MAYBE_INLINE static void
s3(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0F330F33, x0F33F0CC, x5A66A599;
	vtype x2111B7BB, x03FF3033, x05BB50EE, x074F201F, x265E97A4;
	vtype x556BA09E, x665A93AC, x99A56C53;
	vtype x25A1A797, x5713754C, x66559355, x47B135C6;
	vtype x9A5A5C60, xD07AF8F8, x87698DB4, xE13C1EE1;
	vtype x000CFFCF, x9A485CCE, x0521DDF4, x9E49915E;
	vtype xD069F8B4, x030FF0C3, xD2699876;
	vtype xD579DDF4, xD579F0C3, xB32C6396;
	vtype x0, x1, x2, x3;

	vsel(x0F330F33, a4, a3, a5);
	vxor(x0F33F0CC, a6, x0F330F33);
	vxor(x5A66A599, a2, x0F33F0CC);

	vsel(x2111B7BB, a3, a6, x5A66A599);
	vsel(x03FF3033, a5, a3, x0F33F0CC);
	vsel(x05BB50EE, a5, x0F33F0CC, a2);
	vsel(x074F201F, x03FF3033, a4, x05BB50EE);
	vxor(x265E97A4, x2111B7BB, x074F201F);

	vsel(x556BA09E, x5A66A599, x05BB50EE, a4);
	vsel(x665A93AC, x556BA09E, x265E97A4, a3);
	vnot(x99A56C53, x665A93AC);
	vsel(x1, x265E97A4, x99A56C53, a1);
	vxor(*out2, *out2, x1);

	vxor(x25A1A797, x03FF3033, x265E97A4);
	vsel(x5713754C, a2, x0F33F0CC, x074F201F);
	vsel(x66559355, x665A93AC, a2, a5);
	vsel(x47B135C6, x25A1A797, x5713754C, x66559355);

	vxor(x9A5A5C60, x03FF3033, x99A56C53);
	vsel(xD07AF8F8, x9A5A5C60, x556BA09E, x5A66A599);
	vxor(x87698DB4, x5713754C, xD07AF8F8);
	vxor(xE13C1EE1, x66559355, x87698DB4);

	vsel(x000CFFCF, a4, a6, x0F33F0CC);
	vsel(x9A485CCE, x9A5A5C60, x000CFFCF, x05BB50EE);
	vsel(x0521DDF4, x87698DB4, a6, x9A5A5C60);
	vsel(x9E49915E, x9A485CCE, x66559355, x0521DDF4);
	vsel(x0, x9E49915E, xE13C1EE1, a1);
	vxor(*out1, *out1, x0);

	vsel(xD069F8B4, xD07AF8F8, x87698DB4, a5);
	vsel(x030FF0C3, x000CFFCF, x03FF3033, a4);
	vsel(xD2699876, xD069F8B4, x9E49915E, x030FF0C3);
	vsel(x3, x5A66A599, xD2699876, a1);
	vxor(*out4, *out4, x3);

	vsel(xD579DDF4, xD07AF8F8, a2, x5713754C);
	vsel(xD579F0C3, xD579DDF4, x030FF0C3, a6);
	vxor(xB32C6396, x66559355, xD579F0C3);
	vsel(x2, xB32C6396, x47B135C6, a1);
	vxor(*out3, *out3, x2);
}
#endif

#if regs >= 13
/* s4-000014, 26 gates, 13 regs, 2/17/42/70/98 stall cycles */
MAYBE_INLINE static void
s4(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0505AFAF, x0555AF55, x0A5AA05A, x46566456, x0A0A5F5F, x0AF55FA0,
	    x0AF50F0F, x4CA36B59;
	vtype xB35C94A6;
	vtype x01BB23BB, x5050FAFA, xA31C26BE, xA91679E1;
	vtype x56E9861E;
	vtype x50E9FA1E, x0AF55F00, x827D9784, xD2946D9A;
	vtype x31F720B3, x11FB21B3, x4712A7AD, x9586CA37;
	vtype x0, x1, x2, x3;

	vsel(x0505AFAF, a5, a3, a1);
	vsel(x0555AF55, x0505AFAF, a1, a4);
	vxor(x0A5AA05A, a3, x0555AF55);
	vsel(x46566456, a1, x0A5AA05A, a2);
	vsel(x0A0A5F5F, a3, a5, a1);
	vxor(x0AF55FA0, a4, x0A0A5F5F);
	vsel(x0AF50F0F, x0AF55FA0, a3, a5);
	vxor(x4CA36B59, x46566456, x0AF50F0F);

	vnot(xB35C94A6, x4CA36B59);

	vsel(x01BB23BB, a4, a2, x0555AF55);
	vxor(x5050FAFA, a1, x0505AFAF);
	vsel(xA31C26BE, xB35C94A6, x01BB23BB, x5050FAFA);
	vxor(xA91679E1, x0A0A5F5F, xA31C26BE);

	vnot(x56E9861E, xA91679E1);

	vsel(x50E9FA1E, x5050FAFA, x56E9861E, a4);
	vsel(x0AF55F00, x0AF50F0F, x0AF55FA0, x0A0A5F5F);
	vsel(x827D9784, xB35C94A6, x0AF55F00, a2);
	vxor(xD2946D9A, x50E9FA1E, x827D9784);
	vsel(x2, xD2946D9A, x4CA36B59, a6);
	vxor(*out3, *out3, x2);
	vsel(x3, xB35C94A6, xD2946D9A, a6);
	vxor(*out4, *out4, x3);

	vsel(x31F720B3, a2, a4, x0AF55FA0);
	vsel(x11FB21B3, x01BB23BB, x31F720B3, x5050FAFA);
	vxor(x4712A7AD, x56E9861E, x11FB21B3);
	vxor(x9586CA37, xD2946D9A, x4712A7AD);
	vsel(x0, x56E9861E, x9586CA37, a6);
	vxor(*out1, *out1, x0);
	vsel(x1, x9586CA37, xA91679E1, a6);
	vxor(*out2, *out2, x1);
}
#else
/* s4-000033, 26 gates, 12 regs, 4/22/48/76/104 stall cycles */
MAYBE_INLINE static void
s4(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0505AFAF, x0555AF55, x0A5AA05A, x46566456, x0A0A5F5F, x0AF55FA0,
	    x0AF50F0F, x4CA36B59;
	vtype xB35C94A6;
	vtype x01BB23BB, x5050FAFA, xA31C26BE, xA91679E1;
	vtype x56E9861E;
	vtype x50E9FA1E, x0AF55F00, x827D9784, xD2946D9A;
	vtype xD2F56D00, x46F9870F, x4773A737, x9586CA37;
	vtype x0, x1, x2, x3;

	vsel(x0505AFAF, a5, a3, a1);
	vsel(x0555AF55, x0505AFAF, a1, a4);
	vxor(x0A5AA05A, a3, x0555AF55);
	vsel(x46566456, a1, x0A5AA05A, a2);
	vsel(x0A0A5F5F, a3, a5, a1);
	vxor(x0AF55FA0, a4, x0A0A5F5F);
	vsel(x0AF50F0F, x0AF55FA0, a3, a5);
	vxor(x4CA36B59, x46566456, x0AF50F0F);

	vnot(xB35C94A6, x4CA36B59);

	vsel(x01BB23BB, a4, a2, x0555AF55);
	vxor(x5050FAFA, a1, x0505AFAF);
	vsel(xA31C26BE, xB35C94A6, x01BB23BB, x5050FAFA);
	vxor(xA91679E1, x0A0A5F5F, xA31C26BE);

	vnot(x56E9861E, xA91679E1);

	vsel(x50E9FA1E, x5050FAFA, x56E9861E, a4);
	vsel(x0AF55F00, x0AF50F0F, x0AF55FA0, x0A0A5F5F);
	vsel(x827D9784, xB35C94A6, x0AF55F00, a2);
	vxor(xD2946D9A, x50E9FA1E, x827D9784);
	vsel(x2, xD2946D9A, x4CA36B59, a6);
	vxor(*out3, *out3, x2);
	vsel(x3, xB35C94A6, xD2946D9A, a6);
	vxor(*out4, *out4, x3);

	vsel(xD2F56D00, xD2946D9A, x0AF55F00, a4);
	vsel(x46F9870F, x56E9861E, x0AF50F0F, a2);
	vsel(x4773A737, x46F9870F, a2, x01BB23BB);
	vxor(x9586CA37, xD2F56D00, x4773A737);
	vsel(x0, x56E9861E, x9586CA37, a6);
	vxor(*out1, *out1, x0);
	vsel(x1, x9586CA37, xA91679E1, a6);
	vxor(*out2, *out2, x1);
}
#endif

#if regs <= 18 && latency <= 2
/* s5-000000, 35 gates, 18 regs, 7/33/68/105/142 stall cycles */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x550F550F, xAAF0AAF0, xA5F5A5F5, x96C696C6, x00FFFF00, x963969C6;
	vtype x2E3C2E3C, xB73121F7, x1501DF0F, x00558A5F, x2E69A463;
	vtype x0679ED42, x045157FD, xB32077FF, x9D49D39C;
	vtype xAC81CFB2, xF72577AF, x5BA4B81D;
	vtype x5BA477AF, x4895469F, x3A35273A, x1A35669A;
	vtype x12E6283D, x9E47D3D4, x1A676AB4;
	vtype x2E3C69C6, x92C7C296, x369CC1D6;
	vtype x891556DF, xE5E77F82, x6CF2295D;
	vtype x0, x1, x2, x3;

	vsel(x550F550F, a1, a3, a5);
	vnot(xAAF0AAF0, x550F550F);
	vsel(xA5F5A5F5, xAAF0AAF0, a1, a3);
	vxor(x96C696C6, a2, xA5F5A5F5);
	vxor(x00FFFF00, a5, a6);
	vxor(x963969C6, x96C696C6, x00FFFF00);

	vsel(x2E3C2E3C, a3, xAAF0AAF0, a2);
	vsel(xB73121F7, a2, x963969C6, x96C696C6);
	vsel(x1501DF0F, a6, x550F550F, xB73121F7);
	vsel(x00558A5F, x1501DF0F, a5, a1);
	vxor(x2E69A463, x2E3C2E3C, x00558A5F);

	vsel(x0679ED42, x00FFFF00, x2E69A463, x96C696C6);
	vsel(x045157FD, a6, a1, x0679ED42);
	vsel(xB32077FF, xB73121F7, a6, x045157FD);
	vxor(x9D49D39C, x2E69A463, xB32077FF);
	vsel(x2, x9D49D39C, x2E69A463, a4);
	vxor(*out3, *out3, x2);

	vsel(xAC81CFB2, xAAF0AAF0, x1501DF0F, x0679ED42);
	vsel(xF72577AF, xB32077FF, x550F550F, a1);
	vxor(x5BA4B81D, xAC81CFB2, xF72577AF);
	vsel(x1, x5BA4B81D, x963969C6, a4);
	vxor(*out2, *out2, x1);

	vsel(x5BA477AF, x5BA4B81D, xF72577AF, a6);
	vsel(x4895469F, x5BA477AF, x00558A5F, a2);
	vsel(x3A35273A, x2E3C2E3C, a2, x963969C6);
	vsel(x1A35669A, x4895469F, x3A35273A, x5BA4B81D);

	vsel(x12E6283D, a5, x5BA4B81D, x963969C6);
	vsel(x9E47D3D4, x96C696C6, x9D49D39C, xAC81CFB2);
	vsel(x1A676AB4, x12E6283D, x9E47D3D4, x4895469F);

	vsel(x2E3C69C6, x2E3C2E3C, x963969C6, a6);
	vsel(x92C7C296, x96C696C6, x1A676AB4, a1);
	vsel(x369CC1D6, x2E3C69C6, x92C7C296, x5BA4B81D);
	vsel(x0, x369CC1D6, x1A676AB4, a4);
	vxor(*out1, *out1, x0);

	vsel(x891556DF, xB32077FF, x4895469F, x3A35273A);
	vsel(xE5E77F82, xF72577AF, x00FFFF00, x12E6283D);
	vxor(x6CF2295D, x891556DF, xE5E77F82);
	vsel(x3, x1A35669A, x6CF2295D, a4);
	vxor(*out4, *out4, x3);
}
#elif regs == 19 || (regs >= 20 && latency >= 3)
/* s5-000005, 35 gates, 19 regs, 7/29/60/95/132 stall cycles */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x550F550F, xAAF0AAF0, xA5F5A5F5, x96C696C6, x00FFFF00, x963969C6;
	vtype x2E3C2E3C, xB73121F7, x1501DF0F, x00558A5F, x2E69A463;
	vtype x0679ED42, x045157FD, xB32077FF, x9D49D39C;
	vtype xAC81CFB2, xF72577AF, x5BA4B81D;
	vtype x5BA477AF, x4895469F, x3A35273A, x1A35669A;
	vtype x12E6283D, x9E47D3D4, x1A676AB4;
	vtype x2E3CD3D4, x9697C1C6, x369CC1D6;
	vtype x891556DF, xE5E77F82, x6CF2295D;
	vtype x0, x1, x2, x3;

	vsel(x550F550F, a1, a3, a5);
	vnot(xAAF0AAF0, x550F550F);
	vsel(xA5F5A5F5, xAAF0AAF0, a1, a3);
	vxor(x96C696C6, a2, xA5F5A5F5);
	vxor(x00FFFF00, a5, a6);
	vxor(x963969C6, x96C696C6, x00FFFF00);

	vsel(x2E3C2E3C, a3, xAAF0AAF0, a2);
	vsel(xB73121F7, a2, x963969C6, x96C696C6);
	vsel(x1501DF0F, a6, x550F550F, xB73121F7);
	vsel(x00558A5F, x1501DF0F, a5, a1);
	vxor(x2E69A463, x2E3C2E3C, x00558A5F);

	vsel(x0679ED42, x00FFFF00, x2E69A463, x96C696C6);
	vsel(x045157FD, a6, a1, x0679ED42);
	vsel(xB32077FF, xB73121F7, a6, x045157FD);
	vxor(x9D49D39C, x2E69A463, xB32077FF);
	vsel(x2, x9D49D39C, x2E69A463, a4);
	vxor(*out3, *out3, x2);

	vsel(xAC81CFB2, xAAF0AAF0, x1501DF0F, x0679ED42);
	vsel(xF72577AF, xB32077FF, x550F550F, a1);
	vxor(x5BA4B81D, xAC81CFB2, xF72577AF);
	vsel(x1, x5BA4B81D, x963969C6, a4);
	vxor(*out2, *out2, x1);

	vsel(x5BA477AF, x5BA4B81D, xF72577AF, a6);
	vsel(x4895469F, x5BA477AF, x00558A5F, a2);
	vsel(x3A35273A, x2E3C2E3C, a2, x963969C6);
	vsel(x1A35669A, x4895469F, x3A35273A, x5BA4B81D);

	vsel(x12E6283D, a5, x5BA4B81D, x963969C6);
	vsel(x9E47D3D4, x96C696C6, x9D49D39C, xAC81CFB2);
	vsel(x1A676AB4, x12E6283D, x9E47D3D4, x4895469F);

	vsel(x2E3CD3D4, x2E3C2E3C, x9E47D3D4, a6);
	vsel(x9697C1C6, x96C696C6, x963969C6, x045157FD);
	vsel(x369CC1D6, x2E3CD3D4, x9697C1C6, x5BA477AF);
	vsel(x0, x369CC1D6, x1A676AB4, a4);
	vxor(*out1, *out1, x0);

	vsel(x891556DF, xB32077FF, x4895469F, x3A35273A);
	vsel(xE5E77F82, xF72577AF, x00FFFF00, x12E6283D);
	vxor(x6CF2295D, x891556DF, xE5E77F82);
	vsel(x3, x1A35669A, x6CF2295D, a4);
	vxor(*out4, *out4, x3);
}
#elif regs <= 18 && latency >= 5
/* s5-000011, 35 gates, 18 regs, 9/31/62/95/132 stall cycles */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x550F550F, xAAF0AAF0, xA5F5A5F5, x96C696C6, x00FFFF00, x963969C6;
	vtype x2E3C2E3C, xB73121F7, x1501DF0F, x00558A5F, x2E69A463;
	vtype x0679ED42, x045157FD, xB32077FF, x9D49D39C;
	vtype xAC81CFB2, xF72577AF, x5BA4B81D;
	vtype x5BA477AF, x4895469F, x3A35273A, x1A35669A;
	vtype x12E6283D, x9E47D3D4, x1A676AB4;
	vtype x2E3CD3D4, x96DF41C6, x369CC1D6;
	vtype x891556DF, xE5E77F82, x6CF2295D;
	vtype x0, x1, x2, x3;

	vsel(x550F550F, a1, a3, a5);
	vnot(xAAF0AAF0, x550F550F);
	vsel(xA5F5A5F5, xAAF0AAF0, a1, a3);
	vxor(x96C696C6, a2, xA5F5A5F5);
	vxor(x00FFFF00, a5, a6);
	vxor(x963969C6, x96C696C6, x00FFFF00);

	vsel(x2E3C2E3C, a3, xAAF0AAF0, a2);
	vsel(xB73121F7, a2, x963969C6, x96C696C6);
	vsel(x1501DF0F, a6, x550F550F, xB73121F7);
	vsel(x00558A5F, x1501DF0F, a5, a1);
	vxor(x2E69A463, x2E3C2E3C, x00558A5F);

	vsel(x0679ED42, x00FFFF00, x2E69A463, x96C696C6);
	vsel(x045157FD, a6, a1, x0679ED42);
	vsel(xB32077FF, xB73121F7, a6, x045157FD);
	vxor(x9D49D39C, x2E69A463, xB32077FF);
	vsel(x2, x9D49D39C, x2E69A463, a4);
	vxor(*out3, *out3, x2);

	vsel(xAC81CFB2, xAAF0AAF0, x1501DF0F, x0679ED42);
	vsel(xF72577AF, xB32077FF, x550F550F, a1);
	vxor(x5BA4B81D, xAC81CFB2, xF72577AF);
	vsel(x1, x5BA4B81D, x963969C6, a4);
	vxor(*out2, *out2, x1);

	vsel(x5BA477AF, x5BA4B81D, xF72577AF, a6);
	vsel(x4895469F, x5BA477AF, x00558A5F, a2);
	vsel(x3A35273A, x2E3C2E3C, a2, x963969C6);
	vsel(x1A35669A, x4895469F, x3A35273A, x5BA4B81D);

	vsel(x12E6283D, a5, x5BA4B81D, x963969C6);
	vsel(x9E47D3D4, x96C696C6, x9D49D39C, xAC81CFB2);
	vsel(x1A676AB4, x12E6283D, x9E47D3D4, x4895469F);

	vsel(x2E3CD3D4, x2E3C2E3C, x9E47D3D4, a6);
	vsel(x96DF41C6, x963969C6, x96C696C6, x12E6283D);
	vsel(x369CC1D6, x2E3CD3D4, x96DF41C6, x5BA477AF);
	vsel(x0, x369CC1D6, x1A676AB4, a4);
	vxor(*out1, *out1, x0);

	vsel(x891556DF, xB32077FF, x4895469F, x3A35273A);
	vsel(xE5E77F82, xF72577AF, x00FFFF00, x12E6283D);
	vxor(x6CF2295D, x891556DF, xE5E77F82);
	vsel(x3, x1A35669A, x6CF2295D, a4);
	vxor(*out4, *out4, x3);
}
#elif regs >= 20
/* s5-000016, 35 gates, 20 regs, 6/30/62/98/135 stall cycles */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x550F550F, xAAF0AAF0, xA5F5A5F5, x96C696C6, x00FFFF00, x963969C6;
	vtype x2E3C2E3C, xB73121F7, x1501DF0F, x00558A5F, x2E69A463;
	vtype x0679ED42, x045157FD, xB32077FF, x9D49D39C;
	vtype xAC81CFB2, xF72577AF, x5BA4B81D;
	vtype x5BA477AF, x4895469F, x3A35273A, x1A35669A;
	vtype x12E6283D, x9E47D3D4, x1A676AB4;
	vtype x891556DF, xE5E77F82, x6CF2295D;
	vtype x2E3CA5F5, x9697C1C6, x369CC1D6;
	vtype x0, x1, x2, x3;

	vsel(x550F550F, a1, a3, a5);
	vnot(xAAF0AAF0, x550F550F);
	vsel(xA5F5A5F5, xAAF0AAF0, a1, a3);
	vxor(x96C696C6, a2, xA5F5A5F5);
	vxor(x00FFFF00, a5, a6);
	vxor(x963969C6, x96C696C6, x00FFFF00);

	vsel(x2E3C2E3C, a3, xAAF0AAF0, a2);
	vsel(xB73121F7, a2, x963969C6, x96C696C6);
	vsel(x1501DF0F, a6, x550F550F, xB73121F7);
	vsel(x00558A5F, x1501DF0F, a5, a1);
	vxor(x2E69A463, x2E3C2E3C, x00558A5F);

	vsel(x0679ED42, x00FFFF00, x2E69A463, x96C696C6);
	vsel(x045157FD, a6, a1, x0679ED42);
	vsel(xB32077FF, xB73121F7, a6, x045157FD);
	vxor(x9D49D39C, x2E69A463, xB32077FF);
	vsel(x2, x9D49D39C, x2E69A463, a4);
	vxor(*out3, *out3, x2);

	vsel(xAC81CFB2, xAAF0AAF0, x1501DF0F, x0679ED42);
	vsel(xF72577AF, xB32077FF, x550F550F, a1);
	vxor(x5BA4B81D, xAC81CFB2, xF72577AF);
	vsel(x1, x5BA4B81D, x963969C6, a4);
	vxor(*out2, *out2, x1);

	vsel(x5BA477AF, x5BA4B81D, xF72577AF, a6);
	vsel(x4895469F, x5BA477AF, x00558A5F, a2);
	vsel(x3A35273A, x2E3C2E3C, a2, x963969C6);
	vsel(x1A35669A, x4895469F, x3A35273A, x5BA4B81D);

	vsel(x12E6283D, a5, x5BA4B81D, x963969C6);
	vsel(x9E47D3D4, x96C696C6, x9D49D39C, xAC81CFB2);
	vsel(x1A676AB4, x12E6283D, x9E47D3D4, x4895469F);

	vsel(x891556DF, xB32077FF, x4895469F, x3A35273A);
	vsel(xE5E77F82, xF72577AF, x00FFFF00, x12E6283D);
	vxor(x6CF2295D, x891556DF, xE5E77F82);
	vsel(x3, x1A35669A, x6CF2295D, a4);
	vxor(*out4, *out4, x3);

	vsel(x2E3CA5F5, x2E3C2E3C, xA5F5A5F5, a6);
	vsel(x9697C1C6, x96C696C6, x963969C6, x045157FD);
	vsel(x369CC1D6, x2E3CA5F5, x9697C1C6, x5BA477AF);
	vsel(x0, x369CC1D6, x1A676AB4, a4);
	vxor(*out1, *out1, x0);
}
#else
/* s5-000023, 35 gates, 18 regs, 9/30/61/96/133 stall cycles */
MAYBE_INLINE static void
s5(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x550F550F, xAAF0AAF0, xA5F5A5F5, x96C696C6, x00FFFF00, x963969C6;
	vtype x2E3C2E3C, xB73121F7, x1501DF0F, x00558A5F, x2E69A463;
	vtype x0679ED42, x045157FD, xB32077FF, x9D49D39C;
	vtype xAC81CFB2, xF72577AF, x5BA4B81D;
	vtype x5BA477AF, x4895469F, x3A35273A, x1A35669A;
	vtype x12E6283D, x9E47D3D4, x1A676AB4;
	vtype x891556DF, xE5E77F82, x6CF2295D;
	vtype x2E3CD3D4, x96DF41C6, x369CC1D6;
	vtype x0, x1, x2, x3;

	vsel(x550F550F, a1, a3, a5);
	vnot(xAAF0AAF0, x550F550F);
	vsel(xA5F5A5F5, xAAF0AAF0, a1, a3);
	vxor(x96C696C6, a2, xA5F5A5F5);
	vxor(x00FFFF00, a5, a6);
	vxor(x963969C6, x96C696C6, x00FFFF00);

	vsel(x2E3C2E3C, a3, xAAF0AAF0, a2);
	vsel(xB73121F7, a2, x963969C6, x96C696C6);
	vsel(x1501DF0F, a6, x550F550F, xB73121F7);
	vsel(x00558A5F, x1501DF0F, a5, a1);
	vxor(x2E69A463, x2E3C2E3C, x00558A5F);

	vsel(x0679ED42, x00FFFF00, x2E69A463, x96C696C6);
	vsel(x045157FD, a6, a1, x0679ED42);
	vsel(xB32077FF, xB73121F7, a6, x045157FD);
	vxor(x9D49D39C, x2E69A463, xB32077FF);
	vsel(x2, x9D49D39C, x2E69A463, a4);
	vxor(*out3, *out3, x2);

	vsel(xAC81CFB2, xAAF0AAF0, x1501DF0F, x0679ED42);
	vsel(xF72577AF, xB32077FF, x550F550F, a1);
	vxor(x5BA4B81D, xAC81CFB2, xF72577AF);
	vsel(x1, x5BA4B81D, x963969C6, a4);
	vxor(*out2, *out2, x1);

	vsel(x5BA477AF, x5BA4B81D, xF72577AF, a6);
	vsel(x4895469F, x5BA477AF, x00558A5F, a2);
	vsel(x3A35273A, x2E3C2E3C, a2, x963969C6);
	vsel(x1A35669A, x4895469F, x3A35273A, x5BA4B81D);

	vsel(x12E6283D, a5, x5BA4B81D, x963969C6);
	vsel(x9E47D3D4, x96C696C6, x9D49D39C, xAC81CFB2);
	vsel(x1A676AB4, x12E6283D, x9E47D3D4, x4895469F);

	vsel(x891556DF, xB32077FF, x4895469F, x3A35273A);
	vsel(xE5E77F82, xF72577AF, x00FFFF00, x12E6283D);
	vxor(x6CF2295D, x891556DF, xE5E77F82);
	vsel(x3, x1A35669A, x6CF2295D, a4);
	vxor(*out4, *out4, x3);

	vsel(x2E3CD3D4, x2E3C2E3C, x9E47D3D4, a6);
	vsel(x96DF41C6, x963969C6, x96C696C6, x12E6283D);
	vsel(x369CC1D6, x2E3CD3D4, x96DF41C6, x5BA477AF);
	vsel(x0, x369CC1D6, x1A676AB4, a4);
	vxor(*out1, *out1, x0);
}
#endif

#if regs >= 16 && latency <= 2
/* s6-000000, 34 gates, 16 regs, 5/34/70/107/144 stall cycles */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x555500FF, x666633CC, x606F30CF, x353A659A, x353A9A65, xCAC5659A;
	vtype x353A6565, x0A3F0A6F, x6C5939A3, x5963A3C6;
	vtype x35FF659A, x3AF06A95, x05CF0A9F, x16E94A97;
	vtype x86CD4C9B, x12E0FFFD, x942D9A67;
	vtype x142956AB, x455D45DF, x1C3EE619;
	vtype x2AEA70D5, x20CF7A9F, x3CF19C86, x69A49C79;
	vtype x840DBB67, x6DA19C1E, x925E63E1;
	vtype x9C3CA761, x257A75D5, xB946D2B4;
	vtype x0, x1, x2, x3;

	vsel(x555500FF, a1, a4, a5);
	vxor(x666633CC, a2, x555500FF);
	vsel(x606F30CF, x666633CC, a4, a3);
	vxor(x353A659A, a1, x606F30CF);
	vxor(x353A9A65, a5, x353A659A);
	vnot(xCAC5659A, x353A9A65);

	vsel(x353A6565, x353A659A, x353A9A65, a4);
	vsel(x0A3F0A6F, a3, a4, x353A6565);
	vxor(x6C5939A3, x666633CC, x0A3F0A6F);
	vxor(x5963A3C6, x353A9A65, x6C5939A3);

	vsel(x35FF659A, a4, x353A659A, x353A6565);
	vxor(x3AF06A95, a3, x35FF659A);
	vsel(x05CF0A9F, a4, a3, x353A9A65);
	vsel(x16E94A97, x3AF06A95, x05CF0A9F, x6C5939A3);

	vsel(x86CD4C9B, xCAC5659A, x05CF0A9F, x6C5939A3);
	vsel(x12E0FFFD, a5, x3AF06A95, x16E94A97);
	vsel(x942D9A67, x86CD4C9B, x353A9A65, x12E0FFFD);
	vsel(x0, xCAC5659A, x942D9A67, a6);
	vxor(*out1, *out1, x0);

	vsel(x142956AB, x353A659A, x942D9A67, a2);
	vsel(x455D45DF, a1, x86CD4C9B, x142956AB);
	vxor(x1C3EE619, x5963A3C6, x455D45DF);
	vsel(x3, x5963A3C6, x1C3EE619, a6);
	vxor(*out4, *out4, x3);

	vsel(x2AEA70D5, x3AF06A95, x606F30CF, x353A9A65);
	vsel(x20CF7A9F, x2AEA70D5, x05CF0A9F, x0A3F0A6F);
	vxor(x3CF19C86, x1C3EE619, x20CF7A9F);
	vxor(x69A49C79, x555500FF, x3CF19C86);

	vsel(x840DBB67, a5, x942D9A67, x86CD4C9B);
	vsel(x6DA19C1E, x69A49C79, x3CF19C86, x840DBB67);
	vnot(x925E63E1, x6DA19C1E);
	vsel(x1, x925E63E1, x69A49C79, a6);
	vxor(*out2, *out2, x1);

	vsel(x9C3CA761, x840DBB67, x1C3EE619, x3CF19C86);
	vsel(x257A75D5, x455D45DF, x2AEA70D5, x606F30CF);
	vxor(xB946D2B4, x9C3CA761, x257A75D5);
	vsel(x2, x16E94A97, xB946D2B4, a6);
	vxor(*out3, *out3, x2);
}
#elif regs == 15
/* s6-000008, 34 gates, 15 regs, 6/25/57/94/131 stall cycles */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x555500FF, x666633CC, x606F30CF, x353A659A, x353A9A65, xCAC5659A;
	vtype x353A6565, x0A3F0A6F, x6C5939A3, x5963A3C6;
	vtype x35FF659A, x3AF06A95, x05CF0A9F, x16E94A97;
	vtype x86CD4C9B, x12E0FFFD, x942D9A67;
	vtype x142956AB, x455D45DF, x1C3EE619;
	vtype xC3C36393, x2D1B471E, xC70B631E, x925E63E1;
	vtype x8C2F1A67, x965B6386, x69A49C79;
	vtype x1C2E8201, xA56850B5, xB946D2B4;
	vtype x0, x1, x2, x3;

	vsel(x555500FF, a1, a4, a5);
	vxor(x666633CC, a2, x555500FF);
	vsel(x606F30CF, x666633CC, a4, a3);
	vxor(x353A659A, a1, x606F30CF);
	vxor(x353A9A65, a5, x353A659A);
	vnot(xCAC5659A, x353A9A65);

	vsel(x353A6565, x353A659A, x353A9A65, a4);
	vsel(x0A3F0A6F, a3, a4, x353A6565);
	vxor(x6C5939A3, x666633CC, x0A3F0A6F);
	vxor(x5963A3C6, x353A9A65, x6C5939A3);

	vsel(x35FF659A, a4, x353A659A, x353A6565);
	vxor(x3AF06A95, a3, x35FF659A);
	vsel(x05CF0A9F, a4, a3, x353A9A65);
	vsel(x16E94A97, x3AF06A95, x05CF0A9F, x6C5939A3);

	vsel(x86CD4C9B, xCAC5659A, x05CF0A9F, x6C5939A3);
	vsel(x12E0FFFD, a5, x3AF06A95, x16E94A97);
	vsel(x942D9A67, x86CD4C9B, x353A9A65, x12E0FFFD);
	vsel(x0, xCAC5659A, x942D9A67, a6);
	vxor(*out1, *out1, x0);

	vsel(x142956AB, x353A659A, x942D9A67, a2);
	vsel(x455D45DF, a1, x86CD4C9B, x142956AB);
	vxor(x1C3EE619, x5963A3C6, x455D45DF);
	vsel(x3, x5963A3C6, x1C3EE619, a6);
	vxor(*out4, *out4, x3);

	vsel(xC3C36393, xCAC5659A, a2, a3);
	vsel(x2D1B471E, x353A659A, a3, x5963A3C6);
	vsel(xC70B631E, xC3C36393, x2D1B471E, x05CF0A9F);
	vxor(x925E63E1, x555500FF, xC70B631E);

	vsel(x8C2F1A67, x942D9A67, x0A3F0A6F, x5963A3C6);
	vsel(x965B6386, x925E63E1, xC70B631E, x8C2F1A67);
	vnot(x69A49C79, x965B6386);
	vsel(x1, x925E63E1, x69A49C79, a6);
	vxor(*out2, *out2, x1);

	vsel(x1C2E8201, x942D9A67, x1C3EE619, x8C2F1A67);
	vxor(xA56850B5, a2, x965B6386);
	vxor(xB946D2B4, x1C2E8201, xA56850B5);
	vsel(x2, x16E94A97, xB946D2B4, a6);
	vxor(*out3, *out3, x2);
}
#elif regs <= 14
/* s6-000082, 34 gates, 14 regs, 8/31/65/102/139 stall cycles */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x555500FF, x666633CC, x606F30CF, x353A659A, x353A9A65, xCAC5659A;
	vtype x353A6565, x0A3F0A6F, x6C5939A3, x5963A3C6;
	vtype x35FF659A, x3AF06A95, x066F0CCF, x16E94A97;
	vtype x1872E297, x35BE6539, x1C3EE619;
	vtype x86CD4C9B, x12E0FFFD, x942D9A67;
	vtype x0A63C087, x9E4E5AE0, x02FA65FD, x925E63E1;
	vtype xAB756193, x8A75E187, xB946D2B4;
	vtype x375A7BA0, x965B6386, x69A49C79;
	vtype x0, x1, x2, x3;

	vsel(x555500FF, a1, a4, a5);
	vxor(x666633CC, a2, x555500FF);
	vsel(x606F30CF, x666633CC, a4, a3);
	vxor(x353A659A, a1, x606F30CF);
	vxor(x353A9A65, a5, x353A659A);
	vnot(xCAC5659A, x353A9A65);

	vsel(x353A6565, x353A659A, x353A9A65, a4);
	vsel(x0A3F0A6F, a3, a4, x353A6565);
	vxor(x6C5939A3, x666633CC, x0A3F0A6F);
	vxor(x5963A3C6, x353A9A65, x6C5939A3);

	vsel(x35FF659A, a4, x353A659A, x353A6565);
	vxor(x3AF06A95, a3, x35FF659A);
	vsel(x066F0CCF, a3, a4, x5963A3C6);
	vsel(x16E94A97, x3AF06A95, x066F0CCF, x6C5939A3);

	vsel(x1872E297, x5963A3C6, x3AF06A95, a1);
	vsel(x35BE6539, x35FF659A, x353A6565, x6C5939A3);
	vsel(x1C3EE619, x1872E297, x35BE6539, x066F0CCF);
	vsel(x3, x5963A3C6, x1C3EE619, a6);
	vxor(*out4, *out4, x3);

	vsel(x86CD4C9B, xCAC5659A, x066F0CCF, x6C5939A3);
	vsel(x12E0FFFD, a5, x3AF06A95, x16E94A97);
	vsel(x942D9A67, x86CD4C9B, x353A9A65, x12E0FFFD);
	vsel(x0, xCAC5659A, x942D9A67, a6);
	vxor(*out1, *out1, x0);

	vsel(x0A63C087, x1872E297, x066F0CCF, a2);
	vxor(x9E4E5AE0, x942D9A67, x0A63C087);
	vsel(x02FA65FD, x12E0FFFD, a4, x353A9A65);
	vsel(x925E63E1, x9E4E5AE0, x02FA65FD, x6C5939A3);

	vsel(xAB756193, a2, xCAC5659A, x9E4E5AE0);
	vsel(x8A75E187, x0A63C087, xAB756193, x925E63E1);
	vxor(xB946D2B4, a2, x8A75E187);
	vsel(x2, x16E94A97, xB946D2B4, a6);
	vxor(*out3, *out3, x2);

	vsel(x375A7BA0, a2, x9E4E5AE0, x16E94A97);
	vsel(x965B6386, x8A75E187, x375A7BA0, x1C3EE619);
	vnot(x69A49C79, x965B6386);
	vsel(x1, x925E63E1, x69A49C79, a6);
	vxor(*out2, *out2, x1);
}
#else
/* s6-000461, 34 gates, 16 regs, 7/23/48/82/118 stall cycles */
MAYBE_INLINE static void
s6(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x555500FF, x666633CC, x606F30CF, x353A659A, x353A9A65, xCAC5659A;
	vtype x553A5565, x0A3F0A6F, x6C5939A3, x5963A3C6;
	vtype x15FF459A, x1AF04A95, x066F0CCF, x16E94A97;
	vtype x1872E297, x55BE5539, x1C3EE619;
	vtype x86CD4C9B, x12E0FFFD, x942D9A67;
	vtype x2FCAD0F0, x1BF21BB1, x466E4C89, x69A49C79;
	vtype x965B6386, x12769BE1, x925E63E1;
	vtype x9867CA97, x69339C33, xB946D2B4;
	vtype x0, x1, x2, x3;

	vsel(x555500FF, a1, a4, a5);
	vxor(x666633CC, a2, x555500FF);
	vsel(x606F30CF, x666633CC, a4, a3);
	vxor(x353A659A, a1, x606F30CF);
	vxor(x353A9A65, a5, x353A659A);
	vnot(xCAC5659A, x353A9A65);

	vsel(x553A5565, a1, x353A9A65, a4);
	vsel(x0A3F0A6F, a3, a4, x553A5565);
	vxor(x6C5939A3, x666633CC, x0A3F0A6F);
	vxor(x5963A3C6, x353A9A65, x6C5939A3);

	vsel(x15FF459A, a4, x353A659A, x553A5565);
	vxor(x1AF04A95, a3, x15FF459A);
	vsel(x066F0CCF, a3, a4, x5963A3C6);
	vsel(x16E94A97, x1AF04A95, x066F0CCF, x6C5939A3);

	vsel(x1872E297, x5963A3C6, x1AF04A95, a1);
	vsel(x55BE5539, x15FF459A, x553A5565, x6C5939A3);
	vsel(x1C3EE619, x1872E297, x55BE5539, x066F0CCF);
	vsel(x3, x5963A3C6, x1C3EE619, a6);
	vxor(*out4, *out4, x3);

	vsel(x86CD4C9B, xCAC5659A, x066F0CCF, x6C5939A3);
	vsel(x12E0FFFD, a5, x1AF04A95, x16E94A97);
	vsel(x942D9A67, x86CD4C9B, x353A9A65, x12E0FFFD);
	vsel(x0, xCAC5659A, x942D9A67, a6);
	vxor(*out1, *out1, x0);

	vxor(x2FCAD0F0, x353A9A65, x1AF04A95);
	vsel(x1BF21BB1, x1AF04A95, a2, x553A5565);
	vsel(x466E4C89, x55BE5539, x066F0CCF, x1BF21BB1);
	vxor(x69A49C79, x2FCAD0F0, x466E4C89);

	vnot(x965B6386, x69A49C79);
	vsel(x12769BE1, x1BF21BB1, x942D9A67, x69A49C79);
	vsel(x925E63E1, x965B6386, x12769BE1, x555500FF);
	vsel(x1, x925E63E1, x69A49C79, a6);
	vxor(*out2, *out2, x1);

	vsel(x9867CA97, x942D9A67, x1872E297, x2FCAD0F0);
	vsel(x69339C33, x69A49C79, a2, a4);
	vsel(xB946D2B4, x9867CA97, x2FCAD0F0, x69339C33);
	vsel(x2, x16E94A97, xB946D2B4, a6);
	vxor(*out3, *out3, x2);
}
#endif

#if regs <= 16 || latency >= 3
/* s7-000013, 34 gates, 15 regs, 9/27/56/88/119 stall cycles */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44447777, x4B4B7878, x22772277, x0505F5F5, x220522F5, x694E5A8D;
	vtype x00FFFF00, x66666666, x32353235, x26253636, x26DAC936;
	vtype x738F9C63, x11EF9867, x26DA9867;
	vtype x4B4B9C63, x4B666663, x4E639396;
	vtype x4E4B393C, xFF00FF00, xFF05DD21, xB14EE41D;
	vtype xD728827B, x6698807B, x699C585B;
	vtype x738C847B, xA4A71E18, x74878E78;
	vtype x333D9639, x74879639, x8B7869C6;
	vtype x0, x1, x2, x3;

	vsel(x44447777, a2, a6, a3);
	vxor(x4B4B7878, a4, x44447777);
	vsel(x22772277, a3, a5, a2);
	vsel(x0505F5F5, a6, a2, a4);
	vsel(x220522F5, x22772277, x0505F5F5, a5);
	vxor(x694E5A8D, x4B4B7878, x220522F5);

	vxor(x00FFFF00, a5, a6);
	vxor(x66666666, a2, a3);
	vsel(x32353235, a3, x220522F5, a4);
	vsel(x26253636, x66666666, x32353235, x4B4B7878);
	vxor(x26DAC936, x00FFFF00, x26253636);
	vsel(x0, x26DAC936, x694E5A8D, a1);
	vxor(*out1, *out1, x0);

	vxor(x738F9C63, a2, x26DAC936);
	vsel(x11EF9867, x738F9C63, a5, x66666666);
	vsel(x26DA9867, x26DAC936, x11EF9867, a6);

	vsel(x4B4B9C63, x4B4B7878, x738F9C63, a6);
	vsel(x4B666663, x4B4B9C63, x66666666, x00FFFF00);
	vxor(x4E639396, x0505F5F5, x4B666663);

	vsel(x4E4B393C, x4B4B7878, x4E639396, a2);
	vnot(xFF00FF00, a5);
	vsel(xFF05DD21, xFF00FF00, x738F9C63, x32353235);
	vxor(xB14EE41D, x4E4B393C, xFF05DD21);
	vsel(x1, xB14EE41D, x26DA9867, a1);
	vxor(*out2, *out2, x1);

	vxor(xD728827B, x66666666, xB14EE41D);
	vsel(x6698807B, x26DA9867, xD728827B, x4E4B393C);
	vsel(x699C585B, x6698807B, x694E5A8D, xFF05DD21);
	vsel(x2, x699C585B, x4E639396, a1);
	vxor(*out3, *out3, x2);

	vsel(x738C847B, x738F9C63, xD728827B, x4B4B7878);
	vxor(xA4A71E18, x738F9C63, xD728827B);
	vsel(x74878E78, x738C847B, xA4A71E18, a4);

	vsel(x333D9639, x32353235, x738C847B, xB14EE41D);
	vsel(x74879639, x74878E78, x333D9639, a6);
	vnot(x8B7869C6, x74879639);
	vsel(x3, x74878E78, x8B7869C6, a1);
	vxor(*out4, *out4, x3);
}
#else
/* s7-000019, 34 gates, 17 regs, 5/28/57/88/119 stall cycles */
MAYBE_INLINE static void
s7(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x44447777, x4B4B7878, x22772277, x0505F5F5, x220522F5, x694E5A8D;
	vtype x00FFFF00, x66666666, x32353235, x26253636, x26DAC936;
	vtype x738F9C63, x11EF9867, x26DA9867;
	vtype x4B4B9C63, x4B666663, x4E639396;
	vtype x4E4B393C, xFF00FF00, xFF05DD21, xB14EE41D;
	vtype xD728827B, x6698807B, x699C585B;
	vtype x778A8877, xA4A71E18, x74878E78;
	vtype x204A5845, x74879639, x8B7869C6;
	vtype x0, x1, x2, x3;

	vsel(x44447777, a2, a6, a3);
	vxor(x4B4B7878, a4, x44447777);
	vsel(x22772277, a3, a5, a2);
	vsel(x0505F5F5, a6, a2, a4);
	vsel(x220522F5, x22772277, x0505F5F5, a5);
	vxor(x694E5A8D, x4B4B7878, x220522F5);

	vxor(x00FFFF00, a5, a6);
	vxor(x66666666, a2, a3);
	vsel(x32353235, a3, x220522F5, a4);
	vsel(x26253636, x66666666, x32353235, x4B4B7878);
	vxor(x26DAC936, x00FFFF00, x26253636);
	vsel(x0, x26DAC936, x694E5A8D, a1);
	vxor(*out1, *out1, x0);

	vxor(x738F9C63, a2, x26DAC936);
	vsel(x11EF9867, x738F9C63, a5, x66666666);
	vsel(x26DA9867, x26DAC936, x11EF9867, a6);

	vsel(x4B4B9C63, x4B4B7878, x738F9C63, a6);
	vsel(x4B666663, x4B4B9C63, x66666666, x00FFFF00);
	vxor(x4E639396, x0505F5F5, x4B666663);

	vsel(x4E4B393C, x4B4B7878, x4E639396, a2);
	vnot(xFF00FF00, a5);
	vsel(xFF05DD21, xFF00FF00, x738F9C63, x32353235);
	vxor(xB14EE41D, x4E4B393C, xFF05DD21);
	vsel(x1, xB14EE41D, x26DA9867, a1);
	vxor(*out2, *out2, x1);

	vxor(xD728827B, x66666666, xB14EE41D);
	vsel(x6698807B, x26DA9867, xD728827B, x4E4B393C);
	vsel(x699C585B, x6698807B, x694E5A8D, xFF05DD21);
	vsel(x2, x699C585B, x4E639396, a1);
	vxor(*out3, *out3, x2);

	vsel(x778A8877, x738F9C63, x26DAC936, x26253636);
	vxor(xA4A71E18, x738F9C63, xD728827B);
	vsel(x74878E78, x778A8877, xA4A71E18, a4);

	vsel(x204A5845, x26DA9867, x694E5A8D, x26DAC936);
	vsel(x74879639, x74878E78, a3, x204A5845);
	vnot(x8B7869C6, x74879639);
	vsel(x3, x74878E78, x8B7869C6, a1);
	vxor(*out4, *out4, x3);
}
#endif

#if latency >= 3
/* s8-000035, 32 gates, 15 regs, 6/15/47/79/111 stall cycles */
MAYBE_INLINE static void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0505F5F5, x05FAF50A, x0F0F00FF, x22227777, x07DA807F, x34E9B34C;
	vtype x00FFF00F, x0033FCCF, x5565B15C, x0C0C3F3F, x59698E63;
	vtype x3001F74E, x30555745, x693CD926;
	vtype x0C0CD926, x0C3F25E9, x38D696A5;
	vtype xC729695A;
	vtype x03D2117B, xC778395B, xCB471CB2;
	vtype x5425B13F, x56B3803F, x919AE965;
	vtype x03DA807F, x613CD515, x62E6556A, xA59E6C31;
	vtype x0, x1, x2, x3;

	vsel(x0505F5F5, a5, a1, a3);
	vxor(x05FAF50A, a4, x0505F5F5);
	vsel(x0F0F00FF, a3, a4, a5);
	vsel(x22227777, a2, a5, a1);
	vsel(x07DA807F, x05FAF50A, x0F0F00FF, x22227777);
	vxor(x34E9B34C, a2, x07DA807F);

	vsel(x00FFF00F, x05FAF50A, a4, a3);
	vsel(x0033FCCF, a5, x00FFF00F, a2);
	vsel(x5565B15C, a1, x34E9B34C, x0033FCCF);
	vsel(x0C0C3F3F, a3, a5, a2);
	vxor(x59698E63, x5565B15C, x0C0C3F3F);

	vsel(x3001F74E, x34E9B34C, a5, x05FAF50A);
	vsel(x30555745, x3001F74E, a1, x00FFF00F);
	vxor(x693CD926, x59698E63, x30555745);
	vsel(x2, x693CD926, x59698E63, a6);
	vxor(*out3, *out3, x2);

	vsel(x0C0CD926, x0C0C3F3F, x693CD926, a5);
	vxor(x0C3F25E9, x0033FCCF, x0C0CD926);
	vxor(x38D696A5, x34E9B34C, x0C3F25E9);

	vnot(xC729695A, x38D696A5);

	vsel(x03D2117B, x07DA807F, a2, x0C0CD926);
	vsel(xC778395B, xC729695A, x03D2117B, x30555745);
	vxor(xCB471CB2, x0C3F25E9, xC778395B);
	vsel(x1, xCB471CB2, x34E9B34C, a6);
	vxor(*out2, *out2, x1);

	vsel(x5425B13F, x5565B15C, x0C0C3F3F, x03D2117B);
	vsel(x56B3803F, x07DA807F, x5425B13F, x59698E63);
	vxor(x919AE965, xC729695A, x56B3803F);
	vsel(x3, xC729695A, x919AE965, a6);
	vxor(*out4, *out4, x3);

	vsel(x03DA807F, x03D2117B, x07DA807F, x693CD926);
	vsel(x613CD515, a1, x693CD926, x34E9B34C);
	vxor(x62E6556A, x03DA807F, x613CD515);
	vxor(xA59E6C31, xC778395B, x62E6556A);
	vsel(x0, xA59E6C31, x38D696A5, a6);
	vxor(*out1, *out1, x0);
}
#else
/* s8-000037, 32 gates, 15 regs, 3/17/49/81/113 stall cycles */
MAYBE_INLINE static void
s8(vtype a1, vtype a2, vtype a3, vtype a4, vtype a5, vtype a6,
    vtype * out1, vtype * out2, vtype * out3, vtype * out4)
{
	vtype x0505F5F5, x05FAF50A, x0F0F00FF, x22227777, x07DA807F, x34E9B34C;
	vtype x00FFF00F, x0033FCCF, x5565B15C, x0C0C3F3F, x59698E63;
	vtype x3001F74E, x30555745, x693CD926;
	vtype x0C0CD926, x0C3F25E9, x38D696A5;
	vtype xC729695A;
	vtype x03D2117B, xC778395B, xCB471CB2;
	vtype x5425B13F, x56B3803F, x919AE965;
	vtype x17B3023F, x75555755, x62E6556A, xA59E6C31;
	vtype x0, x1, x2, x3;

	vsel(x0505F5F5, a5, a1, a3);
	vxor(x05FAF50A, a4, x0505F5F5);
	vsel(x0F0F00FF, a3, a4, a5);
	vsel(x22227777, a2, a5, a1);
	vsel(x07DA807F, x05FAF50A, x0F0F00FF, x22227777);
	vxor(x34E9B34C, a2, x07DA807F);

	vsel(x00FFF00F, x05FAF50A, a4, a3);
	vsel(x0033FCCF, a5, x00FFF00F, a2);
	vsel(x5565B15C, a1, x34E9B34C, x0033FCCF);
	vsel(x0C0C3F3F, a3, a5, a2);
	vxor(x59698E63, x5565B15C, x0C0C3F3F);

	vsel(x3001F74E, x34E9B34C, a5, x05FAF50A);
	vsel(x30555745, x3001F74E, a1, x00FFF00F);
	vxor(x693CD926, x59698E63, x30555745);
	vsel(x2, x693CD926, x59698E63, a6);
	vxor(*out3, *out3, x2);

	vsel(x0C0CD926, x0C0C3F3F, x693CD926, a5);
	vxor(x0C3F25E9, x0033FCCF, x0C0CD926);
	vxor(x38D696A5, x34E9B34C, x0C3F25E9);

	vnot(xC729695A, x38D696A5);

	vsel(x03D2117B, x07DA807F, a2, x0C0CD926);
	vsel(xC778395B, xC729695A, x03D2117B, x30555745);
	vxor(xCB471CB2, x0C3F25E9, xC778395B);
	vsel(x1, xCB471CB2, x34E9B34C, a6);
	vxor(*out2, *out2, x1);

	vsel(x5425B13F, x5565B15C, x0C0C3F3F, x03D2117B);
	vsel(x56B3803F, x07DA807F, x5425B13F, x59698E63);
	vxor(x919AE965, xC729695A, x56B3803F);
	vsel(x3, xC729695A, x919AE965, a6);
	vxor(*out4, *out4, x3);

	vsel(x17B3023F, x07DA807F, a2, x59698E63);
	vor(x75555755, a1, x30555745);
	vxor(x62E6556A, x17B3023F, x75555755);
	vxor(xA59E6C31, xC778395B, x62E6556A);
	vsel(x0, xA59E6C31, x38D696A5, a6);
	vxor(*out1, *out1, x0);
}
#endif
