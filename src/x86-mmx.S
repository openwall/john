/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2000-2001 by Solar Designer and others:
 *
 * The MMX DES S-box code is by Bruce Ford and Rémi Guyomarch, originally
 * for use in the distributed.net clients, included here with permission.
 * Only minor modifications have been made to their S-box code. Optimized
 * S-box expressions are based on work by Matthew Kwan (see nonstd.c).
 *
 * Note: there's some MMX code in x86.S as well.
 */

#ifdef UNDERSCORES
#define DES_bs_all			_DES_bs_all
#define DES_bs_init_asm			_DES_bs_init_asm
#define DES_bs_crypt			_DES_bs_crypt
#define DES_bs_crypt_25			_DES_bs_crypt_25
#define DES_bs_crypt_LM			_DES_bs_crypt_LM
#endif

/*
 * Some broken systems don't offer section alignments larger than 4 bytes,
 * while for the MMX code we need at least an 8 byte alignment. ALIGN_FIX
 * is here to work around this issue when we happen to get bad addresses.
 */
#ifndef ALIGN_FIX
#ifdef ALIGN_LOG
#define DO_ALIGN(log)			.align (log)
#else
#define DO_ALIGN(log)			.align (1 << (log))
#endif
#else
#ifdef ALIGN_LOG
#define DO_ALIGN(log)			.align (log); .space 4
#else
#define DO_ALIGN(log)			.align (1 << (log)); .space 4
#endif
#endif

#ifdef BSD
.data
#else
.bss
#endif

.globl DES_bs_all
DO_ALIGN(5)
DES_bs_all:
DES_bs_all_KSp:
.space (0x300 * 4)
DES_bs_all_KS_p:
DES_bs_all_KS_v:
.space (0x300 * 8)
DES_bs_all_E:
.space (96 * 4)
DES_bs_all_K:
.space (56 * 8)
DES_bs_all_B:
.space (64 * 8)
DES_bs_all_tmp:
.space (16 * 8)
DES_bs_all_fields_not_used_here:
.space (0x100 + 0x100 + 4 + 4 + 64 * 8)
DES_bs_all_possible_alignment_gaps:
.space 0x100

#define E(i)				DES_bs_all_E+(i)*4
#define B(i)				DES_bs_all_B+(i)*8
#define tmp_at(i)			DES_bs_all_tmp+(i)*8

#define pnot				tmp_at(0)

#define a1				%mm0
#define a2				%mm1
#define a3				%mm2
#define a4				%mm3
#define a5				%mm4
#define a6				%mm5

#define S1_out1				%mm5
#define S1_out2				%mm7
#define S1_out3				%mm2
#define S1_out4				%mm0

#define S1_a1				tmp_at(1)
#define S1_a3				tmp_at(2)
#define S1_a5				tmp_at(3)
#define S1_x1				tmp_at(4)
#define S1_x3				tmp_at(5)
#define S1_x4				tmp_at(6)
#define S1_x5				tmp_at(7)
#define S1_x6				tmp_at(8)
#define S1_x13				tmp_at(9)
#define S1_x14				tmp_at(10)
#define S1_x25				tmp_at(11)
#define S1_x26				tmp_at(12)
#define S1_x38				tmp_at(13)
#define S1_x55				tmp_at(14)
#define S1_x58				tmp_at(15)

#define S1(out1, out2, out3, out4, extra) \
	movq %mm0,S1_a1; \
	movq %mm3,%mm6; \
	pxor pnot,%mm0; \
	pxor %mm2,%mm3; \
	pxor pnot,%mm6; \
	movq %mm0,%mm7; \
	extra; \
	movq %mm4,S1_a5; \
	por %mm2,%mm7; \
	movq %mm3,S1_x3; \
	movq %mm5,%mm4; \
	movq %mm6,S1_x1; \
	pxor %mm0,%mm3; \
	movq %mm7,S1_x5; \
	por %mm6,%mm0; \
	movq %mm2,S1_a3; \
	pand %mm6,%mm7; \
	movq %mm3,S1_x4; \
	por %mm3,%mm2; \
	pxor pnot,%mm2; \
	pand %mm0,%mm4; \
	movq %mm7,%mm6; \
	por %mm5,%mm2; \
	movq %mm7,S1_x6; \
	por %mm5,%mm6; \
	pxor %mm2,%mm7; \
	pxor %mm6,%mm3; \
	movq %mm2,S1_x25; \
	pxor %mm4,%mm6; \
	pand S1_a3,%mm4; \
	movq %mm6,%mm2; \
	pxor S1_a3,%mm6; \
	por %mm1,%mm2; \
	pand S1_x5,%mm6; \
	pxor %mm3,%mm2; \
	movq %mm4,S1_x38; \
	pxor %mm2,%mm0; \
	movq %mm7,S1_x26; \
	movq %mm5,%mm4; \
	movq %mm2,S1_x13; \
	por %mm0,%mm4; \
	movq S1_x1,%mm7; \
	por %mm1,%mm6; \
	movq %mm0,S1_x14; \
	movq %mm3,%mm2; \
	pandn S1_x3,%mm0; \
	pxor %mm7,%mm4; \
	por S1_x4,%mm5; \
	por %mm1,%mm0; \
	pxor S1_x38,%mm5; \
	pxor %mm0,%mm4; \
	movq S1_a5,%mm0; \
	pand %mm7,%mm2; \
	movq %mm6,S1_x55; \
	por %mm1,%mm2; \
	movq S1_x14,%mm6; \
	por %mm4,%mm0; \
	pand S1_x5,%mm6; \
	por %mm3,%mm7; \
	movq %mm5,S1_x58; \
	pxor %mm3,%mm6; \
	pxor S1_x6,%mm7; \
	movq %mm1,%mm5; \
	pxor S1_x26,%mm2; \
	pand %mm6,%mm5; \
	pand S1_a3,%mm6; \
	pxor %mm7,%mm5; \
	por S1_a5,%mm5; \
	movq S1_a1,%mm7; \
	pxor %mm2,%mm5; \
	movq S1_x4,%mm2; \
	por %mm3,%mm7; \
	por S1_x38,%mm2; \
	pxor %mm6,%mm3; \
	pxor S1_x25,%mm6; \
	pxor %mm4,%mm7; \
	movq S1_a3,%mm4; \
	por %mm1,%mm7; \
	por S1_x26,%mm4; \
	por %mm1,%mm6; \
	pxor S1_x14,%mm4; \
	pxor %mm2,%mm6; \
	movq S1_x13,%mm2; \
	pxor %mm4,%mm7; \
	pxor S1_x55,%mm3; \
	pxor %mm2,%mm0; \
	pxor out1,%mm5; \
	pand %mm3,%mm2; \
	movq S1_a5,%mm4; \
	pand %mm1,%mm2; \
	movq %mm5,out1; \
	pxor S1_x58,%mm2; \
	pand %mm4,%mm7; \
	pxor out4,%mm0; \
	pand %mm4,%mm2; \
	pxor out2,%mm7; \
	movq %mm0,out4; \
	pxor out3,%mm2; \
	pxor %mm6,%mm7; \
	pxor %mm3,%mm2; \
	movq %mm7,out2; \
	movq %mm2,out3

#define S2_out1				%mm1
#undef S2_out2
#define S2_out3				%mm7
#define S2_out4				%mm2

#define S2_a1				tmp_at(1)
#define S2_a2				tmp_at(2)
#define S2_a3				tmp_at(3)
#define S2_a4				tmp_at(4)
#define S2_x3				tmp_at(5)
#define S2_x4				tmp_at(6)
#define S2_x5				tmp_at(7)
#define S2_x13				tmp_at(8)
#define S2_x18				tmp_at(9)
#define S2_x25				tmp_at(10)

#define S2(out1, out2, out3, out4, extra) \
	movq %mm3,S2_a4; \
	movq %mm4,%mm6; \
	extra; \
	movq %mm0,S2_a1; \
	movq %mm4,%mm7; \
	pxor pnot,%mm0; \
	pxor %mm5,%mm6; \
	pxor pnot,%mm7; \
	movq %mm0,%mm3; \
	movq %mm2,S2_a3; \
	por %mm5,%mm7; \
	movq %mm6,S2_x3; \
	por %mm7,%mm3; \
	pxor %mm4,%mm7; \
	pxor %mm0,%mm6; \
	pand %mm1,%mm3; \
	por %mm7,%mm2; \
	movq %mm1,S2_a2; \
	pxor %mm5,%mm3; \
	movq %mm6,S2_x4; \
	pxor %mm1,%mm6; \
	movq %mm7,S2_x13; \
	pand %mm3,%mm1; \
	pand S2_a3,%mm3; \
	pxor %mm2,%mm1; \
	movq S2_x4,%mm7; \
	movq %mm1,%mm2; \
	pand S2_a4,%mm2; \
	pxor %mm6,%mm3; \
	movq %mm6,S2_x5; \
	pxor %mm2,%mm3; \
	movq S2_a1,%mm2; \
	por %mm5,%mm7; \
	por %mm2,%mm1; \
	pand %mm3,%mm7; \
	pxor out2,%mm3; \
	por %mm4,%mm2; \
	por S2_a3,%mm7; \
	movq %mm2,%mm6; \
	pxor S2_x13,%mm1; \
	por %mm5,%mm6; \
	movq %mm3,out2; \
	pand %mm0,%mm4; \
	movq S2_x13,%mm3; \
	por %mm0,%mm5; \
	movq %mm2,S2_x18; \
	pxor %mm6,%mm3; \
	movq S2_a2,%mm2; \
	pxor %mm6,%mm0; \
	pxor %mm2,%mm3; \
	pand %mm2,%mm0; \
	pxor %mm3,%mm7; \
	por %mm4,%mm2; \
	pxor S2_x3,%mm4; \
	pand %mm3,%mm6; \
	pxor %mm0,%mm4; \
	pxor %mm5,%mm6; \
	movq %mm7,S2_x25; \
	pand %mm3,%mm0; \
	movq S2_a3,%mm7; \
	pxor %mm2,%mm5; \
	pxor S2_x5,%mm0; \
	pand %mm4,%mm7; \
	pand S2_a2,%mm4; \
	pxor %mm5,%mm7; \
	por S2_a4,%mm7; \
	movq %mm1,%mm5; \
	por S2_a3,%mm5; \
	por %mm2,%mm1; \
	pand S2_x18,%mm2; \
	pxor %mm3,%mm4; \
	movq S2_a4,%mm3; \
	pand %mm4,%mm2; \
	pand S2_a3,%mm4; \
	pxor %mm5,%mm0; \
	pxor S2_x25,%mm7; \
	pxor %mm6,%mm4; \
	pxor out3,%mm7; \
	pand %mm3,%mm1; \
	por %mm3,%mm2; \
	pxor out1,%mm1; \
	pxor %mm4,%mm2; \
	pxor %mm0,%mm1; \
	pxor out4,%mm2; \
	movq %mm1,out1; \
	movq %mm7,out3; \
	movq %mm2,out4

#define S3_out1				%mm2
#define S3_out2				%mm6
#define S3_out3				%mm3
#define S3_out4				%mm7

#define S3_a1				tmp_at(1)
#define S3_x2				tmp_at(2)
#define S3_x9				tmp_at(3)
#define S3_a5				tmp_at(4)
#define S3_x4				tmp_at(5)
#define S3_a6				tmp_at(6)
#define S3_x6				tmp_at(7)
#define S3_x5				tmp_at(8)
#define S3_x11				tmp_at(9)
#define S3_x12				tmp_at(10)
#define S3_x13				tmp_at(11)
#define S3_x54				tmp_at(12)
#define S3_x7				tmp_at(13)
#define S3_a4				tmp_at(14)
#define S3_a3				S3_a5
#define S3_x38				S3_x4

#define S3(out1, out2, out3, out4, extra) \
	movq %mm0,S3_a1; \
	extra; \
	movq %mm4,%mm0; \
	movq %mm5,%mm6; \
	pxor pnot,%mm6; \
	movq %mm4,%mm7; \
	pxor %mm6,%mm7; \
	movq %mm6,S3_x2; \
	pand %mm2,%mm0; \
	movq %mm7,S3_x9; \
	pxor %mm5,%mm0; \
	movq %mm4,S3_a5; \
	pandn %mm3,%mm4; \
	movq %mm0,S3_x4; \
	por %mm3,%mm7; \
	movq S3_a5,%mm6; \
	pxor %mm4,%mm0; \
	movq %mm5,S3_a6; \
	pandn %mm2,%mm6; \
	movq %mm0,S3_x6; \
	pxor %mm6,%mm7; \
	movq S3_x2,%mm5; \
	pxor %mm1,%mm0; \
	movq %mm4,S3_x5; \
	movq %mm7,%mm4; \
	por S3_x4,%mm5; \
	pand %mm0,%mm4; \
	movq %mm7,S3_x11; \
	pxor %mm5,%mm6; \
	pxor S3_a5,%mm7; \
	por %mm1,%mm6; \
	movq %mm4,S3_x12; \
	pand %mm5,%mm4; \
	movq %mm7,S3_x13; \
	por %mm0,%mm7; \
	movq %mm4,S3_x54; \
	movq %mm2,%mm4; \
	pxor S3_x9,%mm4; \
	pand %mm3,%mm7; \
	movq %mm0,S3_x7; \
	pxor %mm3,%mm4; \
	pxor S3_a6,%mm5; \
	pxor %mm4,%mm6; \
	movq %mm3,S3_a4; \
	por %mm5,%mm3; \
	movq %mm2,S3_a3; \
	pxor %mm3,%mm5; \
	por %mm1,%mm5; \
	pxor %mm7,%mm2; \
	pxor S3_x12,%mm7; \
	movq %mm2,%mm4; \
	por S3_x5,%mm2; \
	pand %mm1,%mm7; \
	por S3_x4,%mm4; \
	por %mm1,%mm2; \
	pxor S3_x11,%mm7; \
	pxor %mm3,%mm2; \
	movq S3_a1,%mm3; \
	pxor S3_a4,%mm4; \
	pand %mm3,%mm7; \
	pxor S3_x7,%mm7; \
	por %mm3,%mm2; \
	movq %mm4,S3_x38; \
	pxor %mm6,%mm2; \
	pxor out4,%mm7; \
	por %mm1,%mm4; \
	movq S3_a3,%mm6; \
	movq %mm2,%mm3; \
	pxor S3_x9,%mm6; \
	por S3_x5,%mm6; \
	pxor S3_x38,%mm3; \
	pxor %mm6,%mm4; \
	movq S3_a6,%mm6; \
	pand S3_x11,%mm6; \
	movq %mm7,out4; \
	movq S3_x2,%mm0; \
	pxor %mm6,%mm3; \
	por S3_x6,%mm6; \
	pand %mm1,%mm3; \
	por S3_x38,%mm0; \
	pxor %mm6,%mm3; \
	pxor S3_x13,%mm0; \
	movq %mm5,%mm6; \
	por S3_a1,%mm3; \
	pxor %mm5,%mm0; \
	pand S3_x54,%mm6; \
	pxor %mm4,%mm3; \
	por S3_a1,%mm6; \
	pxor out3,%mm3; \
	pxor %mm0,%mm6; \
	pxor out1,%mm2; \
	movq %mm3,out3; \
	pxor out2,%mm6; \
	movq %mm2,out1; \
	movq %mm6,out2

#define S4_out1				%mm1
#define S4_out2				%mm0
#define S4_out3				%mm6
#define S4_out4				%mm5

#define S4_a2				tmp_at(1)
#define S4_a3				tmp_at(2)
#define S4_a4				tmp_at(3)
#define S4_a6				tmp_at(4)

#define S4(out1, out2, out3, out4, extra) \
	movq %mm2,%mm6; \
	movq %mm3,S4_a4; \
	movq %mm0,%mm7; \
	movq %mm1,S4_a2; \
	por %mm0,%mm6; \
	extra; \
	pand %mm4,%mm7; \
	movq %mm1,%mm3; \
	movq %mm5,S4_a6; \
	movq %mm2,S4_a3; \
	movq %mm4,%mm5; \
	pand %mm6,%mm5; \
	por %mm2,%mm3; \
	pxor pnot,%mm2; \
	pxor %mm5,%mm0; \
	pxor pnot,%mm0; \
	pxor %mm7,%mm6; \
	pxor %mm0,%mm3; \
	movq %mm1,%mm7; \
	pand %mm6,%mm7; \
	pxor %mm2,%mm5; \
	pxor %mm4,%mm2; \
	pand %mm5,%mm0; \
	pxor %mm7,%mm4; \
	pand %mm1,%mm5; \
	por %mm1,%mm2; \
	pxor %mm6,%mm5; \
	movq S4_a4,%mm1; \
	movq %mm0,%mm6; \
	pand %mm4,%mm1; \
	pxor %mm2,%mm6; \
	por S4_a4,%mm6; \
	pxor %mm3,%mm1; \
	pand S4_a2,%mm4; \
	pxor %mm5,%mm6; \
	movq S4_a6,%mm3; \
	pxor %mm0,%mm4; \
	pxor S4_a3,%mm7; \
	movq %mm3,%mm0; \
	pxor %mm2,%mm7; \
	pand %mm6,%mm0; \
	movq S4_a4,%mm2; \
	por %mm3,%mm6; \
	pxor %mm1,%mm0; \
	pand %mm2,%mm7; \
	pxor pnot,%mm1; \
	pxor %mm7,%mm4; \
	movq %mm4,%mm5; \
	pxor %mm1,%mm4; \
	pxor out1,%mm1; \
	por %mm4,%mm2; \
	pand S4_a2,%mm4; \
	pxor %mm6,%mm1; \
	pxor %mm0,%mm4; \
	pxor out3,%mm6; \
	pxor %mm4,%mm2; \
	pxor out2,%mm0; \
	pand %mm2,%mm3; \
	pxor %mm2,%mm6; \
	pxor %mm3,%mm5; \
	movq %mm1,out1; \
	pxor %mm5,%mm6; \
	movq %mm0,out2; \
	pxor out4,%mm5; \
	movq %mm6,out3; \
	movq %mm5,out4

#define S5_out1				%mm5
#define S5_out2				%mm7
#define S5_out3				%mm6
#define S5_out4				%mm4

#define S5_a1				tmp_at(1)
#define S5_a2				tmp_at(2)
#define S5_a6				tmp_at(3)
#define S5_x2				tmp_at(4)
#define S5_x4				tmp_at(5)
#define S5_x5				tmp_at(6)
#define S5_x6				tmp_at(7)
#define S5_x7				tmp_at(8)
#define S5_x8				tmp_at(9)
#define S5_x9				tmp_at(10)
#define S5_x13				tmp_at(11)
#define S5_x16				tmp_at(12)
#define S5_x17				S5_a6
#define S5_x21				S5_x7
#define S5_x24				S5_x8
#define S5_x28				S5_x17
#define S5_x38				S5_x9

#define S5(out1, out2, out3, out4, extra) \
	movq %mm1,S5_a2; \
	movq %mm3,%mm6; \
	movq %mm2,%mm7; \
	pandn %mm2,%mm6; \
	pandn %mm0,%mm7; \
	movq %mm6,%mm1; \
	movq %mm0,S5_a1; \
	pxor %mm0,%mm1; \
	extra; \
	pxor %mm3,%mm0; \
	movq %mm1,S5_x2; \
	movq %mm5,S5_a6; \
	por %mm0,%mm6; \
	por %mm7,%mm5; \
	movq %mm6,S5_x7; \
	pxor %mm5,%mm1; \
	movq %mm5,S5_x4; \
	pand %mm2,%mm6; \
	movq S5_a6,%mm5; \
	pxor %mm3,%mm6; \
	pandn S5_x7,%mm5; \
	movq %mm0,S5_x6; \
	movq %mm7,%mm0; \
	movq %mm5,S5_x8; \
	pxor %mm2,%mm5; \
	movq %mm1,S5_x5; \
	pxor %mm3,%mm0; \
	movq %mm5,S5_x9; \
	pandn %mm6,%mm7; \
	por S5_a6,%mm0; \
	por %mm4,%mm5; \
	movq %mm6,S5_x13; \
	pxor %mm1,%mm5; \
	movq %mm0,S5_x16; \
	pxor %mm0,%mm7; \
	movq S5_a2,%mm0; \
	movq %mm4,%mm1; \
	movq %mm7,S5_x17; \
	por %mm7,%mm1; \
	pand S5_x5,%mm7; \
	pxor %mm6,%mm1; \
	pandn %mm1,%mm0; \
	movq %mm7,%mm6; \
	pandn S5_x7,%mm6; \
	pxor %mm0,%mm5; \
	pxor S5_x9,%mm7; \
	movq %mm3,%mm0; \
	movq %mm5,S5_x21; \
	movq %mm6,%mm5; \
	pandn S5_x8,%mm0; \
	pandn %mm1,%mm5; \
	pxor out3,%mm6; \
	pxor %mm2,%mm0; \
	movq S5_a1,%mm2; \
	movq %mm0,%mm1; \
	pxor S5_x9,%mm2; \
	pand %mm4,%mm1; \
	movq %mm7,S5_x38; \
	pxor %mm1,%mm6; \
	movq S5_x4,%mm1; \
	movq %mm2,%mm7; \
	pand S5_x2,%mm7; \
	pand %mm3,%mm1; \
	pxor S5_x17,%mm1; \
	pandn %mm4,%mm7; \
	movq %mm2,S5_x24; \
	pxor %mm7,%mm1; \
	movq out2,%mm7; \
	por %mm2,%mm3; \
	movq S5_a2,%mm2; \
	pxor %mm1,%mm7; \
	movq %mm3,S5_x28; \
	pandn %mm3,%mm2; \
	movq S5_x38,%mm3; \
	pxor %mm2,%mm7; \
	movq S5_x16,%mm2; \
	por %mm4,%mm3; \
	por S5_x13,%mm2; \
	por %mm5,%mm1; \
	pxor out1,%mm5; \
	pxor %mm3,%mm2; \
	por S5_a2,%mm2; \
	movq %mm7,out2; \
	pxor S5_x6,%mm1; \
	pxor %mm2,%mm6; \
	pandn %mm4,%mm1; \
	movq S5_x38,%mm2; \
	pxor S5_x24,%mm1; \
	movq %mm2,%mm3; \
	pxor S5_x21,%mm2; \
	pxor %mm1,%mm5; \
	pand S5_x6,%mm3; \
	pandn %mm4,%mm2; \
	pand S5_x28,%mm2; \
	pxor %mm0,%mm3; \
	pxor pnot,%mm6; \
	pxor %mm2,%mm3; \
	movq S5_x21,%mm4; \
	por S5_a2,%mm3; \
	movq %mm6,out3; \
	pxor out4,%mm4; \
	pxor %mm3,%mm5; \
	movq %mm4,out4; \
	movq %mm5,out1

#define S6_out1				%mm0
#undef S6_out2
#define S6_out3				%mm2
#define S6_out4				%mm4

#define S6_a1				tmp_at(1)
#define S6_a2				tmp_at(2)
#define S6_a3				tmp_at(3)
#define S6_a4				tmp_at(4)
#define S6_x1				tmp_at(5)
#define S6_x2				tmp_at(6)
#define S6_x5				tmp_at(7)
#define S6_x6				tmp_at(8)
#define S6_x8				tmp_at(9)
#define S6_x15				tmp_at(10)
#define S6_x16				tmp_at(11)

#define S6(out1, out2, out3, out4, extra) \
	movq %mm2,S6_a3; \
	extra; \
	movq %mm4,%mm6; \
	pxor pnot,%mm6; \
	movq %mm5,%mm7; \
	movq %mm1,S6_a2; \
	movq %mm4,%mm2; \
	movq %mm3,S6_a4; \
	pxor %mm1,%mm7; \
	pxor pnot,%mm1; \
	pxor %mm6,%mm7; \
	movq %mm6,S6_x2; \
	pxor %mm0,%mm7; \
	pand %mm5,%mm2; \
	movq %mm4,%mm6; \
	movq %mm1,S6_x1; \
	movq %mm5,%mm3; \
	pand S6_a2,%mm3; \
	pand %mm7,%mm6; \
	movq %mm0,S6_a1; \
	por %mm2,%mm1; \
	movq %mm2,S6_x6; \
	pand %mm6,%mm0; \
	movq %mm3,S6_x15; \
	pxor %mm0,%mm1; \
	movq S6_a4,%mm0; \
	movq %mm4,%mm2; \
	movq %mm6,S6_x8; \
	pand %mm1,%mm0; \
	movq %mm7,S6_x5; \
	pxor %mm3,%mm2; \
	movq S6_x2,%mm6; \
	pxor %mm7,%mm0; \
	movq S6_a1,%mm7; \
	pxor %mm5,%mm1; \
	movq %mm2,S6_x16; \
	pand %mm7,%mm2; \
	movq S6_a4,%mm3; \
	pxor %mm2,%mm6; \
	pxor S6_a2,%mm2; \
	pand %mm7,%mm1; \
	por %mm6,%mm3; \
	pxor %mm5,%mm6; \
	pxor %mm3,%mm1; \
	pand %mm6,%mm7; \
	pand S6_a3,%mm1; \
	pand %mm4,%mm6; \
	movq S6_x6,%mm3; \
	pxor %mm1,%mm0; \
	pxor out2,%mm0; \
	por %mm2,%mm3; \
	pand S6_a4,%mm3; \
	pxor %mm7,%mm4; \
	movq S6_x5,%mm1; \
	pxor %mm3,%mm4; \
	pxor pnot,%mm2; \
	por %mm4,%mm5; \
	movq %mm0,out2; \
	movq %mm5,%mm3; \
	pandn S6_a4,%mm3; \
	pxor %mm6,%mm1; \
	movq S6_x6,%mm0; \
	pxor %mm2,%mm3; \
	por S6_a4,%mm1; \
	pxor %mm3,%mm0; \
	pand S6_a3,%mm3; \
	pxor %mm1,%mm0; \
	por S6_x5,%mm6; \
	movq %mm7,%mm1; \
	pxor S6_x15,%mm7; \
	pxor %mm3,%mm4; \
	movq S6_a4,%mm3; \
	pxor %mm5,%mm7; \
	pand S6_x8,%mm5; \
	por %mm3,%mm7; \
	pxor S6_x6,%mm6; \
	por %mm3,%mm5; \
	por S6_x16,%mm1; \
	pxor %mm6,%mm5; \
	pxor S6_x1,%mm1; \
	movq S6_a3,%mm3; \
	pxor %mm1,%mm7; \
	pxor out4,%mm4; \
	por %mm3,%mm7; \
	pand %mm1,%mm2; \
	pxor out1,%mm0; \
	por %mm3,%mm2; \
	pxor %mm7,%mm0; \
	pxor %mm5,%mm2; \
	movq %mm4,out4; \
	pxor out3,%mm2; \
	movq %mm0,out1; \
	movq %mm2,out3

#define S7_out1				%mm7
#define S7_out2				%mm1
#define S7_out3				%mm3
#define S7_out4				%mm0

#define S7_a1				tmp_at(1)
#define S7_a2				tmp_at(2)
#define S7_a4				tmp_at(3)
#define S7_a6				tmp_at(4)
#define S7_x6				tmp_at(5)
#define S7_x7				tmp_at(6)
#define S7_x8				tmp_at(7)
#define S7_x11				tmp_at(8)
#define S7_x13				tmp_at(9)
#define S7_x15				tmp_at(10)
#define S7_x25				tmp_at(11)
#define S7_x26				tmp_at(12)

#define S7(out1, out2, out3, out4, extra) \
	movq %mm0,S7_a1; \
	movq %mm1,%mm6; \
	extra; \
	movq %mm1,S7_a2; \
	movq %mm3,%mm7; \
	movq %mm5,S7_a6; \
	pand %mm3,%mm6; \
	movq %mm3,S7_a4; \
	pxor %mm4,%mm6; \
	pxor pnot,%mm4; \
	pand %mm6,%mm7; \
	pand %mm4,%mm3; \
	movq %mm1,%mm5; \
	pxor %mm2,%mm6; \
	pxor %mm7,%mm5; \
	movq %mm7,S7_x6; \
	por %mm1,%mm4; \
	por %mm3,%mm1; \
	pxor %mm6,%mm7; \
	movq %mm5,S7_x7; \
	pand %mm2,%mm4; \
	pand %mm2,%mm5; \
	por %mm7,%mm3; \
	movq %mm1,S7_x13; \
	pxor %mm5,%mm0; \
	por S7_a6,%mm0; \
	pxor %mm4,%mm1; \
	movq %mm4,S7_x15; \
	pxor %mm6,%mm0; \
	movq %mm5,S7_x8; \
	movq %mm3,%mm4; \
	movq S7_a6,%mm6; \
	movq %mm0,%mm5; \
	pxor S7_x6,%mm5; \
	por %mm6,%mm4; \
	movq %mm7,S7_x25; \
	por %mm6,%mm5; \
	movq S7_a1,%mm7; \
	pxor %mm1,%mm5; \
	movq %mm3,S7_x26; \
	pand %mm5,%mm7; \
	movq %mm0,S7_x11; \
	pxor %mm0,%mm7; \
	movq S7_a4,%mm3; \
	movq %mm7,%mm0; \
	por S7_a2,%mm0; \
	pand %mm3,%mm1; \
	pand S7_x13,%mm3; \
	por S7_x7,%mm2; \
	pxor S7_x6,%mm0; \
	pxor %mm3,%mm2; \
	movq S7_a2,%mm3; \
	movq %mm0,%mm6; \
	pxor pnot,%mm3; \
	pxor S7_x15,%mm6; \
	por %mm3,%mm1; \
	pand S7_x26,%mm0; \
	pxor %mm6,%mm4; \
	pand S7_a6,%mm0; \
	por %mm3,%mm6; \
	por S7_a6,%mm6; \
	pand %mm5,%mm3; \
	pand S7_a6,%mm1; \
	pxor %mm3,%mm0; \
	por S7_a1,%mm0; \
	pxor %mm6,%mm2; \
	pxor S7_x11,%mm1; \
	pxor %mm4,%mm0; \
	movq S7_a1,%mm4; \
	pxor %mm2,%mm5; \
	movq S7_a4,%mm6; \
	por %mm2,%mm4; \
	pxor S7_x25,%mm6; \
	pxor %mm4,%mm1; \
	movq S7_a6,%mm4; \
	pand %mm1,%mm6; \
	movq S7_x6,%mm3; \
	pand %mm4,%mm6; \
	pxor S7_x15,%mm3; \
	pxor %mm5,%mm6; \
	pxor S7_x8,%mm2; \
	por %mm4,%mm3; \
	por S7_a1,%mm6; \
	pxor %mm2,%mm3; \
	pxor out1,%mm7; \
	pxor %mm6,%mm3; \
	pxor out2,%mm1; \
	movq %mm7,out1; \
	pxor out3,%mm3; \
	movq %mm1,out2; \
	pxor out4,%mm0; \
	movq %mm3,out3; \
	movq %mm0,out4

#define S8_out1				%mm6
#define S8_out2				%mm2
#define S8_out3				%mm5
#define S8_out4				%mm1

#define S8_a1				tmp_at(1)
#define S8_a2				tmp_at(2)
#define S8_a4				tmp_at(3)
#define S8_a5				tmp_at(4)
#define S8_a6				tmp_at(5)
#define S8_x14				tmp_at(6)
#define S8_x22				tmp_at(7)
#define S8_x33				tmp_at(8)

#define S8(out1, out2, out3, out4, extra) \
	movq %mm0,S8_a1; \
	extra; \
	movq %mm2,%mm6; \
	pxor pnot,%mm0; \
	movq %mm2,%mm7; \
	movq %mm3,S8_a4; \
	por %mm0,%mm7; \
	pxor pnot,%mm3; \
	pxor %mm0,%mm6; \
	movq %mm5,S8_a6; \
	movq %mm4,%mm5; \
	movq %mm1,S8_a2; \
	movq %mm7,%mm1; \
	movq %mm4,S8_a5; \
	pxor %mm3,%mm7; \
	por %mm6,%mm5; \
	por %mm7,%mm0; \
	pand %mm4,%mm1; \
	pandn %mm0,%mm2; \
	por %mm7,%mm4; \
	pxor %mm1,%mm2; \
	movq %mm5,S8_x22; \
	pand %mm3,%mm5; \
	por S8_a2,%mm2; \
	pxor %mm4,%mm7; \
	pxor %mm0,%mm3; \
	movq %mm4,%mm1; \
	pxor S8_x22,%mm7; \
	pxor %mm3,%mm1; \
	pxor %mm6,%mm4; \
	pxor %mm5,%mm2; \
	pxor S8_a1,%mm5; \
	pand %mm3,%mm6; \
	movq %mm1,S8_x14; \
	pand %mm4,%mm5; \
	movq %mm7,S8_x33; \
	movq %mm0,%mm1; \
	pand S8_a5,%mm3; \
	movq %mm0,%mm7; \
	pand S8_a5,%mm1; \
	pxor %mm3,%mm7; \
	pand S8_a2,%mm7; \
	pxor %mm1,%mm6; \
	movq S8_a6,%mm1; \
	pxor %mm4,%mm7; \
	por S8_a2,%mm6; \
	pandn %mm0,%mm4; \
	pxor S8_x14,%mm6; \
	pand %mm2,%mm1; \
	pxor S8_a1,%mm3; \
	pxor %mm6,%mm2; \
	por S8_a6,%mm6; \
	pxor %mm7,%mm1; \
	pxor S8_x22,%mm3; \
	pxor %mm7,%mm6; \
	por S8_a2,%mm4; \
	pand S8_a2,%mm5; \
	pxor %mm4,%mm3; \
	movq S8_a1,%mm4; \
	pand S8_x33,%mm4; \
	por S8_a4,%mm7; \
	pxor %mm4,%mm0; \
	pand S8_a2,%mm7; \
	pxor %mm0,%mm5; \
	movq S8_a6,%mm4; \
	por %mm0,%mm2; \
	pxor S8_x33,%mm7; \
	por %mm4,%mm5; \
	pxor out1,%mm6; \
	pand %mm4,%mm2; \
	pxor out4,%mm1; \
	pxor %mm7,%mm5; \
	pxor %mm3,%mm2; \
	pxor out3,%mm5; \
	movq %mm6,out1; \
	pxor out2,%mm2; \
	movq %mm1,out4; \
	movq %mm5,out3; \
	movq %mm2,out2

#define zero				%mm0

#define DES_bs_clear_block_8(i) \
	movq zero,B(i); \
	movq zero,B(i + 1); \
	movq zero,B(i + 2); \
	movq zero,B(i + 3); \
	movq zero,B(i + 4); \
	movq zero,B(i + 5); \
	movq zero,B(i + 6); \
	movq zero,B(i + 7)

#define DES_bs_clear_block \
	DES_bs_clear_block_8(0); \
	DES_bs_clear_block_8(8); \
	DES_bs_clear_block_8(16); \
	DES_bs_clear_block_8(24); \
	DES_bs_clear_block_8(32); \
	DES_bs_clear_block_8(40); \
	DES_bs_clear_block_8(48); \
	DES_bs_clear_block_8(56)

#define k_ptr				%edx
#define K(i)				(i)*8(k_ptr)
#define k(i)				(i)*4(k_ptr)

#define a6_xor_ptr			%esi
#define a6_p				pxor (a6_xor_ptr),a6
#define a6_v(i)				pxor K(i),a6

#define tmp1				%ecx
#define tmp2				a6_xor_ptr

#define xor_E(i) \
	movl E(i),tmp1; \
	movq K(i),a1; \
	movl E(i + 1),tmp2; \
	movq K(i + 1),a2; \
	pxor (tmp1),a1; \
	pxor (tmp2),a2; \
	movl E(i + 2),tmp1; \
	movq K(i + 2),a3; \
	movl E(i + 3),tmp2; \
	movq K(i + 3),a4; \
	pxor (tmp1),a3; \
	pxor (tmp2),a4; \
	movl E(i + 4),tmp1; \
	movq K(i + 4),a5; \
	movl E(i + 5),a6_xor_ptr; \
	movq K(i + 5),a6; \
	pxor (tmp1),a5

#define xor_B(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6) \
	movq B(b1),a1; \
	movq B(b2),a2; \
	pxor K(k1),a1; \
	movq B(b3),a3; \
	pxor K(k2),a2; \
	movq B(b4),a4; \
	pxor K(k3),a3; \
	movq B(b5),a5; \
	pxor K(k4),a4; \
	movq B(b6),a6; \
	pxor K(k5),a5

#define xor_B_KS_p(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6, k6) \
	movl k(k1),tmp1; \
	movl k(k2),tmp2; \
	movq B(b1),a1; \
	movq B(b2),a2; \
	pxor (tmp1),a1; \
	movl k(k3),tmp1; \
	pxor (tmp2),a2; \
	movl k(k4),tmp2; \
	movq B(b3),a3; \
	movq B(b4),a4; \
	pxor (tmp1),a3; \
	movl k(k5),tmp1; \
	pxor (tmp2),a4; \
	movq B(b5),a5; \
	movl k(k6),a6_xor_ptr; \
	movq B(b6),a6; \
	pxor (tmp1),a5

.data

DO_ALIGN(3)
mm_ones:
.quad -1

.text

DO_ALIGN(5)
.globl DES_bs_init_asm
DES_bs_init_asm:
	movq mm_ones,%mm0
	movq %mm0,pnot
	ret

#define rounds_and_swapped		%ebp
#define iterations			%eax

DO_ALIGN(5)
.globl DES_bs_crypt
DES_bs_crypt:
	movl 4(%esp),iterations
	pxor zero,zero
	pushl %ebp
	pushl %esi
	movl $DES_bs_all_KS_v,k_ptr
	DES_bs_clear_block
	movl $8,rounds_and_swapped
DES_bs_crypt_start:
	xor_E(0)
	S1(B(40), B(48), B(54), B(62), a6_p)
	xor_E(6)
	S2(B(44), B(59), B(33), B(49), a6_p)
	xor_E(12)
	S3(B(55), B(47), B(61), B(37), a6_p)
	xor_E(18)
	S4(B(57), B(51), B(41), B(32), a6_p)
	xor_E(24)
	S5(B(39), B(45), B(56), B(34), a6_p)
	xor_E(30)
	S6(B(35), B(60), B(42), B(50), a6_p)
	xor_E(36)
	S7(B(63), B(43), B(53), B(38), a6_p)
	xor_E(42)
	S8(B(36), B(58), B(46), B(52), a6_p)
	cmpl $0x100,rounds_and_swapped
	je DES_bs_crypt_next
DES_bs_crypt_swap:
	xor_E(48)
	S1(B(8), B(16), B(22), B(30), a6_p)
	xor_E(54)
	S2(B(12), B(27), B(1), B(17), a6_p)
	xor_E(60)
	S3(B(23), B(15), B(29), B(5), a6_p)
	xor_E(66)
	S4(B(25), B(19), B(9), B(0), a6_p)
	xor_E(72)
	S5(B(7), B(13), B(24), B(2), a6_p)
	xor_E(78)
	S6(B(3), B(28), B(10), B(18), a6_p)
	xor_E(84)
	S7(B(31), B(11), B(21), B(6), a6_p)
	xor_E(90)
	addl $96*8,k_ptr
	S8(B(4), B(26), B(14), B(20), a6_p)
	decl rounds_and_swapped
	jnz DES_bs_crypt_start
	subl $0x300*8+48*8,k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_swap
	popl %esi
	popl %ebp
#ifdef EMMS
	emms
#endif
	ret
DES_bs_crypt_next:
	subl $0x300*8-48*8,k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_start
	popl %esi
	popl %ebp
#ifdef EMMS
	emms
#endif
	ret

DO_ALIGN(5)
.globl DES_bs_crypt_25
DES_bs_crypt_25:
	pxor zero,zero
	pushl %ebp
	pushl %esi
	movl $DES_bs_all_KS_v,k_ptr
	DES_bs_clear_block
	movl $8,rounds_and_swapped
	movl $25,iterations
DES_bs_crypt_25_start:
	xor_E(0)
	S1(B(40), B(48), B(54), B(62), a6_p)
	xor_E(6)
	S2(B(44), B(59), B(33), B(49), a6_p)
	xor_B(7, 12, 8, 13, 9, 14, 10, 15, 11, 16, 12)
	S3(B(55), B(47), B(61), B(37), a6_v(17))
	xor_B(11, 18, 12, 19, 13, 20, 14, 21, 15, 22, 16)
	S4(B(57), B(51), B(41), B(32), a6_v(23))
	xor_E(24)
	S5(B(39), B(45), B(56), B(34), a6_p)
	xor_E(30)
	S6(B(35), B(60), B(42), B(50), a6_p)
	xor_B(23, 36, 24, 37, 25, 38, 26, 39, 27, 40, 28)
	S7(B(63), B(43), B(53), B(38), a6_v(41))
	xor_B(27, 42, 28, 43, 29, 44, 30, 45, 31, 46, 0)
	S8(B(36), B(58), B(46), B(52), a6_v(47))
	cmpl $0x100,rounds_and_swapped
	je DES_bs_crypt_25_next
DES_bs_crypt_25_swap:
	xor_E(48)
	S1(B(8), B(16), B(22), B(30), a6_p)
	xor_E(54)
	S2(B(12), B(27), B(1), B(17), a6_p)
	xor_B(39, 60, 40, 61, 41, 62, 42, 63, 43, 64, 44)
	S3(B(23), B(15), B(29), B(5), a6_v(65))
	xor_B(43, 66, 44, 67, 45, 68, 46, 69, 47, 70, 48)
	S4(B(25), B(19), B(9), B(0), a6_v(71))
	xor_E(72)
	S5(B(7), B(13), B(24), B(2), a6_p)
	xor_E(78)
	S6(B(3), B(28), B(10), B(18), a6_p)
	xor_B(55, 84, 56, 85, 57, 86, 58, 87, 59, 88, 60)
	S7(B(31), B(11), B(21), B(6), a6_v(89))
	xor_B(59, 90, 60, 91, 61, 92, 62, 93, 63, 94, 32)
	S8(B(4), B(26), B(14), B(20), a6_v(95))
	addl $96*8,k_ptr
	decl rounds_and_swapped
	jnz DES_bs_crypt_25_start
	subl $0x300*8+48*8,k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_25_swap
	popl %esi
	popl %ebp
#ifdef EMMS
	emms
#endif
	ret
DES_bs_crypt_25_next:
	subl $0x300*8-48*8,k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jmp DES_bs_crypt_25_start

#define ones				%mm1

#define rounds				%eax

DO_ALIGN(5)
.globl DES_bs_crypt_LM
DES_bs_crypt_LM:
	pxor zero,zero
	pushl %esi
	movq pnot,ones
	movl $DES_bs_all_KS_p,k_ptr
	movq zero,B(0)
	movq zero,B(1)
	movq zero,B(2)
	movq zero,B(3)
	movq zero,B(4)
	movq zero,B(5)
	movq zero,B(6)
	movq zero,B(7)
	movq ones,B(8)
	movq ones,B(9)
	movq ones,B(10)
	movq zero,B(11)
	movq ones,B(12)
	movq zero,B(13)
	movq zero,B(14)
	movq zero,B(15)
	movq zero,B(16)
	movq zero,B(17)
	movq zero,B(18)
	movq zero,B(19)
	movq zero,B(20)
	movq zero,B(21)
	movq zero,B(22)
	movq ones,B(23)
	movq zero,B(24)
	movq zero,B(25)
	movq ones,B(26)
	movq zero,B(27)
	movq zero,B(28)
	movq ones,B(29)
	movq ones,B(30)
	movq ones,B(31)
	movq zero,B(32)
	movq zero,B(33)
	movq zero,B(34)
	movq ones,B(35)
	movq zero,B(36)
	movq ones,B(37)
	movq ones,B(38)
	movq ones,B(39)
	movq zero,B(40)
	movq zero,B(41)
	movq zero,B(42)
	movq zero,B(43)
	movq zero,B(44)
	movq ones,B(45)
	movq zero,B(46)
	movq zero,B(47)
	movq ones,B(48)
	movq ones,B(49)
	movq zero,B(50)
	movq zero,B(51)
	movq zero,B(52)
	movq zero,B(53)
	movq ones,B(54)
	movq zero,B(55)
	movq ones,B(56)
	movq zero,B(57)
	movq ones,B(58)
	movq zero,B(59)
	movq ones,B(60)
	movq ones,B(61)
	movq ones,B(62)
	movq ones,B(63)
	movl $8,rounds
DES_bs_crypt_LM_loop:
	xor_B_KS_p(31, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5)
	S1(B(40), B(48), B(54), B(62), a6_p)
	xor_B_KS_p(3, 6, 4, 7, 5, 8, 6, 9, 7, 10, 8, 11)
	S2(B(44), B(59), B(33), B(49), a6_p)
	xor_B_KS_p(7, 12, 8, 13, 9, 14, 10, 15, 11, 16, 12, 17)
	S3(B(55), B(47), B(61), B(37), a6_p)
	xor_B_KS_p(11, 18, 12, 19, 13, 20, 14, 21, 15, 22, 16, 23)
	S4(B(57), B(51), B(41), B(32), a6_p)
	xor_B_KS_p(15, 24, 16, 25, 17, 26, 18, 27, 19, 28, 20, 29)
	S5(B(39), B(45), B(56), B(34), a6_p)
	xor_B_KS_p(19, 30, 20, 31, 21, 32, 22, 33, 23, 34, 24, 35)
	S6(B(35), B(60), B(42), B(50), a6_p)
	xor_B_KS_p(23, 36, 24, 37, 25, 38, 26, 39, 27, 40, 28, 41)
	S7(B(63), B(43), B(53), B(38), a6_p)
	xor_B_KS_p(27, 42, 28, 43, 29, 44, 30, 45, 31, 46, 0, 47)
	S8(B(36), B(58), B(46), B(52), a6_p)
	xor_B_KS_p(63, 48, 32, 49, 33, 50, 34, 51, 35, 52, 36, 53)
	S1(B(8), B(16), B(22), B(30), a6_p)
	xor_B_KS_p(35, 54, 36, 55, 37, 56, 38, 57, 39, 58, 40, 59)
	S2(B(12), B(27), B(1), B(17), a6_p)
	xor_B_KS_p(39, 60, 40, 61, 41, 62, 42, 63, 43, 64, 44, 65)
	S3(B(23), B(15), B(29), B(5), a6_p)
	xor_B_KS_p(43, 66, 44, 67, 45, 68, 46, 69, 47, 70, 48, 71)
	S4(B(25), B(19), B(9), B(0), a6_p)
	xor_B_KS_p(47, 72, 48, 73, 49, 74, 50, 75, 51, 76, 52, 77)
	S5(B(7), B(13), B(24), B(2), a6_p)
	xor_B_KS_p(51, 78, 52, 79, 53, 80, 54, 81, 55, 82, 56, 83)
	S6(B(3), B(28), B(10), B(18), a6_p)
	xor_B_KS_p(55, 84, 56, 85, 57, 86, 58, 87, 59, 88, 60, 89)
	S7(B(31), B(11), B(21), B(6), a6_p)
	xor_B_KS_p(59, 90, 60, 91, 61, 92, 62, 93, 63, 94, 32, 95)
	addl $96*4,k_ptr
	S8(B(4), B(26), B(14), B(20), a6_p)
	decl rounds
	jnz DES_bs_crypt_LM_loop
	popl %esi
#ifdef EMMS
	emms
#endif
	ret
