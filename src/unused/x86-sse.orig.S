/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2000-2001,2005,2006,2008 by Solar Designer and others:
 *
 * The MMX DES S-box code that this SSE2 DES S-box code is derived from
 * is by Bruce Ford and Rémi Guyomarch, originally for use in the
 * distributed.net clients, included here with permission.  Only minor
 * modifications have been made to their S-box code.  The optimized S-box
 * expressions are based on work by Matthew Kwan (see nonstd.c).
 *
 * ...with changes in the jumbo patch, by Alain Espinosa (starting with a
 * comment further down this file).
 */

#include "arch.h"

/*
 * Some broken systems don't offer section alignments larger than 4 bytes,
 * while for the SSE code we need at least a 16 byte alignment.  ALIGN_FIX
 * is here to work around this issue when we happen to get bad addresses.
 */
#ifndef ALIGN_FIX
#ifdef ALIGN_LOG
#define DO_ALIGN(log)			.align log
#else
#define DO_ALIGN(log)			.align 1 << log
#endif
#else
#ifdef ALIGN_LOG
#define DO_ALIGN(log)			.align log; .space ALIGN_FIX
#else
#define DO_ALIGN(log)			.align 1 << log; .space ALIGN_FIX
#endif
#endif

#if DES_BS_ASM

#ifdef UNDERSCORES
#define DES_bs_all			_DES_bs_all
#define DES_bs_init_asm			_DES_bs_init_asm
#define DES_bs_crypt			_DES_bs_crypt
#define DES_bs_crypt_25			_DES_bs_crypt_25
#define DES_bs_crypt_LM			_DES_bs_crypt_LM
#endif

#ifdef __sun
/* Sun's assembler doesn't recognize .space */
#define DO_SPACE(size)			.zero size
#else
/* Mac OS X assembler doesn't recognize .zero */
#define DO_SPACE(size)			.space size
#endif

/* Sun's assembler can't multiply, but at least it can add... */
#define nptr(n)				n+n+n+n
#define nvec(n)				n+n+n+n+n+n+n+n+n+n+n+n+n+n+n+n

#ifdef BSD
.data
#else
.bss
#endif

.globl DES_bs_all
DO_ALIGN(5)
DES_bs_all:
DES_bs_all_KSp:
DO_SPACE(nptr(0x300))
DES_bs_all_KS_p:
DES_bs_all_KS_v:
DO_SPACE(nvec(0x300))
DES_bs_all_E:
DO_SPACE(nptr(96))
DES_bs_all_K:
DO_SPACE(nvec(56))
DES_bs_all_B:
DO_SPACE(nvec(64))
DES_bs_all_tmp:
DO_SPACE(nvec(16))
DES_bs_all_fields_not_used_here:
DO_SPACE(0x400 + 0x100 + 4 + 4 + 0x400)
DES_bs_all_possible_alignment_gaps:
DO_SPACE(0x100)

#define E(i)				DES_bs_all_E+nptr(i)
#define B(i)				DES_bs_all_B+nvec(i)
#define tmp_at(i)			DES_bs_all_tmp+nvec(i)

#define pnot				tmp_at(0)

#define a1				%xmm0
#define a2				%xmm1
#define a3				%xmm2
#define a4				%xmm3
#define a5				%xmm4
#define a6				%xmm5

#define S1_out1				%xmm5
#define S1_out2				%xmm7
#define S1_out3				%xmm2
#define S1_out4				%xmm0

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
	movdqa %xmm0,S1_a1; \
	movdqa %xmm3,%xmm6; \
	pxor pnot,%xmm0; \
	pxor %xmm2,%xmm3; \
	pxor pnot,%xmm6; \
	movdqa %xmm0,%xmm7; \
	extra; \
	movdqa %xmm4,S1_a5; \
	por %xmm2,%xmm7; \
	movdqa %xmm3,S1_x3; \
	movdqa %xmm5,%xmm4; \
	movdqa %xmm6,S1_x1; \
	pxor %xmm0,%xmm3; \
	movdqa %xmm7,S1_x5; \
	por %xmm6,%xmm0; \
	movdqa %xmm2,S1_a3; \
	pand %xmm6,%xmm7; \
	movdqa %xmm3,S1_x4; \
	por %xmm3,%xmm2; \
	pxor pnot,%xmm2; \
	pand %xmm0,%xmm4; \
	movdqa %xmm7,%xmm6; \
	por %xmm5,%xmm2; \
	movdqa %xmm7,S1_x6; \
	por %xmm5,%xmm6; \
	pxor %xmm2,%xmm7; \
	pxor %xmm6,%xmm3; \
	movdqa %xmm2,S1_x25; \
	pxor %xmm4,%xmm6; \
	pand S1_a3,%xmm4; \
	movdqa %xmm6,%xmm2; \
	pxor S1_a3,%xmm6; \
	por %xmm1,%xmm2; \
	pand S1_x5,%xmm6; \
	pxor %xmm3,%xmm2; \
	movdqa %xmm4,S1_x38; \
	pxor %xmm2,%xmm0; \
	movdqa %xmm7,S1_x26; \
	movdqa %xmm5,%xmm4; \
	movdqa %xmm2,S1_x13; \
	por %xmm0,%xmm4; \
	movdqa S1_x1,%xmm7; \
	por %xmm1,%xmm6; \
	movdqa %xmm0,S1_x14; \
	movdqa %xmm3,%xmm2; \
	pandn S1_x3,%xmm0; \
	pxor %xmm7,%xmm4; \
	por S1_x4,%xmm5; \
	por %xmm1,%xmm0; \
	pxor S1_x38,%xmm5; \
	pxor %xmm0,%xmm4; \
	movdqa S1_a5,%xmm0; \
	pand %xmm7,%xmm2; \
	movdqa %xmm6,S1_x55; \
	por %xmm1,%xmm2; \
	movdqa S1_x14,%xmm6; \
	por %xmm4,%xmm0; \
	pand S1_x5,%xmm6; \
	por %xmm3,%xmm7; \
	movdqa %xmm5,S1_x58; \
	pxor %xmm3,%xmm6; \
	pxor S1_x6,%xmm7; \
	movdqa %xmm1,%xmm5; \
	pxor S1_x26,%xmm2; \
	pand %xmm6,%xmm5; \
	pand S1_a3,%xmm6; \
	pxor %xmm7,%xmm5; \
	por S1_a5,%xmm5; \
	movdqa S1_a1,%xmm7; \
	pxor %xmm2,%xmm5; \
	movdqa S1_x4,%xmm2; \
	por %xmm3,%xmm7; \
	por S1_x38,%xmm2; \
	pxor %xmm6,%xmm3; \
	pxor S1_x25,%xmm6; \
	pxor %xmm4,%xmm7; \
	movdqa S1_a3,%xmm4; \
	por %xmm1,%xmm7; \
	por S1_x26,%xmm4; \
	por %xmm1,%xmm6; \
	pxor S1_x14,%xmm4; \
	pxor %xmm2,%xmm6; \
	movdqa S1_x13,%xmm2; \
	pxor %xmm4,%xmm7; \
	pxor S1_x55,%xmm3; \
	pxor %xmm2,%xmm0; \
	pxor out1,%xmm5; \
	pand %xmm3,%xmm2; \
	movdqa S1_a5,%xmm4; \
	pand %xmm1,%xmm2; \
	movdqa %xmm5,out1; \
	pxor S1_x58,%xmm2; \
	pand %xmm4,%xmm7; \
	pxor out4,%xmm0; \
	pand %xmm4,%xmm2; \
	pxor out2,%xmm7; \
	movdqa %xmm0,out4; \
	pxor out3,%xmm2; \
	pxor %xmm6,%xmm7; \
	pxor %xmm3,%xmm2; \
	movdqa %xmm7,out2; \
	movdqa %xmm2,out3

#define S2_out1				%xmm1
#undef S2_out2
#define S2_out3				%xmm7
#define S2_out4				%xmm2

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
	movdqa %xmm3,S2_a4; \
	movdqa %xmm4,%xmm6; \
	extra; \
	movdqa %xmm0,S2_a1; \
	movdqa %xmm4,%xmm7; \
	pxor pnot,%xmm0; \
	pxor %xmm5,%xmm6; \
	pxor pnot,%xmm7; \
	movdqa %xmm0,%xmm3; \
	movdqa %xmm2,S2_a3; \
	por %xmm5,%xmm7; \
	movdqa %xmm6,S2_x3; \
	por %xmm7,%xmm3; \
	pxor %xmm4,%xmm7; \
	pxor %xmm0,%xmm6; \
	pand %xmm1,%xmm3; \
	por %xmm7,%xmm2; \
	movdqa %xmm1,S2_a2; \
	pxor %xmm5,%xmm3; \
	movdqa %xmm6,S2_x4; \
	pxor %xmm1,%xmm6; \
	movdqa %xmm7,S2_x13; \
	pand %xmm3,%xmm1; \
	pand S2_a3,%xmm3; \
	pxor %xmm2,%xmm1; \
	movdqa S2_x4,%xmm7; \
	movdqa %xmm1,%xmm2; \
	pand S2_a4,%xmm2; \
	pxor %xmm6,%xmm3; \
	movdqa %xmm6,S2_x5; \
	pxor %xmm2,%xmm3; \
	movdqa S2_a1,%xmm2; \
	por %xmm5,%xmm7; \
	por %xmm2,%xmm1; \
	pand %xmm3,%xmm7; \
	pxor out2,%xmm3; \
	por %xmm4,%xmm2; \
	por S2_a3,%xmm7; \
	movdqa %xmm2,%xmm6; \
	pxor S2_x13,%xmm1; \
	por %xmm5,%xmm6; \
	movdqa %xmm3,out2; \
	pand %xmm0,%xmm4; \
	movdqa S2_x13,%xmm3; \
	por %xmm0,%xmm5; \
	movdqa %xmm2,S2_x18; \
	pxor %xmm6,%xmm3; \
	movdqa S2_a2,%xmm2; \
	pxor %xmm6,%xmm0; \
	pxor %xmm2,%xmm3; \
	pand %xmm2,%xmm0; \
	pxor %xmm3,%xmm7; \
	por %xmm4,%xmm2; \
	pxor S2_x3,%xmm4; \
	pand %xmm3,%xmm6; \
	pxor %xmm0,%xmm4; \
	pxor %xmm5,%xmm6; \
	movdqa %xmm7,S2_x25; \
	pand %xmm3,%xmm0; \
	movdqa S2_a3,%xmm7; \
	pxor %xmm2,%xmm5; \
	pxor S2_x5,%xmm0; \
	pand %xmm4,%xmm7; \
	pand S2_a2,%xmm4; \
	pxor %xmm5,%xmm7; \
	por S2_a4,%xmm7; \
	movdqa %xmm1,%xmm5; \
	por S2_a3,%xmm5; \
	por %xmm2,%xmm1; \
	pand S2_x18,%xmm2; \
	pxor %xmm3,%xmm4; \
	movdqa S2_a4,%xmm3; \
	pand %xmm4,%xmm2; \
	pand S2_a3,%xmm4; \
	pxor %xmm5,%xmm0; \
	pxor S2_x25,%xmm7; \
	pxor %xmm6,%xmm4; \
	pxor out3,%xmm7; \
	pand %xmm3,%xmm1; \
	por %xmm3,%xmm2; \
	pxor out1,%xmm1; \
	pxor %xmm4,%xmm2; \
	pxor %xmm0,%xmm1; \
	pxor out4,%xmm2; \
	movdqa %xmm1,out1; \
	movdqa %xmm7,out3; \
	movdqa %xmm2,out4

#define S3_out1				%xmm2
#define S3_out2				%xmm6
#define S3_out3				%xmm3
#define S3_out4				%xmm7

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
	movdqa %xmm0,S3_a1; \
	extra; \
	movdqa %xmm4,%xmm0; \
	movdqa %xmm5,%xmm6; \
	pxor pnot,%xmm6; \
	movdqa %xmm4,%xmm7; \
	pxor %xmm6,%xmm7; \
	movdqa %xmm6,S3_x2; \
	pand %xmm2,%xmm0; \
	movdqa %xmm7,S3_x9; \
	pxor %xmm5,%xmm0; \
	movdqa %xmm4,S3_a5; \
	pandn %xmm3,%xmm4; \
	movdqa %xmm0,S3_x4; \
	por %xmm3,%xmm7; \
	movdqa S3_a5,%xmm6; \
	pxor %xmm4,%xmm0; \
	movdqa %xmm5,S3_a6; \
	pandn %xmm2,%xmm6; \
	movdqa %xmm0,S3_x6; \
	pxor %xmm6,%xmm7; \
	movdqa S3_x2,%xmm5; \
	pxor %xmm1,%xmm0; \
	movdqa %xmm4,S3_x5; \
	movdqa %xmm7,%xmm4; \
	por S3_x4,%xmm5; \
	pand %xmm0,%xmm4; \
	movdqa %xmm7,S3_x11; \
	pxor %xmm5,%xmm6; \
	pxor S3_a5,%xmm7; \
	por %xmm1,%xmm6; \
	movdqa %xmm4,S3_x12; \
	pand %xmm5,%xmm4; \
	movdqa %xmm7,S3_x13; \
	por %xmm0,%xmm7; \
	movdqa %xmm4,S3_x54; \
	movdqa %xmm2,%xmm4; \
	pxor S3_x9,%xmm4; \
	pand %xmm3,%xmm7; \
	movdqa %xmm0,S3_x7; \
	pxor %xmm3,%xmm4; \
	pxor S3_a6,%xmm5; \
	pxor %xmm4,%xmm6; \
	movdqa %xmm3,S3_a4; \
	por %xmm5,%xmm3; \
	movdqa %xmm2,S3_a3; \
	pxor %xmm3,%xmm5; \
	por %xmm1,%xmm5; \
	pxor %xmm7,%xmm2; \
	pxor S3_x12,%xmm7; \
	movdqa %xmm2,%xmm4; \
	por S3_x5,%xmm2; \
	pand %xmm1,%xmm7; \
	por S3_x4,%xmm4; \
	por %xmm1,%xmm2; \
	pxor S3_x11,%xmm7; \
	pxor %xmm3,%xmm2; \
	movdqa S3_a1,%xmm3; \
	pxor S3_a4,%xmm4; \
	pand %xmm3,%xmm7; \
	pxor S3_x7,%xmm7; \
	por %xmm3,%xmm2; \
	movdqa %xmm4,S3_x38; \
	pxor %xmm6,%xmm2; \
	pxor out4,%xmm7; \
	por %xmm1,%xmm4; \
	movdqa S3_a3,%xmm6; \
	movdqa %xmm2,%xmm3; \
	pxor S3_x9,%xmm6; \
	por S3_x5,%xmm6; \
	pxor S3_x38,%xmm3; \
	pxor %xmm6,%xmm4; \
	movdqa S3_a6,%xmm6; \
	pand S3_x11,%xmm6; \
	movdqa %xmm7,out4; \
	movdqa S3_x2,%xmm0; \
	pxor %xmm6,%xmm3; \
	por S3_x6,%xmm6; \
	pand %xmm1,%xmm3; \
	por S3_x38,%xmm0; \
	pxor %xmm6,%xmm3; \
	pxor S3_x13,%xmm0; \
	movdqa %xmm5,%xmm6; \
	por S3_a1,%xmm3; \
	pxor %xmm5,%xmm0; \
	pand S3_x54,%xmm6; \
	pxor %xmm4,%xmm3; \
	por S3_a1,%xmm6; \
	pxor out3,%xmm3; \
	pxor %xmm0,%xmm6; \
	pxor out1,%xmm2; \
	movdqa %xmm3,out3; \
	pxor out2,%xmm6; \
	movdqa %xmm2,out1; \
	movdqa %xmm6,out2

#define S4_out1				%xmm1
#define S4_out2				%xmm0
#define S4_out3				%xmm6
#define S4_out4				%xmm5

#define S4_a2				tmp_at(1)
#define S4_a3				tmp_at(2)
#define S4_a4				tmp_at(3)
#define S4_a6				tmp_at(4)

#define S4(out1, out2, out3, out4, extra) \
	movdqa %xmm2,%xmm6; \
	movdqa %xmm3,S4_a4; \
	movdqa %xmm0,%xmm7; \
	movdqa %xmm1,S4_a2; \
	por %xmm0,%xmm6; \
	extra; \
	pand %xmm4,%xmm7; \
	movdqa %xmm1,%xmm3; \
	movdqa %xmm5,S4_a6; \
	movdqa %xmm2,S4_a3; \
	movdqa %xmm4,%xmm5; \
	pand %xmm6,%xmm5; \
	por %xmm2,%xmm3; \
	pxor pnot,%xmm2; \
	pxor %xmm5,%xmm0; \
	pxor pnot,%xmm0; \
	pxor %xmm7,%xmm6; \
	pxor %xmm0,%xmm3; \
	movdqa %xmm1,%xmm7; \
	pand %xmm6,%xmm7; \
	pxor %xmm2,%xmm5; \
	pxor %xmm4,%xmm2; \
	pand %xmm5,%xmm0; \
	pxor %xmm7,%xmm4; \
	pand %xmm1,%xmm5; \
	por %xmm1,%xmm2; \
	pxor %xmm6,%xmm5; \
	movdqa S4_a4,%xmm1; \
	movdqa %xmm0,%xmm6; \
	pand %xmm4,%xmm1; \
	pxor %xmm2,%xmm6; \
	por S4_a4,%xmm6; \
	pxor %xmm3,%xmm1; \
	pand S4_a2,%xmm4; \
	pxor %xmm5,%xmm6; \
	movdqa S4_a6,%xmm3; \
	pxor %xmm0,%xmm4; \
	pxor S4_a3,%xmm7; \
	movdqa %xmm3,%xmm0; \
	pxor %xmm2,%xmm7; \
	pand %xmm6,%xmm0; \
	movdqa S4_a4,%xmm2; \
	por %xmm3,%xmm6; \
	pxor %xmm1,%xmm0; \
	pand %xmm2,%xmm7; \
	pxor pnot,%xmm1; \
	pxor %xmm7,%xmm4; \
	movdqa %xmm4,%xmm5; \
	pxor %xmm1,%xmm4; \
	pxor out1,%xmm1; \
	por %xmm4,%xmm2; \
	pand S4_a2,%xmm4; \
	pxor %xmm6,%xmm1; \
	pxor %xmm0,%xmm4; \
	pxor out3,%xmm6; \
	pxor %xmm4,%xmm2; \
	pxor out2,%xmm0; \
	pand %xmm2,%xmm3; \
	pxor %xmm2,%xmm6; \
	pxor %xmm3,%xmm5; \
	movdqa %xmm1,out1; \
	pxor %xmm5,%xmm6; \
	movdqa %xmm0,out2; \
	pxor out4,%xmm5; \
	movdqa %xmm6,out3; \
	movdqa %xmm5,out4

#define S5_out1				%xmm5
#define S5_out2				%xmm7
#define S5_out3				%xmm6
#define S5_out4				%xmm4

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
	movdqa %xmm1,S5_a2; \
	movdqa %xmm3,%xmm6; \
	movdqa %xmm2,%xmm7; \
	pandn %xmm2,%xmm6; \
	pandn %xmm0,%xmm7; \
	movdqa %xmm6,%xmm1; \
	movdqa %xmm0,S5_a1; \
	pxor %xmm0,%xmm1; \
	extra; \
	pxor %xmm3,%xmm0; \
	movdqa %xmm1,S5_x2; \
	movdqa %xmm5,S5_a6; \
	por %xmm0,%xmm6; \
	por %xmm7,%xmm5; \
	movdqa %xmm6,S5_x7; \
	pxor %xmm5,%xmm1; \
	movdqa %xmm5,S5_x4; \
	pand %xmm2,%xmm6; \
	movdqa S5_a6,%xmm5; \
	pxor %xmm3,%xmm6; \
	pandn S5_x7,%xmm5; \
	movdqa %xmm0,S5_x6; \
	movdqa %xmm7,%xmm0; \
	movdqa %xmm5,S5_x8; \
	pxor %xmm2,%xmm5; \
	movdqa %xmm1,S5_x5; \
	pxor %xmm3,%xmm0; \
	movdqa %xmm5,S5_x9; \
	pandn %xmm6,%xmm7; \
	por S5_a6,%xmm0; \
	por %xmm4,%xmm5; \
	movdqa %xmm6,S5_x13; \
	pxor %xmm1,%xmm5; \
	movdqa %xmm0,S5_x16; \
	pxor %xmm0,%xmm7; \
	movdqa S5_a2,%xmm0; \
	movdqa %xmm4,%xmm1; \
	movdqa %xmm7,S5_x17; \
	por %xmm7,%xmm1; \
	pand S5_x5,%xmm7; \
	pxor %xmm6,%xmm1; \
	pandn %xmm1,%xmm0; \
	movdqa %xmm7,%xmm6; \
	pandn S5_x7,%xmm6; \
	pxor %xmm0,%xmm5; \
	pxor S5_x9,%xmm7; \
	movdqa %xmm3,%xmm0; \
	movdqa %xmm5,S5_x21; \
	movdqa %xmm6,%xmm5; \
	pandn S5_x8,%xmm0; \
	pandn %xmm1,%xmm5; \
	pxor out3,%xmm6; \
	pxor %xmm2,%xmm0; \
	movdqa S5_a1,%xmm2; \
	movdqa %xmm0,%xmm1; \
	pxor S5_x9,%xmm2; \
	pand %xmm4,%xmm1; \
	movdqa %xmm7,S5_x38; \
	pxor %xmm1,%xmm6; \
	movdqa S5_x4,%xmm1; \
	movdqa %xmm2,%xmm7; \
	pand S5_x2,%xmm7; \
	pand %xmm3,%xmm1; \
	pxor S5_x17,%xmm1; \
	pandn %xmm4,%xmm7; \
	movdqa %xmm2,S5_x24; \
	pxor %xmm7,%xmm1; \
	movdqa out2,%xmm7; \
	por %xmm2,%xmm3; \
	movdqa S5_a2,%xmm2; \
	pxor %xmm1,%xmm7; \
	movdqa %xmm3,S5_x28; \
	pandn %xmm3,%xmm2; \
	movdqa S5_x38,%xmm3; \
	pxor %xmm2,%xmm7; \
	movdqa S5_x16,%xmm2; \
	por %xmm4,%xmm3; \
	por S5_x13,%xmm2; \
	por %xmm5,%xmm1; \
	pxor out1,%xmm5; \
	pxor %xmm3,%xmm2; \
	por S5_a2,%xmm2; \
	movdqa %xmm7,out2; \
	pxor S5_x6,%xmm1; \
	pxor %xmm2,%xmm6; \
	pandn %xmm4,%xmm1; \
	movdqa S5_x38,%xmm2; \
	pxor S5_x24,%xmm1; \
	movdqa %xmm2,%xmm3; \
	pxor S5_x21,%xmm2; \
	pxor %xmm1,%xmm5; \
	pand S5_x6,%xmm3; \
	pandn %xmm4,%xmm2; \
	pand S5_x28,%xmm2; \
	pxor %xmm0,%xmm3; \
	pxor pnot,%xmm6; \
	pxor %xmm2,%xmm3; \
	movdqa S5_x21,%xmm4; \
	por S5_a2,%xmm3; \
	movdqa %xmm6,out3; \
	pxor out4,%xmm4; \
	pxor %xmm3,%xmm5; \
	movdqa %xmm4,out4; \
	movdqa %xmm5,out1

#define S6_out1				%xmm0
#undef S6_out2
#define S6_out3				%xmm2
#define S6_out4				%xmm4

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
	movdqa %xmm2,S6_a3; \
	extra; \
	movdqa %xmm4,%xmm6; \
	pxor pnot,%xmm6; \
	movdqa %xmm5,%xmm7; \
	movdqa %xmm1,S6_a2; \
	movdqa %xmm4,%xmm2; \
	movdqa %xmm3,S6_a4; \
	pxor %xmm1,%xmm7; \
	pxor pnot,%xmm1; \
	pxor %xmm6,%xmm7; \
	movdqa %xmm6,S6_x2; \
	pxor %xmm0,%xmm7; \
	pand %xmm5,%xmm2; \
	movdqa %xmm4,%xmm6; \
	movdqa %xmm1,S6_x1; \
	movdqa %xmm5,%xmm3; \
	pand S6_a2,%xmm3; \
	pand %xmm7,%xmm6; \
	movdqa %xmm0,S6_a1; \
	por %xmm2,%xmm1; \
	movdqa %xmm2,S6_x6; \
	pand %xmm6,%xmm0; \
	movdqa %xmm3,S6_x15; \
	pxor %xmm0,%xmm1; \
	movdqa S6_a4,%xmm0; \
	movdqa %xmm4,%xmm2; \
	movdqa %xmm6,S6_x8; \
	pand %xmm1,%xmm0; \
	movdqa %xmm7,S6_x5; \
	pxor %xmm3,%xmm2; \
	movdqa S6_x2,%xmm6; \
	pxor %xmm7,%xmm0; \
	movdqa S6_a1,%xmm7; \
	pxor %xmm5,%xmm1; \
	movdqa %xmm2,S6_x16; \
	pand %xmm7,%xmm2; \
	movdqa S6_a4,%xmm3; \
	pxor %xmm2,%xmm6; \
	pxor S6_a2,%xmm2; \
	pand %xmm7,%xmm1; \
	por %xmm6,%xmm3; \
	pxor %xmm5,%xmm6; \
	pxor %xmm3,%xmm1; \
	pand %xmm6,%xmm7; \
	pand S6_a3,%xmm1; \
	pand %xmm4,%xmm6; \
	movdqa S6_x6,%xmm3; \
	pxor %xmm1,%xmm0; \
	pxor out2,%xmm0; \
	por %xmm2,%xmm3; \
	pand S6_a4,%xmm3; \
	pxor %xmm7,%xmm4; \
	movdqa S6_x5,%xmm1; \
	pxor %xmm3,%xmm4; \
	pxor pnot,%xmm2; \
	por %xmm4,%xmm5; \
	movdqa %xmm0,out2; \
	movdqa %xmm5,%xmm3; \
	pandn S6_a4,%xmm3; \
	pxor %xmm6,%xmm1; \
	movdqa S6_x6,%xmm0; \
	pxor %xmm2,%xmm3; \
	por S6_a4,%xmm1; \
	pxor %xmm3,%xmm0; \
	pand S6_a3,%xmm3; \
	pxor %xmm1,%xmm0; \
	por S6_x5,%xmm6; \
	movdqa %xmm7,%xmm1; \
	pxor S6_x15,%xmm7; \
	pxor %xmm3,%xmm4; \
	movdqa S6_a4,%xmm3; \
	pxor %xmm5,%xmm7; \
	pand S6_x8,%xmm5; \
	por %xmm3,%xmm7; \
	pxor S6_x6,%xmm6; \
	por %xmm3,%xmm5; \
	por S6_x16,%xmm1; \
	pxor %xmm6,%xmm5; \
	pxor S6_x1,%xmm1; \
	movdqa S6_a3,%xmm3; \
	pxor %xmm1,%xmm7; \
	pxor out4,%xmm4; \
	por %xmm3,%xmm7; \
	pand %xmm1,%xmm2; \
	pxor out1,%xmm0; \
	por %xmm3,%xmm2; \
	pxor %xmm7,%xmm0; \
	pxor %xmm5,%xmm2; \
	movdqa %xmm4,out4; \
	pxor out3,%xmm2; \
	movdqa %xmm0,out1; \
	movdqa %xmm2,out3

#define S7_out1				%xmm7
#define S7_out2				%xmm1
#define S7_out3				%xmm3
#define S7_out4				%xmm0

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
	movdqa %xmm0,S7_a1; \
	movdqa %xmm1,%xmm6; \
	extra; \
	movdqa %xmm1,S7_a2; \
	movdqa %xmm3,%xmm7; \
	movdqa %xmm5,S7_a6; \
	pand %xmm3,%xmm6; \
	movdqa %xmm3,S7_a4; \
	pxor %xmm4,%xmm6; \
	pxor pnot,%xmm4; \
	pand %xmm6,%xmm7; \
	pand %xmm4,%xmm3; \
	movdqa %xmm1,%xmm5; \
	pxor %xmm2,%xmm6; \
	pxor %xmm7,%xmm5; \
	movdqa %xmm7,S7_x6; \
	por %xmm1,%xmm4; \
	por %xmm3,%xmm1; \
	pxor %xmm6,%xmm7; \
	movdqa %xmm5,S7_x7; \
	pand %xmm2,%xmm4; \
	pand %xmm2,%xmm5; \
	por %xmm7,%xmm3; \
	movdqa %xmm1,S7_x13; \
	pxor %xmm5,%xmm0; \
	por S7_a6,%xmm0; \
	pxor %xmm4,%xmm1; \
	movdqa %xmm4,S7_x15; \
	pxor %xmm6,%xmm0; \
	movdqa %xmm5,S7_x8; \
	movdqa %xmm3,%xmm4; \
	movdqa S7_a6,%xmm6; \
	movdqa %xmm0,%xmm5; \
	pxor S7_x6,%xmm5; \
	por %xmm6,%xmm4; \
	movdqa %xmm7,S7_x25; \
	por %xmm6,%xmm5; \
	movdqa S7_a1,%xmm7; \
	pxor %xmm1,%xmm5; \
	movdqa %xmm3,S7_x26; \
	pand %xmm5,%xmm7; \
	movdqa %xmm0,S7_x11; \
	pxor %xmm0,%xmm7; \
	movdqa S7_a4,%xmm3; \
	movdqa %xmm7,%xmm0; \
	por S7_a2,%xmm0; \
	pand %xmm3,%xmm1; \
	pand S7_x13,%xmm3; \
	por S7_x7,%xmm2; \
	pxor S7_x6,%xmm0; \
	pxor %xmm3,%xmm2; \
	movdqa S7_a2,%xmm3; \
	movdqa %xmm0,%xmm6; \
	pxor pnot,%xmm3; \
	pxor S7_x15,%xmm6; \
	por %xmm3,%xmm1; \
	pand S7_x26,%xmm0; \
	pxor %xmm6,%xmm4; \
	pand S7_a6,%xmm0; \
	por %xmm3,%xmm6; \
	por S7_a6,%xmm6; \
	pand %xmm5,%xmm3; \
	pand S7_a6,%xmm1; \
	pxor %xmm3,%xmm0; \
	por S7_a1,%xmm0; \
	pxor %xmm6,%xmm2; \
	pxor S7_x11,%xmm1; \
	pxor %xmm4,%xmm0; \
	movdqa S7_a1,%xmm4; \
	pxor %xmm2,%xmm5; \
	movdqa S7_a4,%xmm6; \
	por %xmm2,%xmm4; \
	pxor S7_x25,%xmm6; \
	pxor %xmm4,%xmm1; \
	movdqa S7_a6,%xmm4; \
	pand %xmm1,%xmm6; \
	movdqa S7_x6,%xmm3; \
	pand %xmm4,%xmm6; \
	pxor S7_x15,%xmm3; \
	pxor %xmm5,%xmm6; \
	pxor S7_x8,%xmm2; \
	por %xmm4,%xmm3; \
	por S7_a1,%xmm6; \
	pxor %xmm2,%xmm3; \
	pxor out1,%xmm7; \
	pxor %xmm6,%xmm3; \
	pxor out2,%xmm1; \
	movdqa %xmm7,out1; \
	pxor out3,%xmm3; \
	movdqa %xmm1,out2; \
	pxor out4,%xmm0; \
	movdqa %xmm3,out3; \
	movdqa %xmm0,out4

#define S8_out1				%xmm6
#define S8_out2				%xmm2
#define S8_out3				%xmm5
#define S8_out4				%xmm1

#define S8_a1				tmp_at(1)
#define S8_a2				tmp_at(2)
#define S8_a4				tmp_at(3)
#define S8_a5				tmp_at(4)
#define S8_a6				tmp_at(5)
#define S8_x14				tmp_at(6)
#define S8_x22				tmp_at(7)
#define S8_x33				tmp_at(8)

#define S8(out1, out2, out3, out4, extra) \
	movdqa %xmm0,S8_a1; \
	extra; \
	movdqa %xmm2,%xmm6; \
	pxor pnot,%xmm0; \
	movdqa %xmm2,%xmm7; \
	movdqa %xmm3,S8_a4; \
	por %xmm0,%xmm7; \
	pxor pnot,%xmm3; \
	pxor %xmm0,%xmm6; \
	movdqa %xmm5,S8_a6; \
	movdqa %xmm4,%xmm5; \
	movdqa %xmm1,S8_a2; \
	movdqa %xmm7,%xmm1; \
	movdqa %xmm4,S8_a5; \
	pxor %xmm3,%xmm7; \
	por %xmm6,%xmm5; \
	por %xmm7,%xmm0; \
	pand %xmm4,%xmm1; \
	pandn %xmm0,%xmm2; \
	por %xmm7,%xmm4; \
	pxor %xmm1,%xmm2; \
	movdqa %xmm5,S8_x22; \
	pand %xmm3,%xmm5; \
	por S8_a2,%xmm2; \
	pxor %xmm4,%xmm7; \
	pxor %xmm0,%xmm3; \
	movdqa %xmm4,%xmm1; \
	pxor S8_x22,%xmm7; \
	pxor %xmm3,%xmm1; \
	pxor %xmm6,%xmm4; \
	pxor %xmm5,%xmm2; \
	pxor S8_a1,%xmm5; \
	pand %xmm3,%xmm6; \
	movdqa %xmm1,S8_x14; \
	pand %xmm4,%xmm5; \
	movdqa %xmm7,S8_x33; \
	movdqa %xmm0,%xmm1; \
	pand S8_a5,%xmm3; \
	movdqa %xmm0,%xmm7; \
	pand S8_a5,%xmm1; \
	pxor %xmm3,%xmm7; \
	pand S8_a2,%xmm7; \
	pxor %xmm1,%xmm6; \
	movdqa S8_a6,%xmm1; \
	pxor %xmm4,%xmm7; \
	por S8_a2,%xmm6; \
	pandn %xmm0,%xmm4; \
	pxor S8_x14,%xmm6; \
	pand %xmm2,%xmm1; \
	pxor S8_a1,%xmm3; \
	pxor %xmm6,%xmm2; \
	por S8_a6,%xmm6; \
	pxor %xmm7,%xmm1; \
	pxor S8_x22,%xmm3; \
	pxor %xmm7,%xmm6; \
	por S8_a2,%xmm4; \
	pand S8_a2,%xmm5; \
	pxor %xmm4,%xmm3; \
	movdqa S8_a1,%xmm4; \
	pand S8_x33,%xmm4; \
	por S8_a4,%xmm7; \
	pxor %xmm4,%xmm0; \
	pand S8_a2,%xmm7; \
	pxor %xmm0,%xmm5; \
	movdqa S8_a6,%xmm4; \
	por %xmm0,%xmm2; \
	pxor S8_x33,%xmm7; \
	por %xmm4,%xmm5; \
	pxor out1,%xmm6; \
	pand %xmm4,%xmm2; \
	pxor out4,%xmm1; \
	pxor %xmm7,%xmm5; \
	pxor %xmm3,%xmm2; \
	pxor out3,%xmm5; \
	movdqa %xmm6,out1; \
	pxor out2,%xmm2; \
	movdqa %xmm1,out4; \
	movdqa %xmm5,out3; \
	movdqa %xmm2,out2

#define zero				%xmm0

#define DES_bs_clear_block_8(i) \
	movdqa zero,B(i); \
	movdqa zero,B(i + 1); \
	movdqa zero,B(i + 2); \
	movdqa zero,B(i + 3); \
	movdqa zero,B(i + 4); \
	movdqa zero,B(i + 5); \
	movdqa zero,B(i + 6); \
	movdqa zero,B(i + 7)

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
#define K(i)				nvec(i)(k_ptr)
#define k(i)				nptr(i)(k_ptr)

#define a6_xor_ptr			%esi
#define a6_p				pxor (a6_xor_ptr),a6
#define a6_v(i)				pxor K(i),a6

#define tmp1				%ecx
#define tmp2				a6_xor_ptr

#define xor_E(i) \
	movl E(i),tmp1; \
	movdqa K(i),a1; \
	movl E(i + 1),tmp2; \
	movdqa K(i + 1),a2; \
	pxor (tmp1),a1; \
	pxor (tmp2),a2; \
	movl E(i + 2),tmp1; \
	movdqa K(i + 2),a3; \
	movl E(i + 3),tmp2; \
	movdqa K(i + 3),a4; \
	pxor (tmp1),a3; \
	pxor (tmp2),a4; \
	movl E(i + 4),tmp1; \
	movdqa K(i + 4),a5; \
	movl E(i + 5),a6_xor_ptr; \
	movdqa K(i + 5),a6; \
	pxor (tmp1),a5

#define xor_B(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6) \
	movdqa B(b1),a1; \
	movdqa B(b2),a2; \
	pxor K(k1),a1; \
	movdqa B(b3),a3; \
	pxor K(k2),a2; \
	movdqa B(b4),a4; \
	pxor K(k3),a3; \
	movdqa B(b5),a5; \
	pxor K(k4),a4; \
	movdqa B(b6),a6; \
	pxor K(k5),a5

#define xor_B_KS_p(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6, k6) \
	movl k(k1),tmp1; \
	movl k(k2),tmp2; \
	movdqa B(b1),a1; \
	movdqa B(b2),a2; \
	pxor (tmp1),a1; \
	movl k(k3),tmp1; \
	pxor (tmp2),a2; \
	movl k(k4),tmp2; \
	movdqa B(b3),a3; \
	movdqa B(b4),a4; \
	pxor (tmp1),a3; \
	movl k(k5),tmp1; \
	pxor (tmp2),a4; \
	movdqa B(b5),a5; \
	movl k(k6),a6_xor_ptr; \
	movdqa B(b6),a6; \
	pxor (tmp1),a5

.text

DO_ALIGN(5)
.globl DES_bs_init_asm
DES_bs_init_asm:
	pcmpeqd %xmm0,%xmm0
	movdqa %xmm0,pnot
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
	addl $nvec(96),k_ptr
	S8(B(4), B(26), B(14), B(20), a6_p)
	decl rounds_and_swapped
	jnz DES_bs_crypt_start
	subl $nvec(0x300+48),k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_swap
	popl %esi
	popl %ebp
	ret
DES_bs_crypt_next:
	subl $nvec(0x300-48),k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_start
	popl %esi
	popl %ebp
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
	addl $nvec(96),k_ptr
	decl rounds_and_swapped
	jnz DES_bs_crypt_25_start
	subl $nvec(0x300+48),k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_25_swap
	popl %esi
	popl %ebp
	ret
DES_bs_crypt_25_next:
	subl $nvec(0x300-48),k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jmp DES_bs_crypt_25_start

#define ones				%xmm1

#define rounds				%eax

DO_ALIGN(5)
.globl DES_bs_crypt_LM
DES_bs_crypt_LM:
	pxor zero,zero
	pushl %esi
	pcmpeqd ones,ones
	movl $DES_bs_all_KS_p,k_ptr
	movdqa zero,B(0)
	movdqa zero,B(1)
	movdqa zero,B(2)
	movdqa zero,B(3)
	movdqa zero,B(4)
	movdqa zero,B(5)
	movdqa zero,B(6)
	movdqa zero,B(7)
	movdqa ones,B(8)
	movdqa ones,B(9)
	movdqa ones,B(10)
	movdqa zero,B(11)
	movdqa ones,B(12)
	movdqa zero,B(13)
	movdqa zero,B(14)
	movdqa zero,B(15)
	movdqa zero,B(16)
	movdqa zero,B(17)
	movdqa zero,B(18)
	movdqa zero,B(19)
	movdqa zero,B(20)
	movdqa zero,B(21)
	movdqa zero,B(22)
	movdqa ones,B(23)
	movdqa zero,B(24)
	movdqa zero,B(25)
	movdqa ones,B(26)
	movdqa zero,B(27)
	movdqa zero,B(28)
	movdqa ones,B(29)
	movdqa ones,B(30)
	movdqa ones,B(31)
	movdqa zero,B(32)
	movdqa zero,B(33)
	movdqa zero,B(34)
	movdqa ones,B(35)
	movdqa zero,B(36)
	movdqa ones,B(37)
	movdqa ones,B(38)
	movdqa ones,B(39)
	movdqa zero,B(40)
	movdqa zero,B(41)
	movdqa zero,B(42)
	movdqa zero,B(43)
	movdqa zero,B(44)
	movdqa ones,B(45)
	movdqa zero,B(46)
	movdqa zero,B(47)
	movdqa ones,B(48)
	movdqa ones,B(49)
	movdqa zero,B(50)
	movdqa zero,B(51)
	movdqa zero,B(52)
	movdqa zero,B(53)
	movdqa ones,B(54)
	movdqa zero,B(55)
	movdqa ones,B(56)
	movdqa zero,B(57)
	movdqa ones,B(58)
	movdqa zero,B(59)
	movdqa ones,B(60)
	movdqa ones,B(61)
	movdqa ones,B(62)
	movdqa ones,B(63)
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
	addl $nptr(96),k_ptr
	S8(B(4), B(26), B(14), B(20), a6_p)
	decl rounds
	jnz DES_bs_crypt_LM_loop
	popl %esi
	ret

#endif


/* The following was written by Alain Espinosa <alainesp at gmail.com> in 2007.
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2007 Alain Espinosa and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

/*
 * FIXME: this depends on the assembler being able to multiply, which won't
 * work on Solaris (unless the use of GNU assembler is forced).
 */

#ifdef UNDERSCORES
#define nt_crypt_all_sse2 _nt_crypt_all_sse2
#define nt_buffer1x _nt_buffer1x
#define nt_buffer4x _nt_buffer4x
#define output1x _output1x
#define output4x _output4x
#endif

/*
extern nt_crypt_all_sse2(int count);
*/

.globl nt_crypt_all_sse2

.data
DO_ALIGN(6)
const_init_a:
.long 0xFFFFFFFF
.long 0xFFFFFFFF
.long 0xFFFFFFFF
.long 0xFFFFFFFF
const_init_b:
.long 0xefcdab89
.long 0xefcdab89
.long 0xefcdab89
.long 0xefcdab89
const_init_c:
.long 0x98badcfe
.long 0x98badcfe
.long 0x98badcfe
.long 0x98badcfe
const_init_d:
.long 0x10325476
.long 0x10325476
.long 0x10325476
.long 0x10325476

const_stage2:
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999
.long 0x5a827999
const_stage3:
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1
.long 0x6ed9eba1

#define a  %xmm0
#define b  %xmm1
#define c  %xmm2
#define d  %xmm3
#define t1 %xmm4
#define t2 %xmm5
#define t3 %xmm6
#define t4 %xmm7

#undef a3
#define a3  %eax
#define b3  %ebx
#define c3  %ecx
#define d3  %edx
#define t13 %esi
#define t23 %edi
#define Q2 $0x5a827999
#define Q3 $0x6ed9eba1

#define STEP1(aa, bb, cc, dd, aa3, bb3, cc3, dd3, x, s, base)	\
	paddd (256*base)+(x*16)+nt_buffer4x, aa;		\
	addl (64*base)+(x*4)+nt_buffer1x, aa3;			\
	movdqa cc, t1;						\
	movl cc3, t13;						\
	pxor dd, t1;						\
	xorl dd3, t13;						\
	pand bb, t1;						\
	andl bb3, t13;						\
	pxor dd, t1;						\
	xorl dd3, t13;						\
	paddd t1, aa;						\
	addl t13, aa3;						\
	movdqa aa, t2;						\
	roll $s, aa3;						\
	pslld $s, aa;						\
	psrld $(32-s), t2;					\
	por t2, aa;

#define STEP2(aa, bb, cc, dd, aa3, bb3, cc3, dd3, x, s, base)	\
	paddd (256*base)+(x*16)+nt_buffer4x, aa;		\
	addl (64*base)+(x*4)+nt_buffer1x, aa3;			\
	movdqa cc, t1;						\
	movl cc3, t13;						\
	movdqa cc, t2;						\
	movl cc3, t23;						\
	por dd, t1;						\
	orl dd3, t13;						\
	pand dd, t2;						\
	andl dd3, t23;						\
	pand bb, t1;						\
	andl bb3, t13;						\
	paddd t3, aa;						\
	addl Q2, aa3;						\
	por t2, t1;						\
	orl t23, t13;						\
	paddd t1, aa;						\
	addl t13, aa3;						\
	movdqa aa, t1;						\
	roll $s, aa3;						\
	pslld $s, aa;						\
	psrld $(32-s), t1;					\
	por t1, aa;

#define STEP3(aa, bb, cc, dd, aa3, bb3, cc3, dd3, x, s, base)	\
	paddd (256*base)+(x*16)+nt_buffer4x, aa;		\
	addl (64*base)+(x*4)+nt_buffer1x, aa3;			\
	movdqa dd, t1;						\
	movl dd3, t13;						\
	pxor cc, t1;						\
	xorl cc3, t13;						\
	paddd t4, aa;						\
	addl Q3, aa3;						\
	pxor bb, t1;						\
	xorl bb3, t13;						\
	paddd t1, aa;						\
	addl t13, aa3;						\
	movdqa aa, t1;						\
	roll $s, aa3;						\
	pslld $s, aa;						\
	psrld $(32-s), t1;					\
	por t1, aa;

#define NT_CRYPT_BODY(base)					\
	movdqa const_init_a, a;					\
	movl const_init_a, a3;					\
	movdqa const_init_b, b;					\
	movl const_init_b, b3;					\
	movdqa const_init_c, c;					\
	movl const_init_c, c3;					\
	movdqa const_init_d, d;					\
	movl const_init_d, d3;					\
								\
	paddd (256*base)+nt_buffer4x, a;			\
	addl (64*base)+nt_buffer1x, a3;				\
	pslld $3, a;						\
	roll $3, a3;						\
								\
	STEP1(d, a, b, c, d3, a3, b3, c3, 1 , 7 , base)		\
	STEP1(c, d, a, b, c3, d3, a3, b3, 2 , 11, base)		\
	STEP1(b, c, d, a, b3, c3, d3, a3, 3 , 19, base)		\
	STEP1(a, b, c, d, a3, b3, c3, d3, 4 , 3 , base)		\
	STEP1(d, a, b, c, d3, a3, b3, c3, 5 , 7 , base)		\
	STEP1(c, d, a, b, c3, d3, a3, b3, 6 , 11, base)		\
	STEP1(b, c, d, a, b3, c3, d3, a3, 7 , 19, base)		\
	STEP1(a, b, c, d, a3, b3, c3, d3, 8 , 3 , base)		\
	STEP1(d, a, b, c, d3, a3, b3, c3, 9 , 7 , base)		\
	STEP1(c, d, a, b, c3, d3, a3, b3, 10, 11, base)		\
	STEP1(b, c, d, a, b3, c3, d3, a3, 11, 19, base)		\
	STEP1(a, b, c, d, a3, b3, c3, d3, 12, 3 , base)		\
	STEP1(d, a, b, c, d3, a3, b3, c3, 13, 7 , base)		\
	STEP1(c, d, a, b, c3, d3, a3, b3, 14, 11, base)		\
	STEP1(b, c, d, a, b3, c3, d3, a3, 15, 19, base)		\
								\
	STEP2(a, b, c, d, a3, b3, c3, d3, 0 , 3 , base)		\
	STEP2(d, a, b, c, d3, a3, b3, c3, 4 , 5 , base)		\
	STEP2(c, d, a, b, c3, d3, a3, b3, 8 , 9 , base)		\
	STEP2(b, c, d, a, b3, c3, d3, a3, 12, 13, base)		\
	STEP2(a, b, c, d, a3, b3, c3, d3, 1 , 3 , base)		\
	STEP2(d, a, b, c, d3, a3, b3, c3, 5 , 5 , base)		\
	STEP2(c, d, a, b, c3, d3, a3, b3, 9 , 9 , base)		\
	STEP2(b, c, d, a, b3, c3, d3, a3, 13, 13, base)		\
	STEP2(a, b, c, d, a3, b3, c3, d3, 2 , 3 , base)		\
	STEP2(d, a, b, c, d3, a3, b3, c3, 6 , 5 , base)		\
	STEP2(c, d, a, b, c3, d3, a3, b3, 10, 9 , base)		\
	STEP2(b, c, d, a, b3, c3, d3, a3, 14, 13, base)		\
	STEP2(a, b, c, d, a3, b3, c3, d3, 3 , 3 , base)		\
	STEP2(d, a, b, c, d3, a3, b3, c3, 7 , 5 , base)		\
	STEP2(c, d, a, b, c3, d3, a3, b3, 11, 9 , base)		\
	STEP2(b, c, d, a, b3, c3, d3, a3, 15, 13, base)		\
								\
	STEP3(a, b, c, d, a3, b3, c3, d3, 0 , 3 , base)		\
	STEP3(d, a, b, c, d3, a3, b3, c3, 8 , 9 , base)		\
	STEP3(c, d, a, b, c3, d3, a3, b3, 4 , 11, base)		\
	STEP3(b, c, d, a, b3, c3, d3, a3, 12, 15, base)		\
	STEP3(a, b, c, d, a3, b3, c3, d3, 2 , 3 , base)		\
	STEP3(d, a, b, c, d3, a3, b3, c3, 10, 9 , base)		\
	STEP3(c, d, a, b, c3, d3, a3, b3, 6 , 11, base)		\
	STEP3(b, c, d, a, b3, c3, d3, a3, 14, 15, base)		\
	STEP3(a, b, c, d, a3, b3, c3, d3, 1 , 3 , base)		\
	STEP3(d, a, b, c, d3, a3, b3, c3, 9 , 9 , base)		\
	STEP3(c, d, a, b, c3, d3, a3, b3, 5 , 11, base)		\
	movdqa a, t1;						\
	movl a3, t13;						\
	paddd (256*base)+208+nt_buffer4x, b;			\
	addl (64*base)+52+nt_buffer1x, b3;			\
	pxor d, t1;						\
	xorl d3,t13;						\
	pxor c, t1;						\
	xorl c3,t13;						\
	paddd t1, b;						\
	addl t13,b3;						\
								\
	movdqa a,  (64*base)+output4x;				\
	movl a3,  (16*base)+output1x;				\
	movdqa b, (64*base)+16+output4x;			\
	movl b3,  (16*base)+4+output1x;				\
	movdqa c, (64*base)+32+output4x;			\
	movl c3,  (16*base)+8+output1x;				\
	movdqa d, (64*base)+48+output4x;			\
	movl d3,  (16*base)+12+output1x;

.text

DO_ALIGN(6)

nt_crypt_all_sse2:
	pusha

	movdqa const_stage2, t3
	movdqa const_stage3, t4

	NT_CRYPT_BODY(0)
	NT_CRYPT_BODY(1)
	NT_CRYPT_BODY(2)
	NT_CRYPT_BODY(3)
	NT_CRYPT_BODY(4)
	NT_CRYPT_BODY(5)
	NT_CRYPT_BODY(6)
	NT_CRYPT_BODY(7)

	popa

	ret

#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",@progbits
#endif
