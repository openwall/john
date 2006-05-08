/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2000-2001,2005,2006 by Solar Designer and others:
 *
 * The MMX DES S-box code that this SSE DES S-box code is derived from is
 * by Bruce Ford and Rémi Guyomarch, originally for use in the
 * distributed.net clients, included here with permission.  Only minor
 * modifications have been made to their S-box code.  The optimized S-box
 * expressions are based on work by Matthew Kwan (see nonstd.c).
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
 * while for the SSE code we need at least an 16 byte alignment.  ALIGN_FIX
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
#define DO_ALIGN(log)			.align (log); .space ALIGN_FIX
#else
#define DO_ALIGN(log)			.align (1 << (log)); .space ALIGN_FIX
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
.space (0x300 * 16)
DES_bs_all_E:
.space (96 * 4)
DES_bs_all_K:
.space (56 * 16)
DES_bs_all_B:
.space (64 * 16)
DES_bs_all_tmp:
.space (16 * 16)
DES_bs_all_fields_not_used_here:
.space (0x400 + 0x100 + 4 + 4 + 128 * 8)
DES_bs_all_possible_alignment_gaps:
.space 0x100

#define E(i)				DES_bs_all_E+(i)*4
#define B(i)				DES_bs_all_B+(i)*16
#define tmp_at(i)			DES_bs_all_tmp+(i)*16

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
	movaps %xmm0,S1_a1; \
	movaps %xmm3,%xmm6; \
	xorps pnot,%xmm0; \
	xorps %xmm2,%xmm3; \
	xorps pnot,%xmm6; \
	movaps %xmm0,%xmm7; \
	extra; \
	movaps %xmm4,S1_a5; \
	orps %xmm2,%xmm7; \
	movaps %xmm3,S1_x3; \
	movaps %xmm5,%xmm4; \
	movaps %xmm6,S1_x1; \
	xorps %xmm0,%xmm3; \
	movaps %xmm7,S1_x5; \
	orps %xmm6,%xmm0; \
	movaps %xmm2,S1_a3; \
	andps %xmm6,%xmm7; \
	movaps %xmm3,S1_x4; \
	orps %xmm3,%xmm2; \
	xorps pnot,%xmm2; \
	andps %xmm0,%xmm4; \
	movaps %xmm7,%xmm6; \
	orps %xmm5,%xmm2; \
	movaps %xmm7,S1_x6; \
	orps %xmm5,%xmm6; \
	xorps %xmm2,%xmm7; \
	xorps %xmm6,%xmm3; \
	movaps %xmm2,S1_x25; \
	xorps %xmm4,%xmm6; \
	andps S1_a3,%xmm4; \
	movaps %xmm6,%xmm2; \
	xorps S1_a3,%xmm6; \
	orps %xmm1,%xmm2; \
	andps S1_x5,%xmm6; \
	xorps %xmm3,%xmm2; \
	movaps %xmm4,S1_x38; \
	xorps %xmm2,%xmm0; \
	movaps %xmm7,S1_x26; \
	movaps %xmm5,%xmm4; \
	movaps %xmm2,S1_x13; \
	orps %xmm0,%xmm4; \
	movaps S1_x1,%xmm7; \
	orps %xmm1,%xmm6; \
	movaps %xmm0,S1_x14; \
	movaps %xmm3,%xmm2; \
	andnps S1_x3,%xmm0; \
	xorps %xmm7,%xmm4; \
	orps S1_x4,%xmm5; \
	orps %xmm1,%xmm0; \
	xorps S1_x38,%xmm5; \
	xorps %xmm0,%xmm4; \
	movaps S1_a5,%xmm0; \
	andps %xmm7,%xmm2; \
	movaps %xmm6,S1_x55; \
	orps %xmm1,%xmm2; \
	movaps S1_x14,%xmm6; \
	orps %xmm4,%xmm0; \
	andps S1_x5,%xmm6; \
	orps %xmm3,%xmm7; \
	movaps %xmm5,S1_x58; \
	xorps %xmm3,%xmm6; \
	xorps S1_x6,%xmm7; \
	movaps %xmm1,%xmm5; \
	xorps S1_x26,%xmm2; \
	andps %xmm6,%xmm5; \
	andps S1_a3,%xmm6; \
	xorps %xmm7,%xmm5; \
	orps S1_a5,%xmm5; \
	movaps S1_a1,%xmm7; \
	xorps %xmm2,%xmm5; \
	movaps S1_x4,%xmm2; \
	orps %xmm3,%xmm7; \
	orps S1_x38,%xmm2; \
	xorps %xmm6,%xmm3; \
	xorps S1_x25,%xmm6; \
	xorps %xmm4,%xmm7; \
	movaps S1_a3,%xmm4; \
	orps %xmm1,%xmm7; \
	orps S1_x26,%xmm4; \
	orps %xmm1,%xmm6; \
	xorps S1_x14,%xmm4; \
	xorps %xmm2,%xmm6; \
	movaps S1_x13,%xmm2; \
	xorps %xmm4,%xmm7; \
	xorps S1_x55,%xmm3; \
	xorps %xmm2,%xmm0; \
	xorps out1,%xmm5; \
	andps %xmm3,%xmm2; \
	movaps S1_a5,%xmm4; \
	andps %xmm1,%xmm2; \
	movaps %xmm5,out1; \
	xorps S1_x58,%xmm2; \
	andps %xmm4,%xmm7; \
	xorps out4,%xmm0; \
	andps %xmm4,%xmm2; \
	xorps out2,%xmm7; \
	movaps %xmm0,out4; \
	xorps out3,%xmm2; \
	xorps %xmm6,%xmm7; \
	xorps %xmm3,%xmm2; \
	movaps %xmm7,out2; \
	movaps %xmm2,out3

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
	movaps %xmm3,S2_a4; \
	movaps %xmm4,%xmm6; \
	extra; \
	movaps %xmm0,S2_a1; \
	movaps %xmm4,%xmm7; \
	xorps pnot,%xmm0; \
	xorps %xmm5,%xmm6; \
	xorps pnot,%xmm7; \
	movaps %xmm0,%xmm3; \
	movaps %xmm2,S2_a3; \
	orps %xmm5,%xmm7; \
	movaps %xmm6,S2_x3; \
	orps %xmm7,%xmm3; \
	xorps %xmm4,%xmm7; \
	xorps %xmm0,%xmm6; \
	andps %xmm1,%xmm3; \
	orps %xmm7,%xmm2; \
	movaps %xmm1,S2_a2; \
	xorps %xmm5,%xmm3; \
	movaps %xmm6,S2_x4; \
	xorps %xmm1,%xmm6; \
	movaps %xmm7,S2_x13; \
	andps %xmm3,%xmm1; \
	andps S2_a3,%xmm3; \
	xorps %xmm2,%xmm1; \
	movaps S2_x4,%xmm7; \
	movaps %xmm1,%xmm2; \
	andps S2_a4,%xmm2; \
	xorps %xmm6,%xmm3; \
	movaps %xmm6,S2_x5; \
	xorps %xmm2,%xmm3; \
	movaps S2_a1,%xmm2; \
	orps %xmm5,%xmm7; \
	orps %xmm2,%xmm1; \
	andps %xmm3,%xmm7; \
	xorps out2,%xmm3; \
	orps %xmm4,%xmm2; \
	orps S2_a3,%xmm7; \
	movaps %xmm2,%xmm6; \
	xorps S2_x13,%xmm1; \
	orps %xmm5,%xmm6; \
	movaps %xmm3,out2; \
	andps %xmm0,%xmm4; \
	movaps S2_x13,%xmm3; \
	orps %xmm0,%xmm5; \
	movaps %xmm2,S2_x18; \
	xorps %xmm6,%xmm3; \
	movaps S2_a2,%xmm2; \
	xorps %xmm6,%xmm0; \
	xorps %xmm2,%xmm3; \
	andps %xmm2,%xmm0; \
	xorps %xmm3,%xmm7; \
	orps %xmm4,%xmm2; \
	xorps S2_x3,%xmm4; \
	andps %xmm3,%xmm6; \
	xorps %xmm0,%xmm4; \
	xorps %xmm5,%xmm6; \
	movaps %xmm7,S2_x25; \
	andps %xmm3,%xmm0; \
	movaps S2_a3,%xmm7; \
	xorps %xmm2,%xmm5; \
	xorps S2_x5,%xmm0; \
	andps %xmm4,%xmm7; \
	andps S2_a2,%xmm4; \
	xorps %xmm5,%xmm7; \
	orps S2_a4,%xmm7; \
	movaps %xmm1,%xmm5; \
	orps S2_a3,%xmm5; \
	orps %xmm2,%xmm1; \
	andps S2_x18,%xmm2; \
	xorps %xmm3,%xmm4; \
	movaps S2_a4,%xmm3; \
	andps %xmm4,%xmm2; \
	andps S2_a3,%xmm4; \
	xorps %xmm5,%xmm0; \
	xorps S2_x25,%xmm7; \
	xorps %xmm6,%xmm4; \
	xorps out3,%xmm7; \
	andps %xmm3,%xmm1; \
	orps %xmm3,%xmm2; \
	xorps out1,%xmm1; \
	xorps %xmm4,%xmm2; \
	xorps %xmm0,%xmm1; \
	xorps out4,%xmm2; \
	movaps %xmm1,out1; \
	movaps %xmm7,out3; \
	movaps %xmm2,out4

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
	movaps %xmm0,S3_a1; \
	extra; \
	movaps %xmm4,%xmm0; \
	movaps %xmm5,%xmm6; \
	xorps pnot,%xmm6; \
	movaps %xmm4,%xmm7; \
	xorps %xmm6,%xmm7; \
	movaps %xmm6,S3_x2; \
	andps %xmm2,%xmm0; \
	movaps %xmm7,S3_x9; \
	xorps %xmm5,%xmm0; \
	movaps %xmm4,S3_a5; \
	andnps %xmm3,%xmm4; \
	movaps %xmm0,S3_x4; \
	orps %xmm3,%xmm7; \
	movaps S3_a5,%xmm6; \
	xorps %xmm4,%xmm0; \
	movaps %xmm5,S3_a6; \
	andnps %xmm2,%xmm6; \
	movaps %xmm0,S3_x6; \
	xorps %xmm6,%xmm7; \
	movaps S3_x2,%xmm5; \
	xorps %xmm1,%xmm0; \
	movaps %xmm4,S3_x5; \
	movaps %xmm7,%xmm4; \
	orps S3_x4,%xmm5; \
	andps %xmm0,%xmm4; \
	movaps %xmm7,S3_x11; \
	xorps %xmm5,%xmm6; \
	xorps S3_a5,%xmm7; \
	orps %xmm1,%xmm6; \
	movaps %xmm4,S3_x12; \
	andps %xmm5,%xmm4; \
	movaps %xmm7,S3_x13; \
	orps %xmm0,%xmm7; \
	movaps %xmm4,S3_x54; \
	movaps %xmm2,%xmm4; \
	xorps S3_x9,%xmm4; \
	andps %xmm3,%xmm7; \
	movaps %xmm0,S3_x7; \
	xorps %xmm3,%xmm4; \
	xorps S3_a6,%xmm5; \
	xorps %xmm4,%xmm6; \
	movaps %xmm3,S3_a4; \
	orps %xmm5,%xmm3; \
	movaps %xmm2,S3_a3; \
	xorps %xmm3,%xmm5; \
	orps %xmm1,%xmm5; \
	xorps %xmm7,%xmm2; \
	xorps S3_x12,%xmm7; \
	movaps %xmm2,%xmm4; \
	orps S3_x5,%xmm2; \
	andps %xmm1,%xmm7; \
	orps S3_x4,%xmm4; \
	orps %xmm1,%xmm2; \
	xorps S3_x11,%xmm7; \
	xorps %xmm3,%xmm2; \
	movaps S3_a1,%xmm3; \
	xorps S3_a4,%xmm4; \
	andps %xmm3,%xmm7; \
	xorps S3_x7,%xmm7; \
	orps %xmm3,%xmm2; \
	movaps %xmm4,S3_x38; \
	xorps %xmm6,%xmm2; \
	xorps out4,%xmm7; \
	orps %xmm1,%xmm4; \
	movaps S3_a3,%xmm6; \
	movaps %xmm2,%xmm3; \
	xorps S3_x9,%xmm6; \
	orps S3_x5,%xmm6; \
	xorps S3_x38,%xmm3; \
	xorps %xmm6,%xmm4; \
	movaps S3_a6,%xmm6; \
	andps S3_x11,%xmm6; \
	movaps %xmm7,out4; \
	movaps S3_x2,%xmm0; \
	xorps %xmm6,%xmm3; \
	orps S3_x6,%xmm6; \
	andps %xmm1,%xmm3; \
	orps S3_x38,%xmm0; \
	xorps %xmm6,%xmm3; \
	xorps S3_x13,%xmm0; \
	movaps %xmm5,%xmm6; \
	orps S3_a1,%xmm3; \
	xorps %xmm5,%xmm0; \
	andps S3_x54,%xmm6; \
	xorps %xmm4,%xmm3; \
	orps S3_a1,%xmm6; \
	xorps out3,%xmm3; \
	xorps %xmm0,%xmm6; \
	xorps out1,%xmm2; \
	movaps %xmm3,out3; \
	xorps out2,%xmm6; \
	movaps %xmm2,out1; \
	movaps %xmm6,out2

#define S4_out1				%xmm1
#define S4_out2				%xmm0
#define S4_out3				%xmm6
#define S4_out4				%xmm5

#define S4_a2				tmp_at(1)
#define S4_a3				tmp_at(2)
#define S4_a4				tmp_at(3)
#define S4_a6				tmp_at(4)

#define S4(out1, out2, out3, out4, extra) \
	movaps %xmm2,%xmm6; \
	movaps %xmm3,S4_a4; \
	movaps %xmm0,%xmm7; \
	movaps %xmm1,S4_a2; \
	orps %xmm0,%xmm6; \
	extra; \
	andps %xmm4,%xmm7; \
	movaps %xmm1,%xmm3; \
	movaps %xmm5,S4_a6; \
	movaps %xmm2,S4_a3; \
	movaps %xmm4,%xmm5; \
	andps %xmm6,%xmm5; \
	orps %xmm2,%xmm3; \
	xorps pnot,%xmm2; \
	xorps %xmm5,%xmm0; \
	xorps pnot,%xmm0; \
	xorps %xmm7,%xmm6; \
	xorps %xmm0,%xmm3; \
	movaps %xmm1,%xmm7; \
	andps %xmm6,%xmm7; \
	xorps %xmm2,%xmm5; \
	xorps %xmm4,%xmm2; \
	andps %xmm5,%xmm0; \
	xorps %xmm7,%xmm4; \
	andps %xmm1,%xmm5; \
	orps %xmm1,%xmm2; \
	xorps %xmm6,%xmm5; \
	movaps S4_a4,%xmm1; \
	movaps %xmm0,%xmm6; \
	andps %xmm4,%xmm1; \
	xorps %xmm2,%xmm6; \
	orps S4_a4,%xmm6; \
	xorps %xmm3,%xmm1; \
	andps S4_a2,%xmm4; \
	xorps %xmm5,%xmm6; \
	movaps S4_a6,%xmm3; \
	xorps %xmm0,%xmm4; \
	xorps S4_a3,%xmm7; \
	movaps %xmm3,%xmm0; \
	xorps %xmm2,%xmm7; \
	andps %xmm6,%xmm0; \
	movaps S4_a4,%xmm2; \
	orps %xmm3,%xmm6; \
	xorps %xmm1,%xmm0; \
	andps %xmm2,%xmm7; \
	xorps pnot,%xmm1; \
	xorps %xmm7,%xmm4; \
	movaps %xmm4,%xmm5; \
	xorps %xmm1,%xmm4; \
	xorps out1,%xmm1; \
	orps %xmm4,%xmm2; \
	andps S4_a2,%xmm4; \
	xorps %xmm6,%xmm1; \
	xorps %xmm0,%xmm4; \
	xorps out3,%xmm6; \
	xorps %xmm4,%xmm2; \
	xorps out2,%xmm0; \
	andps %xmm2,%xmm3; \
	xorps %xmm2,%xmm6; \
	xorps %xmm3,%xmm5; \
	movaps %xmm1,out1; \
	xorps %xmm5,%xmm6; \
	movaps %xmm0,out2; \
	xorps out4,%xmm5; \
	movaps %xmm6,out3; \
	movaps %xmm5,out4

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
	movaps %xmm1,S5_a2; \
	movaps %xmm3,%xmm6; \
	movaps %xmm2,%xmm7; \
	andnps %xmm2,%xmm6; \
	andnps %xmm0,%xmm7; \
	movaps %xmm6,%xmm1; \
	movaps %xmm0,S5_a1; \
	xorps %xmm0,%xmm1; \
	extra; \
	xorps %xmm3,%xmm0; \
	movaps %xmm1,S5_x2; \
	movaps %xmm5,S5_a6; \
	orps %xmm0,%xmm6; \
	orps %xmm7,%xmm5; \
	movaps %xmm6,S5_x7; \
	xorps %xmm5,%xmm1; \
	movaps %xmm5,S5_x4; \
	andps %xmm2,%xmm6; \
	movaps S5_a6,%xmm5; \
	xorps %xmm3,%xmm6; \
	andnps S5_x7,%xmm5; \
	movaps %xmm0,S5_x6; \
	movaps %xmm7,%xmm0; \
	movaps %xmm5,S5_x8; \
	xorps %xmm2,%xmm5; \
	movaps %xmm1,S5_x5; \
	xorps %xmm3,%xmm0; \
	movaps %xmm5,S5_x9; \
	andnps %xmm6,%xmm7; \
	orps S5_a6,%xmm0; \
	orps %xmm4,%xmm5; \
	movaps %xmm6,S5_x13; \
	xorps %xmm1,%xmm5; \
	movaps %xmm0,S5_x16; \
	xorps %xmm0,%xmm7; \
	movaps S5_a2,%xmm0; \
	movaps %xmm4,%xmm1; \
	movaps %xmm7,S5_x17; \
	orps %xmm7,%xmm1; \
	andps S5_x5,%xmm7; \
	xorps %xmm6,%xmm1; \
	andnps %xmm1,%xmm0; \
	movaps %xmm7,%xmm6; \
	andnps S5_x7,%xmm6; \
	xorps %xmm0,%xmm5; \
	xorps S5_x9,%xmm7; \
	movaps %xmm3,%xmm0; \
	movaps %xmm5,S5_x21; \
	movaps %xmm6,%xmm5; \
	andnps S5_x8,%xmm0; \
	andnps %xmm1,%xmm5; \
	xorps out3,%xmm6; \
	xorps %xmm2,%xmm0; \
	movaps S5_a1,%xmm2; \
	movaps %xmm0,%xmm1; \
	xorps S5_x9,%xmm2; \
	andps %xmm4,%xmm1; \
	movaps %xmm7,S5_x38; \
	xorps %xmm1,%xmm6; \
	movaps S5_x4,%xmm1; \
	movaps %xmm2,%xmm7; \
	andps S5_x2,%xmm7; \
	andps %xmm3,%xmm1; \
	xorps S5_x17,%xmm1; \
	andnps %xmm4,%xmm7; \
	movaps %xmm2,S5_x24; \
	xorps %xmm7,%xmm1; \
	movaps out2,%xmm7; \
	orps %xmm2,%xmm3; \
	movaps S5_a2,%xmm2; \
	xorps %xmm1,%xmm7; \
	movaps %xmm3,S5_x28; \
	andnps %xmm3,%xmm2; \
	movaps S5_x38,%xmm3; \
	xorps %xmm2,%xmm7; \
	movaps S5_x16,%xmm2; \
	orps %xmm4,%xmm3; \
	orps S5_x13,%xmm2; \
	orps %xmm5,%xmm1; \
	xorps out1,%xmm5; \
	xorps %xmm3,%xmm2; \
	orps S5_a2,%xmm2; \
	movaps %xmm7,out2; \
	xorps S5_x6,%xmm1; \
	xorps %xmm2,%xmm6; \
	andnps %xmm4,%xmm1; \
	movaps S5_x38,%xmm2; \
	xorps S5_x24,%xmm1; \
	movaps %xmm2,%xmm3; \
	xorps S5_x21,%xmm2; \
	xorps %xmm1,%xmm5; \
	andps S5_x6,%xmm3; \
	andnps %xmm4,%xmm2; \
	andps S5_x28,%xmm2; \
	xorps %xmm0,%xmm3; \
	xorps pnot,%xmm6; \
	xorps %xmm2,%xmm3; \
	movaps S5_x21,%xmm4; \
	orps S5_a2,%xmm3; \
	movaps %xmm6,out3; \
	xorps out4,%xmm4; \
	xorps %xmm3,%xmm5; \
	movaps %xmm4,out4; \
	movaps %xmm5,out1

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
	movaps %xmm2,S6_a3; \
	extra; \
	movaps %xmm4,%xmm6; \
	xorps pnot,%xmm6; \
	movaps %xmm5,%xmm7; \
	movaps %xmm1,S6_a2; \
	movaps %xmm4,%xmm2; \
	movaps %xmm3,S6_a4; \
	xorps %xmm1,%xmm7; \
	xorps pnot,%xmm1; \
	xorps %xmm6,%xmm7; \
	movaps %xmm6,S6_x2; \
	xorps %xmm0,%xmm7; \
	andps %xmm5,%xmm2; \
	movaps %xmm4,%xmm6; \
	movaps %xmm1,S6_x1; \
	movaps %xmm5,%xmm3; \
	andps S6_a2,%xmm3; \
	andps %xmm7,%xmm6; \
	movaps %xmm0,S6_a1; \
	orps %xmm2,%xmm1; \
	movaps %xmm2,S6_x6; \
	andps %xmm6,%xmm0; \
	movaps %xmm3,S6_x15; \
	xorps %xmm0,%xmm1; \
	movaps S6_a4,%xmm0; \
	movaps %xmm4,%xmm2; \
	movaps %xmm6,S6_x8; \
	andps %xmm1,%xmm0; \
	movaps %xmm7,S6_x5; \
	xorps %xmm3,%xmm2; \
	movaps S6_x2,%xmm6; \
	xorps %xmm7,%xmm0; \
	movaps S6_a1,%xmm7; \
	xorps %xmm5,%xmm1; \
	movaps %xmm2,S6_x16; \
	andps %xmm7,%xmm2; \
	movaps S6_a4,%xmm3; \
	xorps %xmm2,%xmm6; \
	xorps S6_a2,%xmm2; \
	andps %xmm7,%xmm1; \
	orps %xmm6,%xmm3; \
	xorps %xmm5,%xmm6; \
	xorps %xmm3,%xmm1; \
	andps %xmm6,%xmm7; \
	andps S6_a3,%xmm1; \
	andps %xmm4,%xmm6; \
	movaps S6_x6,%xmm3; \
	xorps %xmm1,%xmm0; \
	xorps out2,%xmm0; \
	orps %xmm2,%xmm3; \
	andps S6_a4,%xmm3; \
	xorps %xmm7,%xmm4; \
	movaps S6_x5,%xmm1; \
	xorps %xmm3,%xmm4; \
	xorps pnot,%xmm2; \
	orps %xmm4,%xmm5; \
	movaps %xmm0,out2; \
	movaps %xmm5,%xmm3; \
	andnps S6_a4,%xmm3; \
	xorps %xmm6,%xmm1; \
	movaps S6_x6,%xmm0; \
	xorps %xmm2,%xmm3; \
	orps S6_a4,%xmm1; \
	xorps %xmm3,%xmm0; \
	andps S6_a3,%xmm3; \
	xorps %xmm1,%xmm0; \
	orps S6_x5,%xmm6; \
	movaps %xmm7,%xmm1; \
	xorps S6_x15,%xmm7; \
	xorps %xmm3,%xmm4; \
	movaps S6_a4,%xmm3; \
	xorps %xmm5,%xmm7; \
	andps S6_x8,%xmm5; \
	orps %xmm3,%xmm7; \
	xorps S6_x6,%xmm6; \
	orps %xmm3,%xmm5; \
	orps S6_x16,%xmm1; \
	xorps %xmm6,%xmm5; \
	xorps S6_x1,%xmm1; \
	movaps S6_a3,%xmm3; \
	xorps %xmm1,%xmm7; \
	xorps out4,%xmm4; \
	orps %xmm3,%xmm7; \
	andps %xmm1,%xmm2; \
	xorps out1,%xmm0; \
	orps %xmm3,%xmm2; \
	xorps %xmm7,%xmm0; \
	xorps %xmm5,%xmm2; \
	movaps %xmm4,out4; \
	xorps out3,%xmm2; \
	movaps %xmm0,out1; \
	movaps %xmm2,out3

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
	movaps %xmm0,S7_a1; \
	movaps %xmm1,%xmm6; \
	extra; \
	movaps %xmm1,S7_a2; \
	movaps %xmm3,%xmm7; \
	movaps %xmm5,S7_a6; \
	andps %xmm3,%xmm6; \
	movaps %xmm3,S7_a4; \
	xorps %xmm4,%xmm6; \
	xorps pnot,%xmm4; \
	andps %xmm6,%xmm7; \
	andps %xmm4,%xmm3; \
	movaps %xmm1,%xmm5; \
	xorps %xmm2,%xmm6; \
	xorps %xmm7,%xmm5; \
	movaps %xmm7,S7_x6; \
	orps %xmm1,%xmm4; \
	orps %xmm3,%xmm1; \
	xorps %xmm6,%xmm7; \
	movaps %xmm5,S7_x7; \
	andps %xmm2,%xmm4; \
	andps %xmm2,%xmm5; \
	orps %xmm7,%xmm3; \
	movaps %xmm1,S7_x13; \
	xorps %xmm5,%xmm0; \
	orps S7_a6,%xmm0; \
	xorps %xmm4,%xmm1; \
	movaps %xmm4,S7_x15; \
	xorps %xmm6,%xmm0; \
	movaps %xmm5,S7_x8; \
	movaps %xmm3,%xmm4; \
	movaps S7_a6,%xmm6; \
	movaps %xmm0,%xmm5; \
	xorps S7_x6,%xmm5; \
	orps %xmm6,%xmm4; \
	movaps %xmm7,S7_x25; \
	orps %xmm6,%xmm5; \
	movaps S7_a1,%xmm7; \
	xorps %xmm1,%xmm5; \
	movaps %xmm3,S7_x26; \
	andps %xmm5,%xmm7; \
	movaps %xmm0,S7_x11; \
	xorps %xmm0,%xmm7; \
	movaps S7_a4,%xmm3; \
	movaps %xmm7,%xmm0; \
	orps S7_a2,%xmm0; \
	andps %xmm3,%xmm1; \
	andps S7_x13,%xmm3; \
	orps S7_x7,%xmm2; \
	xorps S7_x6,%xmm0; \
	xorps %xmm3,%xmm2; \
	movaps S7_a2,%xmm3; \
	movaps %xmm0,%xmm6; \
	xorps pnot,%xmm3; \
	xorps S7_x15,%xmm6; \
	orps %xmm3,%xmm1; \
	andps S7_x26,%xmm0; \
	xorps %xmm6,%xmm4; \
	andps S7_a6,%xmm0; \
	orps %xmm3,%xmm6; \
	orps S7_a6,%xmm6; \
	andps %xmm5,%xmm3; \
	andps S7_a6,%xmm1; \
	xorps %xmm3,%xmm0; \
	orps S7_a1,%xmm0; \
	xorps %xmm6,%xmm2; \
	xorps S7_x11,%xmm1; \
	xorps %xmm4,%xmm0; \
	movaps S7_a1,%xmm4; \
	xorps %xmm2,%xmm5; \
	movaps S7_a4,%xmm6; \
	orps %xmm2,%xmm4; \
	xorps S7_x25,%xmm6; \
	xorps %xmm4,%xmm1; \
	movaps S7_a6,%xmm4; \
	andps %xmm1,%xmm6; \
	movaps S7_x6,%xmm3; \
	andps %xmm4,%xmm6; \
	xorps S7_x15,%xmm3; \
	xorps %xmm5,%xmm6; \
	xorps S7_x8,%xmm2; \
	orps %xmm4,%xmm3; \
	orps S7_a1,%xmm6; \
	xorps %xmm2,%xmm3; \
	xorps out1,%xmm7; \
	xorps %xmm6,%xmm3; \
	xorps out2,%xmm1; \
	movaps %xmm7,out1; \
	xorps out3,%xmm3; \
	movaps %xmm1,out2; \
	xorps out4,%xmm0; \
	movaps %xmm3,out3; \
	movaps %xmm0,out4

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
	movaps %xmm0,S8_a1; \
	extra; \
	movaps %xmm2,%xmm6; \
	xorps pnot,%xmm0; \
	movaps %xmm2,%xmm7; \
	movaps %xmm3,S8_a4; \
	orps %xmm0,%xmm7; \
	xorps pnot,%xmm3; \
	xorps %xmm0,%xmm6; \
	movaps %xmm5,S8_a6; \
	movaps %xmm4,%xmm5; \
	movaps %xmm1,S8_a2; \
	movaps %xmm7,%xmm1; \
	movaps %xmm4,S8_a5; \
	xorps %xmm3,%xmm7; \
	orps %xmm6,%xmm5; \
	orps %xmm7,%xmm0; \
	andps %xmm4,%xmm1; \
	andnps %xmm0,%xmm2; \
	orps %xmm7,%xmm4; \
	xorps %xmm1,%xmm2; \
	movaps %xmm5,S8_x22; \
	andps %xmm3,%xmm5; \
	orps S8_a2,%xmm2; \
	xorps %xmm4,%xmm7; \
	xorps %xmm0,%xmm3; \
	movaps %xmm4,%xmm1; \
	xorps S8_x22,%xmm7; \
	xorps %xmm3,%xmm1; \
	xorps %xmm6,%xmm4; \
	xorps %xmm5,%xmm2; \
	xorps S8_a1,%xmm5; \
	andps %xmm3,%xmm6; \
	movaps %xmm1,S8_x14; \
	andps %xmm4,%xmm5; \
	movaps %xmm7,S8_x33; \
	movaps %xmm0,%xmm1; \
	andps S8_a5,%xmm3; \
	movaps %xmm0,%xmm7; \
	andps S8_a5,%xmm1; \
	xorps %xmm3,%xmm7; \
	andps S8_a2,%xmm7; \
	xorps %xmm1,%xmm6; \
	movaps S8_a6,%xmm1; \
	xorps %xmm4,%xmm7; \
	orps S8_a2,%xmm6; \
	andnps %xmm0,%xmm4; \
	xorps S8_x14,%xmm6; \
	andps %xmm2,%xmm1; \
	xorps S8_a1,%xmm3; \
	xorps %xmm6,%xmm2; \
	orps S8_a6,%xmm6; \
	xorps %xmm7,%xmm1; \
	xorps S8_x22,%xmm3; \
	xorps %xmm7,%xmm6; \
	orps S8_a2,%xmm4; \
	andps S8_a2,%xmm5; \
	xorps %xmm4,%xmm3; \
	movaps S8_a1,%xmm4; \
	andps S8_x33,%xmm4; \
	orps S8_a4,%xmm7; \
	xorps %xmm4,%xmm0; \
	andps S8_a2,%xmm7; \
	xorps %xmm0,%xmm5; \
	movaps S8_a6,%xmm4; \
	orps %xmm0,%xmm2; \
	xorps S8_x33,%xmm7; \
	orps %xmm4,%xmm5; \
	xorps out1,%xmm6; \
	andps %xmm4,%xmm2; \
	xorps out4,%xmm1; \
	xorps %xmm7,%xmm5; \
	xorps %xmm3,%xmm2; \
	xorps out3,%xmm5; \
	movaps %xmm6,out1; \
	xorps out2,%xmm2; \
	movaps %xmm1,out4; \
	movaps %xmm5,out3; \
	movaps %xmm2,out2

#define zero				%xmm0

#define DES_bs_clear_block_8(i) \
	movaps zero,B(i); \
	movaps zero,B(i + 1); \
	movaps zero,B(i + 2); \
	movaps zero,B(i + 3); \
	movaps zero,B(i + 4); \
	movaps zero,B(i + 5); \
	movaps zero,B(i + 6); \
	movaps zero,B(i + 7)

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
#define K(i)				(i)*16(k_ptr)
#define k(i)				(i)*4(k_ptr)

#define a6_xor_ptr			%esi
#define a6_p				xorps (a6_xor_ptr),a6
#define a6_v(i)				xorps K(i),a6

#define tmp1				%ecx
#define tmp2				a6_xor_ptr

#define xor_E(i) \
	movl E(i),tmp1; \
	movaps K(i),a1; \
	movl E(i + 1),tmp2; \
	movaps K(i + 1),a2; \
	xorps (tmp1),a1; \
	xorps (tmp2),a2; \
	movl E(i + 2),tmp1; \
	movaps K(i + 2),a3; \
	movl E(i + 3),tmp2; \
	movaps K(i + 3),a4; \
	xorps (tmp1),a3; \
	xorps (tmp2),a4; \
	movl E(i + 4),tmp1; \
	movaps K(i + 4),a5; \
	movl E(i + 5),a6_xor_ptr; \
	movaps K(i + 5),a6; \
	xorps (tmp1),a5

#define xor_B(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6) \
	movaps B(b1),a1; \
	movaps B(b2),a2; \
	xorps K(k1),a1; \
	movaps B(b3),a3; \
	xorps K(k2),a2; \
	movaps B(b4),a4; \
	xorps K(k3),a3; \
	movaps B(b5),a5; \
	xorps K(k4),a4; \
	movaps B(b6),a6; \
	xorps K(k5),a5

#define xor_B_KS_p(b1, k1, b2, k2, b3, k3, b4, k4, b5, k5, b6, k6) \
	movl k(k1),tmp1; \
	movl k(k2),tmp2; \
	movaps B(b1),a1; \
	movaps B(b2),a2; \
	xorps (tmp1),a1; \
	movl k(k3),tmp1; \
	xorps (tmp2),a2; \
	movl k(k4),tmp2; \
	movaps B(b3),a3; \
	movaps B(b4),a4; \
	xorps (tmp1),a3; \
	movl k(k5),tmp1; \
	xorps (tmp2),a4; \
	movaps B(b5),a5; \
	movl k(k6),a6_xor_ptr; \
	movaps B(b6),a6; \
	xorps (tmp1),a5

.data

DO_ALIGN(4)
mm_ones:
.quad -1
.quad -1

.text

DO_ALIGN(5)
.globl DES_bs_init_asm
DES_bs_init_asm:
	movaps mm_ones,%xmm0
	movaps %xmm0,pnot
	ret

#define rounds_and_swapped		%ebp
#define iterations			%eax

DO_ALIGN(5)
.globl DES_bs_crypt
DES_bs_crypt:
	movl 4(%esp),iterations
	xorps zero,zero
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
	addl $96*16,k_ptr
	S8(B(4), B(26), B(14), B(20), a6_p)
	decl rounds_and_swapped
	jnz DES_bs_crypt_start
	subl $0x300*16+48*16,k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_swap
	popl %esi
	popl %ebp
	ret
DES_bs_crypt_next:
	subl $0x300*16-48*16,k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_start
	popl %esi
	popl %ebp
	ret

DO_ALIGN(5)
.globl DES_bs_crypt_25
DES_bs_crypt_25:
	xorps zero,zero
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
	addl $96*16,k_ptr
	decl rounds_and_swapped
	jnz DES_bs_crypt_25_start
	subl $0x300*16+48*16,k_ptr
	movl $0x108,rounds_and_swapped
	decl iterations
	jnz DES_bs_crypt_25_swap
	popl %esi
	popl %ebp
	ret
DES_bs_crypt_25_next:
	subl $0x300*16-48*16,k_ptr
	movl $8,rounds_and_swapped
	decl iterations
	jmp DES_bs_crypt_25_start

#define ones				%xmm1

#define rounds				%eax

DO_ALIGN(5)
.globl DES_bs_crypt_LM
DES_bs_crypt_LM:
	xorps zero,zero
	pushl %esi
	movaps pnot,ones
	movl $DES_bs_all_KS_p,k_ptr
	movaps zero,B(0)
	movaps zero,B(1)
	movaps zero,B(2)
	movaps zero,B(3)
	movaps zero,B(4)
	movaps zero,B(5)
	movaps zero,B(6)
	movaps zero,B(7)
	movaps ones,B(8)
	movaps ones,B(9)
	movaps ones,B(10)
	movaps zero,B(11)
	movaps ones,B(12)
	movaps zero,B(13)
	movaps zero,B(14)
	movaps zero,B(15)
	movaps zero,B(16)
	movaps zero,B(17)
	movaps zero,B(18)
	movaps zero,B(19)
	movaps zero,B(20)
	movaps zero,B(21)
	movaps zero,B(22)
	movaps ones,B(23)
	movaps zero,B(24)
	movaps zero,B(25)
	movaps ones,B(26)
	movaps zero,B(27)
	movaps zero,B(28)
	movaps ones,B(29)
	movaps ones,B(30)
	movaps ones,B(31)
	movaps zero,B(32)
	movaps zero,B(33)
	movaps zero,B(34)
	movaps ones,B(35)
	movaps zero,B(36)
	movaps ones,B(37)
	movaps ones,B(38)
	movaps ones,B(39)
	movaps zero,B(40)
	movaps zero,B(41)
	movaps zero,B(42)
	movaps zero,B(43)
	movaps zero,B(44)
	movaps ones,B(45)
	movaps zero,B(46)
	movaps zero,B(47)
	movaps ones,B(48)
	movaps ones,B(49)
	movaps zero,B(50)
	movaps zero,B(51)
	movaps zero,B(52)
	movaps zero,B(53)
	movaps ones,B(54)
	movaps zero,B(55)
	movaps ones,B(56)
	movaps zero,B(57)
	movaps ones,B(58)
	movaps zero,B(59)
	movaps ones,B(60)
	movaps ones,B(61)
	movaps ones,B(62)
	movaps ones,B(63)
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
	ret
