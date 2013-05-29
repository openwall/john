/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2003,2006,2011 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * x86 assembly routines.
 */

#include "arch.h"

#ifdef UNDERSCORES
#define DES_IV				_DES_IV
#define DES_count			_DES_count
#define DES_KS_current			_DES_KS_current
#define DES_KS_copy			_DES_KS_copy
#define DES_KS_table			_DES_KS_table
#define DES_SPE_L			_DES_SPE_L
#define DES_SPE_H			_DES_SPE_H
#define DES_SPE_F			_DES_SPE_F
#define DES_std_crypt			_DES_std_crypt
#define DES_xor_key1			_DES_xor_key1
#define DES_xor_key2			_DES_xor_key2
#define MD5_body			_MD5_body
#define BF_body				_BF_body
#define BF_current			_BF_current
#define CPU_detect			_CPU_detect
#endif

/*
 * Some broken systems don't offer section alignments larger than 4 bytes,
 * while for the MMX code we need at least an 8 byte alignment. ALIGN_FIX
 * is here to work around this issue when we happen to get bad addresses.
 */
#ifndef ALIGN_FIX
#ifdef ALIGN_LOG
#define DO_ALIGN(log)			.align (log)
#elif defined(DUMBAS)
#define DO_ALIGN(log)			.align 1 << log
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

/*
 * DES stuff.
 *
 * Included are versions for:
 * 1. MMX (Pentium MMX and newer Intel x86 CPUs, some clones);
 * 2. Intel Pentium without MMX;
 * 3. The rest (good for Pentium Pro, 486, clones).
 *
 * MMX has to be enabled at compile time (via DES_X2 in arch.h), while #2
 * or #3 is chosen based on CPUID info at runtime.
 *
 * Note: MMX code for the bitslice DES implementation is in x86-mmx.S, so
 * you probably want to look in there instead.
 */

.text

#if DES_X2

/*
 * DES MMX routines.
 */

#define R				%mm0
#define L				%mm1
#define tmp1				%mm2
#define tmp2				%mm3
#define K1				%mm4
#define K2				%mm5
#define K3				%mm6
#define K4				%mm7

#define DES_copy(ofs1, ofs2) \
	movq ofs1(%edx),%mm0; \
	movq ofs2(%edx),%mm1; \
	movq %mm0,DES_KS_copy+ofs1; \
	movq %mm1,DES_KS_copy+ofs2

#define DES_2_ROUNDS_START(K) \
	pxor R,tmp1; \
	movd tmp1,%eax; \
	movb %al,%bl; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	psrlq $32,tmp1; \
	pxor DES_SPE_F(%ebx,%ebx),L; \
	pxor DES_SPE_F+0x200(%edx,%edx),L; \
	movb %al,%bl; \
	movb %ah,%dl; \
	movd tmp1,%eax; \
	pxor DES_SPE_F+0x400(%ebx,%ebx),L; \
	pxor DES_SPE_F+0x600(%edx,%edx),L; \
	movb %al,%bl; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	pxor DES_SPE_F+0x800(%ebx,%ebx),L; \
	pxor DES_SPE_F+0xA00(%edx,%edx),L; \
	movb %al,%bl; \
	movb %ah,%dl; \
	movq K,tmp1; \
	pxor DES_SPE_F+0xC00(%ebx,%ebx),L; \
	pxor DES_SPE_F+0xE00(%edx,%edx),L; \
	pxor L,tmp1; \
	movd tmp1,%eax; \
	movb %al,%bl; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	psrlq $32,tmp1; \
	pxor DES_SPE_F(%ebx,%ebx),R; \
	pxor DES_SPE_F+0x200(%edx,%edx),R; \
	movb %al,%bl; \
	movb %ah,%dl; \
	movd tmp1,%eax; \
	pxor DES_SPE_F+0x400(%ebx,%ebx),R; \
	pxor DES_SPE_F+0x600(%edx,%edx),R; \
	movb %al,%bl; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	pxor DES_SPE_F+0x800(%ebx,%ebx),R; \
	pxor DES_SPE_F+0xA00(%edx,%edx),R; \
	movb %al,%bl; \
	movb %ah,%dl

#define DES_2_ROUNDS(K1, K2) \
	DES_2_ROUNDS_START(K1); \
	movq K2,tmp1; \
	pxor DES_SPE_F+0xC00(%ebx,%ebx),R; \
	pxor DES_SPE_F+0xE00(%edx,%edx),R

DO_ALIGN(12)
.globl DES_std_crypt
DES_std_crypt:
	movl 4(%esp),%edx
	pushl %ebx
	movl DES_count,%ecx
	xorl %ebx,%ebx
	movq (%edx),K1
	movq 32(%edx),K2
	movq K1,tmp1
	movq 8(%edx),K3
	movq 16(%edx),K4
	DES_copy(24, 40)
	DES_copy(48, 56)
	DES_copy(64, 96)
	DES_copy(72, 80)
	DES_copy(88, 104)
	DES_copy(112, 120)
	movq DES_IV,R
	xorl %edx,%edx
	movq DES_IV+8,L
DES_loop:
	DES_2_ROUNDS(K3, K4)
	DES_2_ROUNDS(DES_KS_copy+24, K2)
	DES_2_ROUNDS(DES_KS_copy+40, DES_KS_copy+48)
	DES_2_ROUNDS(DES_KS_copy+56, DES_KS_copy+64)
	DES_2_ROUNDS(DES_KS_copy+72, DES_KS_copy+80)
	DES_2_ROUNDS(DES_KS_copy+88, DES_KS_copy+96)
	DES_2_ROUNDS(DES_KS_copy+104, DES_KS_copy+112)
	DES_2_ROUNDS_START(DES_KS_copy+120)
	movq K1,tmp1
	pxor DES_SPE_F+0xC00(%ebx,%ebx),R
	movq L,tmp2
	pxor DES_SPE_F+0xE00(%edx,%edx),R
	decl %ecx
	movq R,L
	movq tmp2,R
	jnz DES_loop
	movl 12(%esp),%edx
	popl %ebx
	movq R,(%edx)
	movq L,8(%edx)
#ifdef EMMS
	emms
#endif
	ret

#define DES_xor1(ofs1, ofs2) \
	movq DES_KS_current+ofs1,%mm0; \
	movq DES_KS_current+ofs2,%mm1; \
	pxor ofs1(%edx),%mm0; \
	pxor ofs2(%edx),%mm1; \
	movq %mm0,DES_KS_current+ofs1; \
	movq %mm1,DES_KS_current+ofs2

DO_ALIGN(4)
.globl DES_xor_key1
DES_xor_key1:
	movl 4(%esp),%edx
	DES_xor1(0, 32)
	DES_xor1(8, 16)
	DES_xor1(24, 40)
	DES_xor1(48, 56)
	DES_xor1(64, 96)
	DES_xor1(72, 80)
	DES_xor1(88, 104)
	DES_xor1(112, 120)
#ifdef EMMS
	emms
#endif
	ret

#define DES_xor2(ofs1, ofs2) \
	movq DES_KS_current+ofs1,%mm0; \
	movq DES_KS_current+ofs2,%mm1; \
	pxor ofs1(%edx),%mm0; \
	pxor ofs2(%edx),%mm1; \
	pxor ofs1(%ecx),%mm0; \
	pxor ofs2(%ecx),%mm1; \
	movq %mm0,DES_KS_current+ofs1; \
	movq %mm1,DES_KS_current+ofs2

DO_ALIGN(4)
.globl DES_xor_key2
DES_xor_key2:
	movl 4(%esp),%edx
	movl 8(%esp),%ecx
	DES_xor2(0, 32)
	DES_xor2(8, 16)
	DES_xor2(24, 40)
	DES_xor2(48, 56)
	DES_xor2(64, 96)
	DES_xor2(72, 80)
	DES_xor2(88, 104)
	DES_xor2(112, 120)
#ifdef EMMS
	emms
#endif
	ret

#else

/*
 * DES non-MMX routines.
 */

#define Rl				%ecx
#define Rh				%ebp
#define Ll				%esi
#define Lh				%edi

#define DES_copy(ofs) \
	movl ofs(%edx),%esi; \
	movl ofs+4(%edx),%edi; \
	movl %esi,DES_KS_copy+ofs; \
	movl %edi,DES_KS_copy+ofs+4

#define DES_CRYPT_START \
	movl 4(%esp),%edx; \
	pushl %ebp; \
	pushl %esi; \
	pushl %edi; \
	pushl %ebx; \
	movl (%edx),%eax; \
	movl 4(%edx),%edi; \
	movl %eax,DES_KS_copy; \
	movl %edi,DES_KS_copy+4; \
	DES_copy(32); \
	DES_copy(8); \
	DES_copy(16); \
	DES_copy(24); \
	DES_copy(40); \
	DES_copy(48); \
	DES_copy(56); \
	DES_copy(64); \
	DES_copy(96); \
	DES_copy(72); \
	DES_copy(80); \
	DES_copy(88); \
	DES_copy(104); \
	DES_copy(112); \
	DES_copy(120); \
	movl DES_IV,Rl; \
	movl DES_IV+4,Rh; \
	movl DES_IV+8,Ll; \
	movl DES_IV+12,Lh; \
	movl DES_count,%edx; \
	xorl %ebx,%ebx; \
	movl %edx,DES_count_tmp; \
	xorl %edx,%edx

#define DES_CRYPT_END \
	movl 24(%esp),%edx; \
	popl %ebx; \
	movl Rl,(%edx); \
	movl Rh,4(%edx); \
	movl Ll,8(%edx); \
	movl Lh,12(%edx); \
	popl %edi; \
	popl %esi; \
	popl %ebp; \
	ret

/*
 * Intel Pentium optimized version, extra operations are used to avoid
 * imperfect pairing.
 */

#define DES_2_ROUNDS_START_P1(K) \
	xorl Rl,%eax; \
	movb %al,%bl; \
	movb %ah,%dl; \
	movl Rl,DES_SavedL; \
	shrl $16,%eax; \
	movl DES_SPE_L(%ebx),Rl; \
	xorl Rl,Ll; \
	movl DES_SPE_H(%ebx),Rl; \
	xorl Rl,Lh; \
	movl DES_SPE_L+0x100(%edx),Rl; \
	xorl Rl,Ll; \
	movl DES_SPE_H+0x100(%edx),Rl; \
	movb %al,%bl; \
	xorl Rl,Lh; \
	movb %ah,%dl; \
	movl K+4,%eax; \
	movl DES_SPE_L+0x200(%ebx),Rl; \
	xorl Rh,%eax; \
	xorl Rl,Ll; \
	movl DES_SPE_H+0x200(%ebx),Rl; \
	xorl Rl,Lh; \
	movl DES_SPE_L+0x300(%edx),Rl; \
	xorl Rl,Ll; \
	movb %al,%bl; \
	movl DES_SPE_H+0x300(%edx),Rl; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	xorl Rl,Lh; \
	movl DES_SPE_L+0x400(%ebx),Rl; \
	xorl Rl,Ll; \
	movl DES_SPE_H+0x400(%ebx),Rl; \
	xorl Rl,Lh; \
	movl DES_SPE_L+0x500(%edx),Rl; \
	xorl Rl,Ll; \
	movb %al,%bl; \
	movl DES_SPE_H+0x500(%edx),Rl; \
	movb %ah,%dl; \
	xorl Rl,Lh; \
	movl DES_SPE_L+0x600(%ebx),Rl; \
	xorl Rl,Ll; \
	movl DES_SPE_H+0x600(%ebx),Rl; \
	xorl Rl,Lh; \
	movl DES_SPE_L+0x700(%edx),Rl; \
	xorl Rl,Ll; \
	movl K+8,%eax; \
	movl DES_SPE_H+0x700(%edx),Rl; \
	xorl Ll,%eax; \
	xorl Rl,Lh; \
	movb %al,%bl; \
	movl DES_SavedL,Rl; \
	movb %ah,%dl; \
	movl Ll,DES_SavedL; \
	shrl $16,%eax; \
	movl DES_SPE_L(%ebx),Ll; \
	xorl Ll,Rl; \
	movl DES_SPE_H(%ebx),Ll; \
	xorl Ll,Rh; \
	movl DES_SPE_L+0x100(%edx),Ll; \
	xorl Ll,Rl; \
	movl DES_SPE_H+0x100(%edx),Ll; \
	movb %al,%bl; \
	xorl Ll,Rh; \
	movb %ah,%dl; \
	movl K+12,%eax; \
	movl DES_SPE_L+0x200(%ebx),Ll; \
	xorl Lh,%eax; \
	xorl Ll,Rl; \
	movl DES_SPE_H+0x200(%ebx),Ll; \
	xorl Ll,Rh; \
	movl DES_SPE_L+0x300(%edx),Ll; \
	xorl Ll,Rl; \
	movb %al,%bl; \
	movl DES_SPE_H+0x300(%edx),Ll; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	xorl Ll,Rh; \
	movl DES_SPE_L+0x400(%ebx),Ll; \
	xorl Ll,Rl; \
	movl DES_SPE_H+0x400(%ebx),Ll; \
	xorl Ll,Rh; \
	movl DES_SPE_L+0x500(%edx),Ll; \
	xorl Ll,Rl; \
	movb %al,%bl; \
	movl DES_SPE_H+0x500(%edx),Ll; \
	movb %ah,%dl; \
	xorl Ll,Rh; \
	movl DES_SPE_L+0x600(%ebx),Ll; \
	xorl Ll,Rl; \
	movl DES_SPE_H+0x600(%ebx),Ll; \
	xorl Ll,Rh; \
	movl DES_SPE_L+0x700(%edx),Ll

#define DES_2_ROUNDS_P1(K) \
	DES_2_ROUNDS_START_P1(K); \
	xorl Ll,Rl; \
	movl DES_SPE_H+0x700(%edx),Ll; \
	xorl Ll,Rh; \
	movl K+16,%eax; \
	movl DES_SavedL,Ll

DO_ALIGN(12)
DES_std_crypt_P1:
	DES_CRYPT_START
DES_loop_P1:
	DES_2_ROUNDS_P1(DES_KS_copy)
	DES_2_ROUNDS_P1(DES_KS_copy+16)
	DES_2_ROUNDS_P1(DES_KS_copy+32)
	DES_2_ROUNDS_P1(DES_KS_copy+48)
	DES_2_ROUNDS_P1(DES_KS_copy+64)
	DES_2_ROUNDS_P1(DES_KS_copy+80)
	DES_2_ROUNDS_P1(DES_KS_copy+96)
	DES_2_ROUNDS_START_P1(DES_KS_copy+112)
	xorl Rl,Ll
	movl DES_SPE_H+0x700(%edx),%eax
	xorl Rh,%eax
	movl Lh,Rh
	movl %eax,Lh
	movl DES_count_tmp,%eax
	movl DES_SavedL,Rl
	decl %eax
	movl %eax,DES_count_tmp
	movl DES_KS_copy,%eax
	jnz DES_loop_P1
	DES_CRYPT_END

/*
 * Generic x86 version.
 */

#define DES_2_ROUNDS_START_ANY(K) \
	xorl Rl,%eax; \
	movb %al,%bl; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	xorl DES_SPE_L(%ebx),Ll; \
	xorl DES_SPE_H(%ebx),Lh; \
	movb %al,%bl; \
	xorl DES_SPE_L+0x100(%edx),Ll; \
	xorl DES_SPE_H+0x100(%edx),Lh; \
	movb %ah,%dl; \
	movl K+4,%eax; \
	xorl DES_SPE_L+0x200(%ebx),Ll; \
	xorl Rh,%eax; \
	xorl DES_SPE_H+0x200(%ebx),Lh; \
	movb %al,%bl; \
	xorl DES_SPE_L+0x300(%edx),Ll; \
	xorl DES_SPE_H+0x300(%edx),Lh; \
	movb %ah,%dl; \
	xorl DES_SPE_L+0x400(%ebx),Ll; \
	shrl $16,%eax; \
	xorl DES_SPE_H+0x400(%ebx),Lh; \
	movb %al,%bl; \
	xorl DES_SPE_L+0x500(%edx),Ll; \
	xorl DES_SPE_H+0x500(%edx),Lh; \
	movb %ah,%dl; \
	xorl DES_SPE_L+0x600(%ebx),Ll; \
	xorl DES_SPE_H+0x600(%ebx),Lh; \
	xorl DES_SPE_L+0x700(%edx),Ll; \
	movl K+8,%eax; \
	xorl Ll,%eax; \
	movb %al,%bl; \
	xorl DES_SPE_H+0x700(%edx),Lh; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	xorl DES_SPE_L(%ebx),Rl; \
	xorl DES_SPE_H(%ebx),Rh; \
	movb %al,%bl; \
	xorl DES_SPE_L+0x100(%edx),Rl; \
	xorl DES_SPE_H+0x100(%edx),Rh; \
	movb %ah,%dl; \
	movl K+12,%eax; \
	xorl DES_SPE_L+0x200(%ebx),Rl; \
	xorl Lh,%eax; \
	xorl DES_SPE_H+0x200(%ebx),Rh; \
	movb %al,%bl; \
	xorl DES_SPE_L+0x300(%edx),Rl; \
	xorl DES_SPE_H+0x300(%edx),Rh; \
	movb %ah,%dl; \
	shrl $16,%eax; \
	xorl DES_SPE_L+0x400(%ebx),Rl; \
	xorl DES_SPE_H+0x400(%ebx),Rh; \
	movb %al,%bl; \
	xorl DES_SPE_L+0x500(%edx),Rl; \
	xorl DES_SPE_H+0x500(%edx),Rh; \
	movb %ah,%dl

#define DES_2_ROUNDS_ANY(K) \
	DES_2_ROUNDS_START_ANY(K); \
	xorl DES_SPE_L+0x600(%ebx),Rl; \
	xorl DES_SPE_H+0x600(%ebx),Rh; \
	movl K+16,%eax; \
	xorl DES_SPE_L+0x700(%edx),Rl; \
	xorl DES_SPE_H+0x700(%edx),Rh

DO_ALIGN(12)
DES_std_crypt_generic:
	DES_CRYPT_START
DES_loop_generic:
	DES_2_ROUNDS_ANY(DES_KS_copy)
	DES_2_ROUNDS_ANY(DES_KS_copy+16)
	DES_2_ROUNDS_ANY(DES_KS_copy+32)
	DES_2_ROUNDS_ANY(DES_KS_copy+48)
	DES_2_ROUNDS_ANY(DES_KS_copy+64)
	DES_2_ROUNDS_ANY(DES_KS_copy+80)
	DES_2_ROUNDS_ANY(DES_KS_copy+96)
	DES_2_ROUNDS_START_ANY(DES_KS_copy+112)
	movl Ll,%eax
	xorl DES_SPE_L+0x600(%ebx),Rl
	xorl DES_SPE_H+0x600(%ebx),Rh
	movl DES_SPE_L+0x700(%edx),Ll
	xorl Rl,Ll
	movl %eax,Rl
	movl Lh,%eax
	movl DES_SPE_H+0x700(%edx),Lh
	xorl Rh,Lh
	decl DES_count_tmp
	movl %eax,Rh
	movl DES_KS_copy,%eax
	jnz DES_loop_generic
	DES_CRYPT_END

#define DES_xor1(ofs) \
	movl DES_KS_current+ofs,%esi; \
	movl DES_KS_current+ofs+4,%edi; \
	movl ofs(%edx),%eax; \
	movl ofs+4(%edx),%ecx; \
	xorl %esi,%eax; \
	xorl %edi,%ecx; \
	movl %eax,DES_KS_current+ofs; \
	movl %ecx,DES_KS_current+ofs+4

DO_ALIGN(4)
.globl DES_xor_key1
DES_xor_key1:
	movl 4(%esp),%edx
	pushl %esi
	pushl %edi
	DES_xor1(0)
	DES_xor1(32)
	DES_xor1(8)
	DES_xor1(16)
	DES_xor1(24)
	DES_xor1(40)
	DES_xor1(48)
	DES_xor1(56)
	DES_xor1(64)
	DES_xor1(96)
	DES_xor1(72)
	DES_xor1(80)
	DES_xor1(88)
	DES_xor1(104)
	DES_xor1(112)
	DES_xor1(120)
	popl %edi
	popl %esi
	ret

#define DES_xor2(ofs) \
	movl ofs(%edx),%eax; \
	movl ofs+4(%edx),%ecx; \
	movl ofs(%ebx),%esi; \
	movl ofs+4(%ebx),%edi; \
	xorl %esi,%eax; \
	xorl %edi,%ecx; \
	movl DES_KS_current+ofs,%esi; \
	movl DES_KS_current+ofs+4,%edi; \
	xorl %esi,%eax; \
	xorl %edi,%ecx; \
	movl %eax,DES_KS_current+ofs; \
	movl %ecx,DES_KS_current+ofs+4

DO_ALIGN(4)
.globl DES_xor_key2
DES_xor_key2:
	pushl %ebx
	movl 8(%esp),%edx
	movl 12(%esp),%ebx
	pushl %esi
	pushl %edi
	DES_xor2(0)
	DES_xor2(32)
	DES_xor2(8)
	DES_xor2(16)
	DES_xor2(24)
	DES_xor2(40)
	DES_xor2(48)
	DES_xor2(56)
	DES_xor2(64)
	DES_xor2(96)
	DES_xor2(72)
	DES_xor2(80)
	DES_xor2(88)
	DES_xor2(104)
	DES_xor2(112)
	DES_xor2(120)
	popl %edi
	popl %esi
	popl %ebx
	ret

#endif

.data

/*
 * Weird alignments to make sure KS address's bits 5-11 never match current
 * instruction pointer's bits 5-11.
 */
#ifdef DUMBAS
DO_ALIGN(12)
.zero 0x1000 - 32 - 128
#elif defined(__DJGPP__)
.text
DO_ALIGN(12)
.space (0x1000 - 32 - 128 - 0xE0)
#else
DO_ALIGN(12)
.space (0x1000 - 32 - 128)
#endif

#if !DES_X2
/*
 * The function pointer, set by CPU_detect().
 */
.globl DES_std_crypt
DES_std_crypt:
.long DES_std_crypt_generic

DES_SavedL:
.long 0
#endif

/*
 * These are in .data, not .bss, to get them in a cache line that has to be
 * already loaded at DES_std_crypt() startup.
 */
.globl DES_IV
DES_IV:
#ifdef DUMBAS
.zero 16
#else
.space 16
#endif

.globl DES_count
DES_count:
.long 0

DES_count_tmp:
.long 0

DO_ALIGN(5)
.globl DES_KS_copy
DES_KS_copy:
#ifdef DUMBAS
.zero 128
#else
.space 128
#endif

#ifdef __DJGPP__
.space 32
#endif

#ifndef BSD
.bss
DO_ALIGN(5)
#endif

#if DES_X2

.globl DES_SPE_F
DES_SPE_F:
#ifdef DUMBAS
.zero 0x1000
#else
.space 0x1000
#endif

#else

.globl DES_SPE_L
DES_SPE_L:
#ifdef DUMBAS
.zero 0x800
#else
.space 0x800
#endif

/*
 * Cache bank shift. This should be at least as large as the word size, but
 * smaller than the cache line size. (At least on Intel Pentium, two loads
 * can't dual issue if accessing the same cache bank.)
 */
.long 0

.globl DES_SPE_H
DES_SPE_H:
#ifdef DUMBAS
.zero 0x800
#else
.space 0x800
#endif

#endif

DO_ALIGN(5)

.globl DES_KS_current
DES_KS_current:
#ifdef DUMBAS
.zero 128
#else
.space 128
#endif

.globl DES_KS_table
DES_KS_table:
#ifdef DUMBAS
.zero 0x20000
#else
.space (8 * 128 * 16 * 8)
#endif

/*
 * MD5 stuff, optimized for Intel Pentium only right now.
 */

#define S11				7
#define S12				12
#define S13				17
#define S14				22
#define S21				5
#define S22				9
#define S23				14
#define S24				20
#define S31				4
#define S32				11
#define S33				16
#define S34				23
#define S41				6
#define S42				10
#define S43				15
#define S44				21

#define Ca				0x67452301
#define Cb				0xefcdab89
#define Cc				0x98badcfe
#define Cd				0x10325476

#define a				%esi
#define b				%edi
#define c				%edx
#define d				%ebx
#undef tmp1
#undef tmp2
#define tmp1				%eax
#define tmp2				%ecx
#ifdef DUMBAS
#define x(i)				i+i+i+i(%ebp)
#else
#define x(i)				4*i(%ebp)
#endif

.text

#define FF(a, b, c, d, x, s, ac) \
	andl b,tmp1; \
	addl x,a; \
	xorl d,tmp1; \
	addl $ac,a; \
	addl tmp1,a; \
	movl b,tmp1; \
	roll $s,a; \
	xorl c,tmp1; \
	addl b,a

#define GG(a, b, c, d, x, s, ac) \
	movl x,tmp2; \
	xorl b,tmp1; \
	addl tmp2,a; \
	andl d,tmp1; \
	addl $ac,a; \
	xorl c,tmp1; \
	addl tmp1,a; \
	roll $s,a; \
	movl b,tmp1; \
	addl b,a

#define HH(a, b, c, d, x, s, ac) \
	movl c,tmp1; \
	addl tmp2,a; \
	xorl d,tmp1; \
	addl $ac,a; \
	xorl b,tmp1; \
	movl x,tmp2; \
	addl tmp1,a; \
	roll $s,a; \
	addl b,a

#define II(a, b, c, d, x, s, ac) \
	xorl d,tmp2; \
	addl x,a; \
	orl b,tmp2; \
	addl $ac,a; \
	xorl c,tmp2; \
	addl tmp2,a; \
	movl $-1,tmp2; \
	roll $s,a; \
	addl b,a

DO_ALIGN(5)
.globl MD5_body
MD5_body:
	pushl %ebp
	movl 8(%esp),%ebp
	pushl %ebx
	pushl %esi
	pushl %edi
/* Round 1 */
	movl x(0),a
	movl x(1),d
	addl $0xd76aa477,a
	roll $S11,a
	addl $0xf8fa0bcc,d
	addl $Cb,a
	movl x(2),c
	movl a,tmp1
	movl a,tmp2
	andl $0x77777777,tmp1
	xorl $Cb,tmp2
	xorl $Cc,tmp1
	addl $0xbcdb4dd9,c
	addl tmp1,d
	roll $S12,d
	addl a,d
	andl d,tmp2
	xorl $Cb,tmp2
	addl tmp2,c
	movl d,tmp1
	roll $S13,c
	xorl a,tmp1
	addl d,c
	andl c,tmp1
	movl x(3),b
	xorl a,tmp1
	addl $0xb18b7a77,b
	addl tmp1,b
	movl c,tmp1
	roll $S14,b
	xorl d,tmp1
	addl c,b
	FF (a, b, c, d, x( 4), S11, 0xf57c0faf) /* 5 */
	FF (d, a, b, c, x( 5), S12, 0x4787c62a) /* 6 */
	FF (c, d, a, b, x( 6), S13, 0xa8304613) /* 7 */
	FF (b, c, d, a, x( 7), S14, 0xfd469501) /* 8 */
	FF (a, b, c, d, x( 8), S11, 0x698098d8) /* 9 */
	FF (d, a, b, c, x( 9), S12, 0x8b44f7af) /* 10 */
	FF (c, d, a, b, x(10), S13, 0xffff5bb1) /* 11 */
	FF (b, c, d, a, x(11), S14, 0x895cd7be) /* 12 */
	FF (a, b, c, d, x(12), S11, 0x6b901122) /* 13 */
	FF (d, a, b, c, x(13), S12, 0xfd987193) /* 14 */
	FF (c, d, a, b, x(14), S13, 0xa679438e) /* 15 */
	andl c,tmp1
	addl $0x49b40821,b
	xorl a,tmp1
	addl tmp1,b
	roll $S14,b
	movl c,tmp1
	addl c,b
/* Round 2 */
	GG (a, b, c, d, x( 1), S21, 0xf61e2562) /* 17 */
	GG (d, a, b, c, x( 6), S22, 0xc040b340) /* 18 */
	GG (c, d, a, b, x(11), S23, 0x265e5a51) /* 19 */
	GG (b, c, d, a, x( 0), S24, 0xe9b6c7aa) /* 20 */
	GG (a, b, c, d, x( 5), S21, 0xd62f105d) /* 21 */
	GG (d, a, b, c, x(10), S22,  0x2441453) /* 22 */
	xorl d,tmp1
	andl b,tmp1
	addl $0xd8a1e681,c
	xorl a,tmp1
	addl tmp1,c
	roll $S23,c
	movl d,tmp1
	addl d,c
	GG (b, c, d, a, x( 4), S24, 0xe7d3fbc8) /* 24 */
	GG (a, b, c, d, x( 9), S21, 0x21e1cde6) /* 25 */
	GG (d, a, b, c, x(14), S22, 0xc33707d6) /* 26 */
	GG (c, d, a, b, x( 3), S23, 0xf4d50d87) /* 27 */
	GG (b, c, d, a, x( 8), S24, 0x455a14ed) /* 28 */
	GG (a, b, c, d, x(13), S21, 0xa9e3e905) /* 29 */
	GG (d, a, b, c, x( 2), S22, 0xfcefa3f8) /* 30 */
	GG (c, d, a, b, x( 7), S23, 0x676f02d9) /* 31 */
	movl x(12),tmp2
	xorl c,tmp1
	addl tmp2,b
	andl a,tmp1
	addl $0x8d2a4c8a,b
	xorl d,tmp1
	movl x(5),tmp2
	addl tmp1,b
	roll $S24,b
	addl c,b
/* Round 3 */
	HH (a, b, c, d, x( 8), S31, 0xfffa3942) /* 33 */
	HH (d, a, b, c, x(11), S32, 0x8771f681) /* 34 */
	HH (c, d, a, b, x(14), S33, 0x6d9d6122) /* 35 */
	HH (b, c, d, a, x( 1), S34, 0xfde5380c) /* 36 */
	HH (a, b, c, d, x( 4), S31, 0xa4beea44) /* 37 */
	HH (d, a, b, c, x( 7), S32, 0x4bdecfa9) /* 38 */
	HH (c, d, a, b, x(10), S33, 0xf6bb4b60) /* 39 */
	HH (b, c, d, a, x(13), S34, 0xbebfbc70) /* 40 */
	HH (a, b, c, d, x( 0), S31, 0x289b7ec6) /* 41 */
	HH (d, a, b, c, x( 3), S32, 0xeaa127fa) /* 42 */
	HH (c, d, a, b, x( 6), S33, 0xd4ef3085) /* 43 */
	HH (b, c, d, a, x( 9), S34,  0x4881d05) /* 44 */
	HH (a, b, c, d, x(12), S31, 0xd9d4d039) /* 45 */
	HH (d, a, b, c, x( 2), S32, 0xe6db99e5) /* 46 */
	movl a,tmp1
	xorl b,tmp1
	addl $0x1fa27cf8,c
	xorl d,tmp1
	addl tmp1,c
	roll $S33,c
	addl d,c
	HH (b, c, d, a,   $-1, S34, 0xc4ac5665) /* 48 */
/* Round 4 */
	II (a, b, c, d, x( 0), S41, 0xf4292244) /* 49 */
	II (d, a, b, c, x( 7), S42, 0x432aff97) /* 50 */
	II (c, d, a, b, x(14), S43, 0xab9423a7) /* 51 */
	II (b, c, d, a, x( 5), S44, 0xfc93a039) /* 52 */
	II (a, b, c, d, x(12), S41, 0x655b59c3) /* 53 */
	II (d, a, b, c, x( 3), S42, 0x8f0ccc92) /* 54 */
	II (c, d, a, b, x(10), S43, 0xffeff47d) /* 55 */
	II (b, c, d, a, x( 1), S44, 0x85845dd1) /* 56 */
	II (a, b, c, d, x( 8), S41, 0x6fa87e4f) /* 57 */
	xorl c,tmp2
	orl a,tmp2
	addl $0xfe2ce6e0,d
	xorl b,tmp2
	addl tmp2,d
	movl $-1,tmp2
	roll $S42,d
	addl a,d
	II (c, d, a, b, x( 6), S43, 0xa3014314) /* 59 */
	II (b, c, d, a, x(13), S44, 0x4e0811a1) /* 60 */
	II (a, b, c, d, x( 4), S41, 0xf7537e82) /* 61 */
	II (d, a, b, c, x(11), S42, 0xbd3af235) /* 62 */
	II (c, d, a, b, x( 2), S43, 0x2ad7d2bb) /* 63 */
	xorl a,tmp2
	addl x(9),b
	orl c,tmp2
	addl $0xeb86d391,b
	xorl d,tmp2
	addl tmp2,b
	movl 24(%esp),tmp1
	roll $S44,b
/* Update the state and return */
	addl $Ca,a
	addl $Cd,d
	movl a,(tmp1)
	leal Cb(b,c),b
	addl $Cc,c
	movl b,4(tmp1)
	movl c,8(tmp1)
	movl d,12(tmp1)
	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret

#if BF_ASM
/*
 * Blowfish stuff.
 */

#ifdef DUMBAS
#define P(N)				BF_current+0x1000+N+N+N+N
#else
#define P(N)				BF_current+0x1000+4*N
#endif

/*
 * Intel Pentium optimized version, extra operations are used to avoid
 * imperfect pairing.  Also used on the Pentium 4.
 */

#undef L
#undef R
#undef tmp1
#undef tmp2
#define L				%esi
#define R				%edi
#define tmp1				%eax
#define tmp1_lo				%al
#define tmp2				%ecx
#define tmp2_hi				%ch
#define tmp3				%edx
#define tmp3_lo				%dl
#define tmp4				%ebx
#define tmp4_hi				%bh
#define tmp5				%ebp

.text

#define BF_ROUND_P1(L, R, N) \
	xorl L,tmp2; \
	xorl tmp1,tmp1; \
	movl tmp2,L; \
	shrl $16,tmp2; \
	movl L,tmp4; \
	movb tmp2_hi,tmp1_lo; \
	andl $0xFF,tmp2; \
	movb tmp4_hi,tmp3_lo; \
	andl $0xFF,tmp4; \
	movl BF_current(,tmp1,4),tmp1; \
	movl BF_current+0x400(,tmp2,4),tmp5; \
	addl tmp5,tmp1; \
	movl BF_current+0x800(,tmp3,4),tmp5; \
	xorl tmp5,tmp1; \
	movl BF_current+0xC00(,tmp4,4),tmp5; \
	addl tmp1,tmp5; \
	movl P(N)+4,tmp2; \
	xorl tmp5,R

#define BF_ENCRYPT_START_P1 \
	BF_ROUND_P1(L, R, 0); \
	BF_ROUND_P1(R, L, 1); \
	BF_ROUND_P1(L, R, 2); \
	BF_ROUND_P1(R, L, 3); \
	BF_ROUND_P1(L, R, 4); \
	BF_ROUND_P1(R, L, 5); \
	BF_ROUND_P1(L, R, 6); \
	BF_ROUND_P1(R, L, 7); \
	BF_ROUND_P1(L, R, 8); \
	BF_ROUND_P1(R, L, 9); \
	BF_ROUND_P1(L, R, 10); \
	BF_ROUND_P1(R, L, 11); \
	BF_ROUND_P1(L, R, 12); \
	BF_ROUND_P1(R, L, 13); \
	BF_ROUND_P1(L, R, 14); \
	BF_ROUND_P1(R, L, 15); \
	movl BF_ptr,tmp5; \
	xorl L,tmp2; \
	movl P(17),L

#define BF_ENCRYPT_END_P1 \
	xorl R,L; \
	movl tmp2,R

DO_ALIGN(12)
.globl BF_body_P1
BF_body_P1:
	pushl %ebp
	pushl %ebx
	pushl %esi
	pushl %edi
	xorl L,L
	xorl R,R
	movl P(0),tmp2
	xorl tmp3,tmp3
	movl $P(0),BF_ptr
BF_loop_P_P1:
	BF_ENCRYPT_START_P1
	addl $8,tmp5
	BF_ENCRYPT_END_P1
	movl tmp5,BF_ptr
	cmpl $P(18),tmp5
	movl L,-8(tmp5)
	movl R,-4(tmp5)
	movl P(0),tmp2
	jb BF_loop_P_P1
#ifndef DONT_AVOID_PENTIUMPRO_FAMILY_PARTIAL_REGISTER_STALLS
	xorl tmp3,tmp3
#endif
	movl $BF_current,BF_ptr
BF_loop_S_P1:
	BF_ENCRYPT_START_P1
	BF_ENCRYPT_END_P1
	movl P(0),tmp2
	movl L,(tmp5)
	movl R,4(tmp5)
	BF_ENCRYPT_START_P1
	BF_ENCRYPT_END_P1
	movl P(0),tmp2
	movl L,8(tmp5)
	movl R,12(tmp5)
	BF_ENCRYPT_START_P1
	BF_ENCRYPT_END_P1
	movl P(0),tmp2
	movl L,16(tmp5)
	movl R,20(tmp5)
	BF_ENCRYPT_START_P1
	addl $32,tmp5
	BF_ENCRYPT_END_P1
	movl tmp5,BF_ptr
	cmpl $BF_current+0x1000,tmp5
	movl P(0),tmp2
	movl L,-8(tmp5)
	movl R,-4(tmp5)
	jb BF_loop_S_P1
	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret

/*
 * Generic x86 version.
 */

#undef L
#undef R
#undef tmp1
#undef tmp1_lo
#undef tmp2
#undef tmp2_hi
#undef tmp3
#undef tmp3_lo
#undef tmp4
#undef tmp4_hi
#undef tmp5
#define L				%edx
#define L_lo				%dl
#define L_hi				%dh
#define R				%ebx
#define R_lo				%bl
#define R_hi				%bh
#define tmp1				%eax
#define tmp2				%ecx
#define tmp2_hi				%ch
#define tmp3				%esi
#define tmp4				%edi
#define ptr				%ebp

#define BF_ROUND_START(L, L_lo, L_hi) \
	shldl $16,L,tmp2; \
	movzbl L_hi,tmp3; \
	movzbl tmp2_hi,tmp1; \
	andl $0xFF,tmp2; \
	movzbl L_lo,tmp4; \
	movl BF_current(,tmp1,4),tmp1; \
	addl BF_current+0x400(,tmp2,4),tmp1

#define BF_ROUND_END(R, N) \
	xorl BF_current+0x800(,tmp3,4),tmp1; \
	addl BF_current+0xC00(,tmp4,4),tmp1; \
	xorl P(N)+4,R; \
	xorl tmp1,R

#define BF_ROUND(L, L_lo, L_hi, R, N) \
	BF_ROUND_START(L, L_lo, L_hi); \
	BF_ROUND_END(R, N)

#define BF_ENCRYPT_START \
	xorl P(0),L; \
	BF_ROUND(L, L_lo, L_hi, R, 0); \
	BF_ROUND(R, R_lo, R_hi, L, 1); \
	BF_ROUND(L, L_lo, L_hi, R, 2); \
	BF_ROUND(R, R_lo, R_hi, L, 3); \
	BF_ROUND(L, L_lo, L_hi, R, 4); \
	BF_ROUND(R, R_lo, R_hi, L, 5); \
	BF_ROUND(L, L_lo, L_hi, R, 6); \
	BF_ROUND(R, R_lo, R_hi, L, 7); \
	BF_ROUND(L, L_lo, L_hi, R, 8); \
	BF_ROUND(R, R_lo, R_hi, L, 9); \
	BF_ROUND(L, L_lo, L_hi, R, 10); \
	BF_ROUND(R, R_lo, R_hi, L, 11); \
	BF_ROUND(L, L_lo, L_hi, R, 12); \
	BF_ROUND(R, R_lo, R_hi, L, 13); \
	BF_ROUND(L, L_lo, L_hi, R, 14); \
	BF_ROUND_START(R, R_lo, R_hi); \
	movl R,tmp2; \
	movl P(16),R; \
	xorl BF_current+0x800(,tmp3,4),tmp1; \
	xorl L,R; \
	addl BF_current+0xC00(,tmp4,4),tmp1; \
	movl P(17),L; \
	xorl tmp1,R; \

#define BF_ENCRYPT_END \
	xorl tmp2,L

DO_ALIGN(12)
.globl BF_body_generic
BF_body_generic:
	pushl %ebp
	pushl %ebx
	pushl %esi
	pushl %edi
	xorl L,L
	xorl R,R
	movl $P(0),ptr
BF_loop_P_generic:
	BF_ENCRYPT_START
	addl $8,ptr
	BF_ENCRYPT_END
	cmpl $P(18),ptr
	movl L,-8(ptr)
	movl R,-4(ptr)
	jb BF_loop_P_generic
	movl $BF_current,ptr
BF_loop_S_generic:
	BF_ENCRYPT_START
	BF_ENCRYPT_END
	movl L,(ptr)
	movl R,4(ptr)
	BF_ENCRYPT_START
	BF_ENCRYPT_END
	movl L,8(ptr)
	movl R,12(ptr)
	BF_ENCRYPT_START
	BF_ENCRYPT_END
	movl L,16(ptr)
	movl R,20(ptr)
	BF_ENCRYPT_START
	addl $32,ptr
	BF_ENCRYPT_END
	cmpl $BF_current+0x1000,ptr
	movl L,-8(ptr)
	movl R,-4(ptr)
	jb BF_loop_S_generic
	popl %edi
	popl %esi
	popl %ebx
	popl %ebp
	ret

#ifdef BSD
.data
#else
.bss
#endif

#ifdef DUMBAS
DO_ALIGN(12)
.zero 0x1000 - 96
#elif defined(__DJGPP__)
.text
DO_ALIGN(12)
.space (0x1000 - 96 - 0x100)
#else
DO_ALIGN(12)
.space (0x1000 - 96)
#endif

.globl BF_current
BF_current:
#ifdef DUMBAS
.zero 0x1000 + 72
#else
.space (0x1000 + 72)
#endif

BF_ptr:
.long 0

/*
 * The function pointer, set by CPU_detect().
 */
.globl BF_body
BF_body:
.long 0

#ifdef __DJGPP__
.space 32
#endif

/* Blowfish stuff ends here */
#endif

/*
 * CPU detection.
 */

#define EF_ID				$0x00200000
#define CF_MMX				$0x00800000
#define CF_SSE2				$0x04000000
#define CF_XSAVE_OSXSAVE_AVX		$0x1C000000
#define CF_XOP				$0x00000800
/* "GenuineIntel" */
#define CV_INTEL			$0x6C65746E
/* "AuthenticAMD" */
#define CV_AMD				$0x444D4163
/* "CentaurHauls" */
#define CV_CENTAUR			$0x736C7561

.text

#if !DES_X2
#define cpuid \
	.byte 0x0F; \
	.byte 0xA2
#endif

.globl CPU_detect
CPU_detect:
	pushl %ebx
#if BF_ASM
	movl $BF_body_generic,BF_body
#endif
	pushfl
	pushfl
	xorl EF_ID,(%esp)
	popfl
	pushfl
	popl %eax
	xorl (%esp),%eax
	popfl
	andl EF_ID,%eax
	jz CPU_detect_ret		/* 386/486 */
	xorl %eax,%eax
	cpuid
	testl %eax,%eax
	jz CPU_detect_ret		/* Newer 486s */
	pushl %ecx
	movl $1,%eax
	cpuid
#if defined(CPU_REQ_AVX) || defined(CPU_REQ_XOP)
	andl CF_XSAVE_OSXSAVE_AVX,%ecx
	cmpl CF_XSAVE_OSXSAVE_AVX,%ecx
	jne CPU_detect_pop_ecx_fail
	xorl %ecx,%ecx
	pushl %eax
	pushl %edx
	xgetbv
	andb $0x6,%al
	cmpb $0x6,%al
	popl %edx
	popl %eax
	je CPU_detect_AVX
CPU_detect_pop_ecx_fail:
	popl %ecx
	xorl %eax,%eax
	jmp CPU_detect_ret
CPU_detect_AVX:
#endif
#ifdef CPU_REQ_XOP
	pushl %eax
	pushl %edx
	movl $0x80000000,%eax
	cpuid
	movl $0x80000001,%edx
	cmpl %edx,%eax
	jl CPU_detect_no_XOP
	xchgl %edx,%eax
	cpuid
	testl CF_XOP,%ecx
	jnz CPU_detect_XOP
CPU_detect_no_XOP:
	popl %edx
	popl %eax
	jmp CPU_detect_pop_ecx_fail
CPU_detect_XOP:
	popl %edx
	popl %eax
#endif
	popl %ecx
#if DES_BS_VECTOR >= 4
	xchgl %edx,%eax
	andl CF_SSE2,%eax
	jz CPU_detect_ret		/* No SSE2 */
	xchgl %edx,%eax
#elif DES_X2
	xchgl %edx,%eax
	andl CF_MMX,%eax
	jz CPU_detect_ret		/* No MMX */
	xchgl %edx,%eax
#endif
	andl $0xF0FF0,%eax		/* Extended model, family, and model */
	orb $1,%al			/* Detected a suitable CPU */
	cmpl CV_AMD,%ecx
	je CPU_detect_AMD		/* Is an AMD processor */
	cmpl CV_CENTAUR,%ecx
	je CPU_detect_P1		/* Is a Centaur Technology processor */
	cmpl CV_INTEL,%ecx
	jne CPU_detect_ret		/* Not an Intel processor */
	cmpb $5,%ah
	je CPU_detect_P1		/* Intel Pentium */
	cmpb $15,%ah
	je CPU_detect_P1		/* Intel Pentium 4 */
	cmpl $0x106a1,%eax		/* Family 6, model 26 */
	je CPU_detect_i7		/* Core i7 or Xeon W5580/W5590 */
	jmp CPU_detect_ret
CPU_detect_AMD:
	cmpb $6,%ah
	je CPU_detect_P1		/* AMD Athlon */
	cmpb $15,%ah
	jne CPU_detect_ret		/* Neither AMD Athlon nor AMD64 */
CPU_detect_P1:
/*
 * Enable Intel Pentium optimizations when running on one of:
 *
 * Intel Pentium
 * Intel Pentium 4
 * AMD Athlon
 * AMD64 processors
 * Centaur Technology processors (IDT Winchip to VIA C3 and beyond)
 *
 */
#if !DES_X2
	movl $DES_std_crypt_P1,DES_std_crypt
#endif
CPU_detect_i7:
#if BF_ASM
	movl $BF_body_P1,BF_body
#endif
CPU_detect_ret:
	movzbl %al,%eax
	popl %ebx
	ret

#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",@progbits
#endif
