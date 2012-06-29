/* Copyright (c) 2003 Simon Marechal
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "arch.h"

// extern int mdfivemmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));

#ifdef UNDERSCORES
#define mdfivemmx	_mdfivemmx
#define mdfivemmx_noinit_sizeupdate _mdfivemmx_noinit_sizeupdate
#define mdfivemmx_noinit_nosizeupdate _mdfivemmx_noinit_nosizeupdate
#define mdfivemmx_noinit_uniformsizeupdate _mdfivemmx_noinit_uniformsizeupdate
#define mdfivemmx_nosizeupdate _mdfivemmx_nosizeupdate
// These are the VC 'param marshalling' function stubs.  They are __fastcall functions, and have
// to be 'properly' decorated with the @'s   The @12 trailing is due to 12 bytes of params.
#ifdef __MINGW32__
#define mdfivemmx_VC @mdfivemmx_VC@12
#define mdfivemmx_nosizeupdate_VC @mdfivemmx_nosizeupdate_VC@12
#define mdfivemmx_noinit_sizeupdate_VC @mdfivemmx_noinit_sizeupdate_VC@12
#define mdfivemmx_noinit_nosizeupdate_VC @mdfivemmx_noinit_nosizeupdate_VC@12
#define mdfivemmx_noinit_uniformsizeupdate_VC @mdfivemmx_noinit_uniformsizeupdate_VC@12
#endif
#endif
.globl mdfivemmx
.globl mdfivemmx_noinit_sizeupdate
.globl mdfivemmx_noinit_nosizeupdate
.globl mdfivemmx_noinit_uniformsizeupdate
.globl mdfivemmx_nosizeupdate
#ifdef __MINGW32__
.globl mdfivemmx_VC
.globl mdfivemmx_nosizeupdate_VC
.globl mdfivemmx_noinit_sizeupdate_VC
.globl mdfivemmx_noinit_nosizeupdate_VC
.globl mdfivemmx_noinit_uniformsizeupdate_VC
#endif

.data
#if defined (MD5_SSE_PARA) && !defined (MMX_COEF)
#define MMX_COEF 4
#endif

// align of 2*MMX_COEF was crashing on SSE2 builds (at least cross compiling from 64 bit linux)
.align(4*MMX_COEF)

#if (MMX_COEF == 2)
const_init_a: ; .long 0x67452301 ; .long 0x67452301
const_init_b: ; .long 0xefcdab89 ; .long 0xefcdab89
const_init_c: ; .long 0x98badcfe ; .long 0x98badcfe
const_init_d: ; .long 0x10325476 ; .long 0x10325476
storea: ; .long 0 ; .long 0
storeb: ; .long 0 ; .long 0
storec: ; .long 0 ; .long 0
stored: ; .long 0 ; .long 0
#define REGMM0 %mm0
#define REGMM1 %mm1
#define REGMM2 %mm2
#define REGMM3 %mm3
#define REGMM4 %mm4
#define REGMM5 %mm5
#define REGMM6 %mm6
#define REGMM7 %mm7
#define MMXMOVE movq
#include "stages_mmx_md5.S"
#else
const_init_a: ; .long 0x67452301 ; .long 0x67452301 ; .long 0x67452301 ; .long 0x67452301
const_init_b: ; .long 0xefcdab89 ; .long 0xefcdab89 ; .long 0xefcdab89 ; .long 0xefcdab89
const_init_c: ; .long 0x98badcfe ; .long 0x98badcfe ; .long 0x98badcfe ; .long 0x98badcfe
const_init_d: ; .long 0x10325476 ; .long 0x10325476 ; .long 0x10325476 ; .long 0x10325476
storea: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storeb: ; .long 0 ; .long 0 ; .long 0 ; .long 0
storec: ; .long 0 ; .long 0 ; .long 0 ; .long 0
stored: ; .long 0 ; .long 0 ; .long 0 ; .long 0
#define REGMM0 %xmm0
#define REGMM1 %xmm1
#define REGMM2 %xmm2
#define REGMM3 %xmm3
#define REGMM4 %xmm4
#define REGMM5 %xmm5
#define REGMM6 %xmm6
#define REGMM7 %xmm7
#define MMXMOVE movapd
#include "stages_sse2_md5.S"
#endif


#define ctxa REGMM0
#define ctxb REGMM1
#define ctxc REGMM2
#define ctxd REGMM3
#define tmp1 REGMM4
#define tmp2 REGMM5
#define tmp3 REGMM6
#define tmp4 REGMM7


//#define F_MMX(x, y, z)			(z ^ (x & (y ^ z)))

#define F(x,y,z) \
	MMXMOVE y, tmp1; \
	pxor z, tmp1; \
	pand x, tmp1; \
	pxor z, tmp1

//#define G_MMX(x, y, z)			(y ^ (z & (x ^ y)))

#define G(x,y,z) \
	MMXMOVE y, tmp1; \
	pxor x, tmp1; \
	pand z, tmp1; \
	pxor y, tmp1

//#define H_MMX(x, y, z)			(x ^ y ^ z)
#define H(x,y,z) \
	MMXMOVE y, tmp1; \
	pxor z, tmp1; \
	pxor x, tmp1

//#define I(x, y, z)			(y ^ (x | ~z))
#define I(x, y, z) \
	MMXMOVE z, tmp1; \
	pandn tmp4, tmp1; \
	por x, tmp1; \
	pxor y, tmp1;


//#define STEP_MMX(f, a, b, c, d, x, s) \
//	(a) += f((b), (c), (d)) + (x); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

//#define STEP(f, a, b, c, d, x, t, s) \
//	(a) += f((b), (c), (d)) + (x) + (t); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
//	(a) += (b);


#define STEP(f, a, b, c, d, x, t, s) \
	f(b, c, d); \
	paddd (x*4*MMX_COEF)(%edx), tmp1; \
	paddd t, a; \
	paddd tmp1, a; \
	MMXMOVE a, tmp3; \
	psrld $(32-s), tmp3; \
	pslld $s, a; \
	por tmp3, a; \
	paddd b, a

#define STEPD(f, a, b, c, d, x, t, s) \
	f(b, c, d); \
	paddd (x*4*MMX_COEF)(%edx), tmp1; \
	paddd t, a; \
	paddd tmp1, a; \
	MMXMOVE a, tmp3; \
	psrld $(32-s), tmp3; \
	pslld $s, a; \
	por tmp3, a; \
	paddd b, a


.text
/*
 * Try to do some asm md5 w/ mmx
 * %eax ptr -> out
 * %edx ptr -> in
 * %ecx n
 */

init:
	MMXMOVE const_init_a, ctxa
	MMXMOVE const_init_b, ctxb
	MMXMOVE const_init_c, ctxc
	MMXMOVE const_init_d, ctxd
	ret;

sizeupdate:
#if (MMX_COEF == 2)
	shl $3, %ecx
	mov %ecx, %ebx
	and $0xffff, %ecx
	shrl $16,  %ebx
	mov %ecx, (14*4*MMX_COEF)(%edx)
	mov %ebx, (14*4*MMX_COEF+4)(%edx)
#else
	mov %ecx, %ebx
        shr $8, %ecx
        and $0xff, %ebx
        shl $3, %ebx
        mov %ebx, (14*16)(%edx)

        mov %ecx, %ebx
        shr $8, %ecx
        and $0xff, %ebx
        shl $3, %ebx
        mov %ebx, (14*16+4)(%edx)

        mov %ecx, %ebx
        shr $8, %ecx
        and $0xff, %ebx
        shl $3, %ebx
        mov %ebx, (14*16+8)(%edx)

        and $0xff, %ecx
        shl $3, %ecx
        mov %ecx, (14*16+12)(%edx)
#endif
	ret

uniformsizeupdate:
	shl $3, %ecx
	mov %ecx, (14*4*MMX_COEF)(%edx)
	mov %ecx, (14*4*MMX_COEF+4)(%edx)
#if (MMX_COEF == 4)
	mov %ecx, (14*4*MMX_COEF+8)(%edx)
	mov %ecx, (14*4*MMX_COEF+12)(%edx)
#endif
	ret

//entry points
mdfivemmx_noinit_sizeupdate:
	pusha
	call sizeupdate
	jmp mdfivemmx_noinit

mdfivemmx_noinit_nosizeupdate:
	pusha
	jmp mdfivemmx_noinit

mdfivemmx_noinit_uniformsizeupdate:
	pusha
	call uniformsizeupdate
	jmp mdfivemmx_noinit

mdfivemmx:
	pusha
	call sizeupdate
	call init
	jmp mdfivemmx_noinit

mdfivemmx_nosizeupdate:
	pusha
	call init
	jmp mdfivemmx_noinit
//end entry points

#ifdef __MINGW32__
// These are 'magic' param marshalling calls.  I am using VC with __fastcall
// syntax.  For that, the edx is correct.  The stack has what should go into
// ecx on it, THEN the return.  Thus, since we do the pusha here, the popa
// at the end of the mdfilemmx_noinit function, and return from there, we
// MUST return back here, and handle the return with a ret $4.  Thus the
// small amount of monkeying around.  The overhead is very minimal, only an
// op or 2 more than the 'native' __atribute(param(3)) type.
mdfivemmx_VC:
    lea mdfivemmx_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx
    call sizeupdate
    call init
    jmp mdfivemmx_noinit
mdfivemmx_VC_exit:
    ret $4

mdfivemmx_nosizeupdate_VC:
    lea mdfivemmx_nosizeupdate_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx
    call init
    jmp mdfivemmx_noinit
mdfivemmx_nosizeupdate_VC_exit:
    ret $4

mdfivemmx_noinit_sizeupdate_VC:
    lea mdfivemmx_noinit_sizeupdate_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx
    call sizeupdate
    jmp mdfivemmx_noinit
    mdfivemmx_noinit_sizeupdate_VC_exit:
    ret $4

mdfivemmx_noinit_nosizeupdate_VC:
    lea mdfivemmx_noinit_nosizeupdate_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx
    jmp mdfivemmx_noinit
    mdfivemmx_noinit_nosizeupdate_VC_exit:
    ret $4

mdfivemmx_noinit_uniformsizeupdate_VC:
    lea mdfivemmx_noinit_uniformsizeupdate_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx
    call uniformsizeupdate
    jmp mdfivemmx_noinit
mdfivemmx_noinit_uniformsizeupdate_VC_exit:
    ret $4

//end entry points
#endif

mdfivemmx_noinit:
	pcmpeqd tmp4, tmp4;
	MMXMOVE ctxa, storea
	MMXMOVE ctxb, storeb
	MMXMOVE ctxc, storec
	MMXMOVE ctxd, stored

	STEP(F, ctxa, ctxb, ctxc, ctxd, 0, const_stage_1, 7)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 1, const_stage_2, 12)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 2, const_stage_3, 17)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 3, const_stage_4, 22)
	STEP(F, ctxa, ctxb, ctxc, ctxd, 4, const_stage_5, 7)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 5, const_stage_6, 12)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 6, const_stage_7, 17)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 7, const_stage_8, 22)
	STEP(F, ctxa, ctxb, ctxc, ctxd, 8, const_stage_9, 7)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 9, const_stage_10, 12)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 10, const_stage_11, 17)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 11, const_stage_12, 22)
	STEP(F, ctxa, ctxb, ctxc, ctxd, 12, const_stage_13, 7)
	STEP(F, ctxd, ctxa, ctxb, ctxc, 13, const_stage_14, 12)
	STEP(F, ctxc, ctxd, ctxa, ctxb, 14, const_stage_15, 17)
	STEP(F, ctxb, ctxc, ctxd, ctxa, 15, const_stage_16, 22)

	STEP(G, ctxa, ctxb, ctxc, ctxd, 1, const_stage_17, 5)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 6, const_stage_18, 9)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 11, const_stage_19, 14)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 0, const_stage_20, 20)
	STEP(G, ctxa, ctxb, ctxc, ctxd, 5, const_stage_21, 5)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 10, const_stage_22, 9)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 15, const_stage_23, 14)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 4, const_stage_24, 20)
	STEP(G, ctxa, ctxb, ctxc, ctxd, 9, const_stage_25, 5)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 14, const_stage_26, 9)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 3, const_stage_27, 14)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 8, const_stage_28, 20)
	STEP(G, ctxa, ctxb, ctxc, ctxd, 13, const_stage_29, 5)
	STEP(G, ctxd, ctxa, ctxb, ctxc, 2, const_stage_30, 9)
	STEP(G, ctxc, ctxd, ctxa, ctxb, 7, const_stage_31, 14)
	STEP(G, ctxb, ctxc, ctxd, ctxa, 12, const_stage_32, 20)

	STEP(H, ctxa, ctxb, ctxc, ctxd, 5, const_stage_33, 4)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 8, const_stage_34, 11)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 11, const_stage_35, 16)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 14, const_stage_36, 23)
	STEP(H, ctxa, ctxb, ctxc, ctxd, 1, const_stage_37, 4)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 4, const_stage_38, 11)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 7, const_stage_39, 16)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 10, const_stage_40, 23)
	STEP(H, ctxa, ctxb, ctxc, ctxd, 13, const_stage_41, 4)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 0, const_stage_42, 11)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 3, const_stage_43, 16)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 6, const_stage_44, 23)
	STEP(H, ctxa, ctxb, ctxc, ctxd, 9, const_stage_45, 4)
	STEP(H, ctxd, ctxa, ctxb, ctxc, 12, const_stage_46, 11)
	STEP(H, ctxc, ctxd, ctxa, ctxb, 15, const_stage_47, 16)
	STEP(H, ctxb, ctxc, ctxd, ctxa, 2, const_stage_48, 23)

	STEP(I, ctxa, ctxb, ctxc, ctxd, 0, const_stage_49, 6)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 7, const_stage_50, 10)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 14, const_stage_51, 15)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 5, const_stage_52, 21)
	STEP(I, ctxa, ctxb, ctxc, ctxd, 12, const_stage_53, 6)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 3, const_stage_54, 10)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 10, const_stage_55, 15)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 1, const_stage_56, 21)
	STEP(I, ctxa, ctxb, ctxc, ctxd, 8, const_stage_57, 6)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 15, const_stage_58, 10)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 6, const_stage_59, 15)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 13, const_stage_60, 21)
	STEP(I, ctxa, ctxb, ctxc, ctxd, 4, const_stage_61, 6)
	STEP(I, ctxd, ctxa, ctxb, ctxc, 11, const_stage_62, 10)
	STEP(I, ctxc, ctxd, ctxa, ctxb, 2, const_stage_63, 15)
	STEP(I, ctxb, ctxc, ctxd, ctxa, 9, const_stage_64, 21)

	paddd storea, ctxa
	paddd storeb, ctxb
	paddd storec, ctxc
	paddd stored, ctxd

	MMXMOVE ctxa, 0(%eax)
	MMXMOVE ctxa, storea
	MMXMOVE ctxb, (4*MMX_COEF)(%eax)
	MMXMOVE ctxb, storeb
	MMXMOVE ctxc, (8*MMX_COEF)(%eax)
	MMXMOVE ctxc, storec
	MMXMOVE ctxd, (12*MMX_COEF)(%eax)
	MMXMOVE ctxd, stored

	popa

	emms

	ret

#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",@progbits
#endif
