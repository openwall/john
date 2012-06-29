/* Copyright (c) 2003 Simon Marechal
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include "arch.h"

#ifdef __sun
/* Sun's assembler doesn't recognize .space */
#define DO_SPACE(size)			.zero size
#else
/* Mac OS X assembler doesn't recognize .zero */
#define DO_SPACE(size)			.space size
#endif

// extern int mdfourmmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
// extern int mdfourmmx_nosizeupdate(unsigned char *out, unsigned char *in, int ignored) __attribute__((regparm(3)));

#if (MMX_COEF == 2)
#ifdef UNDERSCORES
#define mdfourmmx	_mdfourmmx
#define mdfourmmx_nosizeupdate _mdfourmmx_nosizeupdate
#endif
// For proper VC 'param marshalling' function stubs.
#ifdef __MINGW32__
#define mdfourmmx_VC @mdfourmmx_VC@12
#define mdfourmmx_nosizeupdate_VC @mdfourmmx_nosizeupdate_VC@12
.globl mdfourmmx_VC
.globl mdfourmmx_nosizeupdate_VC
#endif

.globl mdfourmmx
.globl mdfourmmx_nosizeupdate

.data

// align of 2*MMX_COEF was crashing on SSE2 builds (at least cross compiling from 64 bit linux)
.align(4*MMX_COEF)

const_init_a:
.long 0x67452301
.long 0x67452301
const_init_b:
.long 0xefcdab89
.long 0xefcdab89
const_init_c:
.long 0x98badcfe
.long 0x98badcfe
const_init_d:
.long 0x10325476
.long 0x10325476

const_stage2:
.long 0x5a827999
.long 0x5a827999
const_stage3:
.long 0x6ed9eba1
.long 0x6ed9eba1

.align(4*MMX_COEF)
buffer:
DO_SPACE(64*2)

#define ctxa %mm0
#define ctxb %mm1
#define ctxc %mm2
#define ctxd %mm3
#define tmp1 %mm4
#define tmp2 %mm5
#define tmp3 %mm6
#define tmp4 %mm7

//#define F_MMX(x, y, z)			(z ^ (x & (y ^ z)))

#define F(x,y,z) \
	movq y, tmp1; \
	pxor z, tmp1; \
	pand x, tmp1; \
	pxor z, tmp1

//#define G_MMX(x, y, z)			((x & (y | z)) | (y & z))

#define G(x,y,z) \
	movq y, tmp1; \
	movq y, tmp2; \
	por z, tmp1; \
	pand z, tmp2; \
	pand x, tmp1; \
	por tmp2, tmp1

//#define H_MMX(x, y, z)			(x ^ y ^ z)
#define H(x,y,z) \
	movq x, tmp1; \
	pxor y, tmp1; \
	pxor z, tmp1

//#define STEP_MMX(f, a, b, c, d, x, s) \
//	(a) += f((b), (c), (d)) + (x); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

#define STEP1(f, a, b, c, d, x, s) \
	f(b, c, d); \
	paddd (x*8)(%edx), tmp1; \
	paddd tmp1, a; \
	movq a, tmp3; \
	pslld $s, a; \
	psrld $(32-s), tmp3; \
	por tmp3, a

#define STEP2(f, a, b, c, d, x, s) \
	f(b, c, d); \
	paddd (x*8)(%edx), tmp1; \
	paddd tmp4, tmp1; \
	paddd tmp1, a; \
	movq a, tmp3; \
	pslld $s, a; \
	psrld $(32-s), tmp3; \
	por tmp3, a

.text
/*
 * Try to do some asm md4 w/ mmx
 * %eax ptr -> out
 * %edx ptr -> in
 * %ecx n
 */

 #ifdef __MINGW32__
// These are 'magic' param marshalling calls to convert VC __fastcall, to
// GCC/GAS register param ordering.  Same as was done in MD5/SHA1. Requires
// MinGW32 to build the .o, and then VC can use that .o file properly.
mdfourmmx_VC:
    lea mdfourmmx_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx
    jmp mdfourmmx_no_push
mdfourmmx_VC_exit:
    ret $4

mdfourmmx_nosizeupdate_VC:
    lea mdfourmmx_nosizeupdate_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx

    jmp mdfourmmx_no_size
mdfourmmx_nosizeupdate_VC_exit:
    ret $4

#endif

mdfourmmx_nosizeupdate:
	pusha
	jmp mdfourmmx_no_size

mdfourmmx:
	 //MD4 Init
	pusha

mdfourmmx_no_push:
	shl $3, %ecx
	mov %ecx, %ebx
	and $0xffff, %ecx
	shrl $16,  %ebx
	// %ecx contient la taille du premier mdp
	// %edx celle du second
	mov %ecx, (14*8)(%edx)
	mov %ebx, (14*8+4)(%edx)

mdfourmmx_no_size:
	movq const_init_a, ctxa
	movq const_init_b, ctxb
	movq const_init_c, ctxc
	movq const_init_d, ctxd

	STEP1(F, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 1, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 2, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 3, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 4, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 5, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 6, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 7, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 8, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 9, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 10, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 11, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 12, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 13, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 14, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 15, 19)

	movq const_stage2, tmp4

	STEP2(G, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 4, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 8, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 12, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 1, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 5, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 9, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 13, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 2, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 6, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 10, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 14, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 3, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 7, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 11, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 15, 13)

	movq const_stage3, tmp4

	STEP2(H, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 8, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 4, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 12, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 2, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 10, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 6, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 14, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 1, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 9, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 5, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 13, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 3, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 11, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 7, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 15, 15)

	paddd const_init_a, ctxa
	paddd const_init_b, ctxb
	paddd const_init_c, ctxc
	paddd const_init_d, ctxd

	movq ctxa, 0(%eax)
	movq ctxb, 8(%eax)
	movq ctxc, 16(%eax)
	movq ctxd, 24(%eax)

	movd ctxa, %eax
	emms

	popa

	ret

#else  //#elif (MMX_COEF == 4)

// extern int mdfoursse2(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));
// extern int mdfoursse2_nosizeupdate(unsigned char *out, unsigned char *in, int ignored) __attribute__((regparm(3)));

#ifdef UNDERSCORES
#define mdfoursse2	_mdfoursse2
#define mdfoursse2_nosizeupdate	_mdfoursse2_nosizeupdate
#endif
// For proper VC 'param marshalling' function stubs.
#ifdef __MINGW32__
#define mdfoursse2_VC @mdfoursse2_VC@12
#define mdfoursse2_nosizeupdate_VC @mdfoursse2_nosizeupdate_VC@12
.globl mdfoursse2_VC
.globl mdfoursse2_nosizeupdate_VC
#endif

.globl mdfoursse2
.globl mdfoursse2_nosizeupdate

.data
#if defined (MD4_SSE_PARA) && !defined (MMX_COEF)
#define MMX_COEF 4
#endif

// align of 2*MMX_COEF was crashing on SSE2 builds (at least cross compiling from 64 bit linux)
.align(4*MMX_COEF)

const_init_a:
.long 0x67452301
.long 0x67452301
.long 0x67452301
.long 0x67452301
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

.align(4*MMX_COEF)
buffer:
DO_SPACE(64*4)

#define ctxa %xmm0
#define ctxb %xmm1
#define ctxc %xmm2
#define ctxd %xmm3
#define tmp1 %xmm4
#define tmp2 %xmm5
#define tmp3 %xmm6
#define tmp4 %xmm7

//#define F_MMX(x, y, z)			(z ^ (x & (y ^ z)))

#define F(x,y,z) \
	movapd y, tmp1; \
	pxor z, tmp1; \
	pand x, tmp1; \
	pxor z, tmp1

//#define G_MMX(x, y, z)			((x & (y | z)) | (y & z))

#define G(x,y,z) \
	movapd y, tmp1; \
	movapd y, tmp2; \
	por z, tmp1; \
	pand z, tmp2; \
	pand x, tmp1; \
	por tmp2, tmp1

//#define H_MMX(x, y, z)			(x ^ y ^ z)
#define H(x,y,z) \
	movapd x, tmp1; \
	pxor y, tmp1; \
	pxor z, tmp1

//#define STEP_MMX(f, a, b, c, d, x, s) \
//	(a) += f((b), (c), (d)) + (x); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

#define STEP1(f, a, b, c, d, x, s) \
	f(b, c, d); \
	paddd (x*16)(%edx), tmp1; \
	paddd tmp1, a; \
	movapd a, tmp3; \
	pslld $s, a; \
	psrld $(32-s), tmp3; \
	por tmp3, a

#define STEP2(f, a, b, c, d, x, s) \
	f(b, c, d); \
	paddd (x*16)(%edx), tmp1; \
	paddd tmp4, tmp1; \
	paddd tmp1, a; \
	movapd a, tmp3; \
	pslld $s, a; \
	psrld $(32-s), tmp3; \
	por tmp3, a

.text
/*
 * Try to do some asm md4 w/ sse2
 * %eax ptr -> out
 * %edx ptr -> in
 * %ecx n
 */

 #ifdef __MINGW32__
// These are 'magic' param marshalling calls to convert VC __fastcall, to
// GCC/GAS register param ordering.  Same as was done in MD5/SHA1. Requires
// MinGW32 to build the .o, and then VC can use that .o file properly.
mdfoursse2_VC:
    lea mdfoursse2_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx
    jmp mdfoursse2_no_push
mdfoursse2_VC_exit:
    ret $4

mdfoursse2_nosizeupdate_VC:
    lea mdfoursse2_nosizeupdate_VC_exit, %eax
    push %eax
    pusha
    mov %ecx, %eax
    mov 40(%esp), %ecx

    jmp mdfoursse2_no_size
mdfoursse2_nosizeupdate_VC_exit:
    ret $4

#endif

mdfoursse2_nosizeupdate:
	pusha
	jmp mdfoursse2_no_size

mdfoursse2:
	pusha

mdfoursse2_no_push:
	//mov %edx, %eax
	//ret

//	shl $3, %ecx
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

mdfoursse2_no_size:
	movapd const_init_a, ctxa
	movapd const_init_b, ctxb
	movapd const_init_c, ctxc
	movapd const_init_d, ctxd

	STEP1(F, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 1, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 2, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 3, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 4, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 5, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 6, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 7, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 8, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 9, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 10, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 11, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 12, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 13, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 14, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 15, 19)

	movapd const_stage2, tmp4

	STEP2(G, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 4, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 8, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 12, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 1, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 5, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 9, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 13, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 2, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 6, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 10, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 14, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 3, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 7, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 11, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 15, 13)

	movapd const_stage3, tmp4

	STEP2(H, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 8, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 4, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 12, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 2, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 10, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 6, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 14, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 1, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 9, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 5, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 13, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 3, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 11, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 7, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 15, 15)

	paddd const_init_a, ctxa
	paddd const_init_b, ctxb
	paddd const_init_c, ctxc
	paddd const_init_d, ctxd

	movapd ctxa, 0(%eax)
	movapd ctxb, 16(%eax)
	movapd ctxc, 32(%eax)
	movapd ctxd, 48(%eax)

	movd ctxa, %eax
	emms

	popa

	ret

#endif

#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",@progbits
#endif
