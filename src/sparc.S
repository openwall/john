/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001 by Solar Designer
 */

/*
 * SPARC V8 assembly routines.
 */

#include "arch.h"

#ifdef UNDERSCORES
#define DES_IV				_DES_IV
#define DES_count			_DES_count
#define DES_KS_current			_DES_KS_current
#define DES_KS_table			_DES_KS_table
#define DES_SPE_L			_DES_SPE_L
#define DES_SPE_H			_DES_SPE_H
#define DES_SPE_W			_DES_SPE_W
#define DES_std_crypt			_DES_std_crypt
#define DES_xor_key1			_DES_xor_key1
#define DES_xor_key2			_DES_xor_key2
#endif

/*
 * Load an address assuming that it is 1024-byte aligned if the section
 * alignment for this platform is large enough.
 */
#ifdef BSD
#define LDAA(addr, reg)			set (addr),reg
#else
#define LDAA(addr, reg)			sethi %hi(addr),reg
#endif

/*
 * DES stuff.
 */

#define tmp1				%g1
#define tmp2				%g2
#define tmp3				%g3
#define tmp4				%g4
#define count				%l5
#define Dl				%g6
#define Dh				%g7
#define kp				%i0
#define out				%i1
#define Rl				%o2
#define Rh				%o3
#define Ll				%o4
#define Lh				%o5
#if DES_128K
#define tmp5				%g5
#define SPE_L_4				tmp1
#define SPE_0				%l0
#define SPE_1				%l1
#define SPE_2				%l2
#define SPE_3				%l3
#define FFFF				%l4
#else
#define SPE_L_0				%l0
#define SPE_H_0				%l1
#define SPE_L_1				%l2
#define SPE_H_1				%l3
#define SPE_L_2				%l4
#define SPE_H_2				%g5
#define SPE_L_3				%l6
#define SPE_H_3				%l7
#define SPE_L_4				%o0
#define SPE_H_4				%o1
#define SPE_L_5				%i2
#define SPE_H_5				%i3
#define SPE_L_6				%i4
#define SPE_H_6				%i5
#define SPE_L_7				%o7
#define SPE_H_7				%i7
#endif

.text

#if DES_128K

#define DES_2_ROUNDS_START(K) \
	xor Dl,Rl,Dl; \
	xor Dh,Rh,Dh; \
	and Dl,FFFF,tmp1; \
	srl Dl,16,tmp4; \
	ldd [SPE_0+tmp1],tmp2; \
	ldd [SPE_1+tmp4],tmp4; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	xor Ll,tmp4,Ll; \
	and Dh,FFFF,tmp1; \
	xor Lh,tmp5,Lh; \
	srl Dh,16,tmp4; \
	ldd [SPE_2+tmp1],tmp2; \
	ldd [SPE_3+tmp4],tmp4; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	ldd [K+8],Dl; \
	xor Ll,tmp4,Ll; \
	xor Lh,tmp5,Lh; \
	xor Dl,Ll,Dl; \
	xor Dh,Lh,Dh; \
	and Dl,FFFF,tmp1; \
	srl Dl,16,tmp4; \
	ldd [SPE_0+tmp1],tmp2; \
	ldd [SPE_1+tmp4],tmp4; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	xor Rl,tmp4,Rl; \
	and Dh,FFFF,tmp1; \
	xor Rh,tmp5,Rh; \
	srl Dh,16,tmp2; \
	ldd [SPE_2+tmp1],tmp4; \
	ldd [SPE_3+tmp2],tmp2; \
	xor Rl,tmp4,Rl; \
	xor Rh,tmp5,Rh

#else

#define DES_2_ROUNDS_START(K) \
	xor Dl,Rl,Dl; \
	xor Dh,Rh,Dh; \
	and Dl,0xFF,tmp1; \
	srl Dl,8,tmp4; \
	ld [SPE_L_0+tmp1],tmp2; \
	ld [SPE_H_0+tmp1],tmp3; \
	and tmp4,0xFF,Dl; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	srl tmp4,8,tmp4; \
	ld [SPE_L_1+Dl],tmp2; \
	ld [SPE_H_1+Dl],tmp3; \
	and tmp4,0xFF,tmp1; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	ld [SPE_L_2+tmp1],tmp2; \
	ld [SPE_H_2+tmp1],tmp3; \
	srl tmp4,8,tmp4; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	ld [SPE_L_3+tmp4],tmp2; \
	ld [SPE_H_3+tmp4],tmp3; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	and Dh,0xFF,tmp1; \
	srl Dh,8,tmp4; \
	ld [SPE_L_4+tmp1],tmp2; \
	ld [SPE_H_4+tmp1],tmp3; \
	and tmp4,0xFF,Dh; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	srl tmp4,8,tmp4; \
	ld [SPE_L_5+Dh],tmp2; \
	ld [SPE_H_5+Dh],tmp3; \
	and tmp4,0xFF,tmp1; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	ld [SPE_L_6+tmp1],tmp2; \
	ld [SPE_H_6+tmp1],tmp3; \
	srl tmp4,8,tmp4; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	ld [SPE_L_7+tmp4],tmp2; \
	ld [SPE_H_7+tmp4],tmp3; \
	ldd [K+8],Dl; \
	xor Ll,tmp2,Ll; \
	xor Lh,tmp3,Lh; \
	xor Dl,Ll,Dl; \
	xor Dh,Lh,Dh; \
	and Dl,0xFF,tmp1; \
	srl Dl,8,tmp4; \
	ld [SPE_L_0+tmp1],tmp2; \
	ld [SPE_H_0+tmp1],tmp3; \
	and tmp4,0xFF,Dl; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	srl tmp4,8,tmp4; \
	ld [SPE_L_1+Dl],tmp2; \
	ld [SPE_H_1+Dl],tmp3; \
	and tmp4,0xFF,tmp1; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	ld [SPE_L_2+tmp1],tmp2; \
	ld [SPE_H_2+tmp1],tmp3; \
	srl tmp4,8,tmp4; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	ld [SPE_L_3+tmp4],tmp2; \
	ld [SPE_H_3+tmp4],tmp3; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	and Dh,0xFF,tmp1; \
	srl Dh,8,tmp4; \
	ld [SPE_L_4+tmp1],tmp2; \
	ld [SPE_H_4+tmp1],tmp3; \
	and tmp4,0xFF,Dh; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	srl tmp4,8,tmp4; \
	ld [SPE_L_5+Dh],tmp2; \
	ld [SPE_H_5+Dh],tmp3; \
	and tmp4,0xFF,tmp1; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	ld [SPE_L_6+tmp1],tmp2; \
	ld [SPE_H_6+tmp1],tmp3; \
	srl tmp4,8,tmp4; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh; \
	ld [SPE_L_7+tmp4],tmp2; \
	ld [SPE_H_7+tmp4],tmp3

#endif

#define DES_2_ROUNDS(K) \
	DES_2_ROUNDS_START(K); \
	ldd [K+16],Dl; \
	xor Rl,tmp2,Rl; \
	xor Rh,tmp3,Rh

.align 32
.globl DES_std_crypt
DES_std_crypt:
#if DES_128K
	save %sp,-112,%sp
	LDAA (DES_SPE_L+0x400,SPE_L_4)
	LDAA (DES_SPE_W,SPE_0)
	LDAA (DES_SPE_W+0x8000,SPE_1)
	LDAA (DES_SPE_W+0x10000,SPE_2)
	LDAA (DES_SPE_W+0x18000,SPE_3)
	set 0xFFFF,FFFF
#else
	save %sp,-120,%sp
	st %i7,[%fp-24]
	LDAA (DES_SPE_L,SPE_L_0)
	LDAA (DES_SPE_L+0x400,SPE_L_4)
	add SPE_L_0,0x808,SPE_H_0
	add SPE_L_0,0x100,SPE_L_1
	add SPE_L_0,0x200,SPE_L_2
	add SPE_L_0,0x300,SPE_L_3
	add SPE_L_0,0x500,SPE_L_5
	add SPE_L_0,0x600,SPE_L_6
	add SPE_L_0,0x700,SPE_L_7
	add SPE_H_0,0x100,SPE_H_1
	add SPE_H_0,0x200,SPE_H_2
	add SPE_H_0,0x300,SPE_H_3
	add SPE_H_0,0x400,SPE_H_4
	add SPE_H_0,0x500,SPE_H_5
	add SPE_H_0,0x600,SPE_H_6
	add SPE_H_0,0x700,SPE_H_7
#endif
	ldd [kp],Dl
	ldd [SPE_L_4+0xC08],Rl
	ldd [SPE_L_4+0xC10],Ll
	ld [SPE_L_4+0xC18],count
DES_loop:
	DES_2_ROUNDS(kp)
	DES_2_ROUNDS(kp+16)
	DES_2_ROUNDS(kp+32)
	DES_2_ROUNDS(kp+48)
	DES_2_ROUNDS(kp+64)
	DES_2_ROUNDS(kp+80)
	DES_2_ROUNDS(kp+96)
	DES_2_ROUNDS_START(kp+112)
	xor Rl,tmp2,Rl
	xor Rh,tmp3,Rh
	deccc count
	xor Ll,Rl,Ll
	xor Lh,Rh,Lh
	xor Rl,Ll,Rl
	xor Rh,Lh,Rh
	xor Ll,Rl,Ll
	xor Lh,Rh,Lh
	bnz,a DES_loop
	ldd [kp],Dl
#if !DES_128K
	ld [%fp-24],%i7
#endif
	std Rl,[out]
	std Ll,[out+8]
	ret
	restore

#undef kp
#define kp				%g1
#define key1				%o0
#define key2				%o1
#undef tmp1
#undef tmp2
#undef tmp3
#undef tmp4
#undef tmp5
#define tmp1				%g2
#define tmp2				%g3
#define tmp3				%g4
#define tmp4				%g5
#define tmp5				%g6
#define tmp6				%g7
#define tmp7				%o2
#define tmp8				%o3
#define tmp9				%o4
#define tmp10				%o5

#define DES_xor1(ofs, cmd) \
	ldd [key1+ofs],tmp1; \
	ldd [key1+ofs+8],tmp5; \
	ldd [kp+ofs],tmp3; \
	ldd [kp+ofs+8],tmp7; \
	xor tmp1,tmp3,tmp1; \
	xor tmp2,tmp4,tmp2; \
	std tmp1,[kp+ofs]; \
	xor tmp5,tmp7,tmp5; \
	xor tmp6,tmp8,tmp6; \
	cmd; \
	std tmp5,[kp+ofs+8]

.align 16
.globl DES_xor_key1
DES_xor_key1:
	LDAA (DES_KS_current,kp)
	DES_xor1(0,)
	DES_xor1(16,)
	DES_xor1(32,)
	DES_xor1(48,)
	DES_xor1(64,)
	DES_xor1(80,)
	DES_xor1(96,)
	DES_xor1(112, retl)

#define DES_xor2(ofs, cmd) \
	ldd [key1+ofs],tmp1; \
	ldd [key1+ofs+8],tmp7; \
	ldd [key2+ofs],tmp3; \
	ldd [key2+ofs+8],tmp9; \
	ldd [kp+ofs],tmp5; \
	xor tmp1,tmp3,tmp1; \
	xor tmp2,tmp4,tmp2; \
	xor tmp1,tmp5,tmp1; \
	xor tmp2,tmp6,tmp2; \
	ldd [kp+ofs+8],tmp3; \
	xor tmp7,tmp9,tmp7; \
	xor tmp8,tmp10,tmp8; \
	std tmp1,[kp+ofs]; \
	xor tmp7,tmp3,tmp7; \
	xor tmp8,tmp4,tmp8; \
	cmd; \
	std tmp7,[kp+ofs+8]

.align 16
.globl DES_xor_key2
DES_xor_key2:
	LDAA (DES_KS_current,kp)
	DES_xor2(0,)
	DES_xor2(16,)
	DES_xor2(32,)
	DES_xor2(48,)
	DES_xor2(64,)
	DES_xor2(80,)
	DES_xor2(96,)
	DES_xor2(112, retl)

.data

#ifdef BSD
.align 8
#else
.align 1024
#endif

.globl DES_SPE_L
DES_SPE_L:
.skip 0x800

/*
 * Cache bank shift. This should be at least as large as the word size, but
 * smaller than the cache line size.
 */
.skip 8

.globl DES_SPE_H
DES_SPE_H:
.skip 0x800

.globl DES_IV
DES_IV:
.skip 16

.globl DES_count
DES_count:
.skip 4

#ifdef BSD

#if DES_128K
.common DES_SPE_W, 0x20000, "bss"
#endif

.common DES_KS_current, 128, "bss"
.common DES_KS_table, (8 * 128 * 16 * 8), "bss"

#else

#if DES_128K
.common DES_SPE_W, 0x20000, 1024
#endif

.common DES_KS_current, 128, 1024
.common DES_KS_table, (8 * 128 * 16 * 8), 32

#endif
