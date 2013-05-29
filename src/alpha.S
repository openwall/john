/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-99 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

/*
 * Alpha assembly routines.
 *
 * These are optimized for EV4 (21064, 21066), not EV5 (21164), since on
 * a 21164 bitslice DES is always faster anyway. However, I tried to make
 * them have reasonable performance on EV5 too, in places where it didn't
 * affect EV4.
 *
 * In reality, bitslice DES turned out to be faster almost everywhere, so
 * these routines are now only used for BSDI setkey() and AFS by default.
 *
 * The following things were kept in mind while coding:
 *
 * 1. Huge instruction latencies:
 *	3 cycles LDQ to XOR,
 *	2 cycles S8ADDQ to LDQ,
 *	2 cycles EXTBL to S8ADDQ
 *		=> schedule the instructions accordingly;
 *		=> allocate some extra temporary registers;
 *	AND has better latency than EXTBL
 *		=> use it where possible.
 *
 * 2. Dual issue rules:
 *	only one LD/ST with one other instruction can dual issue (simplified)
 *		=> keep in mind for latency calculations;
 *		=> mix LD/ST with other instructions where possible;
 *		=> no need to avoid dependencies if the two instructions are
 *		_both_ from _one_ of these two classes anyway, unless can be
 *		done with no extra cost at all (better for EV5);
 *	the pair has to be qword aligned
 *		=> surround each LD/ST instruction with others, so that it can
 *		dual issue either with the preceding, or the following one.
 *
 * 3. Direct-mapped L1 cache:
 *	=> the entire key schedule (128 bytes) is loaded into 16 registers at
 *	startup, so there's no risk of it overlapping with SPE tables in the
 *	cache, while in the inner loop.
 */

/*
 * DES stuff.
 */

#define D				$0
#define tmp1				$1
#define tmp2				$2
#define tmp3				$3
#define tmp4				$4
#define R				$5
#define L				$6
#define count				$7
#define SPE				$8
#define kp				$16
#define out				$17
#define K1				$18
#define K2				$19
#define K3				$20
#define K4				$21
#define K5				$22
#define K6				$23
#define K7				$24
#define K8				$25
#define K9				$9
#define K10				$10
#define K11				$11
#define K12				$12
#define K13				$13
#define K14				$14
#define K15				$15
#define K16				$16

.text

#define DES_2_ROUNDS_START(K) \
	and D,0xFF,tmp1; \
	extbl D,1,tmp2; \
	s8addq tmp1,SPE,tmp1; \
	s8addq tmp2,SPE,tmp2; \
	extbl D,2,tmp3; \
	ldq tmp1,0(tmp1); \
	extbl D,3,tmp4; \
	s8addq tmp3,SPE,tmp3; \
	ldq tmp2,0x200(tmp2); \
	s8addq tmp4,SPE,tmp4; \
	ldq tmp3,0x400(tmp3); \
	xor L,tmp1,L; \
	ldq tmp4,0x600(tmp4); \
	extbl D,4,tmp1; \
	xor L,tmp2,L; \
	s8addq tmp1,SPE,tmp1; \
	extbl D,5,tmp2; \
	xor L,tmp3,L; \
	ldq tmp1,0x800(tmp1); \
	s8addq tmp2,SPE,tmp2; \
	xor L,tmp4,L; \
	extbl D,6,tmp3; \
	extbl D,7,tmp4; \
	ldq tmp2,0xA00(tmp2); \
	s8addq tmp3,SPE,tmp3; \
	s8addq tmp4,SPE,tmp4; \
	ldq tmp3,0xC00(tmp3); \
	xor L,tmp1,L; \
	ldq tmp4,0xE00(tmp4); \
	xor L,tmp2,L; \
	xor L,tmp3,L; \
	xor L,tmp4,L; \
	xor K,L,D; \
	and D,0xFF,tmp1; \
	extbl D,1,tmp2; \
	s8addq tmp1,SPE,tmp1; \
	s8addq tmp2,SPE,tmp2; \
	extbl D,2,tmp3; \
	ldq tmp1,0(tmp1); \
	extbl D,3,tmp4; \
	s8addq tmp3,SPE,tmp3; \
	ldq tmp2,0x200(tmp2); \
	s8addq tmp4,SPE,tmp4; \
	ldq tmp3,0x400(tmp3); \
	xor R,tmp1,R; \
	ldq tmp4,0x600(tmp4); \
	extbl D,4,tmp1; \
	xor R,tmp2,R; \
	s8addq tmp1,SPE,tmp1; \
	extbl D,5,tmp2; \
	xor R,tmp3,R; \
	ldq tmp1,0x800(tmp1); \
	s8addq tmp2,SPE,tmp2; \
	xor R,tmp4,R; \
	extbl D,6,tmp3; \
	extbl D,7,tmp4; \
	ldq tmp2,0xA00(tmp2); \
	s8addq tmp3,SPE,tmp3; \
	s8addq tmp4,SPE,tmp4; \
	ldq tmp3,0xC00(tmp3); \
	xor R,tmp1,R; \
	ldq tmp4,0xE00(tmp4); \
	xor R,tmp2,R

#define DES_2_ROUNDS(K1, K2) \
	DES_2_ROUNDS_START(K1); \
	xor R,tmp3,R; \
	xor R,tmp4,R; \
	xor K2,R,D

.align 7
.globl DES_std_crypt
.ent DES_std_crypt
DES_std_crypt:
	ldgp $29,0($27)
DES_std_crypt..ng:
	subq $30,56,$30
	lda tmp1,DES_IV
	lda tmp2,DES_count
	lda SPE,DES_SPE_F
	ldq R,0(tmp1)
	ldq L,8(tmp1)
	ldq count,0(tmp2)
	ldq K1,0(kp)
	ldq K2,8(kp)
	ldq K3,16(kp)
	ldq K4,24(kp)
	xor K1,R,D
	ldq K5,32(kp)
	ldq K6,40(kp)
	ldq K7,48(kp)
	ldq K8,56(kp)
	stq K9,0($30)
	stq K10,8($30)
	stq K11,16($30)
	stq K12,24($30)
	stq K13,32($30)
	stq K14,40($30)
	stq K15,48($30)
	ldq K9,64(kp)
	ldq K10,72(kp)
	ldq K11,80(kp)
	ldq K12,88(kp)
	ldq K13,96(kp)
	ldq K14,104(kp)
	ldq K15,112(kp)
	ldq K16,120(kp)
DES_loop:
	DES_2_ROUNDS(K2, K3)
	DES_2_ROUNDS(K4, K5)
	DES_2_ROUNDS(K6, K7)
	DES_2_ROUNDS(K8, K9)
	DES_2_ROUNDS(K10, K11)
	DES_2_ROUNDS(K12, K13)
	DES_2_ROUNDS(K14, K15)
	DES_2_ROUNDS_START(K16)
	subq count,1,count
	xor R,tmp3,tmp3
	bis L,L,R
	xor tmp3,tmp4,L
	xor K1,R,D
	bne count,DES_loop
	ldq K9,0($30)
	ldq K10,8($30)
	ldq K11,16($30)
	ldq K12,24($30)
	ldq K13,32($30)
	ldq K14,40($30)
	ldq K15,48($30)
	stq R,0(out)
	addq $30,56,$30
	stq L,8(out)
	ret $31,($26),1
.end DES_std_crypt

#undef kp
#define kp				$0
#define key1				$16
#define key2				$17
#define tmp5				$5
#define tmp6				$6
#define tmp7				$7
#define tmp8				$8
#define tmp9				$18
#define tmp10				$19
#define tmp11				$20
#define tmp12				$21

#define DES_xor1(ofs) \
	ldq tmp1,ofs(key1); \
	ldq tmp2,ofs(kp); \
	ldq tmp3,ofs+8(key1); \
	ldq tmp4,ofs+8(kp); \
	ldq tmp5,ofs+16(key1); \
	ldq tmp6,ofs+16(kp); \
	xor tmp1,tmp2,tmp1; \
	ldq tmp7,ofs+24(key1); \
	xor tmp3,tmp4,tmp2; \
	ldq tmp8,ofs+24(kp); \
	stq tmp1,ofs(kp); \
	xor tmp5,tmp6,tmp3; \
	stq tmp2,ofs+8(kp); \
	xor tmp7,tmp8,tmp4; \
	stq tmp3,ofs+16(kp); \
	stq tmp4,ofs+24(kp)

.align 3
.globl DES_xor_key1
.ent DES_xor_key1
DES_xor_key1:
	ldgp $29,0($27)
DES_xor_key1..ng:
	lda kp,DES_KS_current
	DES_xor1(0)
	DES_xor1(32)
	DES_xor1(64)
	DES_xor1(96)
	ret $31,($26),1
.end DES_xor_key1

#define DES_xor2(ofs) \
	ldq tmp1,ofs(key1); \
	ldq tmp2,ofs(key2); \
	ldq tmp3,ofs(kp); \
	ldq tmp4,ofs+8(key1); \
	ldq tmp5,ofs+8(key2); \
	xor tmp1,tmp2,tmp1; \
	ldq tmp6,ofs+8(kp); \
	xor tmp1,tmp3,tmp1; \
	ldq tmp7,ofs+16(key1); \
	ldq tmp8,ofs+16(key2); \
	xor tmp4,tmp5,tmp2; \
	ldq tmp9,ofs+16(kp); \
	xor tmp2,tmp6,tmp2; \
	ldq tmp10,ofs+24(key1); \
	ldq tmp11,ofs+24(key2); \
	xor tmp7,tmp8,tmp3; \
	ldq tmp12,ofs+24(kp); \
	xor tmp3,tmp9,tmp3; \
	stq tmp1,ofs(kp); \
	xor tmp10,tmp11,tmp4; \
	stq tmp2,ofs+8(kp); \
	xor tmp4,tmp12,tmp4; \
	stq tmp3,ofs+16(kp); \
	stq tmp4,ofs+24(kp)

.align 3
.globl DES_xor_key2
.ent DES_xor_key2
DES_xor_key2:
	ldgp $29,0($27)
DES_xor_key2..ng:
	lda kp,DES_KS_current
	DES_xor2(0)
	DES_xor2(32)
	DES_xor2(64)
	DES_xor2(96)
	ret $31,($26),1
.end DES_xor_key2

.data

.align 7
.globl DES_SPE_F
DES_SPE_F:
.space 0x1000

.globl DES_IV
DES_IV:
.space 16

.globl DES_count
DES_count:
.space 8

.align 7
.globl DES_KS_current
DES_KS_current:
.space 128

.comm DES_KS_table, (8 * 128 * 16 * 8), 128

#if defined(__ELF__) && defined(__linux__)
.section .note.GNU-stack,"",@progbits
#endif
