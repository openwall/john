/* gost.c - an implementation of GOST Hash Function
 * based on the Russian Standard GOST R 34.11-94.
 * See also RFC 4357.
 *
 * Copyright: 2009 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 */

#include <string.h>
#include <stdio.h>
#include "gost.h"
#include "johnswap.h"

extern unsigned rhash_gost_sbox[4][256];
extern unsigned rhash_gost_sbox_cryptpro[4][256];

/**
 * Initialize algorithm context before calculaing hash
 * with test parameters set.
 *
 * @param ctx context to initialize
 */
void john_gost_init(gost_ctx *ctx)
{
	memset(ctx, 0, sizeof(gost_ctx));
}

/**
 * Initialize GOST algorithm context with CryptoPro parameter set.
 *
 * @param ctx context to initialize
 */
void john_gost_cryptopro_init(gost_ctx *ctx)
{
	john_gost_init(ctx);
	ctx->cryptpro = 1;
}

/*
 *  A macro that performs a full encryption round of GOST 28147-89.
 *  Temporary variables tmp assumed and variables r and l for left and right
 *  blocks.
 */
#ifndef USE_GCC_ASM_IA32
 #define GOST_ENCRYPT_ROUND(key1, key2, sbox) \
	tmp = (key1) + r; \
	l ^= (sbox)[tmp & 0xff] ^ ((sbox) + 256)[(tmp >> 8) & 0xff] ^ \
		((sbox) + 512)[(tmp >> 16) & 0xff] ^ ((sbox) + 768)[tmp >> 24]; \
	tmp = (key2) + l; \
	r ^= (sbox)[tmp & 0xff] ^ ((sbox) + 256)[(tmp >> 8) & 0xff] ^ \
		((sbox) + 512)[(tmp >> 16) & 0xff] ^ ((sbox) + 768)[tmp >> 24];

/* encrypt a block with the given key */
 #define GOST_ENCRYPT(result, i, key, hash, sbox) \
	r = hash[i], l = hash[i + 1]; \
	GOST_ENCRYPT_ROUND(key[0], key[1], sbox) \
	GOST_ENCRYPT_ROUND(key[2], key[3], sbox) \
	GOST_ENCRYPT_ROUND(key[4], key[5], sbox) \
	GOST_ENCRYPT_ROUND(key[6], key[7], sbox) \
	GOST_ENCRYPT_ROUND(key[0], key[1], sbox) \
	GOST_ENCRYPT_ROUND(key[2], key[3], sbox) \
	GOST_ENCRYPT_ROUND(key[4], key[5], sbox) \
	GOST_ENCRYPT_ROUND(key[6], key[7], sbox) \
	GOST_ENCRYPT_ROUND(key[0], key[1], sbox) \
	GOST_ENCRYPT_ROUND(key[2], key[3], sbox) \
	GOST_ENCRYPT_ROUND(key[4], key[5], sbox) \
	GOST_ENCRYPT_ROUND(key[6], key[7], sbox) \
	GOST_ENCRYPT_ROUND(key[7], key[6], sbox) \
	GOST_ENCRYPT_ROUND(key[5], key[4], sbox) \
	GOST_ENCRYPT_ROUND(key[3], key[2], sbox) \
	GOST_ENCRYPT_ROUND(key[1], key[0], sbox) \
	result[i] = l, result[i + 1] = r;

#else /* USE_GCC_ASM_IA32 */

/* a faster x86 version of GOST_ENCRYPT() */
/* it supposes edi=r, esi=l, edx=sbox ; */
 #define ENC_ROUND_ASMx86(key, reg1, reg2) \
	"movl %" #key ", %%eax\n\t" \
	"addl %%" #reg1 ", %%eax\n\t" \
	"movzx %%al, %%ebx\n\t" \
	"movzx %%ah, %%ecx\n\t" \
	"xorl (%%edx, %%ebx, 4), %%" #reg2 "\n\t" \
	"xorl 1024(%%edx, %%ecx, 4), %%" #reg2 "\n\t" \
	"shrl $16, %%eax\n\t" \
	"movzx %%al, %%ebx\n\t" \
	"shrl $8, %%eax\n\t" \
	"xorl 2048(%%edx, %%ebx, 4), %%" #reg2 "\n\t" \
	"xorl 3072(%%edx, %%eax, 4), %%" #reg2 "\n\t"

 #define ENC_ASM(key1, key2) ENC_ROUND_ASMx86(key1, edi, esi) ENC_ROUND_ASMx86(key2, esi, edi)
 #define GOST_ENCRYPT_GCC_ASM_X86() \
	ENC_ASM( 5,  6) ENC_ASM( 7,  8) ENC_ASM( 9, 10) ENC_ASM(11, 12) \
	ENC_ASM( 5,  6) ENC_ASM( 7,  8) ENC_ASM( 9, 10) ENC_ASM(11, 12) \
	ENC_ASM( 5,  6) ENC_ASM( 7,  8) ENC_ASM( 9, 10) ENC_ASM(11, 12) \
	ENC_ASM(12, 11) ENC_ASM(10,  9) ENC_ASM( 8,  7) ENC_ASM( 6,  5)
#endif /* USE_GCC_ASM_IA32 */

/**
 * The core transformation. Process a 512-bit block.
 *
 * @param hash intermediate message hash
 * @param block the message block to process
 */
static void rhash_gost_block_compress(gost_ctx *ctx, const unsigned* block)
{
	unsigned i;
	unsigned key[8], u[8], v[8], w[8], s[8];
	unsigned *sbox = (ctx->cryptpro ? (unsigned*)rhash_gost_sbox_cryptpro : (unsigned*)rhash_gost_sbox);

	/* u := hash, v := <256-bit message block> */
	memcpy(u, ctx->hash, sizeof(u));
	memcpy(v, block, sizeof(v));

	/* w := u xor v */
	w[0] = u[0] ^ v[0], w[1] = u[1] ^ v[1];
	w[2] = u[2] ^ v[2], w[3] = u[3] ^ v[3];
	w[4] = u[4] ^ v[4], w[5] = u[5] ^ v[5];
	w[6] = u[6] ^ v[6], w[7] = u[7] ^ v[7];

	/* calculate keys, encrypt hash and store result to the s[] array */
	for (i = 0;; i += 2) {
		/* key generation: key_i := P(w) */
		key[0] = (w[0] & 0x000000ff) | ((w[2] & 0x000000ff) << 8) | ((w[4] & 0x000000ff) << 16) | ((w[6] & 0x000000ff) << 24);
		key[1] = ((w[0] & 0x0000ff00) >> 8) | (w[2] & 0x0000ff00) | ((w[4] & 0x0000ff00) << 8)  | ((w[6] & 0x0000ff00) << 16);
		key[2] = ((w[0] & 0x00ff0000) >> 16) | ((w[2] & 0x00ff0000) >> 8) | (w[4] & 0x00ff0000) | ((w[6] & 0x00ff0000) << 8);
		key[3] = ((w[0] & 0xff000000) >> 24) | ((w[2] & 0xff000000) >> 16) | ((w[4] & 0xff000000) >> 8) | (w[6] & 0xff000000);
		key[4] = (w[1] & 0x000000ff) | ((w[3] & 0x000000ff) << 8) | ((w[5] & 0x000000ff) << 16) | ((w[7] & 0x000000ff) << 24);
		key[5] = ((w[1] & 0x0000ff00) >> 8) | (w[3] & 0x0000ff00) | ((w[5] & 0x0000ff00) << 8)  | ((w[7] & 0x0000ff00) << 16);
		key[6] = ((w[1] & 0x00ff0000) >> 16) | ((w[3] & 0x00ff0000) >> 8) | (w[5] & 0x00ff0000) | ((w[7] & 0x00ff0000) << 8);
		key[7] = ((w[1] & 0xff000000) >> 24) | ((w[3] & 0xff000000) >> 16) | ((w[5] & 0xff000000) >> 8) | (w[7] & 0xff000000);

		/* encryption: s_i := E_{key_i} (h_i) */
#ifndef USE_GCC_ASM_IA32
		{
			unsigned l, r, tmp;
			GOST_ENCRYPT(s, i, key, ctx->hash, sbox);
		}
#else /* USE_GCC_ASM_IA32 */
		__asm __volatile(
			"movl %%ebx, %13\n\t"
			GOST_ENCRYPT_GCC_ASM_X86() /* optimized for x86 Intel Core 2 */
			"movl %13, %%ebx\n\t"
			: "=S" (s[i]), "=D" (s[i + 1]) /* 0,1: s[i]=esi, s[i + 1]=edi */
			: "d" (sbox), "D" (ctx->hash[i]), "S" (ctx->hash[i + 1]), /* 2,3,4: edx=sbox,edi=r,esi=l */
			"m" (key[0]), "m" (key[1]), "m" (key[2]), "m" (key[3]), /* 5, 6, 7, 8 */
			"m" (key[4]), "m" (key[5]), "m" (key[6]), "m" (key[7]), /* 9,10,11,12 */
			"m" (w[0])  /* store EBX in w[0], cause it's used for PIC on *BSD. */
			/* We avoid push/pop instructions incompatible with gcc -fomit-frame-pointer */
			: "cc", "eax", "ecx");
#endif /* USE_GCC_ASM_IA32 */

		if (i == 0) {
			/* w:= A(u) ^ A^2(v) */
			w[0] = u[2] ^ v[4], w[1] = u[3] ^ v[5];
			w[2] = u[4] ^ v[6], w[3] = u[5] ^ v[7];
			w[4] = u[6] ^ (v[0] ^= v[2]);
			w[5] = u[7] ^ (v[1] ^= v[3]);
			w[6] = (u[0] ^= u[2]) ^ (v[2] ^= v[4]);
			w[7] = (u[1] ^= u[3]) ^ (v[3] ^= v[5]);
		} else if ((i & 2) != 0) {
			if (i == 6) break;

			/* w := A^2(u) xor A^4(v) xor C_3; u := A(u) xor C_3 */
			/* C_3=0xff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00 */
			u[2] ^= u[4] ^ 0x000000ff;
			u[3] ^= u[5] ^ 0xff00ffff;
			u[4] ^= 0xff00ff00;
			u[5] ^= 0xff00ff00;
			u[6] ^= 0x00ff00ff;
			u[7] ^= 0x00ff00ff;
			u[0] ^= 0x00ffff00;
			u[1] ^= 0xff0000ff;

			w[0] = u[4] ^ v[0];
			w[2] = u[6] ^ v[2];
			w[4] = u[0] ^ (v[4] ^= v[6]);
			w[6] = u[2] ^ (v[6] ^= v[0]);
			w[1] = u[5] ^ v[1];
			w[3] = u[7] ^ v[3];
			w[5] = u[1] ^ (v[5] ^= v[7]);
			w[7] = u[3] ^ (v[7] ^= v[1]);
		} else {
			/* i==4 here */
			/* w:= A( A^2(u) xor C_3 ) xor A^6(v) */
			w[0] = u[6] ^ v[4], w[1] = u[7] ^ v[5];
			w[2] = u[0] ^ v[6], w[3] = u[1] ^ v[7];
			w[4] = u[2] ^ (v[0] ^= v[2]);
			w[5] = u[3] ^ (v[1] ^= v[3]);
			w[6] = (u[4] ^= u[6]) ^ (v[2] ^= v[4]);
			w[7] = (u[5] ^= u[7]) ^ (v[3] ^= v[5]);
		}
	}

	/* step hash function: x(block, hash) := psi^61(hash xor psi(block xor psi^12(S))) */

	/* 12 rounds of the LFSR and xor in <message block> */
	u[0] = block[0] ^ s[6];
	u[1] = block[1] ^ s[7];
	u[2] = block[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff) ^ (s[1] & 0xffff) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[7] & 0xffff0000) ^ (s[7] >> 16);
	u[3] = block[3] ^ (s[0] & 0xffff) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ (s[1] << 16) ^ (s[1] >> 16) ^
		(s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
	u[4] = block[4] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[0] >> 16) ^
		(s[1] & 0xffff0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
	u[5] = block[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff0000) ^
		(s[1] & 0xffff) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff0000) ^ (s[7] << 16) ^ (s[7] >> 16);
	u[6] = block[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16)
		^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
	u[7] = block[7] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^
		(s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);

	/* 1 round of the LFSR (a mixing transformation) and xor with <hash> */
	v[0] = ctx->hash[0] ^ (u[1] << 16) ^ (u[0] >> 16);
	v[1] = ctx->hash[1] ^ (u[2] << 16) ^ (u[1] >> 16);
	v[2] = ctx->hash[2] ^ (u[3] << 16) ^ (u[2] >> 16);
	v[3] = ctx->hash[3] ^ (u[4] << 16) ^ (u[3] >> 16);
	v[4] = ctx->hash[4] ^ (u[5] << 16) ^ (u[4] >> 16);
	v[5] = ctx->hash[5] ^ (u[6] << 16) ^ (u[5] >> 16);
	v[6] = ctx->hash[6] ^ (u[7] << 16) ^ (u[6] >> 16);
	v[7] = ctx->hash[7] ^ (u[0] & 0xffff0000) ^ (u[0] << 16) ^ (u[1] & 0xffff0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xffff0000) ^ (u[7] >> 16);

	/* 61 rounds of LFSR, mixing up hash */
	ctx->hash[0] = (v[0] & 0xffff0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^
		(v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^
		(v[3] >> 16) ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[5] ^
		(v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff);
	ctx->hash[1] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^
		(v[1] & 0xffff) ^ v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^
		(v[4] >> 16) ^ (v[5] << 16) ^ (v[6] << 16) ^ v[6] ^
		(v[7] & 0xffff0000) ^ (v[7] >> 16);
	ctx->hash[2] = (v[0] & 0xffff) ^ (v[0] << 16) ^ (v[1] << 16) ^
		(v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^
		v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^
		(v[7] & 0xffff) ^ (v[7] << 16) ^ (v[7] >> 16);
	ctx->hash[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^
		(v[1] & 0xffff0000) ^ (v[1] >> 16) ^ (v[2] << 16) ^
		(v[2] >> 16) ^ v[2] ^ (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^
		(v[5] << 16) ^ (v[6] << 16) ^ (v[7] & 0xffff) ^ (v[7] >> 16);
	ctx->hash[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^
		(v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^
		(v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
	ctx->hash[5] = (v[0] << 16) ^ (v[0] & 0xffff0000) ^ (v[1] << 16) ^
		(v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ v[2] ^
		(v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^
		(v[5] << 16) ^ (v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^
		(v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff0000);
	ctx->hash[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^
		(v[4] >> 16) ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^
		(v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
	ctx->hash[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^
		(v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^
		(v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
}

/**
 * This function calculates hash value by 256-bit blocks.
 * It updates 256-bit check sum as follows:
 *    *(uint256_t)(ctx->sum) += *(uint256_t*)block;
 * and then updates intermediate hash value ctx->hash
 * by calling rhash_gost_block_compress().
 *
 * @param ctx algorithm context
 * @param block the 256-bit message block to process
 */
static void rhash_gost_compute_sum_and_hash(gost_ctx * ctx, const unsigned* block)
{
#if !ARCH_LITTLE_ENDIAN
	unsigned block_le[8]; /* tmp buffer for little endian number */
 #define LOAD_BLOCK_LE(i) (block_le[i] = le2me_32(block[i]))
#else
 #define block_le block
 #define LOAD_BLOCK_LE(i)
#endif

	/* This optimization doesn't improve speed much,
	* and saves too little memory, but it was fun to write! =)  */
#ifdef USE_GCC_ASM_IA32
	__asm __volatile(
		"addl %0, (%1)\n\t"
		"movl 4(%2), %0\n\t"
		"adcl %0, 4(%1)\n\t"
		"movl 8(%2), %0\n\t"
		"adcl %0, 8(%1)\n\t"
		"movl 12(%2), %0\n\t"
		"adcl %0, 12(%1)\n\t"
		"movl 16(%2), %0\n\t"
		"adcl %0, 16(%1)\n\t"
		"movl 20(%2), %0\n\t"
		"adcl %0, 20(%1)\n\t"
		"movl 24(%2), %0\n\t"
		"adcl %0, 24(%1)\n\t"
		"movl 28(%2), %0\n\t"
		"adcl %0, 28(%1)\n\t"
		: : "r" (block[0]), "r" (ctx->sum), "r" (block)
		: "0", "memory", "cc" );
#elif defined(USE_GCC_ASM_X64)
	const uint64_t* block64 = (const uint64_t*)block;
	uint64_t* sum64 = (uint64_t*)ctx->sum;
	__asm __volatile(
		"addq %4, %0\n\t"
		"adcq %5, %1\n\t"
		"adcq %6, %2\n\t"
		"adcq %7, %3\n\t"
		: "+m" (sum64[0]), "+m" (sum64[1]), "+m" (sum64[2]), "+m" (sum64[3])
		: "r" (block64[0]), "r" (block64[1]), "r" (block64[2]), "r" (block64[3])
		: "cc" );
#else /* USE_GCC_ASM_IA32 */

	unsigned i, carry = 0;

	/* compute the 256-bit sum */
	for (i = 0; i < 8; i++) {
		const unsigned old = ctx->sum[i];
		LOAD_BLOCK_LE(i);
		ctx->sum[i] += block_le[i] + carry;
		carry = (ctx->sum[i] < old || ctx->sum[i] < block_le[i] ? 1 : 0);
	}
#endif /* USE_GCC_ASM_IA32 */

	/* update message hash */
	rhash_gost_block_compress(ctx, block_le);
}

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param size length of the message chunk
 */
void john_gost_update(gost_ctx *ctx, const unsigned char* msg, size_t size)
{
	unsigned index = (unsigned)ctx->length & 31;
	ctx->length += size;

	/* fill partial block */
	if (index) {
		unsigned left = gost_block_size - index;
		memcpy(ctx->message + index, msg, (size < left ? size : left));
		if (size < left) return;

		/* process partial block */
		rhash_gost_compute_sum_and_hash(ctx, (unsigned*)ctx->message);
		msg += left;
		size -= left;
	}
	while(size >= gost_block_size) {
		unsigned* aligned_message_block;
#if (defined(__GNUC__) && defined(CPU_X64))
		if (IS_ALIGNED_64(msg)) {
#else
		if (IS_ALIGNED_32(msg)) {
#endif
			/* the most common case is processing of an already aligned message
			on little-endian CPU without copying it */
			aligned_message_block = (unsigned*)msg;
		} else {
			memcpy(ctx->message, msg, gost_block_size);
			aligned_message_block = (unsigned*)ctx->message;
		}

		rhash_gost_compute_sum_and_hash(ctx, aligned_message_block);
		msg += gost_block_size;
		size -= gost_block_size;
	}
	if (size) {
		/* save leftovers */
		memcpy(ctx->message, msg, size);
	}
}

/**
 * Finish hashing and store message digest into given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param result calculated hash in binary form
 */
void john_gost_final(gost_ctx *ctx, unsigned char result[32])
{
	unsigned  index = (unsigned)ctx->length & 31;
	unsigned* msg32 = (unsigned*)ctx->message;

	/* pad the last block with zeroes and hash it */
	if (index > 0) {
		memset(ctx->message + index, 0, 32 - index);
		rhash_gost_compute_sum_and_hash(ctx, msg32);
	}

	/* hash the message length and the sum */
	msg32[0] = (unsigned)(ctx->length << 3);
	msg32[1] = (unsigned)(ctx->length >> 29);
	memset(msg32 + 2, 0, sizeof(unsigned)*6);

	rhash_gost_block_compress(ctx, msg32);
	rhash_gost_block_compress(ctx, ctx->sum);

	/* convert hash state to result bytes */
	le32_copy(result, 0, ctx->hash, gost_hash_length);
}

unsigned rhash_gost_sbox[4][256];
unsigned rhash_gost_sbox_cryptpro[4][256];

/**
 * Calculate a lookup table from S-Boxes.
 * A substitution table is used to speed up hash calculation.
 *
 * @param out pointer to the lookup table to fill
 * @param src pointer to eight S-Boxes to fill the table from
 */
static void rhash_gost_fill_sbox(unsigned out[4][256], const unsigned char src[8][16])
{
	int a, b, i;
	unsigned long ax, bx, cx, dx;

	for (i = 0, a = 0; a < 16; a++) {
		ax = (unsigned)src[1][a] << 15;
		bx = (unsigned)src[3][a] << 23;
		cx = ROTL32((unsigned)src[5][a], 31);
		dx = (unsigned)src[7][a] << 7;

		for (b = 0; b < 16; b++, i++) {
			out[0][i] = ax | ((unsigned)src[0][b] << 11);
			out[1][i] = bx | ((unsigned)src[2][b] << 19);
			out[2][i] = cx | ((unsigned)src[4][b] << 27);
			out[3][i] = dx | ((unsigned)src[6][b] << 3);
		}
	}
}

/**
 * Initialize the GOST lookup tables for both parameters sets.
 * Two lookup tables contain 8 KiB in total, so calculating
 * them at run-time can save a little space in the executable file
 * in trade of consuming some time at pogram start.
 */
void gost_init_table(void)
{
	/* Test parameters set. Eight 4-bit S-Boxes defined by GOST R 34.10-94
	 * standard for testing the hash function.
	 * Also given by RFC 4357 section 11.2 */
	static const unsigned char sbox[8][16] = {
		{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
		{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
		{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
		{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
		{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
		{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
		{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
		{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
	};

	/* Parameter set recommended by RFC 4357.
	 * Eight 4-bit S-Boxes as defined by RFC 4357 section 11.2 */
	static const unsigned char sbox_cryptpro[8][16] = {
		{ 10,  4,  5,  6,  8,  1,  3,  7, 13, 12, 14,  0,  9,  2, 11, 15 },
		{  5, 15,  4,  0,  2, 13, 11,  9,  1,  7,  6,  3, 12, 14, 10,  8 },
		{  7, 15, 12, 14,  9,  4,  1,  0,  3, 11,  5,  2,  6, 10,  8, 13 },
		{  4, 10,  7, 12,  0, 15,  2,  8, 14,  1,  6,  5, 13, 11,  9,  3 },
		{  7,  6,  4, 11,  9, 12,  2, 10,  1,  8,  0, 14, 15, 13,  3,  5 },
		{  7,  6,  2,  4, 13,  9, 15,  0, 10,  1,  5, 11,  8, 14, 12,  3 },
		{ 13, 14,  4,  1,  7,  0,  5, 10,  3, 12,  8, 15,  6,  2,  9, 11 },
		{  1,  3, 10,  9,  5, 11,  4, 15,  8,  6,  7, 14, 13,  0,  2, 12 }
	};
	/* allow this to be called multiple times, in case multiple formats use this
	   code during a run.  Right now, gost_fmt_plug.c uses it, but I am adding it
	   to dynamic, and thus, this function 'can' get called several times */
	static int init_called=0;
	if (init_called) return;
	init_called=1;

	rhash_gost_fill_sbox(rhash_gost_sbox, sbox);
	rhash_gost_fill_sbox(rhash_gost_sbox_cryptpro, sbox_cryptpro);
}

/*
 * gost HMAC context setup
 */
void john_gost_hmac_starts( gost_hmac_ctx *ctx, const unsigned char *key, size_t keylen )
{
	size_t i;
	unsigned char sum[32];

	if ( keylen > 32 )
	{
		john_gost_init( &ctx->ctx );
		john_gost_update( &ctx->ctx, key, keylen );
		john_gost_final( &ctx->ctx, sum );
		keylen = 32;
		key = sum;
	}

	memset( ctx->ipad, 0x36, 32 );
	memset( ctx->opad, 0x5C, 32 );

	for ( i = 0; i < keylen; i++ )
	{
		ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
		ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
	}

	john_gost_init( &ctx->ctx );
	john_gost_update( &ctx->ctx, ctx->ipad, 32 );
}

/*
 * gost HMAC process buffer
 */
void john_gost_hmac_update( gost_hmac_ctx *ctx, const unsigned char *input, size_t ilen )
{
	john_gost_update( &ctx->ctx, input, ilen );
}

/*
 * gost HMAC final digest
 */
void john_gost_hmac_finish( gost_hmac_ctx *ctx, unsigned char *output )
{
	unsigned char tmpbuf[32];

	john_gost_final( &ctx->ctx, tmpbuf );
	john_gost_init( &ctx->ctx );
	john_gost_update( &ctx->ctx, ctx->opad, 32 );
	john_gost_update( &ctx->ctx, tmpbuf, 32 );
	john_gost_final( &ctx->ctx, output );
}

/*
 * output = HMAC-gost( hmac key, input buffer )
 *
 * key == "password" and input == "" should produce output ==
 * "4463230a0698ba7525ebc40383d7c0834d1559e738472b8af305b65965d83a6d"
 */
void john_gost_hmac( const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char *output )
{
	gost_hmac_ctx ctx;

	john_gost_hmac_starts( &ctx, key, keylen );
	john_gost_hmac_update( &ctx, input, ilen );
	john_gost_hmac_finish( &ctx, output );
}

#ifdef TEST

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

struct {
    char   *text;
    unsigned char hash[32];
} tests[] =
{
    {  "",
	    {	0xce, 0x85, 0xb9, 0x9c, 0xc4, 0x67, 0x52, 0xff,
		0xfe, 0xe3, 0x5c, 0xab, 0x9a, 0x7b, 0x02, 0x78,
		0xab, 0xb4, 0xc2, 0xd2, 0x05, 0x5c, 0xff, 0x68,
		0x5a, 0xf4, 0x91, 0x2c, 0x49, 0x49, 0x0f, 0x8d }
    },
    { "This is message, length=32 bytes",
	    {	0xb1, 0xc4, 0x66, 0xd3, 0x75, 0x19, 0xb8, 0x2e,
		0x83, 0x19, 0x81, 0x9f, 0xf3, 0x25, 0x95, 0xe0,
		0x47, 0xa2, 0x8c, 0xb6, 0xf8, 0x3e, 0xff, 0x1c,
		0x69, 0x16, 0xa8, 0x15, 0xa6, 0x37, 0xff, 0xfa  }
    },
    { "Suppose the original message has length = 50 bytes",
	    {	0x47, 0x1a, 0xba, 0x57, 0xa6, 0x0a, 0x77, 0x0d,
		0x3a, 0x76, 0x13, 0x06, 0x35, 0xc1, 0xfb, 0xea,
		0x4e, 0xf1, 0x4d, 0xe5, 0x1f, 0x78, 0xb4, 0xae,
		0x57, 0xdd, 0x89, 0x3b, 0x62, 0xf5, 0x52, 0x08  }
    }
};

int main()
{
	unsigned char hash[32];
	gost_ctx ctx;
	int i;
	gost_init_table();
	for (i = 0; i < 3; i++) {
		gost_init(&ctx);
		gost_update(&ctx, tests[i].text, strlen(tests[i].text));
		gost_final(&ctx, hash);
		printf("test %i: ", i + 1);
		printf("hash %s\n", memcmp(tests[i].hash, hash, 32) ? "is bad" : "is good");
	}
	return 0;
}
#endif

void rhash_u32_swap_copy(void* to, int index, const void* from, size_t length) {
	size_t i;
	unsigned int *pO, *pI;
	pO = (unsigned int *)to;
	pI = (unsigned int *)from;
	length>>=2;
	for (i = 0; i < length; ++i) {
		*pO++ = JOHNSWAP(*pI++);
	}
}
