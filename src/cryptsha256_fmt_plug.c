/*
 * This file is part of John the Ripper password cracker,
 * based on rawSHA256_fmt.c code and Drepper's spec at
 * http://www.akkadia.org/drepper/SHA-crypt.txt
 *
 * This  software is Copyright © 2012 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 */

#include "arch.h"
//#if ARCH_BITS==32 && ARCH_LITTLE_ENDIAN == 1
//#define FORCE_GENERIC_SHA2
//#endif

#include "sha2.h"

#define _GNU_SOURCE
#include <string.h>

#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"

#ifdef _OPENMP
#define OMP_SCALE			16
#include <omp.h>
#endif

#define FORMAT_LABEL			"sha256crypt"
#define FORMAT_NAME			"sha256crypt"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR " " SHA2_LIB

#define BENCHMARK_COMMENT		" (rounds=5000)"
#define BENCHMARK_LENGTH		-1

// 35 character input is MAX password that fits into 2 SHA256 blocks
// 35 character input creates a 118 byte buffer, plus 1 for 0x80 and
// 1 unused byte and 8 byte bit length.  That is max for a 2 block crypt
#define PLAINTEXT_LENGTH		35
#define CIPHERTEXT_LENGTH		43

#define BINARY_SIZE			32
#define SALT_LENGTH			16

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
	{"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.", "U*U***U"},
	{"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
	// this 35 char PW 'should' work, in 1 & 2 buffer code, but it changes the
	// benchmark timings, so has been removed.  Uncomment, test your build, then re-comment it.
//	{"$5$mTfUlwguIR0Gp2ed$nX5lzmEGAZQ.1.CcncGnSq/lxSF7t1P.YkVlljQfOC2", "01234567890123456789012345678901234"},
	{"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
	{"$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43", ""},
	// A 36 byte PW fails with newest code.  It would require 3 block SHA buffering.
	// We only handle 1 and 2, at the current time.
	//{"$5$aewWTiO8RzEz5FBF$CZ3I.vdWF4omQXMQOv1g3XarjhH0wwR29Jwzt6/gvV/", "012345678901234567890123456789012345"},
	{NULL}
};

/* Prefix for optional rounds specification.  */
static const char sha256_rounds_prefix[] = "rounds=";

/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* This structure is 'pre-loaded' with the keyspace of all possible crypts which  */
/* will be performed WITHIN the inner loop.  There are 8 possible buffers that    */
/* are used.  They are cp, pspc, cspp, ppc, cpp, psc, csp, and pc, where p stands */
/* for the 'hash' built from the password (and it is the same length as the       */
/* password), s stands for the hash built from the salt (same size as salt), and  */
/* c stands for the crypt results from the prior loop.  There are 8 possible      */
/* buffer layouts listed, but they fall into a pattern that is 42 long (2*3*7)    */
/* this structure encapsulates this.  we build this buffer, after computing the   */
/* s hash, the p hash, and the starting c values.  Then, within the inner loop,   */
/* we simply spin through this structure, calling the SHA256 code to do the work. */
/* NOTE, most of the time, there will be 1 block and 2 block crypts.  As the      */
/* the password length grows, the more 2 block crypts there are, thus slower      */
typedef struct cryptloopstruct_t {
	unsigned char *buf;			// will allocate to hold 42 2 block buffers (42 * 2 * 64)  Reduced to only requiring 8*2*64
	unsigned char *bufs[42];	// points to the start of each 2 block buffer.
	unsigned char *cptr[42];	// points to where we copy the crypt pointer for next round.
								// Round 0 points to somewhere in round 1's buffer, etc.
	int datlen[42];				// if 1, then this is a small, only 1 block crypt. Some rounds for shorter passwords take only 1 crypt block.
								// NOTE, datlen could be changed to a number, and then we could do > 2 block crypts. Would take a little
								// more memory (and longer PW's certainly DO take more time), but it should work fine. It may be an issue
								// especially when doing OMP, that the memory footprint of this 'hot' inner loop simply gets too big, and
								// things slow down. For now, we are limiting ourselves to 35 byte password, which fits into 2 SHA256 buffers
} cryptloopstruct;

static int (*saved_key_length);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

/* these 2 values are used in setup of the cryptloopstruct, AND to do our SHA256_Init() calls, in the inner loop */
static const unsigned char padding[128] = { 0x80, 0 /* 0,0,0,0.... */ };
#ifndef JTR_INC_COMMON_CRYPTO_SHA2
static const ARCH_WORD_32 ctx_init[8] =
	{0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
#endif

#ifdef _OPENMP
cryptloopstruct *crypt_struct;
#else
cryptloopstruct crypt_struct[1];
#endif

static struct saltstruct {
	unsigned int len;
	unsigned int rounds;
	unsigned char salt[SALT_LENGTH];
} *cur_salt;
#define SALT_SIZE			sizeof(struct saltstruct)

static void init(struct fmt_main *self)
{
	int i;
#ifdef _OPENMP
	int omp_t;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt = omp_t * MIN_KEYS_PER_CRYPT;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt = omp_t * MAX_KEYS_PER_CRYPT;
	crypt_struct = mem_alloc_tiny(self->params.max_keys_per_crypt*sizeof(cryptloopstruct), MEM_ALIGN_WORD);
#endif
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	for (i = 0; i < self->params.max_keys_per_crypt; ++i)
		crypt_struct[i].buf = mem_alloc_tiny(8*2*64, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos, *start;

	if (strncmp(ciphertext, "$5$", 3))
		return 0;

	ciphertext += 3;

	if (!strncmp(ciphertext, sha256_rounds_prefix,
	             sizeof(sha256_rounds_prefix) - 1)) {
		const char *num = ciphertext + sizeof(sha256_rounds_prefix) - 1;
		char *endp;
		if (!strtoul(num, &endp, 10))
			return 0;
		if (*endp == '$')
			ciphertext = endp + 1;
	}

	for (pos = ciphertext; *pos && *pos != '$'; pos++);
	if (!*pos || pos < ciphertext || pos > &ciphertext[SALT_LENGTH]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;

	return 1;
}

#define TO_BINARY(b1, b2, b3) \
	value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

static void *get_binary(char *ciphertext)
{
	static ARCH_WORD_32 outbuf[BINARY_SIZE/4];
	ARCH_WORD_32 value;
	char *pos = strrchr(ciphertext, '$') + 1;
	unsigned char *out = (unsigned char*)outbuf;
	int i=0;

	do {
		TO_BINARY(i, (i+10)%30, (i+20)%30);
		i = (i+21)%30;
	} while (i != 0);
	value = (ARCH_WORD_32)atoi64[ARCH_INDEX(pos[0])] |
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[1])] << 6) |
		((ARCH_WORD_32)atoi64[ARCH_INDEX(pos[2])] << 12);
	out[31] = value >> 8; \
	out[30] = value; \
	return (void *)out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7FFFFFF; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xF; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xFF; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xFFF; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xFFFF; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xFFFFF; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xFFFFFF; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7FFFFFF; }

static void set_key(char *key, int index)
{
	int len = strlen(key);
	saved_key_length[index] = len;
	if (len > PLAINTEXT_LENGTH)
		len = saved_key_length[index] = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, len);
}

static char *get_key(int index)
{
	saved_key[index][saved_key_length[index]] = 0;
	return saved_key[index];
}

/*
These are the 8 types of buffers this algorithm uses:
cp
pspc
cspp
ppc
cpp
psc
csp
pc
*/
static void LoadCryptStruct(int index, char *p_bytes, char *s_bytes) {
	unsigned len_pc, len_ppsc, len_ppc, len_psc; // length of 'data'
	unsigned tot_pc, tot_ppsc, tot_ppc, tot_psc; // length of entire block to crypt (64 or 128)
	unsigned off_pc, off_pspc, off_ppc, off_psc; // offset to the crypt ptr for these 4 'types'.
	unsigned dlen_pc, dlen_ppsc, dlen_ppc, dlen_psc; // is this 1 or 2 block (or actual len for CommonCrypto, since it uses SHA256_Final()
	unsigned plen=saved_key_length[index];
	unsigned char *cp = crypt_struct[index].buf;
	cryptloopstruct *pstr = &(crypt_struct[index]);

	len_pc   = plen + BINARY_SIZE;
	len_ppsc = (plen<<1) + cur_salt->len + BINARY_SIZE;
	len_ppc  = (plen<<1) + BINARY_SIZE;
	len_psc  = plen + cur_salt->len + BINARY_SIZE;

#ifdef JTR_INC_COMMON_CRYPTO_SHA2
	if (len_pc  <=55) tot_pc  =64; else tot_pc  =128;
	if (len_ppsc<=55) tot_ppsc=64; else tot_ppsc=128;
	if (len_ppc <=55) tot_ppc =64; else tot_ppc =128;
	if (len_psc <=55) tot_psc =64; else tot_psc =128;
	dlen_pc  =len_pc;
	dlen_ppsc=len_ppsc;
	dlen_ppc =len_ppc;
	dlen_psc =len_psc;
#else
	if (len_pc  <=55) {tot_pc  =64; dlen_pc  =64;}else{tot_pc  =128; dlen_pc  =128; }
	if (len_ppsc<=55) {tot_ppsc=64; dlen_ppsc=64;}else{tot_ppsc=128; dlen_ppsc=128; }
	if (len_ppc <=55) {tot_ppc =64; dlen_ppc =64;}else{tot_ppc =128; dlen_ppc =128; }
	if (len_psc <=55) {tot_psc =64; dlen_psc =64;}else{tot_psc =128; dlen_psc =128; }
#endif
	off_pc   = len_pc   - BINARY_SIZE;
	off_pspc = len_ppsc - BINARY_SIZE;
	off_ppc  = len_ppc  - BINARY_SIZE;
	off_psc  = len_psc  - BINARY_SIZE;

	// pstr->buf[0] is a cp  (First of this type)
	pstr->bufs[0] = pstr->cptr[41] = cp;
	// For fist element only, we DO copy in the c value.
	memcpy(cp, crypt_out[index], BINARY_SIZE); cp += BINARY_SIZE;
	memcpy(cp, p_bytes, plen); cp += plen;
	pstr->datlen[0] = dlen_pc;
	memcpy(cp, padding, tot_pc-2-len_pc); cp += (tot_pc-len_pc);
	pstr->bufs[0][tot_pc-2] = (len_pc<<3)>>8;
	pstr->bufs[0][tot_pc-1] = (len_pc<<3)&0xFF;

	// pstr->buf[1] is a pspc  (First of this type)
	pstr->bufs[1] = cp;
	pstr->cptr[0] = cp + off_pspc;
	memcpy(cp, p_bytes, plen); cp += plen;
	memcpy(cp, s_bytes, cur_salt->len); cp += cur_salt->len;
	memcpy(cp, p_bytes, plen); cp += (plen+BINARY_SIZE);
	pstr->datlen[1] = dlen_ppsc;
	memcpy(cp, padding, tot_ppsc-2-len_ppsc);  cp += (tot_ppsc-len_ppsc);
	pstr->bufs[1][tot_ppsc-2] = (len_ppsc<<3)>>8;
	pstr->bufs[1][tot_ppsc-1] = (len_ppsc<<3)&0xFF;

	// pstr->buf[2] is a cspp  (First of this type)
	pstr->bufs[2] = pstr->cptr[1] = cp;
	cp += BINARY_SIZE;
	memcpy(cp, s_bytes, cur_salt->len); cp += cur_salt->len;
	memcpy(cp, p_bytes, plen); cp += plen;
	memcpy(cp, p_bytes, plen); cp += plen;
	pstr->datlen[2] = dlen_ppsc;
	memcpy(cp, padding, tot_ppsc-2-len_ppsc);  cp += (tot_ppsc-len_ppsc);
	pstr->bufs[2][tot_ppsc-2] = (len_ppsc<<3)>>8;
	pstr->bufs[2][tot_ppsc-1] = (len_ppsc<<3)&0xFF;

	// pstr->buf[3] is a ppc  (First of this type)
	pstr->bufs[3] = cp;
	pstr->cptr[2] = cp + off_ppc;
	memcpy(cp, p_bytes, plen); cp += plen;
	memcpy(cp, p_bytes, plen); cp +=(plen+BINARY_SIZE);
	pstr->datlen[3] = dlen_ppc;
	memcpy(cp, padding, tot_ppc-2-len_ppc);  cp += (tot_ppc-len_ppc);
	pstr->bufs[3][tot_ppc-2] = (len_ppc<<3)>>8;
	pstr->bufs[3][tot_ppc-1] = (len_ppc<<3)&0xFF;

	// pstr->buf[4] is a cspp  (from 2)
	pstr->bufs[4] = pstr->cptr[3] = pstr->bufs[2];
	pstr->datlen[4] = dlen_ppsc;

	// pstr->buf[5] is a pspc  (from [1])
	pstr->bufs[5] = pstr->bufs[1]; pstr->cptr[4] = pstr->cptr[0];
	pstr->datlen[5] = dlen_ppsc;

	// pstr->buf[6] is a cpp  (First of this type)
	pstr->bufs[6] = pstr->cptr[5] = cp;
	cp += BINARY_SIZE;
	memcpy(cp, p_bytes, plen); cp += plen;
	memcpy(cp, p_bytes, plen); cp += plen;
	pstr->datlen[6] = dlen_ppc;
	memcpy(cp, padding, tot_ppc-2-len_ppc);  cp += (tot_ppc-len_ppc);
	pstr->bufs[6][tot_ppc-2] = (len_ppc<<3)>>8;
	pstr->bufs[6][tot_ppc-1] = (len_ppc<<3)&0xFF;

	// pstr->buf[07] psc  (First of this type)
	pstr->bufs[7] = cp;
	pstr->cptr[6] = cp + off_psc;
	memcpy(cp, p_bytes, plen); cp += plen;
	memcpy(cp, s_bytes, cur_salt->len); cp += (cur_salt->len+BINARY_SIZE);
	pstr->datlen[7] = dlen_psc;
	memcpy(cp, padding, tot_psc-2-len_psc);  cp += (tot_psc-len_psc);
	pstr->bufs[7][tot_psc-2] = (len_psc<<3)>>8;
	pstr->bufs[7][tot_psc-1] = (len_psc<<3)&0xFF;

	// pstr->buf[08] cspp  (from 2)
	pstr->bufs[8] = pstr->cptr[7] = pstr->bufs[2];
	pstr->datlen[8] = dlen_ppsc;

	// pstr->buf[09] ppc   (from 3)
	pstr->bufs[9] = pstr->bufs[3]; pstr->cptr[8] = pstr->cptr[2];
	pstr->datlen[9] = dlen_ppc;

	// pstr->buf[10] cspp  (from 2)
	pstr->bufs[10] = pstr->cptr[9] = pstr->bufs[2];
	pstr->datlen[10] = dlen_ppsc;

	// pstr->buf[11] pspc  (from 1)
	pstr->bufs[11] = pstr->bufs[1]; pstr->cptr[10] = pstr->cptr[0];
	pstr->datlen[11] = dlen_ppsc;

	// pstr->buf[12] cpp   (from 6)
	pstr->bufs[12] = pstr->cptr[11] = pstr->bufs[6];
	pstr->datlen[12] = dlen_ppc;

	// pstr->buf[13] pspc  (from 1)
	pstr->bufs[13] = pstr->bufs[1]; pstr->cptr[12] = pstr->cptr[0];
	pstr->datlen[13] = dlen_ppsc;

	// pstr->buf[14] csp   (First of this type)
	pstr->bufs[14] = pstr->cptr[13] = cp;
	cp += BINARY_SIZE;
	memcpy(cp, s_bytes, cur_salt->len); cp += cur_salt->len;
	memcpy(cp, p_bytes, plen); cp += plen;
	pstr->datlen[14] = dlen_psc;
	memcpy(cp, padding, tot_psc-2-len_psc);  cp += (tot_psc-len_psc);
	pstr->bufs[14][tot_psc-2] = (len_psc<<3)>>8;
	pstr->bufs[14][tot_psc-1] = (len_psc<<3)&0xFF;

	// pstr->buf[15] ppc   (from 3)
	pstr->bufs[15] = pstr->bufs[3]; pstr->cptr[14] = pstr->cptr[2];
	pstr->datlen[15] = dlen_ppc;

	// pstr->buf[16] cspp  (from 2)
	pstr->bufs[16] = pstr->cptr[15] = pstr->bufs[2];
	pstr->datlen[16] = dlen_ppsc;

	// pstr->buf[17] pspc  (from 1)
	pstr->bufs[17] = pstr->bufs[1]; pstr->cptr[16] = pstr->cptr[0];
	pstr->datlen[17] = dlen_ppsc;

	// pstr->buf[18] cpp   (from 6)
	pstr->bufs[18] = pstr->cptr[17] = pstr->bufs[6];
	pstr->datlen[18] = dlen_ppc;

	// pstr->buf[19] pspc  (from 1)
	pstr->bufs[19] = pstr->bufs[1]; pstr->cptr[18] = pstr->cptr[0];
	pstr->datlen[19] = dlen_ppsc;

	// pstr->buf[20] cspp  (from 2)
	pstr->bufs[20] = pstr->cptr[19] = pstr->bufs[2];
	pstr->datlen[20] = dlen_ppsc;

	// pstr->buf[21] pc    (First of this type)
	pstr->bufs[21] = cp;
	pstr->cptr[20] = cp + off_pc;
	memcpy(cp, p_bytes, plen); cp += (plen+BINARY_SIZE);
	pstr->datlen[21] = dlen_pc;
	memcpy(cp, padding, tot_psc-2-len_pc);  cp += (tot_pc-len_pc);
	pstr->bufs[21][tot_pc-2] = (len_pc<<3)>>8;
	pstr->bufs[21][tot_pc-1] = (len_pc<<3)&0xFF;

	// pstr->buf[22] cspp  (from 2)
	pstr->bufs[22] = pstr->cptr[21] = pstr->bufs[2];
	pstr->datlen[22] = dlen_ppsc;

	// pstr->buf[23] pspc  (from 1)
	pstr->bufs[23] = pstr->bufs[1]; pstr->cptr[22] = pstr->cptr[0];
	pstr->datlen[23] = dlen_ppsc;

	// pstr->buf[24] cpp   (from 6)
	pstr->bufs[24] = pstr->cptr[23] = pstr->bufs[6];
	pstr->datlen[24] = dlen_ppc;

	// pstr->buf[25] pspc  (from 1)
	pstr->bufs[25] = pstr->bufs[1]; pstr->cptr[24] = pstr->cptr[0];
	pstr->datlen[25] = dlen_ppsc;

	// pstr->buf[26] cspp  (from 2)
	pstr->bufs[26] = pstr->cptr[25] = pstr->bufs[2];
	pstr->datlen[26] = dlen_ppsc;

	// pstr->buf[27] ppc   (from 3)
	pstr->bufs[27] = pstr->bufs[3]; pstr->cptr[26] = pstr->cptr[2];
	pstr->datlen[27] = dlen_ppc;

	// pstr->buf[28] csp   (from 14)
	pstr->bufs[28] = pstr->cptr[27] = pstr->bufs[14];
	pstr->datlen[28] = dlen_psc;

	// pstr->buf[29] pspc  (from 1)
	pstr->bufs[29] = pstr->bufs[1]; pstr->cptr[28] = pstr->cptr[0];
	pstr->datlen[29] = dlen_ppsc;

	// pstr->buf[30] cpp   (from 6)
	pstr->bufs[30] = pstr->cptr[29] = pstr->bufs[6];
	pstr->datlen[30] = dlen_ppc;

	// pstr->buf[31] pspc  (from 1)
	pstr->bufs[31] = pstr->bufs[1]; pstr->cptr[30] = pstr->cptr[0];
	pstr->datlen[31] = dlen_ppsc;

	// pstr->buf[32] cspp  (from 2)
	pstr->bufs[32] = pstr->cptr[31] = pstr->bufs[2];
	pstr->datlen[32] = dlen_ppsc;

	// pstr->buf[33] ppc   (from 3)
	pstr->bufs[33] = pstr->bufs[3]; pstr->cptr[32] = pstr->cptr[2];
	pstr->datlen[33] = dlen_ppc;

	// pstr->buf[34] cspp  (from 2)
	pstr->bufs[34] = pstr->cptr[33] = pstr->bufs[2];
	pstr->datlen[34] = dlen_ppsc;

	// pstr->buf[35] psc   (from 7)
	pstr->bufs[35] = pstr->bufs[7]; pstr->cptr[34] = pstr->cptr[6];
	pstr->datlen[35] = dlen_psc;

	// pstr->buf[36] cpp   (from 6)
	pstr->bufs[36] = pstr->cptr[35] = pstr->bufs[6];
	pstr->datlen[36] = dlen_ppc;

	// pstr->buf[37] pspc  (from 1)
	pstr->bufs[37] = pstr->bufs[1]; pstr->cptr[36] = pstr->cptr[0];
	pstr->datlen[37] = dlen_ppsc;

	// pstr->buf[38] cspp  (from 2)
	pstr->bufs[38] = pstr->cptr[37] = pstr->bufs[2];
	pstr->datlen[38] = dlen_ppsc;

	// pstr->buf[39] ppc   (from 3)
	pstr->bufs[39] = pstr->bufs[3]; pstr->cptr[38] = pstr->cptr[2];
	pstr->datlen[39] = dlen_ppc;

	// pstr->buf[40] cspp  (from 2)
	pstr->bufs[40] = pstr->cptr[39] = pstr->bufs[2];
	pstr->datlen[40] = dlen_ppsc;

	// pstr->buf[41] pspc  (from 1)
	pstr->bufs[41] = pstr->bufs[1]; pstr->cptr[40] = pstr->cptr[0];
	pstr->datlen[41] = dlen_ppsc;
}


static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		// portably align temp_result char * pointer machine word size.
		union xx {
			unsigned char c[BINARY_SIZE];
			ARCH_WORD a[BINARY_SIZE/sizeof(ARCH_WORD)];
		} u;
		unsigned char *temp_result = u.c;
		SHA256_CTX ctx;
		SHA256_CTX alt_ctx;
		size_t cnt;
		int idx;
		char *cp;
		char p_bytes[PLAINTEXT_LENGTH+1];
		char s_bytes[PLAINTEXT_LENGTH+1];

		/* Prepare for the real work.  */
		SHA256_Init(&ctx);

		/* Add the key string.  */
		SHA256_Update(&ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* The last part is the salt string.  This must be at most 16
		   characters and it ends at the first `$' character (for
		   compatibility with existing implementations).  */
		SHA256_Update(&ctx, cur_salt->salt, cur_salt->len);

		/* Compute alternate SHA256 sum with input KEY, SALT, and KEY.  The
		   final result will be added to the first context.  */
		SHA256_Init(&alt_ctx);

		/* Add key.  */
		SHA256_Update(&alt_ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Add salt.  */
		SHA256_Update(&alt_ctx, cur_salt->salt, cur_salt->len);

		/* Add key again.  */
		SHA256_Update(&alt_ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Now get result of this (32 bytes) and add it to the other
		   context.  */
		SHA256_Final((unsigned char*)crypt_out[index], &alt_ctx);

		/* Add for any character in the key one byte of the alternate sum.  */
		for (cnt = saved_key_length[index]; cnt > BINARY_SIZE; cnt -= BINARY_SIZE)
			SHA256_Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
		SHA256_Update(&ctx, (unsigned char*)crypt_out[index], cnt);

		/* Take the binary representation of the length of the key and for every
		   1 add the alternate sum, for every 0 the key.  */
		for (cnt = saved_key_length[index]; cnt > 0; cnt >>= 1)
			if ((cnt & 1) != 0)
				SHA256_Update(&ctx, (unsigned char*)crypt_out[index], BINARY_SIZE);
			else
				SHA256_Update(&ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Create intermediate result.  */
		SHA256_Final((unsigned char*)crypt_out[index], &ctx);

		/* Start computation of P byte sequence.  */
		SHA256_Init(&alt_ctx);

		/* For every character in the password add the entire password.  */
		for (cnt = 0; cnt < saved_key_length[index]; ++cnt)
			SHA256_Update(&alt_ctx, (unsigned char*)saved_key[index], saved_key_length[index]);

		/* Finish the digest.  */
		SHA256_Final(temp_result, &alt_ctx);

		/* Create byte sequence P.  */
		cp = p_bytes;
		for (cnt = saved_key_length[index]; cnt >= BINARY_SIZE; cnt -= BINARY_SIZE)
			cp = (char *) memcpy (cp, temp_result, BINARY_SIZE) + BINARY_SIZE;
		memcpy (cp, temp_result, cnt);

		/* Start computation of S byte sequence.  */
		SHA256_Init(&alt_ctx);

		/* For every character in the password add the entire password.  */
		for (cnt = 0; cnt < 16 + ((unsigned char*)crypt_out[index])[0]; ++cnt)
			SHA256_Update(&alt_ctx, cur_salt->salt, cur_salt->len);

		/* Finish the digest.  */
		SHA256_Final(temp_result, &alt_ctx);

		/* Create byte sequence S.  */
		cp = s_bytes;
		for (cnt = cur_salt->len; cnt >= BINARY_SIZE; cnt -= BINARY_SIZE)
			cp = (char *) memcpy (cp, temp_result, BINARY_SIZE) + BINARY_SIZE;
		memcpy (cp, temp_result, cnt);

		/* Repeatedly run the collected hash value through SHA256 to
		   burn CPU cycles.  */
		idx = 0;
		LoadCryptStruct(index, p_bytes, s_bytes);

		SHA256_Init(&ctx);
		for (cnt = 1; ; ++cnt) {
			// calling with 64 byte, or 128 byte always, will force the update to properly crypt the data.
			// NOTE the data is fully formed. It ends in a 0x80, is padded with nulls, AND has bit appended.
			SHA256_Update(&ctx, crypt_struct[index].bufs[idx], crypt_struct[index].datlen[idx]);

			if (cnt == cur_salt->rounds)
				break;
#ifdef JTR_INC_COMMON_CRYPTO_SHA2
			SHA256_Final(crypt_struct[index].cptr[idx], &ctx);
#else // !defined JTR_INC_COMMON_CRYPTO_SHA2, so it is oSSL, or generic
#if ARCH_LITTLE_ENDIAN == 1
			{
				int j;
				ARCH_WORD_32 *o = (ARCH_WORD_32 *)crypt_struct[index].cptr[idx];
				for (j = 0; j < 8; ++j)
					*o++ = JOHNSWAP(ctx.h[j]);
			}
#else
			memcpy(crypt_struct[index].cptr[idx], ctx.h, BINARY_SIZE);
#endif
#endif
			if (++idx == 42)
				idx = 0;

#ifdef JTR_INC_COMMON_CRYPTO_SHA2
			SHA256_Init(&ctx);
#else
			// this memcpy is 'good enough', used instead of SHA256_Init()
			memcpy(ctx.h, ctx_init, sizeof(ctx_init));
#endif
		}
#ifdef JTR_INC_COMMON_CRYPTO_SHA2
		SHA256_Final((unsigned char*)crypt_out[index], &ctx);
#else
#if ARCH_LITTLE_ENDIAN == 1
		{
			int j;
			ARCH_WORD_32 *o = (ARCH_WORD_32 *)crypt_out[index];
			for (j = 0; j < 8; ++j)
				*o++ = JOHNSWAP(ctx.h[j]);
		}
#else
		memcpy(crypt_out[index], ctx.h, BINARY_SIZE);
#endif
#endif
	}
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

static void *get_salt(char *ciphertext)
{
	static struct saltstruct out;
	int len;

	out.rounds = ROUNDS_DEFAULT;
	ciphertext += 3;
	if (!strncmp(ciphertext, sha256_rounds_prefix,
	             sizeof(sha256_rounds_prefix) - 1)) {
		const char *num = ciphertext + sizeof(sha256_rounds_prefix) - 1;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);
		if (*endp == '$')
		{
			ciphertext = endp + 1;
			out.rounds = srounds < ROUNDS_MIN ?
				ROUNDS_MIN : srounds;
			out.rounds = srounds > ROUNDS_MAX ?
				ROUNDS_MAX : srounds;
		}
	}

	for (len = 0; ciphertext[len] != '$'; len++);

	memcpy(out.salt, ciphertext, len);
	out.len = len;
	return &out;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

// Public domain hash function by DJ Bernstein
// We are hashing the entire struct
static int salt_hash(void *salt)
{
	unsigned char *s = salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < SALT_SIZE; i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_cryptsha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
