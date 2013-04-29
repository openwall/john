/*
 * MSCHAPv2_fmt.c -- Microsoft PPP CHAP Extensions, Version 2
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2010
 * and placed in the public domain.
 *
 * Modified for performance, OMP and utf-8 support
 * by magnum 2010-2011
 *
 * Support for freeradius-wep-patch challenge/response format
 * added by Linus Lüssing in 2012 and is licensed under CC0/PD terms:
 *  To the extent possible under law, Linus Lüssing has waived all copyright
 *  and related or neighboring rights to this work. This work is published from: Germany.
 *
 *
 * This algorithm is designed for performing brute-force cracking of the
 * MSCHAPv2 challenge/response sets exchanged during network-based
 * authentication attempts. The captured challenge/response set from these
 * attempts should be stored using the following format:
 *
 * USERNAME:::AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * USERNAME::DOMAIN:AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * DOMAIN\USERNAME:::AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * :::MSCHAPv2 CHALLENGE:MSCHAPv2 RESPONSE:
 *
 * For example:
 * User:::5B5D7C7D7B3F2F3E3C2C602132262628:82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF:21402324255E262A28295F2B3A337C7E
 * domain\fred:::56d64cbe7bad61349a0b752335100eaf:d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b:7f8a466cff2a6bf0c80218bbf56d76bc
 *
 * http://freeradius.org/rfc/rfc2759.txt
 *
 */

#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#ifdef MD4_SSE_PARA
#define NBKEYS			(MMX_COEF * MD4_SSE_PARA)
#elif MMX_COEF
#define NBKEYS			MMX_COEF
#else
#ifdef _OPENMP
#define OMP_SCALE		4
#include <omp.h>
#endif
#endif
#include "sse-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "memory.h"
#include "sha.h"
#include "md4.h"
#include "unicode.h"

#ifndef uchar
#define uchar unsigned char
#endif
#define MIN(a, b)		(((a) > (b)) ? (b) : (a))

#define FORMAT_LABEL		"mschapv2"
#define FORMAT_NAME		"MSCHAPv2 C/R MD4 DES"
#define ALGORITHM_NAME		MD4_ALGORITHM_NAME
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1000
#define USERNAME_LENGTH		256 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH		15	/* lmcons.h - CNLEN / DNLEN */
#define FULL_BINARY_SIZE	(2 + 8 * 3)
#define BINARY_SIZE		(2 + 8)
#define BINARY_ALIGN		2
#define SALT_SIZE		8
#define SALT_ALIGN		1
#define CHALLENGE_LENGTH	64
#define CIPHERTEXT_LENGTH	48
#define TOTAL_LENGTH		13 + USERNAME_LENGTH + CHALLENGE_LENGTH + CIPHERTEXT_LENGTH

#ifdef MMX_COEF
#define PLAINTEXT_LENGTH	27
#ifdef MD4_SSE_PARA
//#define SSE_OMP
#if defined (_OPENMP) && defined(SSE_OMP)
#define BLOCK_LOOPS		(2048 / NBKEYS)
#else
#define BLOCK_LOOPS		(1024 / NBKEYS)
#endif
#else
#define BLOCK_LOOPS		1 /* Only 1 is supported for MMX/SSE asm. */
#endif
#define MIN_KEYS_PER_CRYPT	(NBKEYS * BLOCK_LOOPS)
#define MAX_KEYS_PER_CRYPT	(NBKEYS * BLOCK_LOOPS)
#define GETPOS(i, index)	( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*16*MMX_COEF*4 )
#define GETOUTPOS(i, index)	( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*4*MMX_COEF*4 )
#else
#define PLAINTEXT_LENGTH	64
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	2048
#endif

static struct fmt_tests tests[] = {
	{"$MSCHAPv2$4c092fd3fd98236502e8591100046326$b912ce522524d33123a982cf330a57f8e953fa7974042b5d$6a4915d0ce61d42be533640a75391925$1111", "2222"},
	{"$MSCHAPv2$5B5D7C7D7B3F2F3E3C2C602132262628$82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF$21402324255E262A28295F2B3A337C7E$User", "clientPass"},
	{"$MSCHAPv2$d07054459a1fdbc266a006f0220e6fac$33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde$3545cb1d89b507a5de104435e81b14a4$testuser1", "Cricket8"},
	{"$MSCHAPv2$56d64cbe7bad61349a0b752335100eaf$d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b$7f8a466cff2a6bf0c80218bbf56d76bc$fred", "OMG!BBQ!11!one"}, /* domain\fred */
#if PLAINTEXT_LENGTH >= 35
	{"$MSCHAPv2$b3c42db475b881d3c52ff3923d7b3bf8$f07c7a4eb391f5debe32d814679a5a69661b86b33227c4f8$6321f8649b971bd11ce8d5cb22a4a738$bOb", "asdblahblahblahblahblahblahblahblah"}, /* WorkGroup\bOb */
#endif
	{"$MSCHAPv2$d94e7c7972b2376b28c268583e162de7$eba25a3b04d2c7085d01f842e2befc91745c40db0f792356$0677ca7318fd7f65ae1b4f58c9f4f400$lameuser", ""}, /* no password */
	{"$MSCHAPv2$8710da60ebfc4cab$c4e3bb55904c966927ee68e5f1472e1f5d8ec165713b5360$$foo4", "bar4" },
	{"$MSCHAPv2$8710da60ebfc4cab$c4e3bb55904c966927ee68e5f1472e1f5d8ec165713b5360$$", "bar4" },

	/* Ettercap generated three test vectors */
	{"$MSCHAPv2$3D79CC8CDC0261D4$B700770725F87739ADB110B310D9A289CDBB550ADCA6CB86$solar", "solarisalwaysbusy"},
	{"$MSCHAPv2$BA75EB14EFBFBF25$ED8CC90FD40FAA2D6BCD0ABD0B1F562FD777DF6C5609C98B$lulu", "password"},
	{"$MSCHAPv2$95A87FA62EBCD2E3C8B09E1B448A6C72$ED8CC90FD40FAA2D6BCD0ABD0B1F562FD777DF6C5609C98B$E2AE0995EAAC6CEFF0D9757428B51509$lulu", "password"},

	/* Single test vector from chapcrack's sample pcap file */
	{"$MSCHAPv2$6D0E1C056CD94D5F$1C93ABCE815400686BAECA315F348469256420598A73AD49$moxie", "bPCFyF2uL1p5Lg5yrKmqmY"},

	{"", "clientPass",     {"User",        "", "",    "5B5D7C7D7B3F2F3E3C2C602132262628", "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "21402324255E262A28295F2B3A337C7E"} },
	{"", "Cricket8",       {"testuser1",   "", "",    "d07054459a1fdbc266a006f0220e6fac", "33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde", "3545cb1d89b507a5de104435e81b14a4"} },
	{"", "OMG!BBQ!11!one", {"domain\\fred", "", "",   "56d64cbe7bad61349a0b752335100eaf", "d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b", "7f8a466cff2a6bf0c80218bbf56d76bc"} }, /* domain\fred */
	{"", "",               {"lameuser", "", "domain", "d94e7c7972b2376b28c268583e162de7", "eba25a3b04d2c7085d01f842e2befc91745c40db0f792356", "0677ca7318fd7f65ae1b4f58c9f4f400"} }, /* no password */
	{NULL}
};

#ifdef MMX_COEF
static unsigned char *saved_key;
#ifndef MD4_SSE_PARA
static unsigned int total_len;
#endif
#else
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_key_length);
#endif

typedef unsigned short HOT_TYPE;
static HOT_TYPE (*crypt_key);
static unsigned char *nthash;
static ARCH_WORD_32 *bitmap;
static int cmps_per_crypt, use_bitmap;
static int valid_i, valid_j;

static uchar *challenge;
static int keys_prepared;

static void set_key_utf8(char *_key, int index);
static void set_key_CP(char *_key, int index);

static void init(struct fmt_main *self)
{
#if defined (_OPENMP) && !defined(MMX_COEF)
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif

	if (options.utf8) {
		self->methods.set_key = set_key_utf8;
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
	} else {
		if (!options.ascii && !options.iso8859_1)
			self->methods.set_key = set_key_CP;
	}
#if MMX_COEF
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * 64 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	nthash = mem_calloc_tiny(sizeof(*nthash) * 16 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	nthash = mem_calloc_tiny(sizeof(*nthash) * 16 * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
#endif
	crypt_key = mem_calloc_tiny(sizeof(HOT_TYPE) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	bitmap = mem_calloc_tiny(0x10000 / 8, MEM_ALIGN_SIMD);
	use_bitmap = 0; /* we did not use bitmap yet */
	cmps_per_crypt = 2; /* try bitmap */
}

static int valid_long(char *ciphertext)
{
	char *pos, *pos2;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, "$MSCHAPv2$", 10)!=0) return 0;

	if (strlen(ciphertext) > TOTAL_LENGTH)
		return 0;

	/* Validate Authenticator/Server Challenge Length */
	pos = &ciphertext[10];
	for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
		return 0;

	/* Validate MSCHAPv2 Response Length */
	pos2++; pos = pos2;
	for (; strncmp(pos2, "$", 1) != 0; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
		return 0;

	/* Validate Peer/Client Challenge Length */
	pos2++; pos = pos2;
	for (; strncmp(pos2, "$", 1) != 0; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
		return 0;

	/* Validate Username Length */
	if (strlen(++pos2) > USERNAME_LENGTH)
		return 0;

	return 1;
}

static int valid_short(char *ciphertext)
{
	char *pos, *pos2;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, "$MSCHAPv2$", 10)!=0) return 0;

	if (strlen(ciphertext) > TOTAL_LENGTH)
		return 0;

	/* Validate MSCHAPv2 Challenge Length */
	pos = &ciphertext[10];
	for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 4)) )
		return 0;

	/* Validate MSCHAPv2 Response Length */
	pos2++; pos = pos2;
	for (; strncmp(pos2, "$", 1) != 0; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext);
static inline void setup_des_key(uchar key_56[], DES_key_schedule *ks);

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *cp = NULL;

	if (valid_short(ciphertext))
		cp = ciphertext + 10 + CHALLENGE_LENGTH / 4 + 1;
	else if (valid_long(ciphertext))
		cp = ciphertext + 10 + CHALLENGE_LENGTH / 2 + 1;

	if (cp) {
		uchar key[7] = {0, 0, 0, 0, 0, 0, 0};
		DES_key_schedule ks;
		DES_cblock b3cmp;
		uchar binary[8];
		DES_cblock *challenge = get_salt(ciphertext);
		int i, j;

		cp += 2 * 8 * 2;

		for (i = 0; i < 8; i++) {
			binary[i] = atoi16[ARCH_INDEX(cp[i * 2])] << 4;
			binary[i] |= atoi16[ARCH_INDEX(cp[i * 2 + 1])];
		}

		key[0] = valid_i; key[1] = valid_j;
		setup_des_key(key, &ks);
		DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
		if (!memcmp(binary, &b3cmp, 8))
			return 1;

		for (i = 0; i < 0x100; i++)
		for (j = 0; j < 0x100; j++) {
			key[0] = i; key[1] = j;
			setup_des_key(key, &ks);
			DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
			if (!memcmp(binary, &b3cmp, 8)) {
				valid_i = i;
				valid_j = j;
				return 1;
			}
		}
#ifdef DEBUG
		fprintf(stderr, "Rejected MSCHAPv2 hash with invalid 3rd block\n");
#endif
	}
	return 0;
}

static char *prepare_long(char *split_fields[10])
{
	char *username, *cp;

	/* DOMAIN\USERNAME -or - USERNAME -- ignore DOMAIN */
	if ((username = strstr(split_fields[0], "\\")) == NULL)
		username = split_fields[0];
	else
		username++;

	cp = mem_alloc(1+8+1+strlen(split_fields[3])+1+strlen(split_fields[4])+1+strlen(split_fields[5])+1+strlen(username)+1);
	sprintf(cp, "$MSCHAPv2$%s$%s$%s$%s", split_fields[3], split_fields[4], split_fields[5], username);
	if (valid_long(cp)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *prepare_short(char *split_fields[10])
{
	char *cp;

	cp = mem_alloc(1+8+1+strlen(split_fields[3])+1+strlen(split_fields[4])+1+1+1);
	sprintf(cp, "$MSCHAPv2$%s$%s$$", split_fields[3], split_fields[4]);
	if (valid_short(cp)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	char *ret;

	if (!strncmp(split_fields[1], "$MSCHAPv2$", 10))
		ret = NULL;
	else if (split_fields[0] && split_fields[3] && split_fields[4] && split_fields[5] &&
	         strlen(split_fields[3]) == CHALLENGE_LENGTH/2 &&
	         strlen(split_fields[4]) == CIPHERTEXT_LENGTH &&
	         strlen(split_fields[5]) == CHALLENGE_LENGTH/2)
		ret = prepare_long(split_fields);
	else if (split_fields[0] && split_fields[3] && split_fields[4] &&
	         strlen(split_fields[3]) == CHALLENGE_LENGTH/4 &&
	         strlen(split_fields[4]) == CIPHERTEXT_LENGTH)
		ret = prepare_short(split_fields);
	else
		ret = NULL;

	return ret ? ret : split_fields[1];
}

static char *split(char *ciphertext, int index)
{
	static char out[TOTAL_LENGTH + 1];
	int i, j = 0;

	memset(out, 0, TOTAL_LENGTH + 1);
	memcpy(out, ciphertext, strlen(ciphertext));

	/* convert hashes to lower-case - exclude $MSCHAPv2 and USERNAME */
	for (i = 10; i < TOTAL_LENGTH + 1 && j < 3; i++) {
		if (out[i] >= 'A' && out[i] <= 'Z')
			out[i] |= 0x20;
		else if (out[i] == '$')
			j++;
	}

	return out;
}

static inline void setup_des_key(uchar key_56[], DES_key_schedule *ks)
{
	DES_cblock key;

	key[0] = key_56[0];
	key[1] = (key_56[0] << 7) | (key_56[1] >> 1);
	key[2] = (key_56[1] << 6) | (key_56[2] >> 2);
	key[3] = (key_56[2] << 5) | (key_56[3] >> 3);
	key[4] = (key_56[3] << 4) | (key_56[4] >> 4);
	key[5] = (key_56[4] << 3) | (key_56[5] >> 5);
	key[6] = (key_56[5] << 2) | (key_56[6] >> 6);
	key[7] = (key_56[6] << 1);

	DES_set_key(&key, ks);
}

static void *get_binary(char *ciphertext)
{
	static uchar *binary;
	static int warned = 0, loaded = 0;
	DES_cblock *challenge = get_salt(ciphertext);
	int i, j;

	if (!binary) binary = mem_alloc_tiny(FULL_BINARY_SIZE, BINARY_ALIGN);

	if (!warned && ++loaded > 100) {
		warned = 1;
		fprintf(stderr, FORMAT_LABEL ": Note: slow loading. For short "
		        "runs, try --format=" FORMAT_LABEL "-naive\ninstead. "
		        "That version loads faster but runs slower.\n");
	}

	if (valid_short(ciphertext))
		ciphertext += 10 + CHALLENGE_LENGTH / 4 + 1; /* Skip - $MSCHAPv2$, MSCHAPv2 Challenge */
	else
		ciphertext += 10 + CHALLENGE_LENGTH / 2 + 1; /* Skip - $MSCHAPv2$, Authenticator Challenge */

	for (i = 0; i < FULL_BINARY_SIZE - 2; i++) {
		binary[2 + i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] << 4;
		binary[2 + i] |= atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}

	{
		uchar key[7] = {0, 0, 0, 0, 0, 0, 0};
		DES_key_schedule ks;
		DES_cblock b3cmp;

		key[0] = valid_i; key[1] = valid_j;
		setup_des_key(key, &ks);
		DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
		if (!memcmp(&binary[2 + 8 * 2], &b3cmp, 8)) {
			binary[0] = valid_i; binary[1] = valid_j;
			goto out;
		}

		for (i = 0; i < 0x100; i++)
		for (j = 0; j < 0x100; j++) {
			key[0] = i; key[1] = j;
			setup_des_key(key, &ks);
			DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
			if (!memcmp(&binary[2 + 8 * 2], &b3cmp, 8)) {
				binary[0] = i; binary[1] = j;
				goto out;
			}
		}
		fprintf(stderr, "Bug: MSCHAPv2 hash with invalid 3rd block, should have been rejected in valid()\n");
		binary[0] = binary[1] = 0x55;
	}

out:
	return binary;
}

/* Calculate the MSCHAPv2 response for the given challenge, using the
   specified authentication identity (username), password and client
   nonce.
*/
static void crypt_all(int count)
{
	if (!keys_prepared) {
		int i = 0;

		if (use_bitmap) {
#if MAX_KEYS_PER_CRYPT >= 200
//#warning Notice: Using memset
			memset(bitmap, 0, 0x10000 / 8);
#else
//#warning Notice: Not using memset
#ifdef MMX_COEF
			for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++)
#else
			for (i = 0; i < count; i++)
#endif
			{
				unsigned int value = crypt_key[i];
				bitmap[value >> 5] = 0;
			}
#endif
		}

		use_bitmap = cmps_per_crypt >= 2;
		cmps_per_crypt = 0;

#ifdef MMX_COEF
#if defined(MD4_SSE_PARA)
#if (BLOCK_LOOPS > 1)
#if defined(_OPENMP) && defined(MD4_SSE_PARA) && defined(SSE_OMP)
#pragma omp parallel for
#endif
		for (i = 0; i < BLOCK_LOOPS; i++)
			SSEmd4body(&saved_key[i * NBKEYS * 64], (unsigned int*)&nthash[i * NBKEYS * 16], 1);
#else
		SSEmd4body(saved_key, (unsigned int*)nthash, 1);
#endif
#else
		mdfourmmx(nthash, saved_key, total_len);
#endif
		if (use_bitmap)
		for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++) {
			unsigned int value;

			value = *(ARCH_WORD_32*)&nthash[GETOUTPOS(12, i)] >> 16;
			crypt_key[i] = value;
			bitmap[value >> 5] |= 1U << (value & 0x1f);
		}
		else
		for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++) {
			crypt_key[i] = *(ARCH_WORD_32*)&nthash[GETOUTPOS(12, i)] >> 16;
		}
#else
#if defined(_OPENMP) || (MAX_KEYS_PER_CRYPT > 1)
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (i = 0; i < count; i++)
#endif
		{
			MD4_CTX ctx;

			MD4_Init( &ctx );
			MD4_Update(&ctx, saved_key[i], saved_key_length[i]);
			MD4_Final((uchar*)&nthash[i * 16], &ctx);

			crypt_key[i] = ((unsigned short*)&nthash[i * 16])[7];
			if (use_bitmap) {
				unsigned int value = crypt_key[i];
				bitmap[value >> 5] |= 1U << (value & 0x1f);
			}
		}
#endif
		keys_prepared = 1;
	}
}

static int cmp_one(void *binary, int index)
{
	if (crypt_key[index] == *(unsigned short*)binary) {
		DES_key_schedule ks;
		DES_cblock computed_binary;
		unsigned int key[2];
#ifdef MMX_COEF
		int i;

		for (i = 0; i < 2; i++)
			key[i] = *(ARCH_WORD_32*)&nthash[GETOUTPOS(4 * i, index)];
#else
		memcpy(key, &nthash[index * 16], 8);
#endif
		setup_des_key((unsigned char*)key, &ks);
		DES_ecb_encrypt((DES_cblock*)challenge, &computed_binary, &ks, DES_ENCRYPT);
		return !memcmp(((char*)binary) + 2, computed_binary, 8);
	}

	return 0;
}

static int cmp_all(void *binary, int count)
{
	unsigned int value = *(unsigned short*)binary;
	int index;

	cmps_per_crypt++;

	if (use_bitmap && !(bitmap[value >> 5] & (1U << (value & 0x1f))))
		goto out;

#ifdef MMX_COEF
	/* Let's give the optimizer a hint! */
	for (index = 0; index < NBKEYS * BLOCK_LOOPS; index += 2) {
#else
	for (index = 0; index < count; index += 2) {
#endif
		unsigned int a = crypt_key[index];
		unsigned int b = crypt_key[index + 1];

#if 0
		if (((a | b) & value) != value)
			continue;
#endif
		if (a == value || b == value)
			goto thorough;
	}

	goto out;

thorough:
#ifdef MMX_COEF
	for (index = 0; index < NBKEYS * BLOCK_LOOPS; index++) {
#else
	for (; index < count; index++) {
#endif
		if (crypt_key[index] == value && cmp_one(binary, index))
			return 1;
	}

out:
	return 0;
}

static int cmp_exact(char *source, int index)
{
	DES_key_schedule ks;
	uchar binary[24];
	unsigned char key[21];
#ifdef MMX_COEF
	int i;

	for (i = 0; i < 4; i++)
		((ARCH_WORD_32*)key)[i] = *(ARCH_WORD_32*)&nthash[GETOUTPOS(4 * i, index)];
#else
	memcpy(key, &nthash[index * 16], 16);
#endif
	/* Hash is NULL padded to 21-bytes */
	memset(&key[16], 0, 5);

	/* Split into three 7-byte segments for use as DES keys
	   Use each key to DES encrypt challenge
	   Concatenate output to for 24-byte NTLM response */
	setup_des_key(key, &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)binary, &ks, DES_ENCRYPT);
	setup_des_key(&key[7], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[8], &ks, DES_ENCRYPT);
	setup_des_key(&key[14], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[16], &ks, DES_ENCRYPT);

	return !memcmp(binary, ((char*)get_binary(source)) + 2, FULL_BINARY_SIZE - 2);
}

static void get_challenge(const char *ciphertext, unsigned char *binary_salt)
{
	int i;
	const char *pos = ciphertext + 10;

	for (i = 0; i < SALT_SIZE; i++)
		binary_salt[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];
}

/* Either the cipherext already contains the MSCHAPv2 Challenge (4 Bytes) or
   we are going to calculate it via:
   sha1(|Peer/Client Challenge (8 Bytes)|Authenticator/Server Challenge (8 Bytes)|Username (<=256)|)
*/
static void *get_salt(char *ciphertext)
{
	static unsigned char *binary_salt;
	SHA_CTX ctx;
	unsigned char tmp[16];
	int i;
	char *pos = NULL;
	unsigned char digest[20];

	if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	/* This is just to silence scan-build. It will never happen. It is unclear
	   why only this format gave warnings, many others do similar things. */
	if (!ciphertext)
		return ciphertext;

	memset(binary_salt, 0, SALT_SIZE);
	memset(digest, 0, 20);

	if (valid_short(ciphertext)) {
		get_challenge(ciphertext, binary_salt);
		goto out;
	}

	SHA1_Init(&ctx);

	/* Peer Challenge */
	pos = ciphertext + 10 + 16*2 + 1 + 24*2 + 1; /* Skip $MSCHAPv2$, Authenticator Challenge and Response Hash */

	memset(tmp, 0, 16);
	for (i = 0; i < 16; i++)
		tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

	SHA1_Update(&ctx, tmp, 16);

	/* Authenticator Challenge */
	pos = ciphertext + 10; /* Skip $MSCHAPv2$ */

	memset(tmp, 0, 16);
	for (i = 0; i < 16; i++)
		tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

	SHA1_Update(&ctx, tmp, 16);

	/* Username - Only the user name (as presented by the peer and
	   excluding any prepended domain name) is used as input to SHAUpdate()
	*/
	pos = ciphertext + 10 + 16*2 + 1 + 24*2 + 1 + 16*2 + 1; /* Skip $MSCHAPv2$, Authenticator, Response and Peer */
	SHA1_Update(&ctx, pos, strlen(pos));

	SHA1_Final(digest, &ctx);
	memcpy(binary_salt, digest, SALT_SIZE);

out:
	return (void*)binary_salt;
}

static void set_salt(void *salt)
{
	challenge = salt;
}

static void clear_keys(void)
{
#if defined(MMX_COEF) && !defined(MD4_SSE_PARA)
	total_len = 0;
#endif
}

// ISO-8859-1 to UCS-2, directly into vector key buffer
static void mschapv2_set_key(char *_key, int index)
{
#ifdef MMX_COEF
	const uchar *key = (uchar*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
	unsigned int len, temp2;

	len = 0;
	while((temp2 = *key++)) {
		unsigned int temp;
		if ((temp = *key++) && len < PLAINTEXT_LENGTH - 1)
		{
			temp2 |= (temp << 16);
			*keybuf_word = temp2;
		}
		else
		{
			temp2 |= (0x80 << 16);
			*keybuf_word = temp2;
			len++;
			goto key_cleaning;
		}
		len += 2;
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int*)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
#if ARCH_LITTLE_ENDIAN
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = saved_key[index];
	while (*s)
		*d++ = *s++;
	*d = 0;
	saved_key_length[index] = (int)((char*)d - (char*)saved_key[index]);
#else
	UTF8 *s = (UTF8*)_key;
	UTF8 *d = (UTF8*)saved_key[index];
	while (*s) {
		*d++ = *s++;
		++d;
	}
	*d = 0;
	saved_key_length[index] = (int)((char*)d - (char*)saved_key[index]);
#endif
#endif
	keys_prepared = 0;
}

// Legacy codepage to UCS-2, directly into vector key buffer
static void set_key_CP(char *_key, int index)
{
#ifdef MMX_COEF
	const uchar *key = (uchar*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
	unsigned int len, temp2;

	len = 0;
	while((temp2 = *key++)) {
		unsigned int temp;
		temp2 = CP_to_Unicode[temp2];
		if ((temp = *key++) && len < PLAINTEXT_LENGTH - 1)
		{
			temp = CP_to_Unicode[temp];
			temp2 |= (temp << 16);
			*keybuf_word = temp2;
		} else {
			temp2 |= (0x80 << 16);
			*keybuf_word = temp2;
			len++;
			goto key_cleaning_enc;
		}
		len += 2;
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning_enc:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int*)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
	saved_key_length[index] = enc_to_utf16(saved_key[index],
	                                       PLAINTEXT_LENGTH + 1,
	                                       (uchar*)_key,
	                                       strlen(_key)) << 1;
	if (saved_key_length[index] < 0)
		saved_key_length[index] = strlen16(saved_key[index]);
#endif
	keys_prepared = 0;
}

// UTF-8 to UCS-2, directly into vector key buffer
static void set_key_utf8(char *_key, int index)
{
#ifdef MMX_COEF
	const UTF8 *source = (UTF8*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
	UTF32 chl, chh = 0x80;
	unsigned int len = 0;

	while (*source) {
		chl = *source;
		if (chl >= 0xC0) {
			unsigned int extraBytesToRead = opt_trailingBytesUTF8[chl & 0x3f];
			switch (extraBytesToRead) {
			case 2:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					return;
			case 1:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					return;
			case 0:
				break;
			default:
				return;
			}
			chl -= offsetsFromUTF8[extraBytesToRead];
		}
		source++;
		len++;
		if (*source && len < PLAINTEXT_LENGTH) {
			chh = *source;
			if (chh >= 0xC0) {
				unsigned int extraBytesToRead =
					opt_trailingBytesUTF8[chh & 0x3f];
				switch (extraBytesToRead) {
				case 2:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						return;
				case 1:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						return;
				case 0:
					break;
				default:
					return;
				}
				chh -= offsetsFromUTF8[extraBytesToRead];
			}
			source++;
			len++;
		} else {
			chh = 0x80;
			*keybuf_word = (chh << 16) | chl;
			keybuf_word += MMX_COEF;
			break;
		}
		*keybuf_word = (chh << 16) | chl;
		keybuf_word += MMX_COEF;
	}
	if (chh != 0x80 || len == 0) {
		*keybuf_word = 0x80;
		keybuf_word += MMX_COEF;
	}

	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int*)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
	saved_key_length[index] = utf8_to_utf16(saved_key[index],
	                                        PLAINTEXT_LENGTH + 1,
	                                        (uchar*)_key,
	                                        strlen(_key)) << 1;
	if (saved_key_length[index] < 0)
		saved_key_length[index] = strlen16(saved_key[index]);
#endif
	keys_prepared = 0;
}

// Get the key back from the key buffer, from UCS-2
static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
	static UTF16 key[PLAINTEXT_LENGTH + 1];
	unsigned int md4_size=0;
	unsigned int i=0;

	for(; md4_size < PLAINTEXT_LENGTH; i += MMX_COEF, md4_size++)
	{
		key[md4_size] = keybuf_word[i];
		key[md4_size+1] = keybuf_word[i] >> 16;
		if (key[md4_size] == 0x80 && key[md4_size+1] == 0) {
			key[md4_size] = 0;
			break;
		}
		++md4_size;
		if (key[md4_size] == 0x80 && ((keybuf_word[i+MMX_COEF]&0xFFFF) == 0 || md4_size == PLAINTEXT_LENGTH)) {
			key[md4_size] = 0;
			break;
		}
	}
	return (char*)utf16_to_enc(key);
#else
	return (char*)utf16_to_enc(saved_key[index]);
#endif
}

static int salt_hash(void *salt) { return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1); }

static int binary_hash_0(void *binary) { return *(HOT_TYPE*)binary & 0xF; }
static int binary_hash_1(void *binary) { return *(HOT_TYPE*)binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(HOT_TYPE*)binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(HOT_TYPE*)binary & 0xFFFF; }

static int get_hash_0(int index) { return crypt_key[index] & 0xF; }
static int get_hash_1(int index) { return crypt_key[index] & 0xFF; }
static int get_hash_2(int index) { return crypt_key[index] & 0xFFF; }
static int get_hash_3(int index) { return crypt_key[index] & 0xFFFF; }

struct fmt_main fmt_MSCHAPv2_new = {
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
#if !defined(MMX_COEF) || (defined(MD4_SSE_PARA) && defined(SSE_OMP))
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		prepare,
		valid,
		split,
		get_binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			NULL,
			NULL,
			NULL
		},
		salt_hash,
		set_salt,
		mschapv2_set_key,
		get_key,
		clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			NULL,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
