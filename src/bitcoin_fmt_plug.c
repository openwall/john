/* bitcoin-qt (bitcoin) wallet cracker patch for JtR. Hacked together during
 * April of 2013 by Dhiru Kholia <dhiru at openwall dot com>.
 *
 * Also works for Litecoin-Qt (litecoin) wallet files!
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall dot com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * This cracks password protected bitcoin (bitcoin-qt) "wallet" files.
 *
 * bitcoin => https://github.com/bitcoin/bitcoin
 *
 * Thanks to Solar for asking to add support for bitcoin wallet files.
 */

#include "arch.h"
#include <openssl/opensslv.h>
#if (AC_BUILT && HAVE_EVP_SHA512) || \
	(!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x0090708f)

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bitcoin;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bitcoin);
#else

#include <openssl/evp.h>
#include <string.h>
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "stdint.h"
#include "johnswap.h"
#include "sse-intrinsics.h"
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif
static int omp_t = 1;
#endif
#include "memdbg.h"

#define FORMAT_LABEL		"Bitcoin"
#define FORMAT_NAME		""

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME		"SHA512 AES " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME		"SHA512 AES 64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME		"SHA512 AES 32/" ARCH_BITS_STR " " SHA2_LIB
#endif
#endif

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	64
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_ALIGN			sizeof(int)
#define SALT_SIZE		sizeof(struct custom_salt)
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT	(SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT	(SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

#define SZ 			128

static struct fmt_tests bitcoin_tests[] = {
	/* bitcoin wallet hashes */
	{"$bitcoin$96$169ce74743c260678fbbba92e926198702fd84e46ba555190f6f3d82f6852e4adeaa340d2ac065288e8605f13d1d7c86$16$26049c64dda292d5$177864$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "openwall"},
	{"$bitcoin$96$bd97a08e00e38910550e76848949285b9702fe64460f70d464feb2b63f83e1194c745e58fa4a0f09ac35e5777c507839$16$26049c64dda292d5$258507$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "password"},
	{"$bitcoin$96$4eca412eeb04971428efec70c9e18fb9375be0aa105e7eec55e528d0ba33a07eb6302add36da86736054dee9140ec9b8$16$26049c64dda292d5$265155$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "strongpassword"},
	/* litecoin wallet hash */
	{"$bitcoin$96$54401984b32448917b6d18b7a11debe91d62aaa343ab62ed98e1d3063f30817832c744360331df94cbf1dcececf6d00e$16$bfbc8ee2c07bbb4b$194787$96$07a206d5422640cfa65a8482298ad8e8598b94d99e2c4ce09c9d015b734632778cb46541b8c10284b9e14e5468b654b9$66$03fe6587bf580ee38b719f0b8689c80d300840bbc378707dce51e6f1fe20f49c20", "isyourpasswordstronger"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	unsigned char cry_master[SZ];
	int cry_master_length;
	unsigned char cry_salt[SZ];
	int cry_salt_length;
	int cry_rounds;
	unsigned char ckey[SZ];
	int ckey_length;
	unsigned char public_key[SZ];
	int public_key_length;
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

// #define  BTC_DEBUG

#ifdef BTC_DEBUG
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}
#endif

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p = NULL;
	int res;
	if (strncmp(ciphertext, "$bitcoin$", 9))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += 9;

	if ((p = strtokm(ctcopy, "$")) == NULL) /* cry_master_length (of the hex string) */
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_master */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and cry_master */
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_salt_length (length of hex string) */
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_salt */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and cry_salt */
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_rounds */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* ckey_length (of hex) */
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* ckey */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and ckey */
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* public_key_length */
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* public_key */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and public_key */
		goto err;
	if (!ishex(p))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	int i;
	char *p;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += 9;
	p = strtokm(ctcopy, "$");
	cs.cry_master_length = atoi(p) / 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.cry_master_length; i++)
		cs.cry_master[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.cry_salt_length = atoi(p) / 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.cry_salt_length; i++)
		cs.cry_salt[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "$");
	cs.cry_rounds = atoi(p);

	p = strtokm(NULL, "$");
	cs.ckey_length = atoi(p) / 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.ckey_length; i++)
		cs.ckey[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.public_key_length = atoi(p) / 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.public_key_length; i++)
		cs.public_key[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		unsigned char output[SZ];
		int fOk;
		SHA512_CTX sha_ctx;
		EVP_CIPHER_CTX ctx;
		int nPLen, nFLen;
		int i;

#ifdef SIMD_COEF_64
		//JTR_ALIGN(MEM_ALIGN_SIMD) ARCH_WORD_64 key_iv[SIMD_COEF_64*SHA_BUF_SIZ];  // 2 * 16 bytes == 2048 bits, i.e. two SHA blocks
		// the above alignment was crashing on OMP build on some 32 bit linux (compiler bug?? not aligning).
		// so the alignment was done using raw buffer, and aligning at runtime to get 16 byte alignment.
		// that works, and should cause no noticeable overhead differences.
		char unaligned_buf[MAX_KEYS_PER_CRYPT*SHA_BUF_SIZ*sizeof(ARCH_WORD_64)+MEM_ALIGN_SIMD];
		ARCH_WORD_64 *key_iv = (ARCH_WORD_64*)mem_align(unaligned_buf, MEM_ALIGN_SIMD);
		JTR_ALIGN(8)  unsigned char hash1[SHA512_DIGEST_LENGTH];            // 512 bits
		int index2;

		for (index2 = 0; index2 < MAX_KEYS_PER_CRYPT; index2++) {
			// The first hash for this password
			SHA512_Init(&sha_ctx);
			SHA512_Update(&sha_ctx, saved_key[index+index2], strlen(saved_key[index+index2]));
			SHA512_Update(&sha_ctx, cur_salt->cry_salt, cur_salt->cry_salt_length);
			SHA512_Final(hash1, &sha_ctx);

			// Now copy and convert hash1 from flat into SIMD_COEF_64 buffers.
			for (i = 0; i < SHA512_DIGEST_LENGTH/sizeof(ARCH_WORD_64); ++i) {
#if COMMON_DIGEST_FOR_OPENSSL
				key_iv[SIMD_COEF_64*i + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = sha_ctx.hash[i];  // this is in BE format
#else
				key_iv[SIMD_COEF_64*i + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = sha_ctx.h[i];
#endif
			}

			// We need to set ONE time, the upper half of the data buffer.  We put the 0x80 byte (in BE format), at offset
			// 512-bits (SHA512_DIGEST_LENGTH) multiplied by the SIMD_COEF_64 (same as MAX_KEYS_PER_CRYPT), then zero
			// out the rest of the buffer, putting 512 (#bits) at the end.  Once this part of the buffer is set up, we never
			// touch it again, for the rest of the crypt.  We simply overwrite the first half of this buffer, over and over
			// again, with BE results of the prior hash.
			key_iv[ SHA512_DIGEST_LENGTH/sizeof(ARCH_WORD_64) * SIMD_COEF_64 + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64 ] = 0x8000000000000000ULL;
			for (i = (SHA512_DIGEST_LENGTH/sizeof(ARCH_WORD_64)+1); i < 15; i++)
				key_iv[i*SIMD_COEF_64 + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = 0;
			key_iv[15*SIMD_COEF_64 + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = (SHA512_DIGEST_LENGTH << 3);
		}

		for (i = 1; i < cur_salt->cry_rounds; i++)  // start at 1; the first iteration is already done
			SSESHA512body(key_iv, key_iv, NULL, SSEi_MIXED_IN|SSEi_OUTPUT_AS_INP_FMT);

		for (index2 = 0; index2 < MAX_KEYS_PER_CRYPT; index2++) {
			unsigned char key[32];
			unsigned char iv[16];

			// Copy and convert from SIMD_COEF_64 buffers back into flat buffers, in little-endian
			for (i = 0; i < sizeof(key)/sizeof(ARCH_WORD_64); i++)  // the derived key
				((ARCH_WORD_64 *)key)[i] = JOHNSWAP64(key_iv[SIMD_COEF_64*i + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64]);
			for (i = 0; i < sizeof(iv)/sizeof(ARCH_WORD_64); i++)   // the derived iv
				((ARCH_WORD_64 *)iv)[i]  = JOHNSWAP64(key_iv[SIMD_COEF_64*(sizeof(key)/sizeof(ARCH_WORD_64) + i) + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64]);

			/* NOTE: write our code instead of using following high-level OpenSSL functions */
			EVP_CIPHER_CTX_init(&ctx);
			fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);
			if (fOk)
				fOk = EVP_DecryptUpdate(&ctx, output, &nPLen, cur_salt->cry_master, cur_salt->cry_master_length);
			if (fOk)
				fOk = EVP_DecryptFinal_ex(&ctx, output + nPLen, &nFLen);
			EVP_CIPHER_CTX_cleanup(&ctx);
			// a decrypted mkey is exactly 32 bytes in len; ossl has already checked the padding (16 0x0f's) for us
			if (fOk && nPLen + nFLen == 32) {
				cracked[index + index2] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}

		}
#else
		unsigned char key_iv[SHA512_DIGEST_LENGTH];  // buffer for both the derived key and iv
		SHA512_Init(&sha_ctx);
		SHA512_Update(&sha_ctx, saved_key[index], strlen(saved_key[index]));
		SHA512_Update(&sha_ctx, cur_salt->cry_salt, cur_salt->cry_salt_length);
		SHA512_Final(key_iv, &sha_ctx);
		for (i = 1; i < cur_salt->cry_rounds; i++) {  // start at 1; the first iteration is already done
			SHA512_Init(&sha_ctx);
			SHA512_Update(&sha_ctx, key_iv, SHA512_DIGEST_LENGTH);
			SHA512_Final(key_iv, &sha_ctx);
		}
		/* NOTE: write our code instead of using following high-level OpenSSL functions */
		EVP_CIPHER_CTX_init(&ctx);
		fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key_iv, key_iv+32);
		if (fOk)
			fOk = EVP_DecryptUpdate(&ctx, output, &nPLen, cur_salt->cry_master, cur_salt->cry_master_length);
		if (fOk)
			fOk = EVP_DecryptFinal_ex(&ctx, output + nPLen, &nFLen);
		EVP_CIPHER_CTX_cleanup(&ctx);
		// a decrypted mkey is exactly 32 bytes in len; ossl has already checked the padding (16 0x0f's) for us
		if (fOk && nPLen + nFLen == 32) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

static void bitcoin_set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

#if FMT_MAIN_VERSION
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->cry_rounds;
}
#endif

struct fmt_main fmt_bitcoin = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		bitcoin_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		bitcoin_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* OpenSSL requirement */
