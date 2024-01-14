/*
 * Cracker for bitcoin-qt (bitcoin) wallet hashes. Hacked together during April
 * of 2013 by Dhiru Kholia <dhiru at openwall dot com>.
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
 *
 * Works fine with bitcoin-core-0.14.0 from March, 2017.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_bitcoin;
#elif FMT_REGISTERS_H
john_register_one(&fmt_bitcoin);
#else

#include <stdint.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "aes.h"
#include "johnswap.h"
#include "simd-intrinsics.h"
#include "jumbo.h"

#define FORMAT_LABEL            "Bitcoin"
#define FORMAT_NAME             "Bitcoin Core"
#define FORMAT_TAG              "$bitcoin$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "SHA512 AES " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME          "SHA512 AES 64/" ARCH_BITS_STR
#else
#define ALGORITHM_NAME          "SHA512 AES 32/" ARCH_BITS_STR
#endif
#endif

#if !defined (SHA512_DIGEST_LENGTH)
#define SHA512_DIGEST_LENGTH    64
#endif

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x507
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_ALIGN              sizeof(int)
#define SALT_SIZE               sizeof(struct custom_salt)
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT      (SIMD_COEF_64*SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               1 // Tuned w/ MKPC for core i7
#endif

#define SZ                      128

static struct fmt_tests bitcoin_tests[] = {
	/* retroactively added hashcat's test vector for benchmark compatibility */
	{"$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$96$480008005625057442352316337722323437108374245623701184230273883222762730232857701607167815448714$66$014754433300175043011633205413774877455616682000536368706315333388", "hashcat"},
	/* bitcoin wallet hashes */
	{"$bitcoin$96$169ce74743c260678fbbba92e926198702fd84e46ba555190f6f3d82f6852e4adeaa340d2ac065288e8605f13d1d7c86$16$26049c64dda292d5$177864$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "openwall"},
	{"$bitcoin$96$bd97a08e00e38910550e76848949285b9702fe64460f70d464feb2b63f83e1194c745e58fa4a0f09ac35e5777c507839$16$26049c64dda292d5$258507$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "password"},
	{"$bitcoin$96$4eca412eeb04971428efec70c9e18fb9375be0aa105e7eec55e528d0ba33a07eb6302add36da86736054dee9140ec9b8$16$26049c64dda292d5$265155$96$62aee49c1967b5635b663fc3b047d8bc562f7000921453ab15b98e5a5f2d2adc74393e789fe15c5a3fbc4625536be98a$66$020027f255fbfa6d4c010a1a5984e487443c68e1b32869ccfde92e92005814fd27", "strongpassword"},
	/* litecoin wallet hash */
	{"$bitcoin$96$54401984b32448917b6d18b7a11debe91d62aaa343ab62ed98e1d3063f30817832c744360331df94cbf1dcececf6d00e$16$bfbc8ee2c07bbb4b$194787$96$07a206d5422640cfa65a8482298ad8e8598b94d99e2c4ce09c9d015b734632778cb46541b8c10284b9e14e5468b654b9$66$03fe6587bf580ee38b719f0b8689c80d300840bbc378707dce51e6f1fe20f49c20", "isyourpasswordstronger"},
	/* bitcoin-core-0.14.0 wallet */
	{"$bitcoin$96$8e7be42551c822c7e55a384e15b4fbfec69ceaed000925870dfb262d3381ed4405507f6c94defbae174a218eed0b5ce8$16$b469e6dbd76926cf$244139$96$ec03604094ada8a5d76bbdb455d260ac8b202ec475d5362d334314c4e7012a2f4b8f9cf8761c9862cd20892e138cd29e$66$03fdd0341a72d1a119ea1de51e477f0687a2bf601c07c032cc87ef82e0f8f49b19", "password@12345"},
	/* bitcoin-core-0.14.0 wallet */
	{"$bitcoin$96$2559c50151aeec013a9820c571fbee02e5892a3ead07607ee8de9d0ff55798cff6fe60dbd71d7873cb794a03e0d63b70$16$672204f8ab168ff6$136157$96$a437e8bd884c928603ee00cf85eaaf9245a071efa763db03ab485cb757f155976edc7294a6a731734f383850fcac4316$66$03ff84bb48f454662b91a6e588af8752da0674efa5dae82e7340152afcc38f4ba4", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	/* bitcoin-core-0.15.1 wallet, 2017-12-26 */
	{"$bitcoin$96$a05caebc15448da36badbfca2f17624fdf0aa606627213288ca282919b4347580cb161e9d15cb56f8df550c382d8da0a$16$2da7b13a38ef4fb1$148503$96$9d6d027ce45c3fb7a6d4f68c56577fb3b78c9b2d0686e76480cd17df82c88ee3b8616374895fb6edd2257dece6c1a6a6$66$03ffc099d1b6dc18b063fe4c4abc51ef0647d03296104288dc13a5a05d5d018fe1", "openwall123"},
	/* bitcoin-0.7.0-win32-setup.exe from year 2012 */
	{"$bitcoin$96$23582816ecc192d621e22069f5849583684301882a0128aeebd34c208e200db5dfc8feba73d9284156887223ea288b02$16$3052e5cd17a35872$83181$96$c10fd1099feefaff326bc5437bd9be9afc4eee67d8965abe6b191a750c787287a96dc5afcad3a887ce0848cdcfe15516$66$03ff11e4003e96d7b8a028e12aed4f0a041848f58e4c41eebe6cb862f758da6cb7", "openwall123"},
	/* bitcoin-0.5.2-win32-setup.exe from January 2012 */
	{"$bitcoin$96$a8d2a30b9a5419934cbb7cb0727ddc16c4bebdbf30d7e099ca35f2b1b7ba04cc42eb5b865bff8f65fc6ba9e15428d84f$16$872581181d72f577$128205$96$0a8d43558ed2b55f4a53491df66e6a71003db4588d11dc0a88b976122c2849a74c2bfaace36424cf029795db6fd2c78f$130$04ff53a6f68eab1c52e5b561b4616edb5bed4d7510cdb4931c8da68732a86d86f3a3f7de266f17c8d03e02ebe8e2c86e2f5de0007217fd4aaf5742ca7373113060", "openwall"},
	/* PRiVCY-qt.exe <- privcy-1.1.1.0.tar.gz */
	{"$bitcoin$96$d98326490616ef9f59767c5bf148061565fe1b21078445725ef31629e8ee430bf4d04896d5064b6651ab4c19021e2d7c$16$51ee8c9ab318da9e$46008$96$819f6c8e618869c7933b85f6c59d15ca6786876edc435ba3f400e272c2999b43e0e3cda27acd928d1adbccd01b613e66$66$03feefa49b8cbbdbb327b7c477586e4a3275132cf6778f05bc11c517dc2e9107cb", "openwall"},
	// Truncated PRiVCY hash
	{"$bitcoin$64$65fe1b21078445725ef31629e8ee430bf4d04896d5064b6651ab4c19021e2d7c$16$51ee8c9ab318da9e$46008$96$819f6c8e618869c7933b85f6c59d15ca6786876edc435ba3f400e272c2999b43e0e3cda27acd928d1adbccd01b613e66$66$03feefa49b8cbbdbb327b7c477586e4a3275132cf6778f05bc11c517dc2e9107cb", "openwall"},
	/* Nexus legacy wallet */
	{"$bitcoin$64$6b0fbcd048e791edbab30408e14ee24cc51493b810afb61a1e59bc633993a093$36$74fc96a47606814567f02c7df532f6079cbd$169021$2$00$2$00", "openwall"},
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
	int final_block_fill;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_align(sizeof(*cracked), self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}
// #define  BTC_DEBUG

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p = NULL;
	int res;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;

	if ((p = strtokm(ctcopy, "$")) == NULL) /* cry_master_length (of the hex string) */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_master */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and cry_master */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_salt_length (length of hex string) */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_salt */
		goto err;
	if (strlen(p) != res || strlen(p) > SZ * 2) /* validates atoi() and cry_salt */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* cry_rounds */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* ckey_length (of hex) */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* ckey */
		goto err;
	if (strlen(p) != res) /* validates atoi() and ckey */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* public_key_length */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* public_key */
		goto err;
	if (strlen(p) != res) /* validates atoi() and public_key */
		goto err;
	if (!ishexlc(p))
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
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "$");
	cs.cry_master_length = atoi(p) / 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.cry_master_length; i++)
		cs.cry_master[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	cs.cry_salt_length = atoi(p);
	cs.final_block_fill = 0;
	if (cs.cry_salt_length == 36) { /* Nexus legacy wallet */
		cs.cry_salt_length = 16;
		cs.final_block_fill = 8; /* for mkey size 72 */
	}
	cs.cry_salt_length /= 2;
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.cry_salt_length; i++)
		cs.cry_salt[i] = atoi16[ARCH_INDEX(p[i * 2])]
			* 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "$");
	cs.cry_rounds = atoi(p);

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
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		SHA512_CTX sha_ctx;
		int i;

#ifdef SIMD_COEF_64
/* We use SSEi_HALF_IN, so can halve SHA_BUF_SIZ */
#undef SHA_BUF_SIZ
#define SHA_BUF_SIZ 8
		char unaligned_buf[MIN_KEYS_PER_CRYPT*SHA_BUF_SIZ*sizeof(uint64_t)+MEM_ALIGN_SIMD];
		uint64_t *key_iv = (uint64_t*)mem_align(unaligned_buf, MEM_ALIGN_SIMD);
		JTR_ALIGN(8)  unsigned char hash1[SHA512_DIGEST_LENGTH];            // 512 bits
		int index2;

		for (index2 = 0; index2 < MIN_KEYS_PER_CRYPT; index2++) {
			// The first hash for this password
			SHA512_Init(&sha_ctx);
			SHA512_Update(&sha_ctx, saved_key[index+index2], strlen(saved_key[index+index2]));
			SHA512_Update(&sha_ctx, cur_salt->cry_salt, cur_salt->cry_salt_length);
			SHA512_Final(hash1, &sha_ctx);

			// Now copy and convert hash1 from flat into SIMD_COEF_64 buffers.
			for (i = 0; i < SHA512_DIGEST_LENGTH/sizeof(uint64_t); ++i) {
				key_iv[SIMD_COEF_64*i + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64] = sha_ctx.h[i];
			}
		}

		// the first iteration is already done above
		uint64_t rounds = cur_salt->cry_rounds - 1;
		SIMDSHA512body(key_iv, key_iv, &rounds, SSEi_HALF_IN|SSEi_LOOP);

		for (index2 = 0; index2 < MIN_KEYS_PER_CRYPT; index2++) {
			AES_KEY aes_key;
			union {
				unsigned char uc[32];
				uint64_t u64[4];
			} key;
			unsigned char iv[16];
			unsigned char output[16];

			memcpy(iv, cur_salt->cry_master + cur_salt->cry_master_length - 32, 16);

			// Copy and convert from SIMD_COEF_64 buffers back into flat buffers, in little-endian
#if ARCH_LITTLE_ENDIAN==1
			for (i = 0; i < 4; i++)  // the derived key
				key.u64[i] = JOHNSWAP64(key_iv[SIMD_COEF_64*i + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64]);
#else
			for (i = 0; i < 4; i++)  // the derived key
				key.u64[i] = key_iv[SIMD_COEF_64*i + (index2&(SIMD_COEF_64-1)) + index2/SIMD_COEF_64*SHA_BUF_SIZ*SIMD_COEF_64];
#endif

			AES_set_decrypt_key(key.uc, 256, &aes_key);
			AES_cbc_encrypt(cur_salt->cry_master + cur_salt->cry_master_length - 16, output, 16, &aes_key, iv, AES_DECRYPT);

			if (check_pkcs_pad(output, 16, 16) == cur_salt->final_block_fill) {
				cracked[index + index2] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			}
		}
#else
		AES_KEY aes_key;
		unsigned char key_iv[SHA512_DIGEST_LENGTH];  // buffer for both the derived key and initial IV
		unsigned char iv[16];  // updated IV for the final block
		unsigned char output[16];

		memcpy(iv, cur_salt->cry_master + cur_salt->cry_master_length - 32, 16);

		SHA512_Init(&sha_ctx);
		SHA512_Update(&sha_ctx, saved_key[index], strlen(saved_key[index]));
		SHA512_Update(&sha_ctx, cur_salt->cry_salt, cur_salt->cry_salt_length);
		SHA512_Final(key_iv, &sha_ctx);
		for (i = 1; i < cur_salt->cry_rounds; i++) {  // start at 1; the first iteration is already done
			SHA512_Init(&sha_ctx);
			SHA512_Update(&sha_ctx, key_iv, SHA512_DIGEST_LENGTH);
			SHA512_Final(key_iv, &sha_ctx);
		}

		AES_set_decrypt_key(key_iv, 256, &aes_key);
		AES_cbc_encrypt(cur_salt->cry_master + cur_salt->cry_master_length - 16, output, 16, &aes_key, iv, AES_DECRYPT);

		if (check_pkcs_pad(output, 16, 16) == cur_salt->final_block_fill) {
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)my_salt->cry_rounds;
}

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
		{
			"iteration count",
		},
		{ FORMAT_TAG },
		bitcoin_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
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
