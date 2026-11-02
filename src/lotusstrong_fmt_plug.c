/*
 * JtR format to crack "strong crypto" Lotus Notes / Domino ID files
 * (RC2-128 and AES-128/256 "PBES2" user-ID files).
 *
 * Reverse engineered from HCL Nomad's libnoteslib.so (CipherIDFile,
 * ManagePasswordObj, FormatIDFH, SECConvertPasswordToKeyExt, SecBuildPBES2).
 *
 * Password -> key derivation (identical digest chain as lotus85):
 *
 *   MDC16 = custom 128-bit hash of the password   (the "terrible hash")
 *   SHA1  = SHA1("Lotus Notes Password Pad Uniquifier" || password)
 *
 *   keyType 2 (RC2-128):
 *     digest = MD5(MDC16 || SHA1[:16] || salt16)
 *     key16 = rolling-MAC16(digest), initially zero (SecInitLegacyRC2Key)
 *     blob  = RC2-CBC ciphertext, 128 effective key bits, zero IV
 *
 *   keyType 4..7 (AES-128/256, PBES2):
 *     key   = PBKDF2-HMAC-SHA1(SHA1digest, salt16, iterations, keyLen)
 *     blob  = AES-CBC ciphertext, IV from the file's PBES2 record
 *
 * Verification: the supported ID files contain a 50-byte secret-info record
 * (ODS type 0xe3), followed by CBC padding: six 0x06 bytes for RC2 and fourteen
 * 0x0e bytes for AES.  GetPlaintextSI checks the unpadded record length too.
 * Its first WORD varies (e.g. 00 01 in the RC2 sample), so it is not a
 * password check.  Strong files do not use lotus85's trailing five-byte MAC.
 *
 * Hash format (see run/lotus2john.py):
 *   $lotus-strong$*keytype*saltHEX*iters*keylen*ivHEX*blobHEX
 *
 * This software is Copyright (c) 2026 Dhiru Kholia <dhiru@openwall.com>, and
 * it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lotus_strong;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lotus_strong);
#else

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/md5.h>
#include <openssl/rc2.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "sha.h"

#ifdef _OPENMP
#include <omp.h>
#endif

#include "formats.h"
#include "common.h"
#include "jumbo.h"
#include "memory.h"

#define FORMAT_LABEL          "lotus-strong"
#define FORMAT_NAME           "Lotus Notes/Domino ID strong (RC2-128 / AES)"
#define ALGORITHM_NAME        "MDC/SHA1/MD5/PBKDF2-SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT     ""
#define BENCHMARK_LENGTH      7
#define PLAINTEXT_LENGTH      32
#define BINARY_SIZE           0
#define BINARY_ALIGN          1
#define SALT_SIZE             sizeof(struct custom_salt)
#define SALT_ALIGN            4
#define MIN_KEYS_PER_CRYPT    1
#define MAX_KEYS_PER_CRYPT    4
#define FORMAT_TAG            "$lotus-strong$*"
#define TAG_LENGTH            (sizeof(FORMAT_TAG) - 1)

#ifndef OMP_SCALE
#define OMP_SCALE             16
#endif

#define LOTUS_MAX_BLOB_SIZE   0x64
#define LOTUS_MAX_SALT_SIZE   16
#define LOTUS_CHECK_DATA_SIZE 50

static const char LOTUS_UNIQUE_STRING[] = "Lotus Notes Password Pad Uniquifier";

static const uint8_t ebits_to_num[256]=
{
	0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
	0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
	0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
	0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
	0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
	0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
	0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
	0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
	0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
	0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
	0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
	0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
	0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
	0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
	0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
	0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
	0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
	0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
	0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
	0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
	0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
	0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
	0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
	0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
	0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
	0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
	0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
	0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
	0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
	0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
	0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
	0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
};

static struct custom_salt {
	uint8_t blob[LOTUS_MAX_BLOB_SIZE];
	uint32_t blob_len;
	uint8_t salt[LOTUS_MAX_SALT_SIZE];
	uint32_t iters;
	uint32_t keylen;
	uint8_t iv[16];
	uint32_t key_type;    /* 2 = RC2-128, 4..7 = AES */
} *cur_salt;

static uint8_t *cracked;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];

/* Custom hash transformation function (identical to the lotus85 code) */
static void custom_password_hash_trans(uint8_t *data, uint8_t *out, uint8_t *state)
{
	uint8_t buffer[48];
	size_t i, j;
	uint8_t c;

	memset(buffer, 0, sizeof(buffer));

	memcpy(buffer, state, 16);
	memcpy(buffer + 16, data, 16);

	for (i = 0; i < 16; i += 4) {
		buffer[32+i]   = data[i]   ^ state[i];
		buffer[32+i+1] = data[i+1] ^ state[i+1];
		buffer[32+i+2] = data[i+2] ^ state[i+2];
		buffer[32+i+3] = data[i+3] ^ state[i+3];
	}

	for (j = c = 0; j < 18; j++) {
		for (i = 0; i < sizeof(buffer); i += 6) {
			buffer[i]   ^= ebits_to_num[(c-i+48) & 0xFF];
			buffer[i+1] ^= ebits_to_num[(buffer[i]-i+47) & 0xFF];
			buffer[i+2] ^= ebits_to_num[(buffer[i+1]-i+46) & 0xFF];
			buffer[i+3] ^= ebits_to_num[(buffer[i+2]-i+45) & 0xFF];
			buffer[i+4] ^= ebits_to_num[(buffer[i+3]-i+44) & 0xFF];
			buffer[i+5] ^= ebits_to_num[(buffer[i+4]-i+43) & 0xFF];
			c = buffer[i+5];
		}
	}

	memcpy(state, buffer, 16);

	c = out[15];

	for (i = 0; i < 16; i += 4) {
		out[i]   ^= ebits_to_num[data[i] ^ c];
		out[i+1] ^= ebits_to_num[data[i+1] ^ out[i]];
		out[i+2] ^= ebits_to_num[data[i+2] ^ out[i+1]];
		out[i+3] ^= ebits_to_num[data[i+3] ^ out[i+2]];
		c = out[i+3];
	}
}

/* The 16-byte custom MDC hash of the password */
static void custom_password_hash(const char *password, uint8_t *out)
{
	uint8_t block1[16], state[16], block2[16];
	size_t len, rlen, block_pos = 0;

	len = strlen(password);
	memset(state, 0, sizeof(state));
	memset(block2, 0, sizeof(block2));

	while ((block_pos + 15) < len) {
		memcpy(block1, password + block_pos, sizeof(block1));
		custom_password_hash_trans(block1, state, block2);
		block_pos += 16;
	}

	if (block_pos != len) {
		rlen = len - block_pos;
		memcpy(block1, password + block_pos, rlen);
		memset(block1 + rlen, 16 - rlen, 16 - rlen);
		custom_password_hash_trans(block1, state, block2);
	}
	else {
		memset(block1, sizeof(block1), sizeof(block1));
		custom_password_hash_trans(block1, state, block2);
	}

	custom_password_hash_trans(state, state, block2);

	memcpy(out, block2, sizeof(block2));
}

/* SHA1(uniquifier || password) */
static void password_hash(const char *password, uint8_t *hash)
{
	SHA_CTX s_ctx;
	uint8_t digest[SHA_DIGEST_LENGTH];

	SHA1_Init(&s_ctx);
	SHA1_Update(&s_ctx, LOTUS_UNIQUE_STRING, strlen(LOTUS_UNIQUE_STRING));
	SHA1_Update(&s_ctx, password, strlen(password));
	SHA1_Final(digest, &s_ctx);

	memcpy(hash, digest, sizeof(digest));
}

/* SecInitLegacyRC2Key calls SECCalcMAC with a 16-byte output and input. */
static void compute_key_mac(const uint8_t *digest, uint8_t *key)
{
	size_t i;
	uint8_t c;

	memset(key, 0, 16);
	for (i = 0; i < 16; i++) {
		c = ebits_to_num[key[0] ^ key[1]];
		memmove(key, key + 1, 15);
		key[15] = digest[i] ^ c;
	}
}

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void lotus_strong_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ct_copy, *keepptr, *p;
	int key_type, iters, keylen;
	size_t len;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;

	ct_copy = xstrdup(ciphertext);
	keepptr = ct_copy;
	ct_copy += TAG_LENGTH;

	if ((p = strtokm(ct_copy, "*")) == NULL) goto err;  // key type
	if (!isdec(p))
		goto err;
	key_type = atoi(p);
	if (key_type < 2 || key_type > 7 || key_type == 3)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) goto err;     // salt hex
	if (strlen(p) != 2 * LOTUS_MAX_SALT_SIZE || !ishex(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) goto err;     // iterations
	if (!isdec(p))
		goto err;
	iters = atoi(p);
	if (key_type == 2) {
		if (iters != 0)
			goto err;
	} else if (iters < 1) {
		goto err;
	}
	if ((p = strtokm(NULL, "*")) == NULL) goto err;     // key length
	if (!isdec(p))
		goto err;
	keylen = atoi(p);
	if (keylen != 16 && keylen != 24 && keylen != 32)
		goto err;
	if (key_type == 2 && keylen != 16)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL) goto err;     // IV hex
	len = strlen(p);
	/* The extractor emits an 8-byte zero IV for RC2.  Accept the old
	 * 16-byte representation too; RC2 always uses a zero IV below. */
	if ((len != 32 && (key_type != 2 || len != 16)) || !ishex(p))
		goto err;
	if ((p = strtokm(NULL, "")) == NULL) goto err;    // blob hex, no extra fields
	len = strlen(p);
	/* CipherIDFile pads the 50-byte ODS secret-info record to a full block. */
	if (len != (key_type == 2 ? 112 : 128) || !ishex(p))
		goto err;

	MEM_FREE(keepptr);
	return 1;
err:
	MEM_FREE(keepptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ct_copy = xstrdup(ciphertext);
	char *keepptr = ct_copy;
	char *p;

	memset(&cs, 0, sizeof(cs));
	ct_copy += TAG_LENGTH;

	p = strtokm(ct_copy, "*");
	cs.key_type = atoi(p);
	p = strtokm(NULL, "*");
	for (int i = 0; i < LOTUS_MAX_SALT_SIZE; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i*2])]*16 + atoi16[ARCH_INDEX(p[i*2+1])];
	p = strtokm(NULL, "*");
	cs.iters = atoi(p);
	p = strtokm(NULL, "*");
	cs.keylen = atoi(p);
	p = strtokm(NULL, "*");
	for (int i = 0; i < strlen(p) / 2; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i*2])]*16 + atoi16[ARCH_INDEX(p[i*2+1])];
	p = strtokm(NULL, "");
	cs.blob_len = strlen(p) / 2;
	for (unsigned int i = 0; i < cs.blob_len; i++)
		cs.blob[i] = atoi16[ARCH_INDEX(p[i*2])]*16 + atoi16[ARCH_INDEX(p[i*2+1])];

	MEM_FREE(keepptr);
	return (void *)&cs;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		uint8_t mdc[16], sha1[SHA_DIGEST_LENGTH];
		uint8_t plain[LOTUS_MAX_BLOB_SIZE];
		unsigned int i, padding;

		password_hash(saved_key[index], sha1);

		if (cur_salt->key_type == 2) {
			/* The key object applies a rolling MAC to the MD5 digest. */
			uint8_t digest[16], key[16];
			MD5_CTX ctx;

			custom_password_hash(saved_key[index], mdc);
			MD5_Init(&ctx);
			MD5_Update(&ctx, mdc, 16);
			MD5_Update(&ctx, sha1, 16);
			MD5_Update(&ctx, cur_salt->salt, 16);
			MD5_Final(digest, &ctx);
			compute_key_mac(digest, key);
			{
				RC2_KEY rc_key;
				uint8_t iv[8] = { 0 };

				RC2_set_key(&rc_key, 16, key, 128);
				RC2_cbc_encrypt(cur_salt->blob, plain, cur_salt->blob_len,
				                &rc_key, iv, RC2_DECRYPT);
			}
		} else {
			/* AES: key = PBKDF2-HMAC-SHA1(SHA1digest, salt, iters, keyLen) */
			uint8_t key[32];
			uint8_t iv[16];
			AES_KEY aes_key;

			cracked[index] = 0;
			if (!PKCS5_PBKDF2_HMAC((const char *)sha1, SHA_DIGEST_LENGTH,
			                  cur_salt->salt, LOTUS_MAX_SALT_SIZE,
			                  cur_salt->iters, EVP_sha1(),
			                  cur_salt->keylen, key))
				continue;
			if (AES_set_decrypt_key(key, cur_salt->keylen * 8, &aes_key))
				continue;
			/* CBC updates its IV: keep the salt immutable across keys,
			 * threads and repeated crypt_all() calls. */
			memcpy(iv, cur_salt->iv, sizeof(iv));
			AES_cbc_encrypt(cur_salt->blob, plain, cur_salt->blob_len,
			                &aes_key, iv, AES_DECRYPT);
		}

		/* CBC padding must leave exactly one ODS secret-info record.
		 * A padding-only check still permits false positives (FMT_NOT_EXACT). */
		padding = cur_salt->blob_len - LOTUS_CHECK_DATA_SIZE;
		cracked[index] = 1;
		for (i = LOTUS_CHECK_DATA_SIZE; i < cur_salt->blob_len; i++)
			if (plain[i] != padding) {
				cracked[index] = 0;
				break;
			}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	for (int index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

static struct fmt_tests tests[] = {
	/* Real ID-file hashes: AES-128, RC2-128, and AES-256. */
	{"$lotus-strong$*4*a1866a3f4af733823b884b3e0e4f204b*5000*16*8060c26f3524de79a3afa084f6b0e9e1*"
	 "da3754cdc4e73c2f8d2bf339f9fb05bb1898dd5e811586af0382a030e3848c245c0b11136fe85bbdf7f25aa6fd044f184c824d6df062d5e353124484fbac40f2", "aes@123"},
	{"$lotus-strong$*2*518d7f57e1bfd101b0280c36c83ef208*0*16*0000000000000000*"
	 "fc69fcc2b46d893c43607072d50d736bbf2a163922e046c5a0e459bf36f3eef4778965ead2ebba39ee56140d36b014516ffd09244c63bfb6", "openwall@123"},
	{"$lotus-strong$*5*14335f7e4bea0fd385e28e379fde99c5*5000*32*25b16d733a4fca9c920b42c2e3cee81a*"
	 "a36d6df85cd037804bceca8a29a09217f35a64489e3cdeb419ccb9151e48f91dbc9884761550b5cbfbd72984d7ca9bde3f8cf41eef2893dee1610d844dde2adb", "aes@256"},
	/* Synthetic padded records cover empty, 16-, 17-, and 32-byte
	 * passwords, 8-bit input, and the 16-byte RC2 IV representation. */
	{"$lotus-strong$*2*0102030405060708090a0b0c0d0e0f10*0*16*00000000000000000000000000000000*"
	 "c1dcf91edd611c79de1b6b6ff1573ce109f0eac5066542a961c9f8dbabd2a2164b086989a52f88595e0fd30bedc5f7db0937e4182f63b7fb", ""},
	{"$lotus-strong$*2*02030405060708090a0b0c0d0e0f1011*0*16*00000000000000000000000000000000*"
	 "29d2c430804a7d9d5b73fe256a349b44f368aa4caad3f17e4679b6f4e1bad3b646015e3f4238ee4bf5de56c73c8bec103b9ef2085a3b3b26", "0123456789abcdef0123456789ABCDEF"},
	{"$lotus-strong$*4*030405060708090a0b0c0d0e0f101112*14*24*101112131415161718191a1b1c1d1e1f*"
	 "737c527b9164a466ad7517581429ff42a2aa5f5e6985229956e9961423821874b4376644d11dc99031ca3b49768fad28d3a851c2516c98260c96f39a2caf6177", "1234567890abcdef"},
	{"$lotus-strong$*6*0405060708090a0b0c0d0e0f10111213*15*16*101112131415161718191a1b1c1d1e1f*"
	 "996dbfee3f5b2e5e3983b1f25c744b0190c74cf199d3a3fb484133ff4ea90fd42663aa352560941178a1b32ef7113ecfbcf4970815eb8cc3ec8369ca98d453b0", "0123456789abcdefg"},
	{"$lotus-strong$*7*05060708090a0b0c0d0e0f1011121314*16*32*101112131415161718191a1b1c1d1e1f*"
	 "685b8a795fc7c55cd2a0764b8cf1276a0aef78bf9ad09a9a26f8964c64b3b3cbb929e444e7d59b95a2c8678487458f23975b202b398b7056a8f44d7ac42fa283", "lotus-\xfc"},
	{ NULL }
};

struct fmt_main fmt_lotus_strong = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		lotus_strong_set_key,
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

#endif /* plugin */
#endif /* HAVE_LIBCRYPTO */
