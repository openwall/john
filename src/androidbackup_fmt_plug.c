/*
 * Format for cracking encrypted Android Backups.
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credit goes to "Android backup extractor" project by Nikolay Elenkov for
 * making this work possible.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ab;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ab);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               4  // tuned on i7-7820HQ

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "aes.h"
// #define PBKDF2_HMAC_SHA1_ALSO_INCLUDE_CTX 1
#include "pbkdf2_hmac_sha1.h"
#include "memdbg.h"

#define FORMAT_LABEL            "AndroidBackup"
#define FORMAT_NAME             ""
#define FORMAT_TAG              "$ab$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#ifdef SIMD_COEF_64
#define ALGORITHM_NAME          "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " AES"
#else
#define ALGORITHM_NAME          "PBKDF2-SHA1 32/" ARCH_BITS_STR " AES"
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint64_t)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA1 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

#define SALTLEN                 64
#define IVLEN                   16
#define TAGLEN                  16
#define MAX_MASTERKEYBLOB_LEN   128

static struct fmt_tests tests[] = {
	{"$ab$3*0*10000*2a7c948fd7124307bca8d7ac921a9f019f32b0f74f484cfe9266f3ee0da064fc8a57b1c9e2edf66b8425448d064ef121a453c8941a024dbdfc7481bfbc47437e*3bbd3f57551336c7db480cbdc3dc5ce3da4e185a586a3fd45b816007c2c41889149fbf0e292f88b1207d070d10e577c021dabd0ed8ba8ea6849b0d311942eb37*469920775ce354235ad62500184754d7*749ae8a777d30ea4913084a8266f9f740dfc0a78d545aafb0a39051519a610db5f3d5f68cdaff7f04a74645e8a7b0c5c965d978f4a2fa0650854ab120bb9f683b494a6dcb84d3b74960a6a413fe83648f118e152bad23ab1be294912e357b3b9", "openwall"},
	{"$ab$3*0*10000*dc4e8723d6c1ac065878dc6428e8ad08d3912cf7f1757007a6c6793ee0c6af57c4604a0e2afb4d201d98f7cab1f24927f9319344aa25e28782b2ea8e627f1cc9*d1eb72793eae5d7e28c20e3d142c2c7cdb363e92fb03c3a6444152f83f0edbfc31a8447761074e85ecf6e07341893b9864861015139b9cd20b9474b9a96bf0c7*862f63c48ef68b0f28d784bd81f28f68*6a185cd6b9d4a44470845b9366f10881d7549b0e5d353309ac3b155ca22d8f0064a10c16919472fc6540a49472d1d9adc7f510fdc5906719b8c8aaac492433f7242186314384fd013c37cb4bc646bcb184a37c7091273ff5b54f5485a30eabe0", "password"},
	{"$ab$3*0*10000*6a2b625432affe69b7bec924c643462c1bb47f8270ea32c3f4fe371f7646b51fa5bd3b13592143bd1a03f67bb73f17c0edbaa68f9de8d88190dbf2bc1a51e121*4b8a71cb21ab4510ddf0fbcfa049c4f046baa492b51efbc7d12499c6d2d794443c8d1f19dee8bef088dd7e1951d1215207594f828e53dd5734a9c1be1c0b350c*161cc825bb9c3025b8f81b9a1dccd1d9*9424dfd7d445e3be505a8905565ed3c4359492b0f8b079a8d4ba57d72a9489c0be6e87f51d20c6544152fded3de91bdc5a74966a54d6261190f6379bc8d0a39b2eb6ebeb1768478fdbdf241cc15137111caa00efe8e07ba2c5efcac71f91c101", "åbc"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t iv_length;
	uint32_t iterations;
	unsigned char iv[IVLEN];
	unsigned char user_salt[SALTLEN];
	uint32_t user_salt_length;
	unsigned char ck_salt[SALTLEN];
	uint32_t ck_salt_length;
	unsigned char masteykey_blob[MAX_MASTERKEYBLOB_LEN];
	uint32_t masteykey_blob_length;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);
	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL)  // version / type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value < 1 || value > 5)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // cipher
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // rounds
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // user_salt
		goto err;
	if (hexlenl(p, &extra) > SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // ck_salt
		goto err;
	if (hexlenl(p, &extra) > SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // user_iv
		goto err;
	if (hexlenl(p, &extra) > IVLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // masteykey_blob
		goto err;
	if (hexlenl(p, &extra) > MAX_MASTERKEYBLOB_LEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	p = strtokm(NULL, "*");
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.user_salt_length = strlen(p) / 2;
	for (i = 0; i < cs.user_salt_length; i++)
		cs.user_salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.ck_salt_length = strlen(p) / 2;
	for (i = 0; i < cs.ck_salt_length; i++)
		cs.ck_salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.iv_length = strlen(p) / 2;
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.masteykey_blob_length = strlen(p) / 2;
	for (i = 0; i < cs.masteykey_blob_length; i++)
		cs.masteykey_blob[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

static int check_password(unsigned char *user_key, struct custom_salt *cs)
{
	unsigned char iv[IVLEN];
	unsigned char out[MAX_MASTERKEYBLOB_LEN];
	// unsigned char checksum[32];
	// unsigned char masterkey[32];
	AES_KEY aeskey;
	int pad_byte;
	// int offset = 0;
	int len;

	// decrypt masteykey_blob
	memcpy(iv, cs->iv, cs->iv_length);
        AES_set_decrypt_key(user_key, 256, &aeskey);
        AES_cbc_encrypt(cs->masteykey_blob, out, cs->masteykey_blob_length, &aeskey, iv, AES_DECRYPT);

	len = out[0];
	if (len != IVLEN)  // quick reject
		return 0;

	// padding check
	pad_byte = out[cs->masteykey_blob_length - 1];
	if (check_pkcs_pad(out, cs->masteykey_blob_length, 16) < 0)
		return 0;

	if (pad_byte > 8)
		return 1;

	return 0;

	/* master key iv
	len = out[offset++];
	if (offset + len > cs->masteykey_blob_length)
		return 0;
	memcpy(iv, out + offset, len);
	offset += len;
	// master key itself
	len = out[offset++];
	if (len != 32)  // quick reject
		return 0;
	if (offset + len > cs->masteykey_blob_length)
		return 0;
	memcpy(masterkey, out + offset, len);
	print_hex(masterkey, 32);
	offset += len;
	// master key checksum hash
	len = out[offset++];
	if (offset + len > cs->masteykey_blob_length)
		return 0;
	memcpy(checksum, out + offset, len);

	// calculate checksum using (masterkey, cs->ck_salt, cs->iterations)
	//
	// comments from abe project,
	//   + now validate the decrypted master key against the checksum
	//   + first try the algorithm matching the archive version
	//   + boolean useUtf = version >= BACKUP_FILE_V2
	//
	//   - do two checksum calculations, with useUtf and with !useUtf
	//     - byte[] pwBytes = useUtf8 ? PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(pwArray): PBEParametersGenerator.PKCS5PasswordToBytes(pwArray);
	//     - The PKCS5PasswordToUTF8Bytes is super weird. See Bouncy Castle's source code for its implementation.

	// Note: masterkey needs to be processed with PBEParametersGenerator.PKCS5PasswordToUTF8Bytes function before being passed to pbkdf2_hmac_sha1
	// pbkdf2_sha1(masterkey, 32, cur_salt->ck_salt, cur_salt->ck_salt_length, cur_salt->iterations, checksum, 32, 0);

	// compare with cs->checksum and return status */
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char pkey[MIN_KEYS_PER_CRYPT][32];
		int i;
#ifdef SIMD_COEF_32
		int len[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			len[i] = strlen(saved_key[i+index]);
			pin[i] = (unsigned char*)saved_key[i+index];
			pout[i] = pkey[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, len, cur_salt->user_salt, cur_salt->user_salt_length, cur_salt->iterations, pout, 32, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
			pbkdf2_sha1((unsigned char *)saved_key[index+i],
					strlen(saved_key[index+i]),
					cur_salt->user_salt, cur_salt->user_salt_length, cur_salt->iterations,
					pkey[i], 32, 0);
		}
#endif

		for (i = 0; i < MIN_KEYS_PER_CRYPT; i++) {
			if (check_password(pkey[i], cur_salt)) {
				cracked[index+i] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
				any_cracked |= 1;
			} else {
				cracked[index+i] = 0;
			}
		}
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
	return 1;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_ab = {
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
		set_key,
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
