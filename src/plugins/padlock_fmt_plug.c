/*
 * Format for cracking Padlock password databases.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_padlock;
#elif FMT_REGISTERS_H
john_register_one(&fmt_padlock);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "sha.h"
#include "loader.h"
#include "aes.h"
#include "aes_ccm.h"
#include "pbkdf2_hmac_sha256.h"
#include "jumbo.h"

#define FORMAT_LABEL            "Padlock"
#define FORMAT_NAME             ""
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES " SHA256_ALGORITHM_NAME
#else
#define ALGORITHM_NAME          "PBKDF2-SHA256 AES 32/" ARCH_BITS_STR
#endif
#define PLAINTEXT_LENGTH        125
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define FORMAT_TAG              "$padlock$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT      SSE_GROUP_SZ_SHA256
#define MAX_KEYS_PER_CRYPT      (SSE_GROUP_SZ_SHA256 * 4)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	// empty database
	{"$padlock$1$10000$64$16$bc5ce69b9b9dadafb4566f570cccd15d$6c0f57ec2a0a98974c567cc25a12fff1$16$226683e36d47dc8a3bf7c49fedfdae88$10$07ccbca4012cfa37997d", "openwall"}, // plaintext is "[]"
	// database with one entry
	{"$padlock$1$10000$64$16$bc5ce69b9b9dadafb4566f570cccd15d$0fb7f674020b4223715049a56fa513ca$16$edc14c476a12edc107ac694fc9cb0862$195$8b7a014217b512f88decb734d5edf7c36747dc44a244e01cc1e3e2366e8f70c32edb3a037c61fdc5dba7565131cdbea1a8bb87a9b7923a70d44c8b2ea14f4109adcd3a2f9d1847fd7b77baf2237249354cddc26db31f00188a5160f98a6319cb3d0cca8edcda7fda5d8b2368a584a7fd96eb45adf226176a40477bc3c7300bb51f1e411721b5eeac2af382623bb18a8547cde12d1f21ee26e36a801f77246bbd6e6c3ee8a39f8161b2f7847f5a42a4573bf0de14413e1ce177a0f14dd966f8e71653ae", "openwall"},
	// database with one entry
	{"$padlock$1$10000$64$16$217396d3560f2b9129f7556d556b3150$ff3e884c6211db93abc354d3557d9c04$16$8f1203538ceb691da7443dfd16bc6a36$198$b9c8bf9a7972f71d05b91f60edd4463661730cf4c34a9f7875e759fd8752d5c84ca75b16f3b278f7553ed6d005438f072fdfc3f2d26a5448dcd48d71e707446c1ee2b91761448e742d772998cc61160b5f2ebb80ecf64c8aab7a71a932cadc48aed0cca6dbcef971306b0ba74058f0671b4078c125bcf3eb394a9e9a317b96de48c34af7494e02522de94902f63f316167cb7ee40c4b42a50fe61bdd979c41531ed1a2fa4a13c33ffcf2c7ad4be4abc240f8c94e51afaee0ad9afd494d74c5a92cf0cc751f29", "password@12345"},
	{NULL}
};

static struct custom_salt {
	int version;
	int iterations;
	int tag_len;
	int saltlen;
	int ctlen;
	int addlen;
	unsigned char salt[64];
	unsigned char iv[16];
	unsigned char tag[128];
	unsigned char add[128];
	unsigned char ct[4096];
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int *cracked, cracked_count;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // tag_len
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res != 64 && res != 128 && res != 96)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // saltlen
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res > 128)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iv
		goto bail;
	if (hexlenl(p, &extra) != 16 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // addlen
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res > 128)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // add
		goto bail;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // ctlen
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res > 4096)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // ct
		goto bail;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	memset(&cs, 0, sizeof(cs));

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.version = atoi(p);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs.tag_len = atoi(p) / 8;  // bits-to-bytes
	p = strtokm(NULL, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	for (i = 0; i < 16; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	cs.addlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.addlen; i++)
		cs.add[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	cs.ctlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.ctlen; i++)
		cs.ct[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

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

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char master[MIN_KEYS_PER_CRYPT][32];
		unsigned char output[4096] = {0};
		int i;
		unsigned char *tag = cur_salt->ct + cur_salt->ctlen - cur_salt->tag_len; // last "tag_len" bytes
#ifdef SIMD_COEF_32
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT], *pout[MIN_KEYS_PER_CRYPT];
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			pout[i] = master[i];
		}
		pbkdf2_sha256_sse((const unsigned char**)pin, lens, cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, pout, 32, 0);
#else
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i)
			pbkdf2_sha256((unsigned char *)saved_key[index+i], strlen(saved_key[index+i]), cur_salt->salt, cur_salt->saltlen, cur_salt->iterations, master[i], 32, 0);

#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			memset(output, 0, 4096); // avoid possible false positives that can be caused by older "valid" decrypted data
			aes_ccm_auth_decrypt(master[i], 256,
					cur_salt->ctlen - cur_salt->tag_len,
					cur_salt->iv, 13, cur_salt->add, // 13 is the correct iv size for padlock + sjcl combo
					cur_salt->addlen, cur_salt->ct, output,
					tag, cur_salt->tag_len);
			// CCM tag calculation is broken in Padlock + SJCL combination. Padlock sends "add" data to SJCL
			// without doing base64 decoding! As a result the JavaScript code in SJCL behaves very weirdly.
			// Instead of trying to emulate this broken behavior and struggling with JavaScript, we simply use
			// known plaintext attack here!
			if (cur_salt->ctlen - cur_salt->tag_len == 2) { // special case, empty database
				if (strncmp((const char*)output, "[]", 2) == 0)
					cracked[index+i] = 1;
			} else { // general case
				if (output[0] != '[')
					cracked[index+i] = 0;
				else if (strstr((const char*)output, "\"updated\""))
					cracked[index+i] = 1;
			}
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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
	return 1;
}

static void set_key(char *key, int index)
{
	saved_len[index] =
		strnzcpyn(saved_key[index], key, sizeof(saved_key[index]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int padlock_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}

struct fmt_main fmt_padlock = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"iteration count",
		},
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
		{
			padlock_iteration_count,
		},
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
