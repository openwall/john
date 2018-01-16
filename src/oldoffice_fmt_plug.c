/*
 * MS Office 97-2003 cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2014, magnum
 * Copyright (c) 2009, David Leblanc (http://offcrypto.codeplex.com/)
 *
 * License: Microsoft Public License (MS-PL)
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oldoffice;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oldoffice);
#else

#include <stdint.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "md5.h"
#include "rc4.h"
#include "sha.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "unicode.h"
#include "dyna_salt.h"
#include "memdbg.h"

#define FORMAT_LABEL            "oldoffice"
#define FORMAT_NAME             "MS Office <= 2003"
#define ALGORITHM_NAME          "MD5/SHA1 RC4 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1000
#define PLAINTEXT_LENGTH        64
#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_SIZE               sizeof(dyna_salt*)
#define SALT_ALIGN              MEM_ALIGN_WORD
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

#define CIPHERTEXT_LENGTH       (TAG_LEN + 120)
#define FORMAT_TAG              "$oldoffice$"
#define TAG_LEN                 (sizeof(FORMAT_TAG) - 1)

static struct fmt_tests oo_tests[] = {
	{"$oldoffice$1*de17a7f3c3ff03a39937ba9666d6e952*2374d5b6ce7449f57c9f252f9f9b53d2*e60e1185f7aecedba262f869c0236f81", "test"},
	{"$oldoffice$0*e40b4fdade5be6be329c4238e2099b8a*259590322b55f7a3c38cb96b5864e72d*2e6516bfaf981770fe6819a34998295d", "123456789012345"},
	{"$oldoffice$4*163ae8c43577b94902f58d0106b29205*87deff24175c2414cb1b2abdd30855a3*4182446a527fe4648dffa792d55ae7a15edfc4fb", "Google123"},
	/* Meet-in-the-middle candidate produced with hashcat -m9710 */
	/* Real pw is "hashcat", one collision is "zvDtu!" */
	{"", "zvDtu!", {"", "$oldoffice$1*d6aabb63363188b9b73a88efb9c9152e*afbbb9254764273f8f4fad9a5d82981f*6f09fd2eafc4ade522b5f2bee0eaf66d","f2ab1219ae"} },
#if PLAINTEXT_LENGTH >= 24
	/* 2003-RC4-40bit-MS-Base-Crypto-1.0_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*9f32522fe9bcb69b12f39d3c24b39b2f*fac8b91a8a578468ae7001df4947558f*f2e267a5bea45736b52d6d1051eca1b935eabf3a", "myhovercraftisfullofeels"},
	/* Test-RC4-40bit-MS-Base-DSS_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*095b777a73a10fb6bcd3e48d50f8f8c5*36902daab0d0f38f587a84b24bd40dce*25db453f79e8cbe4da1844822b88f6ce18a5edd2", "myhovercraftisfullofeels"},
	/* 2003-RC4-40bit-MS-Base-DH-SChan_myhovercraftisfullofeels_.doc */
	{"$oldoffice$3*284bc91cb64bc847a7a44bc7bf34fb69*1f8c589c6fcbd43c42b2bc6fff4fd12b*2bc7d8e866c9ea40526d3c0a59e2d37d8ded3550", "myhovercraftisfullofeels"},
	/* Test-RC4-128bit-MS-Strong-Crypto_myhovercraftisfullofeels_.doc */
	{"$oldoffice$4*a58b39c30a06832ee664c1db48d17304*986a45cc9e17e062f05ceec37ec0db17*fe0c130ef374088f3fec1979aed4d67459a6eb9a", "myhovercraftisfullofeels"},
	/* 2003-RC4-40bit-MS-Base-1.0_myhovercraftisfullofeels_.xls */
	{"$oldoffice$3*f426041b2eba9745d30c7949801f7d3a*888b34927e5f31e2703cc4ce86a6fd78*ff66200812fd06c1ba43ec2be9f3390addb20096", "myhovercraftisfullofeels"},
#endif
	/* the following hash was extracted from Proc2356.ppt (manually + by oldoffice2john.py */
	{"$oldoffice$3*DB575DDA2E450AB3DFDF77A2E9B3D4C7*AB183C4C8B5E5DD7B9F3AF8AE5FFF31A*B63594447FAE7D4945D2DAFD113FD8C9F6191BF5", "crypto"},
	{"$oldoffice$3*3fbf56a18b026e25815cbea85a16036c*216562ea03b4165b54cfaabe89d36596*91308b40297b7ce31af2e8c57c6407994b205590", "openwall"},
	{NULL}
};

/* Password encoded in UCS-2 */
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
/* UCS-2 password length, in octets */
static int *saved_len;
/* Last hash with this salt and plain */
static unsigned char (*mitm_key)[16];
static unsigned char (*rc4_key)[16];
static int any_cracked, *cracked;
static size_t cracked_size;
static int new_keys;

typedef struct {
	dyna_salt dsalt;
	int type;
	unsigned char salt[16];
	unsigned char verifier[16]; /* or encryptedVerifier */
	unsigned char verifierHash[20];  /* or encryptedVerifierHash */
	unsigned int has_mitm;
	unsigned char mitm[5]; /* Meet-in-the-middle hint, if we have one */
} custom_salt;

static struct {
	int ct_hash;
	unsigned char mitm[10];
} mitm_catcher;

static custom_salt cs;
static custom_salt *cur_salt = &cs;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	if (options.target_enc == UTF_8)
		self->params.plaintext_length = 3 * PLAINTEXT_LENGTH > 125 ?
			125 : 3 * PLAINTEXT_LENGTH;
	saved_key = mem_alloc(self->params.max_keys_per_crypt *
	                      sizeof(*saved_key));
	saved_len = mem_alloc(self->params.max_keys_per_crypt *
	                      sizeof(*saved_len));
	mitm_key = mem_alloc(self->params.max_keys_per_crypt *
	                     sizeof(*mitm_key));
	rc4_key = mem_alloc(self->params.max_keys_per_crypt *
	                    sizeof(*rc4_key));
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(1, cracked_size);
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(rc4_key);
	MEM_FREE(mitm_key);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

/* Based on ldr_cracked_hash from loader.c */
#define HASH_LOG 30
#define HASH_SIZE (1 << HASH_LOG)
static int hex_hash(char *ciphertext)
{
	unsigned int hash, extra;
	unsigned char *p = (unsigned char *)ciphertext;

	hash = p[0] | 0x20; /* ASCII case insensitive */
	if (!hash)
		goto out;
	extra = p[1] | 0x20;
	if (!extra)
		goto out;

	p += 2;
	while (*p) {
		hash <<= 1; extra <<= 1;
		hash += p[0] | 0x20;
		if (!p[1]) break;
		extra += p[1] | 0x20;
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> HASH_LOG;
			extra ^= extra >> (HASH_LOG - 1);
			hash &= HASH_SIZE - 1;
		}
	}

	hash -= extra;
	hash ^= extra << (HASH_LOG / 2);
	hash ^= hash >> HASH_LOG;
	hash &= HASH_SIZE - 1;
out:
	return hash;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int type, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		return 0;
	if (strlen(ciphertext) > CIPHERTEXT_LENGTH)
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += TAG_LEN;
	if (!(ptr = strtokm(ctcopy, "*"))) /* type */
		goto error;
	type = atoi(ptr);
	if (type < 0 || type > 4)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (hexlen(ptr, &extra) != 32 || extra)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier */
		goto error;
	if (hexlen(ptr, &extra) != 32 || extra)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier hash */
		goto error;
	if (type < 3 && (hexlen(ptr, &extra) != 32 || extra))
		goto error;
	else if (type >= 3 && (hexlen(ptr, &extra) != 40 || extra))
		goto error;
/*
 * Deprecated field: mitm hash (40-bit RC4). The new way to put it is in the
 * uid field, like hashcat's example hash.
 */
	if (type <= 3 && (ptr = strtokm(NULL, "*"))) {
		if (hexlen(ptr, &extra) != 10 || extra)
			goto error;
	}
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

/* uid field may contain a meet-in-the-middle hash */
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	if (split_fields[0] && valid(split_fields[0], self) && split_fields[1] &&
	    hexlen(split_fields[1], 0) == 10) {
		mitm_catcher.ct_hash = hex_hash(split_fields[0]);
		memcpy(mitm_catcher.mitm, split_fields[1], 10);
		return split_fields[0];
	}
	else if (valid(split_fields[1], self) && split_fields[2] &&
	         hexlen(split_fields[2], 0) == 10) {
		mitm_catcher.ct_hash = hex_hash(split_fields[1]);
		memcpy(mitm_catcher.mitm, split_fields[2], 10);
	}
	return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH];
	char *p;
	int extra;

	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);

	/* Drop legacy embedded MITM hash */
	if ((p = strrchr(out, '*')) && (hexlen(&p[1], &extra) == 10 || extra))
		*p = 0;
	return out;
}

static void *get_salt(char *ciphertext)
{
	static void *ptr;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LEN;	/* skip over "$oldoffice$" */
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.verifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	if (cs.type < 3) {
		for (i = 0; i < 16; i++)
			cs.verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	else {
		for (i = 0; i < 20; i++)
			cs.verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if ((p = strtokm(NULL, "*"))) { /* Deprecated field */
		cs.has_mitm = 1;
		for (i = 0; i < 5; i++)
			cs.mitm[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	} else
	if (hex_hash(ciphertext) == mitm_catcher.ct_hash) {
		cs.has_mitm = 1;
		for (i = 0; i < 5; i++)
			cs.mitm[i] = atoi16[ARCH_INDEX(mitm_catcher.mitm[i * 2])] * 16
				+ atoi16[ARCH_INDEX(mitm_catcher.mitm[i * 2 + 1])];
	} else
		cs.has_mitm = 0;

	MEM_FREE(keeptr);

	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(custom_salt, type);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(custom_salt, type, has_mitm, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_copy(&cs, sizeof(custom_salt), MEM_ALIGN_WORD);
	return &ptr;
}

static void set_salt(void *salt)
{
	if (memcmp(cur_salt->salt, (*(custom_salt**)salt)->salt, 16))
	    new_keys = 1;
	cur_salt = *(custom_salt**)salt;
}

static int salt_compare(const void *x, const void *y)
{
	int c;

	c = memcmp((*(custom_salt**)x)->salt, (*(custom_salt**)y)->salt, 16);
	if (c)
		return c;
	c = dyna_salt_cmp((void*)x, (void*)y, SALT_SIZE);
	return c;
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
	for (index = 0; index < count; index++) {
		int i;
		RC4_KEY key;

		if (cur_salt->type < 3) {
			MD5_CTX ctx;
			unsigned char pwdHash[16];
			unsigned char hashBuf[21 * 16];

			if (new_keys) {
				unsigned char key_hash[16];

				MD5_Init(&ctx);
				MD5_Update(&ctx, saved_key[index], saved_len[index]);
				MD5_Final(key_hash, &ctx);
				for (i = 0; i < 16; i++) {
					memcpy(hashBuf + i * 21, key_hash, 5);
					memcpy(hashBuf + i * 21 + 5, cur_salt->salt, 16);
				}
				MD5_Init(&ctx);
				MD5_Update(&ctx, hashBuf, 21 * 16);
				MD5_Final(mitm_key[index], &ctx);
			}

			// Early reject if we got a hint
			if (cur_salt->has_mitm &&
			    memcmp(mitm_key[index], cur_salt->mitm, 5))
				continue;

			if (new_keys) {
				memcpy(hashBuf, mitm_key[index], 5);
				memset(hashBuf + 5, 0, 4);
				MD5_Init(&ctx);
				MD5_Update(&ctx, hashBuf, 9);
				MD5_Final(rc4_key[index], &ctx);
			}

			RC4_set_key(&key, 16, rc4_key[index]); /* rc4Key */
			RC4(&key, 16, cur_salt->verifier, hashBuf); /* encryptedVerifier */
			RC4(&key, 16, cur_salt->verifierHash, hashBuf + 16); /* encryptedVerifierHash */
			/* hash the decrypted verifier */
			MD5_Init(&ctx);
			MD5_Update(&ctx, hashBuf, 16);
			MD5_Final(pwdHash, &ctx);
			if (!memcmp(pwdHash, hashBuf + 16, 16))
#ifdef _OPENMP
#pragma omp critical
#endif
			{
				any_cracked = cracked[index] = 1;
				cur_salt->has_mitm = 1;
				memcpy(cur_salt->mitm, mitm_key[index], 5);
			}
		}
		else {
			SHA_CTX ctx;
			unsigned char H0[24];
			unsigned char Hfinal[20];
			unsigned char DecryptedVerifier[16];
			unsigned char DecryptedVerifierHash[20];

			if (new_keys) {
				unsigned char key_hash[20];

				SHA1_Init(&ctx);
				SHA1_Update(&ctx, cur_salt->salt, 16);
				SHA1_Update(&ctx, saved_key[index], saved_len[index]);
				SHA1_Final(H0, &ctx);
				memset(&H0[20], 0, 4);
				SHA1_Init(&ctx);
				SHA1_Update(&ctx, H0, 24);
				SHA1_Final(key_hash, &ctx);

				if (cur_salt->type < 4) {
					memcpy(mitm_key[index], key_hash, 5);
					memset(&mitm_key[index][5], 0, 11);
				} else
					memcpy(mitm_key[index], key_hash, 16);
			}

			// Early reject if we got a hint
			if (cur_salt->has_mitm &&
			    memcmp(mitm_key[index], cur_salt->mitm, 5))
				continue;

			RC4_set_key(&key, 16, mitm_key[index]); /* dek */
			RC4(&key, 16, cur_salt->verifier, DecryptedVerifier);
			RC4(&key, 16, cur_salt->verifierHash, DecryptedVerifierHash);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, DecryptedVerifier, 16);
			SHA1_Final(Hfinal, &ctx);
			if (!memcmp(Hfinal, DecryptedVerifierHash, 16))
#ifdef _OPENMP
#pragma omp critical
#endif
			{
				any_cracked = cracked[index] = 1;
				if (cur_salt->type < 4) {
					cur_salt->has_mitm = 1;
					memcpy(cur_salt->mitm, mitm_key[index], 5);
				}
			}
		}
	}
	new_keys = 0;

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
	extern volatile int bench_running;

	if (cur_salt->type < 4 && !bench_running) {
		unsigned char *cp, out[11];
		int i;

		cp = cur_salt->mitm;
		for (i = 0; i < 5; i++) {
			out[2 * i + 0] = itoa16[*cp >> 4];
			out[2 * i + 1] = itoa16[*cp & 0xf];
			cp++;
		}
		out[10] = 0;
		fprintf(stderr, "MITM key: %s\n", out);
	}
	return 1;
}

static void set_key(char *key, int index)
{
	/* convert key to UTF-16LE */
	saved_len[index] = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
	saved_len[index] <<= 1;
	new_keys = 1;
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

static unsigned int oo_hash_type(void *salt)
{
	custom_salt *my_salt;

	my_salt = *(custom_salt**)salt;
	return (unsigned int) my_salt->type;
}

struct fmt_main fmt_oldoffice = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8 | FMT_SPLIT_UNIFIES_CASE | FMT_DYNA_SALT,
		{
			"hash type",
		},
		{ FORMAT_TAG },
		oo_tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
		{
			oo_hash_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		salt_compare,
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
