/*
 * This software is
 * Copyright (c) 2015 Michael Kramer <michael.kramer@uni-konstanz.de>,
 * Copyright (c) 2015 magnum,
 * Copyright (c) 2016 Fist0urs <eddy.maaalou@gmail.com>,
 * Copyright (c) 2017 @harmj0y
 *
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Changes,
 *
 * Slight modifications to krb5tgs format to support AS-REP responses by
 * @harmj0y
 *
 * Documentation,
 *
 * http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/ says,
 *
 * If you can enumerate any accounts in a Windows domain that don't require
 * Kerberos preauthentication, you can now easily request a piece of encrypted
 * information for said accounts and efficiently crack the material offline
 * (using the format), revealing the user’s password. The reason for Kerberos
 * preauthentication is to prevent offline password guessing. While the AS-REP
 * ticket itself is encrypted with the service key (in this case the krbtgt
 * hash) the AS-REP "encrypted part" is signed with the client key, i.e. the
 * key of the user we send an AS-REQ for. If preauthentication isn't enabled,
 * an attacker can send an AS-REQ for any user that doesn't have preauth
 * required and receive a bit of encrypted material back that can be cracked
 * offline to reveal the target user’s password.
 *
 * While the AS-REP ticket uses type 2 like a TGS-REP ticket (i.e.
 * kerberoasting) this component of the response is encrypted with the service
 * key, which in this case is the krbtgt hash and therefore not crackable.
 * However, the AS-REP encrypted part, which is the section we can essentially
 * 'downgrade; to RC4-HMAC, is the same algorithm but of message type 8. This
 * difference caused this format to be born.
 *
 * Our krb5tgs format cracks "TGS-REP" messages and this format cracks "AS-REP"
 * messages.
 *
 * Use this format with https://github.com/HarmJ0y/ASREPRoast.
 *
 * See http://www.zytrax.com/tech/survival/kerberos.html for the basics on
 * Kerberos.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5asrep;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5asrep);
#else

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "formats.h"
#include "common.h"
#include "dyna_salt.h"
#include "rc4.h"
#include "md4.h"
#include "hmacmd5.h"
#include "unicode.h"
#include "memdbg.h"

#ifndef OMP_SCALE
#define OMP_SCALE                256
#endif

#define FORMAT_LABEL            "krb5asrep"
#define FORMAT_NAME             "Kerberos 5 AS-REP etype 23"
#define FORMAT_TAG              "$krb5asrep$23$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "MD4 HMAC-MD5 RC4"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1000
#define MIN_PLAINTEXT_LENGTH    0
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            MEM_ALIGN_NONE
#define SALT_SIZE               sizeof(struct custom_salt *)
#define SALT_ALIGN              sizeof(struct custom_salt *)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1

/*
  assuming checksum == edata1

  formats are:
	 checksum$edata2
	 $krb5asrep$23$checksum$edata2
*/
static struct fmt_tests tests[] = {
	{"63B386C8C75ECD10F9DF354F42427FBF$BB46B57E89D878455743D1E4C2CD871B5A526A130595463CC021510BA476247B8F9431505155CBC3D7E6120E93623E083A6A508111937607B73F8F524C23E482B648A9C1BE74D7B72B230711BF405ACE9CAF01D5FAC0304509F0DE2A43E0A0834D5F4D5683CA1B8164359B28AC91B35025158A6C9AAD2585D54BAA0A7D886AC154A0B00BE77E86F25439B2298E9EDA7D4BCBE84F505C6C4E6477BB2C9FF860D80E69E99F83A8D1205743CCDD7EC3C3B8FEC481FCC688EC3BD4BA60D93EB30A3259B2E9542CC281B25061D298F672009DCCE9DCAF47BB296480F941AFCDA533F13EA99739F97B92C971A7B4FB970F", "Password123!"},
	// http://www.exumbraops.com/layerone2016/party (sample.krb.pcap, packet number 1114, AS-REP)
	{"$krb5asrep$23$771adbc2397abddef676742924414f2b$2df6eb2d9c71820dc3fa2c098e071d920f0e412f5f12411632c5ee70e004da1be6f003b78661f8e4507e173552a52da751c45887c19bc1661ed334e0ccb4ef33975d4bd68b3d24746f281b4ca4fdf98fca0e50a8e845ad7d834e020c05b1495bc473b0295c6e9b94963cb912d3ff0f2f48c9075b0f52d9a31e5f4cc67c7af1d816b6ccfda0da5ccf35820a4d7d79073fa404726407ac840910357ef210fcf19ed81660106dfc3f4d9166a89d59d274f31619ddd9a1e2712c879a4e9c471965098842b44fae7ca6dd389d5d98b7fd7aca566ca399d072025e81cf0ef5075447687f80100307145fade7a8", "P@$$w0rd123"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char (*saved_K1)[16];
static int any_cracked, *cracked;
static size_t cracked_size;
static int new_keys;

static struct custom_salt {
	dyna_salt dsalt;
	unsigned char edata1[16];
	uint32_t edata2len;
	unsigned char* edata2;
} *cur_salt;

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char *ptr, *keeptr;
	int i;

	if (strstr(ciphertext, "$SOURCE_HASH$"))
		return ciphertext;
	ptr = mem_alloc_tiny(strlen(ciphertext) + FORMAT_TAG_LEN + 1, MEM_ALIGN_NONE);
	keeptr = ptr;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0) {
		memcpy(ptr, FORMAT_TAG, FORMAT_TAG_LEN);
		ptr += FORMAT_TAG_LEN;
	}

	for (i = 0; i < strlen(ciphertext) + 1; i++)
		ptr[i] = tolower(ARCH_INDEX(ciphertext[i]));

	return keeptr;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	char *ctcopy;
	char *keeptr;
	int extra;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) == 0)
		ctcopy += FORMAT_TAG_LEN;

	/* assume checksum */
	if (((p = strtokm(ctcopy, "$")) == NULL) || strlen(p) != 32)
		goto err;

	/* assume edata2 following */
	if (((p = strtokm(NULL, "$")) == NULL))
		goto err;
	if (!ishex(p) || (hexlen(p, &extra) < (64 + 16) || extra))
		goto err;

	if ((strtokm(NULL, "$") != NULL))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_alloc_align(sizeof(*saved_key) *
			self->params.max_keys_per_crypt,
			MEM_ALIGN_CACHE);
	saved_K1 = mem_alloc_align(sizeof(*saved_K1) *
			self->params.max_keys_per_crypt,
			MEM_ALIGN_CACHE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_K1);
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static void *get_salt(char *ciphertext)
{
	int i;
	static struct custom_salt cs;

	char *p;
	char *ctcopy;
	char *keeptr;
	static void *ptr;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	memset(&cs, 0, sizeof(cs));
	cs.edata2 = NULL;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) == 0)
		ctcopy += FORMAT_TAG_LEN;

	if (((p = strtokm(ctcopy, "$")) != NULL) && strlen(p) == 32) { /* assume checksum */
		for (i = 0; i < 16; i++) {
			cs.edata1[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}

		/* skip '$' */
		p += strlen(p) + 1;

		/* retrieve non-constant length of edata2 */
		for (i = 0; p[i] != '\0'; i++)
			;
		cs.edata2len = i/2;
		cs.edata2 = (unsigned char*) mem_calloc_tiny(cs.edata2len + 1, sizeof(char));

		for (i = 0; i < cs.edata2len; i++) { /* assume edata2 */
			cs.edata2[i] =
				atoi16[ARCH_INDEX(p[i * 2])] * 16 +
				atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
	}

	MEM_FREE(keeptr);

	/* following is used to fool dyna_salt stuff */
	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt, edata1);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt, edata1, edata2len, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memcpy(ptr, &cs, sizeof(struct custom_salt));

	return (void *) &ptr;
}

static void set_salt(void *salt)
{
	cur_salt = *(struct custom_salt**)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, strlen(key) + 1);
	new_keys = 1;
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	// const unsigned char data[4] = {2, 0, 0, 0}; // valid for krb5tgs
	const unsigned char data[4] = {8, 0, 0, 0};
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif

	for (index = 0; index < count; index++) {
		unsigned char K3[16];
#ifdef _MSC_VER
		unsigned char ddata[65536];
#else
		unsigned char ddata[cur_salt->edata2len + 1];
#endif
		unsigned char checksum[16];
		RC4_KEY rckey;

		if (new_keys) {
			MD4_CTX ctx;
			unsigned char key[16];
			UTF16 wkey[PLAINTEXT_LENGTH + 1];
			int len;

			len = enc_to_utf16(wkey, PLAINTEXT_LENGTH,
					(UTF8*)saved_key[index],
					strlen(saved_key[index]));
			if (len <= 0) {
				saved_key[index][-len] = 0;
				len = strlen16(wkey);
			}

			MD4_Init(&ctx);
			MD4_Update(&ctx, (char*)wkey, 2 * len);
			MD4_Final(key, &ctx);

			hmac_md5(key, data, 4, saved_K1[index]);
		}

		hmac_md5(saved_K1[index], cur_salt->edata1, 16, K3);

		RC4_set_key(&rckey, 16, K3);
		RC4(&rckey, 32, cur_salt->edata2, ddata);

		/* check the checksum */
		RC4(&rckey, cur_salt->edata2len - 32, cur_salt->edata2 + 32, ddata + 32);
		hmac_md5(saved_K1[index], ddata, cur_salt->edata2len, checksum);

		if (!memcmp(checksum, cur_salt->edata1, 16)) {
			cracked[index] = 1;

#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}
	new_keys = 0;

	return *pcount;
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

struct fmt_main fmt_krb5asrep = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		MIN_PLAINTEXT_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_OMP | FMT_DYNA_SALT,
		{NULL},
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
		{NULL},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
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

#endif
