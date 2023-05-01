/*
 * DMD5_fmt.c
 *
 * DIGEST-MD5 authentication module for Solar Designer's John the Ripper
 * Uses Solar Designer's MD5 implementation.
 *
 * This software is Copyright 2006, regenrecht@o2.pl, and
 * Copyright 2011, 2013 magnum, and it is hereby released to the general
 * public under the following terms:  Redistribution and use in source and
 * binary forms, with or without modification, are permitted.
 *
 * Input format:
 * $DIGEST-MD5$ username $ realm $ nonce $ digest_uri $ cnonce $ nc $ qop $ response [ $ authzid ]
 *
 * Just base64-decode the blob you see when sniffing, to get all data needed
 * for above.
 *
 * See https://tools.ietf.org/html/rfc2831 (Using Digest Authentication as a
 * SASL Mechanism) for algorithm details.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_DMD5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_DMD5);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "md5.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL            "dmd5"
#define FORMAT_NAME             "DIGEST-MD5 C/R"
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define FORMAT_TAG              "$DIGEST-MD5$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define MD5_HEX_SIZE            (2 * BINARY_SIZE)
#define BINARY_SIZE             16
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              4
#define DSIZE                   (128 - sizeof(int))
#define CIPHERTEXT_LENGTH       (DSIZE * 4)
#define PLAINTEXT_LENGTH        32
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1024

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

static const char itoa16_shr_04[] =
	"0000000000000000"
	"1111111111111111"
	"2222222222222222"
	"3333333333333333"
	"4444444444444444"
	"5555555555555555"
	"6666666666666666"
	"7777777777777777"
	"8888888888888888"
	"9999999999999999"
	"aaaaaaaaaaaaaaaa"
	"bbbbbbbbbbbbbbbb"
	"cccccccccccccccc"
	"dddddddddddddddd"
	"eeeeeeeeeeeeeeee"
	"ffffffffffffffff";

static const char itoa16_and_0f[] =
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef";

static struct custom_salt {
	unsigned char login_id[DSIZE + 64 /* sizeof(realm) */];   // username:realm
	unsigned int  login_id_len;

	unsigned char nonces[DSIZE];     // :nonce:cnonce[:authzid]
	unsigned int  nonces_len;

	unsigned char prehash_KD[DSIZE + 2 * MD5_HEX_SIZE]; // :nonce:nc:cnonce:qop:hex_A2_hash
	unsigned int  prehash_KD_len;
} *cur_salt;

static uint32_t (*crypt_key)[BINARY_SIZE/4];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];

static struct fmt_tests tests[] = {
	// Two hashes from https://tools.ietf.org/html/rfc2831#section-8
	{"$DIGEST-MD5$chris$elwood.innosoft.com$OA6MG9tEQGm2hh$imap/elwood.innosoft.com$OA6MHXh6VqTrRk$00000001$auth$d388dad90d4bbd760a152321f2143af7", "secret"},
	{"$DIGEST-MD5$chris$elwood.innosoft.com$OA9BSXrbuRhWay$acap/elwood.innosoft.com$OA9BSuZWMSpW8m$00000001$auth$6084c6db3fede7352c551284490fd0fc", "secret"},
	// And one unrelated hash
	{"$DIGEST-MD5$s3443$pjwstk$00$ldap/10.253.34.43$0734d94ad9abd5bd7fc5e7e77bcf49a8$00000001$auth-int$dd98347e6da3efd6c4ff2263a729ef77", "test"},
	{NULL}
};

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       PLAINTEXT_LENGTH + 1);
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       BINARY_SIZE);
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *data = ciphertext + FORMAT_TAG_LEN;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	if (strlen(ciphertext) > CIPHERTEXT_LENGTH)
		return 0;

	if (!(p = strchr(data, '$')) || (int)(p-data) >= 64) // username
		return 0;
	data = p + 1; // realm
	if (!(p = strchr(data, '$')) || (int)(p-data) >= 64)
		return 0;
	data = p + 1; // nonce
	if (!(p = strchr(data, '$')) || (int)(p-data) >= 64)
		return 0;
	data = p + 1; // digest_uri
	if (!(p = strchr(data, '$')) || (int)(p-data) >= DSIZE)
		return 0;
	data = p + 1; // cnonce
	if (!(p = strchr(data, '$')) || (int)(p-data) > MD5_HEX_SIZE)
		return 0;
	/* if (hexlenl(data, 0) != p-data) // this is not always hex data!
		return 0; */
	data = p + 1; // nc
	if (!(p = strchr(data, '$')) || (int)(p-data) >= 9)
		return 0;
	data = p + 1; // qop
	if (strncmp(data, "auth", 4) && strncmp(data, "auth-int", 8) &&
	        strncmp(data, "auth-conf", 9))
		return 0;
	if (!(p = strchr(data, '$')) || (int)(p-data) >= 9)
		return 0;
	data = p + 1; // authzid, optional
	if ((p = strchr(data, '$'))) {
		if ((int)(p-data) > MD5_HEX_SIZE || strlen(&p[1]) >= 8)
			return 0;
	} else if (strlen(data) > MD5_HEX_SIZE)
		return 0;
	if (hexlenl(data, &extra) != MD5_HEX_SIZE || extra)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static uint32_t out[BINARY_SIZE/4];
	char response[MD5_HEX_SIZE + 1];
	unsigned int i;
	char *p, *data = ciphertext + FORMAT_TAG_LEN;

	p = strchr(data, '$'); data = p + 1;
	p = strchr(data, '$'); data = p + 1;
	p = strchr(data, '$'); data = p + 1;
	p = strchr(data, '$'); data = p + 1;
	p = strchr(data, '$'); data = p + 1;
	p = strchr(data, '$'); data = p + 1;
	p = strchr(data, '$'); data = p + 1;

	p = strchr(data, '$');
	if (p && (p - data + 1) < sizeof(response))
		strnzcpy(response, data, p - data + 1);
	else
		strnzcpy(response, data, sizeof(response));

	for (i = 0; i < BINARY_SIZE; ++i)
		((unsigned char*)out)[i] =
			(atoi16[ARCH_INDEX(response[i*2])] << 4)
			+ atoi16[ARCH_INDEX(response[i*2+1])];

	return (void*)out;
}

static void *get_salt(char *ciphertext)
{
	char username[64];
	char realm[64];
	char nonce[64];
	char digest_uri[DSIZE];
	char cnonce[MD5_HEX_SIZE + 1];
	char nc[9];
	char qop[9];
	char authzid[8];
	unsigned char *ptr_src, *ptr_dst, v, i;
	char *ccopy = xstrdup(ciphertext);
	char *p, *data = ccopy + FORMAT_TAG_LEN;
	MD5_CTX ctx;
	char A2[DSIZE + sizeof(digest_uri)];
	unsigned char hash[BINARY_SIZE];
	unsigned char hex_hash[2*MD5_HEX_SIZE];
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	if ((p = strchr(data, '$'))) *p = 0;
	strnzcpy(username, data, sizeof(username));

	data = p + 1; if ((p = strchr(data, '$'))) *p = 0;
	strnzcpy(realm, data, sizeof(realm));

	data = p + 1; if ((p = strchr(data, '$'))) *p = 0;
	strnzcpy(nonce, data, sizeof(nonce));

	data = p + 1; if ((p = strchr(data, '$'))) *p = 0;
	strnzcpy(digest_uri, data, sizeof(digest_uri));

	data = p + 1; if ((p = strchr(data, '$'))) *p = 0;
	strnzcpy(cnonce, data, sizeof(cnonce));

	data = p + 1; if ((p = strchr(data, '$'))) *p = 0;
	strnzcpy(nc, data, sizeof(nc));

	data = p + 1; if ((p = strchr(data, '$'))) *p = 0;
	strnzcpy(qop, data, sizeof(qop));

	data = p + 1;
	if ((p = strchr(data, '$'))) {
		*p = 0;
		data = p + 1;
		if (*data)
			strnzcpy(authzid, data, sizeof(authzid));
		else
			*authzid = 0;
	} else {
		*authzid = 0;
	}

	if (!strcmp(qop, "auth"))
		snprintf((char*)A2, sizeof(A2),
		        "AUTHENTICATE:%s", digest_uri);
	else if (!strcmp(qop, "auth-int") || !strcmp(qop, "auth-conf"))
		snprintf((char*)A2, sizeof(A2),
		        "AUTHENTICATE:%s:00000000000000000000000000000000",
		        digest_uri);

	MD5_Init(&ctx);
	MD5_Update(&ctx, A2, strlen((char*)A2));
	MD5_Final(hash, &ctx);

	ptr_src = hash;
	ptr_dst = hex_hash;
	for (i = 0; i < BINARY_SIZE; ++i) {
		v = *ptr_src++;
		*ptr_dst++ = itoa16_shr_04[ARCH_INDEX(v)];
		*ptr_dst++ = itoa16_and_0f[ARCH_INDEX(v)];
	}
	*ptr_dst = 0;

	snprintf((char*)cs.prehash_KD, sizeof(cs.prehash_KD),
	         ":%s:%s:%s:%s:%s", nonce, nc, cnonce, qop, hex_hash);
	cs.prehash_KD_len = strlen((char*)cs.prehash_KD);

	if (authzid[0])
		snprintf((char*)cs.nonces, sizeof(cs.nonces),
		         ":%s:%s:%s", nonce, cnonce, authzid);
	else
		snprintf((char*)cs.nonces, sizeof(cs.nonces),
		         ":%s:%s", nonce, cnonce);

	cs.nonces_len = strlen((char*)cs.nonces);

	snprintf((char*)cs.login_id, sizeof(cs.login_id),
	         "%s:%s:", username, realm);
	cs.login_id_len = strlen((char*)cs.login_id);

	MEM_FREE(ccopy);
	return (void*)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned char hash[16];
		unsigned char hex_hash[MD5_HEX_SIZE];
		unsigned char *ptr_src, *ptr_dst;
		MD5_CTX ctx;
		int i;

		MD5_Init(&ctx);
		// "username:realm"
		MD5_Update(&ctx, cur_salt->login_id, cur_salt->login_id_len);
		// "password"
		MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
		MD5_Final(hash, &ctx);

		MD5_Init(&ctx);
		// previous result
		MD5_Update(&ctx, hash, BINARY_SIZE);
		// ":nonce:cnonce[:authzid]"
		MD5_Update(&ctx, cur_salt->nonces, cur_salt->nonces_len);
		MD5_Final(hash, &ctx);

		// hexify
		ptr_src = hash;
		ptr_dst = hex_hash;
		for (i = 0; i < BINARY_SIZE; ++i) {
			unsigned char v = *ptr_src++;

			*ptr_dst++ = itoa16_shr_04[ARCH_INDEX(v)];
			*ptr_dst++ = itoa16_and_0f[ARCH_INDEX(v)];
		}

		MD5_Init(&ctx);
		// previous result, in hex
		MD5_Update(&ctx, hex_hash, MD5_HEX_SIZE);
		// ":nonce:nc:cnonce:qop:hex_A2_hash
		MD5_Update(&ctx, cur_salt->prehash_KD, cur_salt->prehash_KD_len);
		MD5_Final((unsigned char*)crypt_key[index], &ctx);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	uint32_t b = ((uint32_t*)binary)[0];

	for (index = 0; index < count; index++)
		if (crypt_key[index][0] == b)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_DMD5 = {
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
	},
	{
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
