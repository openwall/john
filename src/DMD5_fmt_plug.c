/*
 * DMD5_fmt.c
 *
 * Modified by magnum 2011 (original version had no self test and could only
 * crack one set of authentication, hard-coded in this file).
 * No rights reserved.
 *
 * Input format:
 * $DIGEST-MD5$ username $ realm $ nonce $ digest_uri $ cnonce $ nc $ qop $ response [ $ authzid ]
 *
 * DIGEST-MD5 authentication module for Solar Designer's John the Ripper
 * Uses Solar Designer's MD5 implementation.
 * regenrecht@o2.pl, Jan 2006
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "md5.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL		"dmd5"
#define FORMAT_NAME		"DIGEST-MD5"
#define ALGORITHM_NAME		"DIGEST-MD5 authentication"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define A1_x_MAX_LEN		1024
#define A2_MAX_LEN		1024
#define KD_MAX_LEN		1024

#define MD5_BIN_SIZE		16
#define MD5_HEX_SIZE		32

#define BINARY_SIZE		16
#define SALT_SIZE		0

#define PLAINTEXT_LENGTH	32

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static char itoa16_shr_04[] =
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

static char itoa16_and_0f[] =
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

static unsigned char prehash_A1_0[A1_x_MAX_LEN+1];
static unsigned char *prehash_A1_0_key;
static unsigned int  prehash_A1_0_len;
static unsigned char A1_0[MD5_BIN_SIZE];
static unsigned char A1_1[A1_x_MAX_LEN+1];
static unsigned int  A1_1_len;
static unsigned char h_A1[MD5_BIN_SIZE];

static unsigned char A2[A2_MAX_LEN+1];
static unsigned char h_A2[MD5_BIN_SIZE];
static unsigned char hex_h_A2[MD5_HEX_SIZE+1];

static unsigned char binary_response[MD5_BIN_SIZE];

static unsigned char prehash_KD_1[KD_MAX_LEN+1];
static unsigned char prehash_KD[KD_MAX_LEN+1];
static unsigned int  prehash_KD_len;
static unsigned char KD[MD5_BIN_SIZE];

static MD5_CTX ctx;

#ifdef _MSC_VER
#define snprintf sprintf_s
#endif

static struct fmt_tests tests[] = {
	{"$DIGEST-MD5$s3443$pjwstk$00$ldap/10.253.34.43$0734d94ad9abd5bd7fc5e7e77bcf49a8$00000001$auth-int$dd98347e6da3efd6c4ff2263a729ef77", "test"},
	{NULL}
};

static int dmd5_valid(char *ciphertext, struct fmt_main *pFmt)
{
	unsigned char *c = (unsigned char *)ciphertext + 12;
	unsigned char f = 0;

	if (strncmp(ciphertext, "$DIGEST-MD5$", 12) != 0)
		return 0;

	while(*c)
		if (*c++ == '$')
			f++;

	if (f < 7 || f > 8) // last field is optional
		return 0;

	return 1;
}

static void *dmd5_binary(char *ciphertext)
{
	char username[64];
	char realm[64];
	char nonce[64];
	char digest_uri[256];
	char cnonce[33];
	char nc[9];
	char qop[9];
	char response[33];
	char authzid[8];
	unsigned char *ptr_src, *ptr_dst, v, i;
	char *p, *data = ciphertext + 12;

	p = strchr(data, '$');
	if (!p)
		return NULL;
	strnzcpy(username, data, p - data + 1);
	data = p + 1;

	p = strchr(data, '$');
	if (!p)
		return NULL;
	strnzcpy(realm, data, p - data + 1);
	data = p + 1;

	p = strchr(data, '$');
	if (!p)
		return NULL;
	strnzcpy(nonce, data, p - data + 1);
	data = p + 1;

	p = strchr(data, '$');
	if (!p)
		return NULL;
	strnzcpy(digest_uri, data, p - data + 1);
	data = p + 1;

	p = strchr(data, '$');
	if (!p)
		return NULL;
	strnzcpy(cnonce, data, p - data + 1);
	data = p + 1;

	p = strchr(data, '$');
	if (!p)
		return NULL;
	strnzcpy(nc, data, p - data + 1);
	data = p + 1;

	p = strchr(data, '$');
	if (!p)
		return NULL;
	strnzcpy(qop, data, p - data + 1);
	data = p + 1;

	p = strchr(data, '$');
	if (p) {
		strnzcpy(response, data, p - data + 1);
		data = p + 1;
		if (*data)
			strnzcpy(authzid, data, sizeof(authzid));
		else
			*authzid = 0;
	} else {
		strnzcpy(response, data, sizeof(response));
		*authzid = 0;
	}

	if (!strcmp(qop, "auth"))
		snprintf((char *)A2, A2_MAX_LEN, "AUTHENTICATE:%s", digest_uri);
	else if (!strcmp(qop, "auth-int") || !strcmp(qop, "auth-conf"))
		snprintf((char *)A2, A2_MAX_LEN,
			"AUTHENTICATE:%s:00000000000000000000000000000000",
			digest_uri);
	else {
		fprintf(stderr, "unknown 'qop' value\n");
		exit(-1);
	}

	MD5_Init(&ctx);
	MD5_Update(&ctx, A2, strlen((char *)A2));
	MD5_Final(h_A2, &ctx);

	ptr_src = h_A2;
	ptr_dst = hex_h_A2;
	for (i = 0; i < MD5_BIN_SIZE; ++i) {
		v = *ptr_src++;
		*ptr_dst++ = itoa16_shr_04[ARCH_INDEX(v)];
		*ptr_dst++ = itoa16_and_0f[ARCH_INDEX(v)];
	}

	snprintf((char *)prehash_KD_1, KD_MAX_LEN, ":%s:%s:%s:%s:%s", nonce, nc,
		cnonce, qop, hex_h_A2);
	prehash_KD_len = strlen((char *)prehash_KD_1) + MD5_HEX_SIZE;

	snprintf((char *)prehash_KD + MD5_HEX_SIZE, KD_MAX_LEN - MD5_HEX_SIZE,
		"%s", prehash_KD_1);

	if (strlen(authzid))
		snprintf((char *)A1_1, A1_x_MAX_LEN, ":%s:%s:%s", nonce, cnonce,
			authzid);
	else
		snprintf((char *)A1_1, A1_x_MAX_LEN, ":%s:%s", nonce, cnonce);

	A1_1_len = strlen((char *)A1_1);

	snprintf((char *)prehash_A1_0, A1_x_MAX_LEN, "%s:%s:", username, realm);
	prehash_A1_0_len = strlen((char *)prehash_A1_0);
	prehash_A1_0_key = prehash_A1_0 + prehash_A1_0_len;

	for (i = 0; i < MD5_BIN_SIZE; ++i)
		binary_response[i] =
			(atoi16[ARCH_INDEX(response[i*2])] << 4)
			+ atoi16[ARCH_INDEX(response[i*2+1])];

	return (void *)binary_response;
}

static void dmd5_set_key(char *key, int index)
{
	unsigned char *ptr_src, *ptr_dst, v;
	int i, key_len;

	ptr_dst = prehash_A1_0_key;
	while ((*ptr_dst++ = *key++));
	key_len = ptr_dst - prehash_A1_0_key - 1;

	MD5_Init(&ctx);
	MD5_Update(&ctx, prehash_A1_0, prehash_A1_0_len + key_len);
	MD5_Final(A1_0, &ctx);

	MD5_Init(&ctx);
	MD5_Update(&ctx, A1_0, MD5_BIN_SIZE);
	MD5_Update(&ctx, A1_1, A1_1_len);
	MD5_Final(h_A1, &ctx);

	ptr_src = h_A1;
	ptr_dst = prehash_KD;

	for (i = 0; i < MD5_BIN_SIZE; ++i) {
		v = *ptr_src++;
		*ptr_dst++ = itoa16_shr_04[ARCH_INDEX(v)];
		*ptr_dst++ = itoa16_and_0f[ARCH_INDEX(v)];
	}
}

static char *dmd5_get_key(int index)
{
	return (char *)(prehash_A1_0 + prehash_A1_0_len);
}

static void dmd5_crypt_all(int count)
{
	MD5_Init(&ctx);
	MD5_Update(&ctx, prehash_KD, prehash_KD_len);
	MD5_Final(KD, &ctx);
}

static int dmd5_cmp_all(void *binary, int index)
{
	return !memcmp(binary, KD, MD5_BIN_SIZE);
}

static int dmd5_cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_DMD5 = {
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
		FMT_CASE | FMT_8_BIT,
		tests
	},
	{
		fmt_default_init,
		fmt_default_prepare,
		dmd5_valid,
		fmt_default_split,
		dmd5_binary,
		fmt_default_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		dmd5_set_key,
		dmd5_get_key,
		fmt_default_clear_keys,
		dmd5_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		dmd5_cmp_all,
		dmd5_cmp_all,
		dmd5_cmp_exact,
		fmt_default_get_source
	}
};
