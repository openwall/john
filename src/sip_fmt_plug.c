/* SIP cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * Copyright (C) 2007  Martin J. Muench <mjm@codito.de>
 * SIP digest authentication password (hash) cracker
 * See doc/SIPcrack-LICENSE */

#include <openssl/md5.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "crc32.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sip_fmt_plug.h"

#define FORMAT_LABEL		"sip"
#define FORMAT_NAME		"SIP"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		256
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests sip_tests[] = {
	{"$sip$*192.168.1.111*192.168.1.104*200*asterisk*REGISTER*sip*192.168.1.104*46cce857****MD5*4dfc7515936a667565228dbaa0293dfc", "123456"},
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
unsigned char cracked;

/* Hash */
MD5_CTX md5_ctx;
static unsigned char md5_bin_hash[MD5_LEN];
static char static_hash[MD5_LEN_HEX+1], dynamic_hash[MD5_LEN_HEX+1], final_hash[MD5_LEN_HEX+1];
static char dynamic_hash_data[DYNAMIC_HASH_SIZE]; /* USER:REALM: */
static char static_hash_data[STATIC_HASH_SIZE];   /* :nonce:nonce_count:cnonce:qop:static_hash */
static size_t static_hash_data_len, dynamic_hash_data_len;
static char bin2hex_table[256][2]; /* table for bin<->hex mapping */
static login_t *login;

static void init(struct fmt_main *pFmt)
{
	/* Init bin 2 hex table for faster conversions later */
	init_bin2hex(bin2hex_table);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$sip$", 5);
}

static void *get_salt(char *ciphertext)
{
	return ciphertext;
}


static void set_salt(void *salt)
{
	char **lines;
	int num_lines;
	char *saltcopy = strdup(salt);
	char *keeptr = saltcopy;
	saltcopy += 6;	/* skip over "$sip$*" */
	login = (login_t *)malloc(sizeof(login_t));
	memset(login, 0, sizeof(login_t));
	lines = stringtoarray(saltcopy, '*', &num_lines);
	assert(num_lines == 13);
	strncpy(login->server,      lines[0], sizeof(login->server)      - 1 );
	strncpy(login->client,      lines[1], sizeof(login->client)      - 1 );
	strncpy(login->user,        lines[2], sizeof(login->user)        - 1 );
	strncpy(login->realm,       lines[3], sizeof(login->realm)       - 1 );
	strncpy(login->method,      lines[4], sizeof(login->method)      - 1 );
	/* special handling for uri */
	sprintf(login->uri, "%s:%s", lines[5], lines[6]);
	strncpy(login->nonce,       lines[7], sizeof(login->nonce)       - 1 );
	strncpy(login->cnonce,      lines[8], sizeof(login->cnonce)      - 1 );
	strncpy(login->nonce_count, lines[9], sizeof(login->nonce_count) - 1 );
	strncpy(login->qop,         lines[10], sizeof(login->qop)         - 1 );
	strncpy(login->algorithm,   lines[11], sizeof(login->algorithm)  - 1 );
	strncpy(login->hash,        lines[12], sizeof(login->hash)       - 1 );
	if(strncmp(login->algorithm, "MD5", strlen(login->algorithm))) {
		printf("\n* Cannot crack '%s' hash, only MD5 supported so far...\n", login->algorithm);
		exit(-1);
	}

	/* Generating MD5 static hash: 'METHOD:URI' */
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, (unsigned char*)login->method, strlen( login->method ));
	MD5_Update(&md5_ctx, (unsigned char*)":", 1);
	MD5_Update(&md5_ctx, (unsigned char*)login->uri, strlen( login->uri ));
	MD5_Final(md5_bin_hash, &md5_ctx);
	bin_to_hex(bin2hex_table, md5_bin_hash, MD5_LEN, static_hash, MD5_LEN_HEX);

	/* Constructing first part of dynamic hash: 'USER:REALM:' */
	snprintf(dynamic_hash_data, sizeof(dynamic_hash_data), "%s:%s:", login->user, login->realm);

	/* Construct last part of final hash data: ':NONCE(:CNONCE:NONCE_COUNT:QOP):<static_hash>' */
	/* no qop */
	if(!strlen(login->qop))
		snprintf(static_hash_data, sizeof(static_hash_data), ":%s:%s", login->nonce, static_hash);
	/* qop/conce/cnonce_count */
	else
		snprintf(static_hash_data, sizeof(static_hash_data), ":%s:%s:%s:%s:%s",
				login->nonce, login->nonce_count, login->cnonce,
				login->qop, static_hash);
	/* Get lens of static buffers */
	dynamic_hash_data_len = strlen(dynamic_hash_data);
	static_hash_data_len  = strlen(static_hash_data);

	/* Begin brute force attack */
#ifdef SIP_DEBUG
	printf("Starting bruteforce against user '%s' (%s: '%s')\n",
			login->user, login->algorithm, login->hash);
#endif
	cracked = 0;
	free(keeptr);
}

static void crypt_all(int count)
{
	/* password */
	char pw[64];
	size_t pw_len=0;
	strcpy(pw, saved_key);

	/* Generate dynamic hash including pw (see above) */
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, (unsigned char*)dynamic_hash_data, dynamic_hash_data_len);
	pw_len = strlen(pw);
	MD5_Update(&md5_ctx,
			(unsigned char*)pw,
			(pw[pw_len-2] == 0x0d ? pw_len-2 : pw[pw_len-1] == 0x0a ? pw_len -1 : pw_len));
	MD5_Final(md5_bin_hash, &md5_ctx);
	bin_to_hex(bin2hex_table, md5_bin_hash, MD5_LEN, dynamic_hash, MD5_LEN_HEX);

	/* Generate digest response hash */
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, (unsigned char*)dynamic_hash, MD5_LEN_HEX);
	MD5_Update(&md5_ctx, (unsigned char*)static_hash_data, static_hash_data_len);
	MD5_Final(md5_bin_hash, &md5_ctx);
	bin_to_hex(bin2hex_table, md5_bin_hash, MD5_LEN, final_hash, MD5_LEN_HEX);

	/* Check for match */
	if(!strncmp(final_hash, login->hash, MD5_LEN_HEX)) {
		cracked= 1;
	}
}

static int cmp_all(void *binary, int count)
{
	if(cracked)
		return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked;
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

static void sip_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	memcpy(saved_key, key, saved_key_length);
	saved_key[saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key;
}

struct fmt_main sip_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		sip_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		sip_set_key,
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
