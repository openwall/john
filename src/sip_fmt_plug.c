/* SIP cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * Copyright (C) 2007  Martin J. Muench <mjm@codito.de>
 * SIP digest authentication password (hash) cracker
 * See doc/SIPcrack-LICENSE */

#include "md5.h"
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
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1
#endif

typedef struct sip_salt_t {
	int static_hash_data_len, dynamic_hash_data_len;
	char *static_hash_data, *dynamic_hash_data;
	char Buf[DYNAMIC_HASH_SIZE + STATIC_HASH_SIZE + 3];
	char login_hash[33];
} sip_salt;

static sip_salt *pSalt;


#define FORMAT_LABEL		"sip"
#define FORMAT_NAME		"SIP MD5"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(sip_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	64

static struct fmt_tests sip_tests[] = {
/* XXX: need more test vectors, then try benchmarking for "many salts" */
	{"$sip$*192.168.1.111*192.168.1.104*200*asterisk*REGISTER*sip*192.168.1.104**46cce857****MD5*4dfc7515936a667565228dbaa0293dfc", "123456"},
	{"$sip$*10.0.1.20*10.0.1.10*1001*asterisk*REGISTER*sips*10.0.1.20*5061*0ef95b07****MD5*576e39e9de6a9ed053eb218f65fe470e", "q1XCLF0KaBObo797"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned char *cracked;
static int any_cracked;
static size_t cracked_size;
static char bin2hex_table[256][2]; /* table for bin<->hex mapping */

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	/* Init bin 2 hex table for faster conversions later */
	init_bin2hex(bin2hex_table);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *q;
	int i,res = 0;
	if (strncmp(ciphertext, "$sip$*", 6))
		return 0;
	if (strlen(ciphertext) > 2048) // sizeof(saltBuf) in get_salt
		return 0;
	for(i = 0; i < strlen(ciphertext); i++)
		if(ciphertext[i] == '*')
			res++;
	if(res != 14)
		goto err;
	res = 0;
	p += 6;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > HOST_MAXLEN) /* host */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > HOST_MAXLEN) /* host */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > USER_MAXLEN) /* user */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > HOST_MAXLEN) /* realm */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > METHOD_MAXLEN) /* method */
		goto err;
	p = q + 1;
	/* uri stuff */
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	res += q - p;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	res += q - p;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	res += q - p;
	if (res > URI_MAXLEN) /* uri */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > NONCE_MAXLEN) /* nonce */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > NONCE_MAXLEN) /* cnonce */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > CNONCE_MAXLEN) /* nonce_count */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > QOP_MAXLEN) /* qop */
		goto err;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if ((q - p) > ALG_MAXLEN) /* algorithm */
		goto err;
	p = q + 1;
	if ((q = strchr(p, '*')) == NULL)
		goto err;
	if (strncmp("MD5*", p, 4))
		goto err;
	p = q + 1;
	if (strspn(p, "0123456789abcdef") != MD5_LEN_HEX) /* hash */
		goto err;
	return 1;
err:
	return 0;
}

// NOTE, this still needs work. I am sure this will not eliminate (compact out)
// duplicate salts.
static void *get_salt(char *ciphertext)
{
	sip_salt *salt;
	static char saltBuf[2048];

	char *lines[16];
	login_t login;
	int num_lines;
	MD5_CTX md5_ctx;
	unsigned char md5_bin_hash[MD5_LEN];
	char static_hash[MD5_LEN_HEX+1];
	char *saltcopy = saltBuf;

	salt = mem_calloc_tiny(sizeof(sip_salt), MEM_ALIGN_NONE);

	strcpy(saltBuf, ciphertext);
	saltcopy += 6;	/* skip over "$sip$*" */
	memset(&login, 0, sizeof(login_t));
	num_lines = stringtoarray(lines, saltcopy, '*');
	assert(num_lines == 14);
	strncpy(login.server,      lines[0], sizeof(login.server)      - 1 );
	strncpy(login.client,      lines[1], sizeof(login.client)      - 1 );
	strncpy(login.user,        lines[2], sizeof(login.user)        - 1 );
	strncpy(login.realm,       lines[3], sizeof(login.realm)       - 1 );
	strncpy(login.method,      lines[4], sizeof(login.method)      - 1 );
	/* special handling for uri */
	if (!strcmp(lines[7], ""))
		sprintf(login.uri, "%s:%s", lines[5], lines[6]);
	else
		sprintf(login.uri, "%s:%s:%s", lines[5], lines[6], lines[7]);

	strncpy(login.nonce,       lines[8], sizeof(login.nonce)       - 1 );
	strncpy(login.cnonce,      lines[9], sizeof(login.cnonce)      - 1 );
	strncpy(login.nonce_count, lines[10], sizeof(login.nonce_count) - 1 );
	strncpy(login.qop,         lines[11], sizeof(login.qop)        - 1 );
	strncpy(login.algorithm,   lines[12], sizeof(login.algorithm)  - 1 );
	strncpy(login.hash,        lines[13], sizeof(login.hash)       - 1 );
	if(strncmp(login.algorithm, "MD5", strlen(login.algorithm))) {
		printf("\n* Cannot crack '%s' hash, only MD5 supported so far...\n", login.algorithm);
		exit(-1);
	}

	/* Generating MD5 static hash: 'METHOD:URI' */
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, (unsigned char*)login.method, strlen( login.method ));
	MD5_Update(&md5_ctx, (unsigned char*)":", 1);
	MD5_Update(&md5_ctx, (unsigned char*)login.uri, strlen( login.uri ));
	MD5_Final(md5_bin_hash, &md5_ctx);
	bin_to_hex(bin2hex_table, md5_bin_hash, MD5_LEN, static_hash, MD5_LEN_HEX);

	/* Constructing first part of dynamic hash: 'USER:REALM:' */
	salt->dynamic_hash_data = salt->Buf;
	snprintf(salt->dynamic_hash_data, DYNAMIC_HASH_SIZE, "%s:%s:", login.user, login.realm);
	salt->dynamic_hash_data_len = strlen(salt->dynamic_hash_data);

	/* Construct last part of final hash data: ':NONCE(:CNONCE:NONCE_COUNT:QOP):<static_hash>' */
	/* no qop */
	salt->static_hash_data = &(salt->Buf[salt->dynamic_hash_data_len+1]);
	if(!strlen(login.qop))
		snprintf(salt->static_hash_data, STATIC_HASH_SIZE, ":%s:%s", login.nonce, static_hash);
	/* qop/conce/cnonce_count */
	else
		snprintf(salt->static_hash_data, STATIC_HASH_SIZE, ":%s:%s:%s:%s:%s",
				login.nonce, login.nonce_count, login.cnonce,
				login.qop, static_hash);
	/* Get lens of static buffers */
	salt->static_hash_data_len  = strlen(salt->static_hash_data);

	/* Begin brute force attack */
#ifdef SIP_DEBUG
	printf("Starting bruteforce against user '%s' (%s: '%s')\n",
			login.user, login.algorithm, login.hash);
#endif
	strcpy(salt->login_hash, login.hash);
	return salt;
}


static void set_salt(void *salt)
{
	pSalt = (sip_salt*)salt;
}

static void crypt_all(int count)
{
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		/* password */
		MD5_CTX md5_ctx;
		unsigned char md5_bin_hash[MD5_LEN];
		char dynamic_hash[MD5_LEN_HEX+1], final_hash[MD5_LEN_HEX+1];

		/* Generate dynamic hash including pw (see above) */
		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx, (unsigned char*)pSalt->dynamic_hash_data, pSalt->dynamic_hash_data_len);
		MD5_Update(&md5_ctx, (unsigned char*)saved_key[index], strlen(saved_key[index]));
		MD5_Final(md5_bin_hash, &md5_ctx);
		bin_to_hex(bin2hex_table, md5_bin_hash, MD5_LEN, dynamic_hash, MD5_LEN_HEX);

		/* Generate digest response hash */
		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx, (unsigned char*)dynamic_hash, MD5_LEN_HEX);
		MD5_Update(&md5_ctx, (unsigned char*)pSalt->static_hash_data, pSalt->static_hash_data_len);
		MD5_Final(md5_bin_hash, &md5_ctx);
		bin_to_hex(bin2hex_table, md5_bin_hash, MD5_LEN, final_hash, MD5_LEN_HEX);

		/* Check for match */
		if(!strncmp(final_hash, pSalt->login_hash, MD5_LEN_HEX))
			any_cracked = cracked[index] = 1;
	}
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

static void sip_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_sip = {
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
