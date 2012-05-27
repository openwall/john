/*
  SKEY_fmt.c

  S/Key dictionary attack module for Solar Designer's John the Ripper.

  skeykeys files should be fed through sed 's/ /:/' first.

  Copyright (c) 2000 Dug Song <dugsong@monkey.org>
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  3. The name of author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifdef HAVE_SKEY

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <skey.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL		"skey"
#define FORMAT_NAME		"S/Key"
#define ALGORITHM_NAME		"MD4/MD5/SHA1/RMD160"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		0
#define SALT_SIZE		sizeof(struct skey_salt_st)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests skey_tests[] = {
	{"0096 luky451004  b519dcfe18eb7aab", "w00w00 v00d00"},
  	{"md5 0099 luky451001  93b3774544ba92a3", "swirling zagnuts"},
	{"sha1 0042 luky451002  d4f0b50e17b29310", "abcdefg12345678"},
	{"rmd160 0099 luky451006  2dbcbb728e8bb456", "squeamish ossifrage"},
	{NULL}
};

/* Saved state. */
static struct skey_salt_st {
	int	num;
	char	type[SKEY_MAX_HASHNAME_LEN + 1];
	char	seed[SKEY_MAX_SEED_LEN + 1];
	unsigned char	hash[SKEY_BINKEY_SIZE];
} saved_salt;
static unsigned char	saved_key[SKEY_BINKEY_SIZE];
static char	saved_pass[PLAINTEXT_LENGTH];

static int
skey_valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q, buf[24];

	if (*ciphertext == '#')
		return (0);

	strnzcpy(buf, ciphertext, sizeof(buf));

	if ((p = strchr(buf, ' ')) == NULL)
		return (0);
	*p++ = '\0';

	if (isalpha(*buf)) {
		if (skey_set_algorithm(buf) == NULL ||
		    (q = strchr(p, ' ')) == NULL)
			return (0);
		*q = '\0';
	}
	else p = buf;

	for ( ; *p; p++) {
		if (!isdigit(*p))
			return (0);
	}
	return (1);
}

static int
hex_decode(char *src, unsigned char *dst, int outsize)
{
	char *p, *pe;
	unsigned char *q, *qe, ch, cl;

	pe = src + strlen(src);
	qe = dst + outsize;

	for (p = src, q = dst; p < pe && q < qe && isxdigit((int)*p); p += 2) {
		ch = tolower(p[0]);
		cl = tolower(p[1]);

		if ((ch >= '0') && (ch <= '9')) ch -= '0';
		else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
		else return (-1);

		if ((cl >= '0') && (cl <= '9')) cl -= '0';
		else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
		else return (-1);

		*q++ = (ch << 4) | cl;
	}
	return (q - dst);
}

static void *
skey_salt(char *ciphertext)
{
	static struct skey_salt_st salt;
	static char buf[128];
	char *p;

	strnzcpy(buf, ciphertext, sizeof(buf));

	if ((p = strtok(buf, " \t")) == NULL)
		return (NULL);

	if (isalpha(*p)) {
		strnzcpy(salt.type, p, sizeof(salt.type));
		if ((p = strtok(NULL, " \t")) == NULL)
			return (NULL);
	}
	else strnzcpy(salt.type, "md4", sizeof(salt.type));

	salt.num = atoi(p);

	if ((p = strtok(NULL, " \t")) == NULL)
		return (NULL);

	strnzcpy(salt.seed, p, sizeof(salt.seed) - 1);

	if ((p = strtok(NULL, " \t")) == NULL)
		return (NULL);

	hex_decode(p, salt.hash, sizeof(salt.hash));

	return (&salt);
}

static void
skey_set_salt(void *salt)
{
	memcpy(&saved_salt, salt, sizeof(saved_salt));
}

static void
skey_set_key(char *key, int index)
{
	strnzcpy(saved_pass, key, sizeof(saved_pass) - 1);
	hex_decode(key, saved_key, sizeof(saved_key));
}

static char *
skey_get_key(int index)
{
	return (saved_pass);
}

static void
skey_crypt_all(int count)
{
	int i;

	skey_set_algorithm(saved_salt.type);

	keycrunch(saved_key, saved_salt.seed, saved_pass);

	for (i = 0; i < saved_salt.num; i++)
		f(saved_key);
}

static int
skey_cmp_all(void *binary, int count)
{
	return (memcmp(saved_key, saved_salt.hash, sizeof(saved_salt.hash)) == 0);
}

static int
skey_cmp_one(void *binary, int count)
{
	return (1);	/* XXX - fallthrough from skey_cmp_all() */
}

static int
skey_cmp_exact(char *source, int count)
{
	return (1);	/* XXX - fallthrough from skey_cmp_one() */
}

struct fmt_main fmt_SKEY = {
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
		skey_tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		skey_valid,
		fmt_default_split,
		fmt_default_binary,
		skey_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		skey_set_salt,
		skey_set_key,
		skey_get_key,
		skey_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		skey_cmp_all,
		skey_cmp_one,
		skey_cmp_exact,
		fmt_default_get_source
	}
};

#endif
