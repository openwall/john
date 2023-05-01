/*
  SKEY_fmt.c  (changed to SKEY_fmt_plug.c when SKEY_jtr_plug.c code written)

  S/Key dictionary attack module for Solar Designer's John the Ripper.

  skeykeys files should be fed through sed 's/ /:/' first.

  Copyright (c) 2000 Dug Song <dugsong@monkey.org>
  All rights reserved, all wrongs reversed.

  Updated to a working state in JtR 2014 (c) magnum 2014

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

  NOTE, the salt 'might' need to be made lower case. The sample .js files
  I found did lc the salt.
*/

#if FMT_EXTERNS_H
extern struct fmt_main fmt_SKEY;
#elif FMT_REGISTERS_H
john_register_one(&fmt_SKEY);
#else

#include "../arch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_SKEY
#include <skey.h>
#else
#include "../SKEY_jtr.h"
#endif

#include "../misc.h"
#include "../common.h"
#include "../formats.h"

#define FORMAT_LABEL		"skey"
#define FORMAT_NAME		"S/Key"
#define ALGORITHM_NAME		"MD4/MD5/SHA1/RMD160 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE			SKEY_BINKEY_SIZE
#define BINARY_ALIGN		4
#define SALT_SIZE		sizeof(struct skey_salt_st)
#define SALT_ALIGN		4
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define HEXCHARS                "0123456789abcdefABCDEF"

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
static uint32_t saved_key[SKEY_BINKEY_SIZE/4];
static char	saved_pass[PLAINTEXT_LENGTH + 1];

static void *skey_salt(char *ciphertext);

static int
skey_valid(char *ciphertext, struct fmt_main *self)
{
	char *p, buf[128];
	int extra;

	if (*ciphertext == '#')
		return 0;

	strnzcpy(buf, ciphertext, sizeof(buf));

	if ((p = strtok(buf, " \t")) == NULL)
		return 0;

	if (isalpha((unsigned char)(*p))) {
		if (skey_set_algorithm(p) == NULL)
			return 0;
		if ((p = strtok(NULL, " \t")) == NULL)
			return 0;
	}

	for ( ; *p; p++) {
		if (!isdigit( ((unsigned char)(*p))))
			return 0;
	}
	if ((p = strtok(NULL, " \t")) == NULL)
		return 0;
	if (strlen(p) > SKEY_MAX_SEED_LEN)
		return 0;
	if ((p = strtok(NULL, " \t")) == NULL)
		return 0;
	if (hexlenl(p, &extra) != (2 * SKEY_BINKEY_SIZE) || extra)
		return 0;

	if (!skey_salt(ciphertext))
		return 0;

	return 1;
}

static int
hex_decode(char *src, unsigned char *dst, int outsize)
{
	char *p, *pe;
	unsigned char *q, *qe, ch, cl;

	pe = src + strlen(src);
	qe = dst + outsize;

	for (p = src, q = dst; p < pe && q < qe && isxdigit((unsigned char)(*p)); p += 2) {
		ch = tolower((unsigned char)(p[0]));
		cl = tolower((unsigned char)(p[1]));

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

// Since our test strings have 1 space as first delim, and 2 spaces as 2nd
// delim, then it is NOT equivalent to use strtokm() vs strtok.
static void *
skey_salt(char *ciphertext)
{
	static struct skey_salt_st salt;
	static char buf[128];
	char *p;

	strnzcpy(buf, ciphertext, sizeof(buf));
	memset(&salt, 0, sizeof(salt));
	if ((p = strtok(buf, " \t")) == NULL)
		return (NULL);

	if (isalpha((unsigned char)(*p))) {
		strnzcpy(salt.type, p, sizeof(salt.type));
		if ((p = strtok(NULL, " \t")) == NULL)
			return (NULL);
	}
	else strnzcpy(salt.type, "md4", sizeof(salt.type));

	salt.num = atoi(p);

	if ((p = strtok(NULL, " \t")) == NULL)
		return (NULL);

	strnzcpy(salt.seed, p, sizeof(salt.seed));
	//strlwr(salt.seed); // This should probably be added here!! and removed from SKEY_jtr_plug.c

	return (&salt);
}

// Since our test strings have 1 space as first delim, and 2 spaces as 2nd
// delim, then it is NOT equivalent to use strtokm() vs strtok.
static void *get_binary(char *ciphertext)
{
	static unsigned char *realcipher;
	char *ctcopy, *p;

	if (!realcipher)
		realcipher = mem_alloc_tiny(SKEY_BINKEY_SIZE, MEM_ALIGN_WORD);
	ctcopy = xstrdup(ciphertext);
	p = strtok(ctcopy, " \t");

	if (isalpha((unsigned char)(*p)))
		strtok(NULL, " \t");
	strtok(NULL, " \t");
	p = strtok(NULL, " \t");

	memset(realcipher, 0, SKEY_BINKEY_SIZE);
	hex_decode(p, realcipher,SKEY_BINKEY_SIZE);

	MEM_FREE(ctcopy);
	return realcipher;
}


static void
skey_set_salt(void *salt)
{
	memcpy(&saved_salt, salt, sizeof(saved_salt));
}

static void
skey_set_key(char *key, int index)
{
	strnzcpy(saved_pass, key, sizeof(saved_pass));
//	hex_decode(key, (unsigned char*)saved_key, sizeof(saved_key));
}

static char *
skey_get_key(int index)
{
	return (saved_pass);
}

static int
skey_crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i;

	skey_set_algorithm(saved_salt.type);

	keycrunch((unsigned char*)saved_key, saved_salt.seed, saved_pass);

	for (i = 0; i < saved_salt.num; i++)
		f((unsigned char*)saved_key);

	return count;
}

static int
skey_cmp_all(void *binary, int count)
{
	return (memcmp(saved_key, binary, sizeof(saved_key)) == 0);
}

static int
skey_cmp_one(void *binary, int count)
{
	return (memcmp(saved_key, binary, sizeof(saved_key)) == 0);
}

static int
skey_cmp_exact(char *source, int index)
{
	return 1;
}

/*
 * report hash type as first tunable cost, even though the iteration count
 * might be more important with regard to CPU time
 */
static unsigned int skey_hash_type(void *salt)
{
	struct skey_salt_st *my_salt;

	my_salt = (struct skey_salt_st*)salt;
	/*
	 * An empty string (like in the first test hash) meaning MD4
	 * is just my assumption based on some googling.
	 * Older implementations apparently only supported MD4, MD5, and SHA1,
	 * while newer only support MD5, SHA1, and RMD160.
	 * If I am wrong, and "" means MD5, the cost difference
	 * hopefully isn't that big.
	 * The alternative would be to report "" as 0 (unknown), but that would
	 * pretend MD4 cost is similar to the cost of a new hash type.
	 * This seems to be more unlikely than MD4 cost being similar to MD5.
	 */
	if (my_salt->type[0] == '\0' || (!strcasecmp(my_salt->type, "md4")))
		return (unsigned int) 1;
	else if (!strcasecmp(my_salt->type, "md5"))
		return (unsigned int) 2;
	else if (!strcasecmp(my_salt->type, "sha1"))
		return (unsigned int) 3;
	else if (!strcasecmp(my_salt->type, "rmd160"))
		return (unsigned int) 4;
	else	/* unknown */
		return (unsigned int) 0;
}

#define COMMON_GET_HASH_VAR saved_key
#include "../common-get-hash.h"

/* iteration count as 2nd tunable cost */
static unsigned int skey_iteration_count(void *salt)
{
	struct skey_salt_st *my_salt;

	my_salt = (struct skey_salt_st*)salt;
	return (unsigned int) my_salt->num;
}

struct fmt_main fmt_SKEY = {
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
		FMT_CASE | FMT_8_BIT,
		{
			"hash type [1:MD4 2:MD5 3:SHA1 4:RMD160]",
			"iteration count",
		},
		{ NULL },
		skey_tests
	}, {
		fmt_default_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		skey_valid,
		fmt_default_split,
		get_binary,
		skey_salt,
		{
			skey_hash_type,
			skey_iteration_count,
		},
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
		skey_set_salt,
		skey_set_key,
		skey_get_key,
		fmt_default_clear_keys,
		skey_crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "../common-get-hash.h"
		},
		skey_cmp_all,
		skey_cmp_one,
		skey_cmp_exact
	}
};

#endif /* plugin stanza */
