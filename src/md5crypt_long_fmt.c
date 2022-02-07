/*
 * AIX smd5 cracker for JtR. Hacked together during April of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>.
 *
 * Also supports standard md5crypt hashes (of lengths up to 125 unlike the
 * optimized SIMD format) and now supports Apache $apr1$ hashes as well.
 *
 * This software is
 * Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>
 * Copyright (c) 2019 magnum
 * Copyright (c) 2019 Solar Designer
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "md5.h"
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "md5crypt_common.h"

#define FORMAT_LABEL            "md5crypt-long"
#define FORMAT_NAME             "crypt(3) $1$ (and variants)"
#define FORMAT_TAG              "{smd5}"
#define FORMAT_TAG1             "$1$"
#define FORMAT_TAG2             "$apr1$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG) - 1)
#define FORMAT_TAG1_LEN         (sizeof(FORMAT_TAG1) - 1)
#define FORMAT_TAG2_LEN         (sizeof(FORMAT_TAG2) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             16
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4

#ifndef OMP_SCALE
#define OMP_SCALE               2 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
	{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"$1$7Uu2iTBB$Y4hQl2WvrOA3LBbLDxbAf0", "12345"},
	{"$apr1$Q6ZYh...$RV6ft2bZ8j.NGrxLYaJt9.", "test"},
	{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	{"$1$$qRPK7m23GJusamGpoGLby/", ""},
	{"$apr1$a2Jqm...$grFrwEgiQleDr0zR4Jx1b.", "15 chars is max"},
	{"$1$$AuJCr07mI7DSew03TmBIv/", "no salt"},
	{"$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30", "invalid salt"},
	{"$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	{"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{"$apr1$rBXqc...$NlXxN9myBOk95T0AyLAsJ0", "john"},
	{"$apr1$Grpld/..$qp5GyjwM2dnA5Cdej9b411", "the"},
	{"$apr1$GBx.D/..$yfVeeYFCIiEXInfRhBRpy/", "ripper"},
	{"$1$bb$19smCEBG0Q1pVil0/HqK./", "aaaaa"},
	{"$1$coin$rebm0t9KJ56mgGWJF5o5M0", "lapin"},
	{"$1$pouet$/Ecz/vyk.zCYvrr6wB78h0", "canard"},
	{"$1$test2$02MCIATVoxq3IhgK6XRkb1", "test1"},
	{"$1$aussi$X67z3kXsWo92F15uChx1H1", "felicie"},
	{"$1$boire$gf.YM2y3InYEu9.NbVr.v0", "manger"},
	{"$1$bas$qvkmmWnVHRCSv/6LQ1doH/", "haut"},
	{"$1$gauche$EPvd6LZlrgb0MMFPxUrJN1", "droite"},
	/* The following 3 hashes are AIX non-standard smd5 hashes */
	{"{smd5}s8/xSJ/v$uGam4GB8hOjTLQqvBfxJ2/", "password"},
	{"{smd5}alRJaSLb$aKM3H1.h1ycXl5GEVDH1e1", "aixsucks?"},
	{"{smd5}eLB0QWeS$Eg.YfWY8clZuCxF0xNrKg.", "0123456789ABCDE"},
	/* The following 3 hashes are AIX w/ lpa_options = std_hash=true */
	{"$1$JVDbGx8K$T9h8HK4LZxeLPMTAxCfpc1", "password"},
	{"$1$1Cu6fEvv$42kuaJ5fMEqyVStPuFG040", "0123456789ABCDE"},
	{"$1$27iyq7Ya$miN09fW1Scj0DHVNyewoU/", ""},
	{"$1$84Othc1n$v1cuReaa5lRdGuHaOa76n0", "a"},
	{"$1$4zq0BsCR$U2ua9WZtDEhzy4gFSiLxN1", "aa"},
	{"$1$DKwjKWxp$PY6PdlPZsXjOppPDoFOz4.", "aaa"},
	{"$1$OKDV6ppN$viTVmH48bSePiCrMvXT/./", "aaaa"},
	{"$1$QEWsCY0O$xrTTMKTepiHMp7Oxgz0pX/", "aaaaa"},
	{"$1$5dfdk2dF$XiJBPNrfKcCgdQ/kcoB40/", "aaaaaa"},
	{"$1$Ps6A1Cy6$WsvLg9cQhm9JU0rXkLEtz.", "aaaaaaa"},
	{"$1$9IK7nZ4M$4nx7Mdj05KGPJX/mZaDrh.", "aaaaaaaa"},
	{"$1$l3pNTqwT$GAc.dcRaxCvC20CFGCjp4/", "aaaaaaaaa"},
	{"$1$jSAARhJR$6daQ/ekjAL0MgOUgGJyp10", "aaaaaaaaaa"},
	{"$1$wk3Xwqqg$2AtdiucwJvJgbaVT1jWpb0", "aaaaaaaaaaa"},
	{"$1$G6Fn69Ei$d7AKJUOIdz/gO4Utc0TQP1", "aaaaaaaaaaaa"},
	{"$1$A7XJ7lGK$W5jTnH/4lW4XwZ.6F7n1N.", "aaaaaaaaaaaaa"},
	{"$1$Rcm46RfA$LfdIK/OP16yHzMYHSlx/B.", "aaaaaaaaaaaaaa"},
	{"$1$4bCSSJMN$TcYKTsukD4SFJE1n4MwMZ/", "aaaaaaaaaaaaaaa"},
	{"$1$mJxBkkl8$u7OHfWCPmNxvf0um7hH89.", "aaaaaaaaaaaaaaaa"},
	{"$1$Ub1gBUt4$TNaLxU7Pq5mk/MiDEb60b/", "aaaaaaaaaaaaaaaaa"},
	{"$1$8ot7QScR$x.p4vjIgdFxxS83x29PkJ0", "aaaaaaaaaaaaaaaaaa"},
	{"$1$wRi4OjD3$eJjKD2AwLMWfOTRYA30zn.", "aaaaaaaaaaaaaaaaaaa"},
	{"$1$lmektrsg$2KSRY4EUFzsYNMg80fG4/0", "aaaaaaaaaaaaaaaaaaaa"},
	{"$1$tgVBKBmE$YRvzsi7qHP2MC1Atg8VCV.", "aaaaaaaaaaaaaaaaaaaaa"},
	{"$1$oTsk88YC$Eh435T1BQzmjQekfqkHof/", "aaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$ykxSZEfP$hJrFeGOFk049L.94Mgggj/", "aaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$LBK4p5tD$5/gAIx8/7hpTVwDC/.KQv/", "aaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$fkEasaUI$G7CelOWHkol2nVHN8XQP40", "aaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$gRevVzeY$eMMQrsl5OHL5dP1p/ktJc/", "aaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$164TNEjj$ppoV6Ju6Vu63j1OlM4zit/", "aaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$ErPmhjp2$lZZstb2M455Xhk50eeH4i/", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$NUssS5fT$QaS4Ywt0IwzxbE0FAGnXn0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$NxlTyiJ7$gxkXTEJdeTzY8P6tqKmcz.", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$Cmy9x7gW$kamvHI42Kh1CH4Shy6g6S/", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$IsuapfCX$4Yq0Adq5nNZgl0LwbSl5Y0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$rSZfNcKX$N4XPvGrfhKsyoEcRSaqmG0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	int is_standard;
	unsigned char salt[16];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	keeptr = ctcopy;
	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		ctcopy += FORMAT_TAG_LEN;
		cs.is_standard = 0;
	}
	else if (!strncmp(ciphertext, FORMAT_TAG1, FORMAT_TAG1_LEN)) {
		ctcopy += FORMAT_TAG1_LEN;
		cs.is_standard = 1;
	} else {
		ctcopy += FORMAT_TAG2_LEN;
		cs.is_standard = 2;
	}

	p = strtokm(ctcopy, "$");
	strncpy((char*)cs.salt, p, 9);
	p = strtokm(NULL, "$");

	MEM_FREE(keeptr);

	return (void *)&cs;
}

#define TO_BINARY(b1, b2, b3) \
	value = \
		(uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out.b[b1] = value >> 16; \
	out.b[b2] = value >> 8; \
	out.b[b3] = value;

static void* get_binary(char *ciphertext)
{
	static union {
		char b[16];
		ARCH_WORD w;
	} out;
	char *pos;
	uint32_t value;

	if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		pos = ciphertext + FORMAT_TAG_LEN;
	else if (!strncmp(ciphertext, FORMAT_TAG1, FORMAT_TAG1_LEN))
		pos = ciphertext + FORMAT_TAG1_LEN;
	else
		pos = ciphertext + FORMAT_TAG2_LEN;

	while (*pos++ != '$');

	TO_BINARY(0, 6, 12);
	TO_BINARY(1, 7, 13);
	TO_BINARY(2, 8, 14);
	TO_BINARY(3, 9, 15);
	TO_BINARY(4, 10, 5);
	out.b[11] =
		(uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6);

	return out.b;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

/*
 * The function below is loosely based on Poul-Henning Kamp's md5_crypt.c from
 * FreeBSD, which is under the following license:
 *
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

static void crypt_md5(char *pw, char *salt, int is_standard, char *passwd)
{
	const char *magic = (is_standard - 1) ? FORMAT_TAG2 : FORMAT_TAG1;
	const int magiclen = (is_standard - 1) ? FORMAT_TAG2_LEN : FORMAT_TAG1_LEN;
	char *sp, *ep;
	unsigned char final[16];
	int sl, pl, i, j;
	MD5_CTX ctx;

	int pwlen = strlen(pw);
	if (pwlen > PLAINTEXT_LENGTH)
		pwlen = PLAINTEXT_LENGTH;

	/* Refine the Salt first */
	sp = salt;

	/* If it starts with the magic string, then skip that */
	if (is_standard && !strncmp(sp, magic, magiclen))
		sp += magiclen;

	/* It stops at the first '$', max 8 chars */
	for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)
		continue;

	/* get the length of the true salt */
	sl = ep - sp;

	MD5_Init(&ctx);
	MD5_Update(&ctx, pw, pwlen);
	MD5_Update(&ctx, sp, sl);
	MD5_Update(&ctx, pw, pwlen);
	MD5_Final(final, &ctx);

	MD5_Init(&ctx);

	/* The password first, since that is what is most unknown */
	MD5_Update(&ctx, pw, pwlen);

	/* Then our magic string */
	if (is_standard)
		MD5_Update(&ctx, magic, magiclen);

	/* Then the raw salt */
	MD5_Update(&ctx, sp, sl);

	/* Then something really weird... */
	for (pl = pwlen; pl > 0; pl -= 16)
		MD5_Update(&ctx, final, (pl > 16) ? 16 : pl);

	for (i = pwlen; i; i >>= 1) {
		if (i & 1)
			MD5_Update(&ctx, "", 1);
		else
			MD5_Update(&ctx, pw, 1);
	}

	MD5_Final(final, &ctx);

	unsigned char buf[8 * 2 + PLAINTEXT_LENGTH * 3];
	memcpy(buf, sp, sl);
	memcpy(&buf[sl], pw, pwlen);
	memcpy(&buf[sl + pwlen], pw, pwlen);
	memcpy(&buf[sl + (pwlen << 1)], sp, sl);
	memcpy(&buf[sl + (pwlen << 1) + sl], pw, pwlen);

	unsigned char *bufp[6];
	unsigned int bufl[6];
	bufp[0] = &buf[sl];
	bufl[0] = pwlen;
	bufp[1] = bufp[0];
	bufl[1] = pwlen << 1;
	bufp[2] = buf;
	bufl[2] = sl + pwlen;
	bufp[3] = bufp[2];
	bufl[3] = bufl[2] + pwlen;
	bufp[4] = &buf[sl + pwlen];
	bufl[4] = bufl[2];
	bufp[5] = bufp[4];
	bufl[5] = bufl[4] + pwlen;

	static const uint8_t map[42] = {
		0, 5, 3, 1, 3, 5, 1, 4, 3, 1, 3, 5, 1, 5, 2, 1, 3, 5, 1, 5, 3,
		0, 3, 5, 1, 5, 3, 1, 2, 5, 1, 5, 3, 1, 3, 4, 1, 5, 3, 1, 3, 5
	};

	i = 500; j = 0;
	do {
		MD5_Init(&ctx);
		MD5_Update(&ctx, final, 16);
		MD5_Update(&ctx, bufp[map[j]], bufl[map[j]]);
		MD5_Final(final, &ctx);

		MD5_Init(&ctx);
		MD5_Update(&ctx, bufp[map[j + 1]], bufl[map[j + 1]]);
		if ((j += 2) >= 42)
			j = 0;
		MD5_Update(&ctx, final, 16);
		MD5_Final(final, &ctx);
	} while (--i);

	memcpy(passwd, final, 16);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		crypt_md5(saved_key[index], (char*)cur_salt->salt, cur_salt->is_standard, (char *)crypt_out[index]);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void md5crypt_long_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int salt_hash(void *salt)
{
	return *(unsigned int*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_md5crypt_long = {
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
		{ FORMAT_TAG, FORMAT_TAG1, FORMAT_TAG2 },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		cryptmd5_common_valid,
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
		salt_hash,
		NULL,
		set_salt,
		md5crypt_long_set_key,
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
