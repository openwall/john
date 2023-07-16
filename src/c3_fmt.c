/*
 * Generic crypt(3) support, as well as support for glibc's crypt_r(3) and
 * Solaris' MT-safe crypt(3C) with OpenMP parallelization.
 *
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2009-2015 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if AC_BUILT
#include "autoconfig.h"
#else
#undef _XOPEN_SOURCE
#undef _XOPEN_SOURCE_EXTENDED
#undef _XOPEN_VERSION
#undef  _XPG4_2
#undef  _XPG6
#undef _GNU_SOURCE
#define _XOPEN_SOURCE 4 /* for crypt(3) */
#define _XOPEN_SOURCE_EXTENDED 1 /* for OpenBSD */
#define _XOPEN_VERSION 4
#define _XPG4_2
#define _XPG6
#define _GNU_SOURCE 1 /* for crypt_r(3) */
#endif

#if HAVE_CRYPT

#include <stdio.h>

#if !AC_BUILT
#include <string.h>
#ifndef _MSC_VER
#include <strings.h>
#endif
#ifdef __CYGWIN__
#include <crypt.h>
#endif
#if defined(_OPENMP) && defined(__GLIBC__)
#include <crypt.h>
#else
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#endif
#endif

#if STRING_WITH_STRINGS
#include <string.h>
#include <strings.h>
#elif HAVE_STRING_H
#include <string.h>
#elif HAVE_STRINGS_H
#include <strings.h>
#endif

#if (!AC_BUILT && defined(HAVE_CRYPT))
#undef HAVE_CRYPT_H
#define HAVE_CRYPT_H 1
#endif

#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#if defined(_OPENMP)
#include <omp.h> /* for omp_get_thread_num() */
#endif

#include "options.h"
#include "arch.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "john.h"
#include "john_mpi.h"

#define FORMAT_LABEL			"crypt"
#define FORMAT_NAME			"generic crypt(3)"
#define ALGORITHM_NAME			"?/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		72

#define BINARY_SIZE			128
#define BINARY_ALIGN			1
#define SALT_SIZE			BINARY_SIZE
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		96
#define MAX_KEYS_PER_CRYPT		96

static struct fmt_tests tests[] = {
	{"CCNf8Sbh3HDfQ", "U*U*U*U*"},
	{"CCX.K.MFy4Ois", "U*U***U"},
	{"CC4rMpbg9AMZ.", "U*U***U*"},
	{"XXxzOu6maQKqQ", "*U*U*U*U"},
	{"SDbsugeBiC58A", ""},
	{NULL}
};

static char saved_key[MAX_KEYS_PER_CRYPT][PLAINTEXT_LENGTH + 1];
static char saved_salt[SALT_SIZE];
static char crypt_out[MAX_KEYS_PER_CRYPT][BINARY_SIZE];

#if defined(_OPENMP) && defined(__GLIBC__)
#define MAX_THREADS			MAX_KEYS_PER_CRYPT

/* We assume that this is zero-initialized (all NULL pointers) */
static struct crypt_data *crypt_data[MAX_THREADS];
#endif

static void init(struct fmt_main *self)
{
	if (options.subformat) {
		int i;
		char *salt = tests[0].ciphertext;
#if defined(_OPENMP) && defined(__GLIBC__)
		struct crypt_data data;

		data.initialized = 0;
#endif

		/*
		 * Allow
		 * ./john --list=format-tests --format=crypt --subformat=md5crypt
		 * in addition to
		 * ./john --test --format=crypt --subformat=md5crypt
		 *
		 * That's why, don't require FLG_TEST_CHK to be set.
		 */
		if (options.flags & FLG_PASSWD) {
			fprintf(stderr,
			        "\n%s: --subformat option is only for --test or --list=format-tests\n", FORMAT_LABEL);
			error();
		}

		if (!strcmp(options.subformat, "?")) {
			fprintf(stderr, "Subformat may either be a verbatim salt, or: descrypt, md5crypt, bcrypt, sha256crypt, sha512crypt, sunmd5, scrypt, yescrypt, gost-yescrypt\n\n");
			error();
		} else if (!strcasecmp(options.subformat, "md5crypt") ||
		    !strcasecmp(options.subformat, "md5")) {
			static struct fmt_tests tests[] = {
			{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
			{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
			{"$1$$qRPK7m23GJusamGpoGLby/", ""},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " md5crypt";
			salt = "$1$dXc3I7Rw$";
		} else if (!strcasecmp(options.subformat, "sunmd5") ||
		    !strcasecmp(options.subformat, "sun-md5")) {
			static struct fmt_tests tests[] = {
			{"$md5$rounds=904$Vc3VgyFx44iS8.Yu$Scf90iLWN6O6mT9TA06NK/", "test"},
			{"$md5$rounds=904$ZZZig8GS.S0pRNhc$dw5NMYJoxLlnFq4E.phLy.", "Don41dL33"},
			{"$md5$rounds=904$zSuVTn567UJLv14u$q2n2ZBFwKg2tElFBIzUq/0", "J4ck!3Wood"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " SunMD5";
			salt = "$md5$rounds=904$Vc3VgyFx44iS8.Yu$dummy";
		} else if ((!strcasecmp(options.subformat, "sha256crypt")) ||
		           (!strcasecmp(options.subformat, "sha-256")) ||
		           (!strcasecmp(options.subformat, "sha256"))) {
			static struct fmt_tests tests[] = {
			{"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
			{"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.", "U*U***U"},
			{"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " SHA-256 rounds=5000";
			salt = "$5$LKO/Ute40T3FNF95$";
		} else if ((!strcasecmp(options.subformat, "sha512crypt")) ||
		           (!strcasecmp(options.subformat, "sha-512")) ||
		           (!strcasecmp(options.subformat, "sha512"))) {
			static struct fmt_tests tests[] = {
			{"$6$LKO/Ute40T3FNF95$6S/6T2YuOIHY0N3XpLKABJ3soYcXD9mB7uVbtEZDj/LNscVhZoZ9DEH.sBciDrMsHOWOoASbNLTypH/5X26gN0", "U*U*U*U*"},
			{"$6$LKO/Ute40T3FNF95$wK80cNqkiAUzFuVGxW6eFe8J.fSVI65MD5yEm8EjYMaJuDrhwe5XXpHDJpwF/kY.afsUs1LlgQAaOapVNbggZ1", "U*U***U"},
			{"$6$LKO/Ute40T3FNF95$YS81pp1uhOHTgKLhSMtQCr2cDiUiN03Ud3gyD4ameviK1Zqz.w3oXsMgO6LrqmIEcG3hiqaUqHi/WEE2zrZqa/", "U*U***U*"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " SHA-512 rounds=5000";
			salt = "$6$LKO/Ute40T3FNF95$";
		} else if (!strcasecmp(options.subformat, "scrypt")) {
			static struct fmt_tests tests[] = {
			{"$7$C6..../....salt$.Q4tfu4SynukrXlisOF3sNclIWRhhQeMKPQT9XVUGVB", "openwall"},
			{"$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D", "pleaseletmein"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " scrypt 16384,8,1";
			salt = "$7$C6..../....SodiumChloride";
		} else if (!strcasecmp(options.subformat, "yescrypt")) {
			static struct fmt_tests tests[] = {
			{"$y$j9T$AAt9R641xPvCI9nXw1HHW/$cuQRBMN3N/f8IcmVN.4YrZ1bHMOiLOoz9/XQMKV/v0A", "openwall"},
			{"$y$j9T$e8R9q85ZuzUkArEUurdtS.$esON.7y6H.u3UCPVCpbRFueRpAut2n2cMf1EhpjbuiC", "pleaseletmein"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " yescrypt";
			salt = "$y$j9T$AAt9R641xPvCI9nXw1HHW/";
		} else if (!strcasecmp(options.subformat, "gost-yescrypt")) {
			static struct fmt_tests tests[] = {
			{"$gy$j9T$Rt9jcSbmNRUKSenPHUxJp/$4zprMvVKuU/xwoYe3gB5k6WFKfpxRv6IbTkdBfVQQu3", "openwall"},
			{"$gy$j9T$dZZACKQy5jE344hHtI3sQ/$d.kB7A2uNANeWuy2td/7oD3GMgbQtcx/XzibtJqHg5.", "pleaseletmein"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " gost-yescrypt";
			salt = "$gy$j9T$Rt9jcSbmNRUKSenPHUxJp/";
		} else if ((!strcasecmp(options.subformat, "bf")) ||
		           (!strcasecmp(options.subformat, "blowfish")) ||
		           (!strcasecmp(options.subformat, "bcrypt"))) {
			static struct fmt_tests tests[] = {
			{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW","U*U"},
			{"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK","U*U*"},
			{"$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a","U*U*U"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " bcrypt x32";
			salt = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.";
		} else if (!strcasecmp(options.subformat, "bsdicrypt")) { /* Undocumented in the usage message and unnumbered */
			static struct fmt_tests tests[] = {
			{"_J9..CCCCXBrJUJV154M", "U*U*U*U*"},
			{"_J9..CCCCXUhOBTXzaiE", "U*U***U"},
			{NULL} };
			self->params.tests = tests;
			self->params.benchmark_comment = " bsdicrypt x725";
			salt = "_J9..CCCC";
		} else if (!strcasecmp(options.subformat, "descrypt") ||
		           !strcasecmp(options.subformat, "des")) {
			salt = "CC";
		} else {
			char *p = mem_alloc_tiny(strlen(options.subformat) + 2,
			                         MEM_ALIGN_NONE);
			strcpy(p, " ");
			strcat(p, options.subformat);
			self->params.benchmark_comment = p;
			salt = options.subformat;
			/* turn off many salts test, since we are not updating the */
			/* params.tests structure data.                            */
			self->params.benchmark_length |= 0x100;
		}

		for (i = 0; i < 5; i++) {
			char *c;

#if defined(_OPENMP) && defined(__GLIBC__)
			c = crypt_r(tests[i].plaintext, salt, &data);
#else
			c = crypt(tests[i].plaintext, salt);
#endif
			if (c && strlen(c) >= 13)
				tests[i].ciphertext = xstrdup(c);
			else {
				fprintf(stderr, "%s not supported on this system\n",
				       options.subformat);
				error();
			}

			/* No need to replace tests that we're not going to use */
			if (tests != self->params.tests)
				break;
		}

		if (strlen(tests[0].ciphertext) == 13 &&
		    strcasecmp(options.subformat, "descrypt") &&
		    strcasecmp(options.subformat, "des")) {
			fprintf(stderr, "%s not supported on this system\n",
			       options.subformat);
			error();
		}
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int length, count_base64, count_base64_2, id, pw_length;
	char pw[PLAINTEXT_LENGTH + 1], *new_ciphertext;
/* We assume that these are zero-initialized */
	static char sup_length[BINARY_SIZE], sup_id[0x80];

	length = count_base64 = count_base64_2 = 0;
	while (ciphertext[length]) {
		if (atoi64[ARCH_INDEX(ciphertext[length])] != 0x7F) {
			count_base64++;
			if (length >= 2)
				count_base64_2++;
		}
		length++;
	}

	if (length < 13 || length >= BINARY_SIZE)
		return 0;

	id = 0;
	if (length == 13 && count_base64 == 13) /* valid salt */
		id = 1;
	else
	if (length == 13 && count_base64_2 == 11) /* invalid salt */
		id = 2;
	else
	if (length >= 13 &&
	    count_base64_2 >= length - 2 && /* allow for invalid salt */
	    (length - 2) % 11 == 0)
		id = 3;
	else
	if (length == 20 && count_base64 == 19 && ciphertext[0] == '_')
		id = 4;
	else
	if (ciphertext[0] == '$') {
		id = (unsigned char)ciphertext[1];
		if (id <= 0x20 || id >= 0x80)
			id = 9;
	} else
	if (ciphertext[0] == '*' || ciphertext[0] == '!') /* likely locked */
		id = 10;

/* Previously detected as supported */
	if (sup_length[length] > 0 && sup_id[id] > 0)
		return 1;

/* Previously detected as unsupported */
	if (sup_length[length] < 0 && sup_id[id] < 0)
		return 0;

	pw_length = ((length - 2) / 11) << 3;
	if (pw_length >= sizeof(pw))
		pw_length = sizeof(pw) - 1;
	memcpy(pw, ciphertext, pw_length); /* reuse the string, why not? */
	pw[pw_length] = 0;

#if defined(_OPENMP) && defined(__GLIBC__)
/*
 * Let's use crypt_r(3) just like we will in crypt_all() below.
 * It is possible that crypt(3) and crypt_r(3) differ in their supported hash
 * types on a given system.
 */
	{
		struct crypt_data **data = &crypt_data[0];
		if (!*data) {
/*
 * **data is not exactly tiny, but we use mem_alloc_tiny() for its alignment
 * support and error checking.  We do not need to free() this memory anyway.
 *
 * The page alignment is to keep different threads' data on different pages.
 */
			*data = mem_alloc_tiny(sizeof(**data), MEM_ALIGN_PAGE);
			memset(*data, 0, sizeof(**data));
		}
		new_ciphertext = crypt_r(pw, ciphertext, *data);
	}
#else
	new_ciphertext = crypt(pw, ciphertext);
#endif

	if (new_ciphertext && strlen(new_ciphertext) == length &&
	    !strncmp(new_ciphertext, ciphertext, 2)) {
		sup_length[length] = 1;
		sup_id[id] = 1;
		return 1;
	}

	if (id != 10 && !ldr_in_pot)
	if (john_main_process)
		fprintf(stderr, "Warning: "
		    "hash encoding string length %d, type id %c%c\n"
		    "appears to be unsupported on this system; "
		    "will not load such hashes.\n",
		    length, id > 0x20 ? '$' : '#', id > 0x20 ? id : '0' + id);

	if (!sup_length[length])
		sup_length[length] = -1;
	if (!sup_id[id])
		sup_id[id] = -1;
	return 0;
}

static void *binary(char *ciphertext)
{
	static char out[BINARY_SIZE];

	strncpy_pad(out, ciphertext, sizeof(out), 0);
	return out;
}

static void *salt(char *ciphertext)
{
	static char out[SALT_SIZE];
	int cut = sizeof(out);

#if 1
/* This piece is optional, but matching salts are not detected without it */
	int length = strlen(ciphertext);

	switch (length) {
	case 13:
	case 24:
		cut = 2;
		break;

	case 20:
		if (ciphertext[0] == '_') cut = 9;
		break;

	case 35:
	case 46:
	case 57:
		if (ciphertext[0] != '$') cut = 2;
		/* fall through */

	default:
		if ((length >= 26 && length <= 34 &&
		    !strncmp(ciphertext, "$1$", 3)) ||
		    (length >= 47 && !strncmp(ciphertext, "$5$", 3)) ||
		    (length >= 90 && !strncmp(ciphertext, "$6$", 3)) ||
		    (length >= 58 && !strncmp(ciphertext, "$7$", 3)) ||
		    (length >= 51 && !strncmp(ciphertext, "$y$", 3)) ||
		    (length >= 52 && !strncmp(ciphertext, "$gy$", 4))) {
			char *p = strrchr(ciphertext + 3, '$');
			if (p) cut = p - ciphertext;
		} else
		if (length == 59 && !strncmp(ciphertext, "$2$", 3))
			cut = 28;
		else
		if (length == 60 &&
		    (!strncmp(ciphertext, "$2a$", 4) ||
		    !strncmp(ciphertext, "$2b$", 4) ||
		    !strncmp(ciphertext, "$2x$", 4) ||
		    !strncmp(ciphertext, "$2y$", 4)))
			cut = 29;
		else
		if (length >= 27 &&
		    (!strncmp(ciphertext, "$md5$", 5) ||
		    !strncmp(ciphertext, "$md5,", 5))) {
			char *p = strrchr(ciphertext + 4, '$');
			if (p) {
				strncpy_pad(out, ciphertext,
				            ++p - ciphertext, 0);
/*
 * Workaround what looks like a bug in sunmd5.c: crypt_genhash_impl() where it
 * takes a different substring as salt depending on whether the optional
 * existing hash encoding is present after the salt or not.  Specifically, the
 * last '$' delimiter is included into the salt when there's no existing hash
 * encoding after it, but is omitted from the salt otherwise.
 */
				out[p - ciphertext] = 'x';
				return out;
			}
		}
	}
#endif

	/* NUL padding is required */
	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, cut);

	return out;
}

#define H(s, i) \
	((int)(unsigned char)(atoi64[ARCH_INDEX((s)[(i)])] ^ (s)[(i) - 1]))

#define H0(s) \
	int i = strlen(s) - 2; \
	return i > 0 ? H((s), i) & PH_MASK_0 : 0
#define H1(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 4)) & PH_MASK_1 : 0
#define H2(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 6)) & PH_MASK_2 : 0
#define H3(s) \
	int i = strlen(s) - 2; \
	return i > 4 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10)) & PH_MASK_3 : 0
#define H4(s) \
	int i = strlen(s) - 2; \
	return i > 6 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10) ^ (H((s), i - 6) << 15)) & PH_MASK_4 : 0

static int binary_hash_0(void *binary)
{
	H0((char *)binary);
}

static int binary_hash_1(void *binary)
{
	H1((char *)binary);
}

static int binary_hash_2(void *binary)
{
	H2((char *)binary);
}

static int binary_hash_3(void *binary)
{
	H3((char *)binary);
}

static int binary_hash_4(void *binary)
{
	H4((char *)binary);
}

static int get_hash_0(int index)
{
	H0(crypt_out[index]);
}

static int get_hash_1(int index)
{
	H1(crypt_out[index]);
}

static int get_hash_2(int index)
{
	H2(crypt_out[index]);
}

static int get_hash_3(int index)
{
	H3(crypt_out[index]);
}

static int get_hash_4(int index)
{
	H4(crypt_out[index]);
}

static int salt_hash(void *salt)
{
	int i, h;

	i = strlen((char *)salt) - 1;
	if (i > 1) i--;

	h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
	h ^= ((unsigned char *)salt)[i - 1];
	h <<= 6;
	h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i - 1])];
	h ^= ((unsigned char *)salt)[i];

	return h & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	strcpy(saved_salt, salt);
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
	static int warned = 0;
	int count = *pcount;
	int index;

#if defined(_OPENMP) && defined(__GLIBC__)
#pragma omp parallel for default(none) private(index) shared(warned, count, crypt_out, saved_key, saved_salt, crypt_data, stderr)
	for (index = 0; index < count; index++) {
		char *hash;
		int t = omp_get_thread_num();
		if (t < MAX_THREADS) {
			struct crypt_data **data = &crypt_data[t];
			if (!*data) {
/* Stagger the structs to reduce their competition for the same cache lines */
				size_t mask = MEM_ALIGN_PAGE, shift = 0;
				while (t) {
					mask >>= 1;
					if (mask < MEM_ALIGN_CACHE)
						break;
					if (t & 1)
						shift += mask;
					t >>= 1;
				}
				*data = (void *)((char *)
				    mem_alloc_tiny(sizeof(**data) +
				    shift, MEM_ALIGN_PAGE) + shift);
				memset(*data, 0, sizeof(**data));
			}
			hash = crypt_r(saved_key[index], saved_salt, *data);
		} else { /* should not happen */
			struct crypt_data data;
			memset(&data, 0, sizeof(data));
			hash = crypt_r(saved_key[index], saved_salt, &data);
		}
		if (!hash) {
#pragma omp critical
			if (!warned) {
				fprintf(stderr,
				    "Warning: crypt_r() returned NULL\n");
				warned = 1;
			}
			hash = "";
		}
		strnzcpy(crypt_out[index], hash, BINARY_SIZE);
	}
#else
#if defined(_OPENMP) && defined(__sun)
/*
 * crypt(3C) is MT-safe on Solaris.  For traditional DES-based hashes, this is
 * implemented with locking (hence there's no speedup from the use of multiple
 * threads, and the per-thread performance is extremely poor anyway).  For
 * modern hash types, the function is actually able to compute multiple hashes
 * in parallel by different threads (and the performance for some hash types is
 * reasonable).  Overall, this code is reasonable to use for SHA-crypt and
 * SunMD5 hashes, which are not yet supported by non-jumbo John natively.
 */
#pragma omp parallel for /* default(none) private(index) shared(warned, count, crypt_out, saved_key, saved_salt, stderr) or __iob */
#endif
	for (index = 0; index < count; index++) {
		char *hash = crypt(saved_key[index], saved_salt);
		if (!hash) {
#if defined(_OPENMP) && defined(__sun)
#pragma omp critical
#endif
			if (!warned) {
				fprintf(stderr,
				    "Warning: crypt() returned NULL\n");
				warned = 1;
			}
			hash = "";
		}
		strnzcpy(crypt_out[index], hash, BINARY_SIZE);
	}
#endif

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!strcmp((char *)binary, crypt_out[index]))
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !strcmp((char *)binary, crypt_out[index]);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

/*
 * For generic crypt(3), the algorithm is returned as the first "tunable cost":
 * 0: unknown
 * 1: descrypt
 * 2: md5crypt
 * 3: sunmd5
 * 4: bcrypt
 * 5: sha256crypt
 * 6: sha512crypt
 * 7: scrypt
 * 10: yescrypt
 * 11: gost-yescrypt
 * New subformats should be added to the end of the list.
 * Otherwise, restored sessions might continue cracking different hashes if the
 * option "--cost=" had been used when starting that session.
 */
static unsigned int c3_subformat_algorithm(void *salt)
{
	const char *c3_salt = salt;

	if (!c3_salt[0] || !c3_salt[1])
		return 0;
	if (!c3_salt[2])
		return 1;
	if (c3_salt[0] != '$')
		return 0;
	switch (c3_salt[1]) {
	case '1':
		return 2;
	case 'm':
		return 3;
	case '2':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case 'y':
		return 10;
	case 'g':
		if (c3_salt[2] == 'y')
			return 11;
	}

	return 0;
}

static unsigned int c3_algorithm_specific_cost1(void *salt)
{
	unsigned int algorithm, rounds;
	char *c3_salt;

	c3_salt = salt;
	algorithm = c3_subformat_algorithm(salt);

	/* No tunable cost parameters, this makes cases 1 and 2 below dead code */
	if (algorithm < 3)
		return 1;

	switch (algorithm) {
		case 1:
			// DES
			return 25;
		case 2:
			// cryptmd5
			return 1000;
		case 3: // sun_md5
			c3_salt = strstr(c3_salt, "rounds=");
			if (!c3_salt) {
				return 904+4096;	// default
			}
			sscanf(c3_salt, "rounds=%d", &rounds);
			return rounds+4096;
		case 4: // bf
			c3_salt += 4;
			sscanf(c3_salt, "%d", &rounds);
			return rounds;
		case 5:
		case 6:
			// sha256crypt and sha512crypt handled the same:  $x$rounds=xxxx$salt$hash  (or $x$salt$hash for 5000 round default);
			c3_salt += 3;
			if (strncmp(c3_salt, "rounds=", 7))
				return 5000;	// default
			sscanf(c3_salt, "rounds=%d", &rounds);
			return rounds;
	}

	return 1;
}

struct fmt_main fmt_crypt = {
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
		{
			"algorithm [0:unknown 1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt "
				"7:scrypt 10:yescrypt 11:gost-yescrypt]",
			"algorithm specific iterations",
		},
		{ NULL },
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		{
			c3_subformat_algorithm,
#if 1
			c3_algorithm_specific_cost1
#endif
		},
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			NULL,
			NULL
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif // HAVE_CRYPT
