/*
 * Format for cracking RADIUS authentication hashes.
 *
 * http://www.untruth.org/~josh/security/radius/radius-auth.html
 *
 * This software is Copyright (c) 2018, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * All credit goes to Joshua Hill for making this work possible.
 *
 * Note: In mode 1 (user password recovery), only the first 16 bytes of the
 * password are recovered.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_radius;
#elif FMT_REGISTERS_H
john_register_one(&fmt_radius);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               16  // tuned on i7-7820HQ (varies wildly)

#include "formats.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"
#include "md5.h"

#define FORMAT_LABEL            "radius"
#define FORMAT_NAME             "RADIUS authentication"
#define FORMAT_TAG              "$radius$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64  // tuned on i7-7820HQ

#define MIN_CIPHERTEXT_LENGTH   16
#define MAX_CIPHERTEXT_LENGTH   128
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH       16
#endif

static struct fmt_tests tests[] = {
	// tshark -q -Xlua_script:network2john.lua -X lua_script1:Passw0rd2 -X lua_script1:0 -r freeradius.pcap
	{"$radius$1*0*Passw0rd2*acf627289be7e214c8e328d0d01fcea2*fe18a76eec4abeeea09eb90e99b359f7", "password2"},
	// same test vector again so that we only benchmark this one (our benchmarks use first two salts)
	{"$radius$1*0*Passw0rd2*acf627289be7e214c8e328d0d01fcea2*fe18a76eec4abeeea09eb90e99b359f7", "password2"},
	// tshark -q -Xlua_script:network2john.lua -X lua_script1:password2 -X lua_script1:1 -r freeradius.pcap
	{"$radius$1*1*password2*acf627289be7e214c8e328d0d01fcea2*fe18a76eec4abeeea09eb90e99b359f7", "Passw0rd2"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static int any_cracked, *cracked;
static size_t cracked_size;

static struct custom_salt {
	uint32_t authenticator_len;
	uint32_t ciphertext_len;
	uint32_t secret_or_password_len;
	uint32_t mode;  // 0 -> attack shared secret, 1 -> attack user password
	char secret_or_password[PLAINTEXT_LENGTH];
	unsigned char authenticator[32];
	unsigned char ciphertext[16];
	unsigned char precalculated_digest[16];  // used for mode 1
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	saved_len = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_len));
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	any_cracked = 0;
	cracked = mem_calloc(cracked_size, 1);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(cracked);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // mode
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // secret_or_password
		goto err;
	if (strlen(p) >= PLAINTEXT_LENGTH)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // authenticator
		goto err;
	if (hexlenl(p, &extra) > 16 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	value = hexlenl(p, &extra);
	if (value < MIN_CIPHERTEXT_LENGTH * 2 || value > MAX_CIPHERTEXT_LENGTH * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	MD5_CTX ctx;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	p = strtokm(NULL, "*");
	cs.mode = atoi(p);
	p = strtokm(NULL, "*");
	cs.secret_or_password_len = strlen(p);
	strcpy(cs.secret_or_password, p);
	p = strtokm(NULL, "*");
	cs.authenticator_len = strlen(p) / 2;
	for (i = 0; i < cs.authenticator_len; i++)
		cs.authenticator[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.ciphertext_len = strlen(p) / 2;
	for (i = 0; i < 16; i++)
		cs.ciphertext[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MD5_Init(&ctx);
	MD5_Update(&ctx, cs.secret_or_password, cs.secret_or_password_len);
	MD5_Update(&ctx, cs.authenticator, cs.authenticator_len);
	MD5_Final(cs.precalculated_digest, &ctx);

	MEM_FREE(keeptr);
	return &cs;
}

static int check_password(int index, struct custom_salt *cs)
{
	int i;

	if (cs->mode == 1) { // recover user password
		unsigned char out[16], rec[17];

		memset(out, 0, 16);
		memcpy(out, saved_key[index], saved_len[index] > 16 ? 16: saved_len[index]);
		for (i = 0; i < 16; i++)
			rec[i] = cs->ciphertext[i] ^ cs->precalculated_digest[i];
		if (!memcmp(out, rec, 16))
			return 1;

/*
 * This is silly: we could just output all plaintext passwords, but we have no
 * mechanism to get them into john.pot from here.  Arguably, this isn't a task
 * for JtR at all.
 */
		if (!bench_or_test_running) {
#ifdef _OPENMP
#pragma omp critical
#endif
			{
				static int rec_count = 0;
				int rec_max = 10;
				rec_count++;
				if (rec_count <= rec_max) {
					rec[16] = 0;
					printf("%s: Recovered password '%s'\n", FORMAT_LABEL, (char *)rec);
				} else if (rec_count == rec_max + 1) {
					printf("%s: Further messages suppressed\n", FORMAT_LABEL);
				}
			}
		}
	} else if (cs->mode == 0) { // recover shared secret
		MD5_CTX ctx;
		unsigned char digest[16];
		unsigned char out[16];

		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], saved_len[index]);
		MD5_Update(&ctx, cs->authenticator, cs->authenticator_len);
		MD5_Final(digest, &ctx);
		memset(out, 0, 16);
		memcpy(out, cs->secret_or_password, cs->secret_or_password_len > 16 ? 16: cs->secret_or_password_len);
		for (i = 0; i < 16; i++)
			out[i] = out[i] ^ digest[i];
		if (!memcmp(out, cs->ciphertext, 16))
			return 1;
	}

	return 0;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		if (check_password(index, cur_salt)) {
			cracked[index] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}

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
	return 1;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_radius = {
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
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
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

#endif /* plugin stanza */
