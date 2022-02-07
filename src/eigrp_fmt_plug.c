/*
 * Cracker for EIGRP (Cisco's proprietary routing protocol) MD5 + HMAC-SHA-256 authentication.
 * http://tools.ietf.org/html/draft-savage-eigrp-00
 *
 * This is dedicated to Darya. You inspire me.
 *
 * This software is Copyright (c) 2014, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_eigrp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_eigrp);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "yescrypt/sha256.h"

#define FORMAT_LABEL            "eigrp"
#define FORMAT_NAME             "EIGRP MD5 / HMAC-SHA-256 authentication"
#define FORMAT_TAG              "$eigrp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5/SHA-256 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        81 // IOU accepts larger strings but doesn't use them fully, passwords are zero padded to a minimum length of 16 (for MD5 hashes only)!
#define BINARY_SIZE             16 // MD5 hash or first 16 bytes of HMAC-SHA-256
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define MAX_SALT_SIZE           1024
#define HEXCHARS                "0123456789abcdef"
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE               128
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif
#endif

static struct fmt_tests tests[] = {
	{"$eigrp$2$020500000000000000000000000000000000002a000200280002001000000001000000000000000000000000$0$x$1a42aaf8ebe2f766100ea1fa05a5fa55", "password12345"},
	{"$eigrp$2$020500000000000000000000000000000000002a000200280002001000000001000000000000000000000000$0$x$f29e7d44351d37e6fc71e2aacca63d28", "1234567812345"},
	{"$eigrp$2$020500000000000000000000000000000000002a000200280002001000000001000000000000000000000000$1$0001000c010001000000000f000400080500030000f5000c0000000400$560c87396267310978883da92c0cff90", "password12345"},
	{"$eigrp$2$020500000000000000000000000000000000002a000200280002001000000001000000000000000000000000$0$x$61f237e29d28538a372f01121f2cd12f", "123456789012345678901234567890"},
	{"$eigrp$2$0205000000000000000000000000000000000001000200280002001000000001000000000000000000000000$0$x$212acb1cb76b31a810a9752c5cf6f554", "ninja"}, // this one is for @digininja :-)
	{"$eigrp$3$020500000000000000000000000000000000000a00020038000300200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000c010001000000000f000400080f00020000f5000a000000020000$0$x$1$10.0.0.2$cff66484cea20c6f58f175f8c004fc6d73be72090e53429c2616309aca38d5f3", "password12345"},  // HMAC-SHA-256 hash
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static struct custom_salt {
	int length;
	int algo_type;
	int have_extra_salt;
	int extra_salt_length;
	unsigned char salt[MAX_SALT_SIZE];
	char ip[45 + 1];
	int ip_length;
	MD5_CTX prep_salt;
	unsigned char extra_salt[MAX_SALT_SIZE];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *ptrkeep;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;
	ptrkeep = xstrdup(ciphertext);
	p = &ptrkeep[TAG_LENGTH];

	if ((p = strtokm(p, "$")) == NULL)
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);

	if (res != 2 && res != 3)  // MD5 hashes + HMAC-SHA256 hashes
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL)	// salt
		goto err;
	if (strlen(p) > MAX_SALT_SIZE*2)
		goto err;
	if (!ishexlc(p))
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	// salt2 (or a junk field)
		goto err;
	if (res == 1) {
		// we only care about extra salt IF that number was a 1
		if (strlen(p) > MAX_SALT_SIZE*2)
			goto err;
		if (!ishexlc(p))
			goto err;
	}

	if ((p = strtokm(NULL, "$")) == NULL)	// binary hash (or IP)
		goto err;
	if (!strcmp(p, "1")) {	// this was an IP
		if ((p = strtokm(NULL, "$")) == NULL)	// IP
			goto err;
		// not doing too much IP validation. Length will have to do.
		// 5 char ip 'could' be 127.1  I know of no short IP. 1.1.1.1 is longer.
		if (strlen(p) < 5 || strlen(p) > sizeof(cur_salt->ip))
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)	// ok, now p is binary.
			goto err;
	}
	res = strlen(p);
	if (res != BINARY_SIZE * 2 &&  res != 32 * 2)
		goto err;
	if (!ishexlc(p))
		goto err;

	MEM_FREE(ptrkeep);
	return 1;
err:
	MEM_FREE(ptrkeep);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i, len;
	char *p, *q;

	memset(&cs, 0, SALT_SIZE);
	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	p = ciphertext;
	cs.algo_type = atoi(p);
	p = p + 2; // salt start
	q = strchr(p, '$');
	len = (q - p) / 2;
	cs.length = len;

	for (i = 0; i < len; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) |
			atoi16[ARCH_INDEX(p[2 * i + 1])];

	q = q + 1;
	cs.have_extra_salt = atoi(q);

	if (cs.have_extra_salt == 1) {
		p = q + 2;
		q = strchr(p, '$');
		cs.extra_salt_length = (q - p) / 2;
		for (i = 0; i < cs.extra_salt_length; i++)
			cs.extra_salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) |
				atoi16[ARCH_INDEX(p[2 * i + 1])];
	} else {
		/* skip over extra_salt */
		p = q + 2;
		q = strchr(p, '$');
	}

	/* dirty hack for HMAC-SHA-256 support */
	if (*q == '$' && *(q+1) == '1' && *(q+2) == '$') { /* IP destination field */
		p = q + 3;
		q = strchr(p, '$');
		cs.ip_length = q - p;
		strncpy(cs.ip, p, cs.ip_length);
	}

	/* Better do this once than 10 million times per second */
	if (cs.algo_type == 2) {
		MD5_Init(&cs.prep_salt);
		MD5_Update(&cs.prep_salt, cs.salt, cs.length);
	}

	return &cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static unsigned char zeropad[16] = {0};

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		MD5_CTX ctx;

		if (cur_salt->algo_type == 2) {
			memcpy(&ctx, &cur_salt->prep_salt, sizeof(MD5_CTX));
			MD5_Update(&ctx, saved_key[index], saved_len[index]);
			if (saved_len[index] < 16) {
				MD5_Update(&ctx, zeropad, 16 - saved_len[index]);
			}
			// do we have extra_salt?
			if (cur_salt->have_extra_salt) {
				MD5_Update(&ctx, cur_salt->extra_salt, cur_salt->extra_salt_length);
			}
			MD5_Final((unsigned char*)crypt_out[index], &ctx);
		} else {
			HMAC_SHA256_CTX hctx[1];
			unsigned char output[32];
			unsigned char buffer[1 + PLAINTEXT_LENGTH + 45 + 1] = { 0 }; // HMAC key ==> '\n' + password + IP address
			buffer[0] = '\n'; // WTF?
			memcpy(buffer + 1, saved_key[index], saved_len[index]);
			memcpy(buffer + 1 + saved_len[index], cur_salt->ip, cur_salt->ip_length);
			HMAC_SHA256_Init(hctx, buffer, 1 + saved_len[index] + cur_salt->ip_length);
			HMAC_SHA256_Update(hctx, cur_salt->salt, cur_salt->length);
			HMAC_SHA256_Final(output, hctx);
			memcpy((unsigned char*)crypt_out[index], output, BINARY_SIZE);
		}

	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
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

static void eigrp_set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_key[index], key,
			PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static unsigned int get_cost(void *salt)
{
	return (unsigned int)((struct custom_salt*)salt)->algo_type;
}

struct fmt_main fmt_eigrp = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"algorithm [2:MD5 3:HMAC-SHA-256]",
		},
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			get_cost,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		eigrp_set_key,
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
