/* This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Based on hmac-sha512 by magnum
 *
 * Minor fixes, format unification and OMP support done by Dhiru Kholia
 * <dhiru@openwall.com>
 *
 * Fixed for supporting $ml$ "dave" format as well as GRUB native format by
 * magnum 2013. Note: We support a binary size of >512 bits (64 bytes / 128
 * chars of hex) but we currently do not calculate it even in cmp_exact(). The
 * chance for a 512-bit hash collision should be pretty dang slim.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_pbkdf2_hmac_sha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_pbkdf2_hmac_sha512);
#else

#include <ctype.h>
#include <string.h>
#include <assert.h>

#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"
#include "sha2.h"
#include "johnswap.h"
#include "stdint.h"
#define PBKDF2_HMAC_SHA512_ALSO_INCLUDE_CTX
#include "pbkdf2_hmac_sha512.h"

#define FORMAT_LABEL            "PBKDF2-HMAC-SHA512"
#define FORMAT_TAG              "$pbkdf2-hmac-sha512$"
#define FORMAT_TAG2             "$ml$"
#define FORMAT_TAG3             "grub.pbkdf2.sha512."
#define FORMAT_NAME             "GRUB2 / OS X 10.8+"

#ifdef SIMD_COEF_64
#define ALGORITHM_NAME		"PBKDF2-SHA512 " SHA512_ALGORITHM_NAME
#else
#if ARCH_BITS >= 64
#define ALGORITHM_NAME          "PBKDF2-SHA512 64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME          "PBKDF2-SHA512 32/" ARCH_BITS_STR " " SHA2_LIB
#endif
#endif

#define BINARY_SIZE             64
#define MAX_CIPHERTEXT_LENGTH   1024 /* Bump this and code will adopt */
#define MAX_BINARY_SIZE         (4*64) /* Bump this and code will adopt */
#define MAX_SALT_SIZE           128 /* Bump this and code will adopt */
#define SALT_SIZE               sizeof(struct custom_salt)
#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA512
#define MAX_KEYS_PER_CRYPT	SSE_GROUP_SZ_SHA512
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        -1
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE               1
#endif
#endif

#include "memdbg.h"

#define PAD_SIZE                128
#define PLAINTEXT_LENGTH        125

static struct fmt_tests tests[] = {
	{"$pbkdf2-hmac-sha512$1000.6b635263736c70346869307a304b5276.80cf814855f2299103a6084366e41d7e14f9894b05ed77fa19881d28f06cde18da9ab44972cd00496843371ce922c70e64f3862b036b59b581fe32fc4408fe49", "magnum"},
	{"$pbkdf2-hmac-sha512$1000.55636d4344326e537236437677674a46.e7a60f0cf216c40b31cc6fc34d6a0093c978bbb49d6934dbca286b63fe28473bd3683917807173aef122e5a6bc5c7b4178ed6225f414c994df46013754a52177", "Ripper"},
	/* OS X 10.8 Mountain Lion hashes, "dave" format */
	{"$ml$23923$c3fa2e153466f7619286024fe7d812d0a8ae836295f84b9133ccc65456519fc3$ccb903ee691ade6d5dee9b3c6931ebed6ddbb1348f1b26c21add8ba0d45f27e61e97c0b80d9a18020944bb78f1ebda6fdd79c5cf08a12c80522caf987c287b6d", "openwall"},
	{"$ml$37174$ef768765ba15907760b71789fe62436e3584dfadbbf1eb8bf98673b60ff4e12b$294d42f6e0c3a93d598340bfb256efd630b53f32173c2b0d278eafab3753c10ec57b7d66e0fa79be3b80b3693e515cdd06e9e9d26d665b830159dcae152ad156", "m\xC3\xBCller"},
	{"$ml$24213$db9168b655339be3ff8936d2cf3cb573bdf7d40afd9a17fca439a0fae1375960$471a868524d66d995c6a8b7a0d27bbbc1af0c203f1ac31e7ceb2fde92f94997b887b38131ac2b543d285674dce639560997136c9af91916a2865ba960762196f", "applecrap"},
	{"$ml$37313$189dce2ede21e297a8884d0a33e4431107e3e40866f3c493e5f9506c2bd2fe44$948010870e110a6d185494799552d8cf30b0203c6706ab06e6270bf0ac17d496d820c5a75c12caf9070051f34acd2a2911bb38b202eebd4413e571e4fbff883e75f35c36c88a2b42a4fb521a97953438c72b2182fd9c5bba902395766e703b52b9aaa3895770d3cebffbee05076d9110ebb9f0342692a238174655b1acdce1c0", "crackable4us"},
	/* GRUB hash, GRUB format */
	{"grub.pbkdf2.sha512.10000.4483972AD2C52E1F590B3E2260795FDA9CA0B07B96FF492814CA9775F08C4B59CD1707F10B269E09B61B1E2D11729BCA8D62B7827B25B093EC58C4C1EAC23137.DF4FCB5DD91340D6D31E33423E4210AD47C7A4DF9FA16F401663BF288C20BF973530866178FE6D134256E4DBEFBD984B652332EED3ACAED834FEA7B73CAE851D", "password"},
	/* Canonical format */
	{"$pbkdf2-hmac-sha512$10000.82dbab96e072834d1f725db9aded51e703f1d449e77d01f6be65147a765c997d8865a1f1ab50856aa3b08d25a5602fe538ad0757b8ca2933fe8ca9e7601b3fbf.859d65960e6d05c6858f3d63fa35c6adfc456637b4a0a90f6afa7d8e217ce2d3dfdc56c8deaca217f0864ae1efb4a09b00eb84cf9e4a2723534f34e26a279193", "openwall"},
	/* max length password (and longer salt) made by pass_gen.pl */
	{"$pbkdf2-hmac-sha512$56789.3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738.c4ac265e1b5d30694d04454e88f3f363a401aa82c7936d08d6bfc0751bc3e395b38422116665feecade927e7fa339d60022796f1354b064a4dc3c5304adf102a","12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	{"$pbkdf2-hmac-sha512$10000.2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e.cd9f205b20c3cc9699b1304d02cfa4dd2f69adda583402e99d1102911b14519653f4d2d09d0c8576d745ec9fa14888e0b3f32b254bb4d80aad2bd8b0c433e56d", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"},
	{NULL}
};

static struct custom_salt {
	uint8_t length;
	uint8_t salt[MAX_SALT_SIZE];
	uint32_t rounds;
} *cur_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
	        self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
	        self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	size_t len;

	if (strncmp(ciphertext, FORMAT_TAG, sizeof(FORMAT_TAG) - 1))
		return 0;
	if (strlen(ciphertext) > MAX_CIPHERTEXT_LENGTH)
		return 0;
	ciphertext += sizeof(FORMAT_TAG) - 1;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtokm(ctcopy, ".")))
		goto error;
	if (!isdecu(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, ".")))
		goto error;
	len = strlen(ptr); // salt length
	if (len > 2 * MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, ".")))
		goto error;
	len = strlen(ptr); // binary length
	if (len < BINARY_SIZE || len > MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	ptr = strtokm(NULL, ".");
	if (ptr)
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

/* This converts any input format to the canonical $pbkdf2-hmac-sha512$ */
static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i;

	if (!*split_fields[1])
		return split_fields[1];

	/* Unify format */
	if (!strncmp(split_fields[1], FORMAT_TAG, sizeof(FORMAT_TAG)-1))
		i = sizeof(FORMAT_TAG) - 1;
	else if (!strncmp(split_fields[1], FORMAT_TAG2, sizeof(FORMAT_TAG2)-1))
		i = sizeof(FORMAT_TAG2) - 1;
	else if (!strncmp(split_fields[1], FORMAT_TAG3, sizeof(FORMAT_TAG3)-1))
		i = sizeof(FORMAT_TAG3) - 1;
	else
		return split_fields[1];

	strcpy(out, FORMAT_TAG);
	strnzcpy(&out[sizeof(FORMAT_TAG)-1], &split_fields[1][i], sizeof(out)-(sizeof(FORMAT_TAG)));

	if (!strncmp(split_fields[1], FORMAT_TAG2, sizeof(FORMAT_TAG2) - 1))
		for (i = sizeof(FORMAT_TAG); out[i]; i++)
			if (out[i] == '$')
				out[i] = '.';

	if (valid(out, self))
		return out;
	else
		return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];

	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);
	return out;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *p;
	int saltlen;
	char delim;

	if (!strncmp(ciphertext, FORMAT_TAG, sizeof(FORMAT_TAG) - 1))
		ciphertext += sizeof(FORMAT_TAG) - 1;
	else if (!strncmp(ciphertext, FORMAT_TAG2, sizeof(FORMAT_TAG2) - 1))
		ciphertext += sizeof(FORMAT_TAG2) - 1;
	else if (!strncmp(ciphertext, FORMAT_TAG3, sizeof(FORMAT_TAG3) - 1))
		ciphertext += sizeof(FORMAT_TAG3) - 1;
	else
		error(); /* Can't happen - caught in valid() */
	cs.rounds = atou(ciphertext);
	delim = strchr(ciphertext, '.') ? '.' : '$';
	ciphertext = strchr(ciphertext, delim) + 1;
	p = strchr(ciphertext, delim);
	saltlen = 0;
	while (ciphertext < p) {        /** extract salt **/
		cs.salt[saltlen++] =
			atoi16[ARCH_INDEX(ciphertext[0])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[1])];
		ciphertext += 2;
	}
	cs.length = saltlen;

	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[MAX_BINARY_SIZE];
		ARCH_WORD_64 dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i, len;
	char delim;

	delim = strchr(ciphertext, '.') ? '.' : '$';
	p = strrchr(ciphertext, delim) + 1;
	len = strlen(p) / 2;
	for (i = 0; i < len && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < len/sizeof(ARCH_WORD_64); ++i) {
		((ARCH_WORD_64*)out)[i] = JOHNSWAP64(((ARCH_WORD_64*)out)[i]);
	}
#endif
	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
#ifdef SSE_GROUP_SZ_SHA512
		int lens[SSE_GROUP_SZ_SHA512], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA512];
		union {
			ARCH_WORD_32 *pout[SSE_GROUP_SZ_SHA512];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA512; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = crypt_out[index+i];
		}
		pbkdf2_sha512_sse((const unsigned char **)pin, lens, cur_salt->salt, cur_salt->length, cur_salt->rounds, &(x.poutc), BINARY_SIZE, 0);
#else
		pbkdf2_sha512((const unsigned char*)(saved_key[index]), strlen(saved_key[index]),
			cur_salt->salt, cur_salt->length,
			cur_salt->rounds, (unsigned char*)crypt_out[index], BINARY_SIZE, 0);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (!memcmp(binary, crypt_out[index], ARCH_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

/* Check the FULL binary, just for good measure. There is no chance we'll
   have a false positive here but this function is not performance sensitive. */
static int cmp_exact(char *source, int index)
{
	int i = 0, len, result;
	char *p;
	char delim;
	unsigned char *binary, *crypt;

	delim = strchr(source, '.') ? '.' : '$';
	p = strrchr(source, delim) + 1;
	len = strlen(p) / 2;

	if (len == BINARY_SIZE) return 1;

	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#if !ARCH_LITTLE_ENDIAN
	for (i = 0; i < len/sizeof(ARCH_WORD_64); ++i) {
		((ARCH_WORD_64*)binary)[i] = JOHNSWAP64(((ARCH_WORD_64*)binary)[i]);
	}
#endif
	pbkdf2_sha512((const unsigned char*)(saved_key[index]), strlen(saved_key[index]),
			cur_salt->salt, cur_salt->length,
			cur_salt->rounds, crypt, len, 0);
	result = !memcmp(binary, crypt, len);
	MEM_FREE(binary);
	MEM_FREE(crypt);
	if (!result)
		fprintf(stderr, "\n%s: Warning: Partial match for '%s'.\n"
		        "This is a bug or a malformed input line of:\n%s\n",
		        FORMAT_LABEL, saved_key[index], source);
	return result;
}

static void set_key(char *key, int index)
{
	int saved_len = strlen(key);
	if (saved_len > PLAINTEXT_LENGTH)
		saved_len = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_len);
	saved_key[index][saved_len] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->rounds;
}
#endif

struct fmt_main fmt_pbkdf2_hmac_sha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		sizeof(ARCH_WORD_32),
		SALT_SIZE,
		sizeof(ARCH_WORD),
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
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
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
