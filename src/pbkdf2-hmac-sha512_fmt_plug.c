/* This software is Copyright (c) 2012 Lukas Odzioba <ukasz@openwall.net>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Based on hmac-sha512 by magnum
 *
 * Minor fixes, format unification and OMP support done by Dhiru Kholia <dhiru@openwall.com>
 *
 * Fixed for supporting $ml$ "dave" format as well as GRUB native format by
 * magnum 2013. Note: We support a binary size of >512 bits (64 bytes / 128
 * chars of hex) but we currently do not calculate it even in cmp_exact(). The
 * chance for a 512-bit hash collision should be pretty dang slim.
 */

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

#define FORMAT_LABEL		"pbkdf2-hmac-sha512"
#define FORMAT_TAG		"$pbkdf2-hmac-sha512$"
#define FORMAT_TAG2		"$ml$"
#define FORMAT_TAG3		"grub.pbkdf2.sha512."
#define FORMAT_NAME		"PBKDF2-HMAC-SHA512 GRUB2 / OS X 10.8"
#if ARCH_BITS >= 64
#define ALGORITHM_NAME		"64/" ARCH_BITS_STR " " SHA2_LIB
#else
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR " " SHA2_LIB
#endif
#define BINARY_SIZE		64
#define MAX_CIPHERTEXT_LENGTH	1024 /* Bump this and code will adopt */
#define MAX_BINARY_SIZE		(4*64) /* Bump this and code will adopt */
#define MAX_SALT_SIZE		128 /* Bump this and code will adopt */
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define KEYS_PER_CRYPT		1
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1
#endif

#define PAD_SIZE		128
#define PLAINTEXT_LENGTH	125

#define MIN(a,b)		(((a)<(b))?(a):(b))
#define MAX(a,b)		(((a)>(b))?(a):(b))

static struct fmt_tests tests[] = {
	/* OS X 10.8 Mountain Lion hashes, "dave" format */
	{"$ml$23923$c3fa2e153466f7619286024fe7d812d0a8ae836295f84b9133ccc65456519fc3$ccb903ee691ade6d5dee9b3c6931ebed6ddbb1348f1b26c21add8ba0d45f27e61e97c0b80d9a18020944bb78f1ebda6fdd79c5cf08a12c80522caf987c287b6d", "openwall"},
	{"$ml$37174$ef768765ba15907760b71789fe62436e3584dfadbbf1eb8bf98673b60ff4e12b$294d42f6e0c3a93d598340bfb256efd630b53f32173c2b0d278eafab3753c10ec57b7d66e0fa79be3b80b3693e515cdd06e9e9d26d665b830159dcae152ad156", "m\xC3\xBCller"},
	{"$ml$24213$db9168b655339be3ff8936d2cf3cb573bdf7d40afd9a17fca439a0fae1375960$471a868524d66d995c6a8b7a0d27bbbc1af0c203f1ac31e7ceb2fde92f94997b887b38131ac2b543d285674dce639560997136c9af91916a2865ba960762196f", "applecrap"},
	{"$ml$37313$189dce2ede21e297a8884d0a33e4431107e3e40866f3c493e5f9506c2bd2fe44$948010870e110a6d185494799552d8cf30b0203c6706ab06e6270bf0ac17d496d820c5a75c12caf9070051f34acd2a2911bb38b202eebd4413e571e4fbff883e75f35c36c88a2b42a4fb521a97953438c72b2182fd9c5bba902395766e703b52b9aaa3895770d3cebffbee05076d9110ebb9f0342692a238174655b1acdce1c0", "crackable4us"},
	/* GRUB hash, GRUB format */
	{"grub.pbkdf2.sha512.10000.4483972AD2C52E1F590B3E2260795FDA9CA0B07B96FF492814CA9775F08C4B59CD1707F10B269E09B61B1E2D11729BCA8D62B7827B25B093EC58C4C1EAC23137.DF4FCB5DD91340D6D31E33423E4210AD47C7A4DF9FA16F401663BF288C20BF973530866178FE6D134256E4DBEFBD984B652332EED3ACAED834FEA7B73CAE851D", "password"},
	/* Generic format made up by us */
	{"$pbkdf2-hmac-sha512$10000.82DBAB96E072834D1F725DB9ADED51E703F1D449E77D01F6BE65147A765C997D8865A1F1AB50856AA3B08D25A5602FE538AD0757B8CA2933FE8CA9E7601B3FBF.859D65960E6D05C6858F3D63FA35C6ADFC456637B4A0A90F6AFA7D8E217CE2D3DFDC56C8DEACA217F0864AE1EFB4A09B00EB84CF9E4A2723534F34E26A279193", "openwall"},
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
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int ishex(char *q)
{
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;
	size_t len;

	if (!strncmp(ciphertext, FORMAT_TAG, sizeof(FORMAT_TAG) - 1))
		ciphertext += sizeof(FORMAT_TAG) - 1;
	else if (!strncmp(ciphertext, FORMAT_TAG2, sizeof(FORMAT_TAG2) - 1))
		ciphertext += sizeof(FORMAT_TAG2) - 1;
	else if (!strncmp(ciphertext, FORMAT_TAG3, sizeof(FORMAT_TAG3) - 1))
		ciphertext += sizeof(FORMAT_TAG3) - 1;
	else
		return 0;
	if (strlen(ciphertext) > MAX_CIPHERTEXT_LENGTH)
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	if (!(ptr = strtok(ctcopy, ".$")))
		goto error;
	if (!atoi(ptr))
		goto error;
	if (!(ptr = strtok(NULL, ".$")))
		goto error;
	len = strlen(ptr); // salt length
	if (len > 2 * MAX_SALT_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtok(NULL, ".$")))
		goto error;
	len = strlen(ptr); // binary length
	if (len < BINARY_SIZE || len > MAX_BINARY_SIZE || len & 1)
		goto error;
	if (!ishex(ptr))
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

static char *split(char *ciphertext, int index)
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
	cs.rounds = atoi(ciphertext);
	delim = strchr(ciphertext, '.') ? '.' : '$';
	ciphertext = strchr(ciphertext, delim) + 1;
	p = strchr(ciphertext, delim);
	saltlen = 0;
	while (ciphertext < p) {	/** extract salt **/
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
		ARCH_WORD dummy;
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
	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void hmac_sha512(uint8_t * pass, uint8_t passlen, uint8_t * salt,
                        uint8_t saltlen, uint32_t add, uint64_t * ret)
{
	uint8_t i, ipad[PAD_SIZE], opad[PAD_SIZE];
	SHA512_CTX ctx;
	memset(ipad, 0x36, PAD_SIZE);
	memset(opad, 0x5c, PAD_SIZE);

	for (i = 0; i < passlen; i++) {
		ipad[i] ^= pass[i];
		opad[i] ^= pass[i];
	}

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, ipad, PAD_SIZE);
	SHA512_Update(&ctx, salt, saltlen);
	if (add > 0) {
#if ARCH_LITTLE_ENDIAN
		add = JOHNSWAP(add);
#endif
		SHA512_Update(&ctx, &add, 4);
	}
	SHA512_Final((uint8_t *) ret, &ctx);

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, opad, PAD_SIZE);
	SHA512_Update(&ctx, (uint8_t *) ret, BINARY_SIZE);
	SHA512_Final((uint8_t *) ret, &ctx);
}


static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (index = 0; index < count; index++)
#endif
	{
		int i, j, l;
		uint64_t tmp[BINARY_SIZE];
		uint64_t key[BINARY_SIZE];

		l = strlen(saved_key[index]);
		hmac_sha512((unsigned char*)saved_key[index], l,
		            (uint8_t *) cur_salt->salt, cur_salt->length,
		            1, tmp);
		memcpy(key, tmp, BINARY_SIZE);

		for (i = 1; i < cur_salt->rounds; i++) {
			hmac_sha512((unsigned char*)saved_key[index], l,
			            (uint8_t *) tmp, BINARY_SIZE, 0, tmp);
			for (j = 0; j < 8; j++)
				key[j] ^= tmp[j];
		}
		memcpy((unsigned char*)crypt_out[index], key, BINARY_SIZE);
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for (; index < count; index++)
#endif
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
	int i = 0, j, l, result;
	uint64_t tmp[BINARY_SIZE];
	uint64_t key[BINARY_SIZE];
	char *p;
	int len, loops;
	char delim;
	char *binary, *crypt;

	delim = strchr(source, '.') ? '.' : '$';
	p = strrchr(source, delim) + 1;
	len = strlen(p) / 2;

	if (len == 64) return 1;

	//printf("Full test of \"%s\"...\n", saved_key[index]);
	binary = mem_alloc(len);
	crypt = mem_alloc(len);

	while (*p) {
		binary[i++] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	l = strlen(saved_key[index]);
	for (loops = 0; loops < (len + 63) / 64; loops++) {
		hmac_sha512((unsigned char*)saved_key[index], l,
		            (uint8_t *) cur_salt->salt, cur_salt->length,
		            loops + 1, tmp);
		memcpy(key, tmp, BINARY_SIZE);

		for (i = 1; i < cur_salt->rounds; i++) {
			hmac_sha512((unsigned char*)saved_key[index], l,
			            (uint8_t *) tmp, BINARY_SIZE, 0, tmp);
			for (j = 0; j < 8; j++)
				key[j] ^= tmp[j];
		}
		memcpy((unsigned char*)&crypt[64 * loops], key, BINARY_SIZE);
	}
	//dump_stuff_msg("in ", binary, len);
	//dump_stuff_msg("out", crypt, len);
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
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_pbkdf2_hmac_sha512 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(ARCH_WORD_32),
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		sizeof(ARCH_WORD),
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
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
