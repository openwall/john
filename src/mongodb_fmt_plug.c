/* Cracker for both MongoDB system and sniffed network hashes. Hacked together
 * during November of 2012 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * Based on https://github.com/cyberpunkych/attacking_mongodb
 *
 * Hash format for MongoDB system hashes: user:$mongodb$0$hash
 * Hash format for MongoDB network hashes: user:$mongodb$1$salt$hash
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted. */

#include "md5.h"
#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL		"mongodb"
#define FORMAT_NAME		"MongoDB system / network MD5"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests mongodb_tests[] = {
	{"$mongodb$0$sa$75692b1d11c072c6c79332e248c4f699", "sa"},
	{"$mongodb$1$sa$58d3229c83e3f87e$0c85e3f74adce5d037426791940c820a", "sa"},
	/* Ettercap generated test vectors */
	{"$mongodb$1$sa$10441db416a99ffc$797d7e18879446845f10ae9d519960b2", "longpassword"},
	{"$mongodb$1$longusername$86336266301fb552$1abe48bac6ad0bf567ab51b094f026a9", "longpassword"},
	/* Ettercap fixed salt MiTM attack generated test vectors */
	{"$mongodb$1$longusername$0000000000000000$53257e018399a241849cb04c70ba8daa", "longpassword"},
	{"$mongodb$1$longusername$0000000000000000$10290925d16d81e50db242c9f3572d91", "longpassword@12345678"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static struct custom_salt {
	int type;
	unsigned char salt[17];
	unsigned char username[128];
} *cur_salt;

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
	int type;

	if (strncmp(ciphertext, "$mongodb$", 9))
		return 0;
	if (!(ctcopy = strdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += 9;

	if (!(ptr = strtok(ctcopy, "$"))) /* type */
		goto error;
	type = atoi(ptr);
	if (type != 0 && type != 1)
		goto error;
	if (!(ptr = strtok(NULL, "$"))) /* username */
		goto error;
	if (strlen(ptr) > 127)
		goto error;
	if (type == 0) {
		if (!(ptr = strtok(NULL, "$"))) /* hash */
			goto error;
		if (strlen(ptr) != 32 || !ishex(ptr))
			goto error;
	} else {
		if (!(ptr = strtok(NULL, "$"))) /* salt */
			goto error;
		if (strlen(ptr) != 16 || !ishex(ptr))
			goto error;
		if (!(ptr = strtok(NULL, "$"))) /* hash */
			goto error;
		if (strlen(ptr) != 32 || !ishex(ptr))
			goto error;
	}

	MEM_FREE(keeptr);
	return 1;

error:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	ctcopy += 9;	/* skip over "$mongodb$*" */
	p = strtok(ctcopy, "$");
	cs.type = atoi(p);
	p = strtok(NULL, "$");
	strcpy((char*)cs.username, p);
	if (cs.type == 1) {
		p = strtok(NULL, "$");
		strcpy((char*)cs.salt, p);
	}
	MEM_FREE(keeptr);
	return (void *)&cs;
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

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		if (cur_salt->type == 0) {
			MD5_CTX ctx;
			MD5_Init(&ctx);
			MD5_Update(&ctx, cur_salt->username, strlen((char*)cur_salt->username));
			MD5_Update(&ctx, ":mongo:", 7);
			MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			MD5_Final((unsigned char*)crypt_out[index], &ctx);
		}
		else {
			unsigned char hexout[32];
			unsigned char out[32];
			MD5_CTX ctx;
			MD5_Init(&ctx);
			MD5_Update(&ctx, cur_salt->username, strlen((char*)cur_salt->username));
			MD5_Update(&ctx, ":mongo:", 7);
			MD5_Update(&ctx, saved_key[index], strlen(saved_key[index]));
			MD5_Final(out, &ctx);
			hex_encode(out, 16, hexout);
			MD5_Init(&ctx);
			MD5_Update(&ctx, cur_salt->salt, 16);
			MD5_Update(&ctx, cur_salt->username, strlen((char*)cur_salt->username));
			MD5_Update(&ctx, hexout, 32);
			MD5_Final((unsigned char*)crypt_out[index], &ctx);
		}
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
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

static void mongodb_set_key(char *key, int index)
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

struct fmt_main fmt_mongodb = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		mongodb_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
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
		mongodb_set_key,
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
