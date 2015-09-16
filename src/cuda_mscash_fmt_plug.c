/*
 * This software is Copyright (c) 2011 Lukas Odzioba
 * <lukas dot odzioba at gmail dot com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 * Based on Alain Espinosa implementation http://openwall.info/wiki/john/MSCash
 */
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_mscash;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_mscash);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_mscash.h"
#include "cuda_common.h"
#include "unicode.h"
#include "memdbg.h"

#define FORMAT_LABEL		"mscash-cuda"
#define FORMAT_NAME		"MS Cache Hash (DCC)"
#define ALGORITHM_NAME		"MD4 CUDA (inefficient, development use only)"
#define MAX_CIPHERTEXT_LENGTH	(2 + 19*3 + 1 + 32)
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0

#define BINARY_ALIGN		sizeof(uint32_t)
#define SALT_ALIGN			sizeof(uint32_t)

static mscash_password *inbuffer;
static mscash_hash *outbuffer;
static mscash_salt currentsalt;

static struct fmt_tests tests[] = {
	{"ab60bdb4493822b175486810ac2abe63", "test2", {"test2"}},
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1"},
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1"},
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1"},
	{"176a4c2bd45ac73687676c2f09045353", "", {"root"}},	// nullstring password
	{"M$test3#14dd041848e12fc48c0aa7a416a4a00c", "test3"},
	{"M$test4#b945d24866af4b01a6d89b9d932a153c", "test4"},

	{"64cd29e36a8431a2b111378564a10631", "test1", {"TEST1"}},	// salt is lowercased before hashing
	{"290efa10307e36a79b3eebf2a6b29455", "okolada", {"nineteen_characters"}},	// max salt length
	{"b945d24866af4b01a6d89b9d932a153c", "test4", {"test4"}},
	{NULL}
};

extern void cuda_mscash(mscash_password *, mscash_hash *, mscash_salt *, int);

static void done(void)
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
	//Allocate memory for hashes and passwords
	inbuffer = (mscash_password *) mem_calloc(MAX_KEYS_PER_CRYPT,
	                                          sizeof(mscash_password));
	outbuffer =
	    (mscash_hash *) mem_alloc(MAX_KEYS_PER_CRYPT * sizeof(mscash_hash));
	check_mem_allocation(inbuffer, outbuffer);
	//Initialize CUDA
	cuda_init();

	if (pers_opts.target_enc == UTF_8) {
		self->params.plaintext_length *= 3;
		if (self->params.plaintext_length > 125)
			self->params.plaintext_length = 125;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	unsigned int i;
	unsigned int l;
	char insalt[3*19+1];
	UTF16 realsalt[21];
	int saltlen;

	if (strncmp(ciphertext, "M$", 2))
		return 0;

	l = strlen(ciphertext);
	if (l <= 32 || l > MAX_CIPHERTEXT_LENGTH)
		return 0;

	l -= 32;
	if(ciphertext[l-1]!='#')
		return 0;

	for (i = l; i < l + 32; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	// This is tricky: Max supported salt length is 19 characters of Unicode
	saltlen = enc_to_utf16(realsalt, 20, (UTF8*)strnzcpy(insalt, &ciphertext[2], l - 2), l - 3);
	if (saltlen < 0 || saltlen > 19) {
		static int warned = 0;

		if (!ldr_in_pot)
		if (!warned++)
			fprintf(stderr, "%s: One or more hashes rejected due to salt length limitation\n", FORMAT_LABEL);

		return 0;
	}

	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i = 0;
	for (; i < MAX_CIPHERTEXT_LENGTH && ciphertext[i]; i++)
		out[i] = ciphertext[i];
	out[i] = 0;
	// lowercase salt as well as hash, encoding-aware
	enc_strlwr(&out[2]);
	return out;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	int i;
	if (!strncmp(split_fields[1], "M$", 2) || !split_fields[0])
		return split_fields[1];
	if (!split_fields[0])
		return split_fields[1];
	// ONLY check, if this string split_fields[1], is ONLY a 32 byte hex string.
	for (i = 0; i < 32; i++)
		if (atoi16[ARCH_INDEX(split_fields[1][i])] == 0x7F)
			return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 4);
	sprintf (cp, "M$%s#%s", split_fields[0], split_fields[1]);
	if (valid(cp, self))
	{
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void *get_binary(char *ciphertext)
{
	static uint32_t binary[4];
	char *hash = strrchr(ciphertext, '#') + 1;
	int i;
	for (i = 0; i < 4; i++) {
		sscanf(hash + (8 * i), "%08x", &binary[i]);
		binary[i] = SWAP(binary[i]);
	}
	return binary;
}

static void *get_salt(char *ciphertext)
{
	static mscash_salt salt;
	UTF8 insalt[SALT_LENGTH + 1];
	char *pos = ciphertext + strlen(mscash_prefix);
	char *end = strrchr(ciphertext, '#');
	int length = 0;

	memset(&salt, 0, sizeof(salt));
	while (pos < end)
		insalt[length++] = *pos++;
	insalt[length] = 0;

	enc_to_utf16(salt.salt, SALT_LENGTH, insalt, length);
	salt.length = length;

	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, sizeof(mscash_salt));
}

static void set_key(char *key, int index)
{
	int length;

	length = enc_to_utf16(inbuffer[index].v,
	                      PLAINTEXT_LENGTH,
	                      (UTF8*)key,
	                      strlen(key));

	if (length < 0)
		length = strlen16(inbuffer[index].v);

	inbuffer[index].length = length;
}

static char *get_key(int index)
{
	UTF16 ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;

	memcpy(ret, inbuffer[index].v, 2 * length);
	ret[length] = 0;
	return (char*)utf16_to_enc(ret);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	cuda_mscash(inbuffer, outbuffer, &currentsalt, count);
	return count;
}

static int get_hash_0(int index)
{
	return outbuffer[index].v[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return outbuffer[index].v[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return outbuffer[index].v[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return outbuffer[index].v[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return outbuffer[index].v[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return outbuffer[index].v[0] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return outbuffer[index].v[0] & PH_MASK_6;
}


static int cmp_all(void *binary, int count)
{
	uint32_t i, b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	uint32_t i, *b = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (b[i] != outbuffer[index].v[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_cuda_mscash = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
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

#endif /* HAVE_CUDA */
