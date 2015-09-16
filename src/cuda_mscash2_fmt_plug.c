/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_mscash2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_mscash2);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "unicode.h"
#include "cuda_mscash2.h"
#include "cuda_common.h"
#include "loader.h"
#include "memdbg.h"

#define FORMAT_LABEL		"mscash2-cuda"
#define FORMAT_NAME		"MS Cache Hash 2 (DCC2)"
#define MAX_CIPHERTEXT_LENGTH	(8 + 5 + 3 * MAX_SALT_LENGTH + 32)
#define ALGORITHM_NAME		"PBKDF2-SHA1 CUDA"
#define MAX_SALT_LENGTH		19

#define BINARY_ALIGN		sizeof(uint32_t)
#define SALT_ALIGN			sizeof(uint32_t)

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
//#define _MSCASH2_DEBUG

static mscash2_password *inbuffer;
static mscash2_hash *outbuffer;
static mscash2_salt currentsalt;

static struct fmt_tests tests[] = {
	{"c0cbe0313a861062e29f92ede58f9b36", "", {"bin"}},	// nullstring password
	{"$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test1"},
	{"$DCC2$10240#Joe#e09b38f84ab0be586b730baf61781e30", "qerwt"},
	{"$DCC2$10240#Joe#6432f517a900b3fc34ffe57f0f346e16", "12345"},
	{"87136ae0a18b2dafe4a41d555425b2ed", "w00t", {"nineteen_characters"}},	// max salt length
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"}},
//unsupported salts lengths
//      {"cfc6a1e33eb36c3d4f84e4c2606623d2", "longpassword", {"twentyXXX_characters"} },
//      {"99ff74cea552799da8769d30b2684bee", "longpassword", {"twentyoneX_characters"} },
//      {"0a721bdc92f27d7fb23b87a445ec562f", "longpassword", {"twentytwoXX_characters"} },
	{"$DCC2$10240#TEST2#c6758e5be7fc943d00b97972a8a97620", "test2"},	// salt is lowercased before hashing
	{"$DCC2$10240#test3#360e51304a2d383ea33467ab0b639cc4", "test3"},
	{"$DCC2$10240#test4#6f79ee93518306f071c47185998566ae", "test4"},
	// Non-standard iterations count
	{"$DCC2$10000#Twelve_chars#54236c670e185043c8016006c001e982", "magnum"},
	{NULL}
};

extern void mscash2_gpu(mscash2_password *, mscash2_hash *, mscash2_salt *,
                        int count);

static void done(void)
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
	//Allocate memory for hashes and passwords
	inbuffer =
		(mscash2_password *) mem_calloc(MAX_KEYS_PER_CRYPT,
		                                sizeof(mscash2_password));
	outbuffer =
	    (mscash2_hash *) mem_alloc(MAX_KEYS_PER_CRYPT*sizeof(mscash2_hash));
	check_mem_allocation(inbuffer, outbuffer);
	//Initialize CUDA
	cuda_init();

	if (pers_opts.target_enc == UTF_8) {
		self->params.plaintext_length *= 3;
		if (self->params.plaintext_length > 125)
			self->params.plaintext_length = 125;
	}
}

extern int mscash2_valid(char *, int, struct fmt_main *);
extern char * mscash2_prepare(char **, struct fmt_main *);
extern char * mscash2_split(char *, int, struct fmt_main *);

static int valid(char *ciphertext, struct fmt_main *self)
{
	return mscash2_valid(ciphertext, MAX_SALT_LENGTH, self);
}

static void *get_binary(char *ciphertext)
{
	static uint32_t binary[4];
	char *hash = strrchr(ciphertext, '#') + 1;
	int i;
	if (hash == NULL)
		return binary;
	for (i = 0; i < 4; i++) {
		sscanf(hash + (8 * i), "%08x", &binary[i]);
		binary[i] = SWAP(binary[i]);
	}
	return binary;
}

static void *get_salt(char *ciphertext)
{
	static mscash2_salt salt;
	UTF8 insalt[3 * MAX_SALT_LENGTH + 1];
	char *pos = ciphertext + strlen(mscash2_prefix);
	char *end = strrchr(ciphertext, '#');
	int length = 0;

	memset(&salt, 0, sizeof(salt));
	salt.rounds = DEFAULT_ROUNDS;
	sscanf(pos, "%u", &salt.rounds);
	pos = strchr(ciphertext, '#') + 1 ;
	while (pos < end)
		insalt[length++] = *pos++;
	insalt[length] = 0;

	salt.length = enc_to_utf16(salt.salt, MAX_SALT_LENGTH, insalt, length);

#ifdef _MSCASH2_DEBUG
	printf("salt=%s\n", utf16_to_enc(salt.salt));
	printf("salt len=%d\n", salt.length);
	printf("salt rounds=%d\n", salt.rounds);
#endif
	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, sizeof(mscash2_salt));
}

static void set_key(char *key, int index)
{
	int length;

#ifdef _MSCASH2_DEBUG
	printf("set_key(%d) = [%s]\n", index, key);
#endif
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

	mscash2_gpu(inbuffer, outbuffer, &currentsalt, count);
	return count;
}

static int binary_hash_0(void *binary)
{
#ifdef _MSCASH2_DEBUG
	puts("binary");
	uint32_t i, *b = binary;
	for (i = 0; i < 4; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	return (((uint32_t *) binary)[0] & PH_MASK_0);
}

static int get_hash_0(int index)
{
#ifdef _MSCASH2_DEBUG
	int i;
	puts("get_hash");
	for (i = 0; i < 4; i++)
		printf("%08x ", outbuffer[index].v[i]);
	puts("");
#endif
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

struct fmt_main fmt_cuda_mscash2 = {
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
		mscash2_prepare,
		valid,
		mscash2_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
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
