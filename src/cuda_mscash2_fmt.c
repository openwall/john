/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on S3nf implementation http://openwall.info/wiki/john/MSCash2
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "unicode.h"
#include "cuda_mscash2.h"
#include "cuda_common.h"

#define FORMAT_LABEL		"mscash2-cuda"
#define FORMAT_NAME		"M$ Cache Hash 2 (DCC2) PBKDF2-HMAC-SHA-1"
#define MAX_CIPHERTEXT_LENGTH    (8+5+19+32)
#define ALGORITHM_NAME		"CUDA"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
//#define _MSCASH2_DEBUG

static mscash2_password *inbuffer;
static mscash2_hash *outbuffer;
static mscash2_salt currentsalt;

static struct fmt_tests tests[] = {
	{"$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test1"},
	{"$DCC2$10240#Joe#e09b38f84ab0be586b730baf61781e30", "qerwt"},
	{"$DCC2$10240#Joe#6432f517a900b3fc34ffe57f0f346e16", "12345"},
	{"c0cbe0313a861062e29f92ede58f9b36", "", {"bin"}},	// nullstring password
	{"87136ae0a18b2dafe4a41d555425b2ed", "w00t", {"nineteen_characters"}},	// max salt length
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"}},
//unsupported salts lengths
//      {"cfc6a1e33eb36c3d4f84e4c2606623d2", "longpassword", {"twentyXXX_characters"} },
//      {"99ff74cea552799da8769d30b2684bee", "longpassword", {"twentyoneX_characters"} },
//      {"0a721bdc92f27d7fb23b87a445ec562f", "longpassword", {"twentytwoXX_characters"} },
	{"$DCC2$10240#TEST2#c6758e5be7fc943d00b97972a8a97620", "test2"},	// salt is lowercased before hashing
	{"$DCC2$10240#test3#360e51304a2d383ea33467ab0b639cc4", "test3"},
	{"$DCC2$10240#test4#6f79ee93518306f071c47185998566ae", "test4"},

	{NULL}
};

extern void mscash2_gpu(mscash2_password *, mscash2_hash *, mscash2_salt *);

static void cleanup()
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
	//Alocate memory for hashes and passwords
	inbuffer =
	    (mscash2_password *) calloc(MAX_KEYS_PER_CRYPT,
	    sizeof(mscash2_password));
	outbuffer =
	    (mscash2_hash *) malloc(sizeof(mscash2_hash) * MAX_KEYS_PER_CRYPT);
	check_mem_allocation(inbuffer, outbuffer);
	atexit(cleanup);
	//Initialize CUDA
	cuda_init(cuda_gpu_id);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
#ifdef _MSCASH2_DEBUG
	printf("valid(%s)\n", ciphertext);
#endif
	int i, l = strlen(ciphertext), saltlength = 0;
	if (strncmp(ciphertext, mscash2_prefix, strlen(mscash2_prefix)) != 0)
		return 0;
	if (l <= 32 || l > MAX_CIPHERTEXT_LENGTH)
		return 0;
	l -= 32;
	if (ciphertext[l - 1] != '#')
		return 0;
	for (i = l; i < l + 32; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	i = 6;
	while (ciphertext[i] && ciphertext[i] != '#')
		i++;
	i++;
	while (ciphertext[i] && ciphertext[i] != '#')
		i++, saltlength++;
	if (saltlength < 0 || saltlength > 19) {
		static int warned = 0;
		if (warned++ == 1)
			fprintf(stderr,
			    "Note: One or more hashes rejected due to salt length limitation\n");
		return 0;
	}

	sscanf(&ciphertext[6], "%d", &i);
	if (i >= 1 << 16)
		return 0;
	return 1;
}

static char *split(char *ciphertext, int index)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i = 0;
	for (; ciphertext[i] && i < MAX_CIPHERTEXT_LENGTH; i++)
		out[i] = ciphertext[i];
	out[i] = 0;
	// lowercase salt as well as hash, encoding-aware
	enc_strlwr(&out[6]);
	return out;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	int i;
	if (!strncmp(split_fields[1], "$DCC2$", 6)) {
		if (valid(split_fields[1], self))
			return split_fields[1];
		// see if this is a form $DCC2$salt#hash.  If so, make it $DCC2$10240#salt#hash and retest (insert 10240# into the line).
		cp = mem_alloc(strlen(split_fields[1]) + 7);
		sprintf(cp, "$DCC2$10240#%s", &(split_fields[1][6]));
		if (valid(cp, self)) {
			char *cipher = str_alloc_copy(cp);
			MEM_FREE(cp);
			return cipher;
		}
		return split_fields[1];
	}
	if (!split_fields[0])
		return split_fields[1];
	// ONLY check, if this string split_fields[1], is ONLY a 32 byte hex string.
	for (i = 0; i < 32; i++)
		if (atoi16[ARCH_INDEX(split_fields[1][i])] == 0x7F)
			return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 14);
	sprintf(cp, "$DCC2$10240#%s#%s", split_fields[0], split_fields[1]);
	if (valid(cp, self)) {
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void *binary(char *ciphertext)
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

static void *salt(char *ciphertext)
{
	static mscash2_salt salt;
	char *pos = ciphertext + strlen(mscash2_prefix);
	int length = 0;
	memset(&salt, 0, sizeof(salt));
	salt.rounds = DEFAULT_ROUNDS;
	sscanf(pos, "%d", &salt.rounds);
	while (*pos++ != '#');
	while (*pos != '#') {
		if (length == 19)
			return NULL;
		salt.salt[length++] = *pos++;
	}
	salt.length = length;
#ifdef _MSCASH2_DEBUG
	int i;
	printf("salt=");
	for (i = 0; i < salt.length; i++)
		putchar(salt.salt[i]);
	puts("");
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
#ifdef _MSCASH2_DEBUG
	printf("set_key(%d) = [%s]\n", index, key);
#endif
	uint8_t length = strlen(key);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, MIN(length, PLAINTEXT_LENGTH));
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;
	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static void crypt_all(int count)
{
	mscash2_gpu(inbuffer, outbuffer, &currentsalt);
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
	return (((uint32_t *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((uint32_t *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((uint32_t *) binary)[0] & 0x7ffffff;
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
	return outbuffer[index].v[0] & 0xf;
}

static int get_hash_1(int index)
{
	return outbuffer[index].v[0] & 0xff;
}

static int get_hash_2(int index)
{
	return outbuffer[index].v[0] & 0xfff;
}

static int get_hash_3(int index)
{
	return outbuffer[index].v[0] & 0xffff;
}

static int get_hash_4(int index)
{
	return outbuffer[index].v[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	return outbuffer[index].v[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	return outbuffer[index].v[0] & 0x7ffffff;
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

static int cmp_exact(char *source, int count)
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
		    PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    SALT_SIZE,
		    MIN_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
		    FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE,
		    tests
	},{
		    init,
		    prepare,
		    valid,
		    split,
		    binary,
		    salt,
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
