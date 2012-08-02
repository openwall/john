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
#define MAX_CIPHERTEXT_LENGTH    (7+19+32)
#define ALGORITHM_NAME		"CUDA, unreliable, may miss guesses"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
//#define _MSCASH2_DEBUG

static mscash2_password *inbuffer;
static mscash2_hash *outbuffer;
static mscash2_salt currentsalt;

static struct fmt_tests tests[] = {
	{"$DCC2$test#a86012faf7d88d1fc037a69764a92cac", "password"},
	{"$DCC2$test#a86012faf7d88d1fc037a69764a92cac", "password"},
	{"$DCC2$#59137848828d14b1fca295a5032b52a1", "a" },                                   //Empty Salt
	{"$DCC2$administrator#a150f71752b5d605ef0b2a1e98945611","a"},
	{"$DCC2$administrator#c14eb8279e4233ec14e9d393637b65e2","ab"},
	{"$DCC2$administrator#8ce9c0279b4e6f226f52d559f9c2c5f3","abc"},
	{"$DCC2$administrator#2fc788d09fad7e26a92d12356fa44bdf","abcd"},
	{"$DCC2$administrator#6aa19842ffea11f0f0c89f8ca8d245bd","abcde"},
	{"$DCC2$test#a86012faf7d88d1fc037a69764a92cac", "password"},
	{"$DCC2$test3#360e51304a2d383ea33467ab0b639cc4", "test3" },
	{"$DCC2$test4#6f79ee93518306f071c47185998566ae", "test4" },
	{"$DCC2$january#26b5495b21f9ad58255d99b5e117abe2", "verylongpassword" },
	{"$DCC2$february#469375e08b5770b989aa2f0d371195ff", "(##)(&#*%%" },
	{"$DCC2$TEST2#c6758e5be7fc943d00b97972a8a97620", "test2" },   // salt is lowercased before hashing
	{"$DCC2$john#ef9a549b7077f12143c18aecb8487d68","w00t"},

	//{"$DCC2$administrator#56f8c24c5a914299db41f70e9b43f36d", "w00t" },
	//{"$DCC2$AdMiNiStRaToR#56f8C24c5A914299Db41F70e9b43f36d", "w00t" },                   //Salt and hash are lowercased

	/*{"$DCC2$nineteen_characters#c4201b8267d74a2db1d5d19f5c9f7b57", "verylongpassword" }, //max salt_length
	{"$DCC2$nineteen_characters#87136ae0a18b2dafe4a41d555425b2ed", "w00t"},
*///
	//{"$DCC2$eighteencharacters#fc5df74eca97afd7cd5abb0032496223", "w00t" },
	//{"$DCC2$john-the-ripper#495c800a038d11e55fafc001eb689d1d", "batman#$@#1991" },
///	  {"$DCC2$jack#dc70386d419fc48442e6d0f64fa5f3da","Skipping and& Dipping"},		//passlen = 21
///	  {"$DCC2$john#d089ffa28f7508f67dcbb85f46b26886","0123456789012345678901234"}, //passlen =25
///	  {"$DCC2$john#51708f1b4587d6e0fb62f71b256692b5","012345678901234567890123456"}, //passlen 27
	  //{"$DCC2$john#e7eb0fe73504d06f796615e6de083963","0123456789012345678901234567"}, //passlen 28
	  //{"$DCC2$john#799c528e18017c5bc2e8d272de8e94ba","012345678901234567890123456789"}, //passlen= 30
	  //{"$DCC2$john#caf1f2deef864f10a67c30be23087fa1","012345678901234567890123456789_"}, //passlen = 31


	{NULL}
};

extern void mscash2_gpu(mscash2_password *, mscash2_hash *, mscash2_salt *);

static void cleanup()
{
	free(inbuffer);
	free(outbuffer);
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
	cuda_init(gpu_id);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos,*hash = strrchr(ciphertext, '#') + 1;
	int hashlength = 0;
	int saltlength = 0;
	if (strncmp(ciphertext, mscash2_prefix, strlen(mscash2_prefix)) != 0)
		return 0;

	if (hash == NULL)
		return 0;
	while (hash < ciphertext + strlen(ciphertext)) {
		if (atoi16[ARCH_INDEX(*hash++)] == 0x7f)
			return 0;
		hashlength++;
	}
	if (hashlength != 32)
		return 0;

	pos = ciphertext + strlen(mscash2_prefix);
	while (*pos++ != '#') {
		if (saltlength == 19)
			return 0;
		saltlength++;
	}
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
	if (!strncmp(split_fields[1], "$DCC2$", 6) &&
	    valid(split_fields[1], self))
		return split_fields[1];
	if (!split_fields[0])
		return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 14);
	sprintf(cp, "$DCC2$%s#%s", split_fields[0], split_fields[1]);
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
	while (*pos != '#') {
		if (length == 19)
			return NULL;
		salt.salt[length++] = *pos++;
	}
	salt.length = length;
	//printf("salt len=%d\n",salt.length);
	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, sizeof(mscash2_salt));
}

static void set_key(char *key, int index)
{
#ifdef _MSCASH2_DEBUG
	printf("set_key(%d) = [%s]\n",index,key);
#endif
	uint8_t length = strlen(key);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, MIN(length,PLAINTEXT_LENGTH));
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
		FMT_CASE | FMT_8_BIT| FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE,
		tests
	}, {
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
