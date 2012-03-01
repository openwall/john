/*
* This software is Copyright (c) 2011 Lukas Odzioba
* <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
* Based on Alain Espinosa implementation http://openwall.info/wiki/john/MSCash
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_mscash.h"
#include "cuda_common.h"

#define FORMAT_LABEL		"mscash-cuda"
#define ALGORITHM_NAME		""

#define BENCHMARK_COMMENT	" len(pass)=8, len(salt)=13"
#define BENCHMARK_LENGTH	-1

static mscash_password *inbuffer;
static mscash_hash *outbuffer;
static mscash_salt currentsalt;

static struct fmt_tests tests[] = {
	{"M$administrator#25fd08fa89795ed54207e6e8442a6ca0", "password"},
	{NULL}
};

extern void cuda_mscash(mscash_password *, mscash_hash *, mscash_salt *);

static void cleanup()
{
 free(inbuffer);
 free(outbuffer);
}

static void init(struct fmt_main *pFmt)
{
  //Alocate memory for hashes and passwords
  inbuffer=(mscash_password*)malloc(sizeof(mscash_password)*MAX_KEYS_PER_CRYPT);
  outbuffer=(mscash_hash*)malloc(sizeof(mscash_hash)*MAX_KEYS_PER_CRYPT);
  check_mem_allocation(inbuffer,outbuffer);
  atexit(cleanup);
  //Initialize CUDA
  cuda_init(gpu_id);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	if (strncmp(ciphertext, mscash_prefix, strlen(mscash_prefix)) != 0)
		return 0;
	char *hash = strrchr(ciphertext, '#') + 1;
	while (hash < ciphertext + strlen(ciphertext))
		if (atoi16[(int)*hash++] == 0x7f)
			return 0;
	return 1;
}

static void *binary(char *ciphertext)
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

static void *salt(char *ciphertext)
{
	static mscash_salt salt;
	char *pos = ciphertext + strlen(mscash_prefix);
	int length = 0;
	while (*pos != '#')
		salt.salt[length++] = *pos++;
	salt.length = length;
	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, sizeof(mscash_salt));
}

static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);
	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);
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
	cuda_mscash(inbuffer, outbuffer, &currentsalt);
}

static int binary_hash_0(void *binary)
{
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

struct fmt_main fmt_cuda_mscash = {
	{
		    FORMAT_LABEL,
		    FORMAT_LABEL,
		    ALGORITHM_NAME,
		    BENCHMARK_COMMENT,
		    BENCHMARK_LENGTH,
		    PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    SALT_SIZE,
		    MIN_KEYS_PER_CRYPT,
		    MAX_KEYS_PER_CRYPT,
		    FMT_CASE | FMT_8_BIT,
	    tests},
	{
		    init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
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
	    cmp_exact}
};
