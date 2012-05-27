/*
* This software is Copyright (c) 2011 Lukas Odzioba <lukas dot odzioba at gmail dot com> 
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#include <string.h>
#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_phpass.h"
#include "cuda_common.h"

#define FORMAT_LABEL		"phpass-cuda"
#define FORMAT_NAME		FORMAT_LABEL

#define PHPASS_TYPE		"PORTABLE-MD5"

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define CIPHERTEXT_LENGTH	34	/// header = 3 | loopcnt = 1 | salt = 8 | ciphertext = 22
#define BINARY_SIZE		16
#define MD5_DIGEST_LENGTH 	16


#define SALT_SIZE		8

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

static unsigned char *inbuffer;//[MAX_KEYS_PER_CRYPT * sizeof(phpass_password)];			/** plaintext ciphertexts **/
static uint32_t *outbuffer;//[MAX_KEYS_PER_CRYPT * 4];						/** calculated hashes **/

static char currentsalt[SALT_SIZE];
static char loopChar = '*';

extern void mem_init(unsigned char *, uint32_t *, char *, char *, int);
extern void mem_clear(void);
extern void gpu_phpass(void);


static struct fmt_tests tests[] = {
/*	{"$P$900000000jPBDh/JWJIyrF0.DmP7kT.", "ala"},
	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	{"$P$900000001ahWiA6cMRZxkgUxj4x/In0", "john"},
	{"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"},
	{"$P$900000000zgzuX4Dc2091D8kak8RdR0", "h3ll00"},
	{"$P$900000000qZTL5A0XQUX9hq0t8SoKE0", "1234567890"},
	{"$P$900112200B9LMtPy2FSq910c1a6BrH0", "1234567890"},
	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	{"$P$9sadli2.wzQIuzsR2nYVhUSlHNKgG/0", "john"},
	{"$P$90000000000tbNYOc9TwXvLEI62rPt1", ""},
*/
      {"$P$9saltstriAcRMGl.91RgbAD6WSq64z.","a"},
      {"$P$9saltstriMljTzvdluiefEfDeGGQEl/","ab"},
      {"$P$9saltstrikCftjZCE7EY2Kg/pjbl8S.","abc"},
      {"$P$9saltstriV/GXRIRi9UVeMLMph9BxF0","abcd"},
      {"$P$9saltstri3JPgLni16rBZtI03oeqT.0","abcde"},
      {"$P$9saltstri0D3A6JyITCuY72ZoXdejV.","abcdef"},
      {"$P$9saltstriXeNc.xV8N.K9cTs/XEn13.","abcdefg"},
      {"$P$9saltstrinwvfzVRP3u1gxG2gTLWqv.","abcdefgh"},
      {"$P$9saltstriSUQTD.yC2WigjF8RU0Q.Z.","abcdefghi"},
      {"$P$9saltstriWPpGLG.jwJkwGRwdKNEsg.","abcdefghij"},

      {"$P$9saltstrizjDEWUMXTlQHQ3/jhpR4C.","abcdefghijk"},
      {"$P$9saltstriGLUwnE6bl91BPJP6sxyka.","abcdefghijkl"},
      {"$P$9saltstriq7s97e2m7dXnTEx2mtPzx.","abcdefghijklm"},
      {"$P$9saltstriTWMzWKsEeiE7CKOVVU.rS0","abcdefghijklmn"},
      {"$P$9saltstriXt7EDPKtkyRVOqcqEW5UU.", "abcdefghijklmno"},
	{NULL}
};

static void cleanup()
{
  free(inbuffer);
  free(outbuffer);
}

static void init(struct fmt_main *pFmt)
{
    //Alocate memory for hashes and passwords
    inbuffer=(unsigned char*)malloc(MAX_KEYS_PER_CRYPT * sizeof(phpass_password)*sizeof(char));
    outbuffer=(uint32_t *)malloc(MAX_KEYS_PER_CRYPT*4*sizeof(uint32_t));
    check_mem_allocation(inbuffer,outbuffer);
    atexit(cleanup);
    //Initialize CUDA
    cuda_init(gpu_id);
}

static int valid(char *ciphertext,struct fmt_main *pFmt)
{
	uint32_t i, count_log2;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	if (strncmp(ciphertext, phpass_prefix, 3) != 0)
		return 0;

	for (i = 3; i < CIPHERTEXT_LENGTH; i++)
		if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
};

//code from historical JtR phpass patch
static void *binary(char *ciphertext)
{
	static unsigned char b[BINARY_SIZE];
	memset(b, 0, BINARY_SIZE);
	int i, bidx = 0;
	unsigned sixbits;
	char *pos = &ciphertext[3 + 1 + 8];

	for (i = 0; i < 5; i++) {
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 6);
		sixbits >>= 2;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 4);
		sixbits >>= 4;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits << 2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] |= (sixbits << 6);
	return (void *) b;
}

static void *salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE + 2];
	memcpy(salt, &ciphertext[4], 8);
	salt[8] = ciphertext[3];
	salt[9] = 0;
	return salt;
}

static int binary_hash_0(void *binary)
{
	return (((ARCH_WORD_32 *) binary)[0] & 0xf);
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xff;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfff;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffff;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xfffff;
}

static int binary_hash_5(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0xffffff;
}

static int binary_hash_6(void *binary)
{
	return ((ARCH_WORD_32 *) binary)[0] & 0x7ffffff;
}

static void set_salt(void *salt)
{
	unsigned char *csalt = salt;
	memcpy(currentsalt,csalt,8);
	loopChar = csalt[8];
}

static void set_key(char *key, int index)
{
	int i, len = strlen(key);
	inbuffer[address(15, index)] = len;
	for (i = 0; i < len; i++)
		inbuffer[address(i, index)] = key[i];
}

static char *get_key(int index)
{
	static char r[PLAINTEXT_LENGTH + 1];
	int i;
	for (i = 0; i < PLAINTEXT_LENGTH; i++)
		r[i] = inbuffer[address(i, index)];
	r[inbuffer[address(15,index)]] = '\0';
	return r;
}

static void crypt_all(int count)
{
	char setting[40];
	strcpy(setting, phpass_prefix);
	setting[3] = loopChar;
	int count_log2 = 0;
	count_log2 = atoi64[ARCH_INDEX(setting[3])];
	strcpy(setting + 4, currentsalt);
	mem_init(inbuffer, outbuffer, setting, itoa64, count_log2);
	gpu_phpass();
	mem_clear();
}

static int get_hash_0(int index)
{
	return outbuffer[address(0, index)] & 0xf;
}

static int get_hash_1(int index)
{
	return outbuffer[address(0, index)] & 0xff;
}

static int get_hash_2(int index)
{
	return outbuffer[address(0, index)] & 0xfff;
}

static int get_hash_3(int index)
{
	return outbuffer[address(0, index)] & 0xffff;
}

static int get_hash_4(int index)
{
	return outbuffer[address(0, index)] & 0xfffff;
}

static int get_hash_5(int index)
{
	return outbuffer[address(0, index)] & 0xffffff;
}

static int get_hash_6(int index)
{
	return outbuffer[address(0, index)] & 0x7ffffff;
}


static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint32_t b = ((uint32_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[address(0, i)])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	for (i = 0; i < 4; i++)
		if (t[i] != outbuffer[address(i, index)])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

struct fmt_main fmt_cuda_phpass = {
	{
		    FORMAT_LABEL,
		    FORMAT_NAME,
		    PHPASS_TYPE,
		    BENCHMARK_COMMENT,
		    BENCHMARK_LENGTH,
		    PLAINTEXT_LENGTH,
		    BINARY_SIZE,
		    SALT_SIZE + 1,
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
		    binary_hash_6},
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
		    get_hash_6},
		    cmp_all,
		    cmp_one,
	    cmp_exact,
		fmt_default_get_source
	}
};
