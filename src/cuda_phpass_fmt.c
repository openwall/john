/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall dot net>
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
#define FORMAT_NAME		"phpass MD5"

#define ALGORITHM_NAME		"CUDA"

#define BENCHMARK_COMMENT	" ($P$9 lengths 1 to 15)"

#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define CIPHERTEXT_LENGTH	34	/// header = 3 | loopcnt = 1 | salt = 8 | ciphertext = 22
#define BINARY_SIZE		16
#define MD5_DIGEST_LENGTH 	16

#define MIN_KEYS_PER_CRYPT	KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

static unsigned char *inbuffer;				/** plaintext ciphertexts **/
static phpass_crack *outbuffer;				/** calculated hashes **/
static phpass_salt currentsalt;
static int any_cracked;

extern void gpu_phpass(uint8_t *, phpass_salt *, phpass_crack *);

static struct fmt_tests tests[] = {
	{"$P$900000000jPBDh/JWJIyrF0.DmP7kT.", "ala"},
	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	{"$P$900000001ahWiA6cMRZxkgUxj4x/In0", "john"},
	{"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"},
	{"$P$900000000zgzuX4Dc2091D8kak8RdR0", "h3ll00"},
	{"$P$900000000qZTL5A0XQUX9hq0t8SoKE0", "1234567890"},
	{"$H$900112200B9LMtPy2FSq910c1a6BrH0", "1234567890"},
	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	{"$P$9sadli2.wzQIuzsR2nYVhUSlHNKgG/0", "john"},
	{"$P$90000000000tbNYOc9TwXvLEI62rPt1", ""},

	{"$P$9saltstriAcRMGl.91RgbAD6WSq64z.", "a"},
	{"$P$9saltstriMljTzvdluiefEfDeGGQEl/", "ab"},
	{"$P$9saltstrikCftjZCE7EY2Kg/pjbl8S.", "abc"},
	{"$P$9saltstriV/GXRIRi9UVeMLMph9BxF0", "abcd"},
	{"$P$9saltstri3JPgLni16rBZtI03oeqT.0", "abcde"},
	{"$P$9saltstri0D3A6JyITCuY72ZoXdejV.", "abcdef"},
	{"$P$9saltstriXeNc.xV8N.K9cTs/XEn13.", "abcdefg"},
	{"$P$9saltstrinwvfzVRP3u1gxG2gTLWqv.", "abcdefgh"},
	{"$P$9saltstriSUQTD.yC2WigjF8RU0Q.Z.", "abcdefghi"},
	{"$P$9saltstriWPpGLG.jwJkwGRwdKNEsg.", "abcdefghij"},

	{"$P$9saltstrizjDEWUMXTlQHQ3/jhpR4C.", "abcdefghijk"},
	{"$P$9saltstriGLUwnE6bl91BPJP6sxyka.", "abcdefghijkl"},
	{"$P$9saltstriq7s97e2m7dXnTEx2mtPzx.", "abcdefghijklm"},
	{"$P$9saltstriTWMzWKsEeiE7CKOVVU.rS0", "abcdefghijklmn"},
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
	///Alocate memory for hashes and passwords
	inbuffer =
	    (uint8_t *) calloc(MAX_KEYS_PER_CRYPT, sizeof(phpass_password));
	outbuffer =
	    (phpass_crack *) calloc(MAX_KEYS_PER_CRYPT, sizeof(phpass_crack));
	check_mem_allocation(inbuffer, outbuffer);
	atexit(cleanup);
	///Initialize CUDA
	cuda_init(gpu_id);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	uint32_t i, count_log2;

	int prefix=0;
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	if (strncmp(ciphertext, "$P$", 3) == 0)
		prefix=1;
	if (strncmp(ciphertext, "$H$", 3) == 0)
		prefix=1;
	if(prefix==0) return 0;

	for (i = 3; i < CIPHERTEXT_LENGTH; i++)
		if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
};

///code from historical JtR phpass patch
static void pbinary(char *ciphertext, unsigned char *out)
{
	memset(out, 0, BINARY_SIZE);
	int i, bidx = 0;
	unsigned sixbits;
	char *pos = &ciphertext[3 + 1 + 8];

	for (i = 0; i < 5; i++) {
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out[bidx++] |= (sixbits << 6);
		sixbits >>= 2;
		out[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out[bidx++] |= (sixbits << 4);
		sixbits >>= 4;
		out[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		out[bidx++] |= (sixbits << 2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	out[bidx] |= (sixbits << 6);
}

static void *binary(char *ciphertext)
{
	static unsigned char b[BINARY_SIZE];
	pbinary(ciphertext, b);
	return (void *) b;
}

static void *salt(char *ciphertext)
{
	static phpass_salt salt;
	salt.rounds = 1 << atoi64[ARCH_INDEX(ciphertext[3])];
	memcpy(salt.salt, &ciphertext[4], 8);
	pbinary(ciphertext, (unsigned char*)salt.hash);
	return &salt;
}

static void set_salt(void *salt)
{
	memcpy(&currentsalt, salt, SALT_SIZE);
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
	r[inbuffer[address(15, index)]] = '\0';
	return r;
}

static void crypt_all(int count)
{
	int i;
	if (any_cracked) {
		memset(outbuffer, 0, sizeof(phpass_crack) * KEYS_PER_CRYPT);
		any_cracked = 0;
	}
	gpu_phpass(inbuffer, &currentsalt, outbuffer);
	for (i = 0; i < count; i++) {
		any_cracked |= outbuffer[i].cracked;
	}
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return outbuffer[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return outbuffer[index].cracked;
}

struct fmt_main fmt_cuda_phpass = {
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
		    FMT_CASE | FMT_8_BIT,
		    tests
	},
	{
		    init,
		    fmt_default_prepare,
		    valid,
		    fmt_default_split,
		    binary,
		    salt,
		    {
			fmt_default_binary_hash
		    },
		    fmt_default_salt_hash,
		    set_salt,
		    set_key,
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
