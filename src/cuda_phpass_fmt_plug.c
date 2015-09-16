/*
* This software is Copyright (c) 2011,2012 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_phpass;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_phpass);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_phpass.h"
#include "cuda_common.h"
#include "memdbg.h"

#define FORMAT_LABEL		"phpass-cuda"
#define FORMAT_NAME		""

#define ALGORITHM_NAME		"MD5 CUDA"

#define BENCHMARK_COMMENT	" ($P$9 lengths 0 to 15)"

#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define CIPHERTEXT_LENGTH	34	/// header = 3 | loopcnt = 1 | salt = 8 | ciphertext = 22
#define BINARY_SIZE		16
#define BINARY_ALIGN		1
#define SALT_ALIGN		1
#define MD5_DIGEST_LENGTH 	16

#define MIN_KEYS_PER_CRYPT	THREADS
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

static unsigned char *inbuffer;				/** plaintext ciphertexts **/
static phpass_crack *outbuffer;				/** calculated hashes **/
static phpass_salt currentsalt;

extern void gpu_phpass(uint8_t *, phpass_salt *, phpass_crack *, int count);

static struct fmt_tests tests[] = {
	{"$P$90000000000tbNYOc9TwXvLEI62rPt1", ""},
	{"$P$9saltstriAcRMGl.91RgbAD6WSq64z.", "a"},
	{"$P$9saltstriMljTzvdluiefEfDeGGQEl/", "ab"},
//	{"$P$9saltstrikCftjZCE7EY2Kg/pjbl8S.", "abc"},
	{"$P$900000000jPBDh/JWJIyrF0.DmP7kT.", "ala"},
//	{"$P$9saltstriV/GXRIRi9UVeMLMph9BxF0", "abcd"},
//	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
//	{"$P$900000001ahWiA6cMRZxkgUxj4x/In0", "john"},
//	{"$P$900000000a94rg7R/nUK0icmALICKj1", "john"},
	{"$P$9sadli2.wzQIuzsR2nYVhUSlHNKgG/0", "john"},
	{"$P$9saltstri3JPgLni16rBZtI03oeqT.0", "abcde"},
//	{"$P$9saltstri0D3A6JyITCuY72ZoXdejV.", "abcdef"},
	{"$P$900000000zgzuX4Dc2091D8kak8RdR0", "h3ll00"},
	{"$P$9saltstriXeNc.xV8N.K9cTs/XEn13.", "abcdefg"},
//	{"$P$9saltstrinwvfzVRP3u1gxG2gTLWqv.", "abcdefgh"},
	{"$P$900000000m6YEJzWtTmNBBL4jypbHv1", "openwall"},
	{"$H$9saltstriSUQTD.yC2WigjF8RU0Q.Z.", "abcdefghi"},
//	{"$P$9saltstriWPpGLG.jwJkwGRwdKNEsg.", "abcdefghij"},
//	{"$P$900000000qZTL5A0XQUX9hq0t8SoKE0", "1234567890"},
	{"$P$900112200B9LMtPy2FSq910c1a6BrH0", "1234567890"},
//	{"$P$9saltstrizjDEWUMXTlQHQ3/jhpR4C.", "abcdefghijk"},
	{"$P$9RjH.g0cuFtd6TnI/A5MRR90TXPc43/", "password__1"},
	{"$P$9saltstriGLUwnE6bl91BPJP6sxyka.", "abcdefghijkl"},
	{"$P$9saltstriq7s97e2m7dXnTEx2mtPzx.", "abcdefghijklm"},
	{"$P$9saltstriTWMzWKsEeiE7CKOVVU.rS0", "abcdefghijklmn"},
	{"$P$9saltstriXt7EDPKtkyRVOqcqEW5UU.", "abcdefghijklmno"},
#if 0
	{"$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00", "test1"},
	{"$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1", "123456"},
	{"$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1", "123456"},
//	{"$P$912345678LIjjb6PhecupozNBmDndU0", "thisisalongertestPW"},
	{"$H$9A5she.OeEiU583vYsRXZ5m2XIpI68/", "123456"},
	{"$P$917UOZtDi6ksoFt.y2wUYvgUI6ZXIK/", "test1"},
//	{"$P$91234567AQwVI09JXzrV1hEC6MSQ8I0", "thisisalongertest"},
	{"$P$9234560A8hN6sXs5ir0NfozijdqT6f0", "test2"},
	{"$P$9234560A86ySwM77n2VA/Ey35fwkfP0", "test3"},
	{"$P$9234560A8RZBZDBzO5ygETHXeUZX5b1", "test4"},
	{"$P$612345678si5M0DDyPpmRCmcltU/YW/", "JohnRipper"}, // 256
	{"$P$6T4Krr44HLrUqGkL8Lu67lzZVbvHLC1", "test12345"}, // 256
	{"$H$712345678WhEyvy1YWzT4647jzeOmo0", "JohnRipper"}, // 512 (phpBB w/older PHP version)
	{"$P$8DkV/nqeaQNTdp4NvWjCkgN48AK69X.", "test12345"}, // 1024
	{"$P$B12345678L6Lpt4BxNotVIMILOa9u81", "JohnRipper"}, // 8192 (WordPress)
//	{"$P$91234567xogA.H64Lkk8Cx8vlWBVzH0", "thisisalongertst"},
#endif
	{NULL}
};

static void done(void)
{
	MEM_FREE(inbuffer);
	MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
	///Allocate memory for hashes and passwords
	inbuffer =
		(uint8_t *) mem_calloc(MAX_KEYS_PER_CRYPT,
		                       sizeof(phpass_password));
	outbuffer =
		(phpass_crack *) mem_calloc(MAX_KEYS_PER_CRYPT,
		                            sizeof(phpass_crack));
	check_mem_allocation(inbuffer, outbuffer);
	///Initialize CUDA
	cuda_init();
}

static int valid(char *ciphertext, struct fmt_main *self)
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
}

///code from historical JtR phpass patch
static void pbinary(char *ciphertext, unsigned char *out)
{
	int i, bidx = 0;
	unsigned sixbits;
	char *pos = &ciphertext[3 + 1 + 8];
	memset(out, 0, BINARY_SIZE);

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

static void *get_binary(char *ciphertext)
{
	static unsigned char b[BINARY_SIZE];
	pbinary(ciphertext, b);
	return (void *) b;
}

static void *get_salt(char *ciphertext)
{
	static phpass_salt salt;
	salt.rounds = 1 << atoi64[ARCH_INDEX(ciphertext[3])];
	memcpy(salt.salt, &ciphertext[4], 8);
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	memset(outbuffer, 0, sizeof(phpass_crack) * KEYS_PER_CRYPT);
	gpu_phpass(inbuffer, &currentsalt, outbuffer, *pcount);
	return *pcount;
}

static int cmp_all(void *binary, int count)
{
	int i;
	unsigned int *b32 = (unsigned int *)binary;
	for(i=0; i < count; i++)
		if(outbuffer[i].hash[0] == b32[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	unsigned int *b32 = (unsigned int *)binary;
	for(i=0; i < 4; i++)
		if(outbuffer[index].hash[i] != b32[i])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int get_hash_0(int index) { return outbuffer[index].hash[0] & PH_MASK_0; }
static int get_hash_1(int index) { return outbuffer[index].hash[0] & PH_MASK_1; }
static int get_hash_2(int index) { return outbuffer[index].hash[0] & PH_MASK_2; }
static int get_hash_3(int index) { return outbuffer[index].hash[0] & PH_MASK_3; }
static int get_hash_4(int index) { return outbuffer[index].hash[0] & PH_MASK_4; }
static int get_hash_5(int index) { return outbuffer[index].hash[0] & PH_MASK_5; }
static int get_hash_6(int index) { return outbuffer[index].hash[0] & PH_MASK_6; }

struct fmt_main fmt_cuda_phpass = {
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
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
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
