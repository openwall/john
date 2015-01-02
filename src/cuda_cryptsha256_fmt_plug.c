/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_cryptsha256;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_cryptsha256);
#else

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <string.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_cryptsha256.h"
#include "cuda_common.h"

#define FORMAT_LABEL		"sha256crypt-cuda"
#define FORMAT_NAME		"crypt(3) $5$"

#define ALGORITHM_NAME		"SHA256 CUDA (inefficient, please use sha256crypt-opencl instead)"

#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define BINARY_SIZE		32
#define MD5_DIGEST_LENGTH 	16

#define CIPHERTEXT_LENGTH	43
#define SALT_LENGTH		16
#define SALT_SIZE		(3+7+9+16)

#define BINARY_ALIGN		4
#define SALT_ALIGN		sizeof(uint32_t)

#define MIN_KEYS_PER_CRYPT	THREADS
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

#include "cryptsha256_common.h"
#include "memdbg.h"

extern void sha256_crypt_gpu(crypt_sha256_password * inbuffer,
	uint32_t * outbuffer, crypt_sha256_salt * host_salt, int count);

static crypt_sha256_password *inbuffer;//[MAX_KEYS_PER_CRYPT];			/** plaintext ciphertexts **/
static uint32_t *outbuffer;//[MAX_KEYS_PER_CRYPT * 8];				/** calculated hashes **/

static char currentsalt[64];
static crypt_sha256_salt host_salt;

void sha256_crypt_cpu(crypt_sha256_password * passwords,
    crypt_sha256_hash * output, crypt_sha256_salt * salt);


static struct fmt_tests tests[] = {
	{"$5$LKO/Ute40T3FNF95$U0prpBQd4PloSGU0pnpM4z9wKn4vZ1.jsrzQfPqxph9", "U*U*U*U*"},
	{"$5$LKO/Ute40T3FNF95$fdgfoJEBoMajNxCv3Ru9LyQ0xZgv0OBMQoq80LQ/Qd.", "U*U***U"},
	{"$5$LKO/Ute40T3FNF95$8Ry82xGnnPI/6HtFYnvPBTYgOL23sdMXn8C29aO.x/A", "U*U***U*"},
	{"$5$9mx1HkCz7G1xho50$O7V7YgleJKLUhcfk9pgzdh3RapEaWqMtEp9UUBAKIPA", "*U*U*U*U"},
	{"$5$kc7lRD1fpYg0g.IP$d7CMTcEqJyTXyeq8hTdu/jB/I6DGkoo62NXbHIR7S43", ""},
	{"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Hello world!"},
	{"$5$V8UMZ8/8.j$GGzeGHZy60318qdLiocMj7DddCnfr7jIcLMDIRy9Tr0", "password"},
	// exceeds tha max. password length for GPU fomats
	//{"$5$mTfUlwguIR0Gp2ed$nX5lzmEGAZQ.1.CcncGnSq/lxSF7t1P.YkVlljQfOC2", "01234567890123456789012345678901234"},

	// Should this test be moved into the #ifdef DEBUG section
	// instead of being turned into a comment?
	// Here is a test case for rounds=50000. Works, but slows down self test a lot (but not benchmarks)
	// so, it is best to uncomment after changes, test that this still works, then comment out before release.
	//{"$5$rounds=50000$LKO/Ute40T3FNF95$S51z7fjx29wblQAQbkqY7G8ExS18kQva39ur8FG5VS0", "U*U*U*U*"},

#ifdef DEBUG
	//Special test cases.
	{"$5$UOUBPEMKQRHHRFML$zicoLpMLhBsNGtEplY/ehM0NtiAqxijiBCrolt7WBW0","jjti"},

	{"$5$XSLWLBSQUCNOWXOB$i7Ho5wUAIjsH2e2zA.WarqYLWir5nmZbUEcjK//Or7.","hgnirgayjnhvi"},
	{"$5$VDCTRFOIDQXRQVHR$uolqT0wEwU.pvI9jq5xU457JQpiwTTKX3PB/9RS4/h4","o"},
	{"$5$WTYWNCYHNPMXPG$UwZyrq0irhWs4OcLKcqSbFdktZaNAD2by1CiNNw7oID","tcepf"},
	{"$5$DQUHKJNMVOEBGBG$91u2d/jMN5QuW3/kBEPG0xC2G8y1TuDU7SGAUYTX.y0","wbfhoc"},
	{"$5$saltstring$0Az3qME7zTXm78kfHrR2OtT8WOu2gd8bcVn/9Y.3l/7", "john"},

	{"$5$saltstring$7cz4bTeQ7MnNssphNhFVrITtuJYY/1tdvLL2uzLvOk8","a"},
	{"$5$saltstring$4Wjlxdm/Hbpo8ZQzKFazuvfUZPVVUQn6v1oPTX3nwX/","ab"},
	{"$5$saltstring$tDHA0KPsYQ8V.LDB1/fgW7cvROod5ZajSrx1tZU2JG9","abc"},
	{"$5$saltstring$LfhGTHVGfbAkxy/xKLgvSfXyeE7hZheoMRKhjfvNF6.","abcd"},
	{"$5$saltstring$Qg0Xm9f2VY.ePLAwNXnOPU/s8btLptK/tEU/gFnn8BD","abcde"},
	{"$5$saltstring$2Snf.yaHnLnLI3Qhsk2S119X4vKbwQyiTMOHp3Oy7F5","abcdef"},
	{"$5$saltstring$4Y5UR.6zwplRx6y93NJVyNkxqdlyT64EV68F2mCrZ16","abcdefg"},
	{"$5$saltstring$bEM3iuUR.CTgy8Wygh4zu.CAgmlwx3uxm3dGA34.Ij4","abcdefgh"},
	{"$5$saltstring$1/OrKXZSFlaEE2DKMhKKE8qCld5X0Ez0vtz5TvO3U3D","abcdefghi"},
	{"$5$saltstring$1IbZU70/Wo9m1b40ha6Ao8d.v6Ja0.bAFg5/QFVzoX/","abcdefghij"},

	{"$5$saltstring$S4gCgloAzqAXE5sRz9DShPvaXrwt4vjDJ4fYgIMbLo1","abcdefghijk"},
	{"$5$saltstring$AFNSzsWaoMDvt7lk2bx0rPapzCz2zGahXDdFeoXrNE9","abcdefghijkl"},
	{"$5$saltstring$QfHc8JBd2DfyloVL0YLDa23Dc67N9mbdYqyRJQlFqZ5","abcdefghijklm"},
	{"$5$saltstring$XKHiS.SSJ545PvJJr2t.HyUpmPZDAIT8fVvzr/HGhd0","abcdefghijklmn"},
	{"$5$saltstring$VxW44bFDcvixlQoTE4E.k5c8v1w0fGMyZ4tn8nGcWn0","abcdefghijklmno"},

	{"$5$QSTVVEKDIDYRNK$4j8TST.29P07GHASD.BUHd0UTaFz7h.Mz//zcHokoZ5","cgyihfkqk"},

	// from a comment in the OpenCL implementation:
	//{"$5$EKt.VLXiPjwyv.xe$52wdOp9ixFXMsHDI1JcCw8KJ83IakDP6J7MIEV2OUk0", "1234567"},
#endif
	//{"$5$rounds=5000$abcdefghijklmnop$BAYQep7SsuSczAeXlks3F54SpxMUUludHi1C4JVOqpD","abcdefghijklmno"},
	{NULL}
};

static void done()
{
 MEM_FREE(inbuffer);
 MEM_FREE(outbuffer);
}

static void init(struct fmt_main *self)
{
  //Allocate memory for hashes and passwords
  inbuffer=(crypt_sha256_password*)mem_calloc(MAX_KEYS_PER_CRYPT*sizeof(crypt_sha256_password));
  outbuffer=(uint32_t*)mem_alloc(MAX_KEYS_PER_CRYPT*sizeof(uint32_t)*8);
  check_mem_allocation(inbuffer,outbuffer);
  //Initialize CUDA
  cuda_init();
}

static void *salt(char *ciphertext)
{
	int end = 0, i, len = strlen(ciphertext);
	static unsigned char ret[64];

	memset(ret, 0, sizeof(ret));
	for (i = len - 1; i >= 0; i--)
		if (ciphertext[i] == '$') {
			end = i;
			break;

		}
	for (i = 0; i < end; i++)
		ret[i] = ciphertext[i];
	ret[end] = 0;
	return (void *) ret;
}

static void set_salt(void *salt)
{
	unsigned char *s = salt;
	int len = strlen(salt);
	unsigned char offset = 0;
	memcpy(currentsalt,s,len+1);
	host_salt.rounds = ROUNDS_DEFAULT;

	if (strncmp((char *) "$5$", (char *) currentsalt, 3) == 0)
		offset += 3;

	if (strncmp((char *) currentsalt + offset, (char *) "rounds=", 7) == 0) {
		const char *num = currentsalt + offset + 7;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			endp += 1;
			host_salt.rounds =
			    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
		}
		offset = endp - currentsalt;
	}
	memcpy(host_salt.salt, currentsalt + offset, 16);
	host_salt.saltlen = strlen(host_salt.salt);
}

static void set_key(char *key, int index)
{
	int len = strlen(key);
	inbuffer[index].length = len;
	memcpy(inbuffer[index].v, key, len);
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	memcpy(ret, inbuffer[index].v, PLAINTEXT_LENGTH);
	ret[inbuffer[index].length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	sha256_crypt_gpu(inbuffer, outbuffer, &host_salt, count);
	return count;
}

static int get_hash_0(int index)
{

	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xf;
}

static int get_hash_1(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xff;
}

static int get_hash_2(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xfff;
}

static int get_hash_3(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xffff;
}

static int get_hash_4(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xfffff;
}

static int get_hash_5(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0xffffff;
}

static int get_hash_6(int index)
{
	uint32_t *out = outbuffer;
	return out[hash_addr(0, index)] & 0x7ffffff;
}

static int cmp_all(void *binary, int count)
{
	uint32_t i;
	uint32_t b = ((uint32_t *) binary)[0];
	uint32_t *out = outbuffer;
	for (i = 0; i < count; i++)
		if (b == out[hash_addr(0, i)])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint32_t *t = (uint32_t *) binary;
	uint32_t *out = outbuffer;

	for (i = 0; i < 8; i++)
		if (t[i] != out[hash_addr(i, index)])
			return 0;
	return 1;
}

static int cmp_exact(char *source, int count)
{
	return 1;
}

#if FMT_MAIN_VERSION > 11
/* iteration count as tunable cost parameter */
static unsigned int iteration_count(void *salt)
{
	crypt_sha256_salt *sha256crypt_salt;

	sha256crypt_salt = salt;
	return (unsigned int)sha256crypt_salt->rounds;
}
#endif

struct fmt_main fmt_cuda_cryptsha256 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
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
