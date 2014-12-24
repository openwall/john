/*
* This software is Copyright (c) 2011 Lukas Odzioba <ukasz at openwall dot net>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*/
#ifdef HAVE_CUDA

#if FMT_EXTERNS_H
extern struct fmt_main fmt_cuda_cryptsha512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_cuda_cryptsha512);
#else

#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "misc.h"
#include "cuda_cryptsha512.h"
#include "cuda_common.h"
// these MUST be defined prior to loading cryptsha512_valid.h
#define BINARY_SIZE			64
#define SALT_LENGTH			16
#define CIPHERTEXT_LENGTH		86
#include "cryptsha512_common.h"
#include "memdbg.h"

#define FORMAT_LABEL		"sha512crypt-cuda"
#define FORMAT_NAME		"crypt(3) $6$"

#define ALGORITHM_NAME		"SHA512 CUDA (inefficient, please use sha512crypt-opencl instead)"

#define BENCHMARK_COMMENT	" (rounds=5000)"
#define BENCHMARK_LENGTH	-1

#define PLAINTEXT_LENGTH	15
#define MD5_DIGEST_LENGTH 	16

#define BINARY_ALIGN		8
#define SALT_ALIGN			sizeof(uint32_t)

#define SALT_SIZE		(3+7+9+16)

#define MIN_KEYS_PER_CRYPT	THREADS
#define MAX_KEYS_PER_CRYPT	KEYS_PER_CRYPT

static crypt_sha512_password *inbuffer;		/** plaintext ciphertexts **/
static crypt_sha512_hash *outbuffer;		/** calculated hashes **/

void sha512_crypt_gpu(crypt_sha512_password * inbuffer,
	crypt_sha512_hash *outbuffer, crypt_sha512_salt *host_salt, int count);

static char currentsalt[64];
static crypt_sha512_salt _salt;

static struct fmt_tests tests[] = {

	{"$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1", "Hello world!"},
#ifdef DEBUG //Special test cases.
	{"$6$saltstring$fgNTR89zXnDUV97U5dkWayBBRaB0WIBnu6s4T7T8Tz1SbUyewwiHjho25yWVkph2p18CmUkqXh4aIyjPnxdgl0","john"},
	{"$6$saltstring$MO53nAXQUKXVLlsbiXyPgMsR6q10N7eF7sPvanwdXnEeCj5kE3eYaRvFv0wVW1UZ4SnNTzc1v4OCOq1ASDQZY0","a"},
	{"$6$saltstring$q.eQ9PCFPe/tOHJPT7lQwnVQ9znjTT89hsg1NWHCRCAMsbtpBLbg1FLq7xo1BaCM0y/z46pXv4CGESVWQlOk30","ab"},
	{"$6$saltstring$pClZZISU0lxEwKr1z81EuJdiMLwWncjShXap25hiDGVMnCvlF5zS3ysvBdVRZqPDCdSTj06rwjrLX3bOS1Cak/","abc"},
	{"$6$saltstring$FJJAXr3hydAPJXM311wrzFhzheQ6LJHrufrYl2kBMnRD2pUi6jdS.fSBJ2J1Qfhcz9tPnlJOzeL7aIYi/dytg.","abcd"},
	{"$6$saltstring$XDecvJ/rq8tgbE1Pfuu1cTiZlhnbF5OA/vyP6HRPpDengVqhB38vbZTK/BDfPP6XBgvMzE.q9rj6Ck5blj/FK.","abcde"},
	{"$6$saltstring$hYPEYaHik6xSMGV1lDWhF0EerSUyCsC150POu9ksaftUWKWwV8TuqSeSLZUkUhjGy7cn.max5qd5IPSICeklL1","abcdef"},
	{"$6$saltstring$YBQ5J5EMRuC6k7B2GTsNaXx8u/957XMB.slQmY/lOjKd1zTIQF.ulLmy8O0VnJJ3cV.1pjP.KCgEjjMpz4pnS1","abcdefg"},
	{"$6$saltstring$AQapizZGhnIjtXF8OCvbSxQJBuOKvpzf1solf9b76wXFX0VRkqids5AC4YSibbhMSX0z4463sq1uAd9LvKNuO/","abcdefgh"},
	{"$6$saltstring$xc66FVXO.Zvv5pS02B4bCmJh5FCBAZpqTK3NoFxTU9U5b6BokbHwmeqQfMqrrkB3j9CXhCzgvC/pvoGPM1xgM1","abcdefghi"},
	{"$6$saltstring$Xet3A8EEzzSuL9hZZ31SfDVPT87qz3a.xxcH7eU50aqARlmXywdlfJ.6Cp/TFG1RcguqwrfUbZBbFn1BQ93Kv.","abcdefghij"},

	{"$6$saltstring$MeML1shJ8psyh5R9YJUZNYNqKzYeBvIsITqc/VqJfUDs8xO5YoUhCn4Db7CXuarMDVkBzIUfYq1d8Tj/T1WBU0","abcdefghijk"},
	{"$6$saltstring$i/3NHph8ZV2klLuOc5yX5kOnJWj9zuWbKiaa/NNEkYpNyamdQS1c7n2XQS3.B2Cs/eVyKwHf62PnOayqLLTOZ.","abcdefghijkl"},
	{"$6$saltstring$l2IxCS4o2S/vud70F1S5Z7H1WE67QFIXCYqskySdLFjjorEJdAnAp1ZqdgfNuZj2orjmeVDTsTXHpZ1IoxSKd.","abcdefghijklm"},
	{"$6$saltstring$PFzjspQs/CDXWALauDTav3u5bHB3n21xWrfwjnjpFO5eM5vuP0qKwDCXmlyZ5svEgsIH1oiZiGlRqkcBP5PiB.","abcdefghijklmn"},
	{"$6$saltstring$rdREv5Pd9C9YGtg.zXEQMb6m0sPeq4b6zFW9oWY9w4ZltmjH3yzMLgl9iBuez9DFFUvF5nJH3Y2xidiq1dH9M.", "abcdefghijklmno"},
#endif
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
  inbuffer=(crypt_sha512_password*)mem_calloc(MAX_KEYS_PER_CRYPT*sizeof(crypt_sha512_password));
  outbuffer=(crypt_sha512_hash*)mem_alloc(MAX_KEYS_PER_CRYPT*sizeof(crypt_sha512_hash));
  check_mem_allocation(inbuffer,outbuffer);
  //Initialize CUDA
  cuda_init();
}

static void *salt(char *ciphertext)
{
	int end = 0, i, len = strlen(ciphertext);
	static unsigned char ret[50];

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
	_salt.rounds = ROUNDS_DEFAULT;
	memcpy(currentsalt,s,len+1);

	if (strncmp((char *) "$6$", (char *) currentsalt, 3) == 0)
		offset += 3;

	if (strncmp((char *) currentsalt + offset, (char *) "rounds=", 7) == 0) {
		const char *num = currentsalt + offset + 7;
		char *endp;
		unsigned long int srounds = strtoul(num, &endp, 10);

		if (*endp == '$') {
			endp += 1;
			_salt.rounds =
			    MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
		}
		offset = endp - currentsalt;
	}
	memcpy(_salt.salt, currentsalt + offset, 16);
	_salt.saltlen = strlen(_salt.salt);
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


static void gpu_crypt_all(int count)
{
	sha512_crypt_gpu(inbuffer, outbuffer, &_salt, count);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;

	gpu_crypt_all(count);
	return count;
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
	uint32_t i;
	uint64_t b = ((uint64_t *) binary)[0];
	for (i = 0; i < count; i++)
		if (b == outbuffer[i].v[0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint64_t *t = (uint64_t *) binary;
	for (i = 0; i < 8; i++) {
		if (t[i] != outbuffer[index].v[i])
			return 0;
	}
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
	crypt_sha512_salt *sha512crypt_salt;

	sha512crypt_salt = salt;
	return (unsigned int)sha512crypt_salt->rounds;
}
#endif


struct fmt_main fmt_cuda_cryptsha512 = {
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
			"iteration count"
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
