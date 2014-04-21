/* 7-Zip cracker patch for JtR. Hacked together during June of 2013 by Dhiru
 * Kholia <dhiru at openwall.com>. Unicode support and other fixes by magnum.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>
 * and Copyright (c) 2013 magnum, and it is hereby released to the general
 * public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include <string.h>
#include <errno.h>
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "sha2.h"
#include "crc32.h"
#include "unicode.h"
#include "memdbg.h"

#define FORMAT_LABEL		"7z"
#define FORMAT_NAME		"7-Zip"
#define FORMAT_TAG		"$7z$"
#define TAG_LENGTH		4
#define ALGORITHM_NAME		"(experimental) SHA256 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define PLAINTEXT_LENGTH	125
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define OMP_SCALE               1 // tuned on core i7

#define BIG_ENOUGH 		(8192 * 32)

static struct fmt_tests sevenzip_tests[] = {
	/* CRC checks passes for these hashes */
	{"$7z$0$19$0$1122$8$d1f50227759415890000000000000000$1412385885$112$112$5e5b8b734adf52a64c541a5a5369023d7cccb78bd910c0092535dfb013a5df84ac692c5311d2e7bbdc580f5b867f7b5dd43830f7b4f37e41c7277e228fb92a6dd854a31646ad117654182253706dae0c069d3f4ce46121d52b6f20741a0bb39fc61113ce14d22f9184adafd6b5333fb1", "password"},
	{"$7z$0$19$0$1122$8$a264c94f2cd72bec0000000000000000$725883103$112$108$64749c0963e20c74602379ca740165b9511204619859d1914819bc427b7e5f0f8fc67f53a0b53c114f6fcf4542a28e4a9d3914b4bc76baaa616d6a7ec9efc3f051cb330b682691193e6fa48159208329460c3025fb273232b82450645f2c12a9ea38b53a2331a1d0858813c8bf25a831", "openwall"},
	/* padding check passes for these hashes */
	{"$7z$0$19$0$1122$8$732b59fd26896e410000000000000000$2955316379$192$183$7544a3a7ec3eb99a33d80e57907e28fb8d0e140ec85123cf90740900429136dcc8ba0692b7e356a4d4e30062da546a66b92ec04c64c0e85b22e3c9a823abef0b57e8d7b8564760611442ecceb2ca723033766d9f7c848e5d234ca6c7863a2683f38d4605322320765938049305655f7fb0ad44d8781fec1bf7a2cb3843f269c6aca757e509577b5592b60b8977577c20aef4f990d2cb665de948004f16da9bf5507bf27b60805f16a9fcc4983208297d3affc4455ca44f9947221216f58c337f", "password"},
	/* not supported hashes, will require validFolder check */
	// {"$7z$0$19$0$1122$8$5fdbec1569ff58060000000000000000$2465353234$112$112$58ba7606aafc7918e3db7f6e0920f410f61f01e9c1533c40850992fee4c5e5215bc6b4ea145313d0ac065b8ec5b47d9fb895bb7f97609be46107d71e219544cfd24b52c2ecd65477f72c466915dcd71b80782b1ac46678ab7f437fd9f7b8e9d9fad54281d252de2a7ae386a65fc69eda", "password"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;

static struct custom_salt {
	int NumCyclesPower;
	int SaltSize;
	int ivSize;
	int type;
	unsigned char data[BIG_ENOUGH];
	unsigned char iv[16];
	unsigned char salt[16];
	unsigned int crc;
	int length;     /* used in decryption */
	int unpacksize; /* used in CRC calculation */
} *cur_salt;

static void init(struct fmt_main *self)
{
	CRC32_t crc;
#if defined (_OPENMP)
	int omp_t = 1;

	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	CRC32_Init(&crc);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, type, NumCyclesPower;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtok(ctcopy, "$")) == NULL)
		goto err;
	if (strlen(p) > 1)
		goto err;
	type = atoi(p);
	if (type != 0)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL) /* NumCyclesPower */
		goto err;
	if (strlen(p) > 2)
		goto err;
	NumCyclesPower = atoi(p);
	if (NumCyclesPower > 24 || NumCyclesPower < 0) // FIXME: 0 is probably not allowed
		goto err;
	if ((p = strtok(NULL, "$")) == NULL) /* salt length */
		goto err;
	if (strlen(p) > 2)
		goto err;
	len = atoi(p);
	if(len > 16 || len < 0) /* salt length */	// FIXME: why is 0 allowed here?
		goto err;
	if ((p = strtok(NULL, "$")) == NULL) /* salt */
		goto err;
	if ((p = strtok(NULL, "$")) == NULL) /* iv length */
		goto err;
	if (strlen(p) > 2)
		goto err;
	len = atoi(p);
	if(len < 0 || len > 16) /* iv length */
		goto err;
	if ((p = strtok(NULL, "$")) == NULL) /* iv */
		goto err;
	// FIXME: ishex check missing, and p+(2*len) should be "0000..."
	if ((p = strtok(NULL, "$")) == NULL) /* crc */
		goto err;
	// FIXME: anything known about min/max length and value of crc?
	if ((p = strtok(NULL, "$")) == NULL) /* data length */
		goto err;
	// FIXME: is data length really an integer, or can it be long?
	//        as long as "len = atoi(p);" is used, max. length is <= 10
	if(strlen(p) > 10)	// FIXME: shouldn't long instead of int be allowed here?
		goto err;
	len = atoi(p);		// FIXME: undefined behavior
	if (len >= INT_MAX)	// FIXME: atoi() might return INT_MAX in case of overflow
		goto err;
	if (len < 0)
		goto err;
	if ((p = strtok(NULL, "$")) == NULL) /* unpacksize */
		goto err;
	if ((p = strtok(NULL, "$")) == NULL) /* data */
		goto err;
	if (strlen(p) != len * 2)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;

	static union {
		struct custom_salt _cs;
		ARCH_WORD_32 dummy;
	} un;
	struct custom_salt *cs = &(un._cs);

	ctcopy += 4;
	p = strtok(ctcopy, "$");
	cs->type = atoi(p);
	p = strtok(NULL, "$");
	cs->NumCyclesPower = atoi(p);
	p = strtok(NULL, "$");
	cs->SaltSize = atoi(p);
	p = strtok(NULL, "$"); /* salt */
	p = strtok(NULL, "$");
	cs->ivSize = atoi(p);
	p = strtok(NULL, "$"); /* iv */
	for (i = 0; i < cs->ivSize; i++)
		cs->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "$"); /* crc */
	cs->crc = atoi(p);
	p = strtok(NULL, "$");
	cs->length = atoi(p);
	p = strtok(NULL, "$");
	cs->unpacksize = atoi(p);
	p = strtok(NULL, "$"); /* crc */
	for (i = 0; i < cs->length; i++)
		cs->data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

// XXX port Python code to C *OR* use code from LZMA SDK
static int validFolder(unsigned char *data)
{
	// int numcoders = self._read64Bit(file)
	return 0;
}

static int sevenzip_decrypt(unsigned char *derived_key, unsigned char *data)
{
#ifdef _MSC_VER
	unsigned char *out;
#else
	unsigned char out[cur_salt->length];
#endif
	AES_KEY akey;
	unsigned char iv[16];
	union {
		unsigned char crcc[4];
		unsigned int crci;
	} _crc_out;
	unsigned char *crc_out = _crc_out.crcc;
	unsigned int ccrc;
	CRC32_t crc;
	int i;
	int nbytes, margin;

#ifdef _MSC_VER
	out = malloc(cur_salt->length);
#endif
	memcpy(iv, cur_salt->iv, 16);

	if(AES_set_decrypt_key(derived_key, 256, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed in crypt!\n");
	}
	AES_cbc_encrypt(cur_salt->data, out, cur_salt->length, &akey, iv, AES_DECRYPT);

	/* various verifications tests */

	// test 0, padding check, bad hack :-(
	margin = nbytes = cur_salt->length - cur_salt->unpacksize;
	i = cur_salt->length - 1;
	while (nbytes > 0) {
		if (out[i] != 0) {
#ifdef _MSC_VER
			free(out);
#endif
			return -1;
		}
		nbytes--;
		i--;
	}
	if (margin > 7) {
		// printf("valid padding test ;-)\n");
		// print_hex(out, cur_salt->length);
#ifdef _MSC_VER
			free(out);
#endif
		return 0;
	}

	// test 1, CRC test
	CRC32_Init(&crc);
	CRC32_Update(&crc, out, cur_salt->unpacksize);
	CRC32_Final(crc_out, crc);
	ccrc =  _crc_out.crci; // computed CRC
	if (ccrc == cur_salt->crc) {
#ifdef _MSC_VER
		free(out);
#endif
		return 0;  // XXX don't be too eager!
	}

	// XXX test 2, "well-formed folder" test
	if (validFolder(out)) {
		printf("validFolder check ;-)\n");
#ifdef _MSC_VER
		free(out);
#endif
		return 0;
	}

#ifdef _MSC_VER
	free(out);
#endif
	return -1;
}



void sevenzip_kdf(UTF8 *password, unsigned char *master)
{
	int len;
	long long rounds = (long long) 1 << cur_salt->NumCyclesPower;
	long long round;
	UTF16 buffer[PLAINTEXT_LENGTH + 1];
#if !ARCH_LITTLE_ENDIAN
	int i;
	unsigned char temp[8] = { 0,0,0,0,0,0,0,0 };
#endif
	SHA256_CTX sha;

	/* Convert password to utf-16-le format (--encoding aware) */
	len = enc_to_utf16(buffer, PLAINTEXT_LENGTH, password, strlen((char*)password));
	if (len <= 0) {
		password[-len] = 0; // match truncation
		len = strlen16(buffer);
	}
	len *= 2;

	/* kdf */
        SHA256_Init(&sha);
	for (round = 0; round < rounds; round++) {
		//SHA256_Update(&sha, "", cur_salt->SaltSize);
		SHA256_Update(&sha, (char*)buffer, len);
#if ARCH_LITTLE_ENDIAN
		SHA256_Update(&sha, (char*)&round, 8);
#else
		SHA256_Update(&sha, temp, 8);
		for (i = 0; i < 8; i++)
			if (++(temp[i]) != 0)
				break;
#endif
	}
	SHA256_Final(master, &sha);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		/* derive key */
		unsigned char master[32];
		sevenzip_kdf((unsigned char*)saved_key[index], master);

		/* do decryption and checks */
		if(sevenzip_decrypt(master, cur_salt->data) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

static void sevenzip_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);

	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

#if FMT_MAIN_VERSION > 11
static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)(1 << my_salt->NumCyclesPower);
}
#endif

struct fmt_main fmt_sevenzip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT | FMT_UNICODE | FMT_UTF8,
#if FMT_MAIN_VERSION > 11
		{
			"iteration count",
		},
#endif
		sevenzip_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{
			iteration_count,
		},
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		sevenzip_set_key,
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
