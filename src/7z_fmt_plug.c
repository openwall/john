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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sevenzip;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sevenzip);
#else

#include <string.h>
#include <errno.h>
#include "aes.h"
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "johnswap.h"
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
#define BENCHMARK_COMMENT	" (512K iterations)"
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		0
#define BINARY_ALIGN		1
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		4
#ifndef OMP_SCALE
#define OMP_SCALE               1 // tuned on core i7
#endif

#ifdef SIMD_COEF_32
#include "simd-intrinsics.h"

#define NBKEYS     (SIMD_COEF_32*SIMD_PARA_SHA256)
#define GETPOS(i,idx) ( (idx&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*4*SIMD_COEF_32 )
#define HASH_IDX_IN(idx)  (((unsigned int)idx&(SIMD_COEF_32-1))+(unsigned int)idx/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32)
#define HASH_IDX_OUT(idx) (((unsigned int)idx&(SIMD_COEF_32-1))+(unsigned int)idx/SIMD_COEF_32*8*SIMD_COEF_32)

#define ALGORITHM_NAME		"AES SHA256" SHA256_ALGORITHM_NAME
#define PLAINTEXT_LENGTH	28
#define MIN_KEYS_PER_CRYPT	NBKEYS
#define MAX_KEYS_PER_CRYPT	NBKEYS
#else
#define ALGORITHM_NAME		"SHA256 AES 32/" ARCH_BITS_STR
#define PLAINTEXT_LENGTH	125
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

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

static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
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
	saved_key = mem_calloc(self->params.max_keys_per_crypt + 1,
	                       sizeof(*saved_key));
	saved_len = mem_calloc(self->params.max_keys_per_crypt + 1,
	                       sizeof(*saved_len));
	cracked   = mem_calloc(self->params.max_keys_per_crypt + 1,
	                       sizeof(*cracked));
	CRC32_Init(&crc);
#ifdef SIMD_COEF_32
	if (pers_opts.target_enc == UTF_8)
		self->params.plaintext_length = PLAINTEXT_LENGTH * 3;
#endif
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len)
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int len, NumCyclesPower;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (strlen(p) != 1 || '0' != *p)     /* p must be "0" */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* NumCyclesPower */
		goto err;
	if (strlen(p) > 2)
		goto err;
	if (!isdec(p))
		goto err;
	NumCyclesPower = atoi(p);
	if (NumCyclesPower > 24)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt length */
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > 16) /* salt length */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv length */
		goto err;
	if (strlen(p) > 2)
		goto err;
	if (!isdec(p))
		goto err;
	len = atoi(p);
	if (len > 16) /* iv length */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iv */
		goto err;
	if (!ishex(p))
		goto err;
	if (strlen(p) / 2 > len && strcmp(p+len*2, "0000000000000000"))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* crc */
		goto err;
	if (!isdecu(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* data length */
		goto err;
	if(!isdec(p))
		goto err;
	len = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* unpacksize */
		goto err;
	if (!isdec(p))	/* no way to validate, other than atoi() works for it */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* data */
		goto err;
	if (strlen(p) / 2 != len)	/* validates data_len atoi() */
		goto err;
	if (!ishex(p))
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

	memset(cs, 0, SALT_SIZE);

	ctcopy += 4;
	p = strtokm(ctcopy, "$");
	cs->type = atoi(p);
	p = strtokm(NULL, "$");
	cs->NumCyclesPower = atoi(p);
	p = strtokm(NULL, "$");
	cs->SaltSize = atoi(p);
	p = strtokm(NULL, "$"); /* salt */
	p = strtokm(NULL, "$");
	cs->ivSize = atoi(p);
	p = strtokm(NULL, "$"); /* iv */
	for (i = 0; i < cs->ivSize; i++)
		cs->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); /* crc */
	cs->crc = atou(p); /* unsigned function */
	p = strtokm(NULL, "$");
	cs->length = atoi(p);
	p = strtokm(NULL, "$");
	cs->unpacksize = atoi(p);
	p = strtokm(NULL, "$"); /* crc */
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

static int sevenzip_decrypt(unsigned char *derived_key)
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
	out = mem_alloc(cur_salt->length);
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
			MEM_FREE(out);
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
			MEM_FREE(out);
#endif
		return 0;
	}

	// test 1, CRC test
	CRC32_Init(&crc);
	CRC32_Update(&crc, out, cur_salt->unpacksize);
	CRC32_Final(crc_out, crc);
	ccrc =  _crc_out.crci; // computed CRC
#if !ARCH_LITTLE_ENDIAN
	ccrc = JOHNSWAP(ccrc);
#endif
	if (ccrc == cur_salt->crc) {
#ifdef _MSC_VER
		MEM_FREE(out);
#endif
		return 0;  // XXX don't be too eager!
	}

	// XXX test 2, "well-formed folder" test
	if (validFolder(out)) {
		printf("validFolder check ;-)\n");
#ifdef _MSC_VER
		MEM_FREE(out);
#endif
		return 0;
	}

#ifdef _MSC_VER
	MEM_FREE(out);
#endif
	return -1;
}

#ifdef SIMD_COEF_32
static void sevenzip_kdf(int *indices, unsigned char *master)
{
	int i, j;
	long long round, rounds = (long long) 1 << cur_salt->NumCyclesPower;
	uint32_t buf_in[2][NBKEYS*16], buf_out[NBKEYS*8] JTR_ALIGN(MEM_ALIGN_SIMD);
	int pw_len = saved_len[indices[0]];
	int tot_len = (pw_len + 8)*rounds;
	int acc_len = 0;
#if !ARCH_LITTLE_ENDIAN
	unsigned char temp[8] = { 0,0,0,0,0,0,0,0 };
#endif

	int cur_buf = 0;
	int fst_blk = 1;

	// it's assumed rounds is divisible by 64
	for (round = 0; round < rounds; ++round) {
		// copy password to vector buffer
		for (i = 0; i < NBKEYS; ++i) {
			UTF16 *buf = saved_key[indices[i]];
			for (j = 0; j < pw_len; ++j) {
				int len = acc_len + j;
				char *in = (char*)buf_in[(len & 64)>>6];
				in[GETPOS(len%64, i)] = ((char*)buf)[j];
			}

			for (j = 0; j < 8; ++j) {
				int len = acc_len + pw_len + j;
				char *in = (char*)buf_in[(len & 64)>>6];
#if ARCH_LITTLE_ENDIAN
				in[GETPOS(len%64, i)] = ((char*)&round)[j];
#else
				in[GETPOS(len%64, i)] = temp[j];
#endif
			}
		}
#if !ARCH_LITTLE_ENDIAN
		for (j = 0; j < 8; j++)
			if (++(temp[j]) != 0)
				break;
#endif
		acc_len += (pw_len + 8);

		// swap out and compute digest on the filled buffer
		if ((acc_len & 64) != (cur_buf << 6)) {
			if (fst_blk)
				SIMDSHA256body(buf_in[cur_buf], buf_out, NULL, SSEi_MIXED_IN);
			else
				SIMDSHA256body(buf_in[cur_buf], buf_out, buf_out, SSEi_MIXED_IN | SSEi_RELOAD);
			fst_blk = 0;
			cur_buf = 1 - cur_buf;
		}
	}

	// padding
	memset(buf_in[0], 0, sizeof(buf_in[0]));
	for (i = 0; i < NBKEYS; ++i) {
		buf_in[0][HASH_IDX_IN(i)] = (0x80 << 24);
		buf_in[0][HASH_IDX_IN(i) + 15*SIMD_COEF_32] = tot_len*8;
	}
	SIMDSHA256body(buf_in[0], buf_out, buf_out, SSEi_MIXED_IN | SSEi_RELOAD);

	// copy out result
	for (i = 0; i < NBKEYS; ++i) {
		uint32_t *m = (uint32_t*)&master[i*32];
		for (j = 0; j < 32/4; ++j)
			m[j] = JOHNSWAP(buf_out[HASH_IDX_OUT(i) + j*SIMD_COEF_32]);
	}
}
#else
static void sevenzip_kdf(int index, unsigned char *master)
{
	long long rounds = (long long) 1 << cur_salt->NumCyclesPower;
	long long round;
#if !ARCH_LITTLE_ENDIAN
	int i;
	unsigned char temp[8] = { 0,0,0,0,0,0,0,0 };
#endif
	SHA256_CTX sha;

	/* kdf */
        SHA256_Init(&sha);
	for (round = 0; round < rounds; round++) {
		//SHA256_Update(&sha, "", cur_salt->SaltSize);
		SHA256_Update(&sha, (char*)saved_key[index], saved_len[index]);
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
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef SIMD_COEF_32
	int len;
	int *indices = mem_calloc(count*NBKEYS, sizeof(*indices));
	int tot_todo = 0;
	for (len = 0; len < PLAINTEXT_LENGTH*2; len += 2) {
		for (index = 0; index < count; ++index) {
			if (saved_len[index] == len)
				indices[tot_todo++] = index;
		}
		while (tot_todo % NBKEYS)
			indices[tot_todo++] = count;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < tot_todo; index += NBKEYS)
	{
		int j;
		unsigned char master[NBKEYS*32];
		sevenzip_kdf(indices + index, master);

		/* do decryption and checks */
		for (j = 0; j < NBKEYS; ++j) {
			if (sevenzip_decrypt(&master[j*32]) == 0)
				cracked[indices[index + j]] = 1;
			else
				cracked[indices[index + j]] = 0;
		}
	}
	MEM_FREE(indices);
#else
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
#endif
	{
		/* derive key */
		unsigned char master[32];
		sevenzip_kdf(index, master);

		/* do decryption and checks */
		if(sevenzip_decrypt(master) == 0)
			cracked[index] = 1;
		else
			cracked[index] = 0;
	}
#endif // SIMD_COEF_32
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
	/* Convert key to utf-16-le format (--encoding aware) */
	int len;
	len = enc_to_utf16(saved_key[index], PLAINTEXT_LENGTH, (UTF8*)key, strlen(key));
	if (len <= 0) {
		key[-len] = 0; // match truncation
		len = strlen16(saved_key[index]);
	}
	len *= 2;
	saved_len[index] = len;
}

static char *get_key(int index)
{
	return (char*)utf16_to_enc(saved_key[index]);
}

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int)(1 << my_salt->NumCyclesPower);
}

struct fmt_main fmt_sevenzip = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_NOT_EXACT | FMT_UNICODE | FMT_UTF8,
		{
			"iteration count",
		},
		sevenzip_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
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

#endif /* plugin stanza */
