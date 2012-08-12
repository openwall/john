/* GPG cracker patch for JtR. Hacked together during Monsoon of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and is based on,
 *
 * pgpry - PGP private key recovery
 * Copyright (C) 2010 Jonas Gehring
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/> */

#include <string.h>
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "md5.h"
#include "rc4.h"
#include "pdfcrack_md5.h"
#include <openssl/aes.h>
#include <assert.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/bn.h>
#include "sha2.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL        "gpg"
#define FORMAT_NAME         "OpenPGP / GnuPG Secret Key"
#define ALGORITHM_NAME      "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    -1000
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

#if defined (_OPENMP)
static int omp_t = 1;
#endif

#define KEYBUFFER_LENGTH 8192
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

// Minimum number of bits when checking the first BN
#define MIN_BN_BITS 64

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

enum {
	SPEC_SIMPLE = 0,
	SPEC_SALTED = 1,
	SPEC_ITERATED_SALTED = 3
};


enum {
        PKA_UNKOWN = 0,
        PKA_RSA_ENCSIGN = 1,
        PKA_DSA = 17
};

enum {
        CIPHER_UNKOWN = -1,
        CIPHER_CAST5 = 3,
        CIPHER_BLOWFISH = 4,
        CIPHER_AES128 = 7,
        CIPHER_AES192 = 8,
        CIPHER_AES256 = 9
};

enum {
        HASH_UNKOWN = -1,
        HASH_MD5 = 1,
        HASH_SHA1 = 2
};

static struct custom_salt {
	int datalen;
	unsigned char data[4096];
	char spec;
	char pk_algorithm;
	char hash_algorithm;
	char cipher_algorithm;
	int usage;
	int bits;
	unsigned char salt[8];
	unsigned char iv[16];
	int ivlen;
	int count;
	void (*s2kfun)(char *, unsigned char*, int);
} *cur_salt;



// Returns the block size (in bytes) of a given cipher
static uint32_t blockSize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_BLOCK;
		case CIPHER_BLOWFISH:
			return BF_BLOCK;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256:
			return AES_BLOCK_SIZE;
		default: break;
	}
	return 0;
}

// Returns the key size (in bytes) of a given cipher
static uint32_t keySize(char algorithm)
{
	switch (algorithm) {
		case CIPHER_CAST5:
			return CAST_KEY_LENGTH;
		case CIPHER_BLOWFISH:
			return 16;
		case CIPHER_AES128:
			return 16;
		case CIPHER_AES192:
			return 24;
		case CIPHER_AES256:
			return 32;
		default: break;
	}
	return 0;
}

// Returns the digest size (in bytes) of a given hash algorithm
static uint32_t digestSize(char algorithm)
{
	switch (algorithm) {
		case HASH_MD5:
			return 16;
		case HASH_SHA1:
			return 20;
		default: break;
	}
	return 0;
}

static struct fmt_tests gpg_tests[] = {
	{"$gpg$*1*348*1024*e5fbff62d94b41de7fc9f3dd93685aa6e03a2c0fcd75282b25892c74922ec66c7327933087304d34d1f5c0acca5659b704b34a67b0d8dedcb53a10aee14c2615527696705d3ab826d53af457b346206c96ef4980847d02129677c5e21045abe1a57be8c0bf7495b2040d7db0169c70f59994bba4c9a13451d38b14bd13d8fe190cdc693ee207d8adfd8f51023b7502c7c8df5a3c46275acad6314d4d528df37896f7b9e53adf641fe444e18674d59cf46d5a6dffdc2f05e077346bf42fe35937e95f644a58a2370012d993c5008e6d6ff0c66c6d0d0b2f1c22961b6d12563a117897675f6b317bc71e4f2dbf6b9fff23186da2724a584d70401136e8c500784df462ea6548db4eecc782e79afe52fd8c1106c7841c085b8d44465d7a1910161d6c707a377a72f85c39fcb4ee58e6b2f617b6c4b173a52f171854f0e1927fa9fcd9d5799e16d840f06234698cfc333f0ad42129e618c2b9c5b29b17b7*3*254*2*3*8*7353cf09958435f9*9961472*efadea6cd5f3e5a7", "openwall"},
	{"$gpg$*1*668*2048*97b296b60904f6d505344b5b0aa277b0f40de05788a39cd9c39b14a56b607bd5db65e8da6111149a1725d06a4b52bdddf0e467e26fe13f72aa5570a0ea591eec2e24d3e9dd7534f26ec9198c8056ea1c03a88161fec88afd43474d31bf89756860c2bc6a6bc9e2a4a2fc6fef30f8cd2f74da6c301ccd5863f3240d1a2db7cbaa2df3a8efe0950f6200cbc10556393583a6ebb2e041095fc62ae3a9e4a0c5c830d73faa72aa8167b7b714ab85d927382d77bbfffb3f7c8184711e81cf9ec2ca03906e151750181500238f7814d2242721b2307baa9ea66e39b10a4fdad30ee6bff50d79ceac604618e74469ae3c80e7711c16fc85233a9eac39941a564b38513c1591502cde7cbd47a4d02a5d7d5ceceb7ff920ee40c29383bd7779be1e00b60354dd86ca514aa30e8f1523efcffdac1292198fe96983cb989a259a4aa475ed9b4ce34ae2282b3ba0169b2e82f9dee476eff215db33632cdcc72a65ba2e68d8e3f1fed90aaa68c4c886927b733144fb7225f1208cd6a108e675cc0cb11393db7451d883abb6adc58699393b8b7b7e19c8584b6fc95720ced39eabaa1124f423cc70f38385c4e9c4b4eeb39e73e891da01299c0e6ce1e97e1750a5c615e28f486c6a0e4da52c15285e7cf26ac859f5f4190e2804ad81ba4f8403e6358fbf1d48c7d593c3bac20a403010926877db3b9d7d0aaacd713a2b9833aff88d1e6b4d228532a66fe68449ad0d706ca7563fe8c2ec77062cc33244a515f2023701c052f0dd172b7914d497fdaefabd91a199d6cb2b62c71472f52c65d6a67d97d7713d39e91f347d2bc73b421fb5c6c6ba028555e5a92a535aabf7a4234d6ea8a315d8e6dcc82087cc76ec8a7b2366cecf176647538968e804541b79a1b602156970d1b943eb2641f2b123e45d7cace9f2dc84b704938fa8c7579a859ef87eca46*3*254*2*3*8*d911a3f73b050340*2097152*347e15bee29eb77d", "password"},
	{NULL}
};

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc_tiny(cracked_size, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$gpg$", 5);
}

static void S2KSimpleSHA1Generator(char *password, unsigned char *key, int length)
{
	SHA_CTX ctx;
	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		SHA1_Update(&ctx, password, strlen(password));
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}

static void S2KSimpleMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		MD5_Update(&ctx, password, strlen(password));
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}


void S2KSaltedSHA1Generator(char *password, unsigned char *key, int length)
{
	SHA_CTX ctx;
	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		SHA1_Update(&ctx, cur_salt->salt, 8);
		SHA1_Update(&ctx, password, strlen(password));
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}

void S2KSaltedMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	int i, j;

	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		MD5_Update(&ctx, cur_salt->salt, 8);
		MD5_Update(&ctx, password, strlen(password));
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}

static void S2KItSaltedSHA1Generator(char *password, unsigned char *key, int length)
{
	unsigned char keybuf[KEYBUFFER_LENGTH];
	SHA_CTX ctx;
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	memcpy(keybuf, cur_salt->salt, 8);

	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		SHA1_Init(&ctx);
		for (j = 0; j < i; j++) {
			SHA1_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}
		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + 8, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = cur_salt->count / bs;
		while (n-- > 0) {
			SHA1_Update(&ctx, keybuf, bs);
		}
		SHA1_Update(&ctx, keybuf, cur_salt->count % bs);
		SHA1_Final(key + (i * SHA_DIGEST_LENGTH), &ctx);
	}
}



static void S2KItSaltedMD5Generator(char *password, unsigned char *key, int length)
{
	MD5_CTX ctx;
	unsigned char keybuf[KEYBUFFER_LENGTH];
	int i, j;
	int32_t tl;
	int32_t mul;
	int32_t bs;
	uint8_t *bptr;
	int32_t n;

	uint32_t numHashes = (length + MD5_DIGEST_LENGTH - 1) / MD5_DIGEST_LENGTH;
	// TODO: This is not very efficient with multiple hashes
	for (i = 0; i < numHashes; i++) {
		MD5_Init(&ctx);
		for (j = 0; j < i; j++) {
			MD5_Update(&ctx, "\0", 1);
		}
		// Find multiplicator
		tl = strlen(password) + 8;
		mul = 1;
		while (mul < tl && ((64 * mul) % tl)) {
			++mul;
		}

		// Try to feed the hash function with 64-byte blocks
		bs = mul * 64;
		bptr = keybuf + tl;
		n = bs / tl;
		memcpy(keybuf + 8, password, strlen(password));
		while (n-- > 1) {
			memcpy(bptr, keybuf, tl);
			bptr += tl;
		}
		n = cur_salt->count / bs;
		while (n-- > 0) {
			MD5_Update(&ctx, keybuf, bs);
		}
		MD5_Update(&ctx, keybuf, cur_salt->count % bs);
		MD5_Final(key + (i * MD5_DIGEST_LENGTH), &ctx);
	}
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 5;	/* skip over "$gpg$" marker */
	p = strtok(ctcopy, "*");
	cs.pk_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.datalen = atoi(p);
	p = strtok(NULL, "*");
	cs.bits = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.datalen; i++)
		cs.data[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.spec = atoi(p);
	p = strtok(NULL, "*");
	cs.usage = atoi(p);
	p = strtok(NULL, "*");
	cs.hash_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.cipher_algorithm = atoi(p);
	p = strtok(NULL, "*");
	cs.ivlen = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.ivlen; i++)
		cs.iv[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.count = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < 8; i++)
		cs.salt[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	free(keeptr);

	// Set up the key generator
	switch(cs.spec) {
		case SPEC_ITERATED_SALTED:
			{
				switch(cs.hash_algorithm) {
					case HASH_SHA1:
						cs.s2kfun = S2KItSaltedSHA1Generator;
						break;
					case HASH_MD5:
						cs.s2kfun = S2KItSaltedMD5Generator;
						break;
					default: break;
				}
			}
			break;
		case SPEC_SALTED:
			{
				switch(cs.hash_algorithm) {
					case HASH_SHA1:
						cs.s2kfun = S2KSaltedSHA1Generator;
						break;
					case HASH_MD5:
						cs.s2kfun = S2KSaltedMD5Generator;
						break;
					default: break;
				}
			}
			break;
		case SPEC_SIMPLE:
			{
				switch(cs.hash_algorithm) {
					case HASH_SHA1:
						cs.s2kfun = S2KSimpleSHA1Generator;
						break;
					case HASH_MD5:
						cs.s2kfun = S2KSimpleMD5Generator;
						break;
					default: break;
				}
			}
			break;
	}
	assert(cs.s2kfun != NULL);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
}

static void gpg_set_key(char *key, int index)
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

static int check(unsigned char *keydata, int ks)
{
	// Decrypt first data block in order to check the first two bits of
	// the MPI. If they are correct, there's a good chance that the
	// password is correct, too.
	unsigned char ivec[32];
	unsigned char out[4096];
	int tmp = 0;
        uint32_t num_bits;
	int checksumOk;
	int i;

	// Quick Hack
	memcpy(ivec, cur_salt->iv, blockSize(cur_salt->cipher_algorithm));
	switch (cur_salt->cipher_algorithm) {
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(cur_salt->data, out, CAST_BLOCK, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(cur_salt->data, out, BF_BLOCK, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(cur_salt->data, out, AES_BLOCK_SIZE, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		default:
				    break;
	}
	num_bits = ((out[0] << 8) | out[1]);
	if (num_bits < MIN_BN_BITS || num_bits > cur_salt->bits) {
		return 0;
	}
	// Decrypt all data
	memcpy(ivec, cur_salt->iv, blockSize(cur_salt->cipher_algorithm));
	tmp = 0;
	switch (cur_salt->cipher_algorithm) {
		case CIPHER_CAST5: {
					   CAST_KEY ck;
					   CAST_set_key(&ck, ks, keydata);
					   CAST_cfb64_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, CAST_DECRYPT);
				   }
				   break;
		case CIPHER_BLOWFISH: {
					      BF_KEY ck;
					      BF_set_key(&ck, ks, keydata);
					      BF_cfb64_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, BF_DECRYPT);
				      }
				      break;
		case CIPHER_AES128:
		case CIPHER_AES192:
		case CIPHER_AES256: {
					    AES_KEY ck;
					    AES_set_encrypt_key(keydata, ks * 8, &ck);
					    AES_cfb128_encrypt(cur_salt->data, out, cur_salt->datalen, &ck, ivec, &tmp, AES_DECRYPT);
				    }
				    break;
		default:
				    break;
	}

	// Verify
	checksumOk = 0;
	switch (cur_salt->usage) {
		case 254: {
				  uint8_t checksum[SHA_DIGEST_LENGTH];
				  SHA_CTX ctx;
				  SHA1_Init(&ctx);
				  SHA1_Update(&ctx, out, cur_salt->datalen - SHA_DIGEST_LENGTH);
				  SHA1_Final(checksum, &ctx);
				  if (memcmp(checksum, out + cur_salt->datalen - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0) {
					  checksumOk = 1;
				  }
			  } break;
		case 0:
		case 255: {
				  uint16_t sum = 0;
				  for (i = 0; i < cur_salt->datalen - 2; i++) {
					  sum += out[i];
				  }
				  if (sum == ((out[cur_salt->datalen - 2] << 8) | out[cur_salt->datalen - 1])) {
					  checksumOk = 1;
				  }
			  } break;
		default:
			  break;
	}
	// If the checksum is ok, try to parse the first MPI of the private key
	if (checksumOk) {
		BIGNUM *b = NULL;
		uint32_t blen = (num_bits + 7) / 8;
		if (blen < cur_salt->datalen && ((b = BN_bin2bn(out + 2, blen, NULL)) != NULL)) {
			BN_free(b);
			return 1;
		}
	}
	return 0;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		// allocate string2key buffer
		int res;
		int ks = keySize(cur_salt->cipher_algorithm);
		int ds = digestSize(cur_salt->hash_algorithm);
		unsigned char keydata[ds * ((ks + ds- 1) / ds)];
		cur_salt->s2kfun(saved_key[index], keydata, ks);
		res = check(keydata, ks);
		if(res)
			any_cracked = cracked[index] = 1;
	}
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return cracked[index];
}

struct fmt_main fmt_gpg = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		gpg_tests
	},
	{
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		gpg_set_key,
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
