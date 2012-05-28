/* Office 2007 cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> */

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"
#include "unicode.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               4
#endif

#define FORMAT_LABEL		"office"
#define FORMAT_NAME		"Office"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		16
#define SALT_SIZE		sizeof(*salt_struct)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static struct fmt_tests office_tests[] = {
	{"$office$*2007*20*128*16*8b2c9e8c878844fc842012273be4bea8*aa862168b80d8c45c852696a8bb499eb*a413507fabe2d87606595f987f679ff4b5b4c2cd86511ee967274442287bc600", "Password"},
	{"$office$*2010*100000*128*16*213aefcafd9f9188e78c1936cbb05a44*d5fc7691292ab6daf7903b9a8f8c8441*46bfac7fb87cd43bd0ab54ebc21c120df5fab7e6f11375e79ee044e663641d5e", "myhovercraftisfullofeels"},
	{NULL}
};

static struct custom_salt {
	char unsigned osalt[32]; /* bigger than necessary */
	char unsigned encryptedVerifier[16];
	char unsigned encryptedVerifierHash[32];
	int version;
	int verifierHashSize;
	int keySize;
	int saltSize;
	/* Office 2010 */
	int spinCount;
} *salt_struct;

#if defined (_OPENMP)
static int omp_t = 1;
#endif
/* 3x is needed for worst-case UTF-8 */
static char (*saved_key)[3 * PLAINTEXT_LENGTH + 1];
static int *cracked;

/* Office 2010 */
static unsigned char encryptedVerifierHashInputBlockKey[] = { 0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79 };
static unsigned char encryptedVerifierHashValueBlockKey[] = { 0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e };

static unsigned char *DeriveKey(unsigned char *hashValue)
{
	int i;
	unsigned char derivedKey[64], *X1;
	SHA_CTX ctx;

	// This is step 4a in 2.3.4.7 of MS_OFFCRYPT version 1.0
	// and is required even though the notes say it should be
	// used only when the encryption algorithm key > hash length.
	for (i = 0; i < 64; i++)
		derivedKey[i] = (i < 20 ? 0x36 ^ hashValue[i] : 0x36);
	X1 = (unsigned char *)malloc(20);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, derivedKey, 64);
	SHA1_Final(X1, &ctx);

	if (salt_struct->verifierHashSize > salt_struct->keySize/8)
		return X1;
	for (i = 0; i < 64; i++)
		derivedKey[i] = (i < 30 ? 0x5C ^ hashValue[i] : 0x5C);

	/* TODO: finish up this function */
	return NULL;
}

static unsigned char* GeneratePasswordHashUsingSHA1(char *password)
{
	unsigned char hashBuf[20], *inputBuf, *key, *final;
	/* H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password */
	unsigned char passwordBuf[512] = {0};
	int passwordBufSize;
	int i;
	SHA_CTX ctx;

	/* convert key to UTF-16LE */
	passwordBufSize = enc_to_utf16((UTF16*)passwordBuf, 125, (UTF8*)password, strlen(password));
	if (passwordBufSize < 0)
		passwordBufSize = strlen16((UTF16*)passwordBuf);
	passwordBufSize <<= 1;

	inputBuf = (unsigned char *)malloc(salt_struct->saltSize + passwordBufSize);
	memcpy(inputBuf, salt_struct->osalt, salt_struct->saltSize);
	memcpy(inputBuf + salt_struct->saltSize, passwordBuf, passwordBufSize);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, inputBuf, salt_struct->saltSize + passwordBufSize);
	SHA1_Final(hashBuf, &ctx);
	free(inputBuf);

	/* Generate each hash in turn
	 * H(n) = H(i, H(n-1))
	 * hashBuf = SHA1Hash(i, hashBuf); */
	// Create an input buffer for the hash.  This will be 4 bytes larger than
	// the hash to accommodate the unsigned int iterator value.
	inputBuf = (unsigned char *)malloc(0x14 + 0x04);
	// Create a byte array of the integer and put at the front of the input buffer
	// 1.3.6 says that little-endian byte ordering is expected
	memcpy(inputBuf + 4, hashBuf, 20);
	for (i = 0; i < 50000; i++) {
		*(int *)inputBuf = i; // XXX: size & endianness
		// 'append' the previously generated hash to the input buffer
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
		SHA1_Final(inputBuf + 4, &ctx);
	}
	// Finally, append "block" (0) to H(n)
	// hashBuf = SHA1Hash(hashBuf, 0);
	i = 0;
	memmove(inputBuf, inputBuf + 4, 20);
	memcpy(inputBuf + 20, &i, 4); // XXX: size & endianness
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
	SHA1_Final(hashBuf, &ctx);
	free(inputBuf);

	key = DeriveKey(hashBuf);

	// Should handle the case of longer key lengths as shown in 2.3.4.9
	// Grab the key length bytes of the final hash as the encrypytion key
	final = (unsigned char *)malloc(salt_struct->keySize/8);
	memcpy(final, key, salt_struct->keySize/8);
	free(key);
	return final;
}

static int PasswordVerifier(unsigned char * key)
{
	unsigned char decryptedVerifier[16];
	AES_KEY akey;
	SHA_CTX ctx;
	unsigned char checkHash[20];
	unsigned char decryptedVerifierHash[32];
	int i;

   	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_derypt_key failed!\n");
		return 0;
	}
	AES_ecb_encrypt(salt_struct->encryptedVerifier, decryptedVerifier, &akey, AES_DECRYPT);
	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_derypt_key failed!\n");
		return 0;
	}
	AES_ecb_encrypt(salt_struct->encryptedVerifierHash, decryptedVerifierHash, &akey, AES_DECRYPT);
	AES_ecb_encrypt(salt_struct->encryptedVerifierHash+16, decryptedVerifierHash+16, &akey, AES_DECRYPT);

	/* find SHA1 hash of decryptedVerifier */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decryptedVerifier, 16);
	SHA1_Final(checkHash, &ctx);
	for (i = 0; i < 16; i++)
		if (decryptedVerifierHash[i] != checkHash[i])
			return 0;
	return 1;
}

static void GenerateAgileEncryptionKey(char *password, unsigned char * blockKey, int hashSize, unsigned char *hashBuf)
{
	/* H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password */
	unsigned char passwordBuf[512] = {0};
	int passwordBufSize;
	int i;
	unsigned char *inputBuf;
	SHA_CTX ctx;

	/* convert key to UTF-16LE */
	passwordBufSize = enc_to_utf16((UTF16*)passwordBuf, 125, (UTF8*)password, strlen(password));
	if (passwordBufSize < 0)
		passwordBufSize = strlen16((UTF16*)passwordBuf);
	passwordBufSize <<= 1;

	inputBuf = (unsigned char *)malloc(salt_struct->saltSize + passwordBufSize);
	memcpy(inputBuf, salt_struct->osalt, salt_struct->saltSize);
	memcpy(inputBuf + salt_struct->saltSize, passwordBuf, passwordBufSize);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, inputBuf, salt_struct->saltSize + passwordBufSize);
	SHA1_Final(hashBuf, &ctx);
	free(inputBuf);

	/* Generate each hash in turn
	 * H(n) = H(i, H(n-1))
	 * hashBuf = SHA1Hash(i, hashBuf); */
	// Create an input buffer for the hash.  This will be 4 bytes larger than
	// the hash to accommodate the unsigned int iterator value.
	inputBuf = (unsigned char *)malloc(28);
	// Create a byte array of the integer and put at the front of the input buffer
	// 1.3.6 says that little-endian byte ordering is expected
	memcpy(inputBuf + 4, hashBuf, 20);
	for (i = 0; i < salt_struct->spinCount; i++) {
		*(int *)inputBuf = i; // XXX: size & endianness
		// 'append' the previously generated hash to the input buffer
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
		SHA1_Final(inputBuf + 4, &ctx);
	}
	// Finally, append "block" (0) to H(n)
	memmove(inputBuf, inputBuf + 4, 20);
	memcpy(inputBuf + 20, blockKey, 8);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, inputBuf, 28);
	SHA1_Final(hashBuf, &ctx);
	free(inputBuf);

	// TODO: Fix up the size per the spec
	if (20 < hashSize) {
		// hashBuf = hashBuf.Concat(Enumerable.Repeat(0x36, size - hashBuf.Length)).ToArray();
	}
}

static void DecryptUsingSymmetricKeyAlgorithm(unsigned char *verifierInputKey, unsigned char *encryptedVerifier, unsigned char *decryptedVerifier, int length)
{
	AES_KEY akey;
	unsigned char iv[16];
	memcpy(iv, salt_struct->osalt, 16);
     	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(verifierInputKey, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_derypt_key failed!\n");
	}
	AES_cbc_encrypt(encryptedVerifier, decryptedVerifier, length, &akey, iv, AES_DECRYPT);
}

static void init(struct fmt_main *pFmt)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	cracked = mem_calloc_tiny(sizeof(*cracked) *
			pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	if (options.utf8)
		pFmt->params.plaintext_length = 3 * PLAINTEXT_LENGTH;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$office$", 8);
}

static void *get_salt(char *ciphertext)
{
	int i;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy, *p;
	ctcopy += 9;	/* skip over "$office$*" */
	salt_struct = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	p = strtok(ctcopy, "*");
	salt_struct->version = atoi(p);
	p = strtok(NULL, "*");
	if(salt_struct->version == 2007) {
		salt_struct->verifierHashSize = atoi(p);
	}
	else {
		salt_struct->spinCount = atoi(p);
	}
	p = strtok(NULL, "*");
	salt_struct->keySize = atoi(p);
	p = strtok(NULL, "*");
	salt_struct->saltSize = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < salt_struct->saltSize; i++)
		salt_struct->osalt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		salt_struct->encryptedVerifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		salt_struct->encryptedVerifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	free(keeptr);
	return (void *)salt_struct;
}

static void set_salt(void *salt)
{
	salt_struct = (struct custom_salt *)salt;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		if(salt_struct->version == 2007) {
			unsigned char *encryptionKey = GeneratePasswordHashUsingSHA1(saved_key[index]);
			if (PasswordVerifier(encryptionKey))
				cracked[index] = 1;
			else
				cracked[index] = 0;
		}
		else if (salt_struct->version == 2010) {
			unsigned char verifierInputKey[20], verifierHashKey[20], decryptedVerifierHashInputBytes[16], decryptedVerifierHashBytes[32];
			unsigned char hash[20];
			SHA_CTX ctx;
			GenerateAgileEncryptionKey(saved_key[index], encryptedVerifierHashInputBlockKey, salt_struct->keySize >> 3, verifierInputKey);
			GenerateAgileEncryptionKey(saved_key[index], encryptedVerifierHashValueBlockKey, salt_struct->keySize >> 3, verifierHashKey);
			DecryptUsingSymmetricKeyAlgorithm(verifierInputKey, salt_struct->encryptedVerifier, decryptedVerifierHashInputBytes, 16);
			DecryptUsingSymmetricKeyAlgorithm(verifierHashKey, salt_struct->encryptedVerifierHash, decryptedVerifierHashBytes, 32);
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, decryptedVerifierHashInputBytes, 16);
			SHA1_Final(hash, &ctx);
			if(!memcmp(hash, decryptedVerifierHashBytes, 20))
				cracked[index] = 1;
			else
				cracked[index] = 0;
		}
	}
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

static void office_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	extern struct fmt_main office_fmt;

	if (saved_key_length > office_fmt.params.plaintext_length)
		saved_key_length = office_fmt.params.plaintext_length;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main office_fmt = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		office_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		office_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact,
		fmt_default_get_source
	}
};
