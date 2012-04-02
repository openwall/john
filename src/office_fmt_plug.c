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

#define FORMAT_LABEL		"office"
#define FORMAT_NAME		"Office"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	8
#define BINARY_SIZE		16
#define SALT_SIZE		256
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
	printf("\n");
}

static struct fmt_tests office_tests[] = {
	{"$office$*2007*20*128*16*8b2c9e8c878844fc842012273be4bea8*aa862168b80d8c45c852696a8bb499eb*a413507fabe2d87606595f987f679ff4b5b4c2cd86511ee967274442287bc600", "Paswword"},
	{NULL}
};

static char unsigned oursalt[32]; /* bigger than necessary */
static char unsigned encryptedVerifier[16];
static char unsigned encryptedVerifierHash[32];
static int version;
static int verifierHashSize;
static int keySize;
static int saltSize;
static char saved_key[PLAINTEXT_LENGTH + 1];
static int cracked;

static unsigned char *DeriveKey(unsigned char *hashValue)
{
	int i;
	unsigned char derivedKey[64];
	
	// This is step 4a in 2.3.4.7 of MS_OFFCRYPT version 1.0
	// and is required even though the notes say it should be 
	// used only when the encryption algorithm key > hash length.
	for (i = 0; i < 64; i++)
		derivedKey[i] = (i < 20 ? 0x36 ^ hashValue[i] : 0x36);
	// print_hex(derivedKey, 64);

	unsigned char *X1 = (unsigned char *)malloc(20);
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, derivedKey, 64);
	SHA1_Final(X1, &ctx);
	// print_hex(X1, 20);

	if (verifierHashSize > keySize/8)
		return X1;
	for (i = 0; i < 64; i++)
		derivedKey[i] = (i < 30 ? 0x5C ^ hashValue[i] : 0x5C);

	/* TODO: finish up this function */
	return NULL;
}


static unsigned char* GeneratePasswordHashUsingSHA1(char *password)
{
	//print_hex(oursalt, saltSize);

	unsigned char hashBuf[20];
	/* H(0) = H(salt, password)
	 * hashBuf = SHA1Hash(salt, password);
	 * create input buffer for SHA1 from salt and unicode version of password */
	unsigned char passwordBuf[512] = {0};
	int passwordBufSize = strlen(password) * 2;
	int i;
	unsigned char c;
	int position = 0;
	/* convert key to UTF-16LE */
	for(i = 0; (c = password[i]); i++) {
		passwordBuf[position] = c;
		position += 2;
	}
	// print_hex(passwordBuf, passwordBufSize);
	unsigned char *inputBuf = (unsigned char *)malloc(saltSize + passwordBufSize);
	memcpy(inputBuf, oursalt, saltSize);
	memcpy(inputBuf + saltSize, passwordBuf, passwordBufSize);
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, inputBuf, saltSize + passwordBufSize);
	SHA1_Final(hashBuf, &ctx);
	// print_hex(hashBuf, 20);
	free(inputBuf);	

	/* Generate each hash in turn
	 * H(n) = H(i, H(n-1)) 
	 * hashBuf = SHA1Hash(i, hashBuf); */
	// Create an input buffer for the hash.  This will be 4 bytes larger than 
	// the hash to accommodate the unsigned int iterator value.
	inputBuf = (unsigned char *)malloc(0x14 + 0x04);
	// Create a byte array of the integer and put at the front of the input buffer
	// 1.3.6 says that little-endian byte ordering is expected
	for (i = 0; i < 50000; i++) {
		memcpy(inputBuf, &i, 4);
		// 'append' the previously generated hash to the input buffer
		memcpy(inputBuf + 4, hashBuf, 20);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
		SHA1_Final(hashBuf, &ctx);
	}
	//print_hex(hashBuf, 20);

	// Finally, append "block" (0) to H(n)
	// hashBuf = SHA1Hash(hashBuf, 0);
	i = 0;
	memcpy(inputBuf, hashBuf, 20);
	memcpy(inputBuf + 20, &i, 4);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, inputBuf, 0x14 + 0x04);
	SHA1_Final(hashBuf, &ctx);
	// print_hex(hashBuf, 20);
	free(inputBuf);

	unsigned char *key = DeriveKey(hashBuf);

	// Should handle the case of longer key lengths as shown in 2.3.4.9
	// Grab the key length bytes of the final hash as the encrypytion key
	unsigned char *final = (unsigned char *)malloc(keySize/8);
	memcpy(final, key, keySize/8);
	free(key);
	// print_hex(final, keySize/8);
	return final;
}


static int PasswordVerifier(unsigned char * key)
{
	// print_hex(key, 16);
	// print_hex(encryptedVerifier, 16);
	unsigned char decryptedVerifier[16];
	AES_KEY akey;
     	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_derypt_key failed!\n");
		return 0;
	}
	AES_ecb_encrypt(encryptedVerifier, decryptedVerifier, &akey, AES_DECRYPT);
	// print_hex(decryptedVerifier, 16);

	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_derypt_key failed!\n");
		return 0;
	} 
	unsigned char decryptedVerifierHash[32];
	AES_ecb_encrypt(encryptedVerifierHash, decryptedVerifierHash, &akey, AES_DECRYPT);
	AES_ecb_encrypt(encryptedVerifierHash+16, decryptedVerifierHash+16, &akey, AES_DECRYPT);
	// print_hex(decryptedVerifierHash, 20);
	// print_hex(decryptedVerifierHash+16, 16);


	/* find SHA1 hash of decryptedVerifier */
	SHA_CTX ctx;
	unsigned char checkHash[20];
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decryptedVerifier, 16);
	SHA1_Final(checkHash, &ctx);
	// print_hex(checkHash, 20);
	// print_hex(decryptedVerifierHash, 20);
	
	int i;
	for (i = 0; i < 16; i++) {
		if (decryptedVerifierHash[i] != checkHash[i]) {
			printf("bad at %d\n", i);
			return 0;
		}
	}
	return 1;
}


static void init(struct fmt_main *pFmt)
{

}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return !strncmp(ciphertext, "$office$", 8);
}

static void *get_salt(char *ciphertext)
{
	return ciphertext;
}


static void set_salt(void *salt)
{
	int i;
	char *saltcopy = strdup(salt);
	char *keeptr = saltcopy;
	saltcopy += 9;	/* skip over "$office$*" */
	char *p = strtok(saltcopy, "*");
	version = atoi(p);
	p = strtok(NULL, "*");
	verifierHashSize = atoi(p);
	p = strtok(NULL, "*");
	keySize = atoi(p);
	p = strtok(NULL, "*");
	saltSize = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < saltSize; i++)
		oursalt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		encryptedVerifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 32; i++)
		encryptedVerifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	cracked = 0;
	free(keeptr);
}

static void crypt_all(int count)
{
	unsigned char *encryptionKey = GeneratePasswordHashUsingSHA1("Password");
	if (PasswordVerifier(encryptionKey)) {
		// printf("Password verification succeeded!\n");
		cracked = 1;
	}
	else {
		printf("Password verification failed!\n");
	}

}

static int cmp_all(void *binary, int count)
{
	return cracked;
}

static int cmp_one(void *binary, int index)
{
	return cracked;
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

static void office_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > 8)
		saved_key_length = 8;
	memcpy(saved_key, key, saved_key_length);
	saved_key[saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key;
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
		FMT_CASE | FMT_8_BIT,
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
		cmp_exact
	}
};
