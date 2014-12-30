/* 
 * Office 2007-2013 cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * office format, and the GPU office formats, and places it into one
 * common location (with some tiny tweaks, for things like valid).
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "office_common.h"
#include "sha.h"
#include "sha2.h"
#include <openssl/aes.h>

void *ms_office_common_get_salt(char *ciphertext)
{
	int i, length;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy, *p;
	ms_office_custom_salt *cur_salt;

	cur_salt = mem_calloc_tiny(sizeof(ms_office_custom_salt), MEM_ALIGN_WORD);
	ctcopy += 9;	/* skip over "$office$*" */
	p = strtok(ctcopy, "*");
	cur_salt->version = atoi(p);
	p = strtok(NULL, "*");
	if(cur_salt->version == 2007) {
		cur_salt->verifierHashSize = atoi(p);
	}
	else {
		cur_salt->spinCount = atoi(p);
	}
	p = strtok(NULL, "*");
	cur_salt->keySize = atoi(p);
	p = strtok(NULL, "*");
	cur_salt->saltSize = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cur_salt->saltSize; i++)
		cur_salt->osalt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	for (i = 0; i < 16; i++)
		cur_salt->encryptedVerifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	length = strlen(p) / 2;
	for (i = 0; i < length; i++)
		cur_salt->encryptedVerifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)cur_salt;
}

/* a common 'static' valid function. The valid in each of the     */
/* formats, link to one of the external function which calls this */
static int valid(char *ciphertext, struct fmt_main *self, char *which)
{
	char *ctcopy, *ptr, *keeptr;
	int res;

	if (strncmp(ciphertext, "$office$*", 9))
		return 0;
	if (!(ctcopy = strdup(ciphertext))) {
		fprintf(stderr, "Memory allocation failed in office format, unable to check if hash is valid!");
		return 0;
	}
	keeptr = ctcopy;
	ctcopy += 9;
	if (!(ptr = strtok(ctcopy, "*")))
		goto error;
	if (strncmp(ptr, "2007", 4) && strncmp(ptr, "2010", 4) && strncmp(ptr, "2013", 4))
		goto error;
	if (which && strncmp(ptr, which, 4))
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* hash size or iterations */
		goto error;
	if (!isdec(ptr)) goto error;
	if (!(ptr = strtok(NULL, "*")))
		goto error;
	if (strncmp(ptr, "128", 3) && strncmp(ptr, "256", 3)) /* key size */
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* salt size */
		goto error;
	res = atoi(ptr);
	if (res != 16) /* can we handle other values? */
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* salt */
		goto error;
	if (strlen(ptr) != res * 2)
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* encrypted verifier */
		goto error;
	if (!ishex(ptr))
		goto error;
	if (!(ptr = strtok(NULL, "*"))) /* encrypted verifier hash */
		goto error;
	if (!ishex(ptr))
		goto error;
	if (strlen(ptr) > 64)
		goto error;
	if ((ptr = strtok(NULL, "*")))
		goto error;

	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

int ms_office_common_valid_all(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, NULL);
}
int ms_office_common_valid_2007(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, "2007");
}
int ms_office_common_valid_2010(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, "2010");
}
int ms_office_common_valid_2013(char *ciphertext, struct fmt_main *self)
{
	return valid(ciphertext, self, "2013");
}

#if FMT_MAIN_VERSION > 11
unsigned int ms_office_common_iteration_count(void *salt)
{
	ms_office_custom_salt *my_salt=(ms_office_custom_salt *)salt;
    /*
	 * Is spinCount always 100000, or just in our format tests?
	 */
	return (unsigned int) my_salt->spinCount;
}
#endif

// MORE common code:

void ms_office_common_DecryptUsingSymmetricKeyAlgorithm(ms_office_custom_salt *cur_salt, unsigned char *verifierInputKey, unsigned char *encryptedVerifier, const unsigned char *decryptedVerifier, int length)
{
	unsigned char iv[32];
	AES_KEY akey;
	memcpy(iv, cur_salt->osalt, 16);
	memset(&iv[16], 0, 16);
	memset(&akey, 0, sizeof(AES_KEY));
	if(cur_salt->keySize == 128) {
		if(AES_set_decrypt_key(verifierInputKey, 128, &akey) < 0) {
			fprintf(stderr, "AES_set_decrypt_key failed!\n");
		}
	}
	else {
		if(AES_set_decrypt_key(verifierInputKey, 256, &akey) < 0) {
			fprintf(stderr, "AES_set_decrypt_key failed!\n");
		}
	}
	AES_cbc_encrypt(encryptedVerifier, (unsigned char*)decryptedVerifier, length, &akey, iv, AES_DECRYPT);
}

int ms_office_common_PasswordVerifier(ms_office_custom_salt *cur_salt, unsigned char *key)
{
	unsigned char decryptedVerifier[16];
	unsigned char decryptedVerifierHash[16];
	AES_KEY akey;
	SHA_CTX ctx;
	unsigned char checkHash[20];

	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed!\n");
		return 0;
	}
	AES_ecb_encrypt(cur_salt->encryptedVerifier, decryptedVerifier, &akey, AES_DECRYPT);
	memset(&akey, 0, sizeof(AES_KEY));
	if(AES_set_decrypt_key(key, 128, &akey) < 0) {
		fprintf(stderr, "AES_set_decrypt_key failed!\n");
		return 0;
	}
	AES_ecb_encrypt(cur_salt->encryptedVerifierHash, decryptedVerifierHash, &akey, AES_DECRYPT);

	/* find SHA1 hash of decryptedVerifier */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decryptedVerifier, 16);
	SHA1_Final(checkHash, &ctx);

	return !memcmp(checkHash, decryptedVerifierHash, 16);
}
