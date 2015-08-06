/*
 * Office 2007-2013 cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * office format, and the GPU office formats, and places it into one
 * common location.
 */

#include "formats.h"

typedef struct ms_office_custom_salt_t {
	char unsigned osalt[32]; /* bigger than necessary */
	char unsigned encryptedVerifier[16];
	char unsigned encryptedVerifierHash[32];
	int version;
	int verifierHashSize;
	int keySize;
	int saltSize;
	/* Office 2010/2013 */
	int spinCount;
} ms_office_custom_salt;

void *ms_office_common_get_salt(char *ciphertext);
void *ms_office_common_binary(char *ciphertext);
int ms_office_common_valid_all(char *ciphertext, struct fmt_main *self);
int ms_office_common_valid_2007(char *ciphertext, struct fmt_main *self);
int ms_office_common_valid_2010(char *ciphertext, struct fmt_main *self);
int ms_office_common_valid_2013(char *ciphertext, struct fmt_main *self);

/* other 'common' functions for MSOffice */
unsigned int ms_office_common_iteration_count(void *salt);
void ms_office_common_DecryptUsingSymmetricKeyAlgorithm(ms_office_custom_salt *cur_salt, unsigned char *verifierInputKey, unsigned char *encryptedVerifier, const unsigned char *decryptedVerifier, int length);
int ms_office_common_PasswordVerifier(ms_office_custom_salt *cur_salt, unsigned char *key, ARCH_WORD_32 *out);

