/*
 * Office 2007-2013 cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * office format, and the GPU office formats, and places it into one
 * common location.
 */

#include "formats.h"

#define FORMAT_TAG_OFFICE           "$office$*"
#define FORMAT_TAG_OFFICE_LEN       (sizeof(FORMAT_TAG_OFFICE)-1)

typedef struct ms_office_custom_salt_t {
	uint8_t osalt[16];
	uint8_t encryptedVerifier[16];
	uint8_t encryptedVerifierHash[32];
	int version;
	int verifierHashSize;
	int keySize;
	int saltSize;
	int spinCount;
} ms_office_custom_salt;

void *ms_office_common_get_salt(char *ciphertext);
void *ms_office_common_binary(char *ciphertext);
int ms_office_common_valid(char *ciphertext, struct fmt_main *self);

/* other 'common' functions for MSOffice */
unsigned int ms_office_common_iteration_count(void *salt);
unsigned int ms_office_common_version(void *salt);
