/*
 * Common code for the Bitwarden format.
 */

#include "formats.h"

#define FORMAT_NAME             "Bitwarden Password Manager"
#define FORMAT_TAG              "$bitwarden$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define SALTLEN                 128
#define IVLEN                   16
#define BLOBLEN                 80

struct custom_salt{
	int salt_length;
	int iterations;
	unsigned char salt[SALTLEN];
	unsigned char iv[IVLEN];
	unsigned char blob[BLOBLEN];
};

extern struct fmt_tests bitwarden_tests[];

int bitwarden_common_valid(char *ciphertext, struct fmt_main *self);
void *bitwarden_common_get_salt(char *ciphertext);
unsigned int bitwarden_common_iteration_count(void *salt);
