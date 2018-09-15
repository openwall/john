/*
 * Common code for the 1Password Agile Keychain format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME             "1Password Agile Keychain"
#define FORMAT_TAG              "$agilekeychain$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#define SALTLEN                 8
#define IVLEN                   8
#define CTLEN                   1040

struct custom_salt {
	unsigned int nkeys;
	unsigned int iterations[2];
	unsigned int saltlen[2];
	unsigned char salt[2][SALTLEN];
	unsigned int ctlen[2];
	unsigned char ct[2][CTLEN];
};

extern struct fmt_tests agilekeychain_tests[];

int agilekeychain_valid(char *ciphertext, struct fmt_main *self);

void *agilekeychain_get_salt(char *ciphertext);
