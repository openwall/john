/*
 * Common code for the PGP WDE format.
 */

#include <string.h>

#include "formats.h"
#include "sha.h"
#include "aes.h"

#define FORMAT_NAME             "PGP Whole Disk Encryption"
#define FORMAT_TAG              "$pgpwde$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	int version;
	int symmAlg;
	int s2ktype;
	int hashIterations;
	int bytes;
	int salt_size;
	unsigned char salt[16];
	unsigned char esk[128];
};

extern struct fmt_tests pgpwde_tests[];

// exported 'common' functions
int pgpwde_valid(char *ciphertext, struct fmt_main *self);
void *pgpwde_get_salt(char *ciphertext);
int pgpwde_decrypt_and_verify(unsigned char *key, unsigned char *esk, int esklen);
