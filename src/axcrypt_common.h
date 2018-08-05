/*
 * Common code for the AxCrypt format.
 */

#include <string.h>

#include "formats.h"
#include "dyna_salt.h"

#define FORMAT_TAG          "$axcrypt$*"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

struct custom_salt {
	dyna_salt dsalt;
	int version;
	uint32_t key_wrapping_rounds;
	unsigned char salt[16];
	unsigned char wrappedkey[24];
	char *keyfile;
};

extern struct fmt_tests axcrypt_tests[];

extern int axcrypt_valid(char *ciphertext, struct fmt_main *self);
extern void *axcrypt_get_salt(char *ciphertext);
extern unsigned int axcrypt_iteration_count(void *salt);
