/*
 * Common code for the PGP SDA format.
 */

#include <string.h>

#include "formats.h"
#include "sha.h"

#define FORMAT_NAME             "PGP Self Decrypting Archive"
#define FORMAT_TAG              "$pgpsda$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	int version;
	int iterations;
	int salt_size;
	unsigned char salt[8];
};

extern struct fmt_tests pgpsda_tests[];

// exported 'common' functions
int pgpsda_common_valid(char *ciphertext, struct fmt_main *self);
void *pgpsda_common_get_salt(char *ciphertext);
unsigned int pgpsda_iteration_count(void *salt);
