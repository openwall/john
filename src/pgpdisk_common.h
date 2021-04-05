/*
 * Common code for the PGP Disk format.
 */

#include <string.h>

#include "formats.h"
#include "sha.h"
#include "aes.h"
#include "twofish.h"

#define FORMAT_NAME             "PGP Disk / Virtual Disk"
#define FORMAT_TAG              "$pgpdisk$"
#define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	int version;
	int algorithm;
	int iterations;
	int salt_size;
	unsigned char salt[16];
};

extern struct fmt_tests pgpdisk_tests[];

// exported 'common' functions
int pgpdisk_common_valid(char *ciphertext, struct fmt_main *self);
void *pgpdisk_common_get_salt(char *ciphertext);
unsigned int pgpdisk_common_iteration_count(void *salt);
unsigned int pgpdisk_common_algorithm(void *salt);
