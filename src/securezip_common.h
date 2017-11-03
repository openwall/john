/*
 * Common code for the SecureZIP format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "sha.h"

#define ERDLEN                  256
#define IVLEN                   16
#define FORMAT_NAME             "PKWARE SecureZIP"
#define FORMAT_TAG              "$zip3$*"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	int iv_length;
	unsigned char iv[IVLEN];
	int algorithm;
	int bit_length;
	int erd_length;
	unsigned char erd[ERDLEN];
};

extern struct fmt_tests securezip_tests[];

// exported 'common' functions
int securezip_common_valid(char *ciphertext, struct fmt_main *self);
void *securezip_common_get_salt(char *ciphertext);
