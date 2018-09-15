/*
 * Common code for the Password Safe format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME             "Password Safe"
#define FORMAT_TAG              "$pwsafe$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

extern struct fmt_tests pwsafe_tests[];

struct custom_salt {
	int version;
	unsigned int iterations;
	unsigned char salt[32];
};

int pwsafe_valid(char *ciphertext, struct fmt_main *self);
