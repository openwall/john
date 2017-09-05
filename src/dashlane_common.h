/*
 * Common code for the Dashlane format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME             "Dashlane Password Manager"
#define FORMAT_TAG              "$dashlane$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

extern struct fmt_tests dashlane_tests[];

struct custom_salt {
	uint32_t type;
	int length;
	unsigned char salt[32];
	unsigned char data[1024];
};

// exported 'common' functions
int dashlane_valid(char *ciphertext, struct fmt_main *self);
void *dashlane_get_salt(char *ciphertext);
int dashlane_verify(struct custom_salt *cur_salt, unsigned char *pkey);
