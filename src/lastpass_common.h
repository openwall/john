/*
 * Common code for the LastPass format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "aes.h"

#define BINARY_SIZE             16
#define FORMAT_NAME             "LastPass offline"
#define FORMAT_TAG              "$lp$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

extern struct fmt_tests lastpass_tests[];

struct custom_salt {
	int iterations;
	int salt_length;
	unsigned char salt[32+1];
};

// exported 'common' functions
int lastpass_common_valid(char *ciphertext, struct fmt_main *self);
void *lastpass_common_get_salt(char *ciphertext);
unsigned int lastpass_common_iteration_count(void *salt);
void *lastpass_common_get_binary(char *ciphertext);
unsigned int lastpass_common_iteration_count(void *salt);
