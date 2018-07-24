/*
 * Common code for the LastPass CLI format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define BINARY_SIZE             16
#define FORMAT_NAME             "LastPass CLI"
#define FORMAT_TAG              "$lpcli$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#define AGENT_VERIFICATION_STRING "`lpass` was written by LastPass.\n"

extern struct fmt_tests lastpass_cli_tests[];

struct custom_salt {
	int iterations;
	int salt_length;
	int type;
	unsigned char iv[32];
	unsigned char salt[32+1];
};

// exported 'common' functions
int lastpass_cli_common_valid(char *ciphertext, struct fmt_main *self);
void *lastpass_cli_common_get_salt(char *ciphertext);
unsigned int lastpass_cli_common_iteration_count(void *salt);
void *lastpass_cli_common_get_binary(char *ciphertext);
unsigned int lastpass_cli_common_iteration_count(void *salt);
