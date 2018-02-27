/*
 * Common code for the Ansible Vault format.
 */

#include "formats.h"

#define FORMAT_NAME             "Ansible Vault"
#define FORMAT_TAG              "$ansible$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define BINARY_SIZE             32
#define BINARY_SIZE_CMP         16

#define SALTLEN                 32
#define BLOBLEN                 8192

struct custom_salt{
	int salt_length;
	int iterations;
	int bloblen;
	unsigned char salt[SALTLEN];
	unsigned char checksum[32];
	unsigned char blob[BLOBLEN];
};

extern struct fmt_tests ansible_tests[];

int ansible_common_valid(char *ciphertext, struct fmt_main *self);
void *ansible_common_get_salt(char *ciphertext);
extern void *ansible_common_get_binary(char *ciphertext);
unsigned int ansible_common_iteration_count(void *salt);
