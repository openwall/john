/*
 * Common code for the VMware VMX format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define SALTLEN                 16
#define BLOBLEN                 116
#define FORMAT_NAME             "VMware VMX"
#define FORMAT_TAG              "$vmx$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	int salt_length;
	unsigned char salt[SALTLEN];
	int iterations;
	int blob_length;
	unsigned char blob[BLOBLEN];
};

extern struct fmt_tests vmx_tests[];

// exported 'common' functions
int vmx_common_valid(char *ciphertext, struct fmt_main *self);
void *vmx_common_get_salt(char *ciphertext);
unsigned int vmx_common_iteration_count(void *salt);
