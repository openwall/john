/*
 * Common code for the Apple iWork format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "sha2.h"
#include "aes.h"

#define SALTLEN                 16
#define IVLEN                   16
#define BLOBLEN                 64
#define FORMAT_NAME             "Apple iWork '09 / '13 / '14"
#define FORMAT_TAG              "$iwork$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

typedef struct format_context {
	int salt_length;
	unsigned char salt[SALTLEN];
	int iv_length;
	unsigned char iv[IVLEN];
	int iterations;
	int blob_length;
	unsigned char blob[BLOBLEN];
} iwork_common_custom_salt;

int iwork_common_valid(char *ciphertext, struct fmt_main *self);
void *iwork_common_get_salt(char *ciphertext);
unsigned int iwork_common_iteration_count(void *salt);

// exported 'common' functions
int iwork_common_decrypt(struct format_context *fctx, unsigned char *key, unsigned char *iv, unsigned char *data);
