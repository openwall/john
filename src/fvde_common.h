/*
 * Common code for the FileVault 2 (FVDE) format.
 */

#include "formats.h"

#define SALTLEN                 16
#define BLOBLEN                 40  // 24 for AES-128
#define FORMAT_NAME             "FileVault 2"
#define FORMAT_TAG              "$fvde$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

typedef struct {
	int salt_length;
	unsigned char salt[SALTLEN];
	unsigned int iterations;
	unsigned int bloblen;
	unsigned int type;
	union blob {  // wrapped kek
		uint64_t qword[BLOBLEN/sizeof(uint64_t)];
		unsigned char chr[BLOBLEN];
	} blob;
} fvde_custom_salt;

extern struct fmt_tests fvde_tests[];

// exported 'common' functions
int fvde_common_valid(char *ciphertext, struct fmt_main *self);
void *fvde_common_get_salt(char *ciphertext);
unsigned int fvde_common_iteration_count(void *salt);
