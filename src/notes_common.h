/*
 * Common code for the Apple Notes format.
 */

#include "formats.h"

#define SALTLEN                 16
#define BLOBLEN                 24
#define FORMAT_NAME             "Apple Notes"
#define FORMAT_TAG              "$ASN$*"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	int salt_length;
	unsigned char salt[SALTLEN];
	unsigned int iterations;
	unsigned int type;
	union blob {  // wrapped kek
		uint64_t qword[BLOBLEN/sizeof(uint64_t)];
		unsigned char chr[BLOBLEN];
	} blob;
};

extern struct fmt_tests notes_tests[];

// exported 'common' functions
int notes_common_valid(char *ciphertext, struct fmt_main *self);
void *notes_common_get_salt(char *ciphertext);
unsigned int notes_common_iteration_count(void *salt);
