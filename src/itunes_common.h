/*
 * Common code for the Apple iTunes Backup format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "sha2.h"

#define SALTLEN                 20
#define WPKYLEN                 40
#define FORMAT_NAME             "Apple iTunes Backup"
#define FORMAT_TAG              "$itunes_backup$*"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	int version;
	union wpky {
		uint64_t qword[WPKYLEN/sizeof(uint64_t)];
		unsigned char chr[WPKYLEN];
	} wpky;
	unsigned char salt[SALTLEN];
	unsigned char dpsl[SALTLEN]; // iTunes Backup 10.x
	long dpic; // iTunes Backup 10.x
	int iterations;
};

int itunes_common_valid(char *ciphertext, struct fmt_main *self);
void *itunes_common_get_salt(char *ciphertext);
unsigned int itunes_common_tunable_version(void *salt);
unsigned int itunes_common_tunable_iterations(void *salt);

// exported 'common' functions
int itunes_common_decrypt(struct custom_salt *cur_salt, unsigned char *key);
