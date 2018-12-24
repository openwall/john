/*
 * Common code for the AxCrypt format.
 */

#include <string.h>

#include "formats.h"
#include "dyna_salt.h"

#define FORMAT_TAG          "$axcrypt$*"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

struct custom_salt {
	dyna_salt dsalt;
	int version;
	uint32_t key_wrapping_rounds;
	uint32_t deriv_salt_length;
	uint32_t deriv_iterations;  // v2 only
	unsigned char salt[64];  // v1 -> 16, v2 -> WrapSalt
	unsigned char deriv_salt[32 + 8];  // v2 only
	unsigned char wrappedkey[144];  // v1 -> 24
	char *keyfile;
};

extern int axcrypt_common_valid(char *ciphertext, struct fmt_main *self, int is_cpu_format);
extern void *axcrypt_get_salt(char *ciphertext);
extern unsigned int axcrypt_iteration_count(void *salt);
