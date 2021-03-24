/*
 * Common code for the NetIQ SSPR format.
 */

#include <string.h>

#include "formats.h"

#define FORMAT_NAME             "NetIQ SSPR / Adobe AEM"
#define FORMAT_TAG              "$sspr$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define BINARY_SIZE             64
#define BINARY_ALIGN            sizeof(uint32_t)
#define BINARY_SIZE_MIN         16
#define MAX_SALT_LEN            1500
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)

struct custom_salt {
	uint32_t iterations;
	uint32_t saltlen;
	uint32_t fmt;
	char salt[MAX_SALT_LEN+1];
};

extern struct fmt_tests sspr_tests[];
extern int sspr_valid(char *ciphertext, struct fmt_main *self);
extern void *sspr_get_salt(char *ciphertext);
extern void *sspr_get_binary(char *ciphertext);
extern unsigned int sspr_get_kdf_type(void *salt);
extern unsigned int sspr_get_iteration_count(void *salt);
