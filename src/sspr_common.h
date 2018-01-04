/*
 * Common code for the NetIQ SSPR format.
 */

#include <string.h>

#include "formats.h"

#define FORMAT_NAME             "NetIQ SSPR"
#define FORMAT_TAG              "$sspr$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define BINARY_SIZE             64
#define BINARY_SIZE_MIN         16
#define MAX_SALT_LEN            1500

struct custom_salt {
	uint32_t iterations;
	uint32_t saltlen;
	uint32_t fmt;
	char salt[MAX_SALT_LEN];
};

int sspr_valid(char *ciphertext, struct fmt_main *self, int is_cpu_format);
void *sspr_get_salt(char *ciphertext);
void *sspr_get_binary(char *ciphertext);
unsigned int sspr_get_kdf_type(void *salt);
