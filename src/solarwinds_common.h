/*
 * Common code for the SolarWinds Orion format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME             "SolarWinds Orion"
#define FORMAT_TAG              "$solarwinds$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#define BINARY_SIZE             64
#define SALT_PADDING            "1244352345234"

extern struct fmt_tests solarwinds_tests[];

struct custom_salt {
	char username[64+1];
	char salt[8+1];
};

int solarwinds_valid(char *ciphertext, struct fmt_main *self);
void *solarwinds_get_salt(char *ciphertext);
void *solarwinds_get_binary(char *ciphertext);
