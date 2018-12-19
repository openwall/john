/*
 * Common code for the Android Backup format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "common.h"
#include "formats.h"
#include "jumbo.h"

#define FORMAT_NAME             ""
#define FORMAT_TAG              "$ab$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define SALTLEN                 64
#define IVLEN                   16
#define TAGLEN                  16
#define MAX_MASTERKEYBLOB_LEN   128

struct custom_salt {
	uint32_t iv_length;
	uint32_t iterations;
	unsigned char iv[IVLEN];
	unsigned char user_salt[SALTLEN];
	uint32_t user_salt_length;
	unsigned char ck_salt[SALTLEN];
	uint32_t ck_salt_length;
	unsigned char masterkey_blob[MAX_MASTERKEYBLOB_LEN];
	uint32_t masterkey_blob_length;
};

extern struct fmt_tests ab_tests[];

int ab_valid(char *ciphertext, struct fmt_main *self);

void *ab_get_salt(char *ciphertext);

unsigned int ab_iteration_count(void *salt);
