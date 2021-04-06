/*
 * Common code for the Telegram Desktop format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "common.h"
#include "formats.h"
#include "jumbo.h"

#define FORMAT_NAME             ""
#define FORMAT_TAG              "$telegram$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define SALTLEN                 32
#define ENCRYPTED_BLOB_LEN      512

struct custom_salt {
	uint32_t version;
	uint32_t iterations;
	unsigned char salt[SALTLEN];
	uint32_t salt_length;
	unsigned char encrypted_blob[ENCRYPTED_BLOB_LEN];
	uint32_t encrypted_blob_length;
};

extern struct fmt_tests telegram_tests[];

extern int telegram_check_password(unsigned char *authkey, struct custom_salt *cs);
extern int telegram_valid(char *ciphertext, struct fmt_main *self);
extern void *telegram_get_salt(char *ciphertext);
extern unsigned int telegram_iteration_count(void *salt);
