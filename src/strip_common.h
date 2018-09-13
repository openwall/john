/*
 * Common code for the STRIP format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME             "Password Manager"

#define FORMAT_TAG              "$strip$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#define ITERATIONS              4000
#define FILE_HEADER_SZ          16
#define SQLITE_FILE_HEADER      "SQLite format 3"
#define HMAC_SALT_MASK          0x3a
#define FAST_PBKDF2_ITER        2
#define SQLITE_MAX_PAGE_SIZE    65536

struct custom_salt {
	unsigned char salt[16];
	unsigned char data[1024];
};

extern struct fmt_tests strip_tests[];

int strip_valid(char *ciphertext, struct fmt_main *self);

void *strip_get_salt(char *ciphertext);

int strip_verify_page(unsigned char *page1);
