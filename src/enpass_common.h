/*
 * Common code for the Enpass Password Manager format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "aes.h"

#define FORMAT_NAME             "Enpass Password Manager"
#define FORMAT_TAG              "$enpass$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FILE_HEADER_SZ          16
#define SQLITE_FILE_HEADER      "SQLite format 3"
#define SQLITE_MAX_PAGE_SIZE    65536

extern int enpass_valid(char *ciphertext, struct fmt_main *self);
extern void *enpass_get_salt(char *ciphertext);
extern unsigned int enpass_version(void *salt);

struct custom_salt {
	unsigned char salt[16];
	unsigned char data[1024];
	unsigned int iterations;
	unsigned int version;
	unsigned int salt_length;
};

static const int page_sz = 1008; /* 1024 - strlen(SQLITE_FILE_HEADER) */

/* See "sqlcipher_codec_ctx_set_use_hmac" function.
 *
 * sqlcipher_codec_ctx_set_use_hmac: use=1 block_sz=16 md_size=20 reserve=48,
 * in case of Enpass Password Manager
 */

static const int reserve_sz = 48;
