/*
 * Common code for the Apple Keychain format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME             "Mac OS X Keychain"
#define FORMAT_TAG              "$keychain$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAG_V2           "$keychainv2$*"
#define FORMAT_TAG_V2_LEN       (sizeof(FORMAT_TAG_V2)-1)

#define SALTLEN                 20
#define IVLEN                   8
#define CTLEN                   48
#define SYMKEY_MAX_CTLEN        256

extern struct fmt_tests keychain_tests[];

struct custom_salt {
	unsigned char salt[SALTLEN];
	unsigned char iv[IVLEN];
	unsigned char ct[CTLEN];
	int has_symkey;
	unsigned char symkey_ct[SYMKEY_MAX_CTLEN];
	int symkey_ct_len;
};

int keychain_valid(char *ciphertext, struct fmt_main *self);

void *keychain_get_salt(char *ciphertext);
