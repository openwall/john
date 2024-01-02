/*
 * Common code for the 1Password Cloud Keychain format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"

#define FORMAT_NAME             "1Password Cloud Keychain"
#define FORMAT_TAG              "$cloudkeychain$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)

#define SALTLEN                 32
#define IVLEN                   16
#define CTLEN                   2048
#define EHMLEN                  32
#define PAD_SIZE                128

extern struct fmt_tests cloudkeychain_tests[];

struct custom_salt {
	unsigned int saltlen;
	unsigned char salt[SALTLEN + 5 /* for OpenCL kernel salt hack */];
	unsigned int iterations;
	unsigned int masterkeylen;
	unsigned char masterkey[CTLEN];
	unsigned int plaintextlen;
	unsigned int ivlen;
	unsigned char iv[IVLEN];
	unsigned int cryptextlen;
	unsigned char cryptext[CTLEN];
	unsigned int expectedhmaclen;
	unsigned char expectedhmac[EHMLEN];
	unsigned int hmacdatalen;
	unsigned char hmacdata[CTLEN];
};

int cloudkeychain_valid(char *ciphertext, struct fmt_main *self);

unsigned int cloudkeychain_iteration_count(void *salt);
