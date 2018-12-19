/*
 * Common code for the PEM format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "common.h"
#include "formats.h"
#include "jumbo.h"
#include "asn1.h"

#define FORMAT_NAME             "PKCS#8 private key (RSA/DSA/ECDSA)"
#define FORMAT_TAG              "$PEM$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define SALTLEN                 8
#define IVLEN                   8
#define CTLEN                   4096

struct custom_salt {
	int salt_length;
	unsigned char salt[SALTLEN];
	int iv_length;
	unsigned char iv[16];
	int iterations;
	int ciphertext_length;
	unsigned char ciphertext[CTLEN];
	int cid;  // cipher id
	int key_length;
};


extern struct fmt_tests pem_tests[];

int pem_valid(char *ciphertext, struct fmt_main *self);

void *pem_get_salt(char *ciphertext);

int pem_decrypt(unsigned char *key, unsigned char *iv, unsigned char *data, struct custom_salt *cur_salt);

unsigned int pem_iteration_count(void *salt);
unsigned int pem_cipher(void *salt);
