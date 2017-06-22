/*
 * Common code for the FreeBSD GELI format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "formats.h"
#include "sha2.h"
#include "aes.h"
#include "hmac_sha.h"

#define SHA512_MDLEN            64
#define G_ELI_MAXMKEYS          2
#define G_ELI_MAXKEYLEN         64
#define G_ELI_USERKEYLEN        G_ELI_MAXKEYLEN
#define G_ELI_DATAKEYLEN        G_ELI_MAXKEYLEN
#define G_ELI_AUTHKEYLEN        G_ELI_MAXKEYLEN
#define G_ELI_IVKEYLEN          G_ELI_MAXKEYLEN
#define G_ELI_SALTLEN           64
#define G_ELI_DATAIVKEYLEN      (G_ELI_DATAKEYLEN + G_ELI_IVKEYLEN)
/* Data-Key, IV-Key, HMAC_SHA512(Derived-Key, Data-Key+IV-Key) */
#define G_ELI_MKEYLEN           (G_ELI_DATAIVKEYLEN + SHA512_MDLEN)

#define FORMAT_NAME             "FreeBSD GELI"
#define FORMAT_TAG              "$geli$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

typedef struct {
	uint32_t md_version;
	uint16_t md_ealgo;
	uint16_t md_keylen;
	uint16_t md_aalgo;
	uint8_t md_keys;
	int32_t md_iterations;
	uint8_t md_salt[G_ELI_SALTLEN + 8];
	uint8_t	md_mkeys[G_ELI_MAXMKEYS * G_ELI_MKEYLEN];
	uint32_t saltlen; // hack
} custom_salt;

extern struct fmt_tests geli_tests[];

// exported 'common' functions
int geli_common_valid(char *ciphertext, struct fmt_main *self);
void *geli_common_get_salt(char *ciphertext);
unsigned int geli_common_iteration_count(void *salt);
int geli_decrypt_verify(custom_salt *cur_salt, unsigned char *key);
