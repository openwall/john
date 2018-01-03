/*
 * Common code for the LibreOffice format.
 */

#include <string.h>

#include "formats.h"

#define FORMAT_TAG              "$odf$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_NAME             "OpenDocument + LibreOffice"

struct custom_salt {
	int cipher_type;
	int checksum_type;
	int iterations;
	int key_size;
	int iv_length;
	int salt_length;
	int content_length;
	unsigned char iv[16];
	unsigned char salt[32];
	unsigned char content[1024];
};

int libreoffice_valid(char *ciphertext, struct fmt_main *self, int is_cpu);
void *libreoffice_get_salt(char *ciphertext);
void *libreoffice_get_binary(char *ciphertext);
unsigned int libreoffice_iteration_count(void *salt);
