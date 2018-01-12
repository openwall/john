/*
 * Common code for the LibreOffice format.
 */

#include <string.h>

#include "formats.h"

#define FORMAT_TAG              "$odf$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_NAME             "OpenDocument + LibreOffice"
#define BINARY_SIZE             8

struct custom_salt {
	int cipher_type;
	int checksum_type;
	int iterations;
	int key_size;
	int iv_length;
	int salt_length;
	int content_length;
	int original_length;	// needed for legacy star office. Will be 0 for libre
	unsigned char iv[16];
	unsigned char salt[32];
	unsigned char content[1024];
};

// mimic bug in Star/Libre office SHA1. Needed for any string of length 52 to 55 mod(64)
extern void SHA1_Libre_Buggy(unsigned char *data, int len, uint32_t results[5]);

int libreoffice_valid(char *ciphertext, struct fmt_main *self, int is_cpu, int is_types);
void *libreoffice_get_salt(char *ciphertext);
void *libreoffice_get_binary(char *ciphertext);
char *libreoffice_prepare(char *fields[10], struct fmt_main *self);
unsigned int libreoffice_iteration_count(void *salt);
int libre_common_cmp_exact(char *source, char *pass, struct custom_salt *cur_salt);
