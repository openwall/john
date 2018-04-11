/*
 * Common code for the ODF/StarOffice/LibreOffice format.
 */

#include <string.h>

#include "formats.h"

#define FORMAT_TAG              "$odf$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_NAME             "OpenDocument Star/Libre/OpenOffice"

struct custom_salt {
	int cipher_type;
	int checksum_type;
	int iterations;
	int key_size;
	int iv_length;
	int salt_length;
	int content_length;
	int original_length;	// Needed for legacy StarOffice. 0 for others
	unsigned char iv[16];
	unsigned char salt[32];
	unsigned char content[1024];
};

extern struct fmt_tests odf_tests[];

// mimic bug in Star/Libre office SHA1. Needed for any string of length 52 to 55 mod(64)
extern void SHA1_odf_buggy(unsigned char *data, int len, uint32_t results[5]);

int odf_valid(char *ciphertext, struct fmt_main *self);
void *odf_get_salt(char *ciphertext);
void *odf_get_binary(char *ciphertext);
char *odf_prepare(char *fields[10], struct fmt_main *self);
unsigned int odf_iteration_count(void *salt);
unsigned int odf_crypto(void *salt);
int odf_common_cmp_exact(char *source, char *pass, struct custom_salt *cur_salt);
