#include "formats.h"

#define FORMAT_TAG              "$blockchain$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define BIG_ENOUGH 		(8192 * 32)

// increase me (in multiples of 16) to increase the decrypted and search area
#define SAFETY_FACTOR 		160

struct custom_salt {
	unsigned char data[SAFETY_FACTOR];
	int length;
	int iter;
};

extern struct fmt_tests blockchain_tests[];

// exported 'common' functions
int blockchain_common_valid(char *ciphertext, struct fmt_main *self);
void *blockchain_common_get_salt(char *ciphertext);
int blockchain_decrypt(unsigned char *derived_key, unsigned char *data);
