/*
 * Common code for the BitLocker format.
 */

#include "formats.h"

#define SALTLEN                 16
#define IVLEN                   12  // nonce length
#define FORMAT_NAME             "BitLocker"
#define FORMAT_TAG              "$bitlocker$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

typedef struct {
	int salt_length;
	int data_size;
	unsigned char salt[SALTLEN];
	unsigned int iterations;
	unsigned char data[256];
	unsigned char iv[IVLEN]; // nonce
} bitlocker_custom_salt;

extern struct fmt_tests bitlocker_tests[];

// exported 'common' functions
int bitlocker_common_valid(char *ciphertext, struct fmt_main *self);
void *bitlocker_common_get_salt(char *ciphertext);
unsigned int bitlocker_common_iteration_count(void *salt);
