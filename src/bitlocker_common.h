/*
 * Common code for the BitLocker format.
 */

#include "formats.h"

#define MACLEN                 16
#define SALTLEN                 16
#define IVLEN                   12  // nonce length
#define FORMAT_NAME             "BitLocker"
#define FORMAT_TAG              "$bitlocker$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

#define BITLOCKER_HASH_UP 		0
#define BITLOCKER_HASH_UP_MAC		1
#define BITLOCKER_HASH_RP 		2
#define BITLOCKER_HASH_RP_MAC		3
#define RECOVERY_KEY_SIZE_CHAR 	56
#define RECOVERY_PASS_BLOCKS 	8

typedef struct {
	int attack_type;
	int salt_length;
	int data_size;
	unsigned char salt[SALTLEN];
	unsigned int iterations;
	unsigned char data[256];
	unsigned char iv[IVLEN]; // nonce
	unsigned char mac[MACLEN]; // nonce
} bitlocker_custom_salt;

extern struct fmt_tests bitlocker_tests[];

// exported 'common' functions
int bitlocker_common_valid(char *ciphertext, struct fmt_main *self);
void *bitlocker_common_get_salt(char *ciphertext);
unsigned int bitlocker_common_iteration_count(void *salt);
