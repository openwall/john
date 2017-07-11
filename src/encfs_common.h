/*
 * encfs JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#include "aes.h"
#include "formats.h"

typedef struct encfs_common_custom_salt_t {
	unsigned int keySize;
	unsigned int iterations;
	unsigned int cipher;
	unsigned int saltLen;
	unsigned char salt[40];
	unsigned int dataLen;
	unsigned char data[128];
	unsigned int ivLength;
} encfs_common_custom_salt;

#define MAX_KEYLENGTH    32 // in bytes (256 bit)
#define MAX_IVLENGTH     20
#define FORMAT_TAG       "$encfs$"
#define FORMAT_TAG_LEN   (sizeof(FORMAT_TAG) - 1)

int encfs_common_valid(char *ciphertext, struct fmt_main *self);
void *encfs_common_get_salt(char *ciphertext);
unsigned int encfs_common_iteration_count(void *salt);

// exported 'common' functions
unsigned int encfs_common_MAC_32(encfs_common_custom_salt *cur_salt, unsigned char *src, int len, unsigned char *key);
void encfs_common_streamDecode(encfs_common_custom_salt *cur_salt, unsigned char *buf, int size, uint64_t iv64, unsigned char *key);

// these common items were better done as #defines.
#define unshuffleBytes(buf, size) do \
{                                    \
	int i;                           \
	for (i=size-1; i; --i)            \
		buf[i] ^= buf[i-1];          \
} while(0)

#define MIN_(a, b) (((a) < (b)) ? (a) : (b))
