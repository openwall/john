/*
 * Common code for cracking DiskCryptor.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "common.h"
#include "formats.h"
#include "jumbo.h"

#define FORMAT_TAG              "$diskcryptor$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)

struct custom_salt {
	uint32_t type;
	uint32_t iterations;
	uint32_t saltlen;
	unsigned char salt[64];
	unsigned char header[2048];
};

// https://diskcryptor.net/wiki/Volume
#define PKCS5_SALT_SIZE         64
#define DISKKEY_SIZE            256
#define MAX_KEY_SIZE            (32*3)
#define PKCS_DERIVE_MAX         (MAX_KEY_SIZE*2)
#define CF_CIPHERS_NUM          7  // 7 types of ciphers possible

#if defined(__GNUC__) && !defined(__MINGW32__)
#define PACKED __attribute__ ((__packed__))
#else
#define PACKED
#pragma pack(push,1)
#endif

struct dc_header {
	uint8_t  salt[PKCS5_SALT_SIZE]; /* pkcs5.2 salt */
	uint32_t sign;                  /* signature 'DCRP' */
	uint32_t hdr_crc;               /* crc32 of decrypted volume header */
	uint16_t version;               /* volume format version */
	uint32_t flags;                 /* volume flags */
	uint32_t disk_id;               /* unique volume identifier */
	int32_t  alg_1;                 /* crypt algo 1 */
	uint8_t  key_1[DISKKEY_SIZE];   /* crypt key 1  */
	int32_t  alg_2;                 /* crypt algo 2 */
	uint8_t  key_2[DISKKEY_SIZE];   /* crypt key 2  */

	uint64_t stor_off;              /* temporary storage offset */
	uint64_t use_size;              /* user available volume size */
	uint64_t tmp_size;              /* temporary part size */
	uint8_t  tmp_wp_mode;           /* data wipe mode */

	uint8_t  reserved[1422 - 1];
} PACKED;

#if !defined(__GNUC__) || defined(__MINGW32__)
#pragma pack(pop)
#endif

extern struct fmt_tests diskcryptor_tests[];

int diskcryptor_valid(char *ciphertext, struct fmt_main *self);

void *diskcryptor_get_salt(char *ciphertext);

unsigned int diskcryptor_iteration_count(void *salt);

int diskcryptor_decrypt_data(unsigned char *key, struct custom_salt *cur_salt);
